package analytics

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// recorded captures a single POST body received by the fake Amplitude server.
type recorded struct {
	URL  string
	Body []byte
}

// fakeAmplitude is a minimal stand-in for api2.amplitude.com used in tests.
type fakeAmplitude struct {
	server *httptest.Server
	mu     sync.Mutex
	posts  []recorded

	// status, if non-zero, is returned for every request.
	status atomic.Int32

	// stallSignal, if set, is closed once the first request is received and
	// the handler then blocks until release is closed. Used to test buffer
	// pressure.
	stallSignal chan struct{}
	release     chan struct{}
}

func newFakeAmplitude() *fakeAmplitude {
	f := &fakeAmplitude{}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.posts = append(f.posts, recorded{URL: r.URL.Path, Body: body})
		f.mu.Unlock()

		if f.stallSignal != nil {
			select {
			case <-f.stallSignal:
			default:
				close(f.stallSignal)
			}
			<-f.release
		}

		if s := f.status.Load(); s != 0 {
			w.WriteHeader(int(s))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	return f
}

func (f *fakeAmplitude) close()             { f.server.Close() }
func (f *fakeAmplitude) eventsURL() string  { return f.server.URL + "/2/httpapi" }
func (f *fakeAmplitude) setStatus(code int) { f.status.Store(int32(code)) }
func (f *fakeAmplitude) snapshot() []recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]recorded, len(f.posts))
	copy(out, f.posts)
	return out
}

// newTestClient builds an amplitudeClient targeted at f with a short flush
// interval so tests don't sleep for whole seconds.
func newTestClient(t *testing.T, f *fakeAmplitude) *amplitudeClient {
	t.Helper()
	em, err := NewAmplitude(AmplitudeConfig{
		APIKey:        "test-key",
		Endpoint:      f.eventsURL(),
		FlushInterval: 20 * time.Millisecond,
		HTTPTimeout:   time.Second,
	})
	if err != nil {
		t.Fatalf("NewAmplitude: %v", err)
	}
	return em.(*amplitudeClient)
}

func TestAmplitude_RejectsMissingAPIKey(t *testing.T) {
	if _, err := NewAmplitude(AmplitudeConfig{}); err == nil {
		t.Fatal("expected error when APIKey is empty")
	}
}

func TestAmplitude_BatchesUpToBatchSize(t *testing.T) {
	f := newFakeAmplitude()
	defer f.close()
	c := newTestClient(t, f)
	t.Cleanup(func() { _ = c.Close(context.Background()) })

	// 25 events at batch size 10 → 2 full batches + 1 partial = 3 POSTs.
	for i := 0; i < 25; i++ {
		c.Emit(Event{Type: "test_event", UserID: "u1", Properties: map[string]any{"i": i}})
	}

	if err := c.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	posts := f.snapshot()
	if len(posts) != 3 {
		t.Fatalf("expected 3 POSTs, got %d", len(posts))
	}

	total := 0
	for _, p := range posts {
		var pl payload
		if err := json.Unmarshal(p.Body, &pl); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if pl.APIKey != "test-key" {
			t.Errorf("api_key=%q, want test-key", pl.APIKey)
		}
		total += len(pl.Events)
	}
	if total != 25 {
		t.Errorf("delivered %d events, want 25", total)
	}
}

func TestAmplitude_FlushOnInterval(t *testing.T) {
	f := newFakeAmplitude()
	defer f.close()
	c := newTestClient(t, f)
	t.Cleanup(func() { _ = c.Close(context.Background()) })

	// Single event won't fill a batch — relies on the 20ms flush ticker.
	c.Emit(Event{Type: "test_event", UserID: "u1"})

	deadline := time.After(time.Second)
	for {
		if len(f.snapshot()) > 0 {
			return
		}
		select {
		case <-deadline:
			t.Fatal("expected flush ticker to deliver event within 1s")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestAmplitude_CloseDrainsPartialBatch(t *testing.T) {
	f := newFakeAmplitude()
	defer f.close()
	c := newTestClient(t, f)

	// Three events — fewer than batchSize, so without close() they'd wait
	// for the ticker. Close should flush them immediately.
	for i := 0; i < 3; i++ {
		c.Emit(Event{Type: "test_event", UserID: "u1"})
	}
	if err := c.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	posts := f.snapshot()
	if len(posts) != 1 {
		t.Fatalf("expected 1 POST after close, got %d", len(posts))
	}
	var pl payload
	if err := json.Unmarshal(posts[0].Body, &pl); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(pl.Events) != 3 {
		t.Errorf("got %d events in drained batch, want 3", len(pl.Events))
	}
}

func TestAmplitude_EmitAfterCloseIsNoop(t *testing.T) {
	f := newFakeAmplitude()
	defer f.close()
	c := newTestClient(t, f)

	if err := c.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Should not panic.
	c.Emit(Event{Type: "after_close", UserID: "u1"})
	if err := c.Close(context.Background()); err != nil {
		t.Errorf("second Close: %v", err)
	}

	if got := len(f.snapshot()); got != 0 {
		t.Errorf("expected 0 POSTs after close, got %d", got)
	}
}

func TestAmplitude_Non2xxResponseDoesNotRetry(t *testing.T) {
	f := newFakeAmplitude()
	defer f.close()
	f.setStatus(http.StatusBadRequest)

	c := newTestClient(t, f)

	for i := 0; i < 10; i++ {
		c.Emit(Event{Type: "test_event", UserID: "u1"})
	}
	if err := c.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	posts := f.snapshot()
	if len(posts) != 1 {
		t.Errorf("expected exactly 1 POST (no retries on 4xx), got %d", len(posts))
	}
}

// TestAmplitude_UserPropertiesOnEvent covers Q3 (client type) — when
// UserProperties is set on an Event, those should be serialised at the
// top level of the wire-format event so Amplitude treats them as sticky on
// the user.
func TestAmplitude_UserPropertiesOnEvent(t *testing.T) {
	f := newFakeAmplitude()
	defer f.close()
	c := newTestClient(t, f)

	c.Emit(Event{
		Type:   "mcp_method_called",
		UserID: "sub_xyz",
		Properties: map[string]any{
			"method": "initialize",
		},
		UserProperties: map[string]any{
			"client_name":    "Claude",
			"client_version": "0.7.1",
		},
	})
	if err := c.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	posts := f.snapshot()
	if len(posts) != 1 {
		t.Fatalf("expected 1 POST, got %d", len(posts))
	}
	if posts[0].URL != "/2/httpapi" {
		t.Errorf("event went to %q, want /2/httpapi", posts[0].URL)
	}

	var pl payload
	if err := json.Unmarshal(posts[0].Body, &pl); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(pl.Events) != 1 {
		t.Fatalf("got %d events in payload, want 1", len(pl.Events))
	}
	got := pl.Events[0]
	if got.UserProperties["client_name"] != "Claude" || got.UserProperties["client_version"] != "0.7.1" {
		t.Errorf("user_properties=%+v, want client_name=Claude client_version=0.7.1", got.UserProperties)
	}
	if got.EventProperties["method"] != "initialize" {
		t.Errorf("event_properties.method=%v, want initialize", got.EventProperties["method"])
	}
}

func TestAmplitude_BufferFullDropsRatherThanBlocking(t *testing.T) {
	f := newFakeAmplitude()
	f.stallSignal = make(chan struct{})
	f.release = make(chan struct{})

	c := newTestClient(t, f)

	// Emit one event to engage the worker → first POST stalls inside the
	// fake server. Subsequent events fill the buffer until it drops.
	c.Emit(Event{Type: "stall_trigger", UserID: "u1"})
	<-f.stallSignal

	// Drown the buffer well past defaultBufferSize. Emit must never block.
	deadline := time.Now().Add(2 * time.Second)
	for i := 0; i < defaultBufferSize*4; i++ {
		c.Emit(Event{Type: "flood", UserID: "u1"})
	}
	if time.Now().After(deadline) {
		t.Fatal("Emit appeared to block")
	}

	// Strict teardown order: release stalled handler, close client (drains
	// the worker), then close the fake server. Doing this inline rather
	// than via t.Cleanup/defer avoids httptest.Server.Close() blocking on
	// an in-flight handler whose release signal hasn't fired yet.
	close(f.release)
	_ = c.Close(context.Background())
	f.close()
}

func TestAmplitude_IgnoresEmptyTypeOrUserID(t *testing.T) {
	f := newFakeAmplitude()
	defer f.close()
	c := newTestClient(t, f)

	c.Emit(Event{Type: "", UserID: "u1"})
	c.Emit(Event{Type: "t", UserID: ""})

	if err := c.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := len(f.snapshot()); got != 0 {
		t.Errorf("expected no POSTs for invalid inputs, got %d", got)
	}
}

func TestNoop_IsSafe(t *testing.T) {
	em := Noop()
	em.Emit(Event{Type: "x", UserID: "u"})
	if err := em.Close(context.Background()); err != nil {
		t.Errorf("Noop.Close: %v", err)
	}
}
