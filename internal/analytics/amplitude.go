package analytics

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// DefaultEndpoint is the Amplitude HTTP V2 production endpoint. EU-residency
// projects must override this via AmplitudeConfig.Endpoint.
const DefaultEndpoint = "https://api2.amplitude.com/2/httpapi"

const (
	defaultBatchSize     = 10
	defaultFlushInterval = 5 * time.Second
	defaultBufferSize    = 256
	defaultHTTPTimeout   = 5 * time.Second
)

// AmplitudeConfig configures the Amplitude HTTP V2 client.
type AmplitudeConfig struct {
	// APIKey is the Amplitude project API key. Required.
	APIKey string

	// Endpoint overrides the events POST URL. Empty → DefaultEndpoint.
	// Override to e.g. https://api.eu.amplitude.com/2/httpapi for EU
	// residency.
	Endpoint string

	// FlushInterval is the maximum time between flushes when the buffer is
	// not full. Zero → defaultFlushInterval.
	FlushInterval time.Duration

	// HTTPTimeout caps every outbound HTTP call. Zero → defaultHTTPTimeout.
	HTTPTimeout time.Duration

	// Logger receives debug/error messages about the worker. nil →
	// slog.Default().
	Logger *slog.Logger

	// HTTPClient overrides the HTTP client used for delivery. nil → a
	// dedicated http.Client with HTTPTimeout. Useful in tests.
	HTTPClient *http.Client
}

// NewAmplitude builds an Emitter that delivers events to Amplitude's HTTP V2
// API. It starts a background worker goroutine; call Close to stop it.
//
// Sticky user properties are attached per event via Event.UserProperties —
// Amplitude HTTP V2 accepts user_properties at the event level, so there is
// no separate identify endpoint to call.
func NewAmplitude(cfg AmplitudeConfig) (Emitter, error) {
	if cfg.APIKey == "" {
		return nil, errors.New("analytics: Amplitude API key is required")
	}
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	flush := cfg.FlushInterval
	if flush <= 0 {
		flush = defaultFlushInterval
	}
	httpTimeout := cfg.HTTPTimeout
	if httpTimeout <= 0 {
		httpTimeout = defaultHTTPTimeout
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: httpTimeout}
	}

	c := &amplitudeClient{
		apiKey:        cfg.APIKey,
		endpoint:      endpoint,
		flushInterval: flush,
		batchSize:     defaultBatchSize,
		httpTimeout:   httpTimeout,
		httpClient:    httpClient,
		logger:        logger,
		ch:            make(chan amplitudeEvent, defaultBufferSize),
		done:          make(chan struct{}),
	}
	go c.run()
	return c, nil
}

type amplitudeClient struct {
	apiKey        string
	endpoint      string
	flushInterval time.Duration
	batchSize     int
	httpTimeout   time.Duration
	httpClient    *http.Client
	logger        *slog.Logger

	ch   chan amplitudeEvent
	done chan struct{}

	// mu guards stopped. Holding mu (write) while closing ch is what makes
	// enqueue panic-safe — enqueue holds mu (read) while sending on ch.
	mu      sync.RWMutex
	stopped bool
}

// amplitudeEvent is the wire-format event sent in the events array.
type amplitudeEvent struct {
	EventType       string         `json:"event_type"`
	UserID          string         `json:"user_id,omitempty"`
	Time            int64          `json:"time"`
	EventProperties map[string]any `json:"event_properties,omitempty"`
	UserProperties  map[string]any `json:"user_properties,omitempty"`
}

// payload is the {api_key, events:[...]} envelope POSTed to /2/httpapi.
type payload struct {
	APIKey string           `json:"api_key"`
	Events []amplitudeEvent `json:"events"`
}

func (c *amplitudeClient) Emit(e Event) {
	if e.Type == "" || e.UserID == "" {
		// Defensive: silently ignore. user_id is required by Amplitude HTTP
		// V2, and an empty event_type is never useful.
		return
	}
	c.enqueue(amplitudeEvent{
		EventType:       e.Type,
		UserID:          e.UserID,
		Time:            time.Now().UnixMilli(),
		EventProperties: e.Properties,
		UserProperties:  e.UserProperties,
	})
}

// enqueue delivers ev to the worker without blocking. Drops if the buffer is
// full or the client is already closed.
func (c *amplitudeClient) enqueue(ev amplitudeEvent) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.stopped {
		return
	}
	select {
	case c.ch <- ev:
	default:
		c.logger.Debug("analytics: drop, buffer full")
	}
}

func (c *amplitudeClient) Close(ctx context.Context) error {
	c.mu.Lock()
	already := c.stopped
	if !already {
		c.stopped = true
		close(c.ch)
	}
	c.mu.Unlock()

	if already {
		return nil
	}
	select {
	case <-c.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// run is the worker goroutine. It batches events up to batchSize and flushes
// either when the batch is full or when flushInterval elapses.
func (c *amplitudeClient) run() {
	defer close(c.done)

	ticker := time.NewTicker(c.flushInterval)
	defer ticker.Stop()

	batch := make([]amplitudeEvent, 0, c.batchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		c.postEvents(batch)
		batch = batch[:0]
	}

	for {
		select {
		case ev, ok := <-c.ch:
			if !ok {
				flush()
				return
			}
			batch = append(batch, ev)
			if len(batch) >= c.batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (c *amplitudeClient) postEvents(events []amplitudeEvent) {
	body, err := json.Marshal(payload{APIKey: c.apiKey, Events: events})
	if err != nil {
		c.logger.Debug("analytics: marshal events failed", "err", err)
		return
	}
	c.post(c.endpoint, body, len(events))
}

func (c *amplitudeClient) post(url string, body []byte, n int) {
	ctx, cancel := context.WithTimeout(context.Background(), c.httpTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		c.logger.Debug("analytics: build request failed", "err", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.Debug("analytics: POST failed", "err", err, "events", n)
		return
	}
	// Drain the body before closing so the underlying connection can be
	// reused by net/http's transport. Cap the discard to a few KB since
	// Amplitude responses are tiny and a malicious or misconfigured endpoint
	// could otherwise stream indefinitely.
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
	}()
	if resp.StatusCode >= 300 {
		c.logger.Debug("analytics: non-2xx response, dropping", "status", resp.StatusCode, "events", n)
	}
}
