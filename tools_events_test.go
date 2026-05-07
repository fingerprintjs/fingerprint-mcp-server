package fpmcpserver

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/fingerprintjs/fingerprint-mcp-server/internal/schema"
	"github.com/fingerprintjs/go-sdk/v8"
)

// TestWrapFPError_PreservesUnwrap pins the contract that wrapFPError keeps the
// original SDK error in the chain even when it rewrites the surface text.
// Without Unwrap, downstream errors.Is/errors.As checks (e.g. for retries on
// a sentinel error) silently start failing after this layer.
func TestWrapFPError_PreservesUnwrap(t *testing.T) {
	t.Run("body-parse path", func(t *testing.T) {
		// Stand in for *openapi.GenericOpenAPIError: any error implementing
		// Body() []byte takes the body-parse branch.
		bodyErr := &fakeBodyErr{
			msg:  "400 Bad Request",
			body: []byte(`{"error":{"code":"request_cannot_be_parsed","message":"start is older than the retention window"}}`),
		}
		got := wrapFPError("failed to search events", bodyErr)
		if !strings.Contains(got.Error(), "retention window") {
			t.Fatalf("surface text missing structured detail: %q", got.Error())
		}
		if !errors.Is(got, bodyErr) {
			t.Errorf("errors.Is must reach the wrapped SDK error; chain breaks debuggability")
		}
		var unwrapped *fakeBodyErr
		if !errors.As(got, &unwrapped) {
			t.Errorf("errors.As must reach the wrapped SDK error type")
		}
	})

	t.Run("plain fallback path", func(t *testing.T) {
		base := errors.New("network unreachable")
		got := wrapFPError("failed to get event", base)
		if !errors.Is(got, base) {
			t.Errorf("plain non-API errors must remain in the chain via %%w")
		}
	})
}

type fakeBodyErr struct {
	msg  string
	body []byte
}

func (e *fakeBodyErr) Error() string { return e.msg }
func (e *fakeBodyErr) Body() []byte  { return e.body }

// TestSearchEventInputToRequest_StartEndRFC3339 verifies that RFC3339 strings on
// the MCP surface are parsed into the equivalent UnixMilli values that the
// underlying SDK still expects. Covers both the "Z" form and an offset form so
// AI tools producing either don't end up sending wrong-time-zone queries.
//
// Fixtures are derived from time.Now() so the test never falls outside the
// 90 day retention window as the calendar moves forward.
func TestSearchEventInputToRequest_StartEndRFC3339(t *testing.T) {
	now := time.Now()
	weekAgo := now.Add(-7 * 24 * time.Hour)
	pacific := time.FixedZone("PDT", -7*3600)
	eastern := time.FixedZone("EDT", -4*3600)

	cases := []struct {
		name  string
		start string
		end   string
	}{
		{"utc Z form", weekAgo.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339)},
		{"offset form", weekAgo.In(pacific).Format(time.RFC3339), now.In(eastern).Format(time.RFC3339)},
		// JS toISOString() emits fractional seconds; reject would break common clients.
		{"fractional seconds", weekAgo.UTC().Format("2006-01-02T15:04:05.000Z"), now.UTC().Format("2006-01-02T15:04:05.000Z")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			startTime, err := time.Parse(time.RFC3339Nano, tc.start)
			if err != nil {
				t.Fatalf("setup: parse start: %v", err)
			}
			endTime, err := time.Parse(time.RFC3339Nano, tc.end)
			if err != nil {
				t.Fatalf("setup: parse end: %v", err)
			}
			expected := fingerprint.NewSearchEventsRequest().
				Start(startTime.UnixMilli()).
				End(endTime.UnixMilli())

			input := schema.SearchEventInput{Start: &tc.start, End: &tc.end}
			got, err := schema.SearchEventInputToRequest(&input)
			if err != nil {
				t.Fatalf("SearchEventInputToRequest: %v", err)
			}
			if !reflect.DeepEqual(got, expected) {
				t.Errorf("request mismatch\n got: %#v\nwant: %#v", got, expected)
			}
		})
	}
}

// TestSearchEventInputToRequest_InvalidStartReturnsError checks the error is
// AI-actionable: it names the field, includes the offending value, and points
// at the RFC3339 format so the AI can immediately reconstruct the call.
func TestSearchEventInputToRequest_InvalidStartReturnsError(t *testing.T) {
	bad := "yesterday"
	input := schema.SearchEventInput{Start: &bad}
	_, err := schema.SearchEventInputToRequest(&input)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	msg := err.Error()
	for _, want := range []string{"start", "yesterday", "RFC3339"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q missing %q", msg, want)
		}
	}
}

// TestSearchEventInputToRequest_InvalidEndReturnsError covers the most likely
// AI mistake post-change: passing a Unix-ms string. Error must call out the
// field name, the offending value, and the format.
func TestSearchEventInputToRequest_InvalidEndReturnsError(t *testing.T) {
	bad := "1714000000000"
	input := schema.SearchEventInput{End: &bad}
	_, err := schema.SearchEventInputToRequest(&input)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	msg := err.Error()
	for _, want := range []string{"end", bad, "RFC3339"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q missing %q", msg, want)
		}
	}
}

// Verifies that SearchEventInputToRequest produces a non-zero request when all input fields are set.
func TestSearchEventInputToRequest_AllFieldsPopulated(t *testing.T) {
	// Populate every field of SearchEventInput with a non-zero value via reflection.
	input := schema.SearchEventInput{}
	inputVal := reflect.ValueOf(&input).Elem()
	for i := 0; i < inputVal.NumField(); i++ {
		field := inputVal.Field(i)
		setNonZero(t, inputVal.Type().Field(i).Name, field)
	}

	// Should not panic and should not error on the (RFC3339) start/end strings
	// produced by setNonZero.
	req, err := schema.SearchEventInputToRequest(&input)
	if err != nil {
		t.Fatalf("SearchEventInputToRequest: %v", err)
	}

	// Verify req is non-zero (i.e., something was set)
	if reflect.DeepEqual(req, fingerprint.NewSearchEventsRequest()) {
		t.Error("SearchEventInputToRequest returned an empty request from a fully populated input")
	}
}

// setNonZero sets a `reflect.Value` to a non-zero value based on its type.
func setNonZero(t *testing.T, name string, v reflect.Value) {
	t.Helper()
	switch v.Kind() {
	case reflect.Ptr:
		ptr := reflect.New(v.Type().Elem())
		setNonZero(t, name, ptr.Elem())
		v.Set(ptr)
	case reflect.String:
		// Start/End must parse as a recent RFC3339 timestamp.
		if name == "Start" || name == "End" {
			v.SetString(time.Now().Add(-time.Hour).UTC().Format(time.RFC3339))
		} else {
			v.SetString("test")
		}
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(1)
	case reflect.Float32, reflect.Float64:
		v.SetFloat(0.5)
	case reflect.Slice:
		slice := reflect.MakeSlice(v.Type(), 1, 1)
		setNonZero(t, name, slice.Index(0))
		v.Set(slice)
	case reflect.Interface:
		v.Set(reflect.ValueOf("test"))
	default:
		t.Fatalf("setNonZero: unsupported kind %s for field %q", v.Kind(), name)
	}
}
