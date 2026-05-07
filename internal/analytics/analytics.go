// Package analytics emits product-analytics events from the MCP server.
//
// The package is designed for fire-and-forget telemetry: Emit and Identify
// must never block the request path, must not propagate transient delivery
// failures back to the caller, and must drop events under sustained pressure
// rather than holding goroutines.
package analytics

import "context"

// Event is a single analytics event ready to be delivered to the backend.
// All fields except Type and UserID are optional.
type Event struct {
	// Type is the event_type sent to Amplitude (e.g. "mcp_method_called").
	Type string
	// UserID identifies the actor — currently the MCP subscription_id.
	UserID string
	// Properties are arbitrary, JSON-serialisable event properties.
	Properties map[string]any
	// UserProperties, when non-nil, are attached to the event as Amplitude
	// user_properties — sticky on the user_id and inherited at query time
	// by all subsequent events. Typically set only on the first event of a
	// session (e.g. on `initialize` when client_name / client_version are
	// available) and left nil thereafter.
	UserProperties map[string]any
}

// Emitter is the minimal interface used by the rest of the server. It is
// intentionally narrow so the production amplitudeClient and the test/no-op
// implementations stay easy to swap.
type Emitter interface {
	// Emit enqueues an event for asynchronous delivery. It must not block.
	Emit(Event)

	// Close drains any in-flight events and stops background workers. It is
	// safe to call multiple times. Subsequent Emit calls after Close are
	// no-ops.
	Close(ctx context.Context) error
}

// Noop returns an Emitter that discards every event. Useful when telemetry
// is disabled (e.g. private mode, missing API key) or in tests that don't
// care about analytics output.
func Noop() Emitter { return noopEmitter{} }

type noopEmitter struct{}

func (noopEmitter) Emit(Event)                  {}
func (noopEmitter) Close(context.Context) error { return nil }
