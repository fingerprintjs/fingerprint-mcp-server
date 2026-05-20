// Package analytics is the hook the MCP server uses to emit product
// telemetry. It defines the Event shape and the Emitter interface; concrete
// backends (Amplitude, Datadog, etc.) live in the embedder's repo and are
// plugged in via fpmcpserver.WithAnalytics.
//
// Emit must never block the request path, must not propagate transient
// delivery failures back to the caller, and must drop events under
// sustained pressure rather than holding goroutines.
package analytics

import "context"

// Event is a single analytics event. Only Type and SubscriptionID are
// required; the rest pass through to the backend as the implementation sees
// fit.
type Event struct {
	// Type is the event name, e.g. "mcp_method_called".
	Type string
	// SubscriptionID is the Fingerprint subscription this event is
	// attributed to. Required.
	SubscriptionID string
	// Properties are arbitrary, JSON-serialisable event properties.
	Properties map[string]any
}

// Emitter is the minimum surface the server needs to deliver events. It is
// kept narrow so the no-op default, recording fakes, and real backends are
// all easy to substitute via WithAnalytics.
type Emitter interface {
	// Emit enqueues an event for asynchronous delivery. Must not block.
	Emit(Event)

	// Close drains any in-flight events and stops background workers. Safe
	// to call multiple times; Emit after Close is a no-op.
	Close(ctx context.Context) error
}

// Noop returns an Emitter that discards every event. The server uses it by
// default when no other emitter is wired up.
func Noop() Emitter { return noopEmitter{} }

type noopEmitter struct{}

func (noopEmitter) Emit(Event)                  {}
func (noopEmitter) Close(context.Context) error { return nil }
