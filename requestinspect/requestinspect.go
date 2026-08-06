// Package requestinspect is the hook the MCP server uses to hand incoming
// HTTP request metadata — the method, the URL, the original headers, and
// the TCP peer address — to the embedder for analysis and logging. It
// defines the Info shape and the Inspector interface; concrete
// implementations (audit logging, abuse detection, etc.) live in the
// embedder's repo and are plugged in via fpmcpserver.WithRequestInspector.
//
// Inspect runs synchronously on the request path, before authentication,
// for every HTTP request to the MCP endpoint. It never runs for the stdio
// transport, which carries no HTTP metadata. Inspection is fail-open: an
// Inspect error is logged by the server and the request proceeds, so
// returning an error can never reject traffic. Implementations should be
// fast and must not panic; anything slow (delivery, enrichment) belongs on
// a background worker.
package requestinspect

import (
	"context"
	"net/http"
	"net/url"
)

// Info is the metadata for a single incoming HTTP request.
type Info struct {
	// Method is the HTTP method of the request, e.g. "POST".
	Method string

	// URL is the request URL as parsed by net/http, passed by reference.
	// For server requests it typically contains only the path and query;
	// the host arrives separately (Host header / Request.Host). Treat it
	// as read-only: mutating it corrupts the request for downstream
	// handlers, and retaining it past the Inspect call requires a copy.
	URL *url.URL

	// Header is the original request header map as parsed by net/http,
	// unmodified by the server and passed by reference. Treat it as
	// read-only: mutating it corrupts the request for downstream
	// handlers, and retaining it past the Inspect call requires a
	// Clone().
	Header http.Header

	// RemoteIP is the IP of the direct TCP peer, without the port (IPv6
	// addresses are unbracketed). Behind a proxy or load balancer this
	// is the proxy's address; consult Header (e.g. X-Forwarded-For) for
	// client attribution. If the peer address has no parseable "ip:port"
	// form, RemoteIP carries the raw address string as-is.
	RemoteIP string

	// RemotePort is the source port of the direct TCP peer. Zero when
	// the peer address has no parseable "ip:port" form.
	RemotePort int
}

// Inspector receives request metadata for analysis and logging. It is kept
// narrow so recording fakes and real backends are all easy to substitute
// via WithRequestInspector.
type Inspector interface {
	// Inspect is called synchronously for every HTTP request to the MCP
	// endpoint, before authentication. ctx is the request context. An
	// error is logged by the server and the request proceeds
	// (fail-open).
	Inspect(ctx context.Context, info Info) error

	// Close drains any buffered work and stops background workers. Safe
	// to call multiple times; Inspect after Close is a no-op.
	Close(ctx context.Context) error
}
