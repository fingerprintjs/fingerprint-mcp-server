package requestinspect_test

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"

	fpmcpserver "github.com/fingerprintjs/fingerprint-mcp-server"
	"github.com/fingerprintjs/fingerprint-mcp-server/config"
	"github.com/fingerprintjs/fingerprint-mcp-server/requestinspect"
)

// auditInspector is an example embedder-side Inspector: the shape a real
// implementation (e.g. audit logging in the hosted build's private repo)
// is expected to take.
//
// Inspect runs synchronously on the request path, so it does only two
// cheap things: redact-and-clone the headers, and hand the metadata to a
// bounded queue consumed by a background worker. When the queue is
// saturated it drops the metadata and returns an error — the server logs
// that error and serves the request anyway (fail-open), so a struggling
// audit backend can never take down the MCP endpoint.
type auditInspector struct {
	logger *slog.Logger
	queue  chan requestinspect.Info
	stop   chan struct{} // closed by Close
	done   chan struct{} // closed when the worker exits
	once   sync.Once
}

func newAuditInspector(logger *slog.Logger, queueSize int) *auditInspector {
	a := &auditInspector{
		logger: logger,
		queue:  make(chan requestinspect.Info, queueSize),
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
	}
	go a.worker()
	return a
}

// redactHeaders strips credentials before the metadata is retained or
// shipped anywhere. The server passes headers verbatim — including
// Authorization — and leaves redaction policy to the embedder. Clone()
// also satisfies the read-only contract: the live map belongs to the
// in-flight request and must not be retained or mutated.
func redactHeaders(h http.Header) http.Header {
	out := h.Clone()
	for _, k := range []string{"Authorization", "Cookie", "Proxy-Authorization"} {
		if out.Get(k) != "" {
			out.Set(k, "[redacted]")
		}
	}
	return out
}

func (a *auditInspector) Inspect(_ context.Context, info requestinspect.Info) error {
	info.Header = redactHeaders(info.Header)
	// The URL is also passed by reference and must be copied before the
	// metadata is retained past this call.
	if info.URL != nil {
		u := *info.URL
		info.URL = &u
	}

	select {
	case a.queue <- info:
		return nil
	case <-a.stop:
		return nil // closed; Inspect is a no-op per the contract
	default:
		// Queue saturated: drop and tell the server. The server logs the
		// error and the request proceeds (fail-open).
		return fmt.Errorf("audit queue full, dropped metadata for %s", info.RemoteIP)
	}
}

func (a *auditInspector) Close(ctx context.Context) error {
	a.once.Do(func() { close(a.stop) })
	select {
	case <-a.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (a *auditInspector) worker() {
	defer close(a.done)
	for {
		select {
		case info := <-a.queue:
			a.deliver(info)
		case <-a.stop:
			// Drain whatever is already buffered, then exit.
			for {
				select {
				case info := <-a.queue:
					a.deliver(info)
				default:
					return
				}
			}
		}
	}
}

// deliver is the stand-in for a real backend (SIEM, object storage, ...).
// RemoteIP/RemotePort are the direct TCP peer; behind a load balancer the
// original client address is in X-Forwarded-For, which the embedder is
// responsible for parsing and trusting (or not).
func (a *auditInspector) deliver(info requestinspect.Info) {
	a.logger.Info("mcp request audit",
		"method", info.Method,
		"url", info.URL.String(),
		"remote_ip", info.RemoteIP,
		"remote_port", info.RemotePort,
		"forwarded_for", info.Header.Get("X-Forwarded-For"),
		"user_agent", info.Header.Get("User-Agent"),
		"header_count", len(info.Header),
	)
}

// Example shows how an embedder implements the Inspector contract and
// wires it into the server. It is compiled (so it cannot rot) but not
// executed by go test, since it has no output comment.
func Example() {
	logger := slog.Default()
	inspector := newAuditInspector(logger, 1024)

	cfg := &config.Config{
		Transport:  "streamable-http",
		PublicMode: true,
	}

	// Run blocks until the server exits and drains the inspector via
	// Close on every exit path. Typically paired with
	// fpmcpserver.WithAnalytics(...) in the hosted build.
	if err := fpmcpserver.Run(context.Background(), cfg,
		fpmcpserver.WithLogger(logger),
		fpmcpserver.WithRequestInspector(inspector),
	); err != nil {
		logger.Error("server exited", "err", err)
	}
}
