package fpmcpserver

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/fingerprintjs/fingerprint-mcp-server/config"
	"github.com/fingerprintjs/fingerprint-mcp-server/internal/analytics"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// requestRecord stores a captured request for assertions.
type requestRecord struct {
	Method string
	Path   string
	Header http.Header
	Body   string
}

// mockFingerprintAPI simulates the Fingerprint Server API.
type mockFingerprintAPI struct {
	server   *httptest.Server
	mu       sync.Mutex
	requests []requestRecord
	// If set, the mock returns this status code and body instead of the default.
	overrideStatus int
	overrideBody   string
}

func newMockFingerprintAPI() *mockFingerprintAPI {
	m := &mockFingerprintAPI{}
	mux := http.NewServeMux()

	// GET /v4/events/{event_id}
	mux.HandleFunc("/v4/events/", func(w http.ResponseWriter, r *http.Request) {
		m.recordRequest(r)

		if m.overrideStatus != 0 {
			w.WriteHeader(m.overrideStatus)
			_, _ = w.Write([]byte(m.overrideBody))
			return
		}

		// /v4/events is search, /v4/events/{id} is get
		eventID := strings.TrimPrefix(r.URL.Path, "/v4/events/")
		if eventID == "" || r.URL.Path == "/v4/events" {
			// search events
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(cannedSearchEventsResponse))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(cannedGetEventResponse))
	})

	// Also handle /v4/events (no trailing slash) for search
	mux.HandleFunc("/v4/events", func(w http.ResponseWriter, r *http.Request) {
		m.recordRequest(r)

		if m.overrideStatus != 0 {
			w.WriteHeader(m.overrideStatus)
			_, _ = w.Write([]byte(m.overrideBody))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(cannedSearchEventsResponse))
	})

	m.server = httptest.NewServer(mux)
	return m
}

func (m *mockFingerprintAPI) recordRequest(r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests = append(m.requests, requestRecord{
		Method: r.Method,
		Path:   r.URL.Path,
		Header: r.Header.Clone(),
		Body:   string(body),
	})
}

func (m *mockFingerprintAPI) lastRequest() requestRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.requests) == 0 {
		return requestRecord{}
	}
	return m.requests[len(m.requests)-1]
}

func (m *mockFingerprintAPI) close() {
	m.server.Close()
}

// mockManagementAPI simulates the Fingerprint Management API.
type mockManagementAPI struct {
	server   *httptest.Server
	mu       sync.Mutex
	requests []requestRecord
}

func newMockManagementAPI() *mockManagementAPI {
	m := &mockManagementAPI{}
	mux := http.NewServeMux()

	// Environments
	mux.HandleFunc("/environments", func(w http.ResponseWriter, r *http.Request) {
		m.recordRequest(r)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write([]byte(cannedListEnvironmentsResponse))
		case http.MethodPost:
			_, _ = w.Write([]byte(cannedCreateEnvironmentResponse))
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/environments/", func(w http.ResponseWriter, r *http.Request) {
		m.recordRequest(r)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodPost:
			_, _ = w.Write([]byte(cannedCreateEnvironmentResponse))
		case http.MethodDelete:
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	// API Keys
	mux.HandleFunc("/api-keys", func(w http.ResponseWriter, r *http.Request) {
		m.recordRequest(r)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write([]byte(cannedListAPIKeysResponse))
		case http.MethodPost:
			_, _ = w.Write([]byte(cannedCreateAPIKeyResponse))
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/api-keys/", func(w http.ResponseWriter, r *http.Request) {
		m.recordRequest(r)
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write([]byte(cannedGetAPIKeyResponse))
		case http.MethodPatch:
			_, _ = w.Write([]byte(cannedGetAPIKeyResponse))
		case http.MethodDelete:
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	m.server = httptest.NewServer(mux)
	return m
}

func (m *mockManagementAPI) recordRequest(r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests = append(m.requests, requestRecord{
		Method: r.Method,
		Path:   r.URL.Path,
		Header: r.Header.Clone(),
		Body:   string(body),
	})
}

func (m *mockManagementAPI) lastRequest() requestRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.requests) == 0 {
		return requestRecord{}
	}
	return m.requests[len(m.requests)-1]
}

func (m *mockManagementAPI) close() {
	m.server.Close()
}

// defaultAuthToken is the auth token used in private mode tests.
const defaultAuthToken = "test-auth-token"

// setupTestServer creates an App with the given config, registers tools, and returns an httptest.Server.
func setupTestServer(t *testing.T, cfg *config.Config) *httptest.Server {
	t.Helper()

	app, err := New(cfg, &opts{})
	if err != nil {
		t.Fatalf("failed to create app: %v", err)
	}

	ctx := context.Background()
	if err := app.registerTools(ctx); err != nil {
		t.Fatalf("failed to register tools: %v", err)
	}

	ts := httptest.NewServer(app.handler())
	t.Cleanup(ts.Close)
	return ts
}

// setupTestServerWithLogger is like setupTestServer but also registers
// resources and prompts and uses the given logger so tests can inspect
// what loggingMiddleware emits.
func setupTestServerWithLogger(t *testing.T, cfg *config.Config, logger *slog.Logger) *httptest.Server {
	t.Helper()

	app, err := New(cfg, &opts{l: logger})
	if err != nil {
		t.Fatalf("failed to create app: %v", err)
	}

	ctx := context.Background()
	if err := app.registerTools(ctx); err != nil {
		t.Fatalf("failed to register tools: %v", err)
	}
	if err := app.registerResources(ctx); err != nil {
		t.Fatalf("failed to register resources: %v", err)
	}
	if err := app.registerPrompts(ctx); err != nil {
		t.Fatalf("failed to register prompts: %v", err)
	}

	ts := httptest.NewServer(app.handler())
	t.Cleanup(ts.Close)
	return ts
}

// captureHandler is a slog.Handler that records every Handle call so tests
// can assert on log attributes. It correctly carries through accumulated
// attributes from Logger.With(...). WithGroup is intentionally not supported
// because the production logging in this package never calls it; if that
// changes in the future, callers will see the panic and update this fixture
// rather than silently lose attribute keys.
type captureHandler struct {
	state *captureState
	attrs []slog.Attr
}

type captureState struct {
	mu      sync.Mutex
	records []slog.Record
}

func newCaptureHandler() *captureHandler {
	return &captureHandler{state: &captureState{}}
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	// Build a record that includes the accumulated attrs so With(...) chains
	// don't silently drop attributes during assertion.
	out := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	for _, a := range h.attrs {
		out.AddAttrs(a)
	}
	r.Attrs(func(a slog.Attr) bool {
		out.AddAttrs(a)
		return true
	})

	h.state.mu.Lock()
	defer h.state.mu.Unlock()
	h.state.records = append(h.state.records, out.Clone())
	return nil
}

func (h *captureHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	merged := make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	merged = append(merged, h.attrs...)
	merged = append(merged, attrs...)
	return &captureHandler{state: h.state, attrs: merged}
}

func (h *captureHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	panic("captureHandler does not implement WithGroup; extend the fixture if production logging starts using groups")
}

func (h *captureHandler) snapshot() []slog.Record {
	h.state.mu.Lock()
	defer h.state.mu.Unlock()
	out := make([]slog.Record, len(h.state.records))
	copy(out, h.state.records)
	return out
}

// recordAttrs flattens an slog.Record's attributes into a map for assertions.
func recordAttrs(r slog.Record) map[string]any {
	attrs := map[string]any{}
	r.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.Any()
		return true
	})
	return attrs
}

// mockAmplitude simulates the Amplitude HTTP V2 endpoints (events + identify).
// Mirrors the shape of mockFingerprintAPI so analytics tests follow the same
// recording-and-assertion pattern as the rest of the suite.
type mockAmplitude struct {
	server   *httptest.Server
	mu       sync.Mutex
	requests []requestRecord
}

func newMockAmplitude() *mockAmplitude {
	m := &mockAmplitude{}
	mux := http.NewServeMux()
	record := func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		m.mu.Lock()
		m.requests = append(m.requests, requestRecord{
			Method: r.Method,
			Path:   r.URL.Path,
			Header: r.Header.Clone(),
			Body:   string(body),
		})
		m.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}
	mux.HandleFunc("/2/httpapi", record)
	mux.HandleFunc("/identify", record)
	m.server = httptest.NewServer(mux)
	return m
}

func (m *mockAmplitude) close()              { m.server.Close() }
func (m *mockAmplitude) eventsURL() string   { return m.server.URL + "/2/httpapi" }
func (m *mockAmplitude) identifyURL() string { return m.server.URL + "/identify" }

func (m *mockAmplitude) snapshot() []requestRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]requestRecord, len(m.requests))
	copy(out, m.requests)
	return out
}

// setupTestServerWithEmitter is like setupTestServer but injects a custom
// analytics.Emitter via opts and registers tools/resources/prompts so a single
// test can exercise every method category that the analytics middleware fires
// for.
func setupTestServerWithEmitter(t *testing.T, cfg *config.Config, emitter analytics.Emitter) *httptest.Server {
	t.Helper()

	app, err := New(cfg, &opts{emitter: emitter})
	if err != nil {
		t.Fatalf("failed to create app: %v", err)
	}

	ctx := context.Background()
	if err := app.registerTools(ctx); err != nil {
		t.Fatalf("failed to register tools: %v", err)
	}
	if err := app.registerResources(ctx); err != nil {
		t.Fatalf("failed to register resources: %v", err)
	}
	if err := app.registerPrompts(ctx); err != nil {
		t.Fatalf("failed to register prompts: %v", err)
	}

	ts := httptest.NewServer(app.handler())
	t.Cleanup(ts.Close)
	return ts
}

// authRoundTripper injects an Authorization: Bearer header into all requests.
type authRoundTripper struct {
	token string
	base  http.RoundTripper
}

func (a *authRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
	}
	return a.base.RoundTrip(req)
}

// tryConnectMCPClient creates an MCP client session with bearer token auth.
// Returns the session and any connection error.
func tryConnectMCPClient(t *testing.T, serverURL string, token string) (*mcp.ClientSession, error) {
	t.Helper()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "v0.0.1"}, nil)

	transport := &mcp.StreamableClientTransport{
		Endpoint: serverURL + "/mcp",
		HTTPClient: &http.Client{
			Transport: &authRoundTripper{token: token, base: http.DefaultTransport},
		},
	}

	session, err := client.Connect(context.Background(), transport, nil)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { session.Close() })
	return session, nil
}

// mustConnectMCPClient creates an MCP client session with bearer token auth.
// Fatals on connection failure.
func mustConnectMCPClient(t *testing.T, serverURL string, token string) *mcp.ClientSession {
	t.Helper()
	session, err := tryConnectMCPClient(t, serverURL, token)
	if err != nil {
		t.Fatalf("failed to connect MCP client: %v", err)
	}
	return session
}

// toolNames extracts tool names from a ListToolsResult.
func toolNames(result *mcp.ListToolsResult) []string {
	names := make([]string, len(result.Tools))
	for i, tool := range result.Tools {
		names[i] = tool.Name
	}
	return names
}

// callTool calls a tool and returns the result and any protocol-level error.
func callTool(t *testing.T, session *mcp.ClientSession, toolName string, args map[string]any) (*mcp.CallToolResult, error) {
	t.Helper()
	return session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      toolName,
		Arguments: args,
	})
}

// mustCallTool calls a tool and fatals on protocol-level error.
func mustCallTool(t *testing.T, session *mcp.ClientSession, toolName string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	result, err := callTool(t, session, toolName, args)
	if err != nil {
		t.Fatalf("CallTool(%s) failed: %v", toolName, err)
	}
	return result
}

// extractTextContent gets the first text content from a CallToolResult.
func extractTextContent(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	for _, c := range result.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			return tc.Text
		}
	}
	t.Fatal("no text content found in result")
	return ""
}

// --- Canned JSON responses ---

const cannedGetEventResponse = `{
	"event_id": "test-event-123",
	"timestamp": 1700000000000,
	"identification": {
		"visitor_id": "test-visitor-id",
		"visitor_found": true
	}
}`

const cannedSearchEventsResponse = `{
	"events": [
		{
			"event_id": "search-event-1",
			"timestamp": 1700000000000,
			"identification": {
				"visitor_id": "search-visitor",
				"visitor_found": true
			}
		}
	]
}`

const cannedListEnvironmentsResponse = `{
	"data": [
		{
			"id": "env-1",
			"name": "Production",
			"description": "Production environment",
			"limit_mode": "none",
			"limit_value": 0,
			"is_restricted": false,
			"restricted_at": null,
			"created_at": "2023-01-01T00:00:00Z",
			"updated_at": null
		}
	],
	"metadata": {
		"pagination": {
			"next_cursor": null,
			"prev_cursor": null
		}
	}
}`

const cannedCreateEnvironmentResponse = `{
	"data": {
		"id": "env-new",
		"name": "Staging",
		"description": "Staging environment",
		"limit_mode": "none",
		"limit_value": 0,
		"is_restricted": false,
		"restricted_at": null,
		"created_at": "2024-01-01T00:00:00Z",
		"updated_at": null
	}
}`

const cannedListAPIKeysResponse = `{
	"data": [
		{
			"id": "key-1",
			"name": "My Key",
			"description": "Test key",
			"status": "enabled",
			"environment": null,
			"type": "public",
			"token": "pub_xxx",
			"rate_limit": 10,
			"created_at": "2023-01-01T00:00:00Z",
			"disabled_at": null
		}
	],
	"metadata": {
		"pagination": {
			"next_cursor": null,
			"prev_cursor": null
		}
	}
}`

const cannedGetAPIKeyResponse = `{
	"data": {
		"id": "key-1",
		"name": "My Key",
		"description": "Test key",
		"status": "enabled",
		"environment": null,
		"type": "public",
		"token": "pub_xxx",
		"rate_limit": 10,
		"created_at": "2023-01-01T00:00:00Z",
		"disabled_at": null
	}
}`

const cannedCreateAPIKeyResponse = `{
	"data": {
		"id": "key-new",
		"name": "New Key",
		"description": "",
		"status": "enabled",
		"environment": null,
		"type": "secret",
		"token": "sec_xxx_visible_at_creation",
		"rate_limit": 5,
		"created_at": "2024-01-01T00:00:00Z",
		"disabled_at": null
	}
}`
