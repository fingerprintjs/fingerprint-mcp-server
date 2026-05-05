package fpmcpserver

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/fingerprintjs/fingerprint-mcp-server/config"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// requestRecord stores a captured request for assertions.
type requestRecord struct {
	Method   string
	Path     string
	RawQuery string
	Header   http.Header
	Body     string
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
		Method:   r.Method,
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
		Header:   r.Header.Clone(),
		Body:     string(body),
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
		Method:   r.Method,
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
		Header:   r.Header.Clone(),
		Body:     string(body),
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

// setupStdioServer creates an App with the given config and runs it over
// in-memory transports that simulate a stdio connection, returning a connected
// client session.
func setupStdioServer(t *testing.T, cfg *config.Config) *mcp.ClientSession {
	t.Helper()

	app, err := New(cfg, &opts{})
	if err != nil {
		t.Fatalf("failed to create app: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	if err := app.registerTools(ctx); err != nil {
		t.Fatalf("failed to register tools: %v", err)
	}

	serverTransport, clientTransport := mcp.NewInMemoryTransports()

	go func() {
		_ = app.server.Run(ctx, serverTransport)
	}()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "v0.0.1"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("failed to connect to stdio server: %v", err)
	}
	t.Cleanup(func() { session.Close() })

	return session
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
