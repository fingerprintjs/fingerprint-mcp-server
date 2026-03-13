package fpmcpserver

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/fingerprintjs/fingerprint-mcp-server/config"
)

// --- Group 1: ListTools ---

func TestListTools_PrivateMode_BothKeys(t *testing.T) {
	fpAPI := newMockFingerprintAPI()
	defer fpAPI.close()
	mgmtAPI := newMockManagementAPI()
	defer mgmtAPI.close()

	ts := setupTestServer(t, &config.Config{
		AuthToken:        defaultAuthToken,
		ServerAPIKey:     "test-server-key",
		ServerAPIURL:     fpAPI.server.URL + "/v4",
		ManagementAPIKey: "test-mgmt-key",
		ManagementAPIURL: mgmtAPI.server.URL,
		Region:           "us",
	})

	session := mustConnectMCPClient(t, ts.URL, defaultAuthToken)
	result, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}

	names := toolNames(result)
	if len(names) != 11 {
		t.Errorf("expected 11 tools, got %d: %v", len(names), names)
	}
}

func TestListTools_PrivateMode_ServerKeyOnly(t *testing.T) {
	fpAPI := newMockFingerprintAPI()
	defer fpAPI.close()

	ts := setupTestServer(t, &config.Config{
		AuthToken:    defaultAuthToken,
		ServerAPIKey: "test-server-key",
		ServerAPIURL: fpAPI.server.URL + "/v4",
		Region:       "us",
	})

	session := mustConnectMCPClient(t, ts.URL, defaultAuthToken)
	result, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}

	names := toolNames(result)
	expected := []string{"get_event", "search_events"}
	if len(names) != len(expected) {
		t.Errorf("expected %d tools, got %d: %v", len(expected), len(names), names)
	}
	for _, e := range expected {
		if !slices.Contains(names, e) {
			t.Errorf("expected tool %q not found in %v", e, names)
		}
	}
}

func TestListTools_PrivateMode_MgmtKeyOnly(t *testing.T) {
	mgmtAPI := newMockManagementAPI()
	defer mgmtAPI.close()

	ts := setupTestServer(t, &config.Config{
		AuthToken:        defaultAuthToken,
		ManagementAPIKey: "test-mgmt-key",
		ManagementAPIURL: mgmtAPI.server.URL,
	})

	session := mustConnectMCPClient(t, ts.URL, defaultAuthToken)
	result, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}

	names := toolNames(result)
	expected := []string{
		"list_environments", "create_environment", "update_environment", "delete_environment",
		"list_api_keys", "get_api_key", "create_api_key", "update_api_key", "delete_api_key",
	}
	if len(names) != len(expected) {
		t.Errorf("expected %d tools, got %d: %v", len(expected), len(names), names)
	}
	for _, e := range expected {
		if !slices.Contains(names, e) {
			t.Errorf("expected tool %q not found in %v", e, names)
		}
	}
}

func TestListTools_PrivateMode_ReadOnly(t *testing.T) {
	fpAPI := newMockFingerprintAPI()
	defer fpAPI.close()
	mgmtAPI := newMockManagementAPI()
	defer mgmtAPI.close()

	ts := setupTestServer(t, &config.Config{
		AuthToken:        defaultAuthToken,
		ServerAPIKey:     "test-server-key",
		ServerAPIURL:     fpAPI.server.URL + "/v4",
		ManagementAPIKey: "test-mgmt-key",
		ManagementAPIURL: mgmtAPI.server.URL,
		Region:           "us",
		ReadOnly:         true,
	})

	session := mustConnectMCPClient(t, ts.URL, defaultAuthToken)
	result, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}

	names := toolNames(result)
	expected := []string{"get_event", "search_events", "list_environments", "list_api_keys", "get_api_key"}
	if len(names) != len(expected) {
		t.Errorf("expected %d tools, got %d: %v", len(expected), len(names), names)
	}
	for _, e := range expected {
		if !slices.Contains(names, e) {
			t.Errorf("expected tool %q not found in %v", e, names)
		}
	}
}

func TestListTools_PublicMode(t *testing.T) {
	ts := setupTestServer(t, &config.Config{
		PublicMode: true,
	})

	session := mustConnectMCPClient(t, ts.URL, "srvKey-mgmtKey-us")
	result, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}

	names := toolNames(result)
	if len(names) != 11 {
		t.Errorf("expected 11 tools in public mode, got %d: %v", len(names), names)
	}
}

// --- Group 2: Authentication ---

func TestAuth_PrivateMode_ValidToken(t *testing.T) {
	fpAPI := newMockFingerprintAPI()
	defer fpAPI.close()
	mgmtAPI := newMockManagementAPI()
	defer mgmtAPI.close()

	ts := setupTestServer(t, &config.Config{
		AuthToken:        "secret",
		ServerAPIKey:     "test-server-key",
		ServerAPIURL:     fpAPI.server.URL + "/v4",
		ManagementAPIKey: "test-mgmt-key",
		ManagementAPIURL: mgmtAPI.server.URL,
		Region:           "us",
	})

	session := mustConnectMCPClient(t, ts.URL, "secret")
	result, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}
	if len(result.Tools) != 11 {
		t.Errorf("expected 11 tools but got %d", len(result.Tools))
	}
}

func TestAuth_PrivateMode_InvalidToken(t *testing.T) {
	ts := setupTestServer(t, &config.Config{
		ServerAPIKey: "test-server-key",
		Region:       "us",
		AuthToken:    "secret",
	})

	_, err := tryConnectMCPClient(t, ts.URL, "wrong")
	if err == nil {
		t.Fatal("expected connection to fail with invalid token")
	}
	if !strings.Contains(err.Error(), "Unauthorized") {
		t.Errorf("expected Unauthorized error, got: %v", err)
	}
}

func TestAuth_PrivateMode_NoToken(t *testing.T) {
	ts := setupTestServer(t, &config.Config{
		ServerAPIKey: "test-server-key",
		Region:       "us",
		AuthToken:    "secret",
	})

	// Empty token — authRoundTripper skips the Authorization header
	_, err := tryConnectMCPClient(t, ts.URL, "")
	if err == nil {
		t.Fatal("expected connection to fail without token")
	}
	if !strings.Contains(err.Error(), "Unauthorized") {
		t.Errorf("expected Unauthorized error, got: %v", err)
	}
}

func TestAuth_PublicMode_SimpleToken(t *testing.T) {
	ts := setupTestServer(t, &config.Config{
		PublicMode: true,
	})

	session := mustConnectMCPClient(t, ts.URL, "srvKey-mgmtKey-us")
	result, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}
	if len(result.Tools) == 0 {
		t.Error("expected tools but got none")
	}
}

func TestAuth_PublicMode_AllEmpty(t *testing.T) {
	ts := setupTestServer(t, &config.Config{
		PublicMode: true,
	})

	// "--" means all parts empty → should be rejected
	_, err := tryConnectMCPClient(t, ts.URL, "--")
	if err == nil {
		t.Fatal("expected connection to fail with all-empty token")
	}
	if !strings.Contains(err.Error(), "Unauthorized") {
		t.Errorf("expected Unauthorized error, got: %v", err)
	}
}

func TestAuth_PublicMode_PartialToken_ServerOnly(t *testing.T) {
	fpAPI := newMockFingerprintAPI()
	defer fpAPI.close()

	ts := setupTestServer(t, &config.Config{
		PublicMode:   true,
		ServerAPIURL: fpAPI.server.URL + "/v4",
	})

	session := mustConnectMCPClient(t, ts.URL, "srvKey--us")
	// Event tools should work
	result := mustCallTool(t, session, "get_event", map[string]any{"event_id": "test-123"})
	if result.IsError {
		t.Errorf("get_event should succeed with server key: %v", extractTextContent(t, result))
	}

	// Management tools should fail (no mgmt key)
	result2 := mustCallTool(t, session, "list_environments", map[string]any{})
	if !result2.IsError {
		t.Error("list_environments should fail without mgmt key")
	}
}

func TestAuth_PublicMode_PartialToken_MgmtOnly(t *testing.T) {
	mgmtAPI := newMockManagementAPI()
	defer mgmtAPI.close()

	ts := setupTestServer(t, &config.Config{
		PublicMode:       true,
		ManagementAPIURL: mgmtAPI.server.URL,
	})

	session := mustConnectMCPClient(t, ts.URL, "-mgmtKey-us")

	// Management tools should work
	result := mustCallTool(t, session, "list_environments", map[string]any{})
	if result.IsError {
		t.Errorf("list_environments should succeed with mgmt key: %v", extractTextContent(t, result))
	}

	// Event tools should fail (no server key)
	result2 := mustCallTool(t, session, "get_event", map[string]any{"event_id": "test-123"})
	if !result2.IsError {
		t.Error("get_event should fail without server key")
	}
}

func TestAuth_PublicMode_InvalidFormat(t *testing.T) {
	ts := setupTestServer(t, &config.Config{
		PublicMode: true,
	})

	_, err := tryConnectMCPClient(t, ts.URL, "too-many-dashes-here")
	if err == nil {
		t.Fatal("expected connection to fail with invalid format token")
	}
}

// --- Group 3: Event Tools ---

func TestGetEvent_Success(t *testing.T) {
	fpAPI := newMockFingerprintAPI()
	defer fpAPI.close()

	ts := setupTestServer(t, &config.Config{
		AuthToken:    defaultAuthToken,
		ServerAPIKey: "test-server-key",
		ServerAPIURL: fpAPI.server.URL + "/v4",
		Region:       "us",
	})

	session := mustConnectMCPClient(t, ts.URL, defaultAuthToken)
	result := mustCallTool(t, session, "get_event", map[string]any{"event_id": "test-event-123"})

	if result.IsError {
		t.Fatalf("expected success, got error: %v", extractTextContent(t, result))
	}

	// Verify the mock received the request
	req := fpAPI.lastRequest()
	if req.Path != "/v4/events/test-event-123" {
		t.Errorf("expected path /v4/events/test-event-123, got %s", req.Path)
	}

	// Verify auth header
	authHeader := req.Header.Get("Authorization")
	if authHeader != "Bearer test-server-key" {
		t.Errorf("expected Authorization 'Bearer test-server-key', got %q", authHeader)
	}
}

func TestGetEvent_EmptyEventID(t *testing.T) {
	fpAPI := newMockFingerprintAPI()
	defer fpAPI.close()

	ts := setupTestServer(t, &config.Config{
		AuthToken:    defaultAuthToken,
		ServerAPIKey: "test-server-key",
		ServerAPIURL: fpAPI.server.URL + "/v4",
		Region:       "us",
	})

	session := mustConnectMCPClient(t, ts.URL, defaultAuthToken)
	result := mustCallTool(t, session, "get_event", map[string]any{"event_id": ""})

	if !result.IsError {
		t.Error("expected error for empty event_id")
	}
	text := extractTextContent(t, result)
	if !strings.Contains(text, "event_id is required") {
		t.Errorf("expected 'event_id is required' error, got: %s", text)
	}
}

func TestGetEvent_APIError(t *testing.T) {
	fpAPI := newMockFingerprintAPI()
	defer fpAPI.close()
	fpAPI.overrideStatus = 404
	fpAPI.overrideBody = `{"error": {"code": "EventNotFound", "message": "event not found"}}`

	ts := setupTestServer(t, &config.Config{
		AuthToken:    defaultAuthToken,
		ServerAPIKey: "test-server-key",
		ServerAPIURL: fpAPI.server.URL + "/v4",
		Region:       "us",
	})

	session := mustConnectMCPClient(t, ts.URL, defaultAuthToken)
	result := mustCallTool(t, session, "get_event", map[string]any{"event_id": "nonexistent"})

	if !result.IsError {
		t.Error("expected error for 404 API response")
	}
}

func TestGetEvent_PublicMode_KeyExtraction(t *testing.T) {
	fpAPI := newMockFingerprintAPI()
	defer fpAPI.close()

	ts := setupTestServer(t, &config.Config{
		PublicMode:   true,
		ServerAPIURL: fpAPI.server.URL + "/v4",
	})

	// Bearer "testKey-mgmt-us" → server key should be "testKey"
	session := mustConnectMCPClient(t, ts.URL, "testKey-mgmt-us")
	result := mustCallTool(t, session, "get_event", map[string]any{"event_id": "evt-1"})

	if result.IsError {
		t.Fatalf("expected success, got error: %v", extractTextContent(t, result))
	}

	req := fpAPI.lastRequest()
	authHeader := req.Header.Get("Authorization")
	if authHeader != "Bearer testKey" {
		t.Errorf("expected server API key 'Bearer testKey' from token, got %q", authHeader)
	}
}

func TestSearchEvents_Success(t *testing.T) {
	fpAPI := newMockFingerprintAPI()
	defer fpAPI.close()

	ts := setupTestServer(t, &config.Config{
		AuthToken:    defaultAuthToken,
		ServerAPIKey: "test-server-key",
		ServerAPIURL: fpAPI.server.URL + "/v4",
		Region:       "us",
	})

	session := mustConnectMCPClient(t, ts.URL, defaultAuthToken)
	limit := 10
	result := mustCallTool(t, session, "search_events", map[string]any{"limit": limit})

	if result.IsError {
		t.Fatalf("expected success, got error: %v", extractTextContent(t, result))
	}
}

func TestSearchEvents_ZeroLimit(t *testing.T) {
	fpAPI := newMockFingerprintAPI()
	defer fpAPI.close()

	ts := setupTestServer(t, &config.Config{
		AuthToken:    defaultAuthToken,
		ServerAPIKey: "test-server-key",
		ServerAPIURL: fpAPI.server.URL + "/v4",
		Region:       "us",
	})

	session := mustConnectMCPClient(t, ts.URL, defaultAuthToken)
	// The MCP SDK validates the schema before the handler runs,
	// so limit=0 with minimum:1 is rejected at protocol level.
	_, err := callTool(t, session, "search_events", map[string]any{"limit": 0})
	if err == nil {
		t.Error("expected error for zero limit")
	}
}

func TestGetEvent_PublicMode_InvalidRegion(t *testing.T) {
	fpAPI := newMockFingerprintAPI()
	defer fpAPI.close()

	ts := setupTestServer(t, &config.Config{
		PublicMode:   true,
		ServerAPIURL: fpAPI.server.URL + "/v4",
	})

	// Bearer "srvKey-mgmt-xx" → region "xx" is invalid
	session := mustConnectMCPClient(t, ts.URL, "srvKey-mgmt-xx")
	result := mustCallTool(t, session, "get_event", map[string]any{"event_id": "evt-1"})

	if !result.IsError {
		t.Fatal("expected error for invalid region")
	}
	text := extractTextContent(t, result)
	if !strings.Contains(text, "unknown region") {
		t.Errorf("expected 'unknown region' error, got: %s", text)
	}
}

// --- Group 4: Management Tools ---

func TestListEnvironments_Success(t *testing.T) {
	mgmtAPI := newMockManagementAPI()
	defer mgmtAPI.close()

	ts := setupTestServer(t, &config.Config{
		AuthToken:        defaultAuthToken,
		ManagementAPIKey: "test-mgmt-key",
		ManagementAPIURL: mgmtAPI.server.URL,
	})

	session := mustConnectMCPClient(t, ts.URL, defaultAuthToken)
	result := mustCallTool(t, session, "list_environments", map[string]any{})

	if result.IsError {
		t.Fatalf("expected success, got error: %v", extractTextContent(t, result))
	}

	// Verify the mock received the correct auth header
	req := mgmtAPI.lastRequest()
	authHeader := req.Header.Get("Authorization")
	if authHeader != "Bearer test-mgmt-key" {
		t.Errorf("expected Authorization 'Bearer test-mgmt-key', got %q", authHeader)
	}
	apiVersion := req.Header.Get("X-API-Version")
	if apiVersion != "2025-11-20" {
		t.Errorf("expected X-API-Version '2025-11-20', got %q", apiVersion)
	}
}

func TestCreateEnvironment_Success(t *testing.T) {
	mgmtAPI := newMockManagementAPI()
	defer mgmtAPI.close()

	ts := setupTestServer(t, &config.Config{
		AuthToken:        defaultAuthToken,
		ManagementAPIKey: "test-mgmt-key",
		ManagementAPIURL: mgmtAPI.server.URL,
	})

	session := mustConnectMCPClient(t, ts.URL, defaultAuthToken)
	result := mustCallTool(t, session, "create_environment", map[string]any{
		"name":        "Staging",
		"description": "Staging env",
	})

	if result.IsError {
		t.Fatalf("expected success, got error: %v", extractTextContent(t, result))
	}

	// Verify mock received the request body
	req := mgmtAPI.lastRequest()
	if !strings.Contains(req.Body, `"name":"Staging"`) {
		t.Errorf("expected request body to contain name, got: %s", req.Body)
	}
}

func TestCreateEnvironment_EmptyName(t *testing.T) {
	mgmtAPI := newMockManagementAPI()
	defer mgmtAPI.close()

	ts := setupTestServer(t, &config.Config{
		AuthToken:        defaultAuthToken,
		ManagementAPIKey: "test-mgmt-key",
		ManagementAPIURL: mgmtAPI.server.URL,
	})

	session := mustConnectMCPClient(t, ts.URL, defaultAuthToken)
	result := mustCallTool(t, session, "create_environment", map[string]any{"name": ""})

	if !result.IsError {
		t.Error("expected error for empty name")
	}
	text := extractTextContent(t, result)
	if !strings.Contains(text, "name is required") {
		t.Errorf("expected 'name is required' error, got: %s", text)
	}
}

func TestDeleteEnvironment_Success(t *testing.T) {
	mgmtAPI := newMockManagementAPI()
	defer mgmtAPI.close()

	ts := setupTestServer(t, &config.Config{
		AuthToken:        defaultAuthToken,
		ManagementAPIKey: "test-mgmt-key",
		ManagementAPIURL: mgmtAPI.server.URL,
	})

	session := mustConnectMCPClient(t, ts.URL, defaultAuthToken)
	result := mustCallTool(t, session, "delete_environment", map[string]any{"id": "env-1"})

	if result.IsError {
		t.Fatalf("expected success, got error: %v", extractTextContent(t, result))
	}

	text := extractTextContent(t, result)
	if !strings.Contains(text, "deleted successfully") {
		t.Errorf("expected success message, got: %s", text)
	}
}

func TestListAPIKeys_Success(t *testing.T) {
	mgmtAPI := newMockManagementAPI()
	defer mgmtAPI.close()

	ts := setupTestServer(t, &config.Config{
		AuthToken:        defaultAuthToken,
		ManagementAPIKey: "test-mgmt-key",
		ManagementAPIURL: mgmtAPI.server.URL,
	})

	session := mustConnectMCPClient(t, ts.URL, defaultAuthToken)
	result := mustCallTool(t, session, "list_api_keys", map[string]any{})

	if result.IsError {
		t.Fatalf("expected success, got error: %v", extractTextContent(t, result))
	}
}

func TestGetAPIKey_Success(t *testing.T) {
	mgmtAPI := newMockManagementAPI()
	defer mgmtAPI.close()

	ts := setupTestServer(t, &config.Config{
		AuthToken:        defaultAuthToken,
		ManagementAPIKey: "test-mgmt-key",
		ManagementAPIURL: mgmtAPI.server.URL,
	})

	session := mustConnectMCPClient(t, ts.URL, defaultAuthToken)
	result := mustCallTool(t, session, "get_api_key", map[string]any{"id": "key-1"})

	if result.IsError {
		t.Fatalf("expected success, got error: %v", extractTextContent(t, result))
	}
}

func TestCreateAPIKey_Success(t *testing.T) {
	mgmtAPI := newMockManagementAPI()
	defer mgmtAPI.close()

	ts := setupTestServer(t, &config.Config{
		AuthToken:        defaultAuthToken,
		ManagementAPIKey: "test-mgmt-key",
		ManagementAPIURL: mgmtAPI.server.URL,
	})

	session := mustConnectMCPClient(t, ts.URL, defaultAuthToken)
	result := mustCallTool(t, session, "create_api_key", map[string]any{
		"type": "secret",
		"name": "New Key",
	})

	if result.IsError {
		t.Fatalf("expected success, got error: %v", extractTextContent(t, result))
	}

	// Verify mock received the request body
	req := mgmtAPI.lastRequest()
	if !strings.Contains(req.Body, `"type":"secret"`) {
		t.Errorf("expected request body to contain type, got: %s", req.Body)
	}
	if !strings.Contains(req.Body, `"name":"New Key"`) {
		t.Errorf("expected request body to contain name, got: %s", req.Body)
	}
}

func TestDeleteAPIKey_Success(t *testing.T) {
	mgmtAPI := newMockManagementAPI()
	defer mgmtAPI.close()

	ts := setupTestServer(t, &config.Config{
		AuthToken:        defaultAuthToken,
		ManagementAPIKey: "test-mgmt-key",
		ManagementAPIURL: mgmtAPI.server.URL,
	})

	session := mustConnectMCPClient(t, ts.URL, defaultAuthToken)
	result := mustCallTool(t, session, "delete_api_key", map[string]any{"id": "key-1"})

	if result.IsError {
		t.Fatalf("expected success, got error: %v", extractTextContent(t, result))
	}

	text := extractTextContent(t, result)
	if !strings.Contains(text, "deleted successfully") {
		t.Errorf("expected success message, got: %s", text)
	}
}

func TestMgmtTool_PublicMode_KeyExtraction(t *testing.T) {
	mgmtAPI := newMockManagementAPI()
	defer mgmtAPI.close()

	ts := setupTestServer(t, &config.Config{
		PublicMode:       true,
		ManagementAPIURL: mgmtAPI.server.URL,
	})

	// Bearer "srv-mgmtTestKey-us" → mgmt key should be "mgmtTestKey"
	session := mustConnectMCPClient(t, ts.URL, "srv-mgmtTestKey-us")
	result := mustCallTool(t, session, "list_environments", map[string]any{})

	if result.IsError {
		t.Fatalf("expected success, got error: %v", extractTextContent(t, result))
	}

	req := mgmtAPI.lastRequest()
	authHeader := req.Header.Get("Authorization")
	if authHeader != "Bearer mgmtTestKey" {
		t.Errorf("expected mgmt API key 'Bearer mgmtTestKey' from token, got %q", authHeader)
	}
}

func TestMgmtTool_PublicMode_NoMgmtKey(t *testing.T) {
	ts := setupTestServer(t, &config.Config{
		PublicMode: true,
	})

	// Bearer "srvKey--us" → no mgmt key
	session := mustConnectMCPClient(t, ts.URL, "srvKey--us")
	result := mustCallTool(t, session, "list_environments", map[string]any{})

	if !result.IsError {
		t.Error("expected error when no mgmt key in token")
	}
	text := extractTextContent(t, result)
	if !strings.Contains(text, "management API key is required") {
		t.Errorf("expected 'management API key is required' error, got: %s", text)
	}
}

// --- Group 5: HTTP Endpoints ---

func TestHealthEndpoint(t *testing.T) {
	ts := setupTestServer(t, &config.Config{
		AuthToken: defaultAuthToken,
	})

	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("health request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestCORS_Options_PublicMode(t *testing.T) {
	ts := setupTestServer(t, &config.Config{
		PublicMode: true,
	})

	req, _ := http.NewRequest(http.MethodOptions, ts.URL+"/mcp", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("OPTIONS request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("expected 204, got %d", resp.StatusCode)
	}

	if origin := resp.Header.Get("Access-Control-Allow-Origin"); origin != "*" {
		t.Errorf("expected CORS origin *, got %q", origin)
	}

	allowHeaders := resp.Header.Get("Access-Control-Allow-Headers")
	if !strings.Contains(allowHeaders, "Authorization") {
		t.Errorf("expected Authorization in allowed headers, got %q", allowHeaders)
	}
}

func TestCORS_Options_PrivateMode(t *testing.T) {
	ts := setupTestServer(t, &config.Config{})

	req, _ := http.NewRequest(http.MethodOptions, ts.URL+"/mcp", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("OPTIONS request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("expected 204, got %d", resp.StatusCode)
	}

	allowHeaders := resp.Header.Get("Access-Control-Allow-Headers")
	if strings.Contains(allowHeaders, "Authorization") {
		t.Errorf("expected Authorization NOT in allowed headers for private mode, got %q", allowHeaders)
	}
}
