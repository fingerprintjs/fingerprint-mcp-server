package fpmcpserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/fingerprintjs/fingerprint-mcp-server/config"
	"github.com/fingerprintjs/fingerprint-mcp-server/internal/analytics"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/modelcontextprotocol/go-sdk/mcp"
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

func TestListTools_PrivateMode_ToolsFilter(t *testing.T) {
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
		Tools:            []string{"get_event", "create_environment", "delete_api_key"},
	})

	session := mustConnectMCPClient(t, ts.URL, defaultAuthToken)
	result, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}

	names := toolNames(result)
	expected := []string{"get_event", "create_environment", "delete_api_key"}
	if len(names) != len(expected) {
		t.Errorf("expected %d tools, got %d: %v", len(expected), len(names), names)
	}
	for _, e := range expected {
		if !slices.Contains(names, e) {
			t.Errorf("expected tool %q not found in %v", e, names)
		}
	}
}

func TestListTools_PrivateMode_ToolsOverridesReadOnly(t *testing.T) {
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
		Tools:            []string{"get_event", "create_environment"},
	})

	session := mustConnectMCPClient(t, ts.URL, defaultAuthToken)
	result, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}

	names := toolNames(result)
	expected := []string{"get_event", "create_environment"}
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
	privKey, pubPEM := generateES256KeyPEM(t)

	ts := setupTestServer(t, &config.Config{
		PublicMode:   true,
		JwtPublicKey: pubPEM,
	})

	token := signFpjsJWT(t, privKey, "srvKey-mgmtKey-us", fpjsJWTIssuer)
	session := mustConnectMCPClient(t, ts.URL, token)
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

func TestAuth_PublicMode_AllEmpty(t *testing.T) {
	privKey, pubPEM := generateES256KeyPEM(t)

	ts := setupTestServer(t, &config.Config{
		PublicMode:   true,
		JwtPublicKey: pubPEM,
	})

	// "--" means all parts empty → should be rejected
	token := signFpjsJWT(t, privKey, "--", fpjsJWTIssuer)
	_, err := tryConnectMCPClient(t, ts.URL, token)
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
	privKey, pubPEM := generateES256KeyPEM(t)

	ts := setupTestServer(t, &config.Config{
		PublicMode:   true,
		JwtPublicKey: pubPEM,
		ServerAPIURL: fpAPI.server.URL + "/v4",
	})

	token := signFpjsJWT(t, privKey, "srvKey--us", fpjsJWTIssuer)
	session := mustConnectMCPClient(t, ts.URL, token)
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
	privKey, pubPEM := generateES256KeyPEM(t)

	ts := setupTestServer(t, &config.Config{
		PublicMode:       true,
		JwtPublicKey:     pubPEM,
		ManagementAPIURL: mgmtAPI.server.URL,
	})

	token := signFpjsJWT(t, privKey, "-mgmtKey-us", fpjsJWTIssuer)
	session := mustConnectMCPClient(t, ts.URL, token)

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

func TestAuth_PublicMode_InvalidToken(t *testing.T) {
	privKey, pubPEM := generateES256KeyPEM(t)

	ts := setupTestServer(t, &config.Config{
		PublicMode:   true,
		JwtPublicKey: pubPEM,
	})

	// Not a JWT at all
	_, err := tryConnectMCPClient(t, ts.URL, "not-a-jwt")
	if err == nil {
		t.Fatal("expected connection to fail with invalid token")
	}

	// JWT with wrong subject format (no dashes)
	token := signFpjsJWT(t, privKey, "nodashes", fpjsJWTIssuer)
	_, err = tryConnectMCPClient(t, ts.URL, token)
	if err == nil {
		t.Fatal("expected connection to fail with invalid subject format")
	}
}

func generateES256KeyPEM(t *testing.T) (privateKey *ecdsa.PrivateKey, publicKeyPEM string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating ES256 key: %v", err)
	}
	pubJWK, err := jwk.FromRaw(&priv.PublicKey)
	if err != nil {
		t.Fatalf("creating JWK from public key: %v", err)
	}
	pem, err := jwk.EncodePEM(pubJWK)
	if err != nil {
		t.Fatalf("encoding public key to PEM: %v", err)
	}
	return priv, string(pem)
}

func signFpjsJWT(t *testing.T, privateKey *ecdsa.PrivateKey, subject, issuer string) string {
	t.Helper()
	token, err := jwt.NewBuilder().
		Subject(subject).
		Issuer(issuer).
		Expiration(time.Now().Add(time.Hour)).
		Build()
	if err != nil {
		t.Fatalf("building JWT: %v", err)
	}
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.ES256, privateKey))
	if err != nil {
		t.Fatalf("signing JWT: %v", err)
	}
	return string(signed)
}

func TestAuth_PublicMode_FpjsJWT_InvalidIssuer(t *testing.T) {
	privKey, pubPEM := generateES256KeyPEM(t)

	ts := setupTestServer(t, &config.Config{
		PublicMode:   true,
		JwtPublicKey: pubPEM,
	})

	token := signFpjsJWT(t, privKey, "srvKey-mgmtKey-us", "https://evil.example.com")
	_, err := tryConnectMCPClient(t, ts.URL, token)
	if err == nil {
		t.Fatal("expected connection to fail with invalid issuer")
	}
}

func TestAuth_PublicMode_FpjsJWT_InvalidSignature(t *testing.T) {
	_, pubPEM := generateES256KeyPEM(t)
	otherKey, _ := generateES256KeyPEM(t)

	ts := setupTestServer(t, &config.Config{
		PublicMode:   true,
		JwtPublicKey: pubPEM,
	})

	// Sign with a different key than what the server expects
	token := signFpjsJWT(t, otherKey, "srvKey-mgmtKey-us", fpjsJWTIssuer)
	_, err := tryConnectMCPClient(t, ts.URL, token)
	if err == nil {
		t.Fatal("expected connection to fail with invalid signature")
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
	privKey, pubPEM := generateES256KeyPEM(t)

	ts := setupTestServer(t, &config.Config{
		PublicMode:   true,
		JwtPublicKey: pubPEM,
		ServerAPIURL: fpAPI.server.URL + "/v4",
	})

	// JWT subject "testKey-mgmt-us" → server key should be "testKey"
	token := signFpjsJWT(t, privKey, "testKey-mgmt-us", fpjsJWTIssuer)
	session := mustConnectMCPClient(t, ts.URL, token)
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
	privKey, pubPEM := generateES256KeyPEM(t)

	ts := setupTestServer(t, &config.Config{
		PublicMode:   true,
		JwtPublicKey: pubPEM,
		ServerAPIURL: fpAPI.server.URL + "/v4",
	})

	// JWT subject "srvKey-mgmt-xx" → region "xx" is invalid
	token := signFpjsJWT(t, privKey, "srvKey-mgmt-xx", fpjsJWTIssuer)
	session := mustConnectMCPClient(t, ts.URL, token)
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
	privKey, pubPEM := generateES256KeyPEM(t)

	ts := setupTestServer(t, &config.Config{
		PublicMode:       true,
		JwtPublicKey:     pubPEM,
		ManagementAPIURL: mgmtAPI.server.URL,
	})

	// JWT subject "srv-mgmtTestKey-us" → mgmt key should be "mgmtTestKey"
	token := signFpjsJWT(t, privKey, "srv-mgmtTestKey-us", fpjsJWTIssuer)
	session := mustConnectMCPClient(t, ts.URL, token)
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
	privKey, pubPEM := generateES256KeyPEM(t)

	ts := setupTestServer(t, &config.Config{
		PublicMode:   true,
		JwtPublicKey: pubPEM,
	})

	// JWT subject "srvKey--us" → no mgmt key
	token := signFpjsJWT(t, privKey, "srvKey--us", fpjsJWTIssuer)
	session := mustConnectMCPClient(t, ts.URL, token)
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

// TestLoggingMiddleware_ResourceAndPromptFields verifies that the middleware
// extracts resource_uri from resources/read requests and prompt_name from
// prompts/get requests and includes them in the structured log line, mirroring
// the existing tool_name extraction. Covers both happy and failure paths.
func TestLoggingMiddleware_ResourceAndPromptFields(t *testing.T) {
	fpAPI := newMockFingerprintAPI()
	defer fpAPI.close()

	handler := newCaptureHandler()
	logger := slog.New(handler)

	cfg := &config.Config{
		AuthToken:    defaultAuthToken,
		ServerAPIKey: "test-server-key",
		ServerAPIURL: fpAPI.server.URL + "/v4",
		Region:       "us",
	}
	ts := setupTestServerWithLogger(t, cfg, logger)

	session := mustConnectMCPClient(t, ts.URL, defaultAuthToken)

	// Static schema resource — no upstream API call needed.
	const resourceURI = "fingerprint://schemas/event"
	if _, err := session.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: resourceURI}); err != nil {
		t.Fatalf("ReadResource(%s) failed: %v", resourceURI, err)
	}

	// Discover an embedded prompt name at runtime so the test isn't coupled to
	// a specific SKILL filename. registerPrompts walks skills/**/SKILL.md.
	promptsList, err := session.ListPrompts(context.Background(), &mcp.ListPromptsParams{})
	if err != nil {
		t.Fatalf("ListPrompts failed: %v", err)
	}
	if len(promptsList.Prompts) == 0 {
		t.Fatal("expected at least one embedded prompt; check skills/ directory")
	}
	promptName := promptsList.Prompts[0].Name
	if _, err := session.GetPrompt(context.Background(), &mcp.GetPromptParams{Name: promptName}); err != nil {
		t.Fatalf("GetPrompt(%s) failed: %v", promptName, err)
	}

	// Failure path: a URI that matches no registered resource or template
	// makes the SDK return a protocol error, exercising the "MCP method failed"
	// branch. The resource_uri attr should still be present on that log line.
	const badURI = "fingerprint://does-not-exist/abc"
	_, _ = session.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: badURI})

	records := handler.snapshot()

	// Assert the new fields populate on the started, completed, and failed
	// records so a regression that touches only one branch (e.g. someone
	// adds a new field on completed but forgets started) fails the test.
	var sawResourceStarted, sawResourceCompleted bool
	var sawPromptStarted, sawPromptCompleted bool
	var sawResourceFailed bool
	for _, r := range records {
		attrs := recordAttrs(r)
		switch {
		case r.Message == "MCP method started" && attrs["method"] == "resources/read" && attrs["resource_uri"] == resourceURI:
			sawResourceStarted = true
		case r.Message == "MCP method completed" && attrs["method"] == "resources/read" && attrs["resource_uri"] == resourceURI:
			sawResourceCompleted = true
		case r.Message == "MCP method started" && attrs["method"] == "prompts/get" && attrs["prompt_name"] == promptName:
			sawPromptStarted = true
		case r.Message == "MCP method completed" && attrs["method"] == "prompts/get" && attrs["prompt_name"] == promptName:
			sawPromptCompleted = true
		case r.Message == "MCP method failed" && attrs["method"] == "resources/read" && attrs["resource_uri"] == badURI:
			sawResourceFailed = true
		}
	}
	if !sawResourceStarted {
		t.Errorf("expected MCP method started with method=resources/read and resource_uri=%q", resourceURI)
	}
	if !sawResourceCompleted {
		t.Errorf("expected MCP method completed with method=resources/read and resource_uri=%q", resourceURI)
	}
	if !sawPromptStarted {
		t.Errorf("expected MCP method started with method=prompts/get and prompt_name=%q", promptName)
	}
	if !sawPromptCompleted {
		t.Errorf("expected MCP method completed with method=prompts/get and prompt_name=%q", promptName)
	}
	if !sawResourceFailed {
		t.Errorf("expected MCP method failed with method=resources/read and resource_uri=%q", badURI)
	}
	if t.Failed() {
		for _, r := range records {
			t.Logf("  %s %v", r.Message, recordAttrs(r))
		}
	}
}

// signFpjsJWTWithSubID mints a Fingerprint-issued JWT carrying the
// urn:fingerprint:sub_id claim used to populate user_id on Amplitude events.
func signFpjsJWTWithSubID(t *testing.T, privateKey *ecdsa.PrivateKey, subject, subID string) string {
	t.Helper()
	builder := jwt.NewBuilder().
		Subject(subject).
		Issuer(fpjsJWTIssuer).
		Expiration(time.Now().Add(time.Hour))
	if subID != "" {
		builder = builder.Claim(claimSubscriptionID, subID)
	}
	token, err := builder.Build()
	if err != nil {
		t.Fatalf("building JWT: %v", err)
	}
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.ES256, privateKey))
	if err != nil {
		t.Fatalf("signing JWT: %v", err)
	}
	return string(signed)
}

// newTestAmplitudeEmitter wires up an analytics.Emitter pointed at the given
// mockAmplitude. It registers a t.Cleanup that drains the emitter so tests
// see all in-flight events before asserting.
func newTestAmplitudeEmitter(t *testing.T, mock *mockAmplitude) analytics.Emitter {
	t.Helper()
	em, err := analytics.NewAmplitude(analytics.AmplitudeConfig{
		APIKey:        "test-amplitude-key",
		Endpoint:      mock.eventsURL(),
		FlushInterval: 20 * time.Millisecond,
		HTTPTimeout:   time.Second,
	})
	if err != nil {
		t.Fatalf("NewAmplitude: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = em.Close(ctx)
	})
	return em
}

func TestAnalytics_PublicMode_EmitsEvent(t *testing.T) {
	fpAPI := newMockFingerprintAPI()
	defer fpAPI.close()
	mockAmp := newMockAmplitude()
	defer mockAmp.close()

	privKey, pubPEM := generateES256KeyPEM(t)
	emitter := newTestAmplitudeEmitter(t, mockAmp)

	cfg := &config.Config{
		PublicMode:   true,
		JwtPublicKey: pubPEM,
		Transport:    "streamable-http",
	}
	ts := setupTestServerWithEmitter(t, cfg, emitter)

	// Public-mode JWT carries serverKey-mgmtKey-region in the subject and the
	// subscription_id as a custom claim.
	const subID = "sub_test_xyz"
	token := signFpjsJWTWithSubID(t, privKey, "test-server-key-test-mgmt-key-us", subID)

	session := mustConnectMCPClient(t, ts.URL, token)

	// initialize is implicit on Connect. Drive a tools/list to land an event.
	if _, err := session.ListTools(context.Background(), &mcp.ListToolsParams{}); err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	// Drain analytics.
	if err := emitter.Close(context.Background()); err != nil {
		t.Fatalf("emitter.Close: %v", err)
	}

	posts := mockAmp.snapshot()
	if len(posts) == 0 {
		t.Fatal("expected at least one POST to mockAmplitude, got 0")
	}

	var sawInitializeWithUserProps, sawMethodEvent bool
	for _, p := range posts {
		if p.Path != "/2/httpapi" {
			t.Errorf("unexpected path %q (no /identify expected since user_properties go on events)", p.Path)
			continue
		}
		var body struct {
			APIKey string `json:"api_key"`
			Events []struct {
				EventType       string         `json:"event_type"`
				UserID          string         `json:"user_id"`
				EventProperties map[string]any `json:"event_properties"`
				UserProperties  map[string]any `json:"user_properties"`
			} `json:"events"`
		}
		if err := json.Unmarshal([]byte(p.Body), &body); err != nil {
			t.Errorf("unmarshal events body: %v", err)
			continue
		}
		if body.APIKey != "test-amplitude-key" {
			t.Errorf("api_key=%q, want test-amplitude-key", body.APIKey)
		}
		for _, e := range body.Events {
			if e.EventType != "mcp_method_called" || e.UserID != subID {
				continue
			}
			sawMethodEvent = true
			if e.EventProperties["transport"] != "streamable-http" {
				t.Errorf("event transport=%v, want streamable-http", e.EventProperties["transport"])
			}
			// initialize is the only method that carries user_properties.
			if e.EventProperties["method"] == "initialize" {
				if e.UserProperties["client_name"] != "test-client" {
					t.Errorf("initialize user_properties.client_name=%v, want test-client", e.UserProperties["client_name"])
				}
				sawInitializeWithUserProps = true
			}
		}
	}
	if !sawMethodEvent {
		t.Errorf("expected an mcp_method_called event for user_id=%q", subID)
	}
	if !sawInitializeWithUserProps {
		t.Errorf("expected an mcp_method_called event with method=initialize and user_properties.client_name set")
	}
}

func TestAnalytics_PrivateMode_EmitsNothing(t *testing.T) {
	fpAPI := newMockFingerprintAPI()
	defer fpAPI.close()
	mockAmp := newMockAmplitude()
	defer mockAmp.close()

	emitter := newTestAmplitudeEmitter(t, mockAmp)

	cfg := &config.Config{
		AuthToken:    defaultAuthToken,
		ServerAPIKey: "test-server-key",
		ServerAPIURL: fpAPI.server.URL + "/v4",
		Region:       "us",
		Transport:    "streamable-http",
		// PublicMode left false → middleware must not emit.
	}
	ts := setupTestServerWithEmitter(t, cfg, emitter)

	session := mustConnectMCPClient(t, ts.URL, defaultAuthToken)
	if _, err := session.ListTools(context.Background(), &mcp.ListToolsParams{}); err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	if err := emitter.Close(context.Background()); err != nil {
		t.Fatalf("emitter.Close: %v", err)
	}

	if got := len(mockAmp.snapshot()); got != 0 {
		t.Errorf("private mode should emit 0 requests, got %d", got)
		for _, p := range mockAmp.snapshot() {
			t.Logf("  %s %s body=%s", p.Method, p.Path, p.Body)
		}
	}
}

func TestAnalytics_PublicMode_NoSubID_EmitsNothing(t *testing.T) {
	mockAmp := newMockAmplitude()
	defer mockAmp.close()

	privKey, pubPEM := generateES256KeyPEM(t)
	emitter := newTestAmplitudeEmitter(t, mockAmp)

	cfg := &config.Config{
		PublicMode:   true,
		JwtPublicKey: pubPEM,
		Transport:    "streamable-http",
	}
	ts := setupTestServerWithEmitter(t, cfg, emitter)

	// Mint a JWT WITHOUT the subscription_id claim. The auth path still
	// succeeds (subID is optional), but with no user identifier the analytics
	// gate stays closed and no event leaves the process.
	token := signFpjsJWTWithSubID(t, privKey, "test-server-key-test-mgmt-key-us", "")

	session := mustConnectMCPClient(t, ts.URL, token)
	if _, err := session.ListTools(context.Background(), &mcp.ListToolsParams{}); err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	if err := emitter.Close(context.Background()); err != nil {
		t.Fatalf("emitter.Close: %v", err)
	}

	if got := len(mockAmp.snapshot()); got != 0 {
		t.Errorf("missing sub_id should result in 0 emitted requests, got %d", got)
	}
}
