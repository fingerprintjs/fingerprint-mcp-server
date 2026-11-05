package fpmcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/fingerprintjs/fingerprint-mcp-server/config"
	"github.com/fingerprintjs/fingerprint-mcp-server/internal/mgmtapi"
)

const cannedWebhook = `{"id":"wh_test","description":"Orders","status":"enabled","verified":false,"environment":null,"url":"https://example.com/hook","legacy":false,"basic_auth":null,"created_at":"2026-10-09T12:00:00Z","last_enabled_at":null,"last_disabled_at":null}`

// A legacy webhook as the API might send it, with credentials that must not reach the model.
const cannedLegacyWebhook = `{"id":"wh_legacy","description":"Old","status":"enabled","verified":true,"environment":"env_1","url":"https://example.com/old","legacy":true,"basic_auth":{"username":"admin","password":"hunter2"},"created_at":"2025-01-01T00:00:00Z","last_enabled_at":null,"last_disabled_at":null}`

type webhookRequest struct {
	method string
	uri    string
	body   string
}

func newWebhookAPI(t *testing.T, createResponse string) (*httptest.Server, *[]webhookRequest) {
	t.Helper()
	var requests []webhookRequest
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-mgmt-key" {
			t.Error("missing Management API credential")
		}
		query := r.URL.Query()
		query.Del("ii")
		r.URL.RawQuery = query.Encode()
		body, _ := io.ReadAll(r.Body)
		requests = append(requests, webhookRequest{r.Method, r.URL.RequestURI(), string(body)})
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/webhooks":
			fmt.Fprintf(w, `{"data":[%s,%s],"metadata":{"pagination":{"next_cursor":"next","prev_cursor":null}}}`, cannedWebhook, cannedLegacyWebhook)
		case r.Method == http.MethodPost && r.URL.Path == "/webhooks":
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, createResponse)
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/verification"):
			fmt.Fprintf(w, `{"data":%s,"environment":null}`, strings.Replace(cannedWebhook, `"verified":false`, `"verified":true`, 1))
		default:
			fmt.Fprintf(w, `{"data":%s,"environment":null}`, cannedWebhook)
		}
	}))
	t.Cleanup(api.Close)
	return api, &requests
}

func TestWebhookToolsLifecycle(t *testing.T) {
	api, requests := newWebhookAPI(t, fmt.Sprintf(`{"data":%s,"environment":null}`, cannedWebhook))
	session := setupStdioServer(t, &config.Config{ManagementAPIKey: "test-mgmt-key", ManagementAPIURL: api.URL})

	list := mustCallTool(t, session, "call_tool", map[string]any{
		"tool_name": "list_webhooks", "arguments": map[string]any{"status": "enabled", "environment": "env_1", "limit": 2, "cursor": "prev"},
	})
	if list.IsError {
		t.Fatal(extractTextContent(t, list))
	}
	var page ListWebhooksOutput
	if err := json.Unmarshal([]byte(extractTextContent(t, list)), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Webhooks) != 2 || page.Pagination.NextCursor == nil || *page.Pagination.NextCursor != "next" {
		t.Fatalf("unexpected page: %+v", page)
	}
	if page.Webhooks[0].BasicAuthConfigured || !page.Webhooks[1].BasicAuthConfigured {
		t.Errorf("basic_auth_configured wrong: %+v", page.Webhooks)
	}

	for _, tc := range []struct {
		tool, proxy string
		args        map[string]any
	}{
		{"get_webhook", "call_tool", map[string]any{"id": "wh_test"}},
		{"create_webhook", "call_write_tool", map[string]any{"url": "https://example.com/hook", "description": "Orders"}},
		{"create_webhook", "call_write_tool", map[string]any{"url": "https://example.com/hook", "environment": "env_1"}},
		{"update_webhook", "call_write_tool", map[string]any{"id": "wh_test", "status": "disabled"}},
		{"verify_webhook", "call_write_tool", map[string]any{"id": "wh_test"}},
	} {
		result := mustCallTool(t, session, tc.proxy, map[string]any{"tool_name": tc.tool, "arguments": tc.args})
		if result.IsError {
			t.Fatalf("%s: %s", tc.tool, extractTextContent(t, result))
		}
		text := extractTextContent(t, result)
		if !strings.Contains(text, `"id":"wh_test"`) {
			t.Errorf("%s returned no webhook: %s", tc.tool, text)
		}
		if strings.Contains(text, "signing_key") || strings.Contains(text, "warning") {
			t.Errorf("%s mentioned a signing key the API did not send: %s", tc.tool, text)
		}
	}

	del := mustCallTool(t, session, "delete_webhook", map[string]any{"id": "wh_test"})
	if del.IsError {
		t.Fatal(extractTextContent(t, del))
	}

	want := []webhookRequest{
		{"GET", "/webhooks?cursor=prev&environment=env_1&limit=2&status=enabled", ""},
		{"GET", "/webhooks/wh_test", ""},
		// An omitted environment stays out of the body, which makes the webhook global.
		{"POST", "/webhooks", `{"url":"https://example.com/hook","description":"Orders"}`},
		{"POST", "/webhooks", `{"url":"https://example.com/hook","environment":"env_1"}`},
		{"PATCH", "/webhooks/wh_test", `{"status":"disabled"}`},
		{"POST", "/webhooks/wh_test/verification", ""},
		{"DELETE", "/webhooks/wh_test", ""},
	}
	if !reflect.DeepEqual(*requests, want) {
		t.Errorf("requests =\n%v\nwant\n%v", *requests, want)
	}
}

func TestCreateWebhook_ReturnsSigningKeyOnceWithWarning(t *testing.T) {
	withKey := strings.Replace(cannedWebhook, `"legacy":false`, `"legacy":false,"signing_key":"sk_secret_123"`, 1)
	api, _ := newWebhookAPI(t, fmt.Sprintf(`{"data":%s,"environment":null}`, withKey))
	session := setupStdioServer(t, &config.Config{ManagementAPIKey: "test-mgmt-key", ManagementAPIURL: api.URL})

	result := mustCallTool(t, session, "create_webhook", map[string]any{"url": "https://example.com/hook"})
	if result.IsError {
		t.Fatal(extractTextContent(t, result))
	}
	var out CreateWebhookOutput
	if err := json.Unmarshal([]byte(extractTextContent(t, result)), &out); err != nil {
		t.Fatal(err)
	}
	if out.SigningKey != "sk_secret_123" {
		t.Errorf("signing_key = %q, want sk_secret_123", out.SigningKey)
	}
	if out.Warning == "" || !strings.Contains(out.Warning, "only once") {
		t.Errorf("missing one-time warning: %q", out.Warning)
	}
	// The key goes at the top level only, next to its warning, not inside the webhook.
	var raw struct {
		Webhook map[string]any `json:"webhook"`
	}
	if err := json.Unmarshal([]byte(extractTextContent(t, result)), &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw.Webhook["signing_key"]; ok {
		t.Error("signing_key duplicated inside webhook")
	}
}

func TestWebhookTools_NeverReturnBasicAuthCredentials(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/webhooks" {
			fmt.Fprintf(w, `{"data":[%s],"metadata":{"pagination":{"next_cursor":null,"prev_cursor":null}}}`, cannedLegacyWebhook)
			return
		}
		// Even if the API ever sent a signing key on a read, it is not passed on.
		fmt.Fprintf(w, `{"data":%s,"environment":null}`, strings.Replace(cannedLegacyWebhook, `"legacy":true`, `"legacy":true,"signing_key":"sk_leak"`, 1))
	}))
	defer api.Close()
	session := setupStdioServer(t, &config.Config{ManagementAPIKey: "test-mgmt-key", ManagementAPIURL: api.URL})

	for _, call := range []struct {
		tool string
		args map[string]any
	}{
		{"list_webhooks", map[string]any{}},
		{"get_webhook", map[string]any{"id": "wh_legacy"}},
		{"update_webhook", map[string]any{"id": "wh_legacy", "description": "Old"}},
	} {
		result := mustCallTool(t, session, call.tool, call.args)
		text := extractTextContent(t, result)
		if result.IsError {
			t.Fatalf("%s: %s", call.tool, text)
		}
		for _, secret := range []string{"hunter2", "admin", "sk_leak", "basic_auth\""} {
			if strings.Contains(text, secret) {
				t.Errorf("%s leaked %q: %s", call.tool, secret, text)
			}
		}
		if !strings.Contains(text, `"basic_auth_configured":true`) {
			t.Errorf("%s did not report basic auth as configured: %s", call.tool, text)
		}
	}
}

func TestBasicAuthConfigured(t *testing.T) {
	for _, tc := range []struct {
		in   any
		want bool
	}{
		{nil, false},
		{map[string]any{}, false},
		{map[string]any{"username": "u"}, true},
	} {
		if got := basicAuthConfigured(tc.in); got != tc.want {
			t.Errorf("basicAuthConfigured(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestWebhookToolsAccessPolicy(t *testing.T) {
	all := []string{"list_webhooks", "get_webhook", "create_webhook", "update_webhook", "verify_webhook", "delete_webhook"}
	for _, tc := range []struct {
		name string
		cfg  config.Config
		want []string
	}{
		{"no management key", config.Config{}, nil},
		{"readonly", config.Config{ManagementAPIKey: "key", ReadOnly: true}, []string{"list_webhooks", "get_webhook"}},
		{"all", config.Config{ManagementAPIKey: "key"}, all},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ }))
			defer api.Close()
			tc.cfg.ManagementAPIURL = api.URL
			session := setupStdioServer(t, &tc.cfg)
			listed, err := session.ListTools(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			names := toolNames(listed)
			for _, name := range all {
				if slices.Contains(names, name) != slices.Contains(tc.want, name) {
					t.Errorf("unexpected availability for %s: %v", name, names)
				}
			}
			for _, tool := range listed.Tools {
				if !slices.Contains(tc.want, tool.Name) {
					continue
				}
				wantRead := tool.Name == "list_webhooks" || tool.Name == "get_webhook"
				if tool.Annotations == nil || tool.Annotations.ReadOnlyHint != wantRead {
					t.Errorf("incorrect annotations for %s", tool.Name)
				}
			}
			// The read proxy never runs a write, and the write proxy never runs a delete.
			for _, name := range []string{"create_webhook", "update_webhook", "verify_webhook", "delete_webhook"} {
				result := mustCallTool(t, session, "call_tool", map[string]any{"tool_name": name, "arguments": map[string]any{"id": "wh_test", "url": "https://example.com/hook"}})
				if !result.IsError {
					t.Errorf("call_tool ran %s", name)
				}
			}
			if tc.name == "all" {
				result := mustCallTool(t, session, "call_write_tool", map[string]any{"tool_name": "delete_webhook", "arguments": map[string]any{"id": "wh_test"}})
				if !result.IsError {
					t.Error("call_write_tool ran delete_webhook")
				}
			}
			if calls != 0 {
				t.Fatalf("denied requests reached the API: %d", calls)
			}
		})
	}
}

func TestWebhookTools_InputValidation(t *testing.T) {
	calls := 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ }))
	defer api.Close()
	session := setupStdioServer(t, &config.Config{ManagementAPIKey: "key", ManagementAPIURL: api.URL})
	for _, call := range []struct {
		tool string
		args map[string]any
	}{
		{"get_webhook", map[string]any{}},
		{"create_webhook", map[string]any{}},
		{"update_webhook", map[string]any{"description": "x"}},
		{"update_webhook", map[string]any{"id": "wh_test"}},
		{"verify_webhook", map[string]any{}},
		{"delete_webhook", map[string]any{}},
	} {
		result, err := callTool(t, session, call.tool, call.args)
		if err == nil && !result.IsError {
			t.Errorf("%s accepted %v", call.tool, call.args)
		}
	}
	if calls != 0 {
		t.Fatalf("invalid input reached the API: %d calls", calls)
	}
}

func TestWebhookToolsErrors(t *testing.T) {
	for _, tc := range []struct {
		status      int
		message     string
		wantMessage string
	}{
		{401, "Invalid API key", "Invalid API key. Check the Management API key"},
		{400, "Webhook is already verified", "Webhook is already verified"},
		{404, "Webhook does not exist.", "Webhook does not exist."},
		{422, "url must start with https://", "url must start with https://"},
	} {
		t.Run(fmt.Sprintf("%d", tc.status), func(t *testing.T) {
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				fmt.Fprintf(w, `{"error":{"message":%q,"code":"webhooks.error","violations":[{"property":"url","message":"must be https"}]}}`, tc.message)
			}))
			defer api.Close()
			// A key that never appears in the messages, which the client would redact.
			session := setupStdioServer(t, &config.Config{ManagementAPIKey: "mgmt-key-0000", ManagementAPIURL: api.URL})
			result := mustCallTool(t, session, "verify_webhook", map[string]any{"id": "wh_test"})
			if !result.IsError {
				t.Fatal("expected tool error")
			}
			var output struct {
				Error mgmtapi.APIError `json:"error"`
			}
			if err := json.Unmarshal([]byte(extractTextContent(t, result)), &output); err != nil {
				t.Fatal(err)
			}
			if output.Error.StatusCode != tc.status || !strings.HasPrefix(output.Error.Message, tc.wantMessage) || output.Error.Code != "webhooks.error" || len(output.Error.Violations) != 1 {
				t.Errorf("unexpected error: %+v", output.Error)
			}
		})
	}
}

func TestWebhookIDsAreEscapedInPaths(t *testing.T) {
	var paths []string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.EscapedPath())
		fmt.Fprintf(w, `{"data":%s,"environment":null}`, cannedWebhook)
	}))
	defer api.Close()
	session := setupStdioServer(t, &config.Config{ManagementAPIKey: "key", ManagementAPIURL: api.URL})
	mustCallTool(t, session, "get_webhook", map[string]any{"id": "../api-keys/x?y"})
	if len(paths) != 1 || paths[0] != "/webhooks/..%2Fapi-keys%2Fx%3Fy" {
		t.Errorf("paths = %v", paths)
	}
}
