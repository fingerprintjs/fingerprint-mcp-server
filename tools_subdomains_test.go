package fpmcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/fingerprintjs/fingerprint-mcp-server/config"
	"github.com/fingerprintjs/fingerprint-mcp-server/internal/mgmtapi"
)

const cannedSubdomainResponse = `{"data":{"id":"certv2_test","subdomain":"metrics.example.com","status":"pending","created_at":"2026-10-09T12:00:00Z","updated_at":"2026-10-09T12:00:00Z","dns_records":{"verification":{"type":"CNAME","host":"_acme-challenge.metrics.example.com","value":"validation.example.com","status":"validated"},"routing":[{"type":"A","host":"metrics.example.com","value":"162.159.141.170","status":"pending_validation"},{"type":"A","host":"metrics.example.com","value":"172.66.1.166","status":"pending_validation"}],"caa":{"type":"CAA","host":"metrics.example.com","value":"0 issue pki.goog","status":"pending_validation"}}}}`

func TestSubdomainToolsLifecycle(t *testing.T) {
	var requests []string
	verified := false
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Query().Get("ii"), "fingerprint-mcp-server/") {
			t.Error("missing integration metadata")
		}
		query := r.URL.Query()
		query.Del("ii")
		r.URL.RawQuery = query.Encode()
		requests = append(requests, r.Method+" "+r.URL.RequestURI())
		if r.Header.Get("Authorization") != "Bearer test-mgmt-key" {
			t.Error("missing Management API credential")
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/subdomains" && query.Get("cursor") == "next-page":
			fmt.Fprint(w, `{"data":[],"metadata":{"pagination":{"next_cursor":null,"prev_cursor":"previous"}}}`)
		case r.Method == http.MethodGet && r.URL.Path == "/subdomains":
			fmt.Fprint(w, `{"data":[{"id":"certv2_test","subdomain":"metrics.example.com","status":"pending","created_at":"2026-10-09T12:00:00Z","updated_at":"2026-10-09T12:00:00Z"}],"metadata":{"pagination":{"next_cursor":"next-page","prev_cursor":null}}}`)
		case strings.HasSuffix(r.URL.Path, "/verify"):
			verified = true
			fallthrough
		default:
			body := cannedSubdomainResponse
			if verified {
				body = strings.ReplaceAll(body, `"pending"`, `"active"`)
				body = strings.ReplaceAll(body, `"pending_validation"`, `"validated"`)
			}
			fmt.Fprint(w, body)
		}
	}))
	defer api.Close()
	session := setupStdioServer(t, &config.Config{ManagementAPIKey: "test-mgmt-key", ManagementAPIURL: api.URL})

	list := mustCallTool(t, session, "call_tool", map[string]any{
		"tool_name": "list_subdomains", "arguments": map[string]any{"limit": 2, "cursor": "previous"},
	})
	var page ListSubdomainsOutput
	if list.IsError {
		t.Fatal(extractTextContent(t, list))
	}
	if err := json.Unmarshal([]byte(extractTextContent(t, list)), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Subdomains.Data) != 1 || page.Subdomains.Metadata.Pagination.NextCursor == nil || *page.Subdomains.Metadata.Pagination.NextCursor != "next-page" {
		t.Fatalf("unexpected page: %+v", page)
	}
	for _, tc := range []struct {
		tool  string
		proxy string
		args  map[string]any
	}{
		{"create_subdomain", "call_write_tool", map[string]any{"hostname": "metrics.example.com"}},
		{"get_subdomain", "call_tool", map[string]any{"id": "certv2_test"}},
		{"verify_subdomain", "call_write_tool", map[string]any{"id": "certv2_test"}},
	} {
		result := mustCallTool(t, session, tc.proxy, map[string]any{"tool_name": tc.tool, "arguments": tc.args})
		if result.IsError {
			t.Fatalf("%s: %s", tc.tool, extractTextContent(t, result))
		}
		var output SubdomainOutput
		if err := json.Unmarshal([]byte(extractTextContent(t, result)), &output); err != nil {
			t.Fatal(err)
		}
		wantStatus := "pending"
		if tc.tool == "verify_subdomain" {
			wantStatus = "active"
		}
		if output.Subdomain.ID != "certv2_test" || output.Subdomain.Status != wantStatus || len(output.Subdomain.DNSRecords.Routing) != 2 || output.Subdomain.DNSRecords.CAA == nil {
			t.Fatalf("%s returned incomplete data: %+v", tc.tool, output)
		}
	}
	// A hostname, with any case or trailing dot, is resolved through every page of the list.
	byHostname := mustCallTool(t, session, "get_subdomain", map[string]any{"hostname": "Metrics.Example.com."})
	if byHostname.IsError || !strings.Contains(extractTextContent(t, byHostname), `"id":"certv2_test"`) {
		t.Fatalf("hostname lookup failed: %s", extractTextContent(t, byHostname))
	}
	// Models often send the proxied arguments as a JSON string; that spelling works too.
	asString := mustCallTool(t, session, "call_tool", map[string]any{"tool_name": "get_subdomain", "arguments": `{"id":"certv2_test"}`})
	if asString.IsError || !strings.Contains(extractTextContent(t, asString), `"id":"certv2_test"`) {
		t.Fatalf("string arguments rejected: %s", extractTextContent(t, asString))
	}
	resumed := setupStdioServer(t, &config.Config{ManagementAPIKey: "test-mgmt-key", ManagementAPIURL: api.URL})
	result := mustCallTool(t, resumed, "get_subdomain", map[string]any{"id": "certv2_test"})
	if result.IsError || !strings.Contains(extractTextContent(t, result), `"status":"active"`) {
		t.Fatal("could not resume the existing subdomain in a new session")
	}
	want := []string{
		"GET /subdomains?cursor=previous&limit=2", "POST /subdomains", "GET /subdomains/certv2_test", "POST /subdomains/certv2_test/verify",
		"GET /subdomains", "GET /subdomains?cursor=next-page", "GET /subdomains/certv2_test",
		"GET /subdomains/certv2_test",
		"GET /subdomains/certv2_test",
	}
	if !reflect.DeepEqual(requests, want) {
		t.Errorf("requests = %v, want %v", requests, want)
	}
}

func TestSubdomainToolsAccessPolicy(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  config.Config
		want []string
	}{
		{"no management key", config.Config{}, nil},
		{"readonly", config.Config{ManagementAPIKey: "key", ReadOnly: true}, []string{"list_subdomains", "get_subdomain"}},
		{"allowlist", config.Config{ManagementAPIKey: "key", Tools: []string{"get_subdomain", "create_environment", "call_tool", "call_write_tool"}}, []string{"get_subdomain"}},
		{"all", config.Config{ManagementAPIKey: "key"}, []string{"list_subdomains", "get_subdomain", "create_subdomain", "verify_subdomain", "connect_subdomain"}},
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
			for _, name := range []string{"list_subdomains", "get_subdomain", "create_subdomain", "verify_subdomain", "connect_subdomain", "delete_subdomain"} {
				if slices.Contains(names, name) != slices.Contains(tc.want, name) {
					t.Errorf("unexpected availability for %s: %v", name, names)
				}
			}
			for _, tool := range listed.Tools {
				if slices.Contains(tc.want, tool.Name) {
					wantRead := tool.Name == "list_subdomains" || tool.Name == "get_subdomain"
					if tool.Annotations == nil || tool.Annotations.ReadOnlyHint != wantRead {
						t.Errorf("incorrect annotations for %s", tool.Name)
					}
				}
			}
			for _, name := range []string{"create_subdomain", "verify_subdomain", "connect_subdomain"} {
				result := mustCallTool(t, session, "call_tool", map[string]any{"tool_name": name, "arguments": map[string]any{"id": "certv2_test", "hostname": "metrics.example.com"}})
				if !result.IsError {
					t.Errorf("call_tool allowed %s", name)
				}
			}
			if tc.name == "allowlist" {
				result := mustCallTool(t, session, "call_write_tool", map[string]any{"tool_name": "create_subdomain", "arguments": map[string]any{"hostname": "metrics.example.com"}})
				if !result.IsError || !strings.Contains(extractTextContent(t, result), "tool_not_found") {
					t.Error("write proxy bypassed allowlist")
				}
			}
			if calls != 0 {
				t.Fatalf("denied requests reached the API: %d", calls)
			}
		})
	}
}

func TestSubdomainToolsErrors(t *testing.T) {
	for _, tc := range []struct {
		status  int
		message string
	}{
		{401, "Invalid API key"}, {404, "Subdomain not found"}, {409, "Subdomain already exists"},
		{400, "Limit of subdomains reached"}, {409, "Limit of subdomains reached"},
		{422, "Invalid subdomain"}, {429, "Too many requests"}, {503, "Service unavailable. Try again later."},
	} {
		t.Run(fmt.Sprintf("%d %s", tc.status, tc.message), func(t *testing.T) {
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Retry-After", "60")
				w.WriteHeader(tc.status)
				fmt.Fprintf(w, `{"error":{"message":%q,"code":"subdomains.error","violations":[{"property":"subdomain","message":"Use a valid hostname"}]}}`, tc.message)
			}))
			defer api.Close()
			session := setupStdioServer(t, &config.Config{ManagementAPIKey: "key", ManagementAPIURL: api.URL})
			result := mustCallTool(t, session, "create_subdomain", map[string]any{"hostname": "metrics.example.com"})
			var output struct {
				Error mgmtapi.APIError `json:"error"`
			}
			if !result.IsError {
				t.Fatal("expected tool error")
			}
			if err := json.Unmarshal([]byte(extractTextContent(t, result)), &output); err != nil {
				t.Fatal(err)
			}
			if output.Error.StatusCode != tc.status || output.Error.Code != "subdomains.error" || len(output.Error.Violations) != 1 || output.Error.RetryAfter != "60" {
				t.Fatalf("lost error details: %+v", output)
			}
			if tc.status == 503 && strings.Contains(output.Error.Message, "Try again later") {
				t.Error("unavailable feature must not instruct blind retries")
			}
			if tc.status == 429 && strings.Contains(output.Error.Message, "verification") {
				t.Error("a create 429 must not carry the verification wait hint")
			}
			if tc.status == 401 && !strings.Contains(output.Error.Message, "Management API key") {
				t.Error("missing authentication recovery guidance")
			}
		})
	}
}

func TestSubdomainToolsPublicAuthenticationAndRedaction(t *testing.T) {
	privKey, pubPEM := generateES256KeyPEM(t)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secretkey" {
			t.Error("did not use the authenticated workspace credential")
		}
		w.WriteHeader(http.StatusUnprocessableEntity)
		fmt.Fprint(w, `{"error":{"code":"secretkey","message":"Bearer secretkey","violations":[{"property":"subdomain","message":"secretkey"}]}}`)
	}))
	defer api.Close()
	var logs bytes.Buffer
	ts := setupTestServerWithLogger(t, &config.Config{
		PublicMode: true, JwtPublicKey: pubPEM, ManagementAPIURL: api.URL,
	}, slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	token := signFpjsJWT(t, privKey, "-secretkey-us", fpjsJWTIssuer)
	session := mustConnectMCPClient(t, ts.URL, token)
	result := mustCallTool(t, session, "create_subdomain", map[string]any{"hostname": "metrics.example.com"})
	if !result.IsError {
		t.Fatal("expected validation failure")
	}
	if strings.Contains(extractTextContent(t, result), "secretkey") || strings.Contains(logs.String(), "secretkey") || strings.Contains(logs.String(), token) {
		t.Fatal("credential exposed in tool output or logs")
	}
}

func TestSubdomainToolsHostnameResolution(t *testing.T) {
	for _, tc := range []struct {
		name  string
		list  string
		input map[string]any
		want  string
	}{
		{"neither id nor hostname", `[]`, map[string]any{}, "id or hostname is required"},
		{"unknown hostname", `[]`, map[string]any{"hostname": "metrics.example.com"}, "no custom subdomain named metrics.example.com"},
		{"repeated cursor", `[]`, map[string]any{"hostname": "metrics.example.com"}, "repeated subdomain pagination cursor"},
		{"ambiguous hostname", `[{"id":"certv2_a","subdomain":"metrics.example.com","status":"pending","created_at":"2026-10-09T12:00:00Z","updated_at":"2026-10-09T12:00:00Z"},{"id":"certv2_b","subdomain":"metrics.example.com","status":"active","created_at":"2026-10-09T12:00:00Z","updated_at":"2026-10-09T12:00:00Z"}]`, map[string]any{"hostname": "metrics.example.com"}, "certv2_a, certv2_b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var verified bool
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/verify") {
					verified = true
				}
				w.Header().Set("Content-Type", "application/json")
				cursor := "null"
				if tc.name == "repeated cursor" {
					cursor = `"again"`
				}
				fmt.Fprintf(w, `{"data":%s,"metadata":{"pagination":{"next_cursor":%s,"prev_cursor":null}}}`, tc.list, cursor)
			}))
			defer api.Close()
			session := setupStdioServer(t, &config.Config{ManagementAPIKey: "key", ManagementAPIURL: api.URL})
			result := mustCallTool(t, session, "verify_subdomain", tc.input)
			if !result.IsError || !strings.Contains(extractTextContent(t, result), tc.want) {
				t.Fatalf("unexpected result: %s", extractTextContent(t, result))
			}
			if verified {
				t.Error("verified without a resolved id")
			}
		})
	}
}

func TestVerifySubdomainRateLimitWithoutRetryAfter(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `{"error":{"message":"You are sending too many requests","code":"rate-limit.exceeded"}}`)
	}))
	defer api.Close()
	session := setupStdioServer(t, &config.Config{ManagementAPIKey: "key", ManagementAPIURL: api.URL})
	result := mustCallTool(t, session, "verify_subdomain", map[string]any{"id": "certv2_test"})
	var output struct {
		Error mgmtapi.APIError `json:"error"`
	}
	if !result.IsError {
		t.Fatal("expected tool error")
	}
	if err := json.Unmarshal([]byte(extractTextContent(t, result)), &output); err != nil {
		t.Fatal(err)
	}
	if output.Error.RetryAfter != "60" || !strings.Contains(output.Error.Message, "Wait before the next verification") {
		t.Fatalf("agent gets no wait time: %+v", output.Error)
	}
}

func TestConnectSubdomainReturnsTheDashboardLink(t *testing.T) {
	var bodies []string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/subdomains":
			fmt.Fprint(w, `{"data":[{"id":"certv2_test","subdomain":"metrics.example.com","status":"pending","created_at":"2026-10-09T12:00:00Z","updated_at":"2026-10-09T12:00:00Z"}],"metadata":{"pagination":{"next_cursor":null,"prev_cursor":null}}}`)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/domain-connect"):
			raw, _ := io.ReadAll(r.Body)
			bodies = append(bodies, string(raw))
			if r.URL.Path != "/subdomains/certv2_test/domain-connect" {
				w.WriteHeader(http.StatusNotFound)
				fmt.Fprint(w, `{"error":{"code":"not_found","message":"Subdomain not found"}}`)
				return
			}
			fmt.Fprint(w, `{"data":{"domain_connect_url":"https://dash.cloudflare.com/domainconnect/apply?domain=example.com&redirect_uri=https%3A%2F%2Fdashboard.fingerprint.com%2Fsubdomains%2Fcertv2_test%3Fdomain_connect%3Dtrue&sig=x","dns_provider":"Cloudflare"}}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer api.Close()
	session := setupStdioServer(t, &config.Config{ManagementAPIKey: "key", ManagementAPIURL: api.URL})

	result := mustCallTool(t, session, "call_write_tool", map[string]any{"tool_name": "connect_subdomain", "arguments": map[string]any{"hostname": "metrics.example.com"}})
	if result.IsError {
		t.Fatal(extractTextContent(t, result))
	}
	var output ConnectSubdomainOutput
	if err := json.Unmarshal([]byte(extractTextContent(t, result)), &output); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(output.Link.DomainConnectURL, "https://dash.cloudflare.com/") || output.Link.DNSProvider != "Cloudflare" {
		t.Fatalf("unexpected link: %+v", output.Link)
	}
	// No port: the provider must redirect to the dashboard, not to a loopback this server cannot run.
	if len(bodies) != 1 || strings.Contains(bodies[0], "port") {
		t.Fatalf("unexpected request body: %v", bodies)
	}
}

func TestConnectSubdomainUnavailableIsAConflict(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		fmt.Fprint(w, `{"error":{"code":"conflict","message":"Domain Connect is not available for this subdomain"}}`)
	}))
	defer api.Close()
	session := setupStdioServer(t, &config.Config{ManagementAPIKey: "key", ManagementAPIURL: api.URL})
	result := mustCallTool(t, session, "connect_subdomain", map[string]any{"id": "certv2_test"})
	if !result.IsError || !strings.Contains(extractTextContent(t, result), `"status":409`) {
		t.Fatalf("expected a structured 409: %s", extractTextContent(t, result))
	}
}
