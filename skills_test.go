package fpmcpserver

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fingerprintjs/fingerprint-mcp-server/config"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const testRemoteSkill = `---
name: fingerprint-get-started
description: remote description
---

# Fingerprint - Get Started

Detect the stack, then install identification.`

func skillServer(t *testing.T, body string, status *atomic.Int32) (*httptest.Server, *atomic.Int64) {
	t.Helper()

	var hits atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		if status != nil && status.Load() != http.StatusOK {
			w.WriteHeader(int(status.Load()))
			return
		}
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(ts.Close)

	return ts, &hits
}

var testSkillsRepo = map[string]string{
	"README.md":                                      "# skills",
	"skills/fingerprint-react/SKILL.md":              "---\nname: fingerprint-react\ndescription: Integrate Fingerprint into a React app: get the visitor_id.\n---\n\n# Fingerprint React\n\nSee `snippets/provider.jsx`.",
	"skills/fingerprint-react/skill.json":            `{"id": "fingerprint-react"}`,
	"skills/fingerprint-react/snippets/provider.jsx": "export const Provider = () => null",
	"skills/fingerprint-proxy-integration/SKILL.md":  "---\nname: fingerprint-proxy-integration\ndescription: \"Serve Fingerprint from your own subdomain so ad blockers do not block it\"\n---\n\n# Proxy",
	"skills/no-skill-file/notes.md":                  "not a skill",
}

func skillsRepoServer(t *testing.T, available *atomic.Bool) *httptest.Server {
	t.Helper()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if available != nil && !available.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if r.URL.Path == "/tree" {
			type entry struct {
				Path string `json:"path"`
				Type string `json:"type"`
			}
			tree := []entry{{Path: "skills", Type: "tree"}, {Path: "skills/fingerprint-react", Type: "tree"}}
			for path := range testSkillsRepo {
				tree = append(tree, entry{Path: path, Type: "blob"})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"tree": tree})
			return
		}
		body, ok := testSkillsRepo[strings.TrimPrefix(r.URL.Path, "/raw/")]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(ts.Close)

	return ts
}

func skillsSession(t *testing.T, options ...OptFunc) *mcp.ClientSession {
	t.Helper()

	o := &opts{l: slog.New(slog.NewTextHandler(io.Discard, nil))}
	for _, f := range options {
		f(o)
	}

	app, err := New(&config.Config{}, o)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := context.Background()
	if err := app.registerTools(ctx); err != nil {
		t.Fatalf("registerTools: %v", err)
	}

	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	serverSession, err := app.server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { _ = serverSession.Close() })

	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	return session
}

func withTestSkills(t *testing.T, available *atomic.Bool) OptFunc {
	ts := skillsRepoServer(t, available)
	return WithSkillsRepo(ts.URL+"/tree", ts.URL+"/raw/")
}

func callSkillsTool(t *testing.T, session *mcp.ClientSession, name string, args map[string]any, out any) *mcp.CallToolResult {
	t.Helper()

	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool(%s): %v", name, err)
	}
	if out != nil && !res.IsError {
		text := res.Content[0].(*mcp.TextContent).Text
		if err := json.Unmarshal([]byte(text), out); err != nil {
			t.Fatalf("decoding %s result: %v\n%s", name, err, text)
		}
	}
	return res
}

func errorCode(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()

	if !res.IsError {
		t.Fatalf("expected an error result, got %+v", res.Content)
	}
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(res.Content[0].(*mcp.TextContent).Text), &body); err != nil {
		t.Fatalf("decoding error result: %v", err)
	}
	return body.Error.Code
}

func TestListSkills_ReturnsSkillsWithDescriptions(t *testing.T) {
	session := skillsSession(t, withTestSkills(t, nil))

	var out ListSkillsOutput
	callSkillsTool(t, session, "list_skills", nil, &out)

	want := []SkillSummary{
		{ID: "fingerprint-proxy-integration", Description: "Serve Fingerprint from your own subdomain so ad blockers do not block it"},
		{ID: "fingerprint-react", Description: "Integrate Fingerprint into a React app: get the visitor_id."},
	}
	if !slices.Equal(out.Skills, want) {
		t.Errorf("list_skills = %+v, want %+v", out.Skills, want)
	}
}

func TestSkillsTools_OnlyListSkillsIsOnTheManifest(t *testing.T) {
	session := skillsSession(t, withTestSkills(t, nil))

	tools, err := session.ListTools(context.Background(), &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	var names []string
	for _, tool := range tools.Tools {
		names = append(names, tool.Name)
	}
	if !slices.Contains(names, "list_skills") {
		t.Errorf("list_skills should be on the manifest: %v", names)
	}
	for _, hidden := range []string{"get_skill", "get_skill_file"} {
		if slices.Contains(names, hidden) {
			t.Errorf("%s should only be reachable through call_tool: %v", hidden, names)
		}
	}

	var listed ListToolsOutput
	callSkillsTool(t, session, "list_tools", nil, &listed)
	for _, hidden := range []string{"get_skill", "get_skill_file"} {
		i := slices.IndexFunc(listed.Tools, func(l ListedTool) bool { return l.Name == hidden })
		if i < 0 {
			t.Errorf("list_tools should report %s", hidden)
			continue
		}
		if got := listed.Tools[i].RunWith; got != "call_tool" {
			t.Errorf("%s run_with = %q, want call_tool", hidden, got)
		}
	}
}

func TestGetSkill_ReturnsBodyAndFiles(t *testing.T) {
	session := skillsSession(t, withTestSkills(t, nil))

	var out GetSkillOutput
	callSkillsTool(t, session, "call_tool", map[string]any{"tool_name": "get_skill", "arguments": map[string]any{"id": "fingerprint-react"}}, &out)

	if strings.HasPrefix(out.Content, "---") || !strings.Contains(out.Content, "# Fingerprint React") {
		t.Errorf("content should be the skill body without frontmatter:\n%s", out.Content)
	}
	if want := []string{"skill.json", "snippets/provider.jsx"}; !slices.Equal(out.Files, want) {
		t.Errorf("files = %v, want %v", out.Files, want)
	}
}

func TestGetSkillFile_ReturnsListedFile(t *testing.T) {
	session := skillsSession(t, withTestSkills(t, nil))

	var out GetSkillFileOutput
	callSkillsTool(t, session, "call_tool", map[string]any{"tool_name": "get_skill_file", "arguments": map[string]any{"id": "fingerprint-react", "path": "snippets/provider.jsx"}}, &out)

	if out.Content != testSkillsRepo["skills/fingerprint-react/snippets/provider.jsx"] {
		t.Errorf("content = %q", out.Content)
	}
}

func TestSkillsTools_RejectUnknownIDsAndPaths(t *testing.T) {
	session := skillsSession(t, withTestSkills(t, nil))

	tests := []struct {
		name string
		tool string
		args map[string]any
		code string
	}{
		{"unknown skill", "get_skill", map[string]any{"id": "nope"}, "skill_not_found"},
		{"directory without SKILL.md", "get_skill", map[string]any{"id": "no-skill-file"}, "skill_not_found"},
		{"file outside the skill", "get_skill_file", map[string]any{"id": "fingerprint-react", "path": "../../README.md"}, "skill_file_not_found"},
		{"unlisted file", "get_skill_file", map[string]any{"id": "fingerprint-react", "path": "snippets/missing.jsx"}, "skill_file_not_found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := callSkillsTool(t, session, "call_tool", map[string]any{"tool_name": tt.tool, "arguments": tt.args}, nil)
			if got := errorCode(t, res); got != tt.code {
				t.Errorf("code = %q, want %q", got, tt.code)
			}
		})
	}
}

func TestListSkills_ReportsUnavailableRepo(t *testing.T) {
	var available atomic.Bool
	session := skillsSession(t, withTestSkills(t, &available))

	res := callSkillsTool(t, session, "list_skills", nil, nil)
	if got := errorCode(t, res); got != "skills_unavailable" {
		t.Errorf("code = %q, want skills_unavailable", got)
	}
}

func TestSkillsTools_DisabledWithoutRepo(t *testing.T) {
	session := skillsSession(t, WithSkillsRepo("", ""))

	var listed ListToolsOutput
	callSkillsTool(t, session, "list_tools", nil, &listed)
	for _, l := range listed.Tools {
		if strings.Contains(l.Name, "skill") {
			t.Errorf("%s should not be served without a skills repo", l.Name)
		}
	}
}

func TestRemoteSkill_CachesWithinTTL(t *testing.T) {
	ts, hits := skillServer(t, testRemoteSkill, nil)
	r := &remoteSkill{url: ts.URL, ttl: time.Hour}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	for range 3 {
		if _, ok := r.get(context.Background(), logger); !ok {
			t.Fatal("expected a cached or fetched skill")
		}
	}

	if got := hits.Load(); got != 1 {
		t.Errorf("expected 1 fetch across 3 gets, got %d", got)
	}
}

func TestRemoteSkill_RejectsOversizedDocument(t *testing.T) {
	ts, _ := skillServer(t, strings.Repeat("x", skillsMaxBytes+1), nil)
	r := &remoteSkill{url: ts.URL, ttl: time.Hour}

	if content, ok := r.get(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil))); ok {
		t.Errorf("an oversized document should be rejected, not truncated to %d bytes", len(content))
	}
}

func TestRemoteSkill_ServesStaleWhenRefetchFails(t *testing.T) {
	var status atomic.Int32
	status.Store(http.StatusOK)
	ts, hits := skillServer(t, testRemoteSkill, &status)

	// A zero TTL forces the second get onto the refresh path.
	r := &remoteSkill{url: ts.URL, ttl: 0}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	first, ok := r.get(context.Background(), logger)
	if !ok {
		t.Fatal("expected the first fetch to succeed")
	}

	status.Store(http.StatusInternalServerError)

	second, ok := r.get(context.Background(), logger)
	if !ok {
		t.Fatal("expected the cached copy to be served after a failed refetch")
	}
	if second != first {
		t.Errorf("stale content differs from the original:\n%q\n%q", second, first)
	}

	before := hits.Load()
	for range 3 {
		if _, ok := r.get(context.Background(), logger); !ok {
			t.Fatal("expected the cached copy to keep being served")
		}
	}
	if got := hits.Load(); got != before {
		t.Errorf("a failed refetch should back off, got %d more attempts", got-before)
	}
}

func TestStripFrontmatter(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"with frontmatter", "---\nname: x\n---\nbody\n", "body\n"},
		{"no frontmatter", "body\n", "body\n"},
		{"unterminated frontmatter is left alone", "---\nname: x\nbody\n", "---\nname: x\nbody\n"},
		{"blank lines after frontmatter are trimmed", "---\nname: x\n---\n\n\nbody", "body"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := stripFrontmatter(tt.in); got != tt.want {
				t.Errorf("stripFrontmatter(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
