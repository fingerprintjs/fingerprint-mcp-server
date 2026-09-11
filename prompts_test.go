package fpmcpserver

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
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

func getOnboardingPrompt(t *testing.T, options ...OptFunc) string {
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
	if err := app.registerPrompts(ctx); err != nil {
		t.Fatalf("registerPrompts: %v", err)
	}

	return promptText(t, app, ctx)
}

func promptText(t *testing.T, app *App, ctx context.Context) string {
	t.Helper()

	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	serverSession, err := app.server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	defer serverSession.Close()

	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer session.Close()

	res, err := session.GetPrompt(ctx, &mcp.GetPromptParams{Name: "onboarding"})
	if err != nil {
		t.Fatalf("GetPrompt: %v", err)
	}
	if len(res.Messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(res.Messages))
	}

	text, ok := res.Messages[0].Content.(*mcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", res.Messages[0].Content)
	}

	return text.Text
}

func TestOnboardingPrompt_InlinesFetchedSkill(t *testing.T) {
	ts, hits := skillServer(t, testRemoteSkill, nil)

	text := getOnboardingPrompt(t, WithGetStartedSkillURL(ts.URL))

	if strings.Contains(text, getStartedPlaceholder) {
		t.Errorf("placeholder was not substituted:\n%s", text)
	}
	if !strings.Contains(text, "Detect the stack, then install identification.") {
		t.Errorf("fetched skill body missing from prompt:\n%s", text)
	}
	if strings.Contains(text, "name: fingerprint-get-started") {
		t.Errorf("fetched frontmatter leaked into prompt:\n%s", text)
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("expected 1 fetch, got %d", got)
	}
}

func TestOnboardingPrompt_FallsBackWhenFetchFails(t *testing.T) {
	var status atomic.Int32
	status.Store(http.StatusInternalServerError)
	ts, _ := skillServer(t, testRemoteSkill, &status)

	text := getOnboardingPrompt(t, WithGetStartedSkillURL(ts.URL))

	if strings.Contains(text, getStartedPlaceholder) {
		t.Errorf("placeholder was not substituted:\n%s", text)
	}
	if !strings.Contains(text, "Fetch and follow "+ts.URL) {
		t.Errorf("fallback pointer missing from prompt:\n%s", text)
	}
}

func TestOnboardingPrompt_FetchDisabled(t *testing.T) {
	_, hits := skillServer(t, testRemoteSkill, nil)

	text := getOnboardingPrompt(t, WithGetStartedSkillURL(""))

	if strings.Contains(text, getStartedPlaceholder) {
		t.Errorf("placeholder was not substituted:\n%s", text)
	}
	if !strings.Contains(text, "Fetch and follow "+defaultGetStartedURL) {
		t.Errorf("disabled fetching should point at the default URL:\n%s", text)
	}
	if got := hits.Load(); got != 0 {
		t.Errorf("expected no fetch when disabled, got %d", got)
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
	ts, _ := skillServer(t, strings.Repeat("x", getStartedMaxBytes+1), nil)
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
