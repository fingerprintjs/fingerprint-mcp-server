package fpmcpserver

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/fingerprintjs/fingerprint-mcp-server/config"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestEmitAnalytics_OnlyTracksInteractiveMethods(t *testing.T) {
	tests := []struct {
		name   string
		method string
		want   int
	}{
		{"tool call reports", "tools/call", 1},
		{"prompt fetch reports", "prompts/get", 1},
		{"resource read reports", "resources/read", 1},
		{"legacy handshake is dropped", "initialize", 0},
		{"modern handshake is dropped", "server/discover", 0},
		{"ping is dropped", "ping", 0},
		{"initialized notification is dropped", "notifications/initialized", 0},
		{"subscription listen is dropped", "subscriptions/listen", 0},
		{"tool listing is dropped", "tools/list", 0},
		{"prompt listing is dropped", "prompts/list", 0},
		{"resource listing is dropped", "resources/list", 0},
		{"resource template listing is dropped", "resources/templates/list", 0},
		{"unknown future method is dropped", "subscriptions/whatever", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			emitter := newRecordingEmitter()
			app, err := New(&config.Config{Transport: "streamable-http"}, &opts{emitter: emitter})
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			app.emitAnalytics(analyticsInputs{
				method:   tt.method,
				subID:    "sub_test_methods",
				duration: 3 * time.Millisecond,
			})

			if got := len(emitter.snapshot()); got != tt.want {
				t.Errorf("%s: emitted %d events, want %d", tt.method, got, tt.want)
			}
		})
	}
}

func TestEmitAnalytics_ReportsTheToolBehindAProxy(t *testing.T) {
	tests := []struct {
		name      string
		toolName  string
		arguments string
		want      string
	}{
		{"read proxy", "call_tool", `{"tool_name":"get_subdomain","arguments":{"id":"certv2_x"}}`, "get_subdomain"},
		{"write proxy", "call_write_tool", `{"tool_name":"create_subdomain","arguments":{"hostname":"metrics.example.com"}}`, "create_subdomain"},
		{"direct call has no target", "get_subdomain", `{"id":"certv2_x"}`, ""},
		{"proxy without a tool name", "call_tool", `{"arguments":{}}`, ""},
		{"proxy with unreadable arguments", "call_write_tool", `not json`, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			emitter := newRecordingEmitter()
			app, err := New(&config.Config{Transport: "streamable-http"}, &opts{emitter: emitter})
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Name: tt.toolName, Arguments: json.RawMessage(tt.arguments)}}
			app.emitAnalytics(analyticsInputs{
				req:      req,
				method:   "tools/call",
				toolName: tt.toolName,
				subID:    "sub_test_proxy",
				duration: time.Millisecond,
			})

			events := emitter.snapshot()
			if len(events) != 1 {
				t.Fatalf("emitted %d events, want 1", len(events))
			}
			got, _ := events[0].Properties["target_tool"].(string)
			if got != tt.want {
				t.Errorf("target_tool = %q, want %q", got, tt.want)
			}
			if events[0].Properties["tool_name"] != tt.toolName {
				t.Errorf("tool_name = %v, want %q", events[0].Properties["tool_name"], tt.toolName)
			}
		})
	}
}
