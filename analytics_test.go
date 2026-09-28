package fpmcpserver

import (
	"testing"
	"time"

	"github.com/fingerprintjs/fingerprint-mcp-server/config"
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
