package fpmcpserver

import (
	"testing"
	"time"

	"github.com/fingerprintjs/fingerprint-mcp-server/config"
)

func TestEmitAnalytics_SkipsPing(t *testing.T) {
	tests := []struct {
		name   string
		method string
		want   int
	}{
		{"ping is dropped", "ping", 0},
		{"tool call still reports", "tools/call", 1},
		{"handshake still reports", "initialize", 1},
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
				subID:    "sub_test_ping",
				duration: 3 * time.Millisecond,
			})

			if got := len(emitter.snapshot()); got != tt.want {
				t.Errorf("%s: emitted %d events, want %d", tt.method, got, tt.want)
			}
		})
	}
}
