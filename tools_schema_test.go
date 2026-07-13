package fpmcpserver

import (
	"strings"
	"testing"

	"github.com/fingerprintjs/fingerprint-mcp-server/internal/schema"
)

// get_current_time references no OpenAPI definitions, so neither its input nor
// output schema should embed the smart-signal defs blob. Before the pruning
// fix both carried the full ~62KB blob, bloating tools/list enough that
// size-limited MCP clients dropped get_current_time — and, by pushing the
// whole payload over the limit, get_event/search_events with it.
func TestGetCurrentTimeSchemas_AreLean(t *testing.T) {
	cases := map[string][]byte{
		"input":  schema.SchemaFromStruct(GetCurrentTimeInput{}),
		"output": schema.SchemaFromStruct(GetCurrentTimeOutput{}),
	}
	for name, raw := range cases {
		if strings.Contains(string(raw), "$defs") {
			t.Errorf("get_current_time %s schema embeds $defs it does not reference (%d bytes)", name, len(raw))
		}
		if strings.Contains(string(raw), "BotInfo") || strings.Contains(string(raw), "IPInfo") {
			t.Errorf("get_current_time %s schema embeds unrelated smart-signal defs", name)
		}
		if len(raw) > 2000 {
			t.Errorf("get_current_time %s schema is %d bytes; expected lean", name, len(raw))
		}
	}
}

// get_event's input references no defs (must be lean); its output references
// Event and must still carry the Event definition.
func TestGetEventSchemas_InputLeanOutputHasEvent(t *testing.T) {
	in := schema.SchemaFromStruct(GetEventInput{})
	if strings.Contains(string(in), "$defs") {
		t.Errorf("get_event input schema should not embed $defs, got %d bytes", len(in))
	}

	out := schema.SchemaFromStruct(GetEventOutput{})
	if !strings.Contains(string(out), `"Event"`) {
		t.Errorf("get_event output schema must include the Event definition")
	}
}
