package schema

import (
	"encoding/json"
	"strings"
	"testing"
)

// Regression tests for $defs pruning.
//
// Before the fix, SchemaFromStruct embedded the entire ~62KB OpenAPI
// definitions blob into the $defs of every schema it generated, even for
// structs that reference no definitions at all. That bloated the advertised
// schemas of get_event, search_events, and get_current_time enough that
// size-limited MCP clients (e.g. the claude.ai connector) silently dropped
// them from tools/list. These tests pin the pruned behavior.

func schemaMap(t *testing.T, raw json.RawMessage) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal schema: %v", err)
	}
	return m
}

func defKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// A struct with no $ref fields must carry no $defs at all.
func TestSchemaFromStruct_NoRefs_OmitsDefs(t *testing.T) {
	type noRef struct {
		Name string `json:"name"`
		Age  int    `json:"age,omitempty"`
	}
	raw := SchemaFromStruct(noRef{})

	if _, ok := schemaMap(t, raw)["$defs"]; ok {
		t.Errorf("struct with no $ref should carry no $defs")
	}
	// The full defs blob is ~62KB; a lean schema is a few hundred bytes.
	if len(raw) > 2000 {
		t.Errorf("schema is %d bytes; the full OpenAPI defs blob is likely still embedded", len(raw))
	}
	if strings.Contains(string(raw), "BotInfo") {
		t.Errorf("schema embeds unrelated definition BotInfo; $defs were not pruned")
	}
}

// A $ref to a leaf definition pulls in only that definition.
func TestSchemaFromStruct_LeafRef_PrunesToThatDef(t *testing.T) {
	type withLeafRef struct {
		Bot string `json:"bot" ref:"BotResult"`
	}
	defs, ok := schemaMap(t, SchemaFromStruct(withLeafRef{}))["$defs"].(map[string]any)
	if !ok {
		t.Fatalf("expected a $defs object")
	}
	if _, ok := defs["BotResult"]; !ok {
		t.Errorf("expected BotResult in $defs, got %v", defKeys(defs))
	}
	if _, ok := defs["Event"]; ok {
		t.Errorf("unrelated def Event should have been pruned, got %v", defKeys(defs))
	}
	if len(defs) != 1 {
		t.Errorf("expected exactly 1 def (BotResult), got %d: %v", len(defs), defKeys(defs))
	}
}

// A $ref to Event must pull in its transitive closure (Event nests other refs
// such as BotResult), otherwise the resulting schema is invalid.
func TestSchemaFromStruct_Ref_IncludesTransitiveClosure(t *testing.T) {
	type withEvent struct {
		Event any `json:"event" ref:"Event"`
	}
	defs, ok := schemaMap(t, SchemaFromStruct(withEvent{}))["$defs"].(map[string]any)
	if !ok {
		t.Fatalf("expected a $defs object")
	}
	for _, want := range []string{"Event", "BotResult"} {
		if _, ok := defs[want]; !ok {
			t.Errorf("expected transitive def %q, got %v", want, defKeys(defs))
		}
	}
}
