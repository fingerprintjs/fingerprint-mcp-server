package schema

import (
	"encoding/json"
	"strings"
	"testing"
)

// Asserts the embedded MCP input schema advertises start/end as RFC3339 strings
// (not Unix ms) and that the descriptions steer AI tools away from training
// cutoff dates.
func TestSearchEventsInputSchema_StartEndAreRFC3339Strings(t *testing.T) {
	var doc map[string]any
	if err := json.Unmarshal(SearchEventsInputSchema, &doc); err != nil {
		t.Fatalf("unmarshal SearchEventsInputSchema: %v", err)
	}

	props, ok := doc["properties"].(map[string]any)
	if !ok {
		t.Fatalf("schema has no properties object")
	}

	for _, name := range []string{"start", "end"} {
		t.Run(name, func(t *testing.T) {
			prop, ok := props[name].(map[string]any)
			if !ok {
				t.Fatalf("property %q missing from schema", name)
			}

			if got := prop["type"]; got != "string" {
				t.Errorf("property %q: type = %v, want %q", name, got, "string")
			}
			if got := prop["format"]; got != "date-time" {
				t.Errorf("property %q: format = %v, want %q", name, got, "date-time")
			}

			desc, _ := prop["description"].(string)
			if desc == "" {
				t.Fatalf("property %q: description is empty", name)
			}
			for _, want := range []string{"RFC3339", "training data"} {
				if !strings.Contains(desc, want) {
					t.Errorf("property %q: description missing %q\n--- description ---\n%s", name, want, desc)
				}
			}
		})
	}
}
