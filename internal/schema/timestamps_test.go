package schema

import (
	"encoding/json"
	"strings"
	"testing"
)

// roundTrip runs v through ReadableTimestamps and back into a generic map so
// assertions read against the JSON the client actually receives.
func roundTrip(t *testing.T, v any) map[string]any {
	t.Helper()
	b, err := json.Marshal(ReadableTimestamps(v))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out
}

func TestReadableTimestamps_ConvertsTopLevelAndNested(t *testing.T) {
	in := map[string]any{
		"timestamp": 1786458425180,
		"identification": map[string]any{
			"first_seen_at": 1786457929567,
			"last_seen_at":  1786458289028,
			"visitor_id":    "MXTOvUNDQApXCOodiqWJ",
		},
	}

	got := roundTrip(t, in)

	if got["timestamp"] != "2026-08-11T14:27:05.180Z" {
		t.Errorf("timestamp = %v, want 2026-08-11T14:27:05.180Z", got["timestamp"])
	}
	ident := got["identification"].(map[string]any)
	if ident["first_seen_at"] != "2026-08-11T14:18:49.567Z" {
		t.Errorf("first_seen_at = %v", ident["first_seen_at"])
	}
	if ident["last_seen_at"] != "2026-08-11T14:24:49.028Z" {
		t.Errorf("last_seen_at = %v", ident["last_seen_at"])
	}
	// Untouched neighbours must survive intact.
	if ident["visitor_id"] != "MXTOvUNDQApXCOodiqWJ" {
		t.Errorf("visitor_id = %v, want it unchanged", ident["visitor_id"])
	}
}

// search_events returns a list, so the walk has to descend through arrays.
func TestReadableTimestamps_ConvertsInsideArrays(t *testing.T) {
	in := map[string]any{
		"events": []any{
			map[string]any{"timestamp": 1786458425180},
			map[string]any{"timestamp": 1786458289028},
		},
		"pagination_key": "abc",
	}

	got := roundTrip(t, in)

	events := got["events"].([]any)
	if events[0].(map[string]any)["timestamp"] != "2026-08-11T14:27:05.180Z" {
		t.Errorf("events[0] = %v", events[0])
	}
	if events[1].(map[string]any)["timestamp"] != "2026-08-11T14:24:49.028Z" {
		t.Errorf("events[1] = %v", events[1])
	}
	if got["pagination_key"] != "abc" {
		t.Errorf("pagination_key = %v, want it unchanged", got["pagination_key"])
	}
}

// Precision is the reason for UseNumber: as a float64 a millisecond value is
// still exact, but the moment it round-trips through a formatter it can come
// back as 1.78645842518e+12.
func TestReadableTimestamps_KeepsMillisecondPrecision(t *testing.T) {
	got := roundTrip(t, map[string]any{"timestamp": 1786458425180})

	if got["timestamp"] != "2026-08-11T14:27:05.180Z" {
		t.Errorf("timestamp = %v, want the .180 preserved", got["timestamp"])
	}
}

// Zero means "no value" in the API, and 1970-01-01 would read as a real date.
func TestReadableTimestamps_LeavesZeroAlone(t *testing.T) {
	got := roundTrip(t, map[string]any{"timestamp": 0})

	if got["timestamp"] != float64(0) {
		t.Errorf("timestamp = %#v, want 0 left as-is", got["timestamp"])
	}
}

// A field that is already a string, or is null, must not be mangled.
func TestReadableTimestamps_IgnoresNonNumericValues(t *testing.T) {
	got := roundTrip(t, map[string]any{
		"timestamp":     "already-a-string",
		"last_seen_at":  nil,
		"first_seen_at": map[string]any{"nested": 1},
	})

	if got["timestamp"] != "already-a-string" {
		t.Errorf("timestamp = %v, want it untouched", got["timestamp"])
	}
	if got["last_seen_at"] != nil {
		t.Errorf("last_seen_at = %v, want nil", got["last_seen_at"])
	}
	if _, ok := got["first_seen_at"].(map[string]any); !ok {
		t.Errorf("first_seen_at = %#v, want the object untouched", got["first_seen_at"])
	}
}

// Only the four known epoch fields are eligible. A number under any other key
// stays a number, however timestamp-shaped it looks.
func TestReadableTimestamps_LeavesUnrelatedNumbersAlone(t *testing.T) {
	got := roundTrip(t, map[string]any{
		"suspect_score": 9,
		"confidence":    map[string]any{"score": 1},
		"velocity":      map[string]any{"events": map[string]any{"1_hour": 1786458425180}},
	})

	if got["suspect_score"] != float64(9) {
		t.Errorf("suspect_score = %v", got["suspect_score"])
	}
	vel := got["velocity"].(map[string]any)["events"].(map[string]any)
	if vel["1_hour"] != float64(1786458425180) {
		t.Errorf("velocity.events.1_hour = %v, want the number untouched", vel["1_hour"])
	}
}

// A payload that can't be marshalled comes back unchanged rather than failing
// the tool call.
func TestReadableTimestamps_ReturnsInputWhenUnmarshalable(t *testing.T) {
	in := map[string]any{"bad": make(chan int)}

	if got := ReadableTimestamps(in); got == nil {
		t.Error("expected the original value back, got nil")
	}
}

// The served schema has to describe what the server actually sends, or an
// agent reading fingerprint://schemas/event is told to expect an integer and
// receives a string.
func TestPatchTimestampFormat_RewritesEpochFields(t *testing.T) {
	in := json.RawMessage(`{
	  "$defs": {
	    "Event": {"properties": {
	      "timestamp": {"type": "integer", "description": "Timestamp of the event with millisecond precision in Unix time.", "example": 1786458425180},
	      "suspect_score": {"type": "integer", "description": "Suspect score"}
	    }},
	    "Identification": {"properties": {
	      "first_seen_at": {"type": "integer", "description": "Unix epoch time milliseconds timestamp indicating the time at which this visitor ID was first seen."}
	    }}
	  }
	}`)

	var got map[string]any
	if err := json.Unmarshal(PatchTimestampFormat(in), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	defs := got["$defs"].(map[string]any)

	ts := defs["Event"].(map[string]any)["properties"].(map[string]any)["timestamp"].(map[string]any)
	if ts["type"] != "string" || ts["format"] != "date-time" {
		t.Errorf("timestamp = %#v, want string/date-time", ts)
	}
	if _, hasExample := ts["example"]; hasExample {
		t.Error("expected the epoch example to be dropped, it contradicts the type")
	}
	if desc := ts["description"].(string); strings.Contains(desc, "Unix time") {
		t.Errorf("description still names Unix time: %q", desc)
	}

	fs := defs["Identification"].(map[string]any)["properties"].(map[string]any)["first_seen_at"].(map[string]any)
	if fs["type"] != "string" {
		t.Errorf("first_seen_at = %#v, want string", fs)
	}
	if desc := fs["description"].(string); !strings.HasPrefix(desc, "RFC3339 timestamp") {
		t.Errorf("description = %q, want the unit phrase replaced", desc)
	}

	// A same-typed neighbour must be left alone.
	ss := defs["Event"].(map[string]any)["properties"].(map[string]any)["suspect_score"].(map[string]any)
	if ss["type"] != "integer" {
		t.Errorf("suspect_score = %#v, want integer", ss)
	}
}

// Event.timestamp is a $ref to a top-level Timestamp def rather than an inline
// property, and the upstream spec writes its example into the description text
// instead of an example key. Both were missed by the first version of the patch
// and only showed up when the schema resource was read from a running server.
func TestPatchTimestampFormat_RewritesRefdDefsAndEmbeddedExamples(t *testing.T) {
	in := json.RawMessage(`{
	  "$defs": {
	    "Timestamp": {"type": "integer", "description": "Timestamp of the event with millisecond precision in Unix time."},
	    "FactoryReset": {"type": "integer", "description": "The time of the most recent factory reset."},
	    "Identification": {"properties": {
	      "first_seen_at": {"type": "integer", "description": "Unix epoch time milliseconds timestamp indicating the time at which this visitor ID was first seen. example: ` + "`" + `1758069706642` + "`" + ` - Corresponding to Wed Sep 17 2025 00:41:46 GMT+0000"}
	    }},
	    "Event": {"properties": {"timestamp": {"$ref": "#/$defs/Timestamp"}}}
	  }
	}`)

	var got map[string]any
	if err := json.Unmarshal(PatchTimestampFormat(in), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	defs := got["$defs"].(map[string]any)

	for _, name := range []string{"Timestamp", "FactoryReset"} {
		def := defs[name].(map[string]any)
		if def["type"] != "string" || def["format"] != "date-time" {
			t.Errorf("$defs.%s = %#v, want string/date-time", name, def)
		}
	}

	fs := defs["Identification"].(map[string]any)["properties"].(map[string]any)["first_seen_at"].(map[string]any)
	if desc := fs["description"].(string); strings.Contains(desc, "1758069706642") || strings.Contains(desc, "Corresponding to") {
		t.Errorf("description still carries the epoch example or its restatement: %q", desc)
	}
	if desc := fs["description"].(string); !strings.HasSuffix(desc, "first seen.") {
		t.Errorf("description = %q, want the meaning kept after stripping the example", desc)
	}

	// The $ref itself is left alone; only the definition it points at changes.
	ref := defs["Event"].(map[string]any)["properties"].(map[string]any)["timestamp"].(map[string]any)
	if ref["$ref"] != "#/$defs/Timestamp" {
		t.Errorf("Event.timestamp = %#v, want the $ref untouched", ref)
	}
}
