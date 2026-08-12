package mgmtapi

import (
	"encoding/json"
	"testing"
	"time"
)

// The Management API spells these three fields differently on the list and
// single-get endpoints. Both payloads below are the real shapes, captured from
// GET /api-keys and GET /api-keys/{id} against the same key.
func TestAPIKey_UnmarshalAcceptsBothFieldSpellings(t *testing.T) {
	want := time.Date(2025, 1, 31, 15, 53, 52, 180_000_000, time.UTC)

	cases := []struct {
		name string
		body string
	}{
		{
			// GET /api-keys
			name: "snake_case, as the list endpoint sends",
			body: `{"id":"tok_0cj","name":"test","type":"public","status":"enabled",
			        "rate_limit":5,"created_at":"2025-01-31T15:53:52.180Z","disabled_at":null}`,
		},
		{
			// GET /api-keys/{id}
			name: "camelCase, as the single-get endpoint sends",
			body: `{"id":"tok_0cj","name":"test","type":"public","status":"enabled",
			        "rateLimit":5,"createdAt":"2025-01-31T15:53:52.180Z","disabledAt":null}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var k APIKey
			if err := json.Unmarshal([]byte(tc.body), &k); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if !k.CreatedAt.Equal(want) {
				t.Errorf("CreatedAt = %v, want %v", k.CreatedAt, want)
			}
			if k.RateLimit != 5 {
				t.Errorf("RateLimit = %v, want 5", k.RateLimit)
			}
			// Fields spelled the same either way must survive the custom decode.
			if k.ID != "tok_0cj" || k.Name != "test" || k.Type != "public" || k.Status != "enabled" {
				t.Errorf("single-word fields lost: %+v", k)
			}
		})
	}
}

// A disabled key carries a timestamp, and it's spelled differently per endpoint
// like the others. Enabled keys send null, which is why this never surfaced.
func TestAPIKey_UnmarshalReadsDisabledAtEitherWay(t *testing.T) {
	want := time.Date(2026, 6, 10, 9, 0, 0, 0, time.UTC)

	for _, body := range []string{
		`{"id":"t","disabled_at":"2026-06-10T09:00:00Z","status":"disabled"}`,
		`{"id":"t","disabledAt":"2026-06-10T09:00:00Z","status":"disabled"}`,
	} {
		var k APIKey
		if err := json.Unmarshal([]byte(body), &k); err != nil {
			t.Fatalf("unmarshal %s: %v", body, err)
		}
		if k.DisabledAt == nil || !k.DisabledAt.Equal(want) {
			t.Errorf("DisabledAt = %v, want %v (from %s)", k.DisabledAt, want, body)
		}
	}
}

// If the API ever sends both, the documented spelling has to win rather than
// the fallback silently overwriting it.
func TestAPIKey_UnmarshalPrefersSnakeCaseWhenBothPresent(t *testing.T) {
	body := `{"id":"t","rate_limit":5,"rateLimit":99,
	          "created_at":"2025-01-31T15:53:52.180Z","createdAt":"2001-01-01T00:00:00Z"}`

	var k APIKey
	if err := json.Unmarshal([]byte(body), &k); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if k.RateLimit != 5 {
		t.Errorf("RateLimit = %v, want the snake_case 5", k.RateLimit)
	}
	if k.CreatedAt.Year() != 2025 {
		t.Errorf("CreatedAt = %v, want the snake_case 2025 value", k.CreatedAt)
	}
}

// Malformed input must still error rather than yielding a zero-valued key.
func TestAPIKey_UnmarshalPropagatesErrors(t *testing.T) {
	var k APIKey
	if err := json.Unmarshal([]byte(`{"created_at":"not-a-time"}`), &k); err == nil {
		t.Error("expected an error for an unparseable timestamp, got nil")
	}
}
