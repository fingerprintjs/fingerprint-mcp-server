package fpmcpserver

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestAnalyticsResourceURI(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "templated event URI is reduced to template",
			in:   "fingerprint://events/abc-123-def",
			want: "fingerprint://events/{event_id}",
		},
		{
			name: "events prefix without an id passes through",
			in:   "fingerprint://events/",
			want: "fingerprint://events/",
		},
		{
			name: "static schema URI passes through unchanged",
			in:   "fingerprint://schemas/event",
			want: "fingerprint://schemas/event",
		},
		{
			name: "static api-key schema URI passes through unchanged",
			in:   "fingerprint://schemas/api-key",
			want: "fingerprint://schemas/api-key",
		},
		{
			name: "empty URI stays empty",
			in:   "",
			want: "",
		},
		{
			name: "unknown scheme passes through",
			in:   "https://example.com/foo",
			want: "https://example.com/foo",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := analyticsResourceURI(tc.in); got != tc.want {
				t.Errorf("analyticsResourceURI(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestCapForAmplitude(t *testing.T) {
	t.Run("short ASCII passes through unchanged", func(t *testing.T) {
		in := "get_event"
		if got := capForAmplitude(in); got != in {
			t.Errorf("capForAmplitude(%q) = %q, want %q", in, got, in)
		}
	})

	t.Run("exactly at limit passes through unchanged", func(t *testing.T) {
		in := strings.Repeat("a", amplitudePropMaxLen)
		if got := capForAmplitude(in); got != in {
			t.Errorf("expected unchanged at exactly the limit; len(in)=%d len(got)=%d", len(in), len(got))
		}
	})

	t.Run("ASCII over the limit is truncated to the limit", func(t *testing.T) {
		in := strings.Repeat("x", amplitudePropMaxLen+100)
		got := capForAmplitude(in)
		if len(got) != amplitudePropMaxLen {
			t.Errorf("len(got)=%d, want %d", len(got), amplitudePropMaxLen)
		}
	})

	t.Run("multi-byte UTF-8 is never truncated mid-rune", func(t *testing.T) {
		// Each emoji is 4 bytes; build a string longer than the limit so
		// we land right at a multi-byte boundary.
		emoji := "🙂" // 4 bytes
		in := strings.Repeat(emoji, (amplitudePropMaxLen/4)+10)
		got := capForAmplitude(in)
		if !utf8.ValidString(got) {
			t.Errorf("truncated string is not valid UTF-8: %q", got)
		}
		if len(got) > amplitudePropMaxLen {
			t.Errorf("len(got)=%d exceeds cap %d", len(got), amplitudePropMaxLen)
		}
	})

	t.Run("empty string passes through", func(t *testing.T) {
		if got := capForAmplitude(""); got != "" {
			t.Errorf("capForAmplitude(\"\") = %q, want empty", got)
		}
	})
}
