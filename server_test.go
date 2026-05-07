package fpmcpserver

import "testing"

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
