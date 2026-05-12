package fpmcpserver

import (
	"net/http"
	"testing"
)

func TestExtractClientIP(t *testing.T) {
	// Headers built via http.Header.Set so keys are stored canonically,
	// matching how Go's net/http server populates extra.Header for real
	// requests (Set canonicalises keys before insertion).
	mkHeader := func(pairs ...[2]string) http.Header {
		h := http.Header{}
		for _, p := range pairs {
			h.Set(p[0], p[1])
		}
		return h
	}

	cases := []struct {
		name   string
		header http.Header
		want   string
	}{
		{
			name:   "nil header (stdio transport — no HTTP request)",
			header: nil,
			want:   "",
		},
		{
			name:   "empty header (HTTP request without proxy headers)",
			header: http.Header{},
			want:   "",
		},
		{
			name:   "single IP in X-Forwarded-For",
			header: mkHeader([2]string{"X-Forwarded-For", "203.0.113.42"}),
			want:   "203.0.113.42",
		},
		{
			name:   "comma-separated XFF takes first IP (original client)",
			header: mkHeader([2]string{"X-Forwarded-For", "203.0.113.42, 10.0.0.1, 10.0.0.2"}),
			want:   "203.0.113.42",
		},
		{
			name:   "XFF with whitespace gets trimmed",
			header: mkHeader([2]string{"X-Forwarded-For", "   203.0.113.42   "}),
			want:   "203.0.113.42",
		},
		{
			name:   "IPv6 address in XFF passes through",
			header: mkHeader([2]string{"X-Forwarded-For", "2001:db8::1"}),
			want:   "2001:db8::1",
		},
		{
			name:   "comma-separated IPv6 chain takes first",
			header: mkHeader([2]string{"X-Forwarded-For", "2001:db8::1, 10.0.0.1"}),
			want:   "2001:db8::1",
		},
		{
			name:   "X-Real-IP fallback when XFF absent",
			header: mkHeader([2]string{"X-Real-IP", "198.51.100.7"}),
			want:   "198.51.100.7",
		},
		{
			name: "XFF preferred over X-Real-IP when both present",
			header: mkHeader(
				[2]string{"X-Forwarded-For", "203.0.113.42"},
				[2]string{"X-Real-IP", "198.51.100.7"},
			),
			want: "203.0.113.42",
		},
		{
			name:   "leading comma in XFF yields empty (degenerate header)",
			header: mkHeader([2]string{"X-Forwarded-For", ",1.2.3.4"}),
			want:   "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractClientIP(tc.header); got != tc.want {
				t.Errorf("extractClientIP(%v) = %q, want %q", tc.header, got, tc.want)
			}
		})
	}
}
