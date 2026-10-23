package siteorigin

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOf(t *testing.T) {
	tests := []struct {
		name, host, proto, want string
	}{
		{"forwarded", "onepiece.mtgban.com", "https", "https://onepiece.mtgban.com"},
		{"forwarded first hop", "onepiece.mtgban.com, attacker.example", "https, http", "https://onepiece.mtgban.com"},
		{"port", "magic.mtgban.com:8080", "", "http://magic.mtgban.com:8080"},
		{"untrusted", "attacker.example", "https", ""},
		{"malformed trusted suffix", "junk onepiece.mtgban.com", "https", ""},
		{"invalid port", "onepiece.mtgban.com:port", "https", ""},
		{"invalid proto", "onepiece.mtgban.com", "ftp", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Host = tt.host
			if tt.proto != "" {
				req.Header.Set("X-Forwarded-Proto", tt.proto)
			}
			if strings.Contains(tt.host, ",") {
				req.Header.Set("X-Forwarded-Host", tt.host)
				req.Host = "internal:8080"
			}
			if got := Of(req); got != tt.want {
				t.Fatalf("Of = %q, want %q", got, tt.want)
			}
		})
	}

	if got := Of(nil); got != "" {
		t.Fatalf("Of(nil) = %q, want empty", got)
	}

	req := httptest.NewRequest("GET", "https://onepiece.mtgban.com/", nil)
	if got := Of(req); got != "https://onepiece.mtgban.com" {
		t.Fatalf("host-only HTTPS Of = %q, want https://onepiece.mtgban.com", got)
	}
}
