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

// A host is the site's own when it is an apex or under one; a lookalike, a
// bare TLD and a host of another site are not.
func TestTrustedAndApex(t *testing.T) {
	for _, tt := range []struct {
		host string
		apex string // empty when not an apex host
		ok   bool
	}{
		{"www.mtgban.com", "mtgban.com", true},
		{"mtgban.com", "mtgban.com", true},
		{"lorcana.mtgban.com:8080", "mtgban.com", true},
		{"MTG.BAN.CARDS.", "ban.cards", true},
		{"mtg.ban.cards", "ban.cards", true},
		{"ban.cards", "ban.cards", true},
		{"localhost", "", true},
		{"localhost:8080", "", true},
		{"mtgban.com.evil.tld", "", false},
		{"ban.cards.evil.tld", "", false},
		{"xban.cards", "", false},
		{"notmtgban.com", "", false},
		{"cards", "", false},
		{"attacker.example", "", false},
		{"mtg.ban.cards:port", "", false},
		{"", "", false},
	} {
		if got := Trusted(tt.host); got != tt.ok {
			t.Errorf("Trusted(%q) = %v, want %v", tt.host, got, tt.ok)
		}
		if got := Apex(tt.host); got != tt.apex {
			t.Errorf("Apex(%q) = %q, want %q", tt.host, got, tt.apex)
		}
	}
}
