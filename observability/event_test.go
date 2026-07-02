// observability/event_test.go
package observability

import "testing"

func TestNormalizePath(t *testing.T) {
	cases := []struct{ base, page, want string }{
		{"/newspaper", "", "newspaper/index"},
		{"/newspaper", "spike_score", "newspaper/spike_score"},
		{"/newspaper", "bogus", "newspaper/other"},
		{"/sleepers", "hotlist", "sleepers/hotlist"},
		{"/sleepers", "", "sleepers/index"},
		{"/search", "options", "search"},
		{"/arbit", "", "arbit"},
		{"/", "", "home"},
	}
	for _, c := range cases {
		if got := NormalizePath(c.base, c.page); got != c.want {
			t.Errorf("NormalizePath(%q,%q)=%q want %q", c.base, c.page, got, c.want)
		}
	}
}

func TestHashVisitor(t *testing.T) {
	if HashVisitor("") != "" {
		t.Fatal("empty email must hash to empty string")
	}
	a := HashVisitor("User@Example.com ")
	b := HashVisitor("user@example.com")
	if a != b {
		t.Fatalf("hash must be case/space insensitive: %q vs %q", a, b)
	}
	if len(a) != 64 {
		t.Fatalf("sha256 hex must be 64 chars, got %d", len(a))
	}
}

func TestIsBot(t *testing.T) {
	if IsBot("") {
		t.Fatal("empty UA is not a bot")
	}
	if !IsBot("Googlebot/2.1 (+http://www.google.com/bot.html)") {
		t.Fatal("Googlebot must classify as bot")
	}
	if IsBot("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15") {
		t.Fatal("a normal phone UA is not a bot")
	}
}
