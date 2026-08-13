package main

import "testing"

// A redirect parameter must never leave the site. The backslash cases are the
// ones a leading-slash test lets through: a browser reads "/\evil.com" the way
// it reads "//evil.com".
func TestIsLocalRedirect(t *testing.T) {
	for _, tt := range []struct {
		target string
		want   bool
	}{
		{"/", true},
		{"/search", true},
		{"/search?q=a/b", true},
		{"", false},
		{"//evil.com", false},
		{`/\evil.com`, false},
		{`/\\evil.com`, false},
		{"https://evil.com", false},
		{"javascript:alert(1)", false},
		{"data:text/html,<script>alert(1)</script>", false},
		{`\\evil.com`, false},
		{"evil.com", false},
	} {
		if got := isLocalRedirect(tt.target); got != tt.want {
			t.Errorf("isLocalRedirect(%q) = %v, want %v", tt.target, got, tt.want)
		}
	}
}
