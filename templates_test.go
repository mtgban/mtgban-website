package main

import "testing"

// TestTemplatesParse parses every template the way production does (via the
// shared funcMap), catching syntax errors and references to unregistered
// template functions such as a mistyped buylist_badge.
func TestTemplatesParse(t *testing.T) {
	saved := DevMode
	DevMode = false
	defer func() { DevMode = saved }()

	if _, err := buildTemplateCache(); err != nil {
		t.Fatalf("templates failed to parse: %v", err)
	}
}
