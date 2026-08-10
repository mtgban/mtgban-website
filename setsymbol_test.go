package main

import (
	"os"
	"testing"
)

func TestBadgeFilesParse(t *testing.T) {
	entries, err := os.ReadDir("img/setsymbol/lorcana")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 8 {
		t.Fatalf("got %d files, want 8", len(entries))
	}
	for _, entry := range entries {
		badge, err := readBadge("img/setsymbol/lorcana/" + entry.Name())
		if err != nil {
			t.Fatalf("%s: %s", entry.Name(), err)
		}
		t.Logf("%-14s font %4.1f  y %4.1f  %.40s...", entry.Name(), badge.Font, badge.TextY, badge.Path)
	}
	fallback, err := readBadge("img/setsymbol/default.svg")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%-14s font %4.1f  y %4.1f  %s", "default.svg", fallback.Font, fallback.TextY, fallback.Path)
}
