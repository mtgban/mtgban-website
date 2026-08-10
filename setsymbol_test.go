package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBadgeFilesParse reads every drawing under img/setsymbol the way the
// server does at startup. A malformed one degrades quietly there — the badge
// falls back to a circle — so it fails here instead.
func TestBadgeFilesParse(t *testing.T) {
	var files []string
	err := filepath.WalkDir("img/setsymbol", func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && strings.HasSuffix(path, ".svg") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no set symbols found")
	}

	for _, path := range files {
		badge, err := readBadge(path)
		if err != nil {
			t.Errorf("%s: %s", path, err)
			continue
		}
		t.Logf("%-40s font %4.1f  y %4.1f", path, badge.Font, badge.TextY)
	}
}
