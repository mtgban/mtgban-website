package main

import (
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/mtgban/mtgban-website/observability"
)

// The script list and js/ agree both ways, and no two files share a basename.
func TestScriptListMatchesTheJSDirectory(t *testing.T) {
	var onDisk []string
	err := filepath.WalkDir("js", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".js") {
			onDisk = append(onDisk, filepath.Base(p))
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(onDisk)
	if dup := slices.Compact(slices.Clone(onDisk)); len(dup) != len(onDisk) {
		t.Fatal("two files under js/ share a basename; an error row could not tell them apart")
	}
	if got := observability.Scripts(); !slices.Equal(got, onDisk) {
		t.Errorf("observability.Scripts() is out of step with js/:\n got  %v\n want %v", got, onDisk)
	}
}
