package access

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// inlineSink captures what the inline fallbacks would persist to the config.
type inlineSink struct {
	table  Table
	grants []Grant
}

// fileHooks reach plain files, standing in for the bucket openers the site
// injects.
func fileHooks(sink *inlineSink) Hooks {
	return Hooks{
		Open: func(_ context.Context, path string) (io.ReadCloser, error) {
			return os.Open(path)
		},
		OpenWrite: func(_ context.Context, path string) (io.WriteCloser, error) {
			return os.Create(path)
		},
		SaveTableInline: func(_ context.Context, table Table) error {
			if sink == nil {
				return errors.New("no inline sink")
			}
			sink.table = table
			return nil
		},
		SaveGrantsInline: func(_ context.Context, grants []Grant) error {
			if sink == nil {
				return errors.New("no inline sink")
			}
			sink.grants = grants
			return nil
		},
	}
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// With no paths set nothing moves: a deployment whose config still carries
// its acl and grants inline keeps working, which is what lets this ship
// before any config is split.
func TestLoadFallsBackToTheConfig(t *testing.T) {
	c := New(fileHooks(nil))
	err := c.Load(context.Background(), Sources{
		FallbackTable:  Table{"Root": {"Search": {}}},
		FallbackGrants: []Grant{{Email: "a@example.com", Tier: "Root"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Table()["Root"]; !ok {
		t.Errorf("table did not come from the fallback: %v", c.Table())
	}
	if len(c.Grants()) != 1 {
		t.Errorf("got %d grants from the fallback, want 1", len(c.Grants()))
	}
}

// A path wins over the inline fields, and reaches a plain file through the
// same call a bucket url would.
func TestLoadReadsThePaths(t *testing.T) {
	dir := t.TempDir()
	tablePath := filepath.Join(dir, "acl.json")
	writeJSON(t, tablePath, Table{"Root": {"Search": {}}, "Mods": {"Search": {}}})
	grantsPath := filepath.Join(dir, "grants.json")
	writeJSON(t, grantsPath, []Grant{
		{Email: "a@example.com", Tier: "Root"},
		{Email: "b@example.com", Tier: "Mods"},
	})

	c := New(fileHooks(nil))
	err := c.Load(context.Background(), Sources{
		TablePath:      tablePath,
		GrantsPath:     grantsPath,
		FallbackTable:  Table{"Inline": {}},
		FallbackGrants: []Grant{{Email: "inline@example.com"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Table()["Inline"]; ok || len(c.Table()) != 2 {
		t.Errorf("table did not come from the path: %v", c.Table())
	}
	if len(c.Grants()) != 2 || c.Grants()[0].Email != "a@example.com" {
		t.Errorf("grants did not come from the path: %v", c.Grants())
	}
}

// A configured path that cannot be read is an error, not a silent fallback:
// enforcing an empty table would lock everyone out without saying why.
func TestLoadReportsAMissingFile(t *testing.T) {
	c := New(fileHooks(nil))
	err := c.Load(context.Background(), Sources{
		TablePath:     filepath.Join(t.TempDir(), "nope.json"),
		FallbackTable: Table{"Inline": {}},
	})
	if err == nil {
		t.Fatal("missing table path did not error")
	}
}

// With a grants path set, a save writes the file and publishes the new list.
func TestSaveGrantsWritesThePath(t *testing.T) {
	dir := t.TempDir()
	grantsPath := filepath.Join(dir, "grants.json")
	writeJSON(t, grantsPath, []Grant{{Email: "a@example.com"}})

	c := New(fileHooks(nil))
	err := c.Load(context.Background(), Sources{GrantsPath: grantsPath})
	if err != nil {
		t.Fatal(err)
	}
	next := append([]Grant{}, c.Grants()...)
	next = append(next, Grant{Email: "b@example.com", Tier: "Mods"})
	if err := c.SaveGrants(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	if len(c.Grants()) != 2 {
		t.Errorf("published %d grants, want 2", len(c.Grants()))
	}
	var onDisk []Grant
	data, err := os.ReadFile(grantsPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &onDisk); err != nil {
		t.Fatal(err)
	}
	if len(onDisk) != 2 || onDisk[1].Email != "b@example.com" {
		t.Errorf("file holds %v, want the saved pair", onDisk)
	}
}

// Without a grants path the save goes through the inline hook — the config
// write-back — and still publishes on success.
func TestSaveGrantsFallsBackInline(t *testing.T) {
	var sink inlineSink
	c := New(fileHooks(&sink))
	err := c.Load(context.Background(), Sources{
		FallbackGrants: []Grant{{Email: "a@example.com"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	next := []Grant{{Email: "a@example.com"}, {Email: "b@example.com"}}
	if err := c.SaveGrants(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	if len(sink.grants) != 2 {
		t.Errorf("inline sink got %d grants, want 2", len(sink.grants))
	}
	if len(c.Grants()) != 2 {
		t.Errorf("published %d grants, want 2", len(c.Grants()))
	}
}

// With a table path set, a save writes the file and publishes the new table.
func TestSaveTableWritesThePath(t *testing.T) {
	dir := t.TempDir()
	tablePath := filepath.Join(dir, "acl.json")
	writeJSON(t, tablePath, Table{"Root": {"Search": {}}})

	c := New(fileHooks(nil))
	err := c.Load(context.Background(), Sources{TablePath: tablePath})
	if err != nil {
		t.Fatal(err)
	}
	next := Table{"Root": {"Search": {}}, "Mods": {"Search": {}}}
	if err := c.SaveTable(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	if len(c.Table()) != 2 {
		t.Errorf("published %d tiers, want 2", len(c.Table()))
	}
	var onDisk Table
	data, err := os.ReadFile(tablePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &onDisk); err != nil {
		t.Fatal(err)
	}
	if _, ok := onDisk["Mods"]; !ok || len(onDisk) != 2 {
		t.Errorf("file holds %v, want the saved pair", onDisk)
	}
}

// Without a table path the save goes through the inline hook — the config
// write-back — and still publishes on success.
func TestSaveTableFallsBackInline(t *testing.T) {
	var sink inlineSink
	c := New(fileHooks(&sink))
	err := c.Load(context.Background(), Sources{
		FallbackTable: Table{"Root": {"Search": {}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	next := Table{"Root": {"Search": {}}, "Mods": {"Search": {}}}
	if err := c.SaveTable(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	if len(sink.table) != 2 {
		t.Errorf("inline sink got %d tiers, want 2", len(sink.table))
	}
	if len(c.Table()) != 2 {
		t.Errorf("published %d tiers, want 2", len(c.Table()))
	}
}
