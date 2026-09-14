package access

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// fileHooks reach plain files, standing in for the bucket openers the site
// injects.
func fileHooks() Hooks {
	return Hooks{
		Open: func(_ context.Context, path string) (io.ReadCloser, error) {
			return os.Open(path)
		},
		OpenWrite: func(_ context.Context, path string) (io.WriteCloser, error) {
			return os.Create(path)
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

// With no path configured, Load, SaveTable and SaveGrants all refuse rather
// than reaching for a path that names no file: an empty path would
// otherwise resolve to a confusing filesystem error instead of naming the
// real problem.
func TestNoPathConfiguredIsRefused(t *testing.T) {
	c := New(fileHooks())
	if err := c.Load(context.Background(), Sources{}); err == nil {
		t.Error("Load with no paths did not error")
	}
	if err := c.SaveTable(context.Background(), Table{}); err == nil {
		t.Error("SaveTable with no table path did not error")
	}
	if err := c.SaveGrants(context.Background(), nil); err == nil {
		t.Error("SaveGrants with no grants path did not error")
	}
}

// A Load reaches a plain file through the same call a bucket url would.
func TestLoadReadsThePaths(t *testing.T) {
	dir := t.TempDir()
	tablePath := filepath.Join(dir, "acl.json")
	writeJSON(t, tablePath, Table{"Root": {"Search": {}}, "Mods": {"Search": {}}})
	grantsPath := filepath.Join(dir, "grants.json")
	writeJSON(t, grantsPath, []Grant{
		{Email: "a@example.com", Tier: "Root"},
		{Email: "b@example.com", Tier: "Mods"},
	})

	c := New(fileHooks())
	err := c.Load(context.Background(), Sources{
		TablePath:  tablePath,
		GrantsPath: grantsPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Table()) != 2 {
		t.Errorf("table did not come from the path: %v", c.Table())
	}
	if len(c.Grants()) != 2 || c.Grants()[0].Email != "a@example.com" {
		t.Errorf("grants did not come from the path: %v", c.Grants())
	}
}

// A configured path that cannot be read is an error, not a silent fallback:
// enforcing an empty table would lock everyone out without saying why.
func TestLoadReportsAMissingFile(t *testing.T) {
	c := New(fileHooks())
	err := c.Load(context.Background(), Sources{
		TablePath: filepath.Join(t.TempDir(), "nope.json"),
	})
	if err == nil {
		t.Fatal("missing table path did not error")
	}
}

// A reload re-reads one value from the sources of the last Load and leaves
// the other alone: the two files change independently, and the point of the
// per-value reload is not re-fetching the one that didn't.
func TestReloadRefreshesOneValueOnly(t *testing.T) {
	dir := t.TempDir()
	tablePath := filepath.Join(dir, "acl.json")
	writeJSON(t, tablePath, Table{"Root": {"Search": {}}})
	grantsPath := filepath.Join(dir, "grants.json")
	writeJSON(t, grantsPath, []Grant{{Email: "a@example.com"}})

	c := New(fileHooks())
	err := c.Load(context.Background(), Sources{
		TablePath:  tablePath,
		GrantsPath: grantsPath,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Both files change behind the client's back, as a peer's save would.
	writeJSON(t, tablePath, Table{"Root": {"Search": {}}, "Mods": {"Search": {}}})
	writeJSON(t, grantsPath, []Grant{{Email: "a@example.com"}, {Email: "b@example.com"}})

	if err := c.ReloadGrants(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(c.Grants()) != 2 {
		t.Errorf("reload published %d grants, want 2", len(c.Grants()))
	}
	if len(c.Table()) != 1 {
		t.Errorf("grants reload touched the table: %v", c.Table())
	}

	if err := c.ReloadTable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(c.Table()) != 2 {
		t.Errorf("reload published %d tiers, want 2", len(c.Table()))
	}
}

// A reload that fails keeps the value it could not replace, mirroring Load's
// no-fallback-on-error rule.
func TestReloadKeepsTheValueOnError(t *testing.T) {
	dir := t.TempDir()
	tablePath := filepath.Join(dir, "acl.json")
	writeJSON(t, tablePath, Table{"Root": {"Search": {}}})
	grantsPath := filepath.Join(dir, "grants.json")
	writeJSON(t, grantsPath, []Grant{{Email: "a@example.com"}})

	c := New(fileHooks())
	err := c.Load(context.Background(), Sources{TablePath: tablePath, GrantsPath: grantsPath})
	if err != nil {
		t.Fatal(err)
	}

	if err := os.Remove(tablePath); err != nil {
		t.Fatal(err)
	}
	if err := c.ReloadTable(context.Background()); err == nil {
		t.Fatal("missing table path did not error")
	}
	if _, ok := c.Table()["Root"]; !ok {
		t.Errorf("failed reload dropped the table: %v", c.Table())
	}
}

// A save writes the grants file and publishes the new list.
func TestSaveGrantsWritesThePath(t *testing.T) {
	dir := t.TempDir()
	tablePath := filepath.Join(dir, "acl.json")
	writeJSON(t, tablePath, Table{"Root": {"Search": {}}})
	grantsPath := filepath.Join(dir, "grants.json")
	writeJSON(t, grantsPath, []Grant{{Email: "a@example.com"}})

	c := New(fileHooks())
	err := c.Load(context.Background(), Sources{TablePath: tablePath, GrantsPath: grantsPath})
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

// A save writes the table file and publishes the new table.
func TestSaveTableWritesThePath(t *testing.T) {
	dir := t.TempDir()
	tablePath := filepath.Join(dir, "acl.json")
	writeJSON(t, tablePath, Table{"Root": {"Search": {}}})
	grantsPath := filepath.Join(dir, "grants.json")
	writeJSON(t, grantsPath, []Grant{{Email: "a@example.com"}})

	c := New(fileHooks())
	err := c.Load(context.Background(), Sources{TablePath: tablePath, GrantsPath: grantsPath})
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
