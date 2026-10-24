package access

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
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

// Two tables are equal when every tier gives every page the same options,
// whatever allocated them, and a nil table is an empty one.
func TestTableEqual(t *testing.T) {
	table := func() Table {
		return Table{
			"Legacy":  {"Search": {"SearchDownloadCSV": "true"}, "Upload": {}},
			"Vintage": {"Search": {"SearchDownloadCSV": "true"}},
		}
	}

	for _, tc := range []struct {
		name  string
		other func() Table
		want  bool
	}{
		{"the same table", table, true},
		{"a flag flipped", func() Table {
			other := table()
			other["Legacy"]["Search"]["SearchDownloadCSV"] = "false"
			return other
		}, false},
		{"an option added", func() Table {
			other := table()
			other["Legacy"]["Search"]["SearchBuylistBlockList"] = "x"
			return other
		}, false},
		{"an option removed", func() Table {
			other := table()
			delete(other["Legacy"]["Search"], "SearchDownloadCSV")
			return other
		}, false},
		{"a feature removed", func() Table {
			other := table()
			delete(other["Legacy"], "Upload")
			return other
		}, false},
		{"a feature added", func() Table {
			other := table()
			other["Vintage"]["Arbit"] = map[string]string{}
			return other
		}, false},
		{"a tier added", func() Table {
			other := table()
			other["Pioneer"] = map[string]map[string]string{"Search": {}}
			return other
		}, false},
		{"a tier removed", func() Table {
			other := table()
			delete(other, "Vintage")
			return other
		}, false},
		{"a feature with no options against one with a nil map", func() Table {
			other := table()
			other["Legacy"]["Upload"] = nil
			return other
		}, true},
		{"nothing", func() Table { return nil }, false},
	} {
		got, back := table().Equal(tc.other()), tc.other().Equal(table())
		if got != tc.want || back != tc.want {
			t.Errorf("%s: equal %v and, the other way, %v; want %v", tc.name, got, back, tc.want)
		}
	}

	var none Table
	for name, other := range map[string]Table{"nil": nil, "empty": {}} {
		if !none.Equal(other) || !other.Equal(none) || !(Table{}).Equal(other) {
			t.Errorf("a nil table is not equal to the %s one", name)
		}
	}
	if none.Equal(table()) || (Table{}).Equal(table()) {
		t.Error("an empty table is equal to a table with tiers")
	}
}

// grantWithTier is g with its tier changed.
func grantWithTier(g Grant, tier string) Grant {
	g.Tier = tier
	return g
}

// grantWithOverrides is g with its overrides changed.
func grantWithOverrides(g Grant, overrides map[string]map[string]string) Grant {
	g.Overrides = overrides
	return g
}

// grantWithLabels is g with the name and category the admin page shows changed.
func grantWithLabels(g Grant, name, category string) Grant {
	g.Name, g.Category = name, category
	return g
}

// Of two grant lists, the emails to report are those whose grant a reader
// would feel: added, removed, or changed in the tier or the overrides the
// signature carries.
func TestGrantsChanged(t *testing.T) {
	csv := func(value string) map[string]map[string]string {
		return map[string]map[string]string{"Search": {"SearchDownloadCSV": value}}
	}
	a := Grant{Email: "a@example.com", Name: "A", Category: "friend", Tier: "Legacy"}
	b := Grant{Email: "b@example.com", Name: "B", Category: "mod", Tier: "Vintage", Overrides: csv("true")}
	c := Grant{Email: "c@example.com", Name: "C", Category: "friend", Tier: "Modern"}
	d := Grant{Email: "d@example.com", Tier: "Legacy"}
	before := []Grant{a, b, c}

	for _, tc := range []struct {
		name  string
		after []Grant
		want  []string
	}{
		{"nothing changed", []Grant{a, b, c}, nil},
		{"a grant added", []Grant{a, b, c, d}, []string{"d@example.com"}},
		{"a grant removed", []Grant{a, b}, []string{"c@example.com"}},
		{"a tier changed", []Grant{grantWithTier(a, "Vintage"), b, c}, []string{"a@example.com"}},
		{"a tier emptied", []Grant{grantWithTier(a, ""), b, c}, []string{"a@example.com"}},
		{"an override changed", []Grant{a, grantWithOverrides(b, csv("false")), c}, []string{"b@example.com"}},
		{"an override added", []Grant{a, b, grantWithOverrides(c, csv("true"))}, []string{"c@example.com"}},
		{"an override removed", []Grant{a, grantWithOverrides(b, nil), c}, []string{"b@example.com"}},
		{"a name and a category changed", []Grant{grantWithLabels(a, "Another", "mod"), grantWithLabels(b, "B", "friend"), c}, nil},
		{"the list reordered", []Grant{c, b, a}, nil},
		{"overrides emptied rather than absent", []Grant{grantWithOverrides(a, map[string]map[string]string{}), b, c}, nil},
		{"an email written in capitals", []Grant{{Email: " A@Example.COM ", Tier: "Legacy"}, b, c}, nil},
		{"several at once", []Grant{grantWithTier(a, "Vintage"), b, grantWithTier(c, "Pioneer"), {Email: "e@example.com"}},
			[]string{"a@example.com", "c@example.com", "e@example.com"}},
		{"everything removed", nil, []string{"a@example.com", "b@example.com", "c@example.com"}},
		{"a grant naming nobody", []Grant{a, b, c, {Tier: "Legacy"}, {Email: "  "}}, nil},
		{"a second grant of an email, the first deciding", []Grant{a, b, c, grantWithTier(a, "Vintage")}, nil},
		{"the first of two grants changed", []Grant{grantWithTier(a, "Vintage"), b, c, a}, []string{"a@example.com"}},
	} {
		got := GrantsChanged(before, tc.after)
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: changed %v, want %v", tc.name, got, tc.want)
		}
	}

	got := GrantsChanged(nil, before)
	if !slices.Equal(got, []string{"a@example.com", "b@example.com", "c@example.com"}) {
		t.Errorf("from no grants: changed %v, want all three", got)
	}
	got = GrantsChanged(nil, nil)
	if got != nil {
		t.Errorf("no grants either side: changed %v, want none", got)
	}
}
