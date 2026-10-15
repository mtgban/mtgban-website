package userstate

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
)

func freshHash(t *testing.T, c *Client) string {
	t.Helper()
	h := HashEmail(t.Name() + "@example.com")
	if _, err := c.db.Exec(`DELETE FROM user_state WHERE email_hash = $1`, h); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	t.Cleanup(func() { _, _ = c.db.Exec(`DELETE FROM user_state WHERE email_hash = $1`, h) })
	return h
}

func TestGetMissingReturnsZeroState(t *testing.T) {
	c := testClient(t)
	h := freshHash(t, c)

	st, err := c.Get(context.Background(), h)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if st.Version != 0 {
		t.Fatalf("expected version 0, got %d", st.Version)
	}
	if string(st.Favorites) != "[]" || string(st.Recents) != "[]" || string(st.Preferences) != "{}" {
		t.Fatalf("expected zero state, got %+v", st)
	}
}

func TestPutCreatesAndBumpsVersion(t *testing.T) {
	c := testClient(t)
	h := freshHash(t, c)
	ctx := context.Background()

	st := State{
		Favorites:   json.RawMessage(`[{"id":"x"}]`),
		Recents:     json.RawMessage(`[{"q":"bolt"}]`),
		Preferences: json.RawMessage(`{"theme":"dark"}`),
	}
	res, conflict, err := c.Put(ctx, h, st, 0)
	if err != nil || conflict {
		t.Fatalf("Put create: conflict=%v err=%v", conflict, err)
	}
	if res.Version != 1 {
		t.Fatalf("expected version 1, got %d", res.Version)
	}

	got, err := c.Get(ctx, h)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Version != 1 {
		t.Fatalf("expected version 1, got %d", got.Version)
	}
}

func TestPutVersionConflictReturnsCurrent(t *testing.T) {
	c := testClient(t)
	h := freshHash(t, c)
	ctx := context.Background()

	if _, _, err := c.Put(ctx, h, State{
		Favorites: json.RawMessage(`[{"id":"a"}]`), Recents: json.RawMessage(`[]`), Preferences: json.RawMessage(`{}`),
	}, 0); err != nil {
		t.Fatalf("seed Put: %v", err)
	}

	// Stale expected version 0 must conflict and return the current state.
	res, conflict, err := c.Put(ctx, h, State{
		Favorites: json.RawMessage(`[{"id":"b"}]`), Recents: json.RawMessage(`[]`), Preferences: json.RawMessage(`{}`),
	}, 0)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if !conflict {
		t.Fatal("expected version conflict")
	}
	if res.Version != 1 {
		t.Fatalf("conflict should return current version 1, got %d", res.Version)
	}
	if string(res.Favorites) == "" || string(res.Favorites) == "[]" {
		t.Fatalf("conflict should return current favorites, got %q", res.Favorites)
	}
}

func TestPatchUpdatesOneSection(t *testing.T) {
	c := testClient(t)
	h := freshHash(t, c)
	ctx := context.Background()

	seed, _, err := c.Put(ctx, h, State{
		Favorites: json.RawMessage(`[]`), Recents: json.RawMessage(`[]`), Preferences: json.RawMessage(`{}`),
	}, 0)
	if err != nil {
		t.Fatalf("seed Put: %v", err)
	}

	res, conflict, err := c.Patch(ctx, h, "favorites", json.RawMessage(`[{"id":"z"}]`), seed.Version)
	if err != nil || conflict {
		t.Fatalf("Patch: conflict=%v err=%v", conflict, err)
	}
	if res.Version != seed.Version+1 {
		t.Fatalf("expected version %d, got %d", seed.Version+1, res.Version)
	}

	got, _ := c.Get(ctx, h)
	if string(got.Recents) != "[]" {
		t.Fatalf("recents should be untouched, got %s", got.Recents)
	}
	if len(got.Favorites) == 0 || string(got.Favorites) == "[]" {
		t.Fatalf("favorites should be updated, got %s", got.Favorites)
	}
}

func TestGetVersion(t *testing.T) {
	c := testClient(t)
	h := freshHash(t, c)
	ctx := context.Background()

	v, err := c.GetVersion(ctx, h)
	if err != nil {
		t.Fatalf("GetVersion missing: %v", err)
	}
	if v != 0 {
		t.Fatalf("missing row should report version 0, got %d", v)
	}

	if _, _, err := c.Put(ctx, h, State{
		Favorites: json.RawMessage(`[]`), Recents: json.RawMessage(`[]`), Preferences: json.RawMessage(`{}`),
	}, 0); err != nil {
		t.Fatalf("Put: %v", err)
	}
	v, err = c.GetVersion(ctx, h)
	if err != nil {
		t.Fatalf("GetVersion: %v", err)
	}
	if v != 1 {
		t.Fatalf("expected version 1, got %d", v)
	}
}

func TestPatchRejectsUnknownSection(t *testing.T) {
	c := testClient(t)
	h := freshHash(t, c)
	if _, _, err := c.Patch(context.Background(), h, "bogus", json.RawMessage(`{}`), 0); err == nil {
		t.Fatal("expected error for unknown section")
	}
}

// sameBackpack compares decoded entries: JSONB reorders keys and spacing.
func sameBackpack(t *testing.T, got, want json.RawMessage) bool {
	t.Helper()
	type entry struct {
		ID  string `json:"id"`
		Qty int    `json:"qty"`
		T   int    `json:"t"`
		M   int    `json:"m"`
	}
	var g, w []entry
	if err := json.Unmarshal(got, &g); err != nil {
		t.Fatalf("decode got %s: %v", got, err)
	}
	if err := json.Unmarshal(want, &w); err != nil {
		t.Fatalf("decode want %s: %v", want, err)
	}
	return slices.Equal(g, w)
}

func TestBackpackIsASection(t *testing.T) {
	c := testClient(t)
	h := freshHash(t, c)

	st, err := c.Get(context.Background(), h)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(st.Backpack) != "[]" {
		t.Fatalf("zero backpack: %s", st.Backpack)
	}

	pack := json.RawMessage(`[{"id":"abc","qty":2,"t":1,"m":1}]`)
	res, conflict, err := c.Patch(context.Background(), h, "backpack", pack, 0)
	if err != nil || conflict {
		t.Fatalf("Patch: err=%v conflict=%v", err, conflict)
	}
	if !sameBackpack(t, res.Backpack, pack) || string(res.Favorites) != "[]" {
		t.Fatalf("after patch: %+v", res)
	}

	st, err = c.Get(context.Background(), h)
	if err != nil || !sameBackpack(t, st.Backpack, pack) || st.Version != 1 {
		t.Fatalf("Get after patch: %+v err=%v", st, err)
	}

	st.Favorites = json.RawMessage(`[{"id":"f1"}]`)
	res, conflict, err = c.Put(context.Background(), h, st, st.Version)
	if err != nil || conflict {
		t.Fatalf("Put: err=%v conflict=%v", err, conflict)
	}
	if !sameBackpack(t, res.Backpack, pack) {
		t.Fatalf("Put dropped the backpack: %s", res.Backpack)
	}

	res, conflict, err = c.Patch(context.Background(), h, "favorites", json.RawMessage(`[{"id":"f2"}]`), res.Version)
	if err != nil || conflict || !sameBackpack(t, res.Backpack, pack) {
		t.Fatalf("Patch favorites touched the backpack: %+v conflict=%v err=%v", res, conflict, err)
	}
}

func TestPutWithoutBackpackKeepsIt(t *testing.T) {
	c := testClient(t)
	h := freshHash(t, c)
	ctx := context.Background()

	pack := json.RawMessage(`[{"id":"abc","qty":3,"t":1,"m":1}]`)
	res, conflict, err := c.Patch(ctx, h, "backpack", pack, 0)
	if err != nil || conflict {
		t.Fatalf("Patch: err=%v conflict=%v", err, conflict)
	}

	// An old client's PUT carries no backpack key.
	old := State{Favorites: json.RawMessage(`[{"id":"f1"}]`), Recents: json.RawMessage(`[]`), Preferences: json.RawMessage(`{}`)}
	res, conflict, err = c.Put(ctx, h, old, res.Version)
	if err != nil || conflict {
		t.Fatalf("Put without backpack: err=%v conflict=%v", err, conflict)
	}
	got, err := c.Get(ctx, h)
	if err != nil || !sameBackpack(t, got.Backpack, pack) {
		t.Fatalf("backpack after a Put without it: %s err=%v", got.Backpack, err)
	}

	repl := json.RawMessage(`[{"id":"xyz","qty":1,"t":2,"m":2}]`)
	old.Backpack = repl
	if _, conflict, err = c.Put(ctx, h, old, res.Version); err != nil || conflict {
		t.Fatalf("Put with backpack: err=%v conflict=%v", err, conflict)
	}
	got, err = c.Get(ctx, h)
	if err != nil || !sameBackpack(t, got.Backpack, repl) {
		t.Fatalf("backpack after a Put with one: %s err=%v", got.Backpack, err)
	}
}

func TestEnsureSchemaIsIdempotent(t *testing.T) {
	c := testClient(t)
	if _, err := c.db.Exec(createTableSQL); err != nil {
		t.Fatalf("create again: %v", err)
	}
	if _, err := c.db.Exec(addBackpackSQL); err != nil {
		t.Fatalf("alter again: %v", err)
	}
	// NewClient skips the ALTER when this finds the column.
	var one int
	if err := c.db.QueryRow(backpackColumnSQL).Scan(&one); err != nil || one != 1 {
		t.Fatalf("column lookup: one=%d err=%v", one, err)
	}
}
