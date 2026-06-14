package userstate

import (
	"context"
	"encoding/json"
	"testing"
)

func freshHash(t *testing.T, c *Client) string {
	t.Helper()
	h := HashEmail(t.Name() + "@example.com")
	if _, err := c.db.Exec(`DELETE FROM user_state WHERE email_hash = $1`, h); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	t.Cleanup(func() { c.db.Exec(`DELETE FROM user_state WHERE email_hash = $1`, h) })
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
