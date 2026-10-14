package userstate

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

// freshShareOwner is freshHash for the share tests: the owner's user_state
// row and shares are cleared before and after.
func freshShareOwner(t *testing.T, c *Client) string {
	t.Helper()
	h := freshHash(t, c)
	wipe := func() {
		if _, err := c.db.Exec(`DELETE FROM favorites_shares WHERE email_hash = $1`, h); err != nil {
			t.Fatalf("cleanup shares: %v", err)
		}
	}
	wipe()
	t.Cleanup(wipe)
	return h
}

func TestCreateShareMakesAValidID(t *testing.T) {
	c := testClient(t)
	h := freshShareOwner(t, c)

	id, err := c.CreateShare(context.Background(), h, "")
	if err != nil {
		t.Fatalf("CreateShare: %v", err)
	}
	if !ValidShareID(id) {
		t.Fatalf("CreateShare returned %q, not a 22-character base64url id", id)
	}
	got, err := c.ShareFor(context.Background(), h)
	if err != nil || got != id {
		t.Fatalf("ShareFor = %q, %v; want %q", got, err, id)
	}
}

// One live link per owner: sharing again retires the old link.
func TestCreateShareRevokesTheOldOne(t *testing.T) {
	c := testClient(t)
	h := freshShareOwner(t, c)
	ctx := context.Background()

	first, err := c.CreateShare(ctx, h, "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.CreateShare(ctx, h, "")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatalf("second share reused the id %q", first)
	}
	if got, _ := c.ShareFor(ctx, h); got != second {
		t.Fatalf("ShareFor = %q, want the second id %q", got, second)
	}
	if _, err := c.SharedFavorites(ctx, first, ""); !errors.Is(err, ErrShareNotFound) {
		t.Fatalf("old id still answers: %v", err)
	}
}

func TestRevokeShareEndsTheLink(t *testing.T) {
	c := testClient(t)
	h := freshShareOwner(t, c)
	ctx := context.Background()

	id, err := c.CreateShare(ctx, h, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.RevokeShare(ctx, h); err != nil {
		t.Fatalf("RevokeShare: %v", err)
	}
	if got, err := c.ShareFor(ctx, h); err != nil || got != "" {
		t.Fatalf("ShareFor after revoke = %q, %v; want empty", got, err)
	}
	if _, err := c.SharedFavorites(ctx, id, ""); !errors.Is(err, ErrShareNotFound) {
		t.Fatalf("revoked id still answers: %v", err)
	}
	// Revoking with nothing live is not an error.
	if err := c.RevokeShare(ctx, h); err != nil {
		t.Fatalf("second RevokeShare: %v", err)
	}
}

func TestSharedFavoritesReadsTheOwnersList(t *testing.T) {
	c := testClient(t)
	h := freshShareOwner(t, c)
	ctx := context.Background()

	id, err := c.CreateShare(ctx, h, "")
	if err != nil {
		t.Fatal(err)
	}
	// An owner with no row yet shares an empty list.
	raw, err := c.SharedFavorites(ctx, id, "")
	if err != nil || string(raw) != "[]" {
		t.Fatalf("SharedFavorites before any sync = %s, %v; want []", raw, err)
	}
	if _, _, err := c.Patch(ctx, h, "favorites", []byte(`[{"id":"card-1","name":"Sol Ring","t":1}]`), 0); err != nil {
		t.Fatalf("Patch: %v", err)
	}
	raw, err = c.SharedFavorites(ctx, id, "")
	if err != nil {
		t.Fatalf("SharedFavorites: %v", err)
	}
	if string(raw) == "[]" || !strings.Contains(string(raw), `"card-1"`) {
		t.Fatalf("SharedFavorites = %s, want the synced list", raw)
	}
	if _, err := c.SharedFavorites(ctx, "AAAAAAAAAAAAAAAAAAAAAA", ""); !errors.Is(err, ErrShareNotFound) {
		t.Fatalf("unknown id: %v, want ErrShareNotFound", err)
	}
}

func TestValidShareID(t *testing.T) {
	tests := []struct {
		id string
		ok bool
	}{
		{"AAAAAAAAAAAAAAAAAAAAAA", true},
		{"abcdefghijklmnopqrstu_", true},
		{"abcdefghijklmnopqrst-9", true},
		{"", false},
		{"AAAAAAAAAAAAAAAAAAAAA", false},   // 21
		{"AAAAAAAAAAAAAAAAAAAAAAA", false}, // 23
		{"AAAAAAAAAAAAAAAAAAAAA=", false},  // padding
		{"AAAAAAAAAAAAAAAAAAAAA/", false},  // standard base64
		{"AAAAAAAAAAAAAAAAAAAA A", false},
	}
	for _, tt := range tests {
		if got := ValidShareID(tt.id); got != tt.ok {
			t.Errorf("ValidShareID(%q) = %v, want %v", tt.id, got, tt.ok)
		}
	}
}

// A share answers only on its own game's site.
func TestSharedFavoritesIsScopedToTheGame(t *testing.T) {
	c := testClient(t)
	h := freshShareOwner(t, c)
	ctx := context.Background()

	id, err := c.CreateShare(ctx, h, "lorcana")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.SharedFavorites(ctx, id, ""); !errors.Is(err, ErrShareNotFound) {
		t.Fatalf("lorcana share on the default site: %v, want ErrShareNotFound", err)
	}
	if _, err := c.SharedFavorites(ctx, id, "lorcana"); err != nil {
		t.Fatalf("lorcana share on its own site: %v", err)
	}
}

// Two creates at once for one owner leave one live share, and both report it.
func TestCreateShareRaceLeavesOneLive(t *testing.T) {
	c := testClient(t)
	h := freshShareOwner(t, c)
	ctx := context.Background()

	var wg sync.WaitGroup
	ids := make([]string, 2)
	errs := make([]error, 2)
	for i := range ids {
		wg.Go(func() { ids[i], errs[i] = c.CreateShare(ctx, h, "") })
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("CreateShare %d: %v", i, err)
		}
	}
	var live int
	if err := c.db.QueryRow(`SELECT count(*) FROM favorites_shares WHERE email_hash = $1 AND revoked_at IS NULL`, h).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if live != 1 {
		t.Fatalf("%d live shares, want 1", live)
	}
	cur, err := c.ShareFor(ctx, h)
	if err != nil {
		t.Fatal(err)
	}
	if ids[0] != cur && ids[1] != cur {
		t.Fatalf("neither create (%q, %q) reported the live id %q", ids[0], ids[1], cur)
	}
}
