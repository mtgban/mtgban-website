package userstate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
	"time"
)

// freshInvite stores an open invite under a code no other test uses, and
// deletes it, with its redemptions, when the test ends.
func freshInvite(t *testing.T, c *Client, maxUses int) Invite {
	t.Helper()
	var buf [6]byte
	if _, err := rand.Read(buf[:]); err != nil {
		t.Fatal(err)
	}
	inv := Invite{
		Code: "t" + hex.EncodeToString(buf[:]), Game: "magic", Tier: "Pioneer",
		Overrides: map[string]map[string]string{"Upload": {"UploadOptimizer": "true"}},
		MaxUses:   maxUses, AccessDays: 7, OpenUntil: time.Now().Add(time.Hour),
		CreatedBy: "admin@example.com", CreatedIP: "198.51.100.7", CreatedUA: "test", CreatedSite: "test",
	}
	t.Cleanup(func() {
		if _, err := c.db.Exec(`DELETE FROM invites WHERE code = $1`, inv.Code); err != nil {
			t.Errorf("cleanup invite: %v", err)
		}
	})
	created, err := c.CreateInvite(context.Background(), inv)
	if err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}
	return created
}

func redeemOf(inv Invite, nonce string) Redeem {
	return Redeem{Code: inv.Code, Nonce: nonce, Tiers: []string{inv.Tier}, IP: "203.0.113.1", UA: "test", Site: "test"}
}

func TestCreateInviteRefusesATakenCode(t *testing.T) {
	c := testClient(t)
	inv := freshInvite(t, c, 1)
	if inv.Uses != 0 || inv.Overrides["Upload"]["UploadOptimizer"] != "true" || !inv.RevokedAt.IsZero() {
		t.Fatalf("created %+v", inv)
	}
	_, err := c.CreateInvite(context.Background(), inv)
	if !errors.Is(err, ErrInviteCodeTaken) {
		t.Fatalf("second CreateInvite: %v, want ErrInviteCodeTaken", err)
	}
}

func TestRedeemInviteSpendsEachUseOnce(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	inv := freshInvite(t, c, 1)

	red, err := c.RedeemInvite(ctx, redeemOf(inv, "first"))
	if err != nil || red.Repeat || red.Tier != inv.Tier || red.Overrides["Upload"]["UploadOptimizer"] != "true" {
		t.Fatalf("first redeem = %+v, %v", red, err)
	}
	if d := time.Until(red.ExpiresAt); d < 6*24*time.Hour || d > 8*24*time.Hour {
		t.Errorf("expires in %v, want about 7 days", d)
	}
	_, err = c.RedeemInvite(ctx, redeemOf(inv, "second"))
	if !errors.Is(err, ErrInviteClosed) {
		t.Fatalf("second redeem: %v, want ErrInviteClosed", err)
	}
	got, err := c.InviteByCode(ctx, inv.Code)
	if err != nil || got.Uses != 1 {
		t.Fatalf("InviteByCode = %+v, %v; want 1 use", got, err)
	}
	reds, err := c.InviteRedemptions(ctx, []string{inv.Code})
	if err != nil || len(reds[inv.Code]) != 1 || reds[inv.Code][0].IP != "203.0.113.1" {
		t.Fatalf("InviteRedemptions = %+v, %v", reds, err)
	}
}

// A double click sends the same nonce twice: whichever press loses the
// race gets the winner's redemption back, and only one use is spent.
func TestRedeemInviteAnswersARepeatedNonceFromItsRow(t *testing.T) {
	for _, maxUses := range []int{1, 3} {
		c := testClient(t)
		ctx := context.Background()
		inv := freshInvite(t, c, maxUses)

		const presses = 8
		start := make(chan struct{})
		results := make([]Redemption, presses)
		errs := make([]error, presses)
		var wg sync.WaitGroup
		for i := range presses {
			wg.Go(func() {
				<-start
				results[i], errs[i] = c.RedeemInvite(ctx, redeemOf(inv, "same"))
			})
		}
		close(start)
		wg.Wait()

		first := 0
		for i := range presses {
			if errs[i] != nil {
				t.Fatalf("max %d: press %d: %v", maxUses, i, errs[i])
			}
			if !results[i].Repeat {
				first++
			}
			if !results[i].ExpiresAt.Equal(results[0].ExpiresAt) {
				t.Errorf("max %d: press %d expires %v, press 0 %v", maxUses, i, results[i].ExpiresAt, results[0].ExpiresAt)
			}
		}
		if first != 1 {
			t.Errorf("max %d: %d presses spent a use, want 1", maxUses, first)
		}
		got, err := c.InviteByCode(ctx, inv.Code)
		if err != nil || got.Uses != 1 {
			t.Errorf("max %d: uses = %d, %v; want 1", maxUses, got.Uses, err)
		}
	}
}

// A repeated nonce re-signs the invite's tier, so it is refused once that
// tier is no longer one an invite may sign.
func TestRedeemInviteRefusesARepeatOfATierNoLongerAllowed(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	inv := freshInvite(t, c, 1)

	in := redeemOf(inv, "same")
	_, err := c.RedeemInvite(ctx, in)
	if err != nil {
		t.Fatalf("first redeem: %v", err)
	}
	in.Tiers = nil
	red, err := c.RedeemInvite(ctx, in)
	if !errors.Is(err, ErrInviteClosed) {
		t.Errorf("repeat = %+v, %v; want ErrInviteClosed", red, err)
	}
}

// Many people pressing at once on the last use: exactly one gets it.
func TestRedeemInviteGivesTheLastUseToOne(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	inv := freshInvite(t, c, 1)

	const presses = 8
	start := make(chan struct{})
	errs := make([]error, presses)
	var wg sync.WaitGroup
	for i := range presses {
		wg.Go(func() {
			<-start
			_, errs[i] = c.RedeemInvite(ctx, redeemOf(inv, string(rune('a'+i))))
		})
	}
	close(start)
	wg.Wait()

	won := 0
	for _, err := range errs {
		switch {
		case err == nil:
			won++
		case !errors.Is(err, ErrInviteClosed):
			t.Fatalf("redeem: %v", err)
		}
	}
	if won != 1 {
		t.Fatalf("%d presses won the one use", won)
	}
}

func TestRedeemInviteRefusesAClosedInvite(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	renamed := freshInvite(t, c, 5)
	in := redeemOf(renamed, "n")
	in.Tiers = []string{"Modern"}
	_, err := c.RedeemInvite(ctx, in)
	if !errors.Is(err, ErrInviteClosed) {
		t.Errorf("tier not allowed: %v, want ErrInviteClosed", err)
	}
	got, _ := c.InviteByCode(ctx, renamed.Code)
	if got.Uses != 0 {
		t.Errorf("tier not allowed spent %d uses", got.Uses)
	}

	revoked := freshInvite(t, c, 5)
	err = c.RevokeInvite(ctx, revoked.Code, "admin@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.RevokeInvite(ctx, revoked.Code, "admin@example.com"); !errors.Is(err, ErrInviteNotFound) {
		t.Errorf("second revoke: %v, want ErrInviteNotFound", err)
	}
	_, err = c.RedeemInvite(ctx, redeemOf(revoked, "n"))
	if !errors.Is(err, ErrInviteClosed) {
		t.Errorf("revoked: %v, want ErrInviteClosed", err)
	}

	expired := freshInvite(t, c, 5)
	if _, err := c.db.Exec(`UPDATE invites SET open_until = now() - interval '1 minute' WHERE code = $1`, expired.Code); err != nil {
		t.Fatal(err)
	}
	_, err = c.RedeemInvite(ctx, redeemOf(expired, "n"))
	if !errors.Is(err, ErrInviteClosed) {
		t.Errorf("expired: %v, want ErrInviteClosed", err)
	}

	if _, err := c.InviteByCode(ctx, "tnosuchcode"); !errors.Is(err, ErrInviteNotFound) {
		t.Errorf("unknown code: %v, want ErrInviteNotFound", err)
	}
}

// An invite goes 90 days after it closed, by expiry or by revocation,
// whichever came first, and its redemptions with it.
func TestPruneInvitesKeepsNinetyDays(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	recent := freshInvite(t, c, 1)
	if _, err := c.RedeemInvite(ctx, redeemOf(recent, "n")); err != nil {
		t.Fatal(err)
	}
	old := freshInvite(t, c, 1)
	if _, err := c.RedeemInvite(ctx, redeemOf(old, "n")); err != nil {
		t.Fatal(err)
	}
	revokedLongAgo := freshInvite(t, c, 1)
	_, err := c.db.Exec(`UPDATE invites SET open_until = now() - interval '91 days' WHERE code = $1`, old.Code)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.db.Exec(`UPDATE invites SET open_until = now() - interval '10 days', revoked_at = now() - interval '91 days' WHERE code = $1`, revokedLongAgo.Code)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.PruneInvites(ctx); err != nil {
		t.Fatal(err)
	}

	if _, err := c.InviteByCode(ctx, recent.Code); err != nil {
		t.Errorf("recent invite pruned: %v", err)
	}
	for _, gone := range []Invite{old, revokedLongAgo} {
		if _, err := c.InviteByCode(ctx, gone.Code); !errors.Is(err, ErrInviteNotFound) {
			t.Errorf("%s kept: %v", gone.Code, err)
		}
	}
	reds, err := c.InviteRedemptions(ctx, []string{old.Code, recent.Code})
	if err != nil || len(reds[old.Code]) != 0 || len(reds[recent.Code]) != 1 {
		t.Errorf("redemptions after prune = %+v, %v", reds, err)
	}
}
