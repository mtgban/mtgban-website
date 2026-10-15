package userstate

import (
	"context"
	"testing"
	"time"
)

func TestValidUploadShareKey(t *testing.T) {
	cases := map[string]bool{
		"":                        false,
		"abc":                     false,
		"AbCdEfGhIjKlMnOpQrStUv":  true,
		"AbCdEfGhIjKlMnOpQrSt-_":  true,
		"AbCdEfGhIjKlMnOpQrStU'":  false,
		"AbCdEfGhIjKlMnOpQrStUvW": false,
	}
	for key, want := range cases {
		if got := ValidUploadShareKey(key); got != want {
			t.Errorf("ValidUploadShareKey(%q) = %v, want %v", key, got, want)
		}
	}
}

// freshShareOwner is freshHash with the owner's upload shares cleared
// before and after.
func freshShareOwner(t *testing.T, c *Client) string {
	t.Helper()
	h := freshHash(t, c)
	wipe := func() {
		if _, err := c.db.Exec(`DELETE FROM upload_shares WHERE email_hash = $1`, h); err != nil {
			t.Fatalf("cleanup upload shares: %v", err)
		}
	}
	wipe()
	t.Cleanup(wipe)
	return h
}

func TestCreateUploadShareThenRead(t *testing.T) {
	c := testClient(t)
	h := freshShareOwner(t, c)
	ctx := context.Background()

	rows := "uuid-1\t2\tNM\t\t\t\t\nuuid-2\t1\tLP\t1.50\tnote\t\t"
	share, err := c.CreateUploadShare(ctx, h, "", rows, true, time.Hour)
	if err != nil {
		t.Fatalf("CreateUploadShare: %v", err)
	}
	if !ValidUploadShareKey(share.Key) {
		t.Fatalf("key %q is not 22 base64url characters", share.Key)
	}
	if time.Until(share.ExpiresAt) < 55*time.Minute {
		t.Fatalf("expiry %v is not about an hour away", share.ExpiresAt)
	}

	got, found, err := c.UploadShareByKey(ctx, share.Key, "")
	if err != nil || !found {
		t.Fatalf("UploadShareByKey: found %v err %v", found, err)
	}
	if got.Rows != rows || !got.Buylist || got.EmailHash != h || got.Key != share.Key {
		t.Fatalf("read back %+v", got)
	}

	second, err := c.CreateUploadShare(ctx, h, "", rows, false, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if second.Key == share.Key {
		t.Fatal("two shares got one key")
	}
}

func TestUploadShareExpiresAndPrunes(t *testing.T) {
	c := testClient(t)
	h := freshShareOwner(t, c)
	ctx := context.Background()

	expired, err := c.CreateUploadShare(ctx, h, "", "uuid-1\t1\t\t\t\t\t", false, -time.Second)
	if err != nil {
		t.Fatal(err)
	}
	live, err := c.CreateUploadShare(ctx, h, "", "uuid-1\t1\t\t\t\t\t", false, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := c.UploadShareByKey(ctx, expired.Key, ""); err != nil || found {
		t.Fatalf("expired share found %v err %v", found, err)
	}

	n, err := c.PruneUploadShares(ctx)
	if err != nil {
		t.Fatalf("PruneUploadShares: %v", err)
	}
	if n < 1 {
		t.Fatalf("pruned %d rows, want at least the expired one", n)
	}
	if _, found, _ := c.UploadShareByKey(ctx, live.Key, ""); !found {
		t.Fatal("prune removed the live share")
	}
}

func TestUploadShareByKeyUnknownAndMalformed(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	if _, found, err := c.UploadShareByKey(ctx, "AbCdEfGhIjKlMnOpQrStUv", ""); err != nil || found {
		t.Fatalf("unknown key: found %v err %v", found, err)
	}
	if _, found, err := c.UploadShareByKey(ctx, "not a key", ""); err != nil || found {
		t.Fatalf("malformed key: found %v err %v", found, err)
	}
}

func TestUploadShareIsScopedToItsGame(t *testing.T) {
	c := testClient(t)
	h := freshShareOwner(t, c)
	ctx := context.Background()
	share, err := c.CreateUploadShare(ctx, h, "lorcana", "uuid-1	1					", false, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := c.UploadShareByKey(ctx, share.Key, ""); err != nil || found {
		t.Fatalf("other game found %v err %v", found, err)
	}
	if _, found, err := c.UploadShareByKey(ctx, share.Key, "lorcana"); err != nil || !found {
		t.Fatalf("own game found %v err %v", found, err)
	}
}

func TestCountLiveUploadShares(t *testing.T) {
	c := testClient(t)
	h := freshShareOwner(t, c)
	ctx := context.Background()
	for _, ttl := range []time.Duration{time.Hour, time.Hour, -time.Second} {
		if _, err := c.CreateUploadShare(ctx, h, "", "uuid-1	1					", false, ttl); err != nil {
			t.Fatal(err)
		}
	}
	n, err := c.CountLiveUploadShares(ctx, h)
	if err != nil || n != 2 {
		t.Fatalf("count %d err %v, want 2 (the expired one is not live)", n, err)
	}
}
