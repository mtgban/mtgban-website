package userstate

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// freshSessionOwner is an email hash named for the test and label, with its
// patreon sessions cleared before and after.
func freshSessionOwner(t *testing.T, c *Client, label string) string {
	t.Helper()
	h := HashEmail(t.Name() + label + "@example.com")
	wipe := func() {
		_, err := c.db.Exec(`DELETE FROM patreon_sessions WHERE email_hash = $1`, h)
		if err != nil {
			t.Fatalf("cleanup patreon sessions: %v", err)
		}
	}
	wipe()
	t.Cleanup(wipe)
	return h
}

func mustCreatePatreonSession(t *testing.T, c *Client, h, token string, maxAge time.Duration) string {
	t.Helper()
	id, err := c.CreatePatreonSession(context.Background(), h, token, maxAge)
	if err != nil {
		t.Fatalf("CreatePatreonSession: %v", err)
	}
	return id
}

// wantLease fails unless a lease of the session answers token and leased,
// and returns the lease's fence.
func wantLease(t *testing.T, c *Client, id, h string, token string, leased bool) string {
	t.Helper()
	return wantLeaseFor(t, c, id, h, time.Minute, token, leased)
}

func wantLeaseFor(t *testing.T, c *Client, id, h string, lease time.Duration, token string, leased bool) string {
	t.Helper()
	got, fence, ok, err := c.LeasePatreonSession(context.Background(), id, h, lease)
	if err != nil {
		t.Fatalf("LeasePatreonSession: %v", err)
	}
	if ok != leased || got != token {
		t.Fatalf("lease = (%q, %v), want (%q, %v)", got, ok, token, leased)
	}
	if ok && len(fence) != 43 {
		t.Fatalf("lease fence %q is not 43 base64url characters", fence)
	}
	return fence
}

func TestPatreonSessionLifecycle(t *testing.T) {
	c := testClient(t)
	h := freshSessionOwner(t, c, "")
	ctx := context.Background()

	id := mustCreatePatreonSession(t, c, h, "token-1", time.Hour)
	if len(id) != 43 || strings.ContainsAny(id, "+/=") {
		t.Fatalf("session id %q is not 43 base64url characters", id)
	}
	other := mustCreatePatreonSession(t, c, h, "token-1", time.Hour)
	if other == id {
		t.Fatal("two sessions got one id")
	}

	fence := wantLease(t, c, id, h, "token-1", true)
	wantLease(t, c, id, h, "", false)

	stored, err := c.CommitPatreonSession(ctx, id, fence, "token-2")
	if err != nil || !stored {
		t.Fatalf("CommitPatreonSession: stored=%v err=%v", stored, err)
	}
	fence = wantLease(t, c, id, h, "token-2", true)

	err = c.DeferPatreonSession(ctx, id, fence, time.Hour)
	if err != nil {
		t.Fatalf("DeferPatreonSession: %v", err)
	}
	wantLease(t, c, id, h, "", false)
	var wait float64
	err = c.db.QueryRow(`SELECT extract(epoch FROM renew_after - now()) FROM patreon_sessions WHERE session_id = $1`, id).Scan(&wait)
	if err != nil || wait < 59*60 || wait > 61*60 {
		t.Fatalf("renew_after is %.0fs away (err %v), want about an hour", wait, err)
	}

	err = c.DeletePatreonSession(ctx, id)
	if err != nil {
		t.Fatalf("DeletePatreonSession: %v", err)
	}
	wantLease(t, c, id, h, "", false)
	wantLease(t, c, other, h, "token-1", true)
}

func TestPatreonSessionCommitOfDeletedSessionStaysDeleted(t *testing.T) {
	c := testClient(t)
	h := freshSessionOwner(t, c, "")
	ctx := context.Background()

	id := mustCreatePatreonSession(t, c, h, "token-1", time.Hour)
	fence := wantLease(t, c, id, h, "token-1", true)
	err := c.DeletePatreonSession(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := c.CommitPatreonSession(ctx, id, fence, "token-2")
	if err != nil {
		t.Fatalf("CommitPatreonSession of a deleted session: %v", err)
	}
	if stored {
		t.Fatal("CommitPatreonSession of a deleted session reported it stored")
	}
	wantLease(t, c, id, h, "", false)
}

// A holder whose lease ran out, and was taken over, can neither commit the
// token it rotated over the newer one nor hold the session back.
func TestPatreonSessionStaleLeaseCannotCommitOrDefer(t *testing.T) {
	c := testClient(t)
	h := freshSessionOwner(t, c, "")
	ctx := context.Background()

	id := mustCreatePatreonSession(t, c, h, "token-1", time.Hour)
	stale := wantLeaseFor(t, c, id, h, -time.Second, "token-1", true)
	current := wantLease(t, c, id, h, "token-1", true)

	stored, err := c.CommitPatreonSession(ctx, id, stale, "stale")
	if err != nil || stored {
		t.Fatalf("stale commit: stored=%v err=%v, want false, nil", stored, err)
	}
	stored, err = c.CommitPatreonSession(ctx, id, current, "token-2")
	if err != nil || !stored {
		t.Fatalf("current commit: stored=%v err=%v, want true, nil", stored, err)
	}
	// The stale defer must not push a session the current holder released.
	err = c.DeferPatreonSession(ctx, id, stale, time.Hour)
	if err != nil {
		t.Fatalf("stale defer: %v", err)
	}
	wantLease(t, c, id, h, "token-2", true)
}

// A never-leased session has no fence, and an empty one must not stand in.
func TestPatreonSessionEmptyFenceCommitsNothing(t *testing.T) {
	c := testClient(t)
	h := freshSessionOwner(t, c, "")
	ctx := context.Background()

	id := mustCreatePatreonSession(t, c, h, "token-1", time.Hour)
	stored, err := c.CommitPatreonSession(ctx, id, "", "forged")
	if err != nil || stored {
		t.Fatalf("empty-fence commit: stored=%v err=%v, want false, nil", stored, err)
	}
	wantLease(t, c, id, h, "token-1", true)
}

func TestPatreonSessionLeaseIsBoundToItsEmail(t *testing.T) {
	c := testClient(t)
	h := freshSessionOwner(t, c, "")
	stranger := freshSessionOwner(t, c, "-stranger")

	id := mustCreatePatreonSession(t, c, h, "token-1", time.Hour)
	wantLease(t, c, id, stranger, "", false)
	wantLease(t, c, id, h, "token-1", true)
}

func TestPatreonSessionLeaseGoesToOneOfManyCallers(t *testing.T) {
	c := testClient(t)
	h := freshSessionOwner(t, c, "")
	id := mustCreatePatreonSession(t, c, h, "token-1", time.Hour)

	const callers = 8
	var wg sync.WaitGroup
	leased := make([]bool, callers)
	for i := range leased {
		wg.Go(func() {
			_, _, ok, err := c.LeasePatreonSession(context.Background(), id, h, time.Minute)
			if err != nil {
				t.Errorf("LeasePatreonSession: %v", err)
			}
			leased[i] = ok
		})
	}
	wg.Wait()

	n := 0
	for _, ok := range leased {
		if ok {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d of %d concurrent leases succeeded, want 1", n, callers)
	}
}

func TestPatreonSessionPastExpiryNeverLeasesAndPrunes(t *testing.T) {
	c := testClient(t)
	h := freshSessionOwner(t, c, "")
	ctx := context.Background()

	// Clear what earlier runs left behind, so the counts below are ours.
	_, err := c.PrunePatreonSessions(ctx)
	if err != nil {
		t.Fatalf("PrunePatreonSessions: %v", err)
	}
	expired := mustCreatePatreonSession(t, c, h, "token-1", -time.Second)
	live := mustCreatePatreonSession(t, c, h, "token-2", time.Hour)

	wantLease(t, c, expired, h, "", false)

	n, err := c.PrunePatreonSessions(ctx)
	if err != nil || n != 1 {
		t.Fatalf("PrunePatreonSessions = %d, %v; want 1, nil", n, err)
	}
	n, err = c.PrunePatreonSessions(ctx)
	if err != nil || n != 0 {
		t.Fatalf("second PrunePatreonSessions = %d, %v; want 0, nil", n, err)
	}
	wantLease(t, c, live, h, "token-2", true)
}

func TestDeletePatreonSessionsRemovesOneEmailsRows(t *testing.T) {
	c := testClient(t)
	h := freshSessionOwner(t, c, "")
	other := freshSessionOwner(t, c, "-other")
	ctx := context.Background()

	a := mustCreatePatreonSession(t, c, h, "token-a", time.Hour)
	b := mustCreatePatreonSession(t, c, h, "token-b", time.Hour)
	kept := mustCreatePatreonSession(t, c, other, "token-c", time.Hour)

	n, err := c.DeletePatreonSessions(ctx, h)
	if err != nil || n != 2 {
		t.Fatalf("DeletePatreonSessions = %d, %v; want 2, nil", n, err)
	}
	wantLease(t, c, a, h, "", false)
	wantLease(t, c, b, h, "", false)
	wantLease(t, c, kept, other, "token-c", true)
}

func TestRekeyPatreonSession(t *testing.T) {
	c := testClient(t)
	h := freshSessionOwner(t, c, "")
	renamed := freshSessionOwner(t, c, "-renamed")

	id := mustCreatePatreonSession(t, c, h, "token-1", time.Hour)
	err := c.RekeyPatreonSession(context.Background(), id, renamed)
	if err != nil {
		t.Fatalf("RekeyPatreonSession: %v", err)
	}
	wantLease(t, c, id, h, "", false)
	wantLease(t, c, id, renamed, "token-1", true)
}

// A closed pool answers every call with an error, never a panic.
func TestPatreonSessionClosedPoolReturnsErrors(t *testing.T) {
	c := testClient(t)
	c.Close()
	ctx := context.Background()
	h := HashEmail(t.Name() + "@example.com")

	_, _, leased, err := c.LeasePatreonSession(ctx, "id", h, time.Minute)
	if err == nil || leased {
		t.Fatalf("LeasePatreonSession on a closed pool: leased %v err %v", leased, err)
	}
	_, err = c.CommitPatreonSession(ctx, "id", "fence", "token")
	if err == nil {
		t.Fatal("CommitPatreonSession on a closed pool returned nil")
	}
}

func TestPatreonSessionsSchemaOnlyCreates(t *testing.T) {
	for _, stmt := range strings.Split(createPatreonSessionsSQL, ";") {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		if !strings.HasPrefix(stmt, "CREATE ") || !strings.Contains(stmt, "IF NOT EXISTS") {
			t.Errorf("statement is not an idempotent CREATE:\n%s", stmt)
		}
	}
}

func TestPatreonSessionsSchemaIsIdempotent(t *testing.T) {
	c := testClient(t)
	for range 2 {
		_, err := c.db.Exec(createPatreonSessionsSQL)
		if err != nil {
			t.Fatalf("create again: %v", err)
		}
	}
}
