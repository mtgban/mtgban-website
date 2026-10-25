package userstate

import (
	"context"
	"slices"
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

// testPatreonClient is the Patreon client the sessions below are issued to.
const testPatreonClient = "client-1"

// mustCreatePatreonSession is a login of the Patreon account the email hash
// h names, holding token.
func mustCreatePatreonSession(t *testing.T, c *Client, h, token string, maxAge time.Duration) string {
	t.Helper()
	return mustCreateLogin(t, c, PatreonLogin{EmailHash: h, PatreonUser: "patreon-" + h, ClientID: testPatreonClient, RefreshToken: token}, maxAge)
}

func mustCreateLogin(t *testing.T, c *Client, login PatreonLogin, maxAge time.Duration) string {
	t.Helper()
	id, err := c.CreatePatreonSession(context.Background(), login, 0, maxAge)
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
	got, fence, ok, err := c.LeasePatreonSessions(context.Background(), id, h, testPatreonClient, lease)
	if err != nil {
		t.Fatalf("LeasePatreonSessions: %v", err)
	}
	if ok != leased || got != token {
		t.Fatalf("lease = (%q, %v), want (%q, %v)", got, ok, token, leased)
	}
	if ok && len(fence) != 43 {
		t.Fatalf("lease fence %q is not 43 base64url characters", fence)
	}
	if !ok && fence != "" {
		t.Fatalf("lease refused but answered the fence %q", fence)
	}
	return fence
}

// sessionState is what a patreon_sessions row holds that a renewal moves.
type sessionState struct {
	token string
	// wait is how far off renew_after is, in seconds, negative once due
	wait  float64
	lease string
}

func stateOf(t *testing.T, c *Client, id string) sessionState {
	t.Helper()
	var st sessionState
	var lease *string
	err := c.db.QueryRow(`
		SELECT refresh_token, extract(epoch FROM renew_after - now()), lease
		  FROM patreon_sessions WHERE session_id = $1`, id).Scan(&st.token, &st.wait, &lease)
	if err != nil {
		t.Fatalf("reading session %s: %v", id, err)
	}
	if lease != nil {
		st.lease = *lease
	}
	return st
}

// ageSession makes a session look as if it was last renewed ago.
func ageSession(t *testing.T, c *Client, id string, ago time.Duration) {
	t.Helper()
	_, err := c.db.Exec(`UPDATE patreon_sessions SET last_renewed = now() - make_interval(secs => $2) WHERE session_id = $1`, id, ago.Seconds())
	if err != nil {
		t.Fatalf("aging session %s: %v", id, err)
	}
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
	wantLease(t, c, other, h, "", false)

	rows, err := c.CommitPatreonSessions(ctx, fence, h, "token-2", 0)
	if err != nil || rows != 2 {
		t.Fatalf("CommitPatreonSessions: rows=%d err=%v, want 2, nil", rows, err)
	}
	fence = wantLease(t, c, other, h, "token-2", true)

	err = c.DeferPatreonSessions(ctx, fence, "", time.Hour)
	if err != nil {
		t.Fatalf("DeferPatreonSessions: %v", err)
	}
	wantLease(t, c, id, h, "", false)
	wantLease(t, c, other, h, "", false)

	n, err := c.DeletePatreonSessions(ctx, h)
	if err != nil || n != 2 {
		t.Fatalf("DeletePatreonSessions = %d, %v; want 2, nil", n, err)
	}
	wantLease(t, c, id, h, "", false)
}

// One lease moves every session of the email, and the token it answers is
// the one renewed last.
func TestPatreonSessionLeaseTakesEverySessionOfTheEmail(t *testing.T) {
	c := testClient(t)
	h := freshSessionOwner(t, c, "")
	stranger := freshSessionOwner(t, c, "-stranger")

	older := mustCreatePatreonSession(t, c, h, "token-old", time.Hour)
	newer := mustCreatePatreonSession(t, c, h, "token-new", time.Hour)
	ageSession(t, c, older, time.Hour)
	untouched := mustCreatePatreonSession(t, c, stranger, "token-stranger", time.Hour)

	fence := wantLease(t, c, older, h, "token-new", true)
	for _, id := range []string{older, newer} {
		st := stateOf(t, c, id)
		if st.lease != fence || st.wait < 50 || st.wait > 61 {
			t.Errorf("session %s: lease %q, due in %.0fs; want the fence and about a minute", id, st.lease, st.wait)
		}
	}
	st := stateOf(t, c, untouched)
	if st.lease != "" || st.wait > 0 || st.token != "token-stranger" {
		t.Errorf("another email's session was touched: %+v", st)
	}
	wantLease(t, c, untouched, stranger, "token-stranger", true)
}

// A session the email's lease did not see, because a login created it
// meanwhile, takes the rotated token all the same, and the lease still
// stands against a second renewal begun from it.
func TestPatreonSessionCommitWritesEveryRowIncludingALaterOne(t *testing.T) {
	c := testClient(t)
	h := freshSessionOwner(t, c, "")
	stranger := freshSessionOwner(t, c, "-stranger")
	ctx := context.Background()

	first := mustCreatePatreonSession(t, c, h, "token-1", time.Hour)
	second := mustCreatePatreonSession(t, c, h, "token-1", time.Hour)
	untouched := mustCreatePatreonSession(t, c, stranger, "token-s", time.Hour)
	fence := wantLease(t, c, first, h, "token-1", true)

	late := mustCreatePatreonSession(t, c, h, "token-0", time.Hour)
	wantLease(t, c, late, h, "", false)

	rows, err := c.CommitPatreonSessions(ctx, fence, h, "token-2", 0)
	if err != nil || rows != 3 {
		t.Fatalf("CommitPatreonSessions: rows=%d err=%v, want 3, nil", rows, err)
	}
	for _, id := range []string{first, second, late} {
		st := stateOf(t, c, id)
		if st.token != "token-2" || st.lease != "" || st.wait > 0 {
			t.Errorf("session %s after the commit: %+v, want token-2, no lease, due", id, st)
		}
	}
	st := stateOf(t, c, untouched)
	if st.token != "token-s" {
		t.Errorf("another email's session holds %q after the commit, want token-s", st.token)
	}

	// The fence is spent
	rows, err = c.CommitPatreonSessions(ctx, fence, h, "token-3", 0)
	if err != nil || rows != 0 {
		t.Fatalf("second commit: rows=%d err=%v, want 0, nil", rows, err)
	}
	st = stateOf(t, c, late)
	if st.token != "token-2" {
		t.Errorf("a spent fence overwrote the token with %q", st.token)
	}
}

// A commit after the sessions were deleted stores nothing.
// A commit may rest the sessions: Refresh now commits that way, so a reader
// cannot press Patreon per request, while a due renewal's commit leaves them
// leasable at once.
func TestPatreonSessionCommitCanRestTheSessions(t *testing.T) {
	c := testClient(t)
	h := freshSessionOwner(t, c, "")
	ctx := context.Background()

	first := mustCreatePatreonSession(t, c, h, "token-1", time.Hour)
	second := mustCreatePatreonSession(t, c, h, "token-1", time.Hour)
	fence := wantLease(t, c, first, h, "token-1", true)

	rows, err := c.CommitPatreonSessions(ctx, fence, h, "token-2", 5*time.Minute)
	if err != nil || rows != 2 {
		t.Fatalf("CommitPatreonSessions: rows=%d err=%v, want 2, nil", rows, err)
	}
	for _, id := range []string{first, second} {
		st := stateOf(t, c, id)
		if st.token != "token-2" || st.lease != "" || st.wait < 290 || st.wait > 300 {
			t.Errorf("session %s after a resting commit: %+v, want token-2, no lease, due in about five minutes", id, st)
		}
	}
	wantLease(t, c, second, h, "", false)
}

func TestPatreonSessionCommitOfDeletedSessionsStaysDeleted(t *testing.T) {
	c := testClient(t)
	h := freshSessionOwner(t, c, "")
	ctx := context.Background()

	id := mustCreatePatreonSession(t, c, h, "token-1", time.Hour)
	fence := wantLease(t, c, id, h, "token-1", true)
	_, err := c.DeletePatreonSessions(ctx, h)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := c.CommitPatreonSessions(ctx, fence, h, "token-2", 0)
	if err != nil || rows != 0 {
		t.Fatalf("commit of deleted sessions: rows=%d err=%v, want 0, nil", rows, err)
	}
	wantLease(t, c, id, h, "", false)
}

// Deferring holds every session of the email back an hour, and the token it
// is given is stored with it; none is stored when it is given none.
func TestPatreonSessionDeferHoldsEveryRowBack(t *testing.T) {
	c := testClient(t)
	h := freshSessionOwner(t, c, "")
	stranger := freshSessionOwner(t, c, "-stranger")
	ctx := context.Background()

	a := mustCreatePatreonSession(t, c, h, "token-1", time.Hour)
	b := mustCreatePatreonSession(t, c, h, "token-1", time.Hour)
	untouched := mustCreatePatreonSession(t, c, stranger, "token-s", time.Hour)

	fence := wantLease(t, c, a, h, "token-1", true)
	err := c.DeferPatreonSessions(ctx, fence, "", time.Hour)
	if err != nil {
		t.Fatalf("DeferPatreonSessions: %v", err)
	}
	for _, id := range []string{a, b} {
		st := stateOf(t, c, id)
		if st.wait < 59*60 || st.wait > 61*60 || st.token != "token-1" {
			t.Errorf("session %s: due in %.0fs holding %q, want an hour and the old token", id, st.wait, st.token)
		}
	}
	wantLease(t, c, a, h, "", false)
	wantLease(t, c, b, h, "", false)
	st := stateOf(t, c, untouched)
	if st.wait > 0 || st.token != "token-s" {
		t.Errorf("another email's session was touched: %+v", st)
	}

	// Once the hour is up the sessions lease again, and a deferral that
	// carries the rotated token stores it on both
	_, err = c.db.Exec(`UPDATE patreon_sessions SET renew_after = now() WHERE email_hash = $1`, h)
	if err != nil {
		t.Fatal(err)
	}
	ageSession(t, c, a, time.Hour)
	fence = wantLease(t, c, b, h, "token-1", true)
	err = c.DeferPatreonSessions(ctx, fence, "token-2", time.Hour)
	if err != nil {
		t.Fatalf("DeferPatreonSessions with a token: %v", err)
	}
	for _, id := range []string{a, b} {
		st := stateOf(t, c, id)
		if st.token != "token-2" || st.wait < 59*60 {
			t.Errorf("session %s after the deferral: %+v, want token-2 and an hour", id, st)
		}
	}
	var renewed float64
	err = c.db.QueryRow(`SELECT extract(epoch FROM now() - last_renewed) FROM patreon_sessions WHERE session_id = $1`, a).Scan(&renewed)
	if err != nil || renewed > 60 {
		t.Errorf("the stored token was renewed %.0fs ago (err %v), want just now", renewed, err)
	}
}

// A holder whose lease ran out, and was taken over, can neither commit the
// token it rotated over the newer one nor hold the sessions back.
func TestPatreonSessionStaleLeaseCannotCommitOrDefer(t *testing.T) {
	c := testClient(t)
	h := freshSessionOwner(t, c, "")
	ctx := context.Background()

	id := mustCreatePatreonSession(t, c, h, "token-1", time.Hour)
	other := mustCreatePatreonSession(t, c, h, "token-1", time.Hour)
	stale := wantLeaseFor(t, c, id, h, -time.Second, "token-1", true)
	current := wantLease(t, c, other, h, "token-1", true)

	rows, err := c.CommitPatreonSessions(ctx, stale, h, "stale", 0)
	if err != nil || rows != 0 {
		t.Fatalf("stale commit: rows=%d err=%v, want 0, nil", rows, err)
	}
	// The stale deferral must not push sessions the current holder holds
	// back, nor store its token.
	err = c.DeferPatreonSessions(ctx, stale, "stale", time.Hour)
	if err != nil {
		t.Fatalf("stale defer: %v", err)
	}
	st := stateOf(t, c, id)
	if st.token != "token-1" || st.wait > 61 {
		t.Errorf("a stale deferral moved a session: %+v", st)
	}
	rows, err = c.CommitPatreonSessions(ctx, current, h, "token-2", 0)
	if err != nil || rows != 2 {
		t.Fatalf("current commit: rows=%d err=%v, want 2, nil", rows, err)
	}
	wantLease(t, c, id, h, "token-2", true)
}

// Sessions never leased have no fence, and an empty one must not stand in.
func TestPatreonSessionEmptyFenceCommitsNothing(t *testing.T) {
	c := testClient(t)
	h := freshSessionOwner(t, c, "")
	ctx := context.Background()

	id := mustCreatePatreonSession(t, c, h, "token-1", time.Hour)
	rows, err := c.CommitPatreonSessions(ctx, "", h, "forged", 0)
	if err != nil || rows != 0 {
		t.Fatalf("empty-fence commit: rows=%d err=%v, want 0, nil", rows, err)
	}
	err = c.DeferPatreonSessions(ctx, "", "forged", time.Hour)
	if err != nil {
		t.Fatalf("empty-fence defer: %v", err)
	}
	st := stateOf(t, c, id)
	if st.token != "token-1" || st.wait > 0 {
		t.Errorf("an empty fence moved a session: %+v", st)
	}
	wantLease(t, c, id, h, "token-1", true)
}

func TestPatreonSessionLeaseIsBoundToItsEmail(t *testing.T) {
	c := testClient(t)
	h := freshSessionOwner(t, c, "")
	stranger := freshSessionOwner(t, c, "-stranger")

	id := mustCreatePatreonSession(t, c, h, "token-1", time.Hour)
	other := mustCreatePatreonSession(t, c, stranger, "token-2", time.Hour)
	wantLease(t, c, id, stranger, "", false)
	wantLease(t, c, other, h, "", false)
	st := stateOf(t, c, id)
	if st.lease != "" || st.wait > 0 {
		t.Errorf("a lease under the wrong email moved a session: %+v", st)
	}
	wantLease(t, c, id, h, "token-1", true)
}

// While one session of the email is leased or backing off, a session that is
// due, one a login created meanwhile, does not start a renewal of its own.
func TestPatreonSessionLeaseWaitsForTheWholeEmail(t *testing.T) {
	c := testClient(t)
	h := freshSessionOwner(t, c, "")

	id := mustCreatePatreonSession(t, c, h, "token-1", time.Hour)
	wantLease(t, c, id, h, "token-1", true)
	late := mustCreatePatreonSession(t, c, h, "token-1", time.Hour)
	wantLease(t, c, late, h, "", false)

	_, err := c.db.Exec(`UPDATE patreon_sessions SET renew_after = now() + interval '1 hour', lease = NULL WHERE session_id = $1`, id)
	if err != nil {
		t.Fatal(err)
	}
	wantLease(t, c, late, h, "", false)
	_, err = c.db.Exec(`UPDATE patreon_sessions SET renew_after = now() WHERE session_id = $1`, id)
	if err != nil {
		t.Fatal(err)
	}
	wantLease(t, c, late, h, "token-1", true)
}

// Of many callers leasing one email through different sessions, one wins.
func TestPatreonSessionLeaseGoesToOneOfManyCallers(t *testing.T) {
	c := testClient(t)
	h := freshSessionOwner(t, c, "")
	ids := []string{
		mustCreatePatreonSession(t, c, h, "token-1", time.Hour),
		mustCreatePatreonSession(t, c, h, "token-1", time.Hour),
		mustCreatePatreonSession(t, c, h, "token-1", time.Hour),
	}

	const callers = 12
	var wg sync.WaitGroup
	leased := make([]bool, callers)
	for i := range leased {
		wg.Go(func() {
			_, _, ok, err := c.LeasePatreonSessions(context.Background(), ids[i%len(ids)], h, testPatreonClient, time.Minute)
			if err != nil {
				t.Errorf("LeasePatreonSessions: %v", err)
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

// A lease that waited on the row lock of one that committed first finds the
// sessions leased when it wakes, and takes nothing.
func TestPatreonSessionLeaseThatWaitedFindsTheSessionsLeased(t *testing.T) {
	c := testClient(t)
	h := freshSessionOwner(t, c, "")
	ctx := context.Background()
	id := mustCreatePatreonSession(t, c, h, "token-1", time.Hour)
	mustCreatePatreonSession(t, c, h, "token-1", time.Hour)

	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `
		UPDATE patreon_sessions SET renew_after = now() + interval '1 minute', lease = 'holder'
		 WHERE email_hash = $1`, h)
	if err != nil {
		t.Fatal(err)
	}

	type answer struct {
		leased bool
		err    error
	}
	answered := make(chan answer)
	go func() {
		_, _, leased, err := c.LeasePatreonSessions(ctx, id, h, testPatreonClient, time.Minute)
		answered <- answer{leased, err}
	}()
	// Wait for the lease to block on the rows the transaction holds
	for range 200 {
		var waiting int
		err = c.db.QueryRow(`SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND query LIKE '%RETURNING s.refresh_token, s.last_renewed%'`).Scan(&waiting)
		if err != nil {
			t.Fatal(err)
		}
		if waiting > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	err = tx.Commit()
	if err != nil {
		t.Fatal(err)
	}

	got := <-answered
	if got.err != nil || got.leased {
		t.Fatalf("lease after waiting: leased %v err %v, want false, nil", got.leased, got.err)
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

// A Patreon account whose email changed takes all its sessions along when
// a renewal commits under the new email.
func TestPatreonSessionCommitFilesTheSessionsUnderANewEmail(t *testing.T) {
	c := testClient(t)
	h := freshSessionOwner(t, c, "")
	renamed := freshSessionOwner(t, c, "-renamed")
	stranger := freshSessionOwner(t, c, "-stranger")
	ctx := context.Background()

	a := mustCreatePatreonSession(t, c, h, "token-1", time.Hour)
	b := mustCreatePatreonSession(t, c, h, "token-1", time.Hour)
	kept := mustCreatePatreonSession(t, c, stranger, "token-s", time.Hour)
	fence := wantLease(t, c, a, h, "token-1", true)
	rows, err := c.CommitPatreonSessions(ctx, fence, renamed, "token-2", 0)
	if err != nil || rows != 2 {
		t.Fatalf("CommitPatreonSessions: rows=%d err=%v, want 2, nil", rows, err)
	}
	wantLease(t, c, a, h, "", false)
	wantLease(t, c, b, renamed, "token-2", true)
	wantLease(t, c, kept, stranger, "token-s", true)
}

// Two Patreon accounts under one email hash, one that changed its email to
// an address the other gave up, hold two tokens, and neither's renewal leases,
// commits or holds back the other's sessions.
func TestPatreonSessionLeaseIsBoundToItsAccount(t *testing.T) {
	c := testClient(t)
	h := freshSessionOwner(t, c, "")
	ctx := context.Background()

	mine := mustCreateLogin(t, c, PatreonLogin{EmailHash: h, PatreonUser: "patreon-mine", ClientID: testPatreonClient, RefreshToken: "token-mine"}, time.Hour)
	theirs := mustCreateLogin(t, c, PatreonLogin{EmailHash: h, PatreonUser: "patreon-theirs", ClientID: testPatreonClient, RefreshToken: "token-theirs"}, time.Hour)
	ageSession(t, c, mine, time.Hour)

	fence := wantLease(t, c, mine, h, "token-mine", true)
	st := stateOf(t, c, theirs)
	if st.lease != "" || st.wait > 0 {
		t.Errorf("another account's session was leased: %+v", st)
	}
	err := c.DeferPatreonSessions(ctx, fence, "token-mine-2", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	st = stateOf(t, c, theirs)
	if st.token != "token-theirs" || st.wait > 0 {
		t.Errorf("another account's session was held back: %+v", st)
	}
	wantLease(t, c, theirs, h, "token-theirs", true)
}

// A session another Patreon client issued is never leased under this one,
// whose refresh would spend a token it cannot redeem.
func TestPatreonSessionLeaseIsBoundToItsClient(t *testing.T) {
	c := testClient(t)
	h := freshSessionOwner(t, c, "")
	ctx := context.Background()

	id := mustCreatePatreonSession(t, c, h, "token-1", time.Hour)
	_, _, leased, err := c.LeasePatreonSessions(ctx, id, h, "client-2", time.Minute)
	if err != nil || leased {
		t.Fatalf("lease under another client: leased %v err %v, want false, nil", leased, err)
	}
	wantLease(t, c, id, h, "token-1", true)
}

// A revocation deletes the account's sessions holding the token Patreon
// refused, leaves one holding another to be tried, and does nothing once a
// renewal that won the refresh has committed.
func TestPatreonSessionRevokeDeletesTheDeadTokensSessions(t *testing.T) {
	c := testClient(t)
	h := freshSessionOwner(t, c, "")
	stranger := freshSessionOwner(t, c, "-stranger")
	ctx := context.Background()

	dead := mustCreatePatreonSession(t, c, h, "token-dead", time.Hour)
	alsoDead := mustCreatePatreonSession(t, c, h, "token-dead", time.Hour)
	live := mustCreatePatreonSession(t, c, h, "token-live", time.Hour)
	ageSession(t, c, live, time.Hour)
	kept := mustCreatePatreonSession(t, c, stranger, "token-dead", time.Hour)

	fence := wantLease(t, c, dead, h, "token-dead", true)
	gone, err := c.RevokePatreonSessions(ctx, fence, "token-dead")
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(gone)
	want := []string{dead, alsoDead}
	slices.Sort(want)
	if !slices.Equal(gone, want) {
		t.Errorf("revoked %q, want %q", gone, want)
	}
	if st := stateOf(t, c, live); st.token != "token-live" {
		t.Errorf("the session holding another token: %+v, want it kept", st)
	}
	if st := stateOf(t, c, kept); st.token != "token-dead" {
		t.Errorf("another email's session: %+v, want it kept", st)
	}

	// A renewal that won the refresh committed and cleared the fence, so a
	// refusal reaching its loser afterwards revokes nothing
	_, err = c.db.Exec(`UPDATE patreon_sessions SET renew_after = now() WHERE session_id = $1`, live)
	if err != nil {
		t.Fatal(err)
	}
	spent := wantLease(t, c, live, h, "token-live", true)
	_, err = c.CommitPatreonSessions(ctx, spent, h, "token-next", 0)
	if err != nil {
		t.Fatal(err)
	}
	gone, err = c.RevokePatreonSessions(ctx, spent, "token-next")
	if err != nil || len(gone) != 0 {
		t.Errorf("revocation after the commit: %q, %v; want nothing", gone, err)
	}
	if st := stateOf(t, c, live); st.token != "token-next" {
		t.Errorf("session after the commit: %+v, want token-next", st)
	}
}

// A login dated from its code exchange is older than a renewal another
// device committed while the login finished, so the lease takes the token
// that renewal rotated to, not the one the login brought.
func TestPatreonSessionLoginIsDatedFromItsExchange(t *testing.T) {
	c := testClient(t)
	h := freshSessionOwner(t, c, "")
	ctx := context.Background()

	device := mustCreatePatreonSession(t, c, h, "token-1", time.Hour)
	fence := wantLease(t, c, device, h, "token-1", true)
	rows, err := c.CommitPatreonSessions(ctx, fence, h, "token-2", 0)
	if err != nil || rows != 1 {
		t.Fatalf("CommitPatreonSessions: rows=%d err=%v", rows, err)
	}
	// The login exchanged its code, and got token-1, before that commit
	late, err := c.CreatePatreonSession(ctx, PatreonLogin{EmailHash: h, PatreonUser: "patreon-" + h, ClientID: testPatreonClient, RefreshToken: "token-1"}, 10*time.Second, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	wantLease(t, c, late, h, "token-2", true)
}

// A closed pool answers every call with an error, never a panic.
func TestPatreonSessionClosedPoolReturnsErrors(t *testing.T) {
	c := testClient(t)
	c.Close()
	ctx := context.Background()
	h := HashEmail(t.Name() + "@example.com")

	_, _, leased, err := c.LeasePatreonSessions(ctx, "id", h, testPatreonClient, time.Minute)
	if err == nil || leased {
		t.Fatalf("LeasePatreonSessions on a closed pool: leased %v err %v", leased, err)
	}
	_, err = c.CommitPatreonSessions(ctx, "fence", h, "token", 0)
	if err == nil {
		t.Fatal("CommitPatreonSessions on a closed pool returned nil")
	}
	err = c.DeferPatreonSessions(ctx, "fence", "", time.Hour)
	if err == nil {
		t.Fatal("DeferPatreonSessions on a closed pool returned nil")
	}
	_, err = c.RevokePatreonSessions(ctx, "fence", "token")
	if err == nil {
		t.Fatal("RevokePatreonSessions on a closed pool returned nil")
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
