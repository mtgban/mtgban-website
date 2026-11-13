package metricsreport

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/observability"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func counting(n *int, v string) func(context.Context) (string, error) {
	return func(context.Context) (string, error) { *n++; return v, nil }
}

func fixedStamp(context.Context) (string, error) { return "s1", nil }

func newTestCache() (*Cache, *clock) {
	clk := &clock{t: time.Unix(0, 0)}
	return NewCache(fixedStamp, clk.now), clk
}

// watchJoins makes c report each caller that joins an in-flight load.
func watchJoins(c *Cache) chan struct{} {
	joins := make(chan struct{}, 16)
	c.joined = func() { joins <- struct{}{} }
	return joins
}

func waitJoins(joins chan struct{}, n int) {
	for range n {
		<-joins
	}
}

func entryCount(c *Cache) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

func mustLoad(t *testing.T, c *Cache, k Key, load func(context.Context) (string, error)) string {
	t.Helper()
	v, err := Load(context.Background(), c, k, load)
	if err != nil {
		t.Fatalf("load %v: %v", k, err)
	}
	return v
}

type result struct {
	v   string
	err error
}

func goLoad(ctx context.Context, c *Cache, k Key, load func(context.Context) (string, error)) chan result {
	out := make(chan result, 1)
	go func() {
		v, err := Load(ctx, c, k, load)
		out <- result{v, err}
	}()
	return out
}

// gated returns a load that signals entered, then waits for release before answering.
func gated(calls *int, v string, err error) (load func(context.Context) (string, error), entered, release chan struct{}) {
	entered, release = make(chan struct{}), make(chan struct{})
	load = func(context.Context) (string, error) {
		*calls++
		close(entered)
		<-release
		return v, err
	}
	return load, entered, release
}

func neverRuns(t *testing.T) func(context.Context) (string, error) {
	return func(context.Context) (string, error) {
		t.Error("a joiner ran its own load")
		return "", errors.New("joiner load")
	}
}

func TestLoadCachesPerKey(t *testing.T) {
	c, _ := newTestCache()
	var a, b int
	ka := Key{Report: "bundle", Instance: "magic", Days: 90, Signed: true, Humans: true}
	kb := ka
	kb.Days = 30
	for range 3 {
		if v := mustLoad(t, c, ka, counting(&a, "A")); v != "A" {
			t.Fatalf("got %q", v)
		}
	}
	if v := mustLoad(t, c, kb, counting(&b, "B")); v != "B" {
		t.Fatalf("got %q", v)
	}
	if a != 1 || b != 1 {
		t.Errorf("loads: a %d b %d, want 1 and 1", a, b)
	}
}

func TestAFailedLoadIsNotCached(t *testing.T) {
	c, _ := newTestCache()
	k := Key{Report: "bundle", Instance: "magic", Days: 90}
	calls := 0
	fail := func(context.Context) (string, error) { calls++; return "", errors.New("down") }
	if _, err := Load(context.Background(), c, k, fail); err == nil {
		t.Fatal("the error is returned")
	}
	if n := entryCount(c); n != 0 {
		t.Errorf("a failed load left %d entries, want 0", n)
	}
	if _, err := Load(context.Background(), c, k, fail); err == nil {
		t.Fatal("the second error is returned")
	}
	if calls != 2 {
		t.Errorf("a failed load ran %d times over two calls, want 2", calls)
	}
}

func TestANewStampDropsEverything(t *testing.T) {
	clk := &clock{t: time.Unix(0, 0)}
	stamp, checks := "day1", 0
	c := NewCache(func(context.Context) (string, error) { checks++; return stamp, nil }, clk.now)
	k := Key{Report: "bundle", Instance: "magic", Days: 90}
	n := 0
	mustLoad(t, c, k, counting(&n, "v"))
	stamp = "day2"
	mustLoad(t, c, k, counting(&n, "v")) // inside the minute: the stamp is not asked again
	if n != 1 || checks != 1 {
		t.Fatalf("loads %d checks %d, want 1 and 1", n, checks)
	}
	clk.t = clk.t.Add(61 * time.Second)
	mustLoad(t, c, k, counting(&n, "v"))
	if n != 2 || checks != 2 {
		t.Errorf("after the fold: loads %d checks %d, want 2 and 2", n, checks)
	}
}

func TestAnUnchangedStampKeepsTheCache(t *testing.T) {
	c, clk := newTestCache()
	k := Key{Report: "bundle", Instance: "magic", Days: 90}
	n := 0
	mustLoad(t, c, k, counting(&n, "v"))
	clk.t = clk.t.Add(24 * time.Hour)
	mustLoad(t, c, k, counting(&n, "v"))
	if n != 1 {
		t.Errorf("a day later with the same stamp the key loaded %d times, want 1", n)
	}
}

func TestAStampErrorKeepsTheCache(t *testing.T) {
	clk := &clock{t: time.Unix(0, 0)}
	checks := 0
	c := NewCache(func(context.Context) (string, error) {
		checks++
		if checks > 1 {
			return "", errors.New("db down")
		}
		return "s1", nil
	}, clk.now)
	k := Key{Report: "bundle", Instance: "magic", Days: 90}
	n := 0
	mustLoad(t, c, k, counting(&n, "v"))
	clk.t = clk.t.Add(61 * time.Second)
	if v := mustLoad(t, c, k, counting(&n, "w")); v != "v" {
		t.Errorf("after a stamp error got %q, want the cached %q", v, "v")
	}
	mustLoad(t, c, k, counting(&n, "w")) // inside the minute: no retry yet
	if n != 1 || checks != 2 {
		t.Fatalf("loads %d checks %d, want 1 and 2", n, checks)
	}
	clk.t = clk.t.Add(61 * time.Second)
	mustLoad(t, c, k, counting(&n, "w"))
	if checks != 3 {
		t.Errorf("the stamp was asked %d times, want a retry after the interval (3)", checks)
	}
}

func TestTheStampQueryIgnoresTheRequestsCancel(t *testing.T) {
	clk := &clock{t: time.Unix(0, 0)}
	var stampErr error
	hasDeadline := false
	c := NewCache(func(ctx context.Context) (string, error) {
		stampErr = ctx.Err()
		_, hasDeadline = ctx.Deadline()
		return "s1", nil
	}, clk.now)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	k := Key{Report: "bundle", Instance: "magic", Days: 90}
	if _, err := Load(ctx, c, k, func(context.Context) (string, error) { return "v", nil }); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	mustLoad(t, c, k, func(context.Context) (string, error) { return "v", nil }) // waits out the first load
	if stampErr != nil || !hasDeadline {
		t.Errorf("the stamp ran with err %v, deadline %v; want a live context with its own deadline", stampErr, hasDeadline)
	}
	c.mu.Lock()
	known := c.known
	c.mu.Unlock()
	if known != "s1" {
		t.Errorf("a cancelled request left the stamp unread (%q)", known)
	}
}

func TestMaxAgeReloadsAnOldEntry(t *testing.T) {
	c, clk := newTestCache()
	k := Key{Report: "health", Instance: "magic"}
	n := 0
	ctx := context.Background()
	load := func(context.Context) (string, error) { n++; return "h", nil }
	for range 2 {
		if _, err := LoadFor(ctx, c, k, time.Minute, load); err != nil {
			t.Fatal(err)
		}
	}
	clk.t = clk.t.Add(59 * time.Second)
	if _, err := LoadFor(ctx, c, k, time.Minute, load); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("inside the maximum age the key loaded %d times, want 1", n)
	}
	clk.t = clk.t.Add(time.Second)
	if _, err := LoadFor(ctx, c, k, time.Minute, load); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("at the maximum age the key loaded %d times in all, want 2", n)
	}
}

func TestOneLoadPerKeyIsShared(t *testing.T) {
	c, _ := newTestCache()
	joins := watchJoins(c)
	k := Key{Report: "bundle", Instance: "magic", Days: 90}
	calls := 0
	slow, entered, release := gated(&calls, "A", nil)
	outs := []chan result{goLoad(context.Background(), c, k, slow)}
	<-entered
	for range 2 {
		outs = append(outs, goLoad(context.Background(), c, k, neverRuns(t)))
	}
	waitJoins(joins, 2)
	close(release)
	for _, out := range outs {
		if r := <-out; r.err != nil || r.v != "A" {
			t.Errorf("got %q %v, want A", r.v, r.err)
		}
	}
	if calls != 1 {
		t.Errorf("the load ran %d times, want 1", calls)
	}
}

func TestASlowKeyDoesNotBlockAnother(t *testing.T) {
	c, _ := newTestCache()
	joins := watchJoins(c)
	ka := Key{Report: "bundle", Instance: "magic", Days: 90}
	kb := Key{Report: "bundle", Instance: "magic", Days: 30}
	calls := 0
	slow, entered, release := gated(&calls, "A", nil)
	first := goLoad(context.Background(), c, ka, slow)
	<-entered
	other := goLoad(context.Background(), c, kb, func(context.Context) (string, error) { return "B", nil })
	if r := <-other; r.err != nil || r.v != "B" {
		t.Fatalf("key B got %q %v while A was loading", r.v, r.err)
	}
	second := goLoad(context.Background(), c, ka, neverRuns(t))
	waitJoins(joins, 1)
	close(release)
	for _, ch := range []chan result{first, second} {
		if r := <-ch; r.err != nil || r.v != "A" {
			t.Errorf("key A got %q %v", r.v, r.err)
		}
	}
	if calls != 1 {
		t.Errorf("A's load ran %d times, want 1", calls)
	}
}

func TestAFailedLoadReachesEveryWaiter(t *testing.T) {
	c, _ := newTestCache()
	joins := watchJoins(c)
	k := Key{Report: "bundle", Instance: "magic", Days: 90}
	calls := 0
	down := errors.New("down")
	fail, entered, release := gated(&calls, "", down)
	outs := []chan result{goLoad(context.Background(), c, k, fail)}
	<-entered
	for range 2 {
		outs = append(outs, goLoad(context.Background(), c, k, neverRuns(t)))
	}
	waitJoins(joins, 2)
	close(release)
	for _, out := range outs {
		if r := <-out; !errors.Is(r.err, down) {
			t.Errorf("a waiter got %q %v, want the load's error", r.v, r.err)
		}
	}
	if n := entryCount(c); n != 0 || calls != 1 {
		t.Errorf("after the failure: %d entries and %d loads, want 0 and 1", n, calls)
	}
	n := 0
	mustLoad(t, c, k, counting(&n, "ok"))
	if n != 1 {
		t.Errorf("after a failure the next call loaded %d times, want 1", n)
	}
}

func TestAPanickingLoadIsNotStuck(t *testing.T) {
	c, _ := newTestCache()
	joins := watchJoins(c)
	k := Key{Report: "bundle", Instance: "magic", Days: 90}
	entered, release := make(chan struct{}), make(chan struct{})
	boom := func(context.Context) (string, error) {
		close(entered)
		<-release
		panic("boom")
	}
	first := goLoad(context.Background(), c, k, boom)
	<-entered
	second := goLoad(context.Background(), c, k, neverRuns(t))
	waitJoins(joins, 1)
	close(release)
	for _, out := range []chan result{first, second} {
		r := <-out
		if r.err == nil || !strings.Contains(r.err.Error(), "panicked: boom") || !strings.Contains(r.err.Error(), "goroutine ") {
			t.Errorf("a waiter of a panicking load got %v, want the panic with its stack", r.err)
		}
	}
	if n := entryCount(c); n != 0 {
		t.Errorf("a panicked load left %d entries, want 0", n)
	}
	n := 0
	if v := mustLoad(t, c, k, counting(&n, "ok")); v != "ok" || n != 1 {
		t.Errorf("after a panic got %q with %d loads, want ok and 1", v, n)
	}
}

func TestALoadPastItsDeadlineFails(t *testing.T) {
	c, _ := newTestCache()
	c.loadMax = time.Millisecond
	k := Key{Report: "bundle", Instance: "magic", Days: 90}
	hung := func(ctx context.Context) (string, error) {
		<-ctx.Done()
		return "", ctx.Err()
	}
	if _, err := Load(context.Background(), c, k, hung); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a hung load returned %v, want context.DeadlineExceeded", err)
	}
	if n := entryCount(c); n != 0 {
		t.Errorf("a timed-out load left %d entries, want 0", n)
	}
	n := 0
	if v := mustLoad(t, c, k, counting(&n, "ok")); v != "ok" || n != 1 {
		t.Errorf("after a timeout got %q with %d loads, want ok and 1", v, n)
	}
}

func TestACancelledStarterReturnsWhileTheLoadGoesOn(t *testing.T) {
	c, _ := newTestCache()
	joins := watchJoins(c)
	k := Key{Report: "bundle", Instance: "magic", Days: 90}
	entered, release := make(chan struct{}), make(chan struct{})
	loadErr := make(chan error, 1)
	slow := func(ctx context.Context) (string, error) {
		close(entered)
		<-release
		loadErr <- ctx.Err()
		return "A", nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	starter := goLoad(ctx, c, k, slow)
	<-entered
	cancel()
	if r := <-starter; !errors.Is(r.err, context.Canceled) {
		t.Fatalf("the cancelled caller got %q %v, want context.Canceled", r.v, r.err)
	}
	waiter := goLoad(context.Background(), c, k, neverRuns(t))
	waitJoins(joins, 1)
	close(release)
	if err := <-loadErr; err != nil {
		t.Errorf("the load's context ended with %v when one caller gave up", err)
	}
	if r := <-waiter; r.err != nil || r.v != "A" {
		t.Errorf("the other caller got %q %v, want A", r.v, r.err)
	}
}

func TestACancelledJoinerReturnsAndTheLoadIsCached(t *testing.T) {
	c, _ := newTestCache()
	joins := watchJoins(c)
	k := Key{Report: "bundle", Instance: "magic", Days: 90}
	calls := 0
	slow, entered, release := gated(&calls, "A", nil)
	starter := goLoad(context.Background(), c, k, slow)
	<-entered
	ctx, cancel := context.WithCancel(context.Background())
	joiner := goLoad(ctx, c, k, neverRuns(t))
	waitJoins(joins, 1)
	cancel()
	if r := <-joiner; !errors.Is(r.err, context.Canceled) {
		t.Fatalf("the cancelled joiner got %q %v, want context.Canceled", r.v, r.err)
	}
	close(release)
	if r := <-starter; r.err != nil || r.v != "A" {
		t.Fatalf("the starter got %q %v, want A", r.v, r.err)
	}
	if v := mustLoad(t, c, k, neverRuns(t)); v != "A" || calls != 1 {
		t.Errorf("the next caller got %q after %d loads, want the cached A after 1", v, calls)
	}
}

func TestADropDuringALoadDoesNotStoreIt(t *testing.T) {
	c, _ := newTestCache()
	k := Key{Report: "bundle", Instance: "magic", Days: 90}
	calls := 0
	slow, entered, release := gated(&calls, "old", nil)
	first := goLoad(context.Background(), c, k, slow)
	<-entered
	c.Drop()
	close(release)
	if r := <-first; r.err != nil || r.v != "old" {
		t.Fatalf("the loading caller got %q %v", r.v, r.err)
	}
	n := 0
	if v := mustLoad(t, c, k, counting(&n, "new")); v != "new" {
		t.Errorf("after a drop mid-load got %q, want new", v)
	}
}

func TestAStampMoveDuringALoadDoesNotStoreIt(t *testing.T) {
	clk := &clock{t: time.Unix(0, 0)}
	stamp := "day1"
	c := NewCache(func(context.Context) (string, error) { return stamp, nil }, clk.now)
	k := Key{Report: "bundle", Instance: "magic", Days: 90}
	calls := 0
	slow, entered, release := gated(&calls, "old", nil)
	first := goLoad(context.Background(), c, k, slow)
	<-entered
	clk.t = clk.t.Add(61 * time.Second)
	stamp = "day2"
	mustLoad(t, c, Key{Report: "bundle", Instance: "magic", Days: 30}, func(context.Context) (string, error) { return "b", nil })
	close(release)
	if r := <-first; r.err != nil || r.v != "old" {
		t.Fatalf("the in-flight caller got %q %v, want old", r.v, r.err)
	}
	n := 0
	if v := mustLoad(t, c, k, counting(&n, "new")); v != "new" || n != 1 {
		t.Errorf("under the new stamp got %q with %d loads, want new and 1", v, n)
	}
}

func TestTheStampQueryHoldsNoLock(t *testing.T) {
	clk := &clock{t: time.Unix(0, 0)}
	entered, release := make(chan struct{}), make(chan struct{})
	c := NewCache(func(context.Context) (string, error) {
		close(entered)
		<-release
		return "s1", nil
	}, clk.now)
	k := Key{Report: "bundle", Instance: "magic", Days: 90}
	done := goLoad(context.Background(), c, k, func(context.Context) (string, error) { return "v", nil })
	<-entered
	c.Drop() // deadlocks if the cache's mutex is held across the stamp query
	n := 0
	if v := mustLoad(t, c, k, counting(&n, "other")); v != "other" {
		t.Errorf("a load during the stamp query got %q", v)
	}
	close(release)
	if r := <-done; r.err != nil {
		t.Error(r.err)
	}
}

func TestTheMapIsBounded(t *testing.T) {
	c, _ := newTestCache()
	c.maxEntries = 3
	n := 0
	for d := range 4 {
		mustLoad(t, c, Key{Report: "bundle", Instance: "magic", Days: d + 1}, counting(&n, "v"))
	}
	if got := entryCount(c); got > 1 {
		t.Errorf("after a fourth key %d entries remain, want at most 1", got)
	}
	mustLoad(t, c, Key{Report: "bundle", Instance: "magic", Days: 1}, counting(&n, "v"))
	if n != 5 {
		t.Errorf("an evicted key was not loaded again: %d loads, want 5", n)
	}
}

func TestNilCacheLoadsEveryTime(t *testing.T) {
	var c *Cache
	n := 0
	k := Key{Report: "bundle"}
	for range 2 {
		mustLoad(t, c, k, counting(&n, "v"))
	}
	if _, err := LoadFor(context.Background(), c, k, time.Minute, counting(&n, "v")); err != nil {
		t.Fatal(err)
	}
	c.Drop()
	if n != 3 {
		t.Errorf("a nil cache loaded %d times over three calls, want 3", n)
	}
}

func TestDrop(t *testing.T) {
	c, _ := newTestCache()
	k := Key{Report: "bundle", Instance: "magic", Days: 90}
	n := 0
	mustLoad(t, c, k, counting(&n, "v"))
	c.Drop()
	mustLoad(t, c, k, counting(&n, "v"))
	if n != 2 {
		t.Errorf("after Drop the key loaded %d times in all, want 2", n)
	}
}

func TestAWrongTypeForAKeyLoadsAgain(t *testing.T) {
	c, _ := newTestCache()
	k := Key{Report: "bundle", Instance: "magic", Days: 90}
	n := 0
	mustLoad(t, c, k, counting(&n, "v"))
	got, err := Load(context.Background(), c, k, func(context.Context) (int, error) { n++; return 7, nil })
	if err != nil || got != 7 || n != 2 {
		t.Errorf("got %d %v after %d loads, want 7 after 2", got, err, n)
	}
}

func TestAJoinerOfAnotherTypeGetsErrType(t *testing.T) {
	c, _ := newTestCache()
	joins := watchJoins(c)
	k := Key{Report: "bundle", Instance: "magic", Days: 90}
	calls := 0
	slow, entered, release := gated(&calls, "s", nil)
	first := goLoad(context.Background(), c, k, slow)
	<-entered
	second := make(chan error, 1)
	go func() {
		_, err := Load(context.Background(), c, k, func(context.Context) (int, error) {
			t.Error("the int joiner ran its own load")
			return 7, nil
		})
		second <- err
	}()
	waitJoins(joins, 1)
	close(release)
	if r := <-first; r.err != nil || r.v != "s" {
		t.Errorf("first got %q %v", r.v, r.err)
	}
	if err := <-second; !errors.Is(err, ErrType) {
		t.Errorf("the other-typed joiner got %v, want ErrType", err)
	}
}

// A caller whose context is already done gets its error and starts no load.
func TestADoneCallerStartsNoLoad(t *testing.T) {
	c, _ := newTestCache()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	if _, err := Load(ctx, c, Key{Report: "bundle"}, counting(&calls, "v")); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	if calls != 0 || entryCount(c) != 0 {
		t.Errorf("%d loads, %d entries after a done caller", calls, entryCount(c))
	}
}

// A remembered failure is served for its time without loading, then loaded again.
func TestARememberedFailureIsServedForItsTime(t *testing.T) {
	c, clk := newTestCache()
	k := Key{Report: "visits", Instance: "magic", Days: 30}
	calls := 0
	fail := func(context.Context) (string, error) { calls++; return "", errors.New("slow") }
	for range 3 {
		if _, err := LoadRemembering(context.Background(), c, k, 0, time.Minute, fail); err == nil || err.Error() != "slow" {
			t.Fatalf("got %v", err)
		}
	}
	if calls != 1 {
		t.Errorf("%d loads within the minute, want 1", calls)
	}
	clk.t = clk.t.Add(time.Minute - time.Nanosecond)
	if _, err := LoadRemembering(context.Background(), c, k, 0, time.Minute, fail); err == nil || calls != 1 {
		t.Errorf("just under a minute: %v, %d loads", err, calls)
	}
	clk.t = clk.t.Add(time.Nanosecond)
	ok := func(context.Context) (string, error) { calls++; return "v", nil }
	if v, err := LoadRemembering(context.Background(), c, k, 0, time.Minute, ok); err != nil || v != "v" || calls != 2 {
		t.Errorf("after a minute: %q, %v, %d loads", v, err, calls)
	}
	// a key that remembers nothing loads again at once
	other := Key{Report: "bundle"}
	n := 0
	failN := func(context.Context) (string, error) { n++; return "", errors.New("down") }
	for range 2 {
		if _, err := Load(context.Background(), c, other, failN); err == nil || err.Error() != "down" {
			t.Fatalf("a plain failure: %v", err)
		}
	}
	if n != 2 {
		t.Errorf("a plain failure was remembered: %d loads", n)
	}
}

// The stamp check never runs past the caller's deadline.
func TestTheStampQueryKeepsTheCallersDeadline(t *testing.T) {
	clk := &clock{t: time.Unix(0, 0)}
	var left time.Duration
	c := NewCache(func(ctx context.Context) (string, error) {
		dl, _ := ctx.Deadline()
		left = time.Until(dl)
		return "s1", nil
	}, clk.now)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := Load(ctx, c, Key{Report: "bundle"}, func(context.Context) (string, error) { return "v", nil }); err != nil {
		t.Fatal(err)
	}
	if left <= 0 || left > time.Second {
		t.Errorf("the stamp had %v, want at most the caller's second", left)
	}
}

// The cap follows the registry, with room for a full click-through, and keeps its floor.
func TestTheCacheCapFollowsTheRegistry(t *testing.T) {
	c := NewCache(fixedStamp, time.Now)
	if n := len(observability.All()); c.maxEntries < 4*n {
		t.Errorf("maxEntries %d is under four entries a name for %d names", c.maxEntries, n)
	}
	if c.maxEntries < minEntries {
		t.Errorf("maxEntries %d is under the floor %d", c.maxEntries, minEntries)
	}
}
