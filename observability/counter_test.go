package observability

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

type call struct {
	minute time.Time
	rows   []Row
}

type fakeCounterStore struct {
	mu       sync.Mutex
	calls    []call        // successful calls only
	attempts int           // every call, failed ones included
	err      error         // fails every call while set
	failCall int           // fails only this attempt (1-based)
	block    chan struct{} // when non-nil, UpsertMinutes waits on it or ctx
	entered  chan struct{} // when non-nil, closed when the first blocked call starts
	deaf     bool          // block ignores ctx
}

func (s *fakeCounterStore) UpsertMinutes(ctx context.Context, minute time.Time, rows []Row) error {
	s.mu.Lock()
	block, entered, deaf := s.block, s.entered, s.deaf
	s.entered = nil
	s.mu.Unlock()
	if block != nil {
		if entered != nil {
			close(entered)
		}
		if deaf {
			<-block
		} else {
			select {
			case <-block:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts++
	if s.err != nil {
		return s.err
	}
	if s.failCall == s.attempts {
		return errors.New("chunk failed")
	}
	s.calls = append(s.calls, call{minute: minute, rows: slices.Clone(rows)})
	return nil
}

func (s *fakeCounterStore) setErr(err error) {
	s.mu.Lock()
	s.err = err
	s.mu.Unlock()
}

func (s *fakeCounterStore) recorded() []call {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.calls)
}

// rowsAt returns every row written for minute, across calls.
func (s *fakeCounterStore) rowsAt(minute time.Time) []Row {
	var out []Row
	for _, c := range s.recorded() {
		if c.minute.Equal(minute) {
			out = append(out, c.rows...)
		}
	}
	return out
}

func (s *fakeCounterStore) allRows() []Row {
	var out []Row
	for _, c := range s.recorded() {
		out = append(out, c.rows...)
	}
	return out
}

type testClock struct{ ns atomic.Int64 }

func newTestClock(t time.Time) *testClock {
	c := &testClock{}
	c.set(t)
	return c
}

func (c *testClock) now() time.Time      { return time.Unix(0, c.ns.Load()).UTC() }
func (c *testClock) set(t time.Time)     { c.ns.Store(t.UnixNano()) }
func (c *testClock) add(d time.Duration) { c.ns.Add(int64(d)) }

var t0 = time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)

func newTestCounter() (*Counter, *fakeCounterStore, *testClock) {
	store := &fakeCounterStore{}
	clock := newTestClock(t0.Add(10 * time.Second))
	return NewCounter(store, "test", clock.now), store, clock
}

func isMetrics(r Row) bool { return strings.HasPrefix(r.Name, "metrics.") }

func withoutMetrics(rows []Row) []Row {
	return slices.DeleteFunc(slices.Clone(rows), isMetrics)
}

func named(rows []Row, name string) []Row {
	return slices.DeleteFunc(slices.Clone(rows), func(r Row) bool { return r.Name != name })
}

// sumNamed adds up n over every row called name.
func sumNamed(rows []Row, name string) int64 {
	var n int64
	for _, r := range named(rows, name) {
		n += r.N
	}
	return n
}

var dimsA = Dims{Instance: "test", Tier: "free", Device: "desktop"}

func TestAddAggregatesWithinAMinute(t *testing.T) {
	c, store, clock := newTestCounter()
	for range 3 {
		c.Add(dimsA, "", "page.view", "search", 1)
	}
	c.Add(dimsA, "", "page.view", "arbit", 1)
	clock.set(t0.Add(time.Minute))
	if err := c.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	calls := store.recorded()
	if len(calls) != 1 || !calls[0].minute.Equal(t0) {
		t.Fatalf("calls = %+v, want one for %v", calls, t0)
	}
	got := withoutMetrics(calls[0].rows)
	want := []Row{
		{Dims: dimsA, Name: "page.view", Value: "arbit", N: 1},
		{Dims: dimsA, Name: "page.view", Value: "search", N: 3},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("rows = %+v, want %+v", got, want)
	}
	if n := sumNamed(calls[0].rows, "metrics.flush"); n != 1 {
		t.Fatalf("metrics.flush = %d, want 1", n)
	}
}

func TestFlushLeavesTheCurrentMinute(t *testing.T) {
	c, store, clock := newTestCounter()
	c.Add(dimsA, "", "page.view", "search", 1)
	clock.set(t0.Add(50 * time.Second))
	if err := c.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, r := range store.rowsAt(t0) {
		if !isMetrics(r) {
			t.Fatalf("row %+v written for the current minute", r)
		}
	}
	// The counter's own row still lands, under the last closed minute.
	if n := sumNamed(store.rowsAt(t0.Add(-time.Minute)), "metrics.flush"); n != 1 {
		t.Fatalf("metrics.flush at %v = %d, want 1", t0.Add(-time.Minute), n)
	}
	clock.set(t0.Add(time.Minute))
	if err := c.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := withoutMetrics(store.rowsAt(t0)); len(got) != 1 || got[0].N != 1 {
		t.Fatalf("after the minute closed: %+v", got)
	}
}

func TestRowsAreSortedAndUnique(t *testing.T) {
	c, store, clock := newTestCounter()
	type k struct {
		d     Dims
		scope string
		value string
	}
	var keys []k
	for i := range 20 {
		d := Dims{Instance: "test", Tier: fmt.Sprint("t", i%3), Device: "mobile", Signed: i%2 == 0, Bot: i%5 == 0}
		keys = append(keys, k{d, fmt.Sprint("s", i%4), fmt.Sprint("v", i)})
	}
	var adds []k
	for range 10 {
		adds = append(adds, keys...)
	}
	rand.Shuffle(len(adds), func(i, j int) { adds[i], adds[j] = adds[j], adds[i] })
	for _, a := range adds {
		c.Add(a.d, a.scope, "page.view", a.value, 1)
	}
	c.Reject()
	clock.set(t0.Add(time.Minute))
	if err := c.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	rows := store.rowsAt(t0)
	strictly := func(a, b Row) int {
		if c := compareRows(a, b); c != 0 {
			return c
		}
		return -1 // equal neighbours read as out of order
	}
	if dup := []Row{rows[0], rows[0]}; slices.IsSortedFunc(dup, strictly) {
		t.Fatal("strictly accepts a duplicate pair")
	}
	if !slices.IsSortedFunc(rows, strictly) {
		t.Fatalf("rows not sorted or not unique: %+v", rows)
	}
	if n := len(rows) - len(withoutMetrics(rows)); n != 2 {
		t.Fatalf("%d metrics rows checked, want flush and rejected", n)
	}
	got := withoutMetrics(rows)
	if len(got) != 20 {
		t.Fatalf("got %d keys, want 20", len(got))
	}
	for _, r := range got {
		if r.N != 10 {
			t.Fatalf("row %+v, want n=10", r)
		}
	}
}

func TestChunksAtSixThousandRows(t *testing.T) {
	c, store, clock := newTestCounter()
	for i := range 13_000 {
		c.Add(dimsA, "", "page.view", fmt.Sprint(i), 1)
	}
	clock.set(t0.Add(time.Minute))
	if err := c.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	calls := store.recorded()
	if len(calls) != 3 {
		t.Fatalf("%d calls, want 3", len(calls))
	}
	total := 0
	for _, cl := range calls {
		if len(cl.rows) > 6000 {
			t.Fatalf("chunk of %d rows", len(cl.rows))
		}
		total += len(cl.rows)
	}
	all := store.allRows()
	if n := len(withoutMetrics(all)); n != 13_000 {
		t.Fatalf("%d feature rows, want 13000", n)
	}
	if total != 13_000+len(named(all, "metrics.flush")) {
		t.Fatalf("total %d rows", total)
	}
}

func TestFailedChunkKeepsOnlyUnsentRows(t *testing.T) {
	c, store, clock := newTestCounter()
	for i := range 13_000 {
		c.Add(dimsA, "", "page.view", fmt.Sprint(i), 1)
	}
	store.failCall = 2
	clock.set(t0.Add(time.Minute))
	if err := c.Flush(context.Background()); err == nil {
		t.Fatal("Flush returned nil, want the chunk's error")
	}
	if n := len(store.rowsAt(t0)); n != 6000 {
		t.Fatalf("first flush wrote %d rows, want one chunk of 6000", n)
	}
	clock.set(t0.Add(2 * time.Minute))
	if err := c.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, r := range withoutMetrics(store.rowsAt(t0)) {
		seen[r.Value] += int(r.N)
	}
	if len(seen) != 13_000 {
		t.Fatalf("%d keys arrived, want 13000", len(seen))
	}
	for v, n := range seen {
		if n != 1 {
			t.Fatalf("key %q counted %d times", v, n)
		}
	}
	if n := sumNamed(store.allRows(), "metrics.flush_fail"); n != 1 {
		t.Fatalf("metrics.flush_fail = %d, want 1", n)
	}
}

func TestFailedFlushIsRetried(t *testing.T) {
	c, store, clock := newTestCounter()
	c.Add(dimsA, "", "page.view", "search", 2)
	store.setErr(errors.New("db down"))
	clock.set(t0.Add(time.Minute))
	if err := c.Flush(context.Background()); err == nil {
		t.Fatal("Flush returned nil, want the store's error")
	}
	if s := c.Stats(); s.FlushFailed != 1 {
		t.Fatalf("FlushFailed = %d, want 1", s.FlushFailed)
	}
	store.setErr(nil)
	clock.set(t0.Add(2 * time.Minute))
	if err := c.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := withoutMetrics(store.rowsAt(t0))
	if len(got) != 1 || got[0].N != 2 {
		t.Fatalf("first minute's rows = %+v", got)
	}
	if n := sumNamed(store.allRows(), "metrics.flush_fail"); n != 1 {
		t.Fatalf("metrics.flush_fail = %d, want 1", n)
	}
}

func TestStaleMinutesAreDiscarded(t *testing.T) {
	c, store, clock := newTestCounter()
	c.Add(dimsA, "", "page.view", "search", 1)
	store.setErr(errors.New("db down"))
	clock.set(t0.Add(31 * time.Minute))
	if err := c.Flush(context.Background()); err == nil {
		t.Fatal("Flush returned nil, want the store's error")
	}
	if s := c.Stats(); s.Dropped != 1 {
		t.Fatalf("Dropped = %d, want 1", s.Dropped)
	}
	store.setErr(nil)
	if err := c.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := store.rowsAt(t0); len(got) != 0 {
		t.Fatalf("stale minute written: %+v", got)
	}
	if n := sumNamed(store.allRows(), "metrics.dropped"); n != 1 {
		t.Fatalf("metrics.dropped = %d, want 1", n)
	}
}

func TestKeyCapDropsNewKeysOnly(t *testing.T) {
	c, store, clock := newTestCounter()
	c.maxKeys = 3
	for _, v := range []string{"a", "b", "c", "d"} {
		c.Add(dimsA, "", "page.view", v, 1)
	}
	if s := c.Stats(); s.Dropped != 1 {
		t.Fatalf("Dropped = %d, want 1", s.Dropped)
	}
	c.Add(dimsA, "", "page.view", "a", 1)
	clock.set(t0.Add(time.Minute))
	if err := c.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	rows := store.rowsAt(t0)
	want := []Row{
		{Dims: dimsA, Name: "page.view", Value: "a", N: 2},
		{Dims: dimsA, Name: "page.view", Value: "b", N: 1},
		{Dims: dimsA, Name: "page.view", Value: "c", N: 1},
	}
	if got := withoutMetrics(rows); !slices.Equal(got, want) {
		t.Fatalf("rows = %+v, want %+v", got, want)
	}
	if n := sumNamed(rows, "metrics.dropped"); n != 1 {
		t.Fatalf("metrics.dropped = %d, want 1", n)
	}
}

// keysHeld returns the key count and the keys actually pending.
func keysHeld(c *Counter) (counted, pending int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, m := range c.pending {
		pending += len(m)
	}
	return c.keys, pending
}

func TestKeyCapHoldsAcrossAFailedFlush(t *testing.T) {
	c, store, clock := newTestCounter()
	c.maxKeys = 5
	c.Add(dimsA, "", "page.view", "a", 1)
	c.Add(dimsA, "", "page.view", "b", 1)
	block := make(chan struct{})
	entered := make(chan struct{})
	store.block, store.entered = block, entered
	clock.set(t0.Add(time.Minute))
	flushed := make(chan error, 1)
	go func() { flushed <- c.Flush(context.Background()) }()
	<-entered
	// In flight: a, b and metrics.flush. Two new keys fit, the third does not.
	for _, v := range []string{"c", "d", "e"} {
		c.Add(dimsA, "", "page.view", v, 1)
	}
	if counted, _ := keysHeld(c); counted > c.maxKeys {
		t.Fatalf("%d keys counted while in flight, cap %d", counted, c.maxKeys)
	}
	store.setErr(errors.New("db down"))
	close(block)
	if err := <-flushed; err == nil {
		t.Fatal("Flush returned nil, want the store's error")
	}
	counted, pending := keysHeld(c)
	if counted != pending || pending > c.maxKeys {
		t.Fatalf("after the failure: counted %d, pending %d, cap %d", counted, pending, c.maxKeys)
	}
	if s := c.Stats(); s.Dropped != 1 {
		t.Fatalf("Dropped = %d, want 1 (only e)", s.Dropped)
	}
	// The retry sends the put-back rows and the new ones, releasing every count.
	store.setErr(nil)
	store.mu.Lock()
	store.block = nil
	store.mu.Unlock()
	clock.set(t0.Add(2 * time.Minute))
	if err := c.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if counted, pending := keysHeld(c); counted != 0 || pending != 0 {
		t.Fatalf("after the retry: counted %d, pending %d", counted, pending)
	}
	if n := sumNamed(store.allRows(), "page.view"); n != 4 {
		t.Fatalf("page.view = %d, want 4", n)
	}
}

func TestPutBackMergeReleasesTheKey(t *testing.T) {
	c, _, _ := newTestCounter()
	k := counterKey{Dims: dimsA, name: "page.view", value: "a"}
	c.mu.Lock()
	c.addLocked(t0, k, 1)
	c.keys++ // the same key also in flight
	c.mu.Unlock()
	c.putBack([]minuteRows{{t0, []Row{{Dims: dimsA, Name: "page.view", Value: "a", N: 2}}}})
	counted, pending := keysHeld(c)
	if counted != 1 || pending != 1 {
		t.Fatalf("counted %d, pending %d, want 1 and 1", counted, pending)
	}
	c.mu.Lock()
	n := c.pending[t0][k]
	c.mu.Unlock()
	if n != 3 {
		t.Fatalf("merged n = %d, want 3", n)
	}
}

func TestRejectIsReported(t *testing.T) {
	c, store, clock := newTestCounter()
	c.Reject()
	c.Reject()
	clock.set(t0.Add(time.Minute))
	if err := c.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	rej := named(store.rowsAt(t0), "metrics.rejected")
	want := Dims{Instance: "test", Device: "job"}
	if len(rej) != 1 || rej[0].N != 2 || rej[0].Dims != want {
		t.Fatalf("metrics.rejected rows = %+v", rej)
	}
	if s := c.Stats(); s.Rejected != 2 {
		t.Fatalf("Rejected = %d, want 2", s.Rejected)
	}
	// Written once: the next flush carries no rejected row.
	clock.add(time.Minute)
	if err := c.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := sumNamed(store.allRows(), "metrics.rejected"); n != 2 {
		t.Fatalf("metrics.rejected total = %d, want 2", n)
	}
}

func TestCloseFlushesTheCurrentMinuteWithinItsDeadline(t *testing.T) {
	c, store, _ := newTestCounter()
	c.Add(dimsA, "", "page.view", "search", 1)
	if err := c.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := withoutMetrics(store.rowsAt(t0)); len(got) != 1 {
		t.Fatalf("current minute rows = %+v", got)
	}

	// A fresh counter: the first one is closed.
	c, store, _ = newTestCounter()
	store.block = make(chan struct{})
	c.Add(dimsA, "", "page.view", "search", 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	closeWithin(ctx, t, c)

	// Cancelled while the store is blocked.
	c, store, _ = newTestCounter()
	store.block = make(chan struct{})
	entered := make(chan struct{})
	store.entered = entered
	c.Add(dimsA, "", "page.view", "search", 1)
	ctx, cancel = context.WithCancel(context.Background())
	go func() {
		<-entered
		cancel()
	}()
	closeWithin(ctx, t, c)

	// A store deaf to ctx: Close's own select must end the wait.
	c, store, _ = newTestCounter()
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	store.block, store.deaf = block, true
	entered = make(chan struct{})
	store.entered = entered
	c.Add(dimsA, "", "page.view", "search", 1)
	ctx, cancel = context.WithCancel(context.Background())
	go func() {
		<-entered
		cancel()
	}()
	closeWithin(ctx, t, c)
	store.mu.Lock()
	attempts := store.attempts
	store.mu.Unlock()
	if attempts != 0 {
		t.Fatalf("store returned (%d attempts), want it still blocked", attempts)
	}
}

// closeWithin asserts Close returns ctx.Err() before a failure deadline.
func closeWithin(ctx context.Context, t *testing.T, c *Counter) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- c.Close(ctx) }()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Close = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return after its context ended")
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	c, store, _ := newTestCounter()
	c.Add(dimsA, "", "page.view", "search", 1)
	if err := c.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	n := len(store.recorded())
	if err := c.Close(context.Background()); err != nil {
		t.Fatalf("second Close = %v, want nil", err)
	}
	if got := len(store.recorded()); got != n {
		t.Fatalf("second Close wrote %d more calls", got-n)
	}
	if got := withoutMetrics(store.rowsAt(t0)); len(got) != 1 {
		t.Fatalf("rows after two Closes = %+v", got)
	}
}

func TestAddAfterCloseIsANoOp(t *testing.T) {
	c, store, clock := newTestCounter()
	if err := c.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.Add(dimsA, "", "page.view", "late", 1)
	clock.add(time.Minute)
	if err := c.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := named(store.allRows(), "page.view"); len(got) != 0 {
		t.Fatalf("Add after Close stored %+v", got)
	}
}

func TestAddIsSafeForConcurrentUse(t *testing.T) {
	c, store, clock := newTestCounter()
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 1000 {
				c.Add(dimsA, "", "page.view", "search", 1)
			}
		})
	}
	wg.Go(func() {
		for range 10 {
			if err := c.Flush(context.Background()); err != nil {
				t.Error(err)
			}
		}
	})
	wg.Wait()
	clock.set(t0.Add(time.Minute))
	if err := c.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := sumNamed(store.allRows(), "page.view"); n != 8000 {
		t.Fatalf("page.view = %d, want 8000", n)
	}
}

// TestNilCounterIsSafe guards nil-safety: every method on a nil *Counter is a no-op.
func TestNilCounterIsSafe(t *testing.T) {
	var c *Counter
	c.Add(dimsA, "", "page.view", "search", 1)
	c.Reject()
	if err := c.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.Run(context.Background(), time.Minute)
	if err := c.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s := c.Stats(); s != (CounterStats{}) {
		t.Fatalf("Stats = %+v", s)
	}
}

func TestRunFlushesOnTheTicker(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := &fakeCounterStore{}
		c := NewCounter(store, "test", time.Now)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			c.Run(ctx, time.Minute)
			close(done)
		}()
		c.Add(dimsA, "", "page.view", "search", 1)
		time.Sleep(2 * time.Minute)
		synctest.Wait()
		rows := store.allRows()
		if got := named(rows, "page.view"); len(got) != 1 || got[0].N != 1 {
			t.Fatalf("page.view rows = %+v", got)
		}
		if len(named(rows, "metrics.flush")) == 0 {
			t.Fatal("no metrics.flush row")
		}
		cancel()
		<-done
	})
}

func TestRunRecoversAPanickingFlush(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := &panicOnceStore{}
		c := NewCounter(store, "test", time.Now)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			c.Run(ctx, time.Minute)
			close(done)
		}()
		c.Add(dimsA, "", "page.view", "search", 1)
		time.Sleep(2 * time.Minute)
		synctest.Wait()
		if n := store.panics.Load(); n != 1 {
			t.Fatalf("store panicked %d times, want 1", n)
		}
		// The panicked flush held page.view and metrics.flush: both dropped.
		if s := c.Stats(); s.Dropped != 2 {
			t.Fatalf("Dropped = %d, want 2", s.Dropped)
		}
		rows := store.allRows()
		if n := sumNamed(rows, "metrics.dropped"); n != 2 {
			t.Fatalf("metrics.dropped = %d, want 2 (the loop kept serving)", n)
		}
		if got := named(rows, "page.view"); len(got) != 0 {
			t.Fatalf("dropped row written: %+v", got)
		}
		cancel()
		<-done
	})
}

// panicOnceStore panics on its first call, then records like the fake.
type panicOnceStore struct {
	fakeCounterStore
	panics atomic.Int64
}

func (s *panicOnceStore) UpsertMinutes(ctx context.Context, minute time.Time, rows []Row) error {
	if s.panics.CompareAndSwap(0, 1) {
		panic("boom")
	}
	return s.fakeCounterStore.UpsertMinutes(ctx, minute, rows)
}
