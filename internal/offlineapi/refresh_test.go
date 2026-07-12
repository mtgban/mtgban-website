package offlineapi

import (
	"sync/atomic"
	"testing"
	"time"
)

// debounceLoop coalesces a burst of signals into a single run after the
// quiet window elapses, then runs again for the next burst.
func TestDebounceLoopCoalescesBurst(t *testing.T) {
	signal := make(chan struct{}, 1)
	var runs int32
	done := make(chan struct{}, 8)
	run := func() {
		atomic.AddInt32(&runs, 1)
		done <- struct{}{}
	}

	go debounceLoop(signal, 20*time.Millisecond, run)

	// Fire a burst; the cap-1 channel plus coalescing should yield one run.
	for i := 0; i < 5; i++ {
		signal <- struct{}{}
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("first burst never ran")
	}
	// Give any erroneous second run time to appear.
	time.Sleep(60 * time.Millisecond)
	if got := atomic.LoadInt32(&runs); got != 1 {
		t.Fatalf("burst ran %d times, want 1", got)
	}

	// A later signal triggers a fresh run.
	signal <- struct{}{}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("second burst never ran")
	}
	if got := atomic.LoadInt32(&runs); got != 2 {
		t.Fatalf("total runs = %d, want 2", got)
	}
}

func TestRequestRefreshDoesNotBlock(t *testing.T) {
	s := &Service{refreshSignal: make(chan struct{}, 1)}
	// No reader drains the channel; extra sends must not block.
	for i := 0; i < 100; i++ {
		s.RequestRefresh()
	}
}
