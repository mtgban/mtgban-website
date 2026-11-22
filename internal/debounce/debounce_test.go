package debounce

import (
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// Loop coalesces a burst of signals into a single run after the quiet
// window elapses, then runs again for the next burst.
func TestLoopCoalescesBurst(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const wait = 20 * time.Millisecond
		signal := make(chan struct{}, 1)
		defer close(signal)
		var runs int32
		go Loop(signal, wait, func() { atomic.AddInt32(&runs, 1) })

		// Fire a burst; the cap-1 channel plus coalescing should yield one run.
		for i := 0; i < 5; i++ {
			signal <- struct{}{}
		}
		synctest.Wait()
		if got := atomic.LoadInt32(&runs); got != 0 {
			t.Fatalf("burst ran %d times before its quiet window ended", got)
		}

		// Any erroneous second run has its time to appear.
		time.Sleep(10 * wait)
		synctest.Wait()
		if got := atomic.LoadInt32(&runs); got != 1 {
			t.Fatalf("burst ran %d times, want 1", got)
		}

		// A later signal triggers a fresh run.
		signal <- struct{}{}
		time.Sleep(10 * wait)
		synctest.Wait()
		if got := atomic.LoadInt32(&runs); got != 2 {
			t.Fatalf("total runs = %d, want 2", got)
		}
	})
}

// Batch runs once per window however steady the signals: a signal every six
// milliseconds against a 20 ms window runs at 20, 44, 68 and 92 ms, where
// Loop would wait for the stream to stop.
func TestBatchRunsThroughASteadyStream(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const wait = 20 * time.Millisecond
		signal := make(chan struct{}, 1)
		var runs int32
		go Batch(signal, wait, func() { atomic.AddInt32(&runs, 1) })

		for range 16 {
			signal <- struct{}{}
			time.Sleep(6 * time.Millisecond)
		}
		synctest.Wait()
		if got := atomic.LoadInt32(&runs); got != 4 {
			t.Fatalf("a 96 ms stream ran %d times, want 4", got)
		}

		time.Sleep(10 * wait)
		synctest.Wait()
		if got := atomic.LoadInt32(&runs); got != 4 {
			t.Fatalf("runs = %d after the stream stopped, want still 4", got)
		}
		close(signal)
	})
}

// A signal that arrives while a run is going starts the next window rather
// than being folded into the run that may already have read past it.
func TestBatchSignalDuringRunStartsNextWindow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const wait = 20 * time.Millisecond
		signal := make(chan struct{}, 1)
		running, release := make(chan struct{}), make(chan struct{})
		var runs int32
		go Batch(signal, wait, func() {
			if atomic.AddInt32(&runs, 1) == 1 {
				running <- struct{}{}
				<-release
			}
		})

		signal <- struct{}{}
		<-running
		signal <- struct{}{}
		close(release)
		time.Sleep(2 * wait)
		synctest.Wait()
		if got := atomic.LoadInt32(&runs); got != 2 {
			t.Fatalf("runs = %d, want 2", got)
		}
		close(signal)
	})
}
