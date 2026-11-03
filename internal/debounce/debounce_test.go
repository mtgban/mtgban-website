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
