// Package debounce provides the shared burst-coalescing run loop used by
// background refreshers.
package debounce

import "time"

// Loop runs `run` once per burst of signals: after the first signal it waits
// for `wait` of quiet, resetting the window each time another signal
// arrives, then runs. A panic in run ends the loop, so a caller that must
// outlive one hands in a run that recovers it.
func Loop(signal <-chan struct{}, wait time.Duration, run func()) {
	for range signal {
		timer := time.NewTimer(wait)
		settling := true
		for settling {
			select {
			case <-signal:
				if !timer.Stop() {
					<-timer.C
				}
				timer.Reset(wait)
			case <-timer.C:
				settling = false
			}
		}
		run()
	}
}

// Batch runs `run` at most once per `wait`: the first signal starts the
// window, every signal before it closes joins the same run, and a signal
// during the run starts the next window. Unlike Loop, a steady stream of
// signals cannot hold the run back past `wait`.
func Batch(signal <-chan struct{}, wait time.Duration, run func()) {
	for range signal {
		timer := time.NewTimer(wait)
		for waiting := true; waiting; {
			select {
			case <-signal:
			case <-timer.C:
				waiting = false
			}
		}
		run()
	}
}
