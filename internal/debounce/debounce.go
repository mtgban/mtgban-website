// Package debounce provides the shared burst-coalescing run loop used by
// background refreshers.
package debounce

import "time"

// Loop runs `run` once per burst of signals: after the first signal it waits
// for `wait` of quiet, resetting the window each time another signal
// arrives, then runs.
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
