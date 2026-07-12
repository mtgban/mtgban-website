package offlineapi

import "time"

// refreshDebounce is the quiet window a burst of RequestRefresh calls must
// settle for before the manifest is recomputed. A pipeline that reloads many
// scrapers in a row triggers a single refresh. Overridable in tests.
var refreshDebounce = 30 * time.Second

// RequestRefresh asks the background refresher to recompute the manifest soon.
// Non-blocking: rapid calls coalesce into one pending signal.
func (s *Service) RequestRefresh() {
	select {
	case s.refreshSignal <- struct{}{}:
	default:
	}
}

// StartRefresher runs the background manifest refresher. All runtime refreshes
// funnel through this single goroutine, so refreshManifest never overlaps
// itself. Call once after startup loads are kicked off.
func (s *Service) StartRefresher() {
	go debounceLoop(s.refreshSignal, refreshDebounce, s.refreshManifest)
}

// debounceLoop runs `run` once per burst of signals: after the first signal it
// waits for `wait` of quiet, resetting the window each time another signal
// arrives, then runs.
func debounceLoop(signal <-chan struct{}, wait time.Duration, run func()) {
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
