package offlineapi

import (
	"time"

	"github.com/mtgban/mtgban-website/internal/debounce"
)

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
//
// Each refresh runs through recovered, which the caller supplies to report
// and recover a panic. It wraps every refresh rather than the loop, so one
// that panics leaves the loop serving the next request.
func (s *Service) StartRefresher(recovered func(job string, fn func()) func()) {
	go debounce.Loop(s.refreshSignal, refreshDebounce, recovered("offline refreshManifest", s.refreshManifest))
}
