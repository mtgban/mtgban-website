package offlineapi

import (
	"time"

	"github.com/mtgban/mtgban-website/internal/debounce"
)

// refreshWindow is how long the manifest waits after the first
// RequestRefresh, so that store reloads landing a few minutes apart
// re-version each set once. Offline prices lag the site by at most this.
// Overridable in tests.
var refreshWindow = 10 * time.Minute

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
	go debounce.Batch(s.refreshSignal, refreshWindow, recovered("offline refreshManifest", s.refreshManifest))
}
