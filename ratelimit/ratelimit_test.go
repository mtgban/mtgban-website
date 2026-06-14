package ratelimit

import (
	"testing"
	"time"
)

func TestCleanupVisitorsEvictsStaleKeepsRecent(t *testing.T) {
	l := NewLimiter(10, 5)
	l.Allow("keep")
	l.Allow("drop")

	// Backdate "drop" well beyond the cleanup max age.
	l.Lock()
	l.visitors["drop"].lastSeen.Store(time.Now().Add(-time.Hour).UnixNano())
	l.Unlock()

	l.CleanupVisitors(10 * time.Minute)

	l.RLock()
	_, keep := l.visitors["keep"]
	_, drop := l.visitors["drop"]
	l.RUnlock()

	if !keep {
		t.Fatal("recently-seen visitor should be kept")
	}
	if drop {
		t.Fatal("stale visitor should be evicted")
	}
}

func TestAllowStillRateLimits(t *testing.T) {
	l := NewLimiter(1, 1) // 1 token, refills slowly
	if !l.Allow("x") {
		t.Fatal("first call should be allowed")
	}
	if l.Allow("x") {
		t.Fatal("second immediate call should be denied")
	}
}
