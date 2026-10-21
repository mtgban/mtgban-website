package ratelimit

import (
	"fmt"
	"net/http"
	"net/http/httptest"
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

func forwarded(remote string, xff ...string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remote
	for _, v := range xff {
		r.Header.Add("X-Forwarded-For", v)
	}
	return r
}

// nginx appends the peer it saw to whatever X-Forwarded-For the client sent,
// so only the last entry is the proxy's; the ones before it are the
// client's to choose and must not move the key.
func TestIPAddressIgnoresWhatTheClientForwards(t *testing.T) {
	for _, tc := range []struct {
		name string
		r    *http.Request
		want string
	}{
		{"nginx, no client header", forwarded("127.0.0.1:5000", "198.51.100.7"), "198.51.100.7"},
		{"nginx, spoofed entry", forwarded("127.0.0.1:5000", "203.0.113.1, 198.51.100.7"), "198.51.100.7"},
		{"nginx, other spoofed entry", forwarded("127.0.0.1:5000", "203.0.113.2, 198.51.100.7"), "198.51.100.7"},
		{"spoofed header line", forwarded("127.0.0.1:5000", "203.0.113.3", "198.51.100.7"), "198.51.100.7"},
		{"internal hop after the peer", forwarded("10.0.0.3:5000", "203.0.113.1, 198.51.100.7, 10.0.0.2"), "198.51.100.7"},
		{"garbage last entry", forwarded("192.0.2.4:5000", "203.0.113.1, not-an-ip"), "192.0.2.4"},
		{"no header", forwarded("192.0.2.4:5000"), "192.0.2.4"},
	} {
		ip, err := IPAddress(tc.r)
		if err != nil || ip.String() != tc.want {
			t.Errorf("%s: got %v, %v; want %s", tc.name, ip, err, tc.want)
		}
	}

	// A client reaching the socket with an X-Real-Ip of its own is still
	// keyed on the socket.
	r := forwarded("192.0.2.4:5000")
	r.Header.Set("X-Real-Ip", "203.0.113.9")
	if ip, _ := IPAddress(r); ip.String() != "192.0.2.4" {
		t.Errorf("X-Real-Ip moved the key to %v", ip)
	}
}

func TestFirstForwarded(t *testing.T) {
	if ip := FirstForwarded(forwarded("127.0.0.1:5000", "203.0.113.1, 198.51.100.7")); ip.String() != "203.0.113.1" {
		t.Errorf("got %v, want 203.0.113.1", ip)
	}
	if ip := FirstForwarded(forwarded("127.0.0.1:5000", "junk, 198.51.100.7")); ip != nil {
		t.Errorf("got %v for a junk first entry, want nil", ip)
	}
	if ip := FirstForwarded(forwarded("127.0.0.1:5000")); ip != nil {
		t.Errorf("got %v with no header, want nil", ip)
	}
}

// A flood of distinct keys (an IPv6 block can supply 2^64 of them) must not
// grow the map past its cap between janitor runs.
func TestAllowBoundsVisitors(t *testing.T) {
	l := NewLimiter(10, 5)
	l.maxVisitors = 64
	for i := range 10 * l.maxVisitors {
		l.Allow(fmt.Sprint("key", i))
	}
	l.RLock()
	n := len(l.visitors)
	l.RUnlock()
	if n > l.maxVisitors {
		t.Fatalf("%d visitors held, want at most %d", n, l.maxVisitors)
	}
	if !l.Allow("fresh") {
		t.Fatal("a new key at the cap should still be allowed")
	}
}

func TestNewLimiterHasACap(t *testing.T) {
	if l := NewLimiter(1, 1); l.maxVisitors <= 0 {
		t.Fatalf("maxVisitors = %d, want a positive default", l.maxVisitors)
	}
}
