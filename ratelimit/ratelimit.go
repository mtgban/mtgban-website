// Package ratelimit throttles requests per key (a visitor IP, an email).
package ratelimit

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

type visitor struct {
	*rate.Limiter
	lastSeen atomic.Int64 // unix nanos of the last Allow
}

// Limiter rate-limits per key (a visitor IP, an email), forgetting a key
// that stays away.
type Limiter struct {
	sync.RWMutex

	burst       int
	rate        rate.Limit
	visitors    map[string]*visitor
	maxVisitors int
}

// DefaultMaxVisitors caps the keys a Limiter holds, a few tens of MB at
// most, so a flood of distinct keys cannot outgrow memory between the
// janitor's runs.
const DefaultMaxVisitors = 100_000

// NewLimiter returns a limiter allowing rate r with the given burst for
// each visitor.
func NewLimiter(r rate.Limit, burst int) *Limiter {
	l := &Limiter{
		rate:        r,
		burst:       burst,
		visitors:    map[string]*visitor{},
		maxVisitors: DefaultMaxVisitors,
	}
	// Bound the visitors map: evict entries idle past 30m, checked every 10m.
	go l.janitor(10*time.Minute, 30*time.Minute)
	return l
}

// Allow reports whether key, a visitor IP or an email, is within its rate.
func (l *Limiter) Allow(key string) bool {
	l.RLock()
	v, exists := l.visitors[key]
	l.RUnlock()

	if !exists {
		l.Lock()
		// Re-check under the write lock in case another goroutine created it.
		if existing, ok := l.visitors[key]; ok {
			v = existing
		} else {
			// At the cap, drop an arbitrary key: it starts over with a
			// full burst, which costs less than refusing every new one.
			if len(l.visitors) >= l.maxVisitors {
				for k := range l.visitors {
					delete(l.visitors, k)
					break
				}
			}
			v = &visitor{Limiter: rate.NewLimiter(l.rate, l.burst)}
			l.visitors[key] = v
		}
		l.Unlock()
	}

	v.lastSeen.Store(time.Now().UnixNano())
	return v.Limiter.Allow()
}

// CleanupVisitors drops visitors not seen within maxAge.
func (l *Limiter) CleanupVisitors(maxAge time.Duration) {
	cutoff := time.Now().Add(-maxAge).UnixNano()
	l.Lock()
	for k, v := range l.visitors {
		if v.lastSeen.Load() < cutoff {
			delete(l.visitors, k)
		}
	}
	l.Unlock()
}

func (l *Limiter) janitor(interval, maxAge time.Duration) {
	t := time.NewTicker(interval)
	for range t.C {
		l.CleanupVisitors(maxAge)
	}
}

// IPAddress is the caller's address as the nearest proxy saw it. Only a
// loopback or private peer, nginx on 127.0.0.1 or an internal load balancer,
// is trusted for X-Forwarded-For: then the key is the last entry that is not
// itself such a hop, the one that proxy appended. Entries before it are
// whatever the client sent, so they never pick the key. Any other peer is
// the key itself.
func IPAddress(r *http.Request) (net.IP, error) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid RemoteAddr: %q", r.RemoteAddr)
	}
	peer := net.ParseIP(host)
	if peer == nil {
		return nil, fmt.Errorf("invalid IP: %q", host)
	}
	if !internalHop(peer) {
		return peer, nil
	}

	entries := forwardedFor(r)
	for i := len(entries) - 1; i >= 0; i-- {
		ip := net.ParseIP(entries[i])
		if ip == nil {
			break
		}
		if !internalHop(ip) {
			return ip, nil
		}
	}
	return peer, nil
}

// internalHop reports whether ip is a proxy's own address, not a client's.
func internalHop(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

// FirstForwarded is the first X-Forwarded-For entry, or nil. Only a proxy
// that replaces the header, as the API gateway does, can vouch for it, so
// read it only for a request that proxy is known to have sent.
func FirstForwarded(r *http.Request) net.IP {
	entries := forwardedFor(r)
	if len(entries) == 0 {
		return nil
	}
	return net.ParseIP(entries[0])
}

// forwardedFor lists the X-Forwarded-For entries across every header line.
func forwardedFor(r *http.Request) []string {
	var entries []string
	for _, line := range r.Header.Values("X-Forwarded-For") {
		for part := range strings.SplitSeq(line, ",") {
			entries = append(entries, strings.TrimSpace(part))
		}
	}
	return entries
}
