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

type Limiter struct {
	sync.RWMutex

	burst    int
	rate     rate.Limit
	visitors map[string]*visitor
}

func NewLimiter(r rate.Limit, burst int) *Limiter {
	l := &Limiter{
		rate:     r,
		burst:    burst,
		visitors: map[string]*visitor{},
	}
	// Evict visitors idle longer than 30 minutes, checked every 10 minutes,
	// so the visitors map can't grow without bound.
	go l.janitor(10*time.Minute, 30*time.Minute)
	return l
}

// Allow checks if the given key has not exceeded the rate limit.
func (l *Limiter) Allow(ip string) bool {
	l.RLock()
	v, exists := l.visitors[ip]
	l.RUnlock()

	if !exists {
		l.Lock()
		// Re-check under the write lock in case another goroutine created it.
		if existing, ok := l.visitors[ip]; ok {
			v = existing
		} else {
			v = &visitor{Limiter: rate.NewLimiter(l.rate, l.burst)}
			l.visitors[ip] = v
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

func IPAddress(r *http.Request) (net.IP, error) {
	// Try headers first
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		// Take the first IP from the comma list
		// The first IP is the real client, and the rest are proxies.
		parts := strings.Split(xff, ",")
		ipStr := strings.TrimSpace(parts[0])
		ip := net.ParseIP(ipStr)
		if ip != nil {
			return ip, nil
		}
	}

	xrip := strings.TrimSpace(r.Header.Get("X-Real-Ip"))
	if xrip != "" {
		ip := net.ParseIP(xrip)
		if ip != nil {
			return ip, nil
		}
	}

	// Fall back to RemoteAddr (this one *is* ip:port)
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid RemoteAddr: %q", r.RemoteAddr)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP: %q", host)
	}

	return ip, nil
}
