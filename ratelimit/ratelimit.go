package ratelimit

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"

	"golang.org/x/time/rate"
)

type visitor struct {
	*rate.Limiter
}

type Limiter struct {
	sync.RWMutex

	burst    int
	rate     rate.Limit
	visitors map[string]*visitor
}

func NewLimiter(r rate.Limit, burst int) *Limiter {
	return &Limiter{
		rate:     r,
		burst:    burst,
		visitors: map[string]*visitor{},
	}
}

// Allow checks if given ip has not exceeded rate limit
func (l *Limiter) Allow(ip string) bool {
	l.RLock()
	v, exists := l.visitors[ip]
	l.RUnlock()

	if !exists {
		v = &visitor{
			Limiter: rate.NewLimiter(l.rate, l.burst),
		}
		l.Lock()
		l.visitors[ip] = v
		l.Unlock()
	}

	return v.Limiter.Allow()
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
