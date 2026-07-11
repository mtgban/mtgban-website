package imgmirror

import (
	"sync"
	"time"
)

// Limiter spaces requests per domain by a minimum interval.
type Limiter struct {
	Interval time.Duration

	mu   sync.Mutex
	next map[string]time.Time
}

// Reserve books the next slot for domain and returns the wait from now.
func (l *Limiter) Reserve(domain string, now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.next == nil {
		l.next = map[string]time.Time{}
	}
	at := l.next[domain]
	if at.Before(now) {
		at = now
	}
	l.next[domain] = at.Add(l.Interval)
	return at.Sub(now)
}

// Backoff returns the retry delay for a 0-based attempt, capped at 30s.
func Backoff(attempt int) time.Duration {
	if attempt < 0 || attempt > 30 {
		return 30 * time.Second
	}
	d := time.Second << uint(attempt)
	if d > 30*time.Second {
		return 30 * time.Second
	}
	return d
}
