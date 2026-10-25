// Package poke keeps what makes a signature stale before its age does: when
// each poked reader was poked, and when the access table last changed. A
// signature issued before either renews on its next request; one issued after
// is left alone, so each of a reader's devices renews once.
package poke

import (
	"sync"
	"time"
)

// Set is the pokes a process holds, in memory: a poke costs a request no
// database work, and one a restarting process missed is caught by the age
// window. A poke lasts the window the caller gives, after_days on the site,
// when that window would have renewed the reader anyway, and the next poke
// sweeps the ones that lapsed; the table's moment lasts as long as the Set.
// Both are kept to the second, the resolution a signature's Expires has, so a
// renewal in their second is issued at them rather than before them.
type Set struct {
	mu         sync.RWMutex
	at         map[string]time.Time // the reader's email hash -> when poked
	aclChanged time.Time
	// reminted is the signatures re-signed under the access table since it
	// last changed, by the HMAC each carries, with when each runs out: a
	// re-signed signature keeps its Expires, so its age cannot tell it from
	// the one it replaced.
	reminted map[string]time.Time
}

// New returns an empty Set.
func New() *Set {
	return &Set{at: map[string]time.Time{}, reminted: map[string]time.Time{}}
}

// Poke marks the reader with the given email hash as poked at at, and drops the
// pokes older than window.
func (s *Set) Poke(hash string, at time.Time, window time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for other, when := range s.at {
		if at.Sub(when) >= window {
			delete(s.at, other)
		}
	}
	s.at[hash] = at.Truncate(time.Second)
}

// Poked says whether the reader with the given email hash was poked within
// window before now.
func (s *Set) Poked(hash string, now time.Time, window time.Duration) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	at, found := s.at[hash]
	return found && now.Sub(at) < window
}

// Len is how many readers are poked, lapsed or not.
func (s *Set) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.at)
}

// StampACL records that the access table changed at now. Every signature
// issued before it is re-signed on its next request, since the page flags it
// carries were baked in from the old table, and the ones re-signed under the
// table it replaces are forgotten.
func (s *Set) StampACL(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.aclChanged = now.Truncate(time.Second)
	s.reminted = map[string]time.Time{}
}

// Reminted records that the signature carrying the HMAC signature was
// re-signed under the current access table and runs out at expires, and
// forgets those that ran out by now.
func (s *Set) Reminted(signature string, expires, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for other, end := range s.reminted {
		if !now.Before(end) {
			delete(s.reminted, other)
		}
	}
	s.reminted[signature] = expires
}

// ACLChanged is when the access table last changed, to the second, or zero
// when it has not since the Set was made.
func (s *Set) ACLChanged() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.aclChanged
}

// Wants says what asks the signature of the reader with the given email hash,
// carrying the HMAC signature and issued at issued, to renew at now whatever
// its age: "poke" when the reader was poked within window before now and
// after it was issued, "acl" when the access table changed after it was
// issued and it was not re-signed since, nothing otherwise. It reads nothing
// but its arguments. Moments are kept to the second, the resolution Expires
// has: a signature minted in the same second as the edit reads as issued at it
// and waits for its age, and one renewed in that second is not renewed again.
func (s *Set) Wants(hash, signature string, issued, now time.Time, window time.Duration) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	at, found := s.at[hash]
	_, reminted := s.reminted[signature]
	switch {
	case found && now.Sub(at) < window && issued.Before(at):
		return "poke"
	case issued.Before(s.aclChanged) && !reminted:
		return "acl"
	}
	return ""
}
