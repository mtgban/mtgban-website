// Package poke keeps what makes a signature stale before its age does: when
// each poked reader was poked, when the access table last changed, and when
// each grantee's grant did. A signature issued before any of them renews or is
// re-signed on its next request; one issued after is left alone, so each of a
// reader's devices renews once.
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
// Both, and a grant's moment, are read to the second, the resolution a
// signature's Expires has, and rounded up, so a signature minted earlier in
// their second reads as issued before them.
type Set struct {
	mu         sync.RWMutex
	at         map[string]time.Time // the reader's email hash -> when poked
	aclChanged time.Time
	// grants is when each grantee's grant last changed, by email hash, to
	// the instant: rounded up only against an issue time, so a re-sign in
	// the edit's own second still answers it.
	grants map[string]time.Time
	// reminted is the signatures re-signed here since the access table last
	// changed, by the HMAC each carries, with when each was re-signed and
	// when it runs out: a re-signed signature keeps its Expires, so its age
	// cannot tell it from the one it replaced.
	reminted map[string]remint
}

type remint struct {
	at, ends time.Time
}

// New returns an empty Set.
func New() *Set {
	return &Set{at: map[string]time.Time{}, grants: map[string]time.Time{}, reminted: map[string]remint{}}
}

// ceilSecond is t rounded up to the second.
func ceilSecond(t time.Time) time.Time {
	return t.Truncate(time.Second).Add(time.Second)
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
	s.at[hash] = ceilSecond(at)
}

// Poked says whether the reader with the given email hash was poked within
// window before now.
func (s *Set) Poked(hash string, now time.Time, window time.Duration) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	at, found := s.at[hash]
	return found && window > 0 && now.Sub(at) < window
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
	s.aclChanged = ceilSecond(now)
	s.reminted = map[string]remint{}
}

// StampGrant records that the grant of the reader with the given email hash
// changed at now: their signatures issued before it are re-signed on their
// next request, as for the access table. It forgets the stamps older than
// keep, the longest a signature lasts.
func (s *Set) StampGrant(hash string, now time.Time, keep time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for other, when := range s.grants {
		if now.Sub(when) >= keep {
			delete(s.grants, other)
		}
	}
	s.grants[hash] = now
}

// Reminted records that the signature carrying the HMAC signature was
// re-signed at now, under the access table and the grants as they are, and
// runs out at expires, and forgets those that ran out by now.
func (s *Set) Reminted(signature string, expires, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for other, re := range s.reminted {
		if !now.Before(re.ends) {
			delete(s.reminted, other)
		}
	}
	s.reminted[signature] = remint{at: now, ends: expires}
}

// ACLChanged is when the access table last changed, rounded up to the
// second, or zero when it has not since the Set was made.
func (s *Set) ACLChanged() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.aclChanged
}

// Wants says what asks the signature of the reader with the given email hash,
// carrying the HMAC signature and issued at issued, to renew at now whatever
// its age: "poke" when the reader was poked within window before now and
// after it was issued, "acl" when the access table changed after it was
// issued and "grant" when the reader's grant did, unless it was re-signed
// since, nothing otherwise. It reads nothing
// but its arguments. Moments are kept to the second, the resolution Expires
// has, and rounded up: a signature minted in the same second as the edit
// reads as issued before it, so one minted under the old state is never
// missed, at the cost of renewing once more one minted in that second after
// it.
func (s *Set) Wants(hash, signature string, issued, now time.Time, window time.Duration) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	at, found := s.at[hash]
	if found && window > 0 && now.Sub(at) < window && issued.Before(at) {
		return "poke"
	}
	// StampACL forgets every re-sign, so one kept came after the table's stamp
	re, resigned := s.reminted[signature]
	cause, stamp := "acl", s.aclChanged
	edited := s.grants[hash]
	if !edited.IsZero() && ceilSecond(edited).After(stamp) {
		cause, stamp = "grant", ceilSecond(edited)
		resigned = resigned && !re.at.Before(edited)
	}
	if issued.Before(stamp) && !resigned {
		return cause
	}
	return ""
}
