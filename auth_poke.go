package main

import (
	"sync"
	"time"
)

// pokeSet holds what makes a signature stale before its age does: when each
// poked reader (an email hash Patreon's webhook named or a grant edit changed)
// was poked, and when the access table last changed. A signature issued before
// either renews on its next request; one issued after is left alone, so each of
// a reader's devices renews once. It lives in memory: a poke costs a request no
// database work, and one a restarting process missed is caught by the age
// window. A poke lasts after_days, when the window would have renewed the
// reader anyway, and the next poke sweeps the ones that lapsed; the table's
// moment lasts as long as the process. Both are kept to the second, the
// resolution a signature's Expires has, so a renewal in their second is issued
// at them rather than before them.
type pokeSet struct {
	mu         sync.RWMutex
	at         map[string]time.Time // userstate.HashEmail of the reader -> when poked
	aclChanged time.Time
}

// Pokes is the set this process keeps. The webhook fills it, directly on the
// site that received the delivery and through the patreon_poke NOTIFY on the
// others; a grant edit pokes its grantee and an access table edit stamps it
// (access_notify.go, common.go).
var Pokes = newPokeSet()

func newPokeSet() *pokeSet {
	return &pokeSet{at: map[string]time.Time{}}
}

// pokeWindow is how long a poke lasts.
func pokeWindow() time.Duration {
	return Infrastructure().PatreonRenewal.After()
}

// poke marks the reader with the given email hash as poked now, and drops the
// pokes that have lapsed.
func (p *pokeSet) poke(hash string) {
	now := time.Now()
	window := pokeWindow()
	p.mu.Lock()
	defer p.mu.Unlock()
	for other, at := range p.at {
		if now.Sub(at) >= window {
			delete(p.at, other)
		}
	}
	p.at[hash] = now.Truncate(time.Second)
}

// poked says whether the reader with the given email hash was poked within
// the window.
func (p *pokeSet) poked(hash string) bool {
	window := pokeWindow()
	p.mu.RLock()
	defer p.mu.RUnlock()
	at, found := p.at[hash]
	return found && time.Since(at) < window
}

// stampACL records that the access table changed at now. Every signature
// issued before it renews on its next request, since the page flags it carries
// were baked in from the old table.
func (p *pokeSet) stampACL(now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.aclChanged = now.Truncate(time.Second)
}

// wants says what asks the signature of the reader with the given email hash,
// issued at issued, to renew now whatever its age: "poke" when the reader was
// poked within the window after it was issued, "acl" when the access table
// changed after it was issued, nothing otherwise. Moments are kept to the
// second, the resolution Expires has: a signature minted in the same second as
// the edit reads as issued at it and waits for its age, and one renewed in that
// second is not renewed again.
func (p *pokeSet) wants(hash string, issued time.Time) string {
	window := pokeWindow()
	p.mu.RLock()
	defer p.mu.RUnlock()
	at, found := p.at[hash]
	switch {
	case found && time.Since(at) < window && issued.Before(at):
		return "poke"
	case issued.Before(p.aclChanged):
		return "acl"
	}
	return ""
}
