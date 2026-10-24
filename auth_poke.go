package main

import (
	"sync"
	"time"
)

// pokeSet holds the readers whose signature is stale before its age says so:
// the email hashes Patreon's webhook named, each with the moment it did. A
// signature issued before its reader's poke renews on its next request; one
// issued after is left alone, so each of a reader's devices renews once. It
// lives in memory: a poke costs a request no database work, and one a
// restarting process missed is caught by the age window. A poke lasts
// after_days, when the window would have renewed the reader anyway, and the
// next poke sweeps the ones that lapsed. The moment is kept to the second, the
// resolution a signature's Expires has, so a renewal in the poke's second is
// issued at it rather than before it.
type pokeSet struct {
	mu sync.RWMutex
	at map[string]time.Time // userstate.HashEmail of the reader -> when poked
}

// Pokes is the set this process keeps. The webhook fills it, directly on the
// site that received the delivery and through the patreon_poke NOTIFY on the
// others.
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

// wants says what asks the signature of the reader with the given email hash,
// issued at issued, to renew now whatever its age: "poke" when the reader was
// poked within the window after it was issued, nothing otherwise. The
// comparison has no slack beyond the second, so a signature minted just before
// the poke does not miss it.
func (p *pokeSet) wants(hash string, issued time.Time) string {
	window := pokeWindow()
	p.mu.RLock()
	defer p.mu.RUnlock()
	at, found := p.at[hash]
	if found && time.Since(at) < window && issued.Before(at) {
		return "poke"
	}
	return ""
}
