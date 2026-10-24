package main

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/internal/infrastructure"
	"github.com/mtgban/mtgban-website/userstate"
)

// freshPokes gives the test a poke set of its own, and puts back the one it
// found.
func freshPokes(t *testing.T) *pokeSet {
	t.Helper()
	saved := Pokes
	t.Cleanup(func() { Pokes = saved })
	Pokes = newPokeSet()
	return Pokes
}

// A poke marks its reader alone, and asks for the signatures issued before it:
// one issued after, as a renewal mints, is left alone.
func TestPokeSetAsksForWhatWasIssuedBeforeThePoke(t *testing.T) {
	renewalConfig(t, renewalBlock, "client-id")
	pokes := newPokeSet()
	reader, other := userstate.HashEmail("reader@example.com"), userstate.HashEmail("other@example.com")

	if pokes.poked(reader) || pokes.wants(reader, time.Now().Add(-day)) != "" {
		t.Error("a reader nobody poked is poked")
	}
	pokes.poke(reader)
	if !pokes.poked(reader) || pokes.poked(other) {
		t.Errorf("after one poke: reader %v, other %v; want the reader alone", pokes.poked(reader), pokes.poked(other))
	}
	at := pokes.at[reader]
	if !at.Equal(at.Truncate(time.Second)) || time.Since(at) > time.Minute {
		t.Errorf("poked at %v, want now to the second", at)
	}

	for _, tc := range []struct {
		name   string
		issued time.Time
		want   string
	}{
		{"issued a day before the poke", at.Add(-day), "poke"},
		{"issued a nanosecond before the poke", at.Add(-time.Nanosecond), "poke"},
		{"issued in the poke's second", at, ""},
		{"issued after the poke", at.Add(time.Minute), ""},
	} {
		got := pokes.wants(reader, tc.issued)
		if got != tc.want {
			t.Errorf("%s: wants %q, want %q", tc.name, got, tc.want)
		}
	}
	if pokes.wants(other, at.Add(-day)) != "" {
		t.Error("a poke asks for another reader's signature")
	}

	// A second poke is the same mark
	pokes.poke(reader)
	if len(pokes.at) != 1 || !pokes.poked(reader) {
		t.Errorf("a repeated poke left %d entries, poked %v; want one entry", len(pokes.at), pokes.poked(reader))
	}
}

// A poke lasts after_days and no longer: past that the age check would have
// renewed the reader anyway, and the next poke drops the entry.
func TestPokeSetAgesOutAfterTheWindow(t *testing.T) {
	renewalConfig(t, renewalBlock, "client-id")
	pokes := newPokeSet()
	lapsed, lasting := userstate.HashEmail("lapsed@example.com"), userstate.HashEmail("lasting@example.com")

	pokes.at[lapsed] = time.Now().Add(-8*day - time.Minute)
	pokes.at[lasting] = time.Now().Add(-8*day + time.Minute)
	if pokes.poked(lapsed) || !pokes.poked(lasting) {
		t.Errorf("lapsed poked %v, lasting poked %v; want only the one inside after_days", pokes.poked(lapsed), pokes.poked(lasting))
	}
	if pokes.wants(lapsed, time.Now().Add(-30*day)) != "" || pokes.wants(lasting, time.Now().Add(-30*day)) != "poke" {
		t.Error("a lapsed poke still asks for its reader's old signature, or a lasting one does not")
	}
	if len(pokes.at) != 2 {
		t.Errorf("a read dropped an entry: %d left, want 2", len(pokes.at))
	}

	pokes.poke(userstate.HashEmail("new@example.com"))
	_, kept := pokes.at[lapsed]
	if kept || len(pokes.at) != 2 {
		t.Errorf("after a poke the lapsed entry is kept: %v with %d entries, want it swept and 2 left", kept, len(pokes.at))
	}
}

// With renewal off there is no window, so nothing stays poked.
func TestPokeSetKeepsNothingWithoutAfterDays(t *testing.T) {
	renewalConfig(t, infrastructure.PatreonRenewal{GraceDays: 3}, "client-id")
	pokes := newPokeSet()
	hash := userstate.HashEmail("reader@example.com")

	pokes.poke(hash)
	if pokes.poked(hash) || pokes.wants(hash, time.Now().Add(-day)) != "" {
		t.Error("a poke is kept while after_days is 0")
	}
}

// Readers poke and read from every request and the listener at once.
func TestPokeSetIsSafeToShare(t *testing.T) {
	renewalConfig(t, renewalBlock, "client-id")
	pokes := newPokeSet()

	var wg sync.WaitGroup
	for i := range 8 {
		hash := userstate.HashEmail(fmt.Sprintf("reader-%d@example.com", i))
		wg.Go(func() {
			for range 200 {
				pokes.poke(hash)
				pokes.poked(hash)
				pokes.wants(hash, time.Now().Add(-day))
			}
		})
	}
	wg.Wait()
	if len(pokes.at) != 8 {
		t.Errorf("%d entries after eight readers poked, want 8", len(pokes.at))
	}
}

// A reader's signature wants renewing when it was issued before the reader's
// poke, or before the access table changed, and says which asked.
func TestPokeSetWantsAStaleOrPokedReader(t *testing.T) {
	renewalConfig(t, renewalBlock, "client-id")
	hash := userstate.HashEmail("reader@example.com")
	stamp := time.Now().Add(-day).Truncate(time.Second)

	pokes := newPokeSet()
	if pokes.wants(hash, time.Now().Add(-100*day)) != "" {
		t.Error("a reader nobody poked wants renewing with no stamp set")
	}

	pokes.stampACL(stamp)
	for _, tc := range []struct {
		name   string
		issued time.Time
		want   string
	}{
		{"issued before the stamp", stamp.Add(-time.Hour), "acl"},
		{"issued a nanosecond before the stamp", stamp.Add(-time.Nanosecond), "acl"},
		{"issued at the stamp", stamp, ""},
		{"issued after the stamp", stamp.Add(time.Hour), ""},
		{"minted just now", time.Now(), ""},
		{"issued long before the stamp", stamp.Add(-30 * day), "acl"},
	} {
		got := pokes.wants(hash, tc.issued)
		if got != tc.want {
			t.Errorf("%s: wants %q, want %q", tc.name, got, tc.want)
		}
	}

	// A poke asks for its reader's signatures issued before it, and is the
	// cause named when the stamp asks for them too
	pokes.poke(hash)
	if pokes.wants(hash, time.Now().Add(-time.Minute)) != "poke" || pokes.wants(hash, stamp.Add(-time.Hour)) != "poke" {
		t.Error("a poke does not ask for the reader's signatures issued before it")
	}
	if pokes.wants(hash, time.Now().Add(time.Minute)) != "" || pokes.wants(userstate.HashEmail("other@example.com"), stamp.Add(time.Hour)) != "" {
		t.Error("a poke asks for a signature issued after it, or for another reader's")
	}
	if pokes.wants(userstate.HashEmail("other@example.com"), stamp.Add(-time.Hour)) != "acl" {
		t.Error("the stamp stopped asking for another reader's old signature")
	}
}

// The stamp does not age out: a signature issued before it is stale however
// old it is, and the next stamp replaces the last.
func TestPokeSetStampDoesNotAge(t *testing.T) {
	renewalConfig(t, renewalBlock, "client-id")
	hash := userstate.HashEmail("reader@example.com")
	pokes := newPokeSet()

	pokes.stampACL(time.Now().Add(-100 * day))
	if pokes.wants(hash, time.Now().Add(-101*day)) != "acl" || pokes.wants(hash, time.Now().Add(-99*day)) != "" {
		t.Error("a stamp of 100 days ago does not ask for exactly the signatures issued before it")
	}

	later := time.Now().Add(-time.Hour).Truncate(time.Second)
	pokes.stampACL(later)
	if pokes.wants(hash, later.Add(-time.Minute)) != "acl" || pokes.wants(hash, later.Add(time.Minute)) != "" {
		t.Error("the next stamp does not replace the last")
	}

	// A poke sweeps lapsed pokes and leaves the stamp
	pokes.poke(userstate.HashEmail("other@example.com"))
	if pokes.wants(hash, later.Add(-time.Minute)) != "acl" {
		t.Error("a poke cleared the stamp")
	}
}

// With renewal off there is no age window, but the stamp is what it was: it
// has no window of its own.
func TestPokeSetStampNeedsNoWindow(t *testing.T) {
	renewalConfig(t, infrastructure.PatreonRenewal{GraceDays: 3}, "client-id")
	pokes := newPokeSet()
	pokes.stampACL(time.Now())

	if pokes.wants(userstate.HashEmail("reader@example.com"), time.Now().Add(-day)) != "acl" {
		t.Error("the stamp does not ask for an older signature without after_days")
	}
}
