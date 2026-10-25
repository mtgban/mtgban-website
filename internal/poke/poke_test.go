package poke

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

const (
	day    = 24 * time.Hour
	window = 8 * day
)

// A poke marks its reader alone, and asks for the signatures issued before it:
// one issued after, as a renewal mints, is left alone.
func TestPokeAsksForWhatWasIssuedBeforeIt(t *testing.T) {
	set := New()
	reader, other := "reader", "other"

	if set.Poked(reader, time.Now(), window) || set.Wants(reader, "", time.Now().Add(-day), time.Now(), window) != "" {
		t.Error("a reader nobody poked is poked")
	}
	set.Poke(reader, time.Now(), window)
	if !set.Poked(reader, time.Now(), window) || set.Poked(other, time.Now(), window) || set.Len() != 1 {
		t.Errorf("after one poke: reader %v, other %v, %d entries; want the reader alone", set.Poked(reader, time.Now(), window), set.Poked(other, time.Now(), window), set.Len())
	}
	at := set.at[reader]
	if !at.Equal(at.Truncate(time.Second)) || !at.After(time.Now().Add(-time.Second)) || time.Until(at) > time.Second {
		t.Errorf("poked at %v, want now rounded up to the second", at)
	}

	for _, tc := range []struct {
		name   string
		issued time.Time
		want   string
	}{
		{"issued a day before the poke", at.Add(-day), "poke"},
		{"issued a nanosecond before the poke", at.Add(-time.Nanosecond), "poke"},
		{"issued in the second before the poke's, which the poke rounded up", at.Add(-time.Second), "poke"},
		{"issued at the poke", at, ""},
		{"issued after the poke", at.Add(time.Minute), ""},
	} {
		got := set.Wants(reader, "", tc.issued, time.Now(), window)
		if got != tc.want {
			t.Errorf("%s: wants %q, want %q", tc.name, got, tc.want)
		}
	}
	if set.Wants(other, "", at.Add(-day), time.Now(), window) != "" {
		t.Error("a poke asks for another reader's signature")
	}

	// A second poke is the same mark, moved to now
	set.Poke(reader, time.Now(), window)
	if set.Len() != 1 || !set.Poked(reader, time.Now(), window) {
		t.Errorf("a repeated poke left %d entries, poked %v; want one entry", set.Len(), set.Poked(reader, time.Now(), window))
	}
}

// A poke lasts the window and no longer: past that the age check would have
// renewed the reader anyway, and the next poke drops the entry.
func TestPokeAgesOutAfterTheWindow(t *testing.T) {
	set := New()
	lapsed, lasting := "lapsed", "lasting"

	set.Poke(lapsed, time.Now().Add(-window-time.Minute), window)
	set.Poke(lasting, time.Now().Add(-window+time.Minute), window)
	if set.Poked(lapsed, time.Now(), window) || !set.Poked(lasting, time.Now(), window) {
		t.Errorf("lapsed poked %v, lasting poked %v; want only the one inside the window", set.Poked(lapsed, time.Now(), window), set.Poked(lasting, time.Now(), window))
	}
	if set.Wants(lapsed, "", time.Now().Add(-30*day), time.Now(), window) != "" || set.Wants(lasting, "", time.Now().Add(-30*day), time.Now(), window) != "poke" {
		t.Error("a lapsed poke still asks for its reader's old signature, or a lasting one does not")
	}
	if set.Len() != 2 {
		t.Errorf("a read dropped an entry: %d left, want 2", set.Len())
	}

	set.Poke("new", time.Now(), window)
	_, kept := set.at[lapsed]
	if kept || set.Len() != 2 {
		t.Errorf("after a poke the lapsed entry is kept: %v with %d entries, want it swept and 2 left", kept, set.Len())
	}
}

// With no window nothing stays poked.
func TestPokeKeepsNothingWithoutAWindow(t *testing.T) {
	set := New()
	set.Poke("reader", time.Now(), 0)
	if set.Poked("reader", time.Now(), 0) || set.Wants("reader", "", time.Now().Add(-day), time.Now(), 0) != "" {
		t.Error("a poke is kept with no window")
	}
}

// Readers poke and read from every request and the listener at once.
func TestSetIsSafeToShare(t *testing.T) {
	set := New()

	var wg sync.WaitGroup
	for i := range 8 {
		hash := fmt.Sprintf("reader-%d", i)
		wg.Go(func() {
			for range 200 {
				set.Poke(hash, time.Now(), window)
				set.Poked(hash, time.Now(), window)
				set.Wants(hash, "", time.Now().Add(-day), time.Now(), window)
				set.Reminted(hash, time.Now().Add(day), time.Now())
				set.StampACL(time.Now())
				set.ACLChanged()
			}
		})
	}
	wg.Wait()
	if set.Len() != 8 {
		t.Errorf("%d entries after eight readers poked, want 8", set.Len())
	}
}

// A reader's signature wants renewing when it was issued before the reader's
// poke, or before the access table changed, and says which asked.
func TestWantsAStaleOrPokedReader(t *testing.T) {
	stamp := time.Now().Add(-day).Truncate(time.Second)
	set := New()
	if set.Wants("reader", "", time.Now().Add(-100*day), time.Now(), window) != "" || !set.ACLChanged().IsZero() {
		t.Error("a reader nobody poked wants renewing with no stamp set")
	}

	set.StampACL(stamp.Add(400 * time.Millisecond))
	if !set.ACLChanged().Equal(stamp.Add(time.Second)) {
		t.Errorf("stamped %v, want %v, rounded up", set.ACLChanged(), stamp.Add(time.Second))
	}
	stamp = set.ACLChanged()
	for _, tc := range []struct {
		name   string
		issued time.Time
		want   string
	}{
		{"issued before the stamp", stamp.Add(-time.Hour), "acl"},
		{"issued a nanosecond before the stamp", stamp.Add(-time.Nanosecond), "acl"},
		{"minted in the stamp's second, before the edit", stamp.Add(-time.Second), "acl"},
		{"issued at the stamp", stamp, ""},
		{"issued after the stamp", stamp.Add(time.Hour), ""},
		{"minted just now", time.Now(), ""},
		{"issued long before the stamp", stamp.Add(-30 * day), "acl"},
	} {
		got := set.Wants("reader", "", tc.issued, time.Now(), window)
		if got != tc.want {
			t.Errorf("%s: wants %q, want %q", tc.name, got, tc.want)
		}
	}

	// A poke asks for its reader's signatures issued before it, and is the
	// cause named when the stamp asks for them too
	set.Poke("reader", time.Now(), window)
	if set.Wants("reader", "", time.Now().Add(-time.Minute), time.Now(), window) != "poke" || set.Wants("reader", "", stamp.Add(-time.Hour), time.Now(), window) != "poke" {
		t.Error("a poke does not ask for the reader's signatures issued before it")
	}
	if set.Wants("reader", "", time.Now().Add(time.Minute), time.Now(), window) != "" || set.Wants("other", "", stamp.Add(time.Hour), time.Now(), window) != "" {
		t.Error("a poke asks for a signature issued after it, or for another reader's")
	}
	if set.Wants("other", "", stamp.Add(-time.Hour), time.Now(), window) != "acl" {
		t.Error("the stamp stopped asking for another reader's old signature")
	}
}

// The stamp does not age out: a signature issued before it is stale however
// old it is, and the next stamp replaces the last.
func TestStampDoesNotAge(t *testing.T) {
	set := New()

	set.StampACL(time.Now().Add(-100 * day))
	if set.Wants("reader", "", time.Now().Add(-101*day), time.Now(), window) != "acl" || set.Wants("reader", "", time.Now().Add(-99*day), time.Now(), window) != "" {
		t.Error("a stamp of 100 days ago does not ask for exactly the signatures issued before it")
	}

	later := time.Now().Add(-time.Hour).Truncate(time.Second)
	set.StampACL(later)
	later = set.ACLChanged()
	if set.Wants("reader", "", later.Add(-time.Minute), time.Now(), window) != "acl" || set.Wants("reader", "", later.Add(time.Minute), time.Now(), window) != "" {
		t.Error("the next stamp does not replace the last")
	}

	// A poke sweeps lapsed pokes and leaves the stamp
	set.Poke("other", time.Now(), window)
	if set.Wants("reader", "", later.Add(-time.Minute), time.Now(), window) != "acl" || !set.ACLChanged().Equal(later) {
		t.Error("a poke cleared the stamp")
	}
}

// The stamp has no window of its own: with none for pokes it asks the same.
func TestStampNeedsNoWindow(t *testing.T) {
	set := New()
	set.StampACL(time.Now())
	if set.Wants("reader", "", time.Now().Add(-day), time.Now(), 0) != "acl" {
		t.Error("the stamp does not ask for an older signature without a window")
	}
}

// A signature re-signed under the table now is not asked for again, though
// its Expires reads as issued before the stamp, until the next stamp; one
// that ran out is forgotten at the next re-sign.
func TestStampSkipsWhatWasReminted(t *testing.T) {
	set := New()
	set.StampACL(time.Now())
	issued := time.Now().Add(-day)

	set.Reminted("fresh", time.Now().Add(10*day), time.Now())
	if set.Wants("reader", "fresh", issued, time.Now(), window) != "" || set.Wants("reader", "stale", issued, time.Now(), window) != "acl" {
		t.Error("the stamp asks for a re-signed signature, or not for one that was not")
	}

	set.Reminted("ran-out", time.Now().Add(-time.Minute), time.Now().Add(-2*time.Minute))
	set.Reminted("another", time.Now().Add(10*day), time.Now())
	if _, kept := set.reminted["ran-out"]; kept {
		t.Error("a re-signed signature that ran out was kept")
	}

	set.StampACL(time.Now().Add(time.Second))
	if set.Wants("reader", "fresh", issued, time.Now(), window) != "acl" {
		t.Error("a signature re-signed under the last table is not asked for after the next stamp")
	}
}
