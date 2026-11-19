package dailycap

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	perName   = 1000
	errorRows = 5
)

var noon = time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)

// The sketch never says less than an address added, however many share it.
func TestNeverUndercounts(t *testing.T) {
	a := New(perName, errorRows).For(noon)
	const addresses = 200_000
	for i := range addresses {
		if got := a.Take(fmt.Sprintf("10.%d.%d.%d", i>>16, i>>8&255, i&255), "ui.load", 1); got != 1 {
			t.Fatalf("address %d refused its first count", i)
		}
	}
	heavy := "192.0.2.1"
	total := int64(0)
	for range 2 * perName {
		total += a.Take(heavy, "ui.load", 1)
	}
	if total > perName {
		t.Errorf("one address added %d, past the cap of %d", total, perName)
	}
	if total < perName/2 {
		t.Errorf("one address added only %d of %d with %d others in the sketch", total, perName, addresses)
	}
}

// Calls at once from one address stay near the cap: each can pass it by at most its own count.
func TestHoldsUnderConcurrentTakes(t *testing.T) {
	a := New(perName, errorRows).For(noon)
	const workers = 8
	var total atomic.Int64
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for range perName {
				total.Add(a.Take("192.0.2.1", "ui.load", 1))
			}
		})
	}
	wg.Wait()
	if got := total.Load(); got < perName || got > perName+workers {
		t.Errorf("added %d, want %d to %d", got, perName, perName+workers)
	}
}

// A new UTC day starts a new Day; the same day keeps it.
func TestTurnsAtMidnightUTC(t *testing.T) {
	c := New(perName, errorRows)
	late := time.Date(2026, 11, 11, 23, 59, 59, 0, time.UTC)
	a := c.For(late)
	if c.For(late.Add(-time.Hour)) != a {
		t.Error("the same UTC day started a new sketch")
	}
	b := c.For(late.Add(2 * time.Second))
	if b == a || b.day != a.day+1 {
		t.Errorf("midnight UTC kept day %d, want %d", b.day, a.day+1)
	}
	// 8 PM in New York on the 11th is already the 12th in UTC
	if c.For(time.Date(2026, 11, 11, 20, 0, 1, 0, time.FixedZone("EST", -5*3600))) != b {
		t.Error("a time in another zone was not read as UTC")
	}
}

// The budget is per address and per UTC day, and a repeat never spends it.
func TestErrorRowBudget(t *testing.T) {
	c := New(perName, errorRows)
	a := c.For(noon)
	for i := range errorRows {
		if !a.MayAddErrorRow("192.0.2.1", "desktop", "build", "navbar.js", "TypeError", i) {
			t.Fatalf("row %d refused within the budget", i)
		}
	}
	for i := range 100 {
		script := fmt.Sprintf("script-%d.js", i)
		if a.MayAddErrorRow("192.0.2.1", "desktop", "build", script, "RangeError", 7) {
			t.Fatalf("a new row on %s passed the budget", script)
		}
	}
	for range 3 {
		if !a.MayAddErrorRow("192.0.2.1", "desktop", "build", "navbar.js", "TypeError", 0) {
			t.Fatal("a row the address started was refused")
		}
	}
	if !a.MayAddErrorRow("192.0.2.2", "desktop", "build", "navbar.js", "RangeError", 7) {
		t.Error("another address was refused its first row")
	}
	if !c.For(noon.AddDate(0, 0, 1)).MayAddErrorRow("192.0.2.1", "desktop", "build", "navbar.js", "RangeError", 7) {
		t.Error("the next day's sketch refused the address")
	}
}
