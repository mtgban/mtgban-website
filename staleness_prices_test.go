package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestStrayPricesAnnounceOnceUntilClear(t *testing.T) {
	var notes []string
	prevNotify, prevStray := strayNotify, strayPriceRows
	t.Cleanup(func() { strayNotify, strayPriceRows = prevNotify, prevStray })
	strayNotify = func(kind, msg string) { notes = append(notes, kind+": "+msg) }
	count := int64(3)
	strayPriceRows = func(context.Context) (int64, error) { return count, nil }

	now := time.Now()
	checkStrayPrices(now)
	checkStrayPrices(now.Add(time.Hour))
	if len(notes) != 1 || !strings.Contains(notes[0], "3 price rows") {
		t.Fatalf("notes = %q, want one alarm naming 3 rows", notes)
	}
	count = 0
	checkStrayPrices(now.Add(2 * time.Hour))
	count = 1
	checkStrayPrices(now.Add(3 * time.Hour))
	if len(notes) != 3 {
		t.Fatalf("notes = %q, want the clear and the new alarm announced", notes)
	}
}
