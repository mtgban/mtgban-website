package main

import (
	"context"
	"strings"
	"testing"
)

func TestStrayPricesSayAtLeastAtTheBound(t *testing.T) {
	var notes []string
	prevNotify, prevRows, prevLimit := strayNotify, strayPriceRows, strayRowLimit
	t.Cleanup(func() { strayNotify, strayPriceRows, strayRowLimit = prevNotify, prevRows, prevLimit })
	strayNotify = func(kind, msg string) { notes = append(notes, kind+": "+msg) }
	strayRowLimit = 50
	strayPriceRows = func(context.Context) (int64, error) { return 50, nil }
	prevState := staleAlarmState.strayPrices
	t.Cleanup(func() { staleAlarmState.strayPrices = prevState })
	staleAlarmState.strayPrices = false

	checkStrayPrices()
	if len(notes) != 1 || !strings.Contains(notes[0], "at least 50 price rows") {
		t.Fatalf("notes = %q, want one alarm saying at least 50", notes)
	}
}

func TestStrayPricesAnnounceOnceUntilClear(t *testing.T) {
	var notes []string
	prevNotify, prevStray := strayNotify, strayPriceRows
	t.Cleanup(func() { strayNotify, strayPriceRows = prevNotify, prevStray })
	strayNotify = func(kind, msg string) { notes = append(notes, kind+": "+msg) }
	count := int64(3)
	strayPriceRows = func(context.Context) (int64, error) { return count, nil }

	checkStrayPrices()
	checkStrayPrices()
	if len(notes) != 1 || !strings.Contains(notes[0], "3 price rows") {
		t.Fatalf("notes = %q, want one alarm naming 3 rows", notes)
	}
	count = 0
	checkStrayPrices()
	count = 1
	checkStrayPrices()
	if len(notes) != 3 {
		t.Fatalf("notes = %q, want the clear and the new alarm announced", notes)
	}
}
