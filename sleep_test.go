package main

import (
	"slices"
	"testing"
)

func TestSleepersLayoutSkipsPlaytest(t *testing.T) {
	skipWithoutDatastore(t)
	playtest := backend().GetUUIDsInSet("CMB1")[0]
	plain := somePlainCardUUIDs(t, 2)
	registerTestSeller(t, "TCGLow", append(plain, playtest))

	sleepers, err := sleepersLayout(backend(), map[string]int{playtest: 100, plain[0]: 50, plain[1]: 2})
	if err != nil {
		t.Fatal(err)
	}
	for _, cardIDs := range sleepers {
		if slices.Contains(cardIDs, playtest) {
			t.Errorf("playtest card %s listed among the sleepers", playtest)
		}
	}
}
