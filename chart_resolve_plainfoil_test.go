package main

import (
	"os"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// No plain printing may be counted among a card's foil finishes.
//
// The pairing downstream is positional, so one plain printing sitting in the
// sorted list shifts every finish after it by a place. Flesh and Blood is
// where this bites: it keys a printing by its print run and treatment
// together, so a card carries "1steditionnormal" and "unlimitededitionnormal"
// beside the foils, and the uuid comparison that used to guard this only ever
// caught the one the "nonfoil" key happened to point at - 4737 of 17547
// printings kept a plain 1st Edition among their foils.
//
// The datastore is the real one or the test does not run: the shape being
// checked is what the loader builds, and a fixture would only re-assert what
// it was written from.
func TestNoPlainPrintingCountsAsFoil(t *testing.T) {
	path := os.Getenv("FLESHANDBLOOD_PATH")
	if path == "" {
		t.Skip("FLESHANDBLOOD_PATH unset")
	}

	saved := Config.Game
	Config.Game = "fleshandblood"
	t.Cleanup(func() {
		Config.Game = saved
		if err := loadDatastore(Config.DatastorePath); err != nil {
			t.Logf("restoring the datastore failed: %v", err)
		}
	})

	if err := loadDatastore(path); err != nil {
		t.Skipf("loading %s: %v", path, err)
	}

	var checked, withExtras, offenders int
	var sample string
	for _, uuid := range mtgmatcher.GetUUIDs() {
		co, err := mtgmatcher.GetUUID(uuid)
		if err != nil || co.Sealed {
			continue
		}
		checked++
		extras := extraFoilFinishes(co, mtgmatcher.GetUUID)
		if len(extras) > 0 {
			withExtras++
		}
		for _, finish := range extras {
			if !strings.HasSuffix(finish, "normal") && finish != mtgmatcher.FinishNonfoil {
				continue
			}
			offenders++
			if sample == "" {
				sample = co.Name + " " + co.SetCode + " #" + co.Number + " " + strings.Join(extras, ",")
			}
			break
		}
	}

	if checked == 0 {
		t.Fatal("the datastore loaded no printings")
	}
	if withExtras == 0 {
		t.Fatalf("no printing of %d carries an extra foil finish; the check proves nothing", checked)
	}
	if offenders != 0 {
		t.Errorf("%d of %d printings count a plain printing among their foils, e.g. %s",
			offenders, checked, sample)
	}
}
