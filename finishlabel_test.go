package main

import (
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

func TestFinishLabel(t *testing.T) {
	tests := []struct {
		name   string
		finish string
		want   string
	}{
		// The three the Foil and Etched flags already describe, plus the two
		// spellings a game uses for a plain printing.
		{"unset", "", ""},
		{"shared nonfoil", mtgmatcher.FinishNonfoil, ""},
		{"shared foil", mtgmatcher.FinishFoil, ""},
		{"shared etched", mtgmatcher.FinishEtched, ""},
		{"a game's plain printing", "normal", ""},

		// The foil family, whose one lowercase word splits on the suffix.
		{"flesh and blood rainbow", "rainbowfoil", "Rainbow Foil"},
		{"flesh and blood cold", "coldfoil", "Cold Foil"},
		{"lorcana holo", "holofoil", "Holo Foil"},

		// The ones no rule gets right.
		{"yugioh print run", "1stedition", "1st Edition"},
		{"lorcana pillars", "rainbowpillars", "Rainbow Pillars"},

		// A name that is neither foil-suffixed nor irregular.
		{"lorcana silver", "silver", "Silver"},
		{"yugioh unlimited", "unlimited", "Unlimited"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			co := &mtgmatcher.CardObject{}
			co.Finish = test.finish
			got := finishLabel(co)
			if got != test.want {
				t.Errorf("finishLabel(%q) = %q, want %q", test.finish, got, test.want)
			}
		})
	}
}

// Magic's CanonicalFinish only ever answers with the three shared names — its
// foil types are promo types, not finishes — so nothing it stores should reach
// the naming rule and change a title that reads correctly today.
func TestFinishLabelLeavesMagicAlone(t *testing.T) {
	uuids := mtgmatcher.GetUUIDs()
	if len(uuids) == 0 {
		t.Skip("no datastore loaded")
	}

	named := map[string]string{}
	for _, uuid := range uuids {
		co, err := mtgmatcher.GetUUID(uuid)
		if err != nil {
			continue
		}
		label := finishLabel(co)
		if label != "" {
			named[co.Finish] = label
		}
	}
	if len(named) != 0 {
		t.Errorf("magic finishes reached the naming rule: %v", named)
	}
}
