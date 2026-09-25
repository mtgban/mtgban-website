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
		// The three the Foil and Etched flags already describe.
		{"unset", "", ""},
		{"shared nonfoil", mtgmatcher.FinishNonfoil, ""},
		{"shared foil", mtgmatcher.FinishFoil, ""},
		{"shared etched", mtgmatcher.FinishEtched, ""},

		// Every other finish, spelled as TCGplayer names the printing.
		{"flesh and blood rainbow", "rainbowfoil", "Rainbow Foil"},
		{"flesh and blood run", "1steditionrainbowfoil", "1st Edition Rainbow Foil"},
		{"lorcana cold", "coldfoil", "Cold Foil"},
		{"gundam holo", "holofoil", "Holofoil"},
		{"pokemon reverse", "reverseholofoil", "Reverse Holofoil"},
		{"yugioh print run", "1stedition", "1st Edition"},
		{"yugioh unlimited", "unlimited", "Unlimited"},

		// A name the table has no row for keeps the rule.
		{"a finish added since", "galaxyfoil", "Galaxy Foil"},
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

// Magic's only finishes are nonfoil, foil and etched — its foil types are
// promo types, not finishes — so nothing it stores should reach the naming
// rule and change a title that reads correctly today.
func TestFinishLabelLeavesMagicAlone(t *testing.T) {
	uuids := backend().GetUUIDs()
	if len(uuids) == 0 {
		t.Skip("no datastore loaded")
	}

	named := map[string]string{}
	for _, uuid := range uuids {
		co, err := backend().GetUUID(uuid)
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
