package main

import (
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

func plstFoilTestCard(setCode string, foil, etched bool) *mtgmatcher.CardObject {
	co := &mtgmatcher.CardObject{Foil: foil, Etched: etched}
	co.SetCode = setCode
	return co
}

func TestNoPLSTFoilSkipsOnlyPLSTFoilAndEtched(t *testing.T) {
	tests := []struct {
		name     string
		co       *mtgmatcher.CardObject
		wantSkip bool
	}{
		{"PLST foil is skipped", plstFoilTestCard("PLST", true, false), true},
		{"PLST etched is skipped", plstFoilTestCard("PLST", false, true), true},
		{"PLST nonfoil is kept", plstFoilTestCard("PLST", false, false), false},
		{"a foil outside PLST is kept", plstFoilTestCard("NEO", true, false), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, skip := noPLSTFoil(tt.co)
			if skip != tt.wantSkip {
				t.Errorf("noPLSTFoil(%+v) skip = %v, want %v", tt.co, skip, tt.wantSkip)
			}
		})
	}
}

func TestIsCardmarketMarketOnlyMatchesMarketsOwnBuckets(t *testing.T) {
	tests := []struct {
		shorthand string
		want      bool
	}{
		{"MKM", true},
		{"MKMPS", true},
		{"MKMIndex", false},
		{"MKMSealed", false},
		{"MKMTrend", false},
		{"TCGDirect", false},
	}
	for _, tt := range tests {
		if got := isCardmarketMarket(tt.shorthand); got != tt.want {
			t.Errorf("isCardmarketMarket(%q) = %v, want %v", tt.shorthand, got, tt.want)
		}
	}
}
