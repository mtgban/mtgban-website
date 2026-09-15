package main

import (
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// promoTypeCards finds one real card whose PromoTypes carries a token (the
// common case - Prerelease, Bundle, Showcase, and most of the game's
// 130-odd promo types), and one whose alt-foil-style promo type shows as a
// Treatments chip instead (a Surge Foil, a Headliner) - the two distinct
// places a promo type reaches GenericCard.
func promoTypeCards(t *testing.T) (plain, chipped string) {
	t.Helper()
	for _, uuid := range mtgmatcher.GetUUIDs() {
		co, err := mtgmatcher.GetUUID(uuid)
		if err != nil || co.Sealed {
			continue
		}
		card := uuid2card(uuid, false, false, false)
		if plain == "" && len(card.PromoTypes) > 0 {
			plain = uuid
		}
		if chipped == "" && len(card.Treatments) > 0 {
			chipped = uuid
		}
		if plain != "" && chipped != "" {
			return plain, chipped
		}
	}
	return plain, chipped
}

// A promo type already shown as its own chip - the alt-foil styling that
// replaced the Foil/Etched tag, or the Treatments badge beside it - never
// also appears in PromoTypes: the two lists are disjoint by construction,
// not by a later filtering step.
func TestPromoTypesAndTreatmentsAreDisjoint(t *testing.T) {
	if !datastoreLoaded() {
		t.Skip("no datastore loaded")
	}
	_, chipped := promoTypeCards(t)
	if chipped == "" {
		t.Skip("this datastore has no printing with a treatment chip")
	}

	card := uuid2card(chipped, false, false, false)
	for _, chip := range card.Treatments {
		for _, p := range card.PromoTypes {
			if p == chip {
				t.Errorf("%s: %q is both a Treatments chip and a PromoTypes entry", card.Name, chip)
			}
		}
	}
}

// Showcase, Extended Art and Borderless are a printing's own promo type the
// same as Prerelease or Bundle, so they show whenever co.PromoTypes carries
// them - even on a printing older than PromosForEverybodyYay. Confirmed
// against the pre-refactor code directly (commit 71c32cc54^): of 22,412
// printings whose PromoTypes carried one of these three, its built Variant
// string named the word for all of them, with no date gate - the switch
// that only fired past PromosForEverybodyYay just avoided duplicating what
// an unconditional loop over co.PromoTypes always added regardless.
func TestFrameEffectPromoTypesShowRegardlessOfDate(t *testing.T) {
	if !datastoreLoaded() {
		t.Skip("no datastore loaded")
	}
	var found bool
	for _, uuid := range mtgmatcher.GetUUIDs() {
		co, err := mtgmatcher.GetUUID(uuid)
		if err != nil || co.Sealed {
			continue
		}
		if showVariant(uuid) {
			continue // only the pre-PromosForEverybodyYay case is interesting here
		}
		hasFrame := false
		for _, pt := range co.PromoTypes {
			if pt == "showcase" || pt == "extendedart" || pt == "borderless" {
				hasFrame = true
			}
		}
		if !hasFrame {
			continue
		}
		found = true
		card := uuid2card(uuid, false, false, false)
		var shown bool
		for _, p := range card.PromoTypes {
			if p == "showcase" || p == "extendedart" || p == "borderless" {
				shown = true
			}
		}
		if !shown {
			t.Errorf("%s (%s): frame effect promo type missing from PromoTypes despite predating PromosForEverybodyYay", co.Name, co.SetCode)
		}
	}
	if !found {
		t.Skip("this datastore has no pre-PromosForEverybodyYay frame effect printing")
	}
}

// Retro frame is the one exception: co.FrameVersion carries no promo type of
// its own in the datastore, so nothing adds "retro" to PromoTypes except the
// hand-added case in uuid2card, gated the same way the old switch gated it.
func TestRetroFrameStaysDateGated(t *testing.T) {
	if !datastoreLoaded() {
		t.Skip("no datastore loaded")
	}
	var found bool
	for _, uuid := range mtgmatcher.GetUUIDs() {
		co, err := mtgmatcher.GetUUID(uuid)
		if err != nil || co.Sealed || co.FrameVersion != "1997" {
			continue
		}
		if showVariant(uuid) {
			continue // only the gated-off case is interesting here
		}
		found = true
		card := uuid2card(uuid, false, false, false)
		for _, p := range card.PromoTypes {
			if p == "retro" {
				t.Errorf("%s (%s): \"retro\" shows despite predating PromosForEverybodyYay", co.Name, co.SetCode)
			}
		}
	}
	if !found {
		t.Skip("this datastore has no pre-PromosForEverybodyYay retro-framed printing")
	}
}

// promo_label is what every card row asks to spell a raw token: mtgmatcher's
// own spelling, with a space put back where title-casing the token could not
// ("bestof" -> "Best Of"), except a "ff" token (Final Fantasy's "ffi", ...),
// which reads as its own initialism rather than the fuller spelling
// PromoTypeLabels carries for it.
func TestPromoTypeLabel(t *testing.T) {
	for _, tt := range []struct {
		value string
		want  string
	}{
		{"ffi", "FFI"},
		{"ffxvi", "FFXVI"},
	} {
		if got := promoTypeLabel(tt.value); got != tt.want {
			t.Errorf("promoTypeLabel(%q) = %q, want %q", tt.value, got, tt.want)
		}
	}

	if !datastoreLoaded() {
		t.Skip("no datastore loaded for the mtgmatcher.PromoTypeLabel comparison")
	}
	for _, value := range mtgmatcher.AllPromoTypes() {
		if strings.HasPrefix(value, "ff") {
			continue
		}
		if got, want := promoTypeLabel(value), mtgmatcher.PromoTypeLabel(value); got != want {
			t.Errorf("promoTypeLabel(%q) = %q, want mtgmatcher's own %q", value, got, want)
		}
	}
}
