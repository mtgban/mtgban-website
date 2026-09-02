package main

import (
	"slices"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// isCaseNames are the values cardFilterIs answers with a case of its own,
// ahead of the promo types every value now also reaches.
var isCaseNames = []string{
	"foil", "nonfoil", "reserved", "token", "oversize", "oversized", "funny",
	"wcd", "gold", "fullart", "fa", "promo", "gamechanger", "gc",
	"extendedart", "ea", "showcase", "sc", "sh", "borderless", "bd", "bl",
	"future", "retro", "old", "reskin", "japanese", "jpn", "jp", "ja",
	"phyrexian", "ph", "commander", "productless", "ampersand", "p9", "altfoil",
}

// Letting every value fall through to the promo types can only widen what
// matches, and on Magic it widens nothing: none of the names answered by a
// case of its own is also a Magic promo type, so no Magic card can reach the
// fallback through one. The names that do carry both meanings belong to the
// other games - "extendedart" is a frame effect on a Magic card and a
// printing's own tag on a Flesh and Blood one.
func TestIsFilterCaseNamesAreNotMagicPromoTypes(t *testing.T) {
	all := mtgmatcher.AllPromoTypes()
	if len(all) == 0 {
		t.Skip("no datastore loaded")
	}

	var both []string
	for _, name := range isCaseNames {
		if slices.Contains(all, name) {
			both = append(both, name)
		}
	}
	if len(both) != 0 {
		t.Errorf("these names are answered by a case and are also Magic promo types, "+
			"so the fallthrough changes what they match: %v", both)
	}
}

// The promo-type check moved out from under default:, so a value with no case
// of its own has to keep reaching it.
func TestIsFilterStillMatchesAPromoType(t *testing.T) {
	all := mtgmatcher.AllPromoTypes()
	if len(all) == 0 {
		t.Skip("no datastore loaded")
	}
	promoType := all[0]

	co := &mtgmatcher.CardObject{}
	co.PromoTypes = []string{promoType}
	if cardFilterIs([]string{promoType}, co) {
		t.Errorf("is:%s did not match a card carrying it", promoType)
	}

	co.PromoTypes = nil
	if !cardFilterIs([]string{promoType}, co) {
		t.Errorf("is:%s matched a card without it", promoType)
	}
}

// An alias only reaches a promo type if it expands to the name a game's
// datastore actually files that promo type under, which is the slug form of
// its label. "ea" is the alias that has to travel: extended art is a frame
// effect on a Magic card and a promo type elsewhere, so the short form would
// otherwise arrive at the promo types as itself and match nothing.
func TestPromoAliasesExpandToSlugs(t *testing.T) {
	want := mtgmatcher.PromoTypeSlug("Extended Art")
	if got := isKnownPromo["ea"]; got != want {
		t.Errorf("isKnownPromo[\"ea\"] = %q, want %q", got, want)
	}

	// Every expansion has to be a slug, or it can never match: a datastore
	// files a promo type under PromoTypeSlug of its label, and cardFilterIs
	// compares what comes out of this map against exactly that.
	for alias, expanded := range isKnownPromo {
		if slug := mtgmatcher.PromoTypeSlug(expanded); slug != expanded {
			t.Errorf("isKnownPromo[%q] = %q, which is not a slug (%q)", alias, expanded, slug)
		}
	}
}
