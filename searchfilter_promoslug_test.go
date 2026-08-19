package main

import "testing"

func TestPromoTypeSlug(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		// Magic's types are already one lower-case word, so an is: query
		// that worked before this change works unchanged.
		{"boosterfun", "boosterfun"},
		{"promopack", "promopack"},
		{"serialized", "serialized"},
		// The other games spell theirs the way the storefront did.
		{"best of", "bestof"},
		{"prize wall", "prizewall"},
		{"Alternate Art", "alternateart"},
		{"Disney Parks & Stores", "disneyparksstores"},
		{"Illumineer's Quest", "illumineersquest"},
		{"Premium Card Collection -Best Selection Vol. 6-", "premiumcardcollectionbestselectionvol6"},
		// Two spellings of one promo answer to one token, which is what
		// makes the tag askable: the catalog writes this event both with
		// and without the stray second space.
		{"English Version 2nd  Anniversary Set", "englishversion2ndanniversaryset"},
		{"English Version 2nd Anniversary Set", "englishversion2ndanniversaryset"},
		{"", ""},
	} {
		if got := promoTypeSlug(tt.in); got != tt.want {
			t.Errorf("promoTypeSlug(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
