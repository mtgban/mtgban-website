package main

import (
	"slices"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

func TestPromoTypeMatches(t *testing.T) {
	if len(mtgmatcher.AllPromoTypes()) == 0 {
		t.Skip("no datastore")
	}

	// An exact token answers alone: asking for "metal" is not asking for
	// every type with "metal" inside it.
	if got := promoTypeMatches("metal"); !slices.Equal(got, []string{"metal"}) {
		t.Errorf("promoTypeMatches(metal) = %v, want just [metal]", got)
	}

	// A promo type is a token that gave up its spaces so it could be typed
	// into a search; the query gives up the same ones on the way in.
	if got := promoTypeMatches("cosmic foil"); !slices.Equal(got, []string{"cosmicfoil"}) {
		t.Errorf("promoTypeMatches(cosmic foil) = %v, want [cosmicfoil]", got)
	}

	// Failing an exact token, everything carrying the query comes back.
	got := promoTypeMatches("confetti")
	if !slices.Contains(got, "confettifoil") {
		t.Errorf("promoTypeMatches(confetti) = %v, want it to reach confettifoil", got)
	}

	// Two characters sit inside most of the list, so they only match exactly.
	if got := promoTypeMatches("fo"); len(got) != 0 {
		t.Errorf("promoTypeMatches(fo) = %v, want nothing for a query that short", got)
	}
	if got := promoTypeMatches(""); len(got) != 0 {
		t.Errorf("promoTypeMatches(empty) = %v, want nothing", got)
	}
}

func TestSetCodeMatches(t *testing.T) {
	if len(mtgmatcher.GetAllSets()) == 0 {
		t.Skip("no datastore")
	}

	if got := setCodeMatches("LEA"); !slices.Equal(got, []string{"LEA"}) {
		t.Errorf("setCodeMatches(LEA) = %v, want just [LEA]", got)
	}

	// A word from a set's name reaches every set carrying it.
	got := setCodeMatches("kamigawa")
	if len(got) < 2 || !slices.Contains(got, "CHK") || !slices.Contains(got, "NEO") {
		t.Errorf("setCodeMatches(kamigawa) = %v, want it to reach at least CHK and NEO", got)
	}

	if got := setCodeMatches("xy"); len(got) != 0 {
		t.Errorf("setCodeMatches(xy) = %v, want nothing for a query that short", got)
	}
	if got := setCodeMatches("notathing"); len(got) != 0 {
		t.Errorf("setCodeMatches(notathing) = %v, want nothing", got)
	}
}

// The fallback answers a name that matched nothing, in the order a searcher is
// likely to have meant it, and declines the cases where the query already said
// what it wanted.
func TestSearchFallback(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore")
	}

	t.Run("a treatment", func(t *testing.T) {
		config := parseSearchOptionsNG("confetti", nil, nil, nil)
		if _, err := searchAndFilter(config); err == nil {
			t.Skip("a card is named confetti here; the fallback would not run")
		}
		keys := searchFallback(config)
		if len(keys) == 0 {
			t.Fatal("want the cards printed as confettifoil")
		}
		for _, key := range keys {
			co, err := mtgmatcher.GetUUID(key)
			if err != nil {
				continue
			}
			if !co.HasPromoType("confettifoil") {
				t.Fatalf("%s (%s) carries %v, not the treatment searched for", co.Name, co.SetCode, co.PromoTypes)
			}
		}
	})

	t.Run("a set", func(t *testing.T) {
		config := parseSearchOptionsNG("kamigawa", nil, nil, nil)
		if _, err := searchAndFilter(config); err == nil {
			t.Skip("a card is named kamigawa here; the fallback would not run")
		}
		keys := searchFallback(config)
		if len(keys) == 0 {
			t.Fatal("want the cards in the Kamigawa sets")
		}
		wanted := setCodeMatches("kamigawa")
		for _, key := range keys {
			co, err := mtgmatcher.GetUUID(key)
			if err != nil {
				continue
			}
			if !slices.Contains(wanted, co.SetCode) {
				t.Fatalf("%s came from %s, which is not one of %v", co.Name, co.SetCode, wanted)
			}
		}
	})

	t.Run("a name that means nothing", func(t *testing.T) {
		config := parseSearchOptionsNG("notathing", nil, nil, nil)
		if keys := searchFallback(config); len(keys) != 0 {
			t.Errorf("got %d results, want the search to give up", len(keys))
		}
	})

	t.Run("a query that already named a set", func(t *testing.T) {
		// "s:LEA kamigawa" asked about LEA. Answering with every Kamigawa set
		// would throw away the part the searcher did say.
		config := parseSearchOptionsNG("s:LEA kamigawa", nil, nil, nil)
		if keys := searchFallback(config); len(keys) != 0 {
			t.Errorf("got %d results, want the named set to stand", len(keys))
		}
	})

	t.Run("a hashing search names its own cards", func(t *testing.T) {
		config := SearchConfig{SearchMode: "hashing", CleanQuery: "kamigawa"}
		if keys := searchFallback(config); len(keys) != 0 {
			t.Errorf("got %d results, want the fallback to stand aside", len(keys))
		}
	})
}
