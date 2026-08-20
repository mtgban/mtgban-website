package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/mtgban-website/internal/palette"
)

// TestPromosEndpoint exercises the promo type list the guide and the palette
// read instead of a hardcoded table. It asks the loaded game, so what it
// answers with depends on which datastore is up - only that it answers at
// all, spells every type, and puts the commonest first, is fixed.
func TestPromosEndpoint(t *testing.T) {
	if len(mtgmatcher.AllPromoTypes()) == 0 {
		t.Skip("no datastore loaded; skipping promo endpoint test")
	}

	paletteService.BuildPromosCache()

	rec := httptest.NewRecorder()
	paletteService.Promos(rec, httptest.NewRequest(http.MethodGet, "/api/palette/promos.json", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); got == "no-store" {
		t.Fatal("cache never warmed, so the endpoint served an empty list")
	}

	var promos []palette.Promo
	if err := json.Unmarshal(rec.Body.Bytes(), &promos); err != nil {
		t.Fatal(err)
	}
	if len(promos) != len(mtgmatcher.AllPromoTypes()) {
		t.Errorf("served %d types, the game declares %d", len(promos), len(mtgmatcher.AllPromoTypes()))
	}

	for _, promo := range promos {
		if promo.Value == "" || promo.Label == "" {
			t.Errorf("%+v has no value or no label", promo)
		}
		// The value is what an is: query carries, so it has to survive
		// being typed: one word, no capitals.
		if mtgmatcher.PromoTypeSlug(promo.Value) != promo.Value {
			t.Errorf("value %q is not a token a query can carry", promo.Value)
		}
	}

	// Commonest first, so a caller showing only the head shows the types
	// most of the game wears.
	for i := 1; i < len(promos); i++ {
		if promos[i-1].Count < promos[i].Count {
			t.Errorf("%q (%d) sorts before %q (%d)",
				promos[i-1].Value, promos[i-1].Count, promos[i].Value, promos[i].Count)
			break
		}
	}

	// A shorthand is offered beside the type it stands for, so the guide can
	// show "is:bf" without a table of its own.
	for _, promo := range promos {
		if promo.Value != "boosterfun" {
			continue
		}
		for _, shorthand := range []string{"bf", "v"} {
			if !slices.Contains(promo.Aliases, shorthand) {
				t.Errorf("boosterfun does not offer the shorthand %q (got %v)", shorthand, promo.Aliases)
			}
		}
	}
}
