package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mtgban/mtgban-website/internal/palette"
)

// TestRaritiesEndpoint checks the rarity list the guide and the palette read
// for the loaded game: every rarity it ranks that a printing carries, rarest
// first, each a word an r: query can carry.
func TestRaritiesEndpoint(t *testing.T) {
	if len(backend().Rarities) == 0 {
		t.Skip("no datastore loaded; skipping rarity endpoint test")
	}

	rec := httptest.NewRecorder()
	testSite.palette.Rarities(rec, httptest.NewRequest(http.MethodGet, "/api/palette/rarities.json", nil))
	if got := rec.Header().Get("Cache-Control"); got == "no-store" {
		t.Fatal("the list was never built, so the endpoint served an empty answer")
	}

	var rarities []palette.Rarity
	err := json.Unmarshal(rec.Body.Bytes(), &rarities)
	if err != nil {
		t.Fatal(err)
	}
	if len(rarities) == 0 {
		t.Fatal("the game's printings carry no rarity the list offers")
	}
	last := -1
	for _, rarity := range rarities {
		rank, ranked := backend().RarityRank(rarity.Value)
		if !ranked || rank <= last {
			t.Errorf("%q is out of the game's order", rarity.Value)
		}
		last = rank
		if rarity.Label == "" || rarity.Count == 0 {
			t.Errorf("%+v has no label or no printings", rarity)
		}
	}
}
