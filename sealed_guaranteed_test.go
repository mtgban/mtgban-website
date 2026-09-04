package main

import (
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// dropWithBonusCards finds a product that holds both a guaranteed list and
// bonus cards, which is the only shape the toggle is for. Chosen by scanning
// rather than pinned, so the test fails for being wrong instead of for a
// product having been reprinted.
func dropWithBonusCards(t *testing.T) *mtgmatcher.CardObject {
	t.Helper()
	for _, code := range mtgmatcher.GetAllSets() {
		set, err := mtgmatcher.GetSet(code)
		if err != nil {
			continue
		}
		for _, product := range set.SealedProduct {
			if !mtgmatcher.SealedHasDecklist(code, product.UUID) {
				continue
			}
			if !mtgmatcher.SealedIsRandom(code, product.UUID) {
				continue
			}
			co, err := mtgmatcher.GetUUID(product.UUID)
			if err == nil {
				return co
			}
		}
	}
	return nil
}

// What the toggle is for: the contents of such a product are a great deal more
// than what it always holds, and the short list is the one nobody could reach.
func TestADropHoldsMoreThanItGuarantees(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	co := dropWithBonusCards(t)
	if co == nil {
		t.Skip("this datastore has no product with both guaranteed and bonus cards")
	}

	deck, err := mtgmatcher.GetDecklist(co.SetCode, co.UUID)
	if err != nil {
		t.Fatalf("%s has no decklist after all: %v", co.Name, err)
	}
	picks, err := mtgmatcher.GetPicksForSealed(co.SetCode, co.UUID)
	if err != nil {
		t.Fatalf("%s opens into nothing: %v", co.Name, err)
	}
	if len(picks) <= len(deck) {
		t.Errorf("%s picks %d cards from a guaranteed %d, so there is nothing to hide",
			co.Name, len(picks), len(deck))
	}
}

// The query says which product it asked about, so the page can offer the other
// reading of it.
func TestContentsQueryRemembersItsProduct(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	co := dropWithBonusCards(t)
	if co == nil {
		t.Skip("this datastore has no product with both guaranteed and bonus cards")
	}

	everything := parseSearchOptionsNG(`contents:"`+co.Name+`"`, nil, nil, nil)
	if everything.ContentsProduct != co.UUID {
		t.Errorf("a contents query names %q, want %q", everything.ContentsProduct, co.UUID)
	}
	if everything.ContentsGuaranteed {
		t.Error("a contents query claims to hold only what is guaranteed")
	}

	guaranteed := parseSearchOptionsNG(`decklist:"`+co.Name+`"`, nil, nil, nil)
	if guaranteed.ContentsProduct != co.UUID {
		t.Errorf("a decklist query names %q, want %q", guaranteed.ContentsProduct, co.UUID)
	}
	if !guaranteed.ContentsGuaranteed {
		t.Error("a decklist query does not say it holds only what is guaranteed")
	}

	// Asking for what is not in a product is asking about neither reading.
	negated := parseSearchOptionsNG(`-contents:"`+co.Name+`"`, nil, nil, nil)
	if negated.ContentsProduct != "" {
		t.Errorf("a negated query offers a toggle over %q", negated.ContentsProduct)
	}
}

// The toggle itself: one pill, active when the short list is showing, linking
// to the other reading either way.
func TestGuaranteedToggleSwitchesBothWays(t *testing.T) {
	everything := PageVars{
		BetaNav:            &NavElem{},
		SearchQuery:        `contents:"Secret Lair Drop A Box of Rocks"`,
		TotalUnique:        15,
		AllKeys:            []string{"a"},
		ContentsProduct:    "Secret Lair Drop A Box of Rocks",
		ContentsOtherQuery: `decklist:"Secret Lair Drop A Box of Rocks"`,
	}
	out := renderPage(t, "search.html", false, everything)
	if !strings.Contains(out, "Guaranteed only") {
		t.Fatal("a product with bonus cards offers no way to hide them")
	}
	// The href is URL-escaped by the template, so match the escaped form.
	if !strings.Contains(strings.ToLower(out), "q=decklist%3a") {
		t.Error("the toggle does not lead to the guaranteed list")
	}
	if strings.Contains(out, "with-label active") {
		t.Error("the toggle reads as on while everything is showing")
	}

	guaranteed := everything
	guaranteed.TotalUnique = 5
	guaranteed.ContentsGuaranteed = true
	guaranteed.ContentsOtherQuery = `contents:"Secret Lair Drop A Box of Rocks"`
	guaranteed.SearchQuery = `decklist:"Secret Lair Drop A Box of Rocks"`
	out = renderPage(t, "search.html", false, guaranteed)
	if !strings.Contains(out, "with-label active") {
		t.Error("the toggle does not read as on while the short list is showing")
	}
	if !strings.Contains(strings.ToLower(out), "q=contents%3a") {
		t.Error("the toggle does not lead back to everything the product may hold")
	}
}

// Every other search is unchanged: there is nothing to toggle between.
func TestGuaranteedToggleIsAbsentElsewhere(t *testing.T) {
	out := renderPage(t, "search.html", false, PageVars{
		BetaNav:     &NavElem{},
		SearchQuery: "lightning bolt",
		TotalUnique: 3,
		AllKeys:     []string{"a"},
	})
	if strings.Contains(out, "Guaranteed only") {
		t.Error("an ordinary search offers to hide bonus cards it never listed")
	}
}

// The toggle is offered only where the two readings differ: a product with
// nothing guaranteed has no short list, and one with no bonus cards is already
// showing it.
func TestContentsToggleOnlyWhereTheReadingsDiffer(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	drop := dropWithBonusCards(t)
	if drop == nil {
		t.Skip("this datastore has no product with both guaranteed and bonus cards")
	}

	query := `contents:"` + drop.Name + `"`
	name, other := contentsToggle(query, SearchConfig{ContentsProduct: drop.UUID})
	if name != drop.Name {
		t.Errorf("the toggle names %q, want %q", name, drop.Name)
	}
	if !strings.HasPrefix(other, `decklist:"`) {
		t.Errorf("the other reading is %q, want a decklist query", other)
	}

	// And back the other way, carrying whatever else the query said.
	back := `decklist:"` + drop.Name + `" f:foil`
	_, other = contentsToggle(back, SearchConfig{ContentsProduct: drop.UUID, ContentsGuaranteed: true})
	if !strings.HasPrefix(other, `contents:"`) || !strings.HasSuffix(other, " f:foil") {
		t.Errorf("the other reading is %q, want a contents query keeping the rest", other)
	}

	// A search that named no product is not a contents search.
	if name, _ := contentsToggle("lightning bolt", SearchConfig{}); name != "" {
		t.Errorf("an ordinary search offers a toggle over %q", name)
	}

	// A product with nothing guaranteed has no short list to switch to.
	var booster string
	for _, code := range mtgmatcher.GetAllSets() {
		set, err := mtgmatcher.GetSet(code)
		if err != nil {
			continue
		}
		for _, product := range set.SealedProduct {
			if !mtgmatcher.SealedHasDecklist(code, product.UUID) &&
				mtgmatcher.SealedIsRandom(code, product.UUID) {
				booster = product.UUID
			}
			if booster != "" {
				break
			}
		}
		if booster != "" {
			break
		}
	}
	if booster != "" {
		name, _ := contentsToggle("contents:whatever", SearchConfig{ContentsProduct: booster})
		if name != "" {
			t.Errorf("a product with nothing guaranteed offers a toggle over %q", name)
		}
	}
}

// The mobile page carries the same switch: scrolling past bonus cards is worse
// on a phone, not better.
func TestGuaranteedToggleIsOnTheMobilePage(t *testing.T) {
	out := renderPage(t, "search.html", true, PageVars{
		BetaNav:            &NavElem{},
		IsMobile:           true,
		SearchQuery:        `contents:"Secret Lair Drop A Box of Rocks"`,
		TotalUnique:        15,
		AllKeys:            []string{"a"},
		ContentsProduct:    "Secret Lair Drop A Box of Rocks",
		ContentsOtherQuery: `decklist:"Secret Lair Drop A Box of Rocks"`,
	})
	if !strings.Contains(out, "Guaranteed") {
		t.Fatal("the mobile page offers no way to hide the bonus cards")
	}
	if !strings.Contains(strings.ToLower(out), "q=decklist%3a") {
		t.Error("the mobile toggle does not lead to the guaranteed list")
	}
}
