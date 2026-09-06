package main

import (
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// productWithBothKinds finds a product that holds a fixed list and cards it
// might come with, which is the only shape any of this is for. Chosen by
// scanning rather than pinned, so the test fails for being wrong instead of
// for a product having been reprinted.
func productWithBothKinds(t *testing.T) *mtgmatcher.CardObject {
	t.Helper()
	for _, code := range mtgmatcher.GetAllSets() {
		set, err := mtgmatcher.GetSet(code)
		if err != nil {
			continue
		}
		for _, product := range set.SealedProduct {
			if !mtgmatcher.SealedHasDecklist(code, product.UUID) ||
				!mtgmatcher.SealedIsRandom(code, product.UUID) {
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

// What the reading is for: such a product lists a great deal more than it
// always holds, so what it might hold is worth asking for on its own.
func TestAProductHoldsMoreThanItGuarantees(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	co := productWithBothKinds(t)
	if co == nil {
		t.Skip("this datastore has no product with both a fixed and a variable part")
	}

	deck, err := mtgmatcher.GetDecklist(co.SetCode, co.UUID)
	if err != nil {
		t.Fatalf("%s has no fixed list after all: %v", co.Name, err)
	}
	picks, err := mtgmatcher.GetPicksForSealed(co.SetCode, co.UUID)
	if err != nil {
		t.Fatalf("%s opens into nothing: %v", co.Name, err)
	}
	if len(picks) <= len(deck) {
		t.Errorf("%s picks %d cards from a guaranteed %d, so there is nothing to separate",
			co.Name, len(picks), len(deck))
	}
}

// The variable reading is the contents with the fixed list taken back out, so
// it is two filters composed rather than a list built.
func TestVariableIsTheContentsWithoutTheFixedList(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	co := productWithBothKinds(t)
	if co == nil {
		t.Skip("this datastore has no product with both a fixed and a variable part")
	}
	deck, err := mtgmatcher.GetDecklist(co.SetCode, co.UUID)
	if err != nil {
		t.Fatal(err)
	}

	config := parseSearchOptionsNG(`variable:"`+co.Name+`"`, nil, nil, nil)

	var holdsContents, dropsTheDeck bool
	for _, filter := range config.CardFilters {
		if filter.Name == "contents" && !filter.Negate &&
			len(filter.Values) == 1 && filter.Values[0] == co.UUID {
			holdsContents = true
		}
		if filter.Name == "idlookup" && filter.Negate && len(filter.Values) == len(deck) {
			dropsTheDeck = true
		}
	}
	if !holdsContents {
		t.Error("the variable reading does not start from the product's contents")
	}
	if !dropsTheDeck {
		t.Error("the variable reading does not take the fixed list back out")
	}

	// And the cards it keeps are the ones the product does not guarantee.
	for _, uuid := range deck {
		if !shouldSkipCardNG(uuid, config.CardFilters) {
			card, _ := mtgmatcher.GetUUID(uuid)
			t.Errorf("%s is guaranteed but survives the variable reading", card)
			break
		}
	}
}

// Each of the three queries says which product it asked about and which
// reading it wanted, so the page can offer the other two.
func TestEachReadingNamesItselfAndItsProduct(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	co := productWithBothKinds(t)
	if co == nil {
		t.Skip("this datastore has no product with both a fixed and a variable part")
	}

	for _, want := range []string{ContentsAll, ContentsFixed, ContentsVariable} {
		config := parseSearchOptionsNG(want+`:"`+co.Name+`"`, nil, nil, nil)
		if config.ContentsProduct != co.UUID {
			t.Errorf("%s: names %q, want %q", want, config.ContentsProduct, co.UUID)
		}
		if config.ContentsMode != want {
			t.Errorf("%s: reads as %q", want, config.ContentsMode)
		}
	}

	// Asking for what is not in a product is asking for none of the three.
	negated := parseSearchOptionsNG(`-contents:"`+co.Name+`"`, nil, nil, nil)
	if negated.ContentsProduct != "" {
		t.Errorf("a negated query offers a switch over %q", negated.ContentsProduct)
	}
}

// A product that holds nothing but other products answers a contents search
// with those products. They are rows on the page, so the search is not empty,
// but there is no card in it to read another way.
func TestAWrapperAnswersWithProductsNotCards(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}

	var wrapper string
	for _, code := range mtgmatcher.GetAllSets() {
		set, err := mtgmatcher.GetSet(code)
		if err != nil {
			continue
		}
		for _, product := range set.SealedProduct {
			if len(product.Contents) != 1 || len(product.Contents["sealed"]) == 0 {
				continue
			}
			if !mtgmatcher.SealedHasDecklist(code, product.UUID) ||
				!mtgmatcher.SealedIsRandom(code, product.UUID) {
				continue
			}
			wrapper = product.Name
			break
		}
		if wrapper != "" {
			break
		}
	}
	if wrapper == "" {
		t.Skip("this datastore has no product that only wraps another")
	}

	config := parseSearchOptionsNG(`contents:"`+wrapper+`"`, nil, nil, nil)
	found, err := searchAndFilter(config)
	if err != nil || len(found) == 0 {
		t.Skipf("%s finds nothing at all: %v", wrapper, err)
	}

	// The rows are products, so the page has something to show and does not
	// exit early - but it holds no card to read another way.
	if containsSingles(found) {
		t.Errorf("%s answered with cards, so the switch would be offered", wrapper)
	}
}

// Only a card counts as something to read another way.
func TestContainsSingles(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	co := productWithBothKinds(t)
	if co == nil {
		t.Skip("this datastore has no product with both a fixed and a variable part")
	}
	deck, err := mtgmatcher.GetDecklist(co.SetCode, co.UUID)
	if err != nil || len(deck) == 0 {
		t.Skip("the product opens into nothing")
	}

	if containsSingles([]string{co.UUID}) {
		t.Error("a sealed product counts as a card")
	}
	if !containsSingles([]string{deck[0]}) {
		t.Error("a card does not count as a card")
	}
	if !containsSingles([]string{co.UUID, deck[0]}) {
		t.Error("a card beside a product does not count")
	}
	if containsSingles(nil) {
		t.Error("nothing at all counts as a card")
	}
}

// The switch is offered only where all three readings mean something.
func TestContentsSwitchOnlyWhereAllThreeMeanSomething(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	co := productWithBothKinds(t)
	if co == nil {
		t.Skip("this datastore has no product with both a fixed and a variable part")
	}

	query := `contents:"` + co.Name + `" f:foil`
	views := contentsViews(query, SearchConfig{ContentsProduct: co.UUID, ContentsMode: ContentsAll})
	if views == nil {
		t.Fatal("a product with both parts offers no switch")
	}
	if views.Product != co.Name || views.Mode != ContentsAll {
		t.Errorf("the switch reads %q / %q", views.Product, views.Mode)
	}
	// Swapping the filter carries the rest of the query with it.
	if !strings.HasPrefix(views.Fixed, `decklist:"`) || !strings.HasSuffix(views.Fixed, ` f:foil`) {
		t.Errorf("the fixed reading is %q", views.Fixed)
	}
	if !strings.HasPrefix(views.Variable, `variable:"`) {
		t.Errorf("the variable reading is %q", views.Variable)
	}

	// A search that named no product is not one of the three.
	if contentsViews("lightning bolt", SearchConfig{}) != nil {
		t.Error("an ordinary search offers the switch")
	}
}

// The switch renders as three pills under the sort row, the current one lit.
func TestContentsSwitchRendersAsPills(t *testing.T) {
	views := &ContentsViews{
		Product:  "Secret Lair Drop Special Guest Junji Ito English",
		Mode:     ContentsFixed,
		All:      `contents:"Secret Lair Drop Special Guest Junji Ito English"`,
		Fixed:    `decklist:"Secret Lair Drop Special Guest Junji Ito English"`,
		Variable: `variable:"Secret Lair Drop Special Guest Junji Ito English"`,
	}
	for _, mobile := range []bool{false, true} {
		out := renderPage(t, "search.html", mobile, PageVars{
			BetaNav:     &NavElem{},
			IsMobile:    mobile,
			SearchQuery: views.Fixed,
			TotalUnique: 4,
			AllKeys:     []string{"a"},
			Contents:    views,
		})
		if !strings.Contains(out, ">Contents<") {
			t.Errorf("mobile=%v: the switch is not labelled", mobile)
		}
		for _, want := range []string{"q=contents%3a", "q=decklist%3a", "q=variable%3a"} {
			if !strings.Contains(strings.ToLower(out), want) {
				t.Errorf("mobile=%v: no link for %s", mobile, want)
			}
		}
		if !strings.Contains(out, `data-lucide="dices"`) {
			t.Errorf("mobile=%v: the variable reading has no button", mobile)
		}
	}

	// Every other search is unchanged.
	out := renderPage(t, "search.html", false, PageVars{
		BetaNav:     &NavElem{},
		SearchQuery: "lightning bolt",
		TotalUnique: 3,
		AllKeys:     []string{"a"},
	})
	if strings.Contains(out, ">Contents<") {
		t.Error("an ordinary search offers the switch")
	}
}

// The setting decides which reading a product's link opens, and only for a
// product that has all three.
func TestTheSettingPicksWhatALinkOpens(t *testing.T) {
	for _, tt := range []struct {
		name            string
		random, hasDeck bool
		pref, want      string
	}{
		{"both, unset", true, true, "", ContentsAll},
		{"both, everything", true, true, ContentsAll, ContentsAll},
		{"both, only fixed", true, true, ContentsFixed, ContentsFixed},
		{"both, only variable", true, true, ContentsVariable, ContentsVariable},
		{"both, nonsense", true, true, "sideways", ContentsAll},
		// A booster box has no fixed list to open, and a plain precon has no
		// variable one: neither has a choice to make.
		{"booster box", true, false, ContentsFixed, ContentsAll},
		{"plain precon", false, true, ContentsVariable, ContentsFixed},
	} {
		got := sealedContentsFilter(tt.random, tt.hasDeck, tt.pref)
		if got != tt.want {
			t.Errorf("%s: link opens %q, want %q", tt.name, got, tt.want)
		}
	}
}
