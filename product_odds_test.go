package main

import (
	"regexp"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/go-mtgban/mtgmatcher/sealed"
)

func TestOddsLabel(t *testing.T) {
	tests := []struct {
		expected float64
		random   bool
		want     string
	}{
		{0.25, false, ""}, // fixed contents: no odds to state
		{0, true, ""},     // the product never yields the card
		{-1, true, ""},    // a count below zero is no count
		{0.5, true, "1 in 2"},
		{0.0833, true, "1 in 12"},
		{0.7, true, "~0.7 each"}, // rounds to "1 in 1" otherwise, which is not odds
		{0.95, true, "~0.95 each"},
		{0.6, true, "1 in 2"},
		{0.4, true, "1 in 3"},
		{1, true, "~1 each"},
		{2.5, true, "~2.5 each"},
		{36, true, "~36 each"},
	}
	for _, tc := range tests {
		if got := oddsLabel(tc.expected, tc.random); got != tc.want {
			t.Errorf("oddsLabel(%v, %v) = %q, want %q", tc.expected, tc.random, got, tc.want)
		}
	}
}

// randomSourceCard finds a card one of whose source products is random and
// yields it, with that product, so the label has something to say.
func randomSourceCard(t *testing.T) (*mtgmatcher.CardObject, *mtgmatcher.CardObject) {
	t.Helper()
	b := backend()
	for _, uuid := range b.GetUUIDs() {
		co, err := b.GetUUID(uuid)
		if err != nil || co.Sealed {
			continue
		}
		for _, productUUID := range cardobject2sources(co) {
			product, err := b.GetUUID(productUUID)
			if err != nil || !sealed.IsRandom(b, product.SetCode, product.UUID) {
				continue
			}
			entries, err := sealed.ProductCounts(b, product.SetCode, product.UUID)
			if err != nil {
				continue
			}
			for _, entry := range entries {
				if entry.UUID == co.UUID && entry.Total() > 0 {
					return co, product
				}
			}
		}
	}
	t.Skip("no card with a random source product that yields it")
	return nil, nil
}

// fixedSourceCard finds a card whose source product is not random.
func fixedSourceCard(t *testing.T) (*mtgmatcher.CardObject, *mtgmatcher.CardObject) {
	t.Helper()
	b := backend()
	for _, uuid := range b.GetUUIDs() {
		co, err := b.GetUUID(uuid)
		if err != nil || co.Sealed {
			continue
		}
		for _, productUUID := range cardobject2sources(co) {
			product, err := b.GetUUID(productUUID)
			if err != nil || sealed.IsRandom(b, product.SetCode, product.UUID) {
				continue
			}
			return co, product
		}
	}
	t.Skip("no card with a fixed source product")
	return nil, nil
}

var oddsLabelShape = regexp.MustCompile(`^(1 in [0-9]+|~[0-9.]+ each)$`)

func TestProductOddsLabelsARandomProduct(t *testing.T) {
	skipWithoutDatastore(t)
	co, product := randomSourceCard(t)

	odds := newProductOdds(backend())
	got := odds.labelFor(co)(product.UUID)
	if !oddsLabelShape.MatchString(got) {
		t.Fatalf("labelFor(%s)(%s) = %q, want a 1 in N or ~X each label", co.Name, product.Name, got)
	}

	entries, err := sealed.ProductCounts(backend(), product.SetCode, product.UUID)
	if err != nil {
		t.Fatal(err)
	}
	var expected float64
	for _, entry := range entries {
		if entry.UUID == co.UUID {
			expected += entry.Total()
		}
	}
	if want := oddsLabel(expected, true); got != want {
		t.Errorf("labelFor = %q, want %q from the summed counts", got, want)
	}
}

func TestProductOddsFixedProductHasNoLabel(t *testing.T) {
	skipWithoutDatastore(t)
	co, product := fixedSourceCard(t)

	odds := newProductOdds(backend())
	if got := odds.labelFor(co)(product.UUID); got != "" {
		t.Errorf("labelFor on the fixed product %s = %q, want no label", product.Name, got)
	}
}

func TestProductOddsComputesEachProductOnce(t *testing.T) {
	skipWithoutDatastore(t)
	co, product := randomSourceCard(t)

	odds := newProductOdds(backend())
	label := odds.labelFor(co)
	label(product.UUID)
	label(product.UUID)
	odds.labelFor(co)(product.UUID)
	if got := len(odds.counts); got != 1 {
		t.Errorf("memo holds %d products after three asks about one, want 1", got)
	}
	if got := len(odds.random); got != 1 {
		t.Errorf("random memo holds %d products after three asks about one, want 1", got)
	}
}

func TestProductOddsUnknownProductIsEmpty(t *testing.T) {
	skipWithoutDatastore(t)
	co, _ := randomSourceCard(t)

	odds := newProductOdds(backend())
	if got := odds.labelFor(co)("not-a-product"); got != "" {
		t.Errorf("labelFor on an unknown product = %q, want no label", got)
	}
	if got := len(odds.counts); got != 0 {
		t.Errorf("an unknown product left %d memo entries, want 0", got)
	}
}

func TestProductOddsEmptyProductIsMemoised(t *testing.T) {
	skipWithoutDatastore(t)
	co, _ := randomSourceCard(t)

	// A non-sealed card is a uuid the backend knows that names no product, so
	// ProductCounts answers with nothing; the memo still fills once.
	odds := newProductOdds(backend())
	label := odds.labelFor(co)
	if got := label(co.UUID); got != "" {
		t.Errorf("labelFor on a card as product = %q, want no label", got)
	}
	label(co.UUID)
	if got := len(odds.counts); got != 1 {
		t.Errorf("a failing product left %d memo entries after two asks, want 1", got)
	}
}

// sealedUUIDs returns n products the backend knows.
func sealedUUIDs(t *testing.T, n int) []string {
	t.Helper()
	uuids := backend().GetSealedUUIDs()
	if len(uuids) < n {
		t.Skipf("only %d sealed products loaded, need %d", len(uuids), n)
	}
	return uuids[:n]
}

// oldProductsHTML is the markup uuid2card built before productsHTML, kept
// here so the refactor is pinned byte for byte.
func oldProductsHTML(b *mtgmatcher.Backend, sourceSealed []string) (string, int) {
	var products string
	var numProducts int
	if len(sourceSealed) > 0 {
		products += "<h4>"
		for _, sealed := range sourceSealed {
			sealedCo, err := b.GetUUID(sealed)
			if err != nil {
				continue
			}
			products += "<a href=/sealed?q=" + sealed + ">" + sealedCo.Name + "</a>"
			numProducts++
		}
		products += "</h4>"
		if len(sourceSealed) > 5 {
			products = strings.Replace(products, "h4>", "h6>", -1)
		} else if len(sourceSealed) > 3 {
			products = strings.Replace(products, "h4>", "h5>", -1)
		}
	}
	return products, numProducts
}

func TestProductsHTMLWithoutOddsIsUnchanged(t *testing.T) {
	skipWithoutDatastore(t)
	for _, n := range []int{0, 1, 3, 4, 5, 6} {
		uuids := sealedUUIDs(t, n)
		wantHTML, wantCount := oldProductsHTML(backend(), uuids)
		gotHTML, gotCount := productsHTML(backend(), uuids, nil)
		if gotHTML != wantHTML || gotCount != wantCount {
			t.Errorf("%d products: got (%q, %d), want (%q, %d)", n, gotHTML, gotCount, wantHTML, wantCount)
		}
	}
}

func TestProductsHTMLLabelsOnlyWhereOddsAnswer(t *testing.T) {
	skipWithoutDatastore(t)
	uuids := sealedUUIDs(t, 2)
	odds := func(productUUID string) string {
		if productUUID == uuids[0] {
			return "1 in 12"
		}
		return ""
	}
	first, _ := backend().GetUUID(uuids[0])
	second, _ := backend().GetUUID(uuids[1])

	got, count := productsHTML(backend(), uuids, odds)
	if count != 2 {
		t.Errorf("count = %d, want 2", count)
	}
	want := "<h4><a href=/sealed?q=" + uuids[0] + ">" + first.Name +
		` <span class="product-odds">1 in 12</span></a>` +
		"<a href=/sealed?q=" + uuids[1] + ">" + second.Name + "</a></h4>"
	if got != want {
		t.Errorf("productsHTML =\n%s\nwant\n%s", got, want)
	}
}

func TestProductsHTMLSkipsUnknownProduct(t *testing.T) {
	skipWithoutDatastore(t)
	uuids := sealedUUIDs(t, 1)
	asked := 0
	odds := func(string) string { asked++; return "1 in 2" }

	got, count := productsHTML(backend(), append([]string{"not-a-product"}, uuids...), odds)
	if count != 1 {
		t.Errorf("count = %d, want 1 (the unknown product is skipped)", count)
	}
	if asked != 1 {
		t.Errorf("odds asked %d times, want 1 (never for the unknown product)", asked)
	}
	if strings.Contains(got, "not-a-product") {
		t.Errorf("markup names the unknown product: %s", got)
	}
}

func TestSearchMetadataLabelsProducts(t *testing.T) {
	skipWithoutDatastore(t)
	co, product := randomSourceCard(t)

	metadata, _ := searchMetadata(backend(), []string{co.UUID}, false)
	card, ok := metadata[co.UUID]
	if !ok {
		t.Fatal("searchMetadata returned no card")
	}
	if !strings.Contains(card.Products, `<span class="product-odds">`) {
		t.Errorf("Products carries no odds label:\n%s", card.Products)
	}
	if !strings.Contains(card.Products, ">"+product.Name+" <span") {
		t.Errorf("Products does not label %s:\n%s", product.Name, card.Products)
	}
	if card.NumProducts < 1 {
		t.Errorf("NumProducts = %d, want at least the labelled product", card.NumProducts)
	}
}

func TestSearchMetadataLeavesSealedProductsAlone(t *testing.T) {
	skipWithoutDatastore(t)
	uuids := sealedUUIDs(t, 1)

	metadata, _ := searchMetadata(backend(), uuids, false)
	card := metadata[uuids[0]]
	plain := uuid2card(backend(), uuids[0], false)
	if card.Products != plain.Products || card.NumProducts != plain.NumProducts {
		t.Errorf("a sealed result's products changed: got (%q, %d), want (%q, %d)",
			card.Products, card.NumProducts, plain.Products, plain.NumProducts)
	}
	if strings.Contains(card.Products, "product-odds") {
		t.Errorf("a sealed result carries odds labels: %s", card.Products)
	}
}
