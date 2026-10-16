package main

import (
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/matcher"
	"github.com/mtgban/go-mtgban/matcher/sealed"
)

func TestOddsLabel(t *testing.T) {
	tests := []struct {
		expected   float64
		guaranteed int
		random     bool
		want       string
	}{
		{0.25, 0, false, ""}, // fixed contents: no odds to state
		{1, 1, false, ""},    // a fixed deck's card: no label either
		{0, 0, true, ""},     // the product never yields the card
		{-1, 0, true, ""},    // a count below zero is no count
		{0.5, 0, true, "1 in 2"},
		{0.0833, 0, true, "1 in 12"},
		{0.014, 0, true, "1 in 71"},
		{0.12, 0, true, "1 in 8.3"}, // one decimal below 10, so 0.6 is not "1 in 2"
		{0.1, 0, true, "1 in 10"},
		{0.0995, 0, true, "1 in 10"}, // not "1 in 10.0"
		{0.7, 0, true, "1 in 1.4"},
		{0.949, 0, true, "1 in 1.1"},
		{0.6, 0, true, "1 in 1.7"},
		{0.4, 0, true, "1 in 2.5"},
		{0.95, 0, true, "~0.95 each"}, // never "1 in 1": from 0.95 the count is the label
		{0.96, 0, true, "~0.96 each"},
		{0.999, 0, true, "~1 each"},
		{1, 0, true, "~1 each"},
		{2.5, 0, true, "~2.5 each"},
		{36, 0, true, "~36 each"},
		{1, 1, true, "1"},      // a bundle's promo: held, not drawn
		{1.0127, 1, true, "1"}, // held once; a booster's chance is too small to show
		{1.04, 1, true, "1"},
		{1.06, 1, true, "1+"},
		{2, 2, true, "2"},
		{2.09, 2, true, "2+"},
		{6.67, 6, true, "6+"}, // a bundle's lands, and more in its boosters
	}
	for _, tc := range tests {
		if got := oddsLabel(tc.expected, tc.guaranteed, tc.random); got != tc.want {
			t.Errorf("oddsLabel(%v, %d, %v) = %q, want %q", tc.expected, tc.guaranteed, tc.random, got, tc.want)
		}
	}
}

func TestExpectedCopies(t *testing.T) {
	tests := []struct {
		expected float64
		want     string
	}{
		{0.0833, "0.083 copies expected"},
		{0.003, "0.003 copies expected"},          // not "0", which two decimals would say
		{0.000076, "under 0.001 copies expected"}, // never exponent form
		{0.6, "0.6 copies expected"},
		{0.9995, "1 copy expected"}, // singular by the shown count, not the float
		{1, "1 copy expected"},
		{1.004, "1 copy expected"},
		{2.5, "2.5 copies expected"},
		{36, "36 copies expected"},
	}
	for _, tc := range tests {
		if got := expectedCopies(tc.expected); got != tc.want {
			t.Errorf("expectedCopies(%v) = %q, want %q", tc.expected, got, tc.want)
		}
	}
}

// randomSourceCard finds a card one of whose source products is random and
// yields it, with that product, so the label has something to say.
func randomSourceCard(t *testing.T) (*matcher.CardObject, *matcher.CardObject) {
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
func fixedSourceCard(t *testing.T) (*matcher.CardObject, *matcher.CardObject) {
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

var oddsLabelShape = regexp.MustCompile(`^(1 in [0-9.]+|~[0-9.]+ each|[0-9]+\+?)$`)

// summedCounts is the uncached path: a card's expected copies in a product,
// summed over the product's entries, the copies held whole, and whether the
// product is random.
func summedCounts(t *testing.T, co, product *matcher.CardObject) (float64, int, bool) {
	t.Helper()
	entries, err := sealed.ProductCounts(backend(), product.SetCode, product.UUID)
	if err != nil {
		t.Fatal(err)
	}
	var expected float64
	var guaranteed int
	for _, entry := range entries {
		if entry.UUID == co.UUID {
			expected += entry.Total()
			if entry.ExpectedCount == 1 {
				guaranteed += entry.Copies
			}
		}
	}
	return expected, guaranteed, sealed.IsRandom(backend(), product.SetCode, product.UUID)
}

func TestProductOddsLabelsARandomProduct(t *testing.T) {
	skipWithoutDatastore(t)
	co, product := randomSourceCard(t)

	got, title := currentDatastore().odds.label(product.UUID, co.UUID)
	if !oddsLabelShape.MatchString(got) {
		t.Fatalf("label(%s, %s) = %q, want a 1 in N, ~X each or N label", product.Name, co.Name, got)
	}

	expected, guaranteed, _ := summedCounts(t, co, product)
	if want := oddsLabel(expected, guaranteed, true); got != want {
		t.Errorf("label = %q, want %q from the summed counts", got, want)
	}
	if want := expectedCopies(expected); title != want {
		t.Errorf("title = %q, want %q", title, want)
	}
}

// guaranteedSourceCard finds a card a random product always holds, as a
// bundle holds its promo beside the boosters.
func guaranteedSourceCard(t *testing.T) (*matcher.CardObject, *matcher.CardObject) {
	t.Helper()
	b := backend()
	for _, uuid := range b.GetUUIDs() {
		co, err := b.GetUUID(uuid)
		if err != nil || co.Sealed {
			continue
		}
		for _, productUUID := range cardobject2sources(co) {
			product, err := b.GetUUID(productUUID)
			if err != nil {
				continue
			}
			_, guaranteed, random := summedCounts(t, co, product)
			if random && guaranteed > 0 {
				return co, product
			}
		}
	}
	t.Skip("no card a random product always holds")
	return nil, nil
}

func TestProductOddsGuaranteedCardShowsItsCount(t *testing.T) {
	skipWithoutDatastore(t)
	co, product := guaranteedSourceCard(t)

	expected, guaranteed, _ := summedCounts(t, co, product)
	got, title := currentDatastore().odds.label(product.UUID, co.UUID)
	want := strconv.Itoa(guaranteed)
	if expected-float64(guaranteed) >= moreFrom {
		want += "+"
	}
	if got != want {
		t.Errorf("label(%s, %s) = %q, want %q", product.Name, co.Name, got, want)
	}
	if want := expectedCopies(expected); title != want {
		t.Errorf("title = %q, want %q", title, want)
	}
}

func TestProductOddsNilLabelsNothing(t *testing.T) {
	skipWithoutDatastore(t)
	co, product := randomSourceCard(t)

	// The datastore before the first load has no odds; uuid2card then
	// builds the plain list.
	var odds *productOdds
	if got, title := odds.label(product.UUID, co.UUID); got != "" || title != "" {
		t.Errorf("nil odds labelled %s in %s (%q, %q), want no label", co.Name, product.Name, got, title)
	}
}

func TestProductOddsFixedProductHasNoLabel(t *testing.T) {
	skipWithoutDatastore(t)
	co, product := fixedSourceCard(t)

	if got, title := currentDatastore().odds.label(product.UUID, co.UUID); got != "" || title != "" {
		t.Errorf("label on the fixed product %s = (%q, %q), want no label", product.Name, got, title)
	}
}

func TestProductOddsUnknownProductIsEmpty(t *testing.T) {
	skipWithoutDatastore(t)
	co, _ := randomSourceCard(t)

	if got, _ := currentDatastore().odds.label("not-a-product", co.UUID); got != "" {
		t.Errorf("label on an unknown product = %q, want no label", got)
	}
}

// TestNewDatastoreCountsEverySourceProduct: the load counts every product
// a card lists as its source, but those ProductCounts rejects.
func TestNewDatastoreCountsEverySourceProduct(t *testing.T) {
	skipWithoutDatastore(t)
	ds := currentDatastore()
	b := ds.backend
	for productUUID := range ds.sources.byProduct {
		product, err := b.GetUUID(productUUID)
		if err != nil {
			continue
		}
		_, err = sealed.ProductCounts(b, product.SetCode, product.UUID)
		_, found := ds.odds.yield[productUUID]
		if found != (err == nil) {
			t.Errorf("%s: counted %v, ProductCounts error %v", product.Name, found, err)
		}
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
func oldProductsHTML(b *matcher.Backend, sourceSealed []string) (string, int) {
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
		gotHTML, gotCount := productsHTML(backend(), uuids, nil, "")
		if gotHTML != wantHTML || gotCount != wantCount {
			t.Errorf("%d products: got (%q, %d), want (%q, %d)", n, gotHTML, gotCount, wantHTML, wantCount)
		}
	}
}

func TestProductsHTMLLabelsOnlyWhereOddsAnswer(t *testing.T) {
	skipWithoutDatastore(t)
	uuids := sealedUUIDs(t, 2)
	odds := &productOdds{yield: map[string]*productYield{
		uuids[0]: {counts: map[string]float64{"card": 1.0 / 12}, random: true},
		uuids[1]: {counts: map[string]float64{}, random: true},
	}}
	first, _ := backend().GetUUID(uuids[0])
	second, _ := backend().GetUUID(uuids[1])

	got, count := productsHTML(backend(), uuids, odds, "card")
	if count != 2 {
		t.Errorf("count = %d, want 2", count)
	}
	want := "<h4><a href=/sealed?q=" + uuids[0] + ">" + first.Name +
		` <span class="product-odds" title="0.083 copies expected">1 in 12</span></a>` +
		"<a href=/sealed?q=" + uuids[1] + ">" + second.Name + "</a></h4>"
	if got != want {
		t.Errorf("productsHTML =\n%s\nwant\n%s", got, want)
	}
}

func TestProductsHTMLSkipsUnknownProduct(t *testing.T) {
	skipWithoutDatastore(t)
	uuids := sealedUUIDs(t, 1)
	odds := &productOdds{yield: map[string]*productYield{
		uuids[0]: {counts: map[string]float64{"card": 0.5}, random: true},
	}}

	got, count := productsHTML(backend(), append([]string{"not-a-product"}, uuids...), odds, "card")
	if count != 1 {
		t.Errorf("count = %d, want 1 (the unknown product is skipped)", count)
	}
	if !strings.Contains(got, ">1 in 2</span>") {
		t.Errorf("markup lost the known product's label: %s", got)
	}
	if strings.Contains(got, "not-a-product") {
		t.Errorf("markup names the unknown product: %s", got)
	}
}

func TestSearchMetadataLabelsProducts(t *testing.T) {
	skipWithoutDatastore(t)
	co, product := randomSourceCard(t)

	ds := currentDatastore()
	metadata, _ := searchMetadata(ds, []string{co.UUID}, false)
	card, ok := metadata[co.UUID]
	if !ok {
		t.Fatal("searchMetadata returned no card")
	}
	if !strings.Contains(card.Products, `<span class="product-odds" title="`) {
		t.Errorf("Products carries no odds label:\n%s", card.Products)
	}
	if !strings.Contains(card.Products, ">"+product.Name+" <span") {
		t.Errorf("Products does not label %s:\n%s", product.Name, card.Products)
	}
	if card.NumProducts < 1 {
		t.Errorf("NumProducts = %d, want at least the labelled product", card.NumProducts)
	}
}

// TestUUID2CardBuildsProductsOnce: uuid2card labels the list itself when
// handed the odds, so searchMetadata has nothing to rebuild.
func TestUUID2CardBuildsProductsOnce(t *testing.T) {
	skipWithoutDatastore(t)
	co, product := randomSourceCard(t)
	ds := currentDatastore()

	plain := uuid2card(backend(), co.UUID, false, nil)
	if strings.Contains(plain.Products, "product-odds") {
		t.Errorf("uuid2card without odds labelled the products: %s", plain.Products)
	}
	labelled := uuid2card(backend(), co.UUID, false, ds.odds)
	if !strings.Contains(labelled.Products, ">"+product.Name+` <span class="product-odds"`) {
		t.Errorf("uuid2card with odds did not label %s: %s", product.Name, labelled.Products)
	}
	if labelled.NumProducts != plain.NumProducts {
		t.Errorf("NumProducts %d with odds, %d without", labelled.NumProducts, plain.NumProducts)
	}
	metadata, _ := searchMetadata(ds, []string{co.UUID}, false)
	if metadata[co.UUID].Products != labelled.Products {
		t.Errorf("searchMetadata's Products differ from uuid2card's with the same odds:\n%s\n%s",
			metadata[co.UUID].Products, labelled.Products)
	}
}

func TestSearchMetadataLeavesSealedProductsAlone(t *testing.T) {
	skipWithoutDatastore(t)
	uuids := sealedUUIDs(t, 1)

	metadata, _ := searchMetadata(currentDatastore(), uuids, false)
	card := metadata[uuids[0]]
	plain := uuid2card(backend(), uuids[0], false, nil)
	if card.Products != plain.Products || card.NumProducts != plain.NumProducts {
		t.Errorf("a sealed result's products changed: got (%q, %d), want (%q, %d)",
			card.Products, card.NumProducts, plain.Products, plain.NumProducts)
	}
	if strings.Contains(card.Products, "product-odds") {
		t.Errorf("a sealed result carries odds labels: %s", card.Products)
	}
}
