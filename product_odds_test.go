package main

import (
	"regexp"
	"strings"
	"testing"
	"time"

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
		{0.014, true, "1 in 71"},
		{0.12, true, "1 in 8.3"}, // one decimal below 10, so 0.6 is not "1 in 2"
		{0.1, true, "1 in 10"},
		{0.0995, true, "1 in 10"}, // not "1 in 10.0"
		{0.7, true, "1 in 1.4"},
		{0.949, true, "1 in 1.1"},
		{0.6, true, "1 in 1.7"},
		{0.4, true, "1 in 2.5"},
		{0.95, true, "~0.95 each"}, // never "1 in 1": from 0.95 the count is the label
		{0.96, true, "~0.96 each"},
		{0.999, true, "~1 each"},
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

var oddsLabelShape = regexp.MustCompile(`^(1 in [0-9.]+|~[0-9.]+ each)$`)

// oddsSize is how many products the memo holds.
func oddsSize(o *productOdds) int {
	n := 0
	o.yield.Range(func(_, _ any) bool { n++; return true })
	return n
}

// summedCounts is the uncached path: a card's expected copies in a product,
// summed over the product's entries, and whether the product is random.
func summedCounts(t *testing.T, co, product *mtgmatcher.CardObject) (float64, bool) {
	t.Helper()
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
	return expected, sealed.IsRandom(backend(), product.SetCode, product.UUID)
}

func TestProductOddsLabelsARandomProduct(t *testing.T) {
	skipWithoutDatastore(t)
	co, product := randomSourceCard(t)

	odds := newProductOdds(backend())
	got, title := odds.labelFor(co)(product.UUID)
	if !oddsLabelShape.MatchString(got) {
		t.Fatalf("labelFor(%s)(%s) = %q, want a 1 in N or ~X each label", co.Name, product.Name, got)
	}

	expected, _ := summedCounts(t, co, product)
	if want := oddsLabel(expected, true); got != want {
		t.Errorf("labelFor = %q, want %q from the summed counts", got, want)
	}
	if want := expectedCopies(expected); title != want {
		t.Errorf("title = %q, want %q", title, want)
	}
}

// TestProductOddsCacheMatchesUncached asks the memo twice about many
// (card, product) pairs: the cached answer has to equal the uncached sum.
func TestProductOddsCacheMatchesUncached(t *testing.T) {
	skipWithoutDatastore(t)
	b := backend()
	odds := newProductOdds(b)
	pairs := 0
	for _, uuid := range b.GetUUIDs() {
		if pairs >= 200 {
			break
		}
		co, err := b.GetUUID(uuid)
		if err != nil || co.Sealed {
			continue
		}
		for _, productUUID := range cardobject2sources(co) {
			product, err := b.GetUUID(productUUID)
			if err != nil {
				continue
			}
			pairs++
			first, _ := odds.labelFor(co)(productUUID)
			second, _ := odds.labelFor(co)(productUUID)
			if want := oddsLabel(summedCounts(t, co, product)); first != want || second != want {
				t.Errorf("%s in %s: cached labels %q then %q, uncached %q", co.Name, product.Name, first, second, want)
			}
		}
	}
	if pairs == 0 {
		t.Skip("no card with a source product")
	}
}

func TestProductOddsNilMemoLabelsNothing(t *testing.T) {
	skipWithoutDatastore(t)
	co, _ := randomSourceCard(t)

	// The datastore before the first load has no memo; uuid2card then
	// builds the plain list.
	var odds *productOdds
	if odds.labelFor(co) != nil {
		t.Error("a nil memo answered with an odds function, want nil")
	}
}

func TestProductOddsSealedProductHasNoOddsFunction(t *testing.T) {
	skipWithoutDatastore(t)
	uuids := sealedUUIDs(t, 1)
	product, _ := backend().GetUUID(uuids[0])

	if newProductOdds(backend()).labelFor(product) != nil {
		t.Errorf("a sealed product %s got an odds function, want nil", product.Name)
	}
}

func TestProductOddsFixedProductHasNoLabel(t *testing.T) {
	skipWithoutDatastore(t)
	co, product := fixedSourceCard(t)

	odds := newProductOdds(backend())
	if got, title := odds.labelFor(co)(product.UUID); got != "" || title != "" {
		t.Errorf("labelFor on the fixed product %s = (%q, %q), want no label", product.Name, got, title)
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
	if got := oddsSize(odds); got != 1 {
		t.Errorf("memo holds %d products after three asks about one, want 1", got)
	}
}

func TestProductOddsUnknownProductIsEmpty(t *testing.T) {
	skipWithoutDatastore(t)
	co, _ := randomSourceCard(t)

	odds := newProductOdds(backend())
	if got, _ := odds.labelFor(co)("not-a-product"); got != "" {
		t.Errorf("labelFor on an unknown product = %q, want no label", got)
	}
	if got := oddsSize(odds); got != 0 {
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
	if got, _ := label(co.UUID); got != "" {
		t.Errorf("labelFor on a card as product = %q, want no label", got)
	}
	label(co.UUID)
	if got := oddsSize(odds); got != 1 {
		t.Errorf("a failing product left %d memo entries after two asks, want 1", got)
	}
}

// TestNewDatastoreStartsAnEmptyOddsMemo: the memo is built with the load
// and starts empty, so a reload drops what the previous one computed.
func TestNewDatastoreStartsAnEmptyOddsMemo(t *testing.T) {
	fixture := fixtureBackend("FIXTUREO", "Fixture Edition Odds", "2020-01-01", [][2]string{
		{"Fixture Card Odds", "1"},
	})
	ds := newSite().newDatastore(fixture, time.Now())
	if ds.odds == nil {
		t.Fatal("newDatastore left odds nil")
	}
	if ds.odds.b != fixture {
		t.Error("the memo reads a backend other than the load's")
	}
	if got := oddsSize(ds.odds); got != 0 {
		t.Errorf("a fresh memo holds %d products, want 0", got)
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
	odds := func(productUUID string) (string, string) {
		if productUUID == uuids[0] {
			return "1 in 12", "0.083 copies expected"
		}
		return "", ""
	}
	first, _ := backend().GetUUID(uuids[0])
	second, _ := backend().GetUUID(uuids[1])

	got, count := productsHTML(backend(), uuids, odds)
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
	asked := 0
	odds := func(string) (string, string) { asked++; return "1 in 2", "0.5 copies expected" }

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
	// The labels came from the datastore's memo, which now holds the product.
	if _, ok := ds.odds.yield.Load(product.UUID); !ok {
		t.Errorf("the datastore's memo does not hold %s after searchMetadata", product.Name)
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
