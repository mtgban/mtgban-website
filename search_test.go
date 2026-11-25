package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/matcher"
	"github.com/mtgban/go-mtgban/mtgban"

	"github.com/mtgban/mtgban-website/internal/infrastructure"
	"github.com/mtgban/mtgban-website/internal/sessionstore"
)

var NameToBeFound string
var EditionToBeFound string
var NumberToBeFound string

// testSite is the *site every test in this package shares unless it builds
// its own.
var testSite *site

func TestMain(m *testing.M) {
	LogDir = "logs"
	Config().DatastorePath = "allprintings5.json"
	Config().Game = DefaultGame
	testSite = newSite()
	Sessions = sessionstore.New(sessionHooks(testSite))
	// Built from the real nav before any test swaps it for its own.
	pageLabelSet()
	routeLabelSet()

	// Tests written against fixtures build their own site, so this lets them
	// run - under -race included - without the real datastore load; the
	// tests that need it skip.
	if os.Getenv("MTGBAN_TEST_DATASTORE") == "off" {
		log.Println("MTGBAN_TEST_DATASTORE=off: not loading the real datastore")
		os.Exit(m.Run())
	}

	// Best-effort datastore load: tests that need real card data skip when
	// it isn't loaded, most through skipWithoutDatastore, so a missing local
	// datastore file shouldn't take down the whole package's test run.
	err := testSite.loadDatastore(Config().DatastorePath)
	if err != nil {
		log.Println("loadDatastore skipped:", err)
		os.Exit(m.Run())
	}

	// A dev convenience: a B2 key pair in the environment loads every dump
	// of Config.Game. CI sets none and loads nothing.
	keyID, appKey := os.Getenv("B2_KEY_ID"), os.Getenv("B2_APP_KEY")
	if keyID != "" && appKey != "" {
		Config().BucketKeys = map[string]infrastructure.BucketKey{dumpsBucket: {AccessKey: keyID, AccessSecret: appKey}}
		bucket, err := openDumpsBucket(context.Background())
		if err == nil {
			err = testSite.loadScrapersNG(bucket, nil)
		}
		if err != nil {
			log.Println("loadScrapersNG skipped:", err)
			os.Exit(m.Run())
		}
	}

	uuid := randomUUID(backend(), false)
	co, err := backend().GetUUID(uuid)
	if err != nil {
		log.Fatalln(err)
	}

	NameToBeFound = co.Name
	EditionToBeFound = co.Edition
	NumberToBeFound = co.Number
	log.Println("Looking up", NameToBeFound, "from", co.SetCode, NumberToBeFound)

	os.Exit(m.Run())
}

func parseSearchOptionsWrapper(input string) SearchConfig {
	return parseSearchOptionsNG(backend(), currentPrices(), input, nil, nil, nil)
}

// skipWithoutDatastore skips a test or benchmark that needs real card data
// when TestMain has loaded none: MTGBAN_TEST_DATASTORE=off, or no datastore
// file. The empty backend served then matches no Forest.
func skipWithoutDatastore(tb testing.TB) {
	tb.Helper()
	_, err := backend().Match(&matcher.InputCard{Name: "Forest"})
	var alias *matcher.AliasingError
	if err != nil && !errors.As(err, &alias) {
		tb.Skip("no datastore loaded")
	}
}

// withSigMode runs one test under the given auth flags, restoring them after.
func withSigMode(t *testing.T, devMode, sigCheck bool) {
	t.Helper()
	savedDev, savedSig := DevMode, SigCheck
	t.Cleanup(func() { DevMode, SigCheck = savedDev, savedSig })
	DevMode, SigCheck = devMode, sigCheck
}

// A variant-qualified name (e.g. "(Borderless)") skips the plain-name search
// index and falls back to attemptMatch, which must still surface every finish
// of the matched printing. Regression guard: the foil used to be dropped
// because the variant already in the name clobbered the "Foil" match hint.
func TestAttemptMatchVariantIncludesFoil(t *testing.T) {
	skipWithoutDatastore(t)

	const query = "Meren of Clan Nel Toth (Borderless)"
	uuids, err := attemptMatch(backend(), query)
	if err != nil {
		t.Fatalf("attemptMatch(%q): %v", query, err)
	}

	var haveNonfoil, haveFoil bool
	for _, id := range uuids {
		co, err := backend().GetUUID(id)
		if err != nil || co.Etched {
			continue
		}
		if co.Foil {
			haveFoil = true
		} else {
			haveNonfoil = true
		}
	}
	if !haveNonfoil {
		t.Errorf("attemptMatch(%q) = %v: missing the nonfoil printing", query, uuids)
	}
	if !haveFoil {
		t.Errorf("attemptMatch(%q) = %v: missing the foil printing", query, uuids)
	}
}

func BenchmarkRegexp(b *testing.B) {
	input := fmt.Sprintf("%s sm:prefix cn:%s f:foil vendor:CK date>%s", NameToBeFound, NumberToBeFound, EditionToBeFound)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		parseSearchOptionsWrapper(input)
	}
}

func BenchmarkSearchExact(b *testing.B) {
	config := SearchConfig{
		CleanQuery: NameToBeFound,
	}

	for n := 0; n < b.N; n++ {
		allKeys, _ := searchAndFilter(currentDatastore(), currentPrices(), config)
		searchParallel(currentPrices(), allKeys, config)
	}
}

func BenchmarkSearchPrefix(b *testing.B) {
	config := parseSearchOptionsWrapper(fmt.Sprintf("%s sm:prefix", NameToBeFound))
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		allKeys, _ := searchAndFilter(currentDatastore(), currentPrices(), config)
		searchParallel(currentPrices(), allKeys, config)
	}
}

func BenchmarkSearchAllFromEdition(b *testing.B) {
	config := parseSearchOptionsWrapper(fmt.Sprintf("s:%s", EditionToBeFound))

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		allKeys, _ := searchAndFilter(currentDatastore(), currentPrices(), config)
		searchParallel(currentPrices(), allKeys, config)
	}
}

func BenchmarkSearchWithEdition(b *testing.B) {
	config := parseSearchOptionsWrapper(fmt.Sprintf("%s s:%s", NameToBeFound, EditionToBeFound))

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		allKeys, _ := searchAndFilter(currentDatastore(), currentPrices(), config)
		searchParallel(currentPrices(), allKeys, config)
	}
}

func BenchmarkSearchWithNumber(b *testing.B) {
	config := parseSearchOptionsWrapper(fmt.Sprintf("%s cn:%s", NameToBeFound, NumberToBeFound))

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		allKeys, _ := searchAndFilter(currentDatastore(), currentPrices(), config)
		searchParallel(currentPrices(), allKeys, config)
	}
}

func BenchmarkSearchWithEditionPrefix(b *testing.B) {
	config := parseSearchOptionsWrapper(fmt.Sprintf("%s s:%s sm:prefix", NameToBeFound, EditionToBeFound))

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		allKeys, _ := searchAndFilter(currentDatastore(), currentPrices(), config)
		searchParallel(currentPrices(), allKeys, config)
	}
}

func BenchmarkSearchOnlyRetail(b *testing.B) {
	config := SearchConfig{
		CleanQuery:  NameToBeFound,
		SkipBuylist: true,
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		allKeys, _ := searchAndFilter(currentDatastore(), currentPrices(), config)
		searchParallel(currentPrices(), allKeys, config)
	}
}

func BenchmarkSearchOnlyBuylist(b *testing.B) {
	config := SearchConfig{
		CleanQuery: NameToBeFound,
		SkipRetail: true,
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		allKeys, _ := searchAndFilter(currentDatastore(), currentPrices(), config)
		searchParallel(currentPrices(), allKeys, config)
	}
}

// The serra bug (#266): "Serra" is an exact (Vanguard) card name, so
// "s:leb serra" used to stop at the exact match, filter it out, and find
// nothing. When filters reject every exact match the search widens to the
// prefix pool; a bare exact query keeps its exact-match priority.
func TestSearchExactNameWidensWhenFiltered(t *testing.T) {
	if _, err := backend().GetSet("LEB"); err != nil {
		t.Skip("datastore not loaded")
	}
	if uuids, err := backend().SearchEquals("serra"); err != nil || len(uuids) == 0 {
		t.Skip("no exact card named Serra in this datastore")
	}

	config := parseSearchOptionsNG(backend(), currentPrices(), "s:leb serra", nil, nil, nil)
	results, err := searchAndFilter(currentDatastore(), currentPrices(), config)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 {
		t.Fatal("s:leb serra should widen to the prefix pool")
	}
	for _, uuid := range results {
		co, err := backend().GetUUID(uuid)
		if err != nil {
			t.Fatal(err)
		}
		if co.SetCode != "LEB" || !strings.HasPrefix(co.Name, "Serra") {
			t.Errorf("unexpected result %s (%s)", co.Name, co.SetCode)
		}
	}

	// Bare exact query: only the exact matches, no widening
	config = parseSearchOptionsNG(backend(), currentPrices(), "serra", nil, nil, nil)
	results, err = searchAndFilter(currentDatastore(), currentPrices(), config)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 {
		t.Fatal("bare serra should find the exact card")
	}
	for _, uuid := range results {
		co, _ := backend().GetUUID(uuid)
		if co.Name != "Serra" {
			t.Errorf("bare exact query widened unexpectedly to %s", co.Name)
		}
	}
}

// brokenStore is a seller whose inventory panics when read, as a scan would
// on a bug in a store's data. Its Info still answers, so only a scan panics.
type brokenStore struct{ mtgban.Seller }

func (brokenStore) Inventory() mtgban.InventoryRecord {
	panic("the inventory broke")
}

// brokenBuylist is brokenStore for a vendor.
type brokenBuylist struct{ mtgban.Vendor }

func (brokenBuylist) Buylist() mtgban.BuylistRecord {
	panic("the buylist broke")
}

// A store scan that panics is reported and costs only its side of the
// search: the page still renders, with the other side's price.
func TestSearchSurvivesAPanickingScan(t *testing.T) {
	skipWithoutDatastore(t)
	withSigMode(t, true, false)
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Search"] == nil {
		LogPages["Search"] = log.New(io.Discard, "", 0)
		defer delete(LogPages, "Search")
	}

	uuid := backend().GetUUIDs()[0]
	inventory := mtgban.InventoryRecord{}
	err := inventory.Add(uuid, &mtgban.InventoryEntry{Conditions: "NM", Price: 12.34, Quantity: 1, URL: "https://example.test"})
	if err != nil {
		t.Fatal(err)
	}
	buylist := mtgban.BuylistRecord{}
	err = buylist.Add(uuid, &mtgban.BuylistEntry{Conditions: "NM", BuyPrice: 12.34, Quantity: 1, URL: "https://example.test"})
	if err != nil {
		t.Fatal(err)
	}
	seller := mtgban.NewSellerFromInventory(inventory, mtgban.ScraperInfo{Name: "Seller", Shorthand: "SLR"})
	vendor := mtgban.NewVendorFromBuylist(buylist, mtgban.ScraperInfo{Name: "Vendor", Shorthand: "VND"})
	for _, probe := range []struct {
		job     string
		value   string
		sellers []mtgban.Seller
		vendors []mtgban.Vendor
	}{
		{"search sellers scan", "the inventory broke", []mtgban.Seller{brokenStore{seller}}, []mtgban.Vendor{vendor}},
		{"search vendors scan", "the buylist broke", []mtgban.Seller{seller}, []mtgban.Vendor{brokenBuylist{vendor}}},
	} {
		t.Run(probe.job, func(t *testing.T) {
			posts := serverWebhook(t)
			withPrices(t, probe.sellers, probe.vendors)

			rec := httptest.NewRecorder()
			testSite.Search(rec, httptest.NewRequest(http.MethodGet, "/search?q="+url.QueryEscape(uuid), nil))
			if rec.Code != http.StatusOK {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
			}
			if !strings.Contains(rec.Body.String(), "12.34") {
				t.Error("the other side's price is missing from the page")
			}

			message, _, source := panicReport(t, posts)
			if message != probe.value {
				t.Errorf("message = %q, want the scan's panic", message)
			}
			if source != "source job: "+probe.job {
				t.Errorf("source = %q, want the scan", source)
			}
		})
	}
}

// A search from one of the site's own pages is logged by its path alone, on
// either apex: the shared favorites page's query is the list's share id.
func TestRefererSourceKeepsTheSiteQueryOut(t *testing.T) {
	for _, tc := range []struct{ referer, want string }{
		{"https://mtgban.com/search/shared?id=abc", "/search/shared"},
		{"https://mtg.ban.cards/search/shared?id=abc", "/search/shared"},
		{"https://example.com/deck?id=abc", "<https://example.com/deck?id=abc>"},
		{"https://mtgban.com.example.com/x?id=abc", "<https://mtgban.com.example.com/x?id=abc>"},
		{"https://mtgban.com,evil.example/x?id=abc", "<https://mtgban.com,evil.example/x?id=abc>"},
	} {
		if got := refererSource(tc.referer); got != tc.want {
			t.Errorf("refererSource(%q) = %q, want %q", tc.referer, got, tc.want)
		}
	}
}

// TestSearchSellersCarryTCGItemLow pairs each TCGplayer row with the item
// price of the same sku, and puts it on no other store's row.
func TestSearchSellersCarryTCGItemLow(t *testing.T) {
	now := time.Now()
	listing := mtgban.InventoryRecord{"card": {
		{Conditions: "NM", Price: 7.5, Quantity: 1, InstanceID: "100"},
		{Conditions: "SP", Price: 6.5, Quantity: 1, InstanceID: "101"},
	}}
	itemLow := mtgban.InventoryRecord{"card": {
		{Conditions: "NM", Price: 6, Quantity: 1, InstanceID: "100"},
		{Conditions: "SP", Price: 5, Quantity: 1, InstanceID: "999"},
	}}
	sellers := []mtgban.Seller{
		mtgban.NewSellerFromInventory(listing, mtgban.ScraperInfo{Name: "TCGplayer", Shorthand: tcgListingsStore, NoQuantityInventory: true, InventoryTimestamp: &now}),
		mtgban.NewSellerFromInventory(itemLow, mtgban.ScraperInfo{Name: "TCGplayer Item Low", Shorthand: tcgItemLowStore, NoQuantityInventory: true, InventoryTimestamp: &now}),
		mtgban.NewSellerFromInventory(listing, mtgban.ScraperInfo{Name: "Other Store", Shorthand: "OS", InventoryTimestamp: &now}),
	}
	withPrices(t, sellers, currentPrices().vendors)

	config := SearchConfig{StoreFilters: []FilterStoreElem{{Name: "seller", Values: fixupStoreCodeNG(currentPrices(), tcgItemLowStore), Negate: true, OnlyForSeller: true}}}
	found := searchSellers(currentPrices(), []string{"card"}, config)
	for grade, want := range map[mtgban.Condition]float64{"NM": 6, "SP": 0} {
		entries := found["card"][grade]
		if len(entries) != 2 {
			t.Fatalf("%s: got %d entries, want 2: %+v", grade, len(entries), entries)
		}
		for _, entry := range entries {
			got := entry.Secondary
			if entry.Shorthand == tcgListingsStore && got != want {
				t.Errorf("%s: TCGplayer item price %v, want %v", grade, got, want)
			}
			if entry.Shorthand != tcgListingsStore && got != 0 {
				t.Errorf("%s: %s carries item price %v", grade, entry.Shorthand, got)
			}
		}
	}
}

// TestSearchSellersCarrySlab keeps a graded entry's slab on its row, as the
// text beside the store's name, and leaves a raw row without one.
func TestSearchSellersCarrySlab(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		slab *mtgban.Slab
		want string
	}{
		{nil, ""},
		{&mtgban.Slab{}, "Graded"},
		{&mtgban.Slab{Grader: "PSA", Score: 10}, "PSA 10"},
		{&mtgban.Slab{Grader: "BGS", Score: 9.5}, "BGS 9.5"},
		{&mtgban.Slab{Grader: "CGC", Score: 10, Label: "Pristine"}, "CGC 10 Pristine"},
		{&mtgban.Slab{Grader: "CGC", Label: "Less than 8"}, "CGC Less than 8"},
		{&mtgban.Slab{Grader: "PSA", Label: "PSA Authentic"}, "PSA Authentic"},
		{&mtgban.Slab{Grader: "CGC", Label: "cgc 8 signed"}, "cgc 8 signed"},
		{&mtgban.Slab{Grader: "PSA", Label: "Graded by PSA, small dent"}, "Graded by PSA, small dent"},
		{&mtgban.Slab{Label: "SGC 9"}, "SGC 9"},
	} {
		inv := mtgban.InventoryRecord{"card": {{Conditions: "NM", Price: 5, Slab: tc.slab}}}
		withPrices(t, []mtgban.Seller{mtgban.NewSellerFromInventory(inv, mtgban.ScraperInfo{Name: "Shop", Shorthand: "SHOP", InventoryTimestamp: &now})}, nil)
		rows := searchSellers(currentPrices(), []string{"card"}, SearchConfig{})["card"]["NM"]
		if len(rows) != 1 {
			t.Fatalf("%+v: got %d rows, want 1", tc.slab, len(rows))
		}
		if got := rows[0].SlabName(); got != tc.want {
			t.Errorf("%+v: got %q, want %q", tc.slab, got, tc.want)
		}
	}
}

// The seller rows name a graded copy's slab, and a raw or locked one shows
// none.
func TestSlabRendersBesideTheStore(t *testing.T) {
	const id = "card"
	slab := &mtgban.Slab{Grader: "CGC", Score: 8.5}
	for _, mobile := range []bool{false, true} {
		out := renderPage(t, "search.html", mobile, PageVars{
			UserNav:  &NavElem{Short: "b"},
			IsMobile: mobile,
			SearchVars: SearchVars{
				SearchRan: true,
				AllKeys:   []string{id},
				CondKeys:  []mtgban.Condition{"INDEX", "NM"},
				FoundSellers: map[string]map[mtgban.Condition][]SearchEntry{id: {"NM": {
					{ScraperName: "Graded", Shorthand: "GRD", Price: 5, URL: "https://example.com/g", Slab: slab},
					{ScraperName: "Raw", Shorthand: "RAW", Price: 4, URL: "https://example.com/r"},
					{ScraperName: "Locked", Shorthand: "LCK", Price: 3, Slab: slab, Locked: true},
				}}},
				SearchQuery: "a card",
			},
			Metadata: map[string]GenericCard{id: {Name: "A Card", SetCode: "TST"}},
		})
		want := `<span class="slab-name" title="CGC 8.5">CGC 8.5</span>`
		if n := strings.Count(out, want); n != 1 || strings.Count(out, "slab-name") != 1 {
			t.Errorf("mobile=%v: the rows carry %d slabs, want the graded one's alone", mobile, n)
		}
	}
}

// The arbitrage pages name a graded copy's slab, under its condition for the
// copy sold and under its price for the one compared with.
func TestArbitNamesTheSlab(t *testing.T) {
	skipWithoutDatastore(t)
	cardID := somePlainCardUUIDs(t, 1)[0]
	// DevMode so render reads templates from disk, and opens every source
	withSigMode(t, true, false)
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	for _, name := range []string{"Arbitrage", "Global"} {
		if LogPages[name] == nil {
			LogPages[name] = log.New(io.Discard, "", 0)
			t.Cleanup(func() { delete(LogPages, name) })
		}
	}
	stock := func(shorthand string, price float64, slab *mtgban.Slab) mtgban.Seller {
		return mtgban.NewSellerFromInventory(mtgban.InventoryRecord{cardID: {{Conditions: "NM", Price: price, Quantity: 2, URL: "u", Slab: slab}}},
			mtgban.ScraperInfo{Name: shorthand, Shorthand: shorthand, GradedMode: slab != nil})
	}
	withPrices(t, []mtgban.Seller{
		stock("RAW", 10, nil),
		stock("SLAB", 40, &mtgban.Slab{Grader: "PSA", Score: 9}),
	}, []mtgban.Vendor{
		mtgban.NewVendorFromBuylist(mtgban.BuylistRecord{cardID: {{Conditions: "NM", BuyPrice: 100, Quantity: 2, URL: "u"}}},
			mtgban.ScraperInfo{Name: "BUY", Shorthand: "BUY"}),
	})
	withConfigCopy(t)
	Config().Stores.GlobalAllowList = []string{"RAW"}
	Config().Stores.GlobalProbeList = []string{"SLAB"}

	const slab = `<span class="arb-slab" title="PSA 9">PSA 9</span>`
	for _, page := range []struct {
		target string
		serve  func(http.ResponseWriter, *http.Request)
		want   int
	}{
		{"/arbit?source=RAW", testSite.Arbit, 0},
		{"/arbit?source=SLAB", testSite.Arbit, 1},
		{"/reverse?source=BUY", testSite.Reverse, 1},
		{"/global?source=RAW&legit=0", testSite.Global, 1},
	} {
		rec := httptest.NewRecorder()
		page.serve(rec, httptest.NewRequest(http.MethodGet, page.target, nil))
		body := rec.Body.String()
		if !strings.Contains(body, `data-arb-id="`+cardID+`"`) {
			t.Errorf("%s: the card is not listed", page.target)
		}
		if n := strings.Count(body, slab); n != page.want {
			t.Errorf("%s: %d rows name the slab, want %d", page.target, n, page.want)
		}
	}
}
