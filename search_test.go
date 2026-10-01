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

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
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
		Config().BucketKeys = map[string]BucketKey{dumpsBucket: {AccessKey: keyID, AccessSecret: appKey}}
		bucket, err := openDumpsBucket(context.Background())
		if err == nil {
			err = loadScrapersNG(bucket, nil)
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
	return parseSearchOptionsNG(backend(), input, nil, nil, nil)
}

// skipWithoutDatastore skips a test or benchmark that needs real card data
// when TestMain has loaded none: MTGBAN_TEST_DATASTORE=off, or no datastore
// file. The empty backend served then matches no Forest.
func skipWithoutDatastore(tb testing.TB) {
	tb.Helper()
	_, err := backend().Match(&mtgmatcher.InputCard{Name: "Forest"})
	var alias *mtgmatcher.AliasingError
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
		allKeys, _ := searchAndFilter(currentDatastore(), config)
		searchParallelNG(allKeys, config)
	}
}

func BenchmarkSearchPrefix(b *testing.B) {
	config := parseSearchOptionsWrapper(fmt.Sprintf("%s sm:prefix", NameToBeFound))
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		allKeys, _ := searchAndFilter(currentDatastore(), config)
		searchParallelNG(allKeys, config)
	}
}

func BenchmarkSearchAllFromEdition(b *testing.B) {
	config := parseSearchOptionsWrapper(fmt.Sprintf("s:%s", EditionToBeFound))

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		allKeys, _ := searchAndFilter(currentDatastore(), config)
		searchParallelNG(allKeys, config)
	}
}

func BenchmarkSearchWithEdition(b *testing.B) {
	config := parseSearchOptionsWrapper(fmt.Sprintf("%s s:%s", NameToBeFound, EditionToBeFound))

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		allKeys, _ := searchAndFilter(currentDatastore(), config)
		searchParallelNG(allKeys, config)
	}
}

func BenchmarkSearchWithNumber(b *testing.B) {
	config := parseSearchOptionsWrapper(fmt.Sprintf("%s cn:%s", NameToBeFound, NumberToBeFound))

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		allKeys, _ := searchAndFilter(currentDatastore(), config)
		searchParallelNG(allKeys, config)
	}
}

func BenchmarkSearchWithEditionPrefix(b *testing.B) {
	config := parseSearchOptionsWrapper(fmt.Sprintf("%s s:%s sm:prefix", NameToBeFound, EditionToBeFound))

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		allKeys, _ := searchAndFilter(currentDatastore(), config)
		searchParallelNG(allKeys, config)
	}
}

func BenchmarkSearchOnlyRetail(b *testing.B) {
	config := SearchConfig{
		CleanQuery:  NameToBeFound,
		SkipBuylist: true,
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		allKeys, _ := searchAndFilter(currentDatastore(), config)
		searchParallelNG(allKeys, config)
	}
}

func BenchmarkSearchOnlyBuylist(b *testing.B) {
	config := SearchConfig{
		CleanQuery: NameToBeFound,
		SkipRetail: true,
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		allKeys, _ := searchAndFilter(currentDatastore(), config)
		searchParallelNG(allKeys, config)
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

	config := parseSearchOptionsNG(backend(), "s:leb serra", nil, nil, nil)
	results, err := searchAndFilter(currentDatastore(), config)
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
	config = parseSearchOptionsNG(backend(), "serra", nil, nil, nil)
	results, err = searchAndFilter(currentDatastore(), config)
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

	prevSellers, prevVendors := sellersPtr.Load(), vendorsPtr.Load()
	t.Cleanup(func() {
		sellersPtr.Store(prevSellers)
		vendorsPtr.Store(prevVendors)
	})
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
			sellersPtr.Store(&probe.sellers)
			vendorsPtr.Store(&probe.vendors)

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
