package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

var NameToBeFound string
var EditionToBeFound string
var NumberToBeFound string

func TestMain(m *testing.M) {
	LogDir = "logs"
	Config.DatastorePath = "allprintings5.json"
	Config.Game = DefaultGame

	// Best-effort datastore load: tests that need real card data guard
	// themselves with t.Skip when the data isn't loaded, so a missing local
	// datastore file shouldn't take down the whole package's test run.
	if err := loadDatastore(Config.DatastorePath); err != nil {
		log.Println("loadDatastore skipped:", err)
		os.Exit(m.Run())
	}

	Config.ScraperConfig.BucketAccessKey = os.Getenv("B2_KEY_ID")
	Config.ScraperConfig.BucketSecretKey = os.Getenv("B2_APP_KEY")
	Config.ScraperConfig.BucketPath = os.Getenv("PATH_DATA")
	Config.ScraperConfig.BucketFileFormat = os.Getenv("PATH_SUFFIX")
	Config.ScraperConfig.Config = map[string]map[string][]string{
		"cardkingdom": {
			"retail": {"CK"},
		},
	}

	if err := loadScrapersNG(Config.ScraperConfig); err != nil {
		log.Println("loadScrapersNG skipped:", err)
		os.Exit(m.Run())
	}

	uuid := randomUUID(false)
	co, err := mtgmatcher.GetUUID(uuid)
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
	return parseSearchOptionsNG(input, nil, nil, nil)
}

// datastoreLoaded reports whether the mtgmatcher card datastore is available,
// so data-dependent tests can skip when it isn't loaded locally or in CI.
func datastoreLoaded() bool {
	_, err := mtgmatcher.Match(&mtgmatcher.InputCard{Name: "Forest"})
	var alias *mtgmatcher.AliasingError
	return err == nil || errors.As(err, &alias)
}

// A variant-qualified name (e.g. "(Borderless)") skips the plain-name search
// index and falls back to attemptMatch, which must still surface every finish
// of the matched printing. Regression guard: the foil used to be dropped
// because the variant already in the name clobbered the "Foil" match hint.
func TestAttemptMatchVariantIncludesFoil(t *testing.T) {
	if !datastoreLoaded() {
		t.Skip("mtgmatcher datastore not loaded")
	}

	const query = "Meren of Clan Nel Toth (Borderless)"
	uuids, err := attemptMatch(query)
	if err != nil {
		t.Fatalf("attemptMatch(%q): %v", query, err)
	}

	var haveNonfoil, haveFoil bool
	for _, id := range uuids {
		co, err := mtgmatcher.GetUUID(id)
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
		allKeys, _ := searchAndFilter(config)
		searchParallelNG(allKeys, config)
	}
}

func BenchmarkSearchPrefix(b *testing.B) {
	config := parseSearchOptionsWrapper(fmt.Sprintf("%s sm:prefix", NameToBeFound))
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		allKeys, _ := searchAndFilter(config)
		searchParallelNG(allKeys, config)
	}
}

func BenchmarkSearchAllFromEdition(b *testing.B) {
	config := parseSearchOptionsWrapper(fmt.Sprintf("s:%s", EditionToBeFound))

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		allKeys, _ := searchAndFilter(config)
		searchParallelNG(allKeys, config)
	}
}

func BenchmarkSearchWithEdition(b *testing.B) {
	config := parseSearchOptionsWrapper(fmt.Sprintf("%s s:%s", NameToBeFound, EditionToBeFound))

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		allKeys, _ := searchAndFilter(config)
		searchParallelNG(allKeys, config)
	}
}

func BenchmarkSearchWithNumber(b *testing.B) {
	config := parseSearchOptionsWrapper(fmt.Sprintf("%s cn:%s", NameToBeFound, NumberToBeFound))

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		allKeys, _ := searchAndFilter(config)
		searchParallelNG(allKeys, config)
	}
}

func BenchmarkSearchWithEditionPrefix(b *testing.B) {
	config := parseSearchOptionsWrapper(fmt.Sprintf("%s s:%s sm:prefix", NameToBeFound, EditionToBeFound))

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		allKeys, _ := searchAndFilter(config)
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
		allKeys, _ := searchAndFilter(config)
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
		allKeys, _ := searchAndFilter(config)
		searchParallelNG(allKeys, config)
	}
}

// The serra bug (#266): "Serra" is an exact (Vanguard) card name, so
// "s:leb serra" used to stop at the exact match, filter it out, and find
// nothing. When filters reject every exact match the search widens to the
// prefix pool; a bare exact query keeps its exact-match priority.
func TestSearchExactNameWidensWhenFiltered(t *testing.T) {
	if _, err := mtgmatcher.GetSet("LEB"); err != nil {
		t.Skip("datastore not loaded")
	}
	if uuids, err := mtgmatcher.SearchEquals("serra"); err != nil || len(uuids) == 0 {
		t.Skip("no exact card named Serra in this datastore")
	}

	config := parseSearchOptionsNG("s:leb serra", nil, nil, nil)
	results, err := searchAndFilter(config)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 {
		t.Fatal("s:leb serra should widen to the prefix pool")
	}
	for _, uuid := range results {
		co, err := mtgmatcher.GetUUID(uuid)
		if err != nil {
			t.Fatal(err)
		}
		if co.SetCode != "LEB" || !strings.HasPrefix(co.Name, "Serra") {
			t.Errorf("unexpected result %s (%s)", co.Name, co.SetCode)
		}
	}

	// Bare exact query: only the exact matches, no widening
	config = parseSearchOptionsNG("serra", nil, nil, nil)
	results, err = searchAndFilter(config)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 {
		t.Fatal("bare serra should find the exact card")
	}
	for _, uuid := range results {
		co, _ := mtgmatcher.GetUUID(uuid)
		if co.Name != "Serra" {
			t.Errorf("bare exact query widened unexpectedly to %s", co.Name)
		}
	}
}
