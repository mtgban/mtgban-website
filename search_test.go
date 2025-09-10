package main

import (
	"fmt"
	"log"
	"os"
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

	err := loadDatastore()
	if err != nil {
		log.Fatalln(err)
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

	err = loadScrapersNG(Config.ScraperConfig)
	if err != nil {
		log.Fatalln(err)
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
