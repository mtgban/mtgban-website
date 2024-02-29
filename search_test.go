package main

import (
	"fmt"
	"log"
	"math/rand"
	"os"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

var NameToBeFound string
var EditionToBeFound string
var NumberToBeFound string

func TestMain(m *testing.M) {
	err := loadDatastore()
	if err != nil {
		log.Fatalln(err)
	}

	DevMode = true
	BenchMode = true

	loadScrapersNG()
	DatabaseLoaded = true

	sets := mtgmatcher.GetSets()
	for _, set := range sets {
		if len(set.Cards) == 0 {
			continue
		}
		index := rand.Intn(len(set.Cards))
		NameToBeFound = set.Cards[index].Name
		EditionToBeFound = set.Name
		NumberToBeFound = set.Cards[index].Number
		log.Println("Looking up", NameToBeFound, "from", set.Name, NumberToBeFound)
		break
	}

	os.Exit(m.Run())
}

func loadScrapersNG() {
	panic("unimplemented")
}

func BenchmarkRegexp(b *testing.B) {
	input := fmt.Sprintf("%s sm:prefix cn:%s f:foil vendor:CK date>%s", NameToBeFound, NumberToBeFound, EditionToBeFound)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		parseSearchOptionsNG(input, nil, nil)
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
	config := parseSearchOptionsNG(fmt.Sprintf("%s sm:prefix", NameToBeFound), nil, nil)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		allKeys, _ := searchAndFilter(config)
		searchParallelNG(allKeys, config)
	}
}

func BenchmarkSearchAllFromEdition(b *testing.B) {
	config := parseSearchOptionsNG(fmt.Sprintf("s:%s", EditionToBeFound), nil, nil)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		allKeys, _ := searchAndFilter(config)
		searchParallelNG(allKeys, config)
	}
}

func BenchmarkSearchWithEdition(b *testing.B) {
	config := parseSearchOptionsNG(fmt.Sprintf("%s s:%s", NameToBeFound, EditionToBeFound), nil, nil)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		allKeys, _ := searchAndFilter(config)
		searchParallelNG(allKeys, config)
	}
}

func BenchmarkSearchWithNumber(b *testing.B) {
	config := parseSearchOptionsNG(fmt.Sprintf("%s cn:%s", NameToBeFound, NumberToBeFound), nil, nil)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		allKeys, _ := searchAndFilter(config)
		searchParallelNG(allKeys, config)
	}
}

func BenchmarkSearchWithEditionPrefix(b *testing.B) {
	config := parseSearchOptionsNG(fmt.Sprintf("%s s:%s sm:prefix", NameToBeFound, EditionToBeFound), nil, nil)

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
