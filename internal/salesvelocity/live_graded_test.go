package salesvelocity

import (
	"cmp"
	"context"
	"fmt"
	"math/rand/v2"
	"os"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/matcher"
)

// TestGradedSalesLive loads the graded sales from the newspaper and prints
// what each filter dropped, with samples to read, and the snapshot's heap.
// Read-only, and skipped unless asked for:
//
//	NEWSPAPER_LIVE=1 NEWSPAPER_LIVE_CONFIG=<absolute path> POKEMON_PATH=<absolute path> go test ./internal/salesvelocity -run TestGradedSalesLive -v
func TestGradedSalesLive(t *testing.T) {
	b, db := liveNewspaperFor(t, matcher.GamePokemon, cmp.Or(os.Getenv("POKEMON_PATH"), "../../pokemon.json"))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	heap := func() int64 {
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return int64(m.HeapAlloc)
	}
	before := heap()
	start := time.Now()
	gb := newGradedBuilder(cardMatcher(b), cardFacts(b), time.Now())
	err := scanGraded(ctx, db, "Pokemon", gb)
	if err != nil {
		t.Fatal(err)
	}
	took := time.Since(start)
	var catchAll []string
	for cardID, card := range gb.cards {
		if card.catalog.number != "" && card.sales >= catchAllSales && float64(card.named) < catchAllShare*float64(card.sales) {
			co, _ := b.GetUUID(cardID)
			catchAll = append(catchAll, fmt.Sprintf("%s %s [%s]: %d of %d titles carry its number", co.Name, co.Number, co.Edition, card.named, card.sales))
		}
	}
	slices.Sort(catchAll)
	snap := gb.snapshot()
	numbers, st := gb.catalog, gb.st
	gb = nil
	after := heap()

	fmt.Printf("%s\nread in %s, snapshot heap %.1f MB\n\n", st.report(len(snap.Cards)), took.Round(time.Millisecond), float64(after-before)/1e6)

	// Samples of the sales the number check drops, split by whether only
	// the total disagrees.
	rows, err := db.QueryContext(ctx, GradedQuery, "Pokemon", GradedSince)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	match := cardMatcher(b)
	var totalOnly, otherDigits, foreign, lots, guessed []string
	var totalOnlyCount, otherDigitsCount int
	for rows.Next() {
		var row gradedRow
		err := rows.Scan(&row.ProductID, &row.Printing, &row.PrintingSource, &row.Company, &row.Grade,
			&row.Label, &row.Cents, &row.At, &row.Source, &row.ListingID, &row.BestOffer, &row.Title)
		if err != nil {
			t.Fatal(err)
		}
		cardID := match(row.ProductID, row.Printing)
		if cardID == "" {
			continue
		}
		title := cleanTitle(row.Title)
		n := numbers(cardID)
		switch {
		case titleForeign.MatchString(title) && !n.nonEnglish:
			foreign = append(foreign, title)
			continue
		case titleLot.MatchString(title):
			lots = append(lots, title)
			continue
		case row.PrintingSource == "default" && contradicts(title, row.Printing):
			guessed = append(guessed, row.Printing+" | "+title)
			continue
		}
		found := titleNumbers(row.Title)
		if n.number == "" || len(found) == 0 || slices.ContainsFunc(found, n.fits) {
			continue
		}
		co, _ := b.GetUUID(cardID)
		line := fmt.Sprintf("%s %s/%s [%s] | %s", co.Name, co.Number, co.SetTotal, co.Edition, row.Title)
		sameDigits := slices.ContainsFunc(found, func(f printedNumber) bool { return f.number == n.number })
		if sameDigits {
			totalOnlyCount++
			totalOnly = append(totalOnly, line)
		} else {
			otherDigitsCount++
			otherDigits = append(otherDigits, line)
		}
	}
	if rows.Err() != nil {
		t.Fatal(rows.Err())
	}
	sample := func(name string, n int, lines []string) {
		rand.Shuffle(len(lines), func(i, j int) { lines[i], lines[j] = lines[j], lines[i] })
		fmt.Printf("%s: %d\n", name, n)
		for _, line := range lines[:min(25, len(lines))] {
			fmt.Println("  ", line)
		}
		fmt.Println()
	}
	fmt.Println("dropped as catch-all:")
	for _, line := range catchAll {
		fmt.Println("  ", line)
	}
	fmt.Println()
	sample("another language", len(foreign), foreign)
	sample("lots", len(lots), lots)
	sample("against their guessed printing", len(guessed), guessed)
	sample("same digits, another total", totalOnlyCount, totalOnly)
	sample("other digits", otherDigitsCount, otherDigits)
	runtime.KeepAlive(snap)
}

// TestGradedSalesLiveSkipsAGameWithNone loads a game the newspaper has no
// slab sales for: the existence check answers and the full read never runs,
// leaving an empty snapshot. Read-only, and skipped like TestGradedSalesLive.
func TestGradedSalesLiveSkipsAGameWithNone(t *testing.T) {
	b, db := liveNewspaperFor(t, matcher.GamePokemon, cmp.Or(os.Getenv("POKEMON_PATH"), "../../pokemon.json"))
	var s GradedStore
	start := time.Now()
	result, problem := s.Load(context.Background(), db, b, "Magic: The Gathering", time.Now())
	took := time.Since(start)
	snap := s.Snapshot()
	if result != "" || problem != "" || snap == nil || len(snap.Cards) != 0 {
		t.Fatalf("result %q, problem %q, snapshot %+v; want an empty one and nothing to report", result, problem, snap)
	}
	fmt.Printf("a game with no slab sales: answered in %s\n", took.Round(time.Millisecond))
}
