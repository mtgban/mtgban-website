package salesvelocity

import (
	"context"
	"fmt"
	"runtime"
	"testing"
	"time"
)

// TestRecentSalesLive times a full load of the recent orders on the newspaper
// and prints what it holds: rows, its heap with one and two snapshots, and how many
// card grades reach RecentShown and recentDepth orders. Read-only, and
// skipped unless asked for:
//
//	NEWSPAPER_LIVE=1 NEWSPAPER_LIVE_CONFIG=<absolute path> go test ./internal/salesvelocity -run TestRecentSalesLive -v
func TestRecentSalesLive(t *testing.T) {
	b, db := liveNewspaper(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	const game = "Magic: The Gathering"
	now := time.Now()
	cutoff := startOfDay(now).AddDate(0, 0, -recentAge)

	heap := func() int64 {
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return int64(m.HeapAlloc)
	}
	before := heap()

	// A full load streams the rows into a new snapshot while the old one
	// still serves: the second load is that peak.
	start := time.Now()
	rb := newRecentBuilder(nil, cardMatcher(b), uint32(cutoff.Unix()))
	err := scanRecent(ctx, db, game, cutoff, time.Time{}, rb)
	if err != nil {
		t.Fatal(err)
	}
	first, st := rb.snapshot(nil), rb.st
	loadTook := time.Since(start)
	rb = nil
	one := heap()
	again := newRecentBuilder(nil, cardMatcher(b), uint32(cutoff.Unix()))
	err = scanRecent(ctx, db, game, cutoff, time.Time{}, again)
	if err != nil {
		t.Fatal(err)
	}
	second := again.snapshot(nil)
	again = nil
	two := heap()

	fmt.Print("| step | ms | count |\n|---|---:|---:|\n")
	fmt.Printf("| read, match and build (orders) | %d | %d |\n", loadTook.Milliseconds(), st.rows)
	fmt.Printf("| cards | | %d |\n\n", len(first.Cards))
	fmt.Printf("%s\n\n", st.report(true, len(first.Cards)))
	fmt.Printf("heap: one snapshot %.1f MB, two while a full load replaces one %.1f MB\n\n",
		float64(one-before)/1e6, float64(two-before)/1e6)

	var groups, shown, full [len(Grades)]int
	for _, r := range first.Cards {
		for i, orders := range r.Grades {
			if len(orders) == 0 {
				continue
			}
			groups[i]++
			if len(orders) >= RecentShown {
				shown[i]++
			}
			if len(orders) >= recentDepth {
				full[i]++
			}
		}
	}
	fmt.Printf("| grade | cards | ≥%d orders | ≥%d orders |\n|---|---:|---:|---:|\n", RecentShown, recentDepth)
	for i, grade := range Grades {
		fmt.Printf("| %s | %d | %d | %d |\n", grade, groups[i], shown[i], full[i])
	}
	runtime.KeepAlive(b)
	runtime.KeepAlive(second)
	runtime.KeepAlive(rb)
	runtime.KeepAlive(again)
}
