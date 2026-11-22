package salesvelocity

import (
	"strings"
	"testing"
	"time"
	"weak"

	"github.com/mtgban/go-mtgban/matcher"
)

var recentNow = time.Date(2026, 11, 22, 9, 0, 0, 0, time.UTC)

func recentAt(days int, hour int) time.Time {
	return recentNow.AddDate(0, 0, -days).Truncate(24 * time.Hour).Add(time.Duration(hour) * time.Hour)
}

func recentMatch(productID int64, variant string) string {
	switch {
	case productID == 1 && variant == "Normal":
		return "card-a"
	case productID == 1 && variant == "Foil":
		return "card-a_f"
	case productID == 2:
		// Two printings of one product resolve to one card.
		return "card-b"
	}
	return ""
}

// buildRecent runs rows through a builder on top of base, nil for a full load.
func buildRecent(base *RecentSnapshot, rows []recentRow, match func(productID int64, variant string) string, cutoff uint32) (*RecentSnapshot, recentStats) {
	rb := newRecentBuilder(base, match, cutoff)
	for _, row := range rows {
		rb.add(row)
	}
	return rb.snapshot(base), rb.st
}

func row(product int64, variant, condition string, at time.Time, cents int64) recentRow {
	return recentRow{ProductID: product, Variant: variant, Condition: condition, At: at, Cents: cents, Qty: 1, Pulled: recentNow}
}

func recentCutoff() uint32 {
	return uint32(startOfDay(recentNow).AddDate(0, 0, -recentAge).Unix())
}

func dates(orders []Order) []string {
	var out []string
	for _, o := range orders {
		out = append(out, time.Unix(int64(o.At), 0).UTC().Format("01-02T15"))
	}
	return out
}

func TestBuildRecentGradesAndCuts(t *testing.T) {
	var rows []recentRow
	for d := range recentDepth + 3 {
		rows = append(rows, row(1, "Normal", "Near Mint", recentAt(d, 10), 500))
	}
	rows = append(rows,
		row(1, "Normal", "Damaged", recentAt(1, 10), 100),
		row(1, "Foil", "Lightly Played", recentAt(2, 10), 900),
		row(1, "Normal", "Unopened", recentAt(1, 10), 100),
		row(9, "Normal", "Near Mint", recentAt(1, 10), 100),
		row(1, "Normal", "Near Mint", recentAt(recentAge+1, 10), 100),
	)
	snap, st := buildRecent(nil, rows, recentMatch, recentCutoff())

	a, found := snap.For("card-a")
	if !found {
		t.Fatal("card-a has no orders")
	}
	nm := dates(a.Grades[0])
	if len(nm) != recentDepth || nm[0] != recentAt(0, 10).Format("01-02T15") || nm[recentDepth-1] != recentAt(recentDepth-1, 10).Format("01-02T15") {
		t.Errorf("NM orders = %v, want the newest %d, newest first", nm, recentDepth)
	}
	if len(a.Grades[4]) != 1 || a.Grades[4][0].Cents != 100 {
		t.Errorf("PO orders = %+v, want the Damaged one", a.Grades[4])
	}
	foil, _ := snap.For("card-a_f")
	if foil == nil || len(foil.Grades[1]) != 1 {
		t.Errorf("foil SP orders = %+v, want one", foil)
	}
	if st.unmatched != 1 || st.old != 1 || st.dropped["Unopened"] != 1 {
		t.Errorf("stats = %+v, want 1 unmatched, 1 old, 1 Unopened dropped", st)
	}
	if !snap.Pulled.Equal(recentNow) {
		t.Errorf("Pulled = %v, want the newest stamp read", snap.Pulled)
	}
	report := st.report(true, len(snap.Cards))
	if !strings.Contains(report, `no grade for "Unopened" 1`) || !strings.Contains(report, "(full)") {
		t.Errorf("report = %q", report)
	}
}

func TestBuildRecentKeepsDistinctOrdersAndDropsRepeats(t *testing.T) {
	sameSecond := recentAt(1, 10)
	other := row(2, "Normal", "Near Mint", sameSecond.Add(250*time.Millisecond), 500)
	listed := row(2, "Normal", "Near Mint", sameSecond, 500)
	listed.ListingID = "photo-1"
	rows := []recentRow{
		row(2, "Normal", "Near Mint", sameSecond, 500),
		// Two printings that resolve to one card sold at the same second and price.
		row(2, "Holofoil", "Near Mint", sameSecond, 500),
		// Another order in the same second, and one from a listing of its own.
		other, listed,
		// The same order read again.
		row(2, "Normal", "Near Mint", sameSecond, 500),
	}
	snap, _ := buildRecent(nil, rows, recentMatch, recentCutoff())
	b, _ := snap.For("card-b")
	if got := len(b.Grades[0]); got != 4 {
		t.Errorf("card-b NM holds %d orders, want 4: the repeat dropped, every distinct order kept", got)
	}
}

func TestBuildRecentCutsABusyGradeAsItGoes(t *testing.T) {
	rb := newRecentBuilder(nil, recentMatch, recentCutoff())
	for d := range 5 * recentDepth {
		rb.add(row(1, "Normal", "Near Mint", recentAt(d%300, d%24), 500))
		if n := len(rb.added["card-a"].Grades[0]); n >= 2*recentDepth {
			t.Fatalf("the grade grew to %d while loading", n)
		}
	}
	snap := rb.snapshot(nil)
	a, _ := snap.For("card-a")
	if got := dates(a.Grades[0]); len(got) != recentDepth || got[0] != recentAt(0, 0).Format("01-02T15") {
		t.Errorf("NM = %v, want the newest %d", got, recentDepth)
	}
}

func TestBuildRecentIncrementalKeepsUntouchedCards(t *testing.T) {
	base, _ := buildRecent(nil, []recentRow{
		row(1, "Normal", "Near Mint", recentAt(3, 10), 500),
		row(2, "Normal", "Near Mint", recentAt(3, 10), 500),
	}, recentMatch, recentCutoff())
	before, _ := base.For("card-b")
	oldA, _ := base.For("card-a")
	oldOrders := oldA.Grades[0]

	later := recentNow.Add(time.Hour)
	// The overlap reads the stored order again beside a new one.
	again := row(1, "Normal", "Near Mint", recentAt(3, 10), 500)
	fresh := row(1, "Normal", "Near Mint", recentAt(0, 10), 600)
	fresh.Pulled = later
	next, _ := buildRecent(base, []recentRow{again, fresh}, recentMatch, recentCutoff())

	after, _ := next.For("card-b")
	if after != before {
		t.Error("an untouched card was rebuilt")
	}
	a, _ := next.For("card-a")
	if got := dates(a.Grades[0]); len(got) != 2 || got[0] != recentAt(0, 10).Format("01-02T15") {
		t.Errorf("card-a NM = %v, want the new order first and the repeat dropped", got)
	}
	if len(oldOrders) != 1 || len(oldA.Grades[0]) != 1 {
		t.Error("the base snapshot was changed")
	}
	if !next.Pulled.Equal(later) {
		t.Errorf("Pulled = %v, want %v", next.Pulled, later)
	}
}

func TestNewOrderClamps(t *testing.T) {
	o, ok := newOrder(recentRow{At: recentNow, Cents: -5, Qty: 1 << 20})
	if !ok || o.Cents != 0 || o.Qty != 65535 {
		t.Errorf("newOrder = %+v %v, want cents 0 and qty clamped", o, ok)
	}
	o, _ = newOrder(recentRow{At: recentNow, Cents: 100, Qty: 0})
	if o.Qty != 1 {
		t.Errorf("qty = %d, want at least 1", o.Qty)
	}
	_, ok = newOrder(recentRow{At: time.Date(1960, 1, 1, 0, 0, 0, 0, time.UTC)})
	if ok {
		t.Error("a date before the epoch fit")
	}
}

func TestRecentGroups(t *testing.T) {
	r := &Recent{}
	for d := range 7 {
		r.Grades[0] = append(r.Grades[0], Order{At: uint32(recentAt(d, 10).Unix()), Cents: 1234, Qty: 1})
	}
	r.Grades[3] = []Order{{At: uint32(time.Date(2025, 12, 30, 0, 0, 0, 0, time.UTC).Unix()), Cents: 5, Qty: 3}}

	groups := r.Groups(recentNow)
	if len(groups) != 2 || groups[0].Grade != "NM" || groups[1].Grade != "HP" {
		t.Fatalf("groups = %+v, want NM then HP", groups)
	}
	if len(groups[0].Shown) != RecentShown || len(groups[0].More) != 2 {
		t.Errorf("NM shown %d, more %d, want %d and 2", len(groups[0].Shown), len(groups[0].More), RecentShown)
	}
	if got := groups[0].Shown[0]; got != (Line{Date: "Nov 22", Source: "TCGplayer", Price: "$12.34"}) {
		t.Errorf("NM first line = %+v", got)
	}
	if got := groups[1].Shown[0]; got != (Line{Date: "Dec 30, 2025", Source: "TCGplayer", Price: "$0.05", Qty: "×3"}) {
		t.Errorf("HP line = %+v", got)
	}
	var none *Recent
	if none.Groups(recentNow) != nil {
		t.Error("a card with no orders has groups")
	}
}

func TestRecentQueryReadsOnlyNewStamps(t *testing.T) {
	for _, want := range []string{"FROM tcgplayerrecentsalemodel", "order_date >= $1", "pulled_at > $2", "game_name = $3"} {
		if !strings.Contains(RecentQuery, want) {
			t.Errorf("RecentQuery lacks %q", want)
		}
	}
	if got := naive(time.Date(2026, 11, 22, 4, 0, 0, 0, time.FixedZone("EST", -5*3600))); got != "2026-11-22 09:00:00" {
		t.Errorf("naive = %q, want the UTC wall clock", got)
	}
}

func TestFullLoad(t *testing.T) {
	b := &matcher.Backend{}
	loaded := &RecentSnapshot{Full: recentNow.Add(-time.Hour), Backend: weak.Make(b)}
	cases := []struct {
		name    string
		current *RecentSnapshot
		b       *matcher.Backend
		now     time.Time
		want    bool
	}{
		{"none loaded", nil, b, recentNow, true},
		{"same day", loaded, b, recentNow, false},
		{"a new day", loaded, b, recentNow.AddDate(0, 0, 1), true},
		{"a new backend", loaded, &matcher.Backend{}, recentNow, true},
	}
	for _, c := range cases {
		if got := fullLoad(c.current, c.b, c.now); got != c.want {
			t.Errorf("%s: fullLoad = %v, want %v", c.name, got, c.want)
		}
	}
}
