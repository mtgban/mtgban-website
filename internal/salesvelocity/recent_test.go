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

func recentMatch(row recentRow) string {
	switch {
	case row.ProductID == 1 && row.Variant == "Normal":
		return "card-a"
	case row.ProductID == 1 && row.Variant == "Foil":
		return "card-a_f"
	case row.ProductID == 2:
		// Two printings of one product resolve to one card.
		return "card-b"
	case row.ProductID == 3:
		return "box"
	}
	return ""
}

func TestRecentMatcherSealed(t *testing.T) {
	product := func(uuid, name, id string) *matcher.CardObject {
		return &matcher.CardObject{Sealed: true, Card: matcher.Card{
			UUID: uuid, Name: name,
			Identifiers: map[string]string{"tcgplayerProductId": id},
		}}
	}
	b := &matcher.Backend{
		AllSealedUUIDs: []string{"box", "drop", "drop-foil"},
		UUIDs: map[string]*matcher.CardObject{
			"box":       product("box", "Booster Box", "10"),
			"drop":      product("drop", "Drop", "20"),
			"drop-foil": product("drop-foil", "Drop Foil", "20"),
		},
	}
	match := recentMatcher(b)
	cases := []struct {
		product int64
		want    string
	}{
		{10, "box"},
		// The listing two products share.
		{20, ""},
		{30, ""},
	}
	for _, c := range cases {
		got := match(row(c.product, "Normal", "Unopened", recentNow, 100))
		if got != c.want {
			t.Errorf("product %d is %q, want %q", c.product, got, c.want)
		}
	}
	// A graded condition is a card's, whatever product it names.
	got := match(row(10, "Normal", "Near Mint", recentNow, 100))
	if got != "" {
		t.Errorf("a Near Mint order of a sealed product is %q, want none", got)
	}
}

// buildRecent runs rows through a builder on top of base, nil for a full load.
func buildRecent(base *RecentSnapshot, rows []recentRow, match func(row recentRow) string) (*RecentSnapshot, recentStats) {
	rb := newRecentBuilder(base, match)
	for _, row := range rows {
		rb.add(row)
	}
	return rb.snapshot(base), rb.st
}

func row(product int64, variant, condition string, at time.Time, cents int64) recentRow {
	return recentRow{ProductID: product, Variant: variant, Condition: condition, At: at, Cents: cents, Qty: 1, Pulled: recentNow}
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
		row(1, "Normal", "Graded", recentAt(1, 10), 100),
		row(3, "Normal", "Unopened", recentAt(1, 10), 12000),
		row(9, "Normal", "Near Mint", recentAt(1, 10), 100),
		// Years old, and still the newest Heavily Played.
		row(1, "Normal", "Heavily Played", recentAt(3*365, 10), 300),
	)
	snap, st := buildRecent(nil, rows, recentMatch)

	a, found := snap.For("card-a")
	if !found {
		t.Fatal("card-a has no orders")
	}
	nm := dates(a.Grades[0])
	if len(nm) != recentDepth || nm[0] != recentAt(0, 10).Format("01-02T15") || nm[recentDepth-1] != recentAt(recentDepth-1, 10).Format("01-02T15") {
		t.Errorf("NM orders = %v, want the newest %d, newest first", nm, recentDepth)
	}
	if len(a.Grades[3]) != 1 || a.Grades[3][0].Cents != 300 {
		t.Errorf("HP orders = %+v, want the old one", a.Grades[3])
	}
	if len(a.Grades[4]) != 1 || a.Grades[4][0].Cents != 100 {
		t.Errorf("PO orders = %+v, want the Damaged one", a.Grades[4])
	}
	foil, _ := snap.For("card-a_f")
	if foil == nil || len(foil.Grades[1]) != 1 {
		t.Errorf("foil SP orders = %+v, want one", foil)
	}
	box, _ := snap.For("box")
	if box == nil || len(box.Grades[5]) != 1 {
		t.Fatalf("box orders = %+v, want one unopened", box)
	}
	groups := box.Groups()
	if len(groups) != 1 || groups[0].Grade != "Unopened" || groups[0].Avg != "120.00" {
		t.Errorf("box groups = %+v, want one Unopened averaging 120.00", groups)
	}
	if st.unmatched != 1 || st.undated != 0 || st.dropped["Graded"] != 1 {
		t.Errorf("stats = %+v, want 1 unmatched, 1 Graded dropped", st)
	}
	if !snap.Pulled.Equal(recentNow) {
		t.Errorf("Pulled = %v, want the newest stamp read", snap.Pulled)
	}
	report := st.report(true, len(snap.Cards))
	if !strings.Contains(report, `no grade for "Graded" 1`) || !strings.Contains(report, "(full)") {
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
	snap, _ := buildRecent(nil, rows, recentMatch)
	b, _ := snap.For("card-b")
	if got := len(b.Grades[0]); got != 4 {
		t.Errorf("card-b NM holds %d orders, want 4: the repeat dropped, every distinct order kept", got)
	}
}

func TestBuildRecentCutsABusyGradeAsItGoes(t *testing.T) {
	rb := newRecentBuilder(nil, recentMatch)
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
	}, recentMatch)
	before, _ := base.For("card-b")
	oldA, _ := base.For("card-a")
	oldOrders := oldA.Grades[0]

	later := recentNow.Add(time.Hour)
	// The overlap reads the stored order again beside a new one.
	again := row(1, "Normal", "Near Mint", recentAt(3, 10), 500)
	fresh := row(1, "Normal", "Near Mint", recentAt(0, 10), 600)
	fresh.Pulled = later
	next, _ := buildRecent(base, []recentRow{again, fresh}, recentMatch)

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

	groups := r.Groups()
	if len(groups) != 2 || groups[0].Grade != "NM" || groups[1].Grade != "HP" {
		t.Fatalf("groups = %+v, want NM then HP", groups)
	}
	if len(groups[0].Shown) != RecentShown || len(groups[0].More) != 2 {
		t.Errorf("NM shown %d, more %d, want %d and 2", len(groups[0].Shown), len(groups[0].More), RecentShown)
	}
	want := Line{Date: "2026-11-22", Time: "2026-11-22 10:00 UTC", Source: "TCGplayer", Price: "12.34"}
	if got := groups[0].Shown[0]; got != want {
		t.Errorf("NM first line = %+v, want %+v", got, want)
	}
	want = Line{Date: "2025-12-30", Time: "2025-12-30 00:00 UTC", Source: "TCGplayer", Price: "0.05", Qty: "×3"}
	if got := groups[1].Shown[0]; got != want {
		t.Errorf("HP line = %+v, want %+v", got, want)
	}
	if groups[0].Avg != "12.34" || groups[1].Avg != "0.05" {
		t.Errorf("averages = %q, %q", groups[0].Avg, groups[1].Avg)
	}
	var none *Recent
	if none.Groups() != nil {
		t.Error("a card with no orders has groups")
	}
}

func TestRecentQueryReadsOnlyNewStamps(t *testing.T) {
	for _, want := range []string{"FROM tcgplayerrecentsalemodel", "pulled_at > $1", "game_name = $2"} {
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
	loaded := &RecentSnapshot{Pulled: recentNow, Full: recentNow.Add(-time.Hour), Backend: weak.Make(b)}
	empty := &RecentSnapshot{Full: recentNow.Add(-time.Hour), Backend: weak.Make(b)}
	cases := []struct {
		name    string
		current *RecentSnapshot
		b       *matcher.Backend
		now     time.Time
		want    bool
	}{
		{"none loaded", nil, b, recentNow, true},
		{"same day", loaded, b, recentNow, false},
		{"same day, none read", empty, b, recentNow, true},
		{"a new day", loaded, b, recentNow.AddDate(0, 0, 1), true},
		{"a new backend", loaded, &matcher.Backend{}, recentNow, true},
	}
	for _, c := range cases {
		if got := fullLoad(c.current, c.b, c.now); got != c.want {
			t.Errorf("%s: fullLoad = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestAverageWeighsCopies(t *testing.T) {
	orders := []Order{{Cents: 1000, Qty: 3}, {Cents: 2000, Qty: 1}}
	if got := averageText(orders); got != "12.50" {
		t.Errorf("averageText = %q, want 12.50: three copies at $10, one at $20", got)
	}
	if averageText(nil) != "" {
		t.Error("no orders has an average")
	}
}
