package observability

import (
	"context"
	"database/sql"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lib/pq"
)

func TestDayQueryValidate(t *testing.T) {
	to := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
	good := DayQuery{Instance: "magic", To: to, Days: 90, Step: 30}
	if err := good.validate(); err != nil {
		t.Fatalf("a good query is refused: %v", err)
	}
	for name, q := range map[string]DayQuery{
		"no instance":      {To: to, Days: 90},
		"no days":          {Instance: "magic", To: to},
		"too many days":    {Instance: "magic", To: to, Days: 401},
		"negative step":    {Instance: "magic", To: to, Days: 90, Step: -1},
		"negative mincell": {Instance: "magic", To: to, Days: 90, MinCell: -1},
		"no day":           {Instance: "magic", Days: 90},
	} {
		if q.validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestDayTotalsRefusesABadQueryUnsent(t *testing.T) {
	// c.db is nil: a query that reached it would panic.
	if _, err := (&Client{}).DayTotals(context.Background(), DayQuery{Instance: "magic", Days: 90}); err == nil {
		t.Fatal("a query with no day is sent")
	}
}

func TestDayTotalsSQLSplitsOnlyWhenAsked(t *testing.T) {
	to := time.Date(2026, 11, 10, 15, 0, 0, 0, time.UTC)
	plain, args := dayTotalsSQL(DayQuery{Instance: "magic", To: to, Days: 90})
	if strings.Contains(plain, ", tier,") || strings.Contains(plain, ", device,") {
		t.Error("an unsplit query selects tier or device")
	}
	if args[1] != "2026-11-10" || args[3] != 90 {
		t.Errorf("day %v step %v, want 2026-11-10 and 90 (Step 0 is one period)", args[1], args[3])
	}
	split, _ := dayTotalsSQL(DayQuery{Instance: "magic", To: to, Days: 90, ByTier: true, ByDevice: true})
	if !strings.Contains(split, "value, tier, device,") {
		t.Error("a split query does not select tier and device")
	}
	for _, q := range []string{plain, split} {
		if !strings.Contains(q, "device IN ('job', 'discord')") {
			t.Error("job and discord rows must pass the signed filter")
		}
	}
}

func TestDayTotalsSQLReadsToAsAUTCDate(t *testing.T) {
	// 01:00 on the 11th east of UTC is still the 10th in UTC.
	to := time.Date(2026, 11, 11, 1, 0, 0, 0, time.FixedZone("east", 3*3600))
	if _, args := dayTotalsSQL(DayQuery{Instance: "magic", To: to, Days: 1}); args[1] != "2026-11-10" {
		t.Errorf("day %v, want 2026-11-10", args[1])
	}
}

var reportTo = time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)

// reportDay is reportTo shifted by n days.
func reportDay(n int) time.Time {
	return reportTo.AddDate(0, 0, n)
}

func dayTotals(t *testing.T, c *Client, q DayQuery) []DayTotal {
	t.Helper()
	got, err := c.DayTotals(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestDayTotalsSumsAPeriod(t *testing.T) {
	c, inst := featureClient(t)
	signed := Dims{Instance: inst, Tier: "Any", Device: "desktop", Signed: true}
	names := []string{"search.sort"}
	replaceDay(t, c, reportDay(0), inst, names, Row{Dims: signed, Name: "search.sort", Value: "alpha", N: 3})
	replaceDay(t, c, reportDay(-2), inst, names, Row{Dims: signed, Name: "search.sort", Value: "alpha", N: 4})
	got := dayTotals(t, c, DayQuery{Instance: inst, To: reportTo, Days: 30})
	if len(got) != 1 {
		t.Fatalf("%d rows, want 1: %+v", len(got), got)
	}
	r := got[0]
	if r.N != 7 || r.Days != 2 || r.Period != 0 || !r.First.Equal(reportDay(-2)) || !r.Last.Equal(reportDay(0)) {
		t.Errorf("got %+v, want n 7 over 2 days from %v to %v in period 0", r, reportDay(-2), reportDay(0))
	}
	if r.Name != "search.sort" || r.Value != "alpha" || r.Tier != "" || r.Device != "" {
		t.Errorf("key %+v", r)
	}
}

func TestDayTotalsPeriods(t *testing.T) {
	c, inst := featureClient(t)
	signed := Dims{Instance: inst, Tier: "Any", Device: "desktop", Signed: true}
	names := []string{"search.sort"}
	row := Row{Dims: signed, Name: "search.sort", Value: "alpha", N: 1}
	for _, d := range []int{0, -21, -40, -60} { // 11-10, 10-20, 10-01, 09-11
		replaceDay(t, c, reportDay(d), inst, names, row)
	}
	got := dayTotals(t, c, DayQuery{Instance: inst, To: reportTo, Days: 60, Step: 30})
	if len(got) != 2 {
		t.Fatalf("%d rows, want 2: %+v", len(got), got)
	}
	if p := got[0]; p.Period != 0 || p.N != 2 || !p.First.Equal(reportDay(-21)) || !p.Last.Equal(reportDay(0)) {
		t.Errorf("period 0 %+v, want 10-20 and 11-10", p)
	}
	if p := got[1]; p.Period != 1 || p.N != 1 || !p.First.Equal(reportDay(-40)) {
		t.Errorf("period 1 %+v, want 10-01 alone (09-11 is outside)", p)
	}
}

func TestDayTotalsWindowEdges(t *testing.T) {
	c, inst := featureClient(t)
	signed := Dims{Instance: inst, Tier: "Any", Device: "desktop", Signed: true}
	names := []string{"search.sort"}
	for _, tc := range []struct {
		to         time.Time
		days, step int
	}{
		{reportTo, 60, 30},
		{reportTo.AddDate(0, 0, -7), 60, 30}, // the digest's shifted window
		{reportTo, 10, 4},                    // the oldest period is two days
		{reportTo, 7, 0},                     // one period
	} {
		if _, err := c.db.Exec("DELETE FROM feature_days WHERE instance = $1", inst); err != nil {
			t.Fatal(err)
		}
		step := tc.step
		if step == 0 {
			step = tc.days
		}
		// Each offset from To is its own value, so its period is read off its row.
		want := map[int]int{0: 0, -(step - 1): 0, -(tc.days - 1): (tc.days - 1) / step}
		if step < tc.days {
			want[-step] = 1
		}
		offsets := []int{1, 0, -(step - 1), -step, -(tc.days - 1), -tc.days}
		slices.Sort(offsets)
		for _, off := range slices.Compact(offsets) {
			replaceDay(t, c, tc.to.AddDate(0, 0, off), inst, names,
				Row{Dims: signed, Name: "search.sort", Value: fmt.Sprintf("d%+d", off), N: 1})
		}
		got := dayTotals(t, c, DayQuery{Instance: inst, To: tc.to, Days: tc.days, Step: tc.step})
		seen := map[int]int{}
		for _, r := range got {
			var off int
			if _, err := fmt.Sscanf(r.Value, "d%d", &off); err != nil {
				t.Fatal(err)
			}
			seen[off] = r.Period
			if day := tc.to.AddDate(0, 0, off); !r.First.Equal(day) || !r.Last.Equal(day) || r.Days != 1 {
				t.Errorf("to %s days %d step %d: offset %d row %+v", sqlDate(tc.to), tc.days, tc.step, off, r)
			}
		}
		if !maps.Equal(seen, want) {
			t.Errorf("to %s days %d step %d: offsets in periods %v, want %v (To+1 and To-Days outside)",
				sqlDate(tc.to), tc.days, tc.step, seen, want)
		}
	}
}

func TestDayTotalsFilters(t *testing.T) {
	c, inst := featureClient(t)
	key := func(d Dims) Row { return Row{Dims: d, Name: "search.sort", Value: "alpha", N: 1} }
	replaceDay(t, c, reportDay(0), inst, []string{"search.sort"},
		key(Dims{Instance: inst, Tier: "Any", Device: "desktop", Signed: true}),
		key(Dims{Instance: inst, Tier: "Any", Device: "desktop"}),
		key(Dims{Instance: inst, Tier: "Any", Device: "desktop", Signed: true, Bot: true}),
		key(Dims{Instance: inst, Device: "job"}),
	)
	for _, tc := range []struct {
		signed, humans bool
		want           int64
	}{
		{true, true, 2},
		{false, true, 3},
		{true, false, 3},
		{false, false, 4},
	} {
		got := dayTotals(t, c, DayQuery{Instance: inst, To: reportTo, Days: 1, Signed: tc.signed, Humans: tc.humans})
		if len(got) != 1 || got[0].N != tc.want {
			t.Errorf("signed %v humans %v: %+v, want one row of %d", tc.signed, tc.humans, got, tc.want)
		}
	}
}

func TestDayTotalsSplits(t *testing.T) {
	c, inst := featureClient(t)
	var rows []Row
	for _, tier := range []string{"Any", "Legacy"} {
		for _, device := range []string{"desktop", "mobile"} {
			rows = append(rows, Row{Dims: Dims{Instance: inst, Tier: tier, Device: device, Signed: true}, Name: "search.sort", Value: "alpha", N: 1})
		}
	}
	replaceDay(t, c, reportDay(0), inst, []string{"search.sort"}, rows...)
	byTier := dayTotals(t, c, DayQuery{Instance: inst, To: reportTo, Days: 1, ByTier: true})
	if len(byTier) != 2 || byTier[0].Tier != "Any" || byTier[1].Tier != "Legacy" || byTier[0].N != 2 {
		t.Errorf("by tier %+v, want Any and Legacy with n 2 each", byTier)
	}
	for _, r := range byTier {
		if r.Device != "" {
			t.Errorf("by tier alone sets device %q", r.Device)
		}
	}
	both := dayTotals(t, c, DayQuery{Instance: inst, To: reportTo, Days: 1, ByTier: true, ByDevice: true})
	if len(both) != 4 {
		t.Fatalf("by tier and device %+v, want 4 rows", both)
	}
	if both[0].Tier != "Any" || both[0].Device != "desktop" || both[3].Tier != "Legacy" || both[3].Device != "mobile" {
		t.Errorf("split order %+v", both)
	}
}

func TestDayTotalsNames(t *testing.T) {
	c, inst := featureClient(t)
	d := Dims{Instance: inst, Tier: "Any", Device: "desktop", Signed: true}
	names := []string{"a.x", "b.y", "c.z"}
	replaceDay(t, c, reportDay(0), inst, names,
		Row{Dims: d, Name: "a.x", N: 1}, Row{Dims: d, Name: "b.y", N: 1}, Row{Dims: d, Name: "c.z", N: 1})
	two := dayTotals(t, c, DayQuery{Instance: inst, To: reportTo, Days: 1, Names: []string{"a.x", "b.y"}})
	if len(two) != 2 || two[0].Name != "a.x" || two[1].Name != "b.y" {
		t.Errorf("named %+v, want a.x and b.y", two)
	}
	if all := dayTotals(t, c, DayQuery{Instance: inst, To: reportTo, Days: 1}); len(all) != 3 {
		t.Errorf("unnamed %+v, want all three", all)
	}
	if none := dayTotals(t, c, DayQuery{Instance: inst, To: reportTo, Days: 1, Names: []string{}}); len(none) != 0 {
		t.Errorf("an empty name list gives %+v, want nothing", none)
	}
}

func TestDayTotalsMinCell(t *testing.T) {
	c, inst := featureClient(t)
	d := Dims{Instance: inst, Tier: "Any", Device: "desktop", Signed: true}
	replaceDay(t, c, reportDay(0), inst, []string{"search.sort"},
		Row{Dims: d, Name: "search.sort", Value: "two", N: 2}, Row{Dims: d, Name: "search.sort", Value: "three", N: 3})
	got := dayTotals(t, c, DayQuery{Instance: inst, To: reportTo, Days: 1, MinCell: 3})
	if len(got) != 1 || got[0].Value != "three" {
		t.Errorf("got %+v, want only the row summing to 3", got)
	}
}

func TestDayTotalsKeepsInstancesApart(t *testing.T) {
	c, inst := featureClient(t)
	other := inst + "-other"
	t.Cleanup(func() { _, _ = c.db.Exec("DELETE FROM feature_days WHERE instance = $1", other) })
	names := []string{"search.sort"}
	replaceDay(t, c, reportDay(0), inst, names, Row{Dims: Dims{Instance: inst, Device: "desktop", Signed: true}, Name: "search.sort", Value: "mine", N: 1})
	replaceDay(t, c, reportDay(0), other, names, Row{Dims: Dims{Instance: other, Device: "desktop", Signed: true}, Name: "search.sort", Value: "theirs", N: 1})
	got := dayTotals(t, c, DayQuery{Instance: inst, To: reportTo, Days: 1})
	if len(got) != 1 || got[0].Value != "mine" {
		t.Errorf("got %+v, want only this instance's row", got)
	}
}

func TestFoldedThrough(t *testing.T) {
	c, inst := featureClient(t)
	ctx := context.Background()
	// Days in 2001 the test owns; real rows are newer and fall after now.
	now := utc(2001, 5, 10, 12, 0)
	flush := Row{Dims: Dims{Instance: inst, Device: "job"}, Name: "metrics.flush", N: 1}
	folded := func() (time.Time, bool) {
		t.Helper()
		d, ok, err := c.FoldedThrough(ctx, now)
		if err != nil {
			t.Fatal(err)
		}
		return d, ok
	}
	// FoldedThrough reads every instance, so the test can judge only its own rows: another
	// instance's flush or fold row at or before now would decide the answer instead.
	var others int
	if err := c.db.QueryRow(`SELECT (SELECT count(*) FROM feature_days WHERE name = 'metrics.flush' AND day <= $2::date AND instance <> $1)
     + (SELECT count(*) FROM feature_events WHERE name = 'job.run' AND scope = 'fold' AND ts <= $3 AND instance <> $1)`,
		inst, sqlDate(now), now).Scan(&others); err != nil {
		t.Fatal(err)
	}
	if others > 0 {
		t.Skipf("%d rows of other instances on or before %v decide FoldedThrough here", others, now)
	}
	if d, ok := folded(); ok {
		t.Fatalf("folded through %v with no rows of its own", d)
	}
	for _, d := range []int{7, 8, 9, 10} { // 10 is today: a hand fold's part-day
		replaceDay(t, c, utc(2001, 5, d, 0, 0), inst, []string{"metrics.flush"}, flush)
	}
	// With no fold run on record, the newest flush day before today.
	if d, ok := folded(); !ok || !d.Equal(utc(2001, 5, 9, 0, 0)) {
		t.Errorf("folded through %v %v, want 2001-05-09", d, ok)
	}
	// The newest fold run finished on the 9th, so the 9th is a part-day.
	upsert(t, c, utc(2001, 5, 9, 0, 41), Row{Dims: Dims{Instance: inst, Device: "job"}, Scope: "fold", Name: "job.run", Value: "ok", N: 1})
	upsert(t, c, utc(2001, 5, 10, 3, 0), Row{Dims: Dims{Instance: inst, Device: "job"}, Scope: "fold", Name: "job.run", Value: "fail", N: 1})
	if d, ok := folded(); !ok || !d.Equal(utc(2001, 5, 8, 0, 0)) {
		t.Errorf("folded through %v %v, want 2001-05-08", d, ok)
	}
	// Tonight's run lands: yesterday is whole.
	upsert(t, c, utc(2001, 5, 10, 0, 41), Row{Dims: Dims{Instance: inst, Device: "job"}, Scope: "fold", Name: "job.run", Value: "ok", N: 1})
	if d, ok := folded(); !ok || !d.Equal(utc(2001, 5, 9, 0, 0)) {
		t.Errorf("folded through %v %v, want 2001-05-09", d, ok)
	}
}

func TestHourTotalsWantsOneName(t *testing.T) {
	c := &Client{}
	if _, err := c.HourTotals(context.Background(), DayQuery{Instance: "magic"}, time.Now()); err == nil {
		t.Fatal("no name is refused")
	}
	if _, err := c.HourTotals(context.Background(), DayQuery{Instance: "magic", Names: []string{"a.x", "b.y"}}, time.Now()); err == nil {
		t.Fatal("two names are refused")
	}
	if _, err := c.HourTotals(context.Background(), DayQuery{Names: []string{"a.x"}}, time.Now()); err == nil {
		t.Fatal("no instance is refused")
	}
}

func TestInstancesLeavesOutShared(t *testing.T) {
	c := testClient(t)
	inst := "test-" + t.Name()
	a, b := inst+"-a", inst+"-b"
	inside, outside, future := inst+"-inside", inst+"-outside", inst+"-future"
	// A test-only name, so the shared and blank rows deleted are exactly these.
	name := "test." + t.Name()
	t.Cleanup(func() {
		_, _ = c.db.Exec("DELETE FROM feature_days WHERE instance = ANY($1)", pq.Array([]string{a, b, inside, outside, future}))
		_, _ = c.db.Exec("DELETE FROM feature_days WHERE instance = ANY($1) AND name = $2", pq.Array([]string{SharedInstance, ""}), name)
	})
	// A day in 2001 the test owns; real rows are newer and fall after it.
	now := utc(2001, 9, 30, 12, 0)
	write := func(day time.Time, i string) {
		replaceDay(t, c, day, i, []string{name}, Row{Dims: Dims{Instance: i, Device: "job"}, Name: name, N: 1})
	}
	for _, i := range []string{a, b, SharedInstance, ""} {
		write(now, i)
	}
	write(utc(2001, 8, 31, 0, 0), inside)  // 30 days before today: in
	write(utc(2001, 8, 30, 0, 0), outside) // 31 days before: out
	write(utc(2001, 10, 1, 0, 0), future)  // after today: out
	got, err := c.Instances(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{a, b, inside} {
		if !slices.Contains(got, want) {
			t.Errorf("instances %v lack %s", got, want)
		}
	}
	for _, unwanted := range []string{SharedInstance, "", outside, future} {
		if slices.Contains(got, unwanted) {
			t.Errorf("instances %v hold %q", got, unwanted)
		}
	}
	if !slices.IsSorted(got) {
		t.Errorf("instances %v are not sorted", got)
	}
}

func foldStamp(t *testing.T, c *Client) string {
	t.Helper()
	s, err := c.FoldStamp(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestFoldStampMoves(t *testing.T) {
	c, inst := featureClient(t)
	// The rows go one past what is stored, under the test's instance, and featureClient deletes them.
	var maxDay, maxRun sql.NullTime
	if err := c.db.QueryRow(`SELECT max(day) FROM feature_days`).Scan(&maxDay); err != nil {
		t.Fatal(err)
	}
	if err := c.db.QueryRow(`SELECT max(ts) FROM feature_events WHERE name = 'job.run' AND value = 'ok'`).Scan(&maxRun); err != nil {
		t.Fatal(err)
	}
	next := utc(2001, 1, 1, 0, 0)
	if maxDay.Valid {
		next = dateDay(maxDay.Time).AddDate(0, 0, 1)
	}
	before := foldStamp(t, c)
	replaceDay(t, c, next, inst, []string{"search.sort"}, Row{Dims: Dims{Instance: inst, Device: "desktop"}, Name: "search.sort", N: 1})
	afterDay := foldStamp(t, c)
	if afterDay == before {
		t.Fatalf("a new day leaves the stamp at %q", before)
	}
	minute := utc(2001, 1, 1, 0, 0)
	if maxRun.Valid {
		minute = maxRun.Time.UTC().Truncate(time.Minute).Add(time.Minute)
	}
	upsert(t, c, minute, Row{Dims: Dims{Instance: inst, Device: "job"}, Scope: "fold", Name: "job.run", Value: "ok", N: 1})
	if after := foldStamp(t, c); after == afterDay {
		t.Fatalf("a finished job leaves the stamp at %q", after)
	}
}

func TestPageVisitsDepth(t *testing.T) {
	c := testClient(t) // deletes the __test__ paths
	ctx := context.Background()
	inst := "test-" + t.Name()
	const path = "__test__/a"
	va, vb := HashVisitor("a@test"), HashVisitor("b@test")
	var evs []Event
	for range 5 {
		evs = append(evs, Event{Path: path, Tier: "Any", Device: "desktop", Visitor: va, Instance: inst})
	}
	evs = append(evs,
		Event{Path: path, Tier: "Any", Device: "mobile", Visitor: vb, Instance: inst},
		Event{Path: path, Tier: "Any", Device: "desktop", Instance: inst},
		Event{Path: path, Tier: "Any", Device: "desktop", Visitor: va, IsBot: true, Instance: inst},
		Event{Path: path, Tier: "Any", Device: "desktop", Visitor: va, Instance: inst + "-other"},
	)
	if err := c.InsertBatch(ctx, evs); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	visits := func() PageVisit {
		t.Helper()
		got, err := c.PageVisits(ctx, inst, now.AddDate(0, 0, -7), now.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range got {
			if p.Path == path {
				return p
			}
		}
		t.Fatalf("no row for %s in %+v", path, got)
		return PageVisit{}
	}
	want := PageVisit{Path: path, Views: 6, MobileViews: 1, Visitors: 2, Once: 2}
	if got := visits(); got != want {
		t.Errorf("same day %+v, want %+v", got, want)
	}
	// Spread A's human hits over five days, numbered in id order.
	_, err := c.db.Exec(`UPDATE events e SET ts = e.ts - (r.rn % 5) * interval '1 day'
FROM (SELECT id, row_number() OVER (ORDER BY id) AS rn FROM events
      WHERE path = $1 AND visitor = $2 AND instance = $3 AND NOT is_bot) r
WHERE e.id = r.id`, path, va, inst)
	if err != nil {
		t.Fatal(err)
	}
	want.Once, want.FivePlus = 1, 1
	if got := visits(); got != want {
		t.Errorf("spread %+v, want %+v", got, want)
	}
}

func TestPageVisitsBounds(t *testing.T) {
	c := testClient(t) // deletes the __test__ paths
	ctx := context.Background()
	inst := "test-" + t.Name()
	const path = "__test__/bounds"
	from, until := utc(2001, 5, 1, 0, 0), utc(2001, 5, 8, 0, 0)
	at := map[string]time.Time{
		"from":   from,                         // in
		"before": from.Add(-time.Microsecond),  // out
		"last":   until.Add(-time.Microsecond), // in
		"until":  until,                        // out
	}
	var evs []Event
	for who := range at {
		evs = append(evs, Event{Path: path, Tier: "Any", Device: "desktop", Visitor: HashVisitor(who + "@test"), Instance: inst})
	}
	if err := c.InsertBatch(ctx, evs); err != nil {
		t.Fatal(err)
	}
	// InsertBatch stamps now; move each reader's hit onto its bound.
	for who, ts := range at {
		if _, err := c.db.Exec(`UPDATE events SET ts = $1 WHERE path = $2 AND visitor = $3`, ts, path, HashVisitor(who+"@test")); err != nil {
			t.Fatal(err)
		}
	}
	got, err := c.PageVisits(ctx, inst, from, until)
	if err != nil {
		t.Fatal(err)
	}
	want := []PageVisit{{Path: path, Views: 2, Visitors: 2, Once: 2}}
	if !slices.Equal(got, want) {
		t.Errorf("got %+v, want %+v (from in, until out)", got, want)
	}
}

func TestCounterHealthBounds(t *testing.T) {
	c, inst := featureClient(t)
	own := Dims{Instance: inst, Device: "job"}
	yesterday, today := utc(2001, 6, 9, 0, 0), utc(2001, 6, 10, 0, 0)
	upsert(t, c, yesterday.Add(-time.Minute), Row{Dims: own, Name: "metrics.dropped", N: 100}) // out
	upsert(t, c, yesterday, Row{Dims: own, Name: "metrics.dropped", N: 1})                     // in, a row of yesterday
	upsert(t, c, today, Row{Dims: own, Name: "metrics.dropped", N: 10})                        // in, a row of today
	got, err := c.CounterHealth(context.Background(), yesterday)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range got {
		if h.Instance != inst {
			continue
		}
		if h.Rows != 1 || h.Dropped != 11 || !h.LastFlush.IsZero() {
			t.Errorf("got %+v, want Rows 1 (yesterday's midnight), Dropped 11 and no flush", h)
		}
		return
	}
	t.Fatalf("no row for %s in %+v", inst, got)
}

func TestCounterHealth(t *testing.T) {
	c, inst := featureClient(t)
	// Days in 2001 the test owns.
	yesterday := utc(2001, 6, 9, 0, 0)
	own := Dims{Instance: inst, Device: "job"}
	upsert(t, c, utc(2001, 6, 10, 8, 0), Row{Dims: own, Name: "metrics.flush", N: 1})
	upsert(t, c, utc(2001, 6, 10, 9, 30), Row{Dims: own, Name: "metrics.flush", N: 1})
	upsert(t, c, utc(2001, 6, 9, 12, 0), Row{Dims: own, Name: "metrics.dropped", N: 4})
	upsert(t, c, utc(2001, 6, 9, 13, 0), Row{Dims: Dims{Instance: inst, Device: "desktop", Signed: true}, Name: "search.sort", Value: "alpha", N: 1})
	upsert(t, c, utc(2001, 6, 8, 23, 59), Row{Dims: own, Name: "metrics.flush_fail", N: 9})
	got, err := c.CounterHealth(context.Background(), yesterday.Add(15*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var h *InstanceHealth
	for i := range got {
		if got[i].Instance == inst {
			h = &got[i]
		}
	}
	if h == nil {
		t.Fatalf("no row for %s in %+v", inst, got)
	}
	want := InstanceHealth{Instance: inst, LastFlush: utc(2001, 6, 10, 9, 30), Rows: 2, Dropped: 4}
	if !h.LastFlush.Equal(want.LastFlush) || h.Rows != want.Rows || h.Dropped != want.Dropped || h.FlushFailed != 0 || h.Rejected != 0 {
		t.Errorf("got %+v, want %+v (the fail before yesterday is outside)", *h, want)
	}
}

func TestJobRuns(t *testing.T) {
	c, inst := featureClient(t)
	job := Dims{Instance: inst, Device: "job"}
	run := func(at time.Time, value string) {
		upsert(t, c, at, Row{Dims: job, Scope: "fold", Name: "job.run", Value: value, N: 1})
	}
	run(utc(2001, 7, 1, 0, 40), "ok")
	run(utc(2001, 7, 2, 0, 40), "ok")
	run(utc(2001, 7, 1, 12, 0), "fail")
	got, err := c.JobRuns(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var mine []JobRun
	for _, r := range got {
		if r.Instance == inst {
			mine = append(mine, r)
		}
	}
	want := []JobRun{
		{Instance: inst, Job: "fold", Result: "ok", At: utc(2001, 7, 2, 0, 40)},
		{Instance: inst, Job: "fold", Result: "fail", At: utc(2001, 7, 1, 12, 0)},
	}
	if !slices.EqualFunc(mine, want, func(a, b JobRun) bool {
		return a.Instance == b.Instance && a.Job == b.Job && a.Result == b.Result && a.At.Equal(b.At)
	}) {
		t.Errorf("got %+v, want %+v", mine, want)
	}
}

func TestHourTotals(t *testing.T) {
	c, inst := featureClient(t)
	signed := Dims{Instance: inst, Tier: "Any", Device: "desktop", Signed: true}
	row := Row{Dims: signed, Scope: "page", Name: "search.sort", Value: "alpha", N: 2}
	for _, at := range []time.Time{utc(2001, 8, 1, 10, 0), utc(2001, 8, 1, 10, 15), utc(2001, 8, 1, 10, 59), utc(2001, 8, 1, 11, 0)} {
		upsert(t, c, at, row)
	}
	bot := row
	bot.Bot = true
	upsert(t, c, utc(2001, 8, 1, 10, 30), bot)
	upsert(t, c, utc(2001, 8, 1, 10, 30), Row{Dims: signed, Name: "other.name", N: 5})
	upsert(t, c, utc(2001, 8, 1, 9, 0), row) // before since
	got, err := c.HourTotals(context.Background(), DayQuery{Instance: inst, Names: []string{"search.sort"}, Humans: true}, utc(2001, 8, 1, 10, 0))
	if err != nil {
		t.Fatal(err)
	}
	want := []HourTotal{
		{Hour: utc(2001, 8, 1, 10, 0), Scope: "page", Value: "alpha", N: 6},
		{Hour: utc(2001, 8, 1, 11, 0), Scope: "page", Value: "alpha", N: 2},
	}
	if !slices.EqualFunc(got, want, func(a, b HourTotal) bool {
		return a.Hour.Equal(b.Hour) && a.Scope == b.Scope && a.Value == b.Value && a.N == b.N
	}) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}
