package metricsreport

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/mtgban/mtgban-website/observability"
)

func settled(area, name, value string) Candidate {
	return Candidate{Area: area, Name: name, Value: value, Class: "unused", DaysMeasured: 30}
}

func TestChanges(t *testing.T) {
	prev := Snapshot{
		Candidates: []Candidate{settled("search", "search.sort", "alpha"),
			{Area: "search", Name: "search.is", Value: "foil", Class: "unused_so_far", DaysMeasured: 29}},
		Signals: []Signal{
			{Section: "failures", Label: "Empty searches", Name: "search.result", Count: 100},
			{Section: "walls", Label: "Page refused for the tier: sleepers", Name: "auth.refuse", Scope: "sleepers", Count: 60},
			{Section: "walls", Label: "API call refused by plan", Name: "api.refuse", Count: 4},
			{Section: "depth", Label: "search", Name: "page.view", Value: "search", Count: 1},
		},
		Problems:    []string{"Job fold: last run failed"},
		CounterDays: 7,
	}
	now := Snapshot{
		Candidates: []Candidate{settled("search", "search.sort", "alpha"), settled("search", "search.is", "foil"),
			settled("upload", "upload.option", "x"), settled("upload", "upload.option", "y"),
			{Area: "news", Name: "news.syp_sort", Value: "edition", Class: "rare", DaysMeasured: 20},   // not 30 days yet
			{Area: "news", Name: "news.filter", Value: "rarity", Class: "reviewed", DaysMeasured: 90}}, // marked
		Signals: []Signal{
			{Section: "failures", Label: "Empty searches", Name: "search.result", Count: 150},
			{Section: "walls", Label: "Page refused for the tier: sleepers", Name: "auth.refuse", Scope: "sleepers", Count: 240},
			{Section: "walls", Label: "API call refused by plan", Name: "api.refuse", Count: 40}, // under the floor
			{Section: "mobile", Label: "arbit", Name: "page.view", Value: "arbit", Count: 80},    // new: 0 to 80
			{Section: "depth", Label: "search", Name: "page.view", Value: "search", Count: 900},  // depth never moves
			{Section: "walls", Label: "Locked sort clicked", Name: "ui.search.sort_locked", NotMeasured: true},
		},
		Problems:    []string{"Counters: 12 events dropped since yesterday"},
		CounterDays: 7,
	}
	got := Changes(now, prev)
	want := "New to consider removing\n- upload: 2\n- search: 1\n\n" +
		"Moved most\n- arbit: 0 to 80\n- Page refused for the tier: sleepers: 60 to 240\n- Empty searches: 100 to 150\n\n" +
		"Health\n- Counters: 12 events dropped since yesterday"
	if got.Text() != want {
		t.Errorf("digest:\n%s\nwant:\n%s", got.Text(), want)
	}
	if len(got.Sections) != 3 || got.Sections[0].Title != "New to consider removing" || len(got.Sections[1].Lines) != 3 {
		t.Errorf("sections = %+v", got.Sections)
	}
}

// counted is a snapshot whose seven days were all counted.
func counted(s Snapshot) Snapshot {
	s.CounterDays = 7
	return s
}

func TestChangesWithNothingToSay(t *testing.T) {
	same := counted(Snapshot{Candidates: []Candidate{settled("search", "search.sort", "alpha")}})
	d := Changes(same, same)
	if !d.Empty() || d.Text() != NothingChanged || NothingChanged != "Nothing changed in the last seven days." {
		t.Errorf("an unchanged week: %+v, %q", d, d.Text())
	}
	if !Changes(counted(Snapshot{}), counted(Snapshot{})).Empty() {
		t.Error("two empty counted snapshots have nothing to say")
	}
	if !(Digest{Sections: []DigestSection{{Title: "Health"}}}).Empty() {
		t.Error("a section with no lines says nothing")
	}
}

func TestChangesNewErrors(t *testing.T) {
	d := Changes(counted(Snapshot{Errors: []string{"a.js:10 TypeError", "b.js:2 RangeError"}}), counted(Snapshot{Errors: []string{"a.js:10 TypeError"}}))
	if d.Text() != "New errors\n- b.js:2 RangeError" {
		t.Errorf("got %q", d.Text())
	}
	seven := []string{"a:1", "a:2", "a:3", "a:4", "a:5", "a:6", "a:7"}
	if d := Changes(counted(Snapshot{Errors: seven}), counted(Snapshot{})); len(d.Sections) != 1 || len(d.Sections[0].Lines) != 5 || d.Sections[0].Lines[0] != "a:1" {
		t.Errorf("seven new errors print %+v, want the first five", d.Sections)
	}
	if !Changes(counted(Snapshot{Errors: seven}), counted(Snapshot{Errors: seven})).Empty() {
		t.Error("the same errors as last week are not news")
	}
	if d := Changes(counted(Snapshot{Errors: []string{"x", "x", "y"}}), counted(Snapshot{})); !slices.Equal(d.Sections[0].Lines, []string{"x", "y"}) {
		t.Errorf("a repeated label prints once: %+v", d.Sections)
	}
}

// A move needs the larger count at the floor, 20 in count and 20% in size; a candidate needs 30 measured days to settle.
func TestChangesThresholds(t *testing.T) {
	sig := func(count int64) Snapshot {
		return counted(Snapshot{Signals: []Signal{{Section: "walls", Label: "w", Name: "auth.refuse", Scope: "x", Value: "no_access", Count: count}}})
	}
	cases := []struct {
		now, prev int64
		want      string
	}{
		{49, 1, NothingChanged},
		{50, 1, "Moved most\n- w: 1 to 50"},
		{10, 200, "Moved most\n- w: 200 to 10"}, // a row that fell is a move too
		{460, 465, NothingChanged},              // 5 is no move
		{119, 100, NothingChanged},              // 19 in count
		{120, 100, "Moved most\n- w: 100 to 120"},
		{239, 200, NothingChanged}, // 39 in count is 19.5%
		{240, 200, "Moved most\n- w: 200 to 240"},
	}
	for _, tc := range cases {
		if got := Changes(sig(tc.now), sig(tc.prev)).Text(); got != tc.want {
			t.Errorf("%d against %d: %q", tc.now, tc.prev, got)
		}
	}
	c := settled("search", "search.sort", "alpha")
	c.DaysMeasured = 29
	if d := Changes(counted(Snapshot{Candidates: []Candidate{c}}), counted(Snapshot{})); !d.Empty() {
		t.Errorf("29 days: %q", d.Text())
	}
	c.DaysMeasured, c.Class = 30, ClassRare
	if d := Changes(counted(Snapshot{Candidates: []Candidate{c}}), counted(Snapshot{})); d.Text() != "New to consider removing\n- search: 1" {
		t.Errorf("rare at 30 days: %q", d.Text())
	}
	c.Class = ClassUnusedSoFar
	if d := Changes(counted(Snapshot{Candidates: []Candidate{c}}), counted(Snapshot{})); !d.Empty() {
		t.Errorf("unused so far is not settled: %q", d.Text())
	}
}

// A row whose name was not measured in prev did not move: it was not counted.
func TestChangesSkipsNewlyMeasured(t *testing.T) {
	prev := Snapshot{Signals: []Signal{{Section: "walls", Label: "Locked row action", Name: "ui.row.locked", NotMeasured: true}}}
	now := Snapshot{Signals: []Signal{{Section: "walls", Label: "Locked row action: join", Name: "ui.row.locked", Value: "join", Count: 400}}}
	if d := Changes(counted(now), counted(prev)); !d.Empty() {
		t.Errorf("got %q", d.Text())
	}
}

// A week the counter did not fully run is not compared, and the digest says so, moves or not.
func TestChangesNeedsBothWeeksCounted(t *testing.T) {
	errors := func(n int64) Signal {
		return Signal{Section: "failures", Label: "Server errors: search", Name: "http.status", Scope: "search", Value: "5xx", Count: n, Denom: 900, Rate: float64(n) / 900}
	}
	cases := []struct {
		name      string
		now, prev int
		want      string
	}{
		{"both counted", 7, 7, "Moved most\n- Server errors: search: 11.1% to 33.3%\n\nHealth\n- p"},
		{"the week before six days", 7, 6, "Not compared\n- The last 7 days have 7 counted days and the 7 before have 6; each needs 7, so no row is compared.\n\nHealth\n- p"},
		{"this week six days", 6, 7, "Not compared\n- The last 7 days have 6 counted days and the 7 before have 7; each needs 7, so no row is compared.\n\nHealth\n- p"},
		{"neither", 0, 0, "Not compared\n- The last 7 days have 0 counted days and the 7 before have 0; each needs 7, so no row is compared.\n\nHealth\n- p"},
	}
	for _, tc := range cases {
		now := Snapshot{Signals: []Signal{errors(300)}, Problems: []string{"p"}, CounterDays: tc.now}
		prev := Snapshot{Signals: []Signal{errors(100)}, CounterDays: tc.prev}
		if got := Changes(now, prev).Text(); got != tc.want {
			t.Errorf("%s: %q", tc.name, got)
		}
	}
	// with nothing that moved, an uncounted week still says so, never NothingChanged
	for _, days := range [][2]int{{7, 6}, {6, 7}, {0, 0}} {
		d := Changes(Snapshot{CounterDays: days[0]}, Snapshot{CounterDays: days[1]})
		if d.Empty() || d.Text() == NothingChanged || len(d.Sections) != 1 || d.Sections[0].Title != "Not compared" {
			t.Errorf("%v with nothing moved: %q", days, d.Text())
		}
	}
	if d := Changes(counted(Snapshot{}), counted(Snapshot{})); d.Text() != NothingChanged {
		t.Errorf("two counted weeks with nothing moved: %q", d.Text())
	}
}

// A failure rate row moves only when it has a rate in both weeks, never from or to 0.
func TestChangesRateRowsNeedARateInBothWeeks(t *testing.T) {
	row := func(count, denom int64) Signal {
		return Signal{Section: "failures", Label: "Slow requests: x", Name: "http.duration", Scope: "x", Count: count, Denom: denom, Rate: float64(count) / float64(denom)}
	}
	cases := []struct {
		name      string
		now, prev []Signal
		want      string
	}{
		{"under the floor before", []Signal{row(55, 80)}, nil, NothingChanged},
		{"under the floor now", nil, []Signal{row(40, 900)}, NothingChanged},
		{"a prev row under the floor", []Signal{row(55, 80)}, []Signal{row(40, 45)}, NothingChanged},
		{"a now row under the floor", []Signal{row(55, 45)}, []Signal{row(5, 900)}, NothingChanged},
		{"a rate in both", []Signal{row(55, 80)}, []Signal{row(5, 50)}, "Moved most\n- Slow requests: x: 10.0% to 68.8%"},
		// twice the count over twice the requests is the same rate: no move
		{"the same rate", []Signal{row(200, 2000)}, []Signal{row(100, 1000)}, NothingChanged},
		{"a rate up 19%", []Signal{row(119, 1000)}, []Signal{row(100, 1000)}, NothingChanged},
		{"a rate up 20%", []Signal{row(120, 1000)}, []Signal{row(100, 1000)}, "Moved most\n- Slow requests: x: 10.0% to 12.0%"},
	}
	for _, tc := range cases {
		if got := Changes(counted(Snapshot{Signals: tc.now}), counted(Snapshot{Signals: tc.prev})).Text(); got != tc.want {
			t.Errorf("%s: %q", tc.name, got)
		}
	}
	// a count row (no denominator) missing before is a real zero
	limited := Signal{Section: "failures", Label: "Rate limited: vote", Name: "ratelimit.reject", Value: "vote", Count: 80}
	if got := Changes(counted(Snapshot{Signals: []Signal{limited}}), counted(Snapshot{})).Text(); got != "Moved most\n- Rate limited: vote: 0 to 80" {
		t.Errorf("count row: %q", got)
	}
}

func TestChangesMovedMostOrder(t *testing.T) {
	var now, prev []Signal
	for i, label := range []string{"d", "c", "b", "a"} {
		now = append(now, Signal{Section: "failures", Label: label, Name: "http.status", Scope: label, Value: "5xx", Count: 200})
		prev = append(prev, Signal{Section: "failures", Label: label, Name: "http.status", Scope: label, Value: "5xx", Count: int64(100 - i%2*50)})
	}
	// d and b doubled, c and a quadrupled; ties by label
	if got := Changes(counted(Snapshot{Signals: now}), counted(Snapshot{Signals: prev})).Sections[0].Lines; !slices.Equal(got, []string{"a: 50 to 200", "c: 50 to 200", "b: 100 to 200"}) {
		t.Errorf("got %q", got)
	}
}

func TestDigestTextIsPlainAndBounded(t *testing.T) {
	var problems, errs []string
	for i := range 20 {
		problems = append(problems, fmt.Sprintf("Job j%d: no run in 14 days", i))
	}
	errs = append(errs, "evil\nline\r\twith <b>tags</b>", strings.Repeat("x", 500))
	d := Changes(counted(Snapshot{Problems: problems, Errors: errs}), counted(Snapshot{}))
	text := d.Text()
	health := d.Sections[1].Lines
	if len(health) != maxSectionLines || health[len(health)-1] != "and 9 more" {
		t.Errorf("health lines = %q", health)
	}
	if d.Sections[0].Lines[0] != "evil line  with <b>tags</b>" {
		t.Errorf("control characters: %q", d.Sections[0].Lines[0])
	}
	if utf8.RuneCountInString(d.Sections[0].Lines[1]) != maxLineRunes {
		t.Errorf("a long line is cut: %d runes", utf8.RuneCountInString(d.Sections[0].Lines[1]))
	}
	if strings.HasSuffix(text, "\n") || strings.Contains(text, "\r") || strings.Contains(text, "\t") || strings.Contains(text, "\n\n\n") {
		t.Errorf("text = %q", text)
	}
	if lines := strings.Count(text, "\n") + 1; lines != 2+2+maxSectionLines+1 {
		t.Errorf("text has %d lines", lines)
	}
	if Changes(counted(Snapshot{Problems: problems, Errors: errs}), counted(Snapshot{})).Text() != text {
		t.Error("the text is deterministic")
	}
}

func TestShiftPeriods(t *testing.T) {
	in := []observability.DayTotal{tot(0, "a", "", "", 1, 1), tot(1, "a", "", "", 2, 1), tot(2, "b", "", "", 3, 1)}
	got := ShiftPeriods(in, 1)
	if len(got) != 2 || got[0].Period != 0 || got[0].N != 2 || got[1].Period != 1 || got[1].N != 3 {
		t.Errorf("got %+v", got)
	}
	if in[1].Period != 1 || ShiftPeriods(in, 3) != nil {
		t.Error("the input is kept, and shifting past every period leaves nothing")
	}
	// the window before, read as the window: Invest's 7-day walls of the 7 days before
	rows := []observability.DayTotal{tot(0, "auth.refuse", "x", "no_access", 70, 7), tot(1, "auth.refuse", "x", "no_access", 20, 7)}
	w7 := Window{Days: 7, Signed: true, Humans: true}
	now, prev := section(Invest(investNames(), rows, nil, w7), "walls"), section(Invest(investNames(), ShiftPeriods(rows, 1), nil, w7), "walls")
	if now[0].Count != 70 || now[0].Previous != 20 || prev[0].Count != 20 {
		t.Errorf("now %+v prev %+v", now[0], prev[0])
	}
}
