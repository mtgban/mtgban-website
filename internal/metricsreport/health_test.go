package metricsreport

import (
	"slices"
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/observability"
)

func TestSilent(t *testing.T) {
	ctx := observability.ReportContext
	names := []observability.Name{
		{Name: "arbit.view", Report: ctx, Page: "arbit,reverse,global"},                  // has rows
		{Name: "news.report", Report: ctx, Page: "newspaper/index,newspaper/syp"},        // index had views, no rows: broken
		{Name: "sleepers.page", Report: ctx, Page: "sleepers/index,sleepers/gap"},        // only gap had views: quiet
		{Name: "apiplans.view", Report: ctx, Page: "api-plans"},                          // its only row is 40 days old: broken
		{Name: "upload.parse_error", Report: observability.ReportSignal, Page: "upload"}, // a rare event: never judged
		{Name: "upload_share.open", Report: observability.ReportSignal, Page: "upload"},  // only on a share link: never judged
		{Name: "alerts.deep_link", Report: ctx, Page: "alerts"},                          // only on a deep link: never judged
		{Name: "upload.mode", Report: ctx, Page: "upload"},                               // only on a priced POST: never judged
		{Name: "screener.sort", Report: observability.ReportCandidate, Page: "screener"}, // an unused feature: Remove's
		// upload.handoff_page is not in names: a site whose registry lacks it judges nothing of it
	}
	totals := []observability.DayTotal{
		tot(0, "page.view", "", "arbit", 500, 30),
		tot(0, "page.view", "", "newspaper/index", 40, 12),
		tot(0, "page.view", "", "sleepers/gap", 40, 12),
		tot(0, "page.view", "", "api-plans", 9, 3),
		tot(0, "page.view", "", "upload", 900, 30),
		tot(0, "page.view", "", "alerts", 90, 30),
		tot(0, "page.view", "", "screener", 90, 30),
		tot(0, "page.view", "", "upload/handoff", 90, 30),
		tot(0, "arbit.view", "arbit", "landing", 9, 4),
		tot(1, "apiplans.view", "", "plain", 9, 4), // 40 days ago does not count
	}
	broken, quiet := Silent(names, totals)
	if !slices.Equal(broken, []string{"apiplans.view", "news.report"}) || !slices.Equal(quiet, []string{"sleepers.page"}) {
		t.Errorf("broken %v quiet %v", broken, quiet)
	}
	// views of the listed page itself
	totals = append(totals, tot(0, "page.view", "", "sleepers/index", 1, 1))
	if broken, _ := Silent(names, totals); !slices.Contains(broken, "sleepers.page") {
		t.Errorf("with a view of sleepers/index: %v", broken)
	}
	// one row of the name clears it
	totals = append(totals, tot(0, "news.report", "", "syp", 1, 1))
	if broken, _ := Silent(names, totals); slices.Contains(broken, "news.report") {
		t.Errorf("one row is enough: %v", broken)
	}
	if b, q := Silent(names, nil); len(b) != 0 || !slices.Equal(q, []string{"apiplans.view", "arbit.view", "news.report", "sleepers.page"}) {
		t.Errorf("no rows at all: broken %v quiet %v", b, q)
	}
	if b, q := Silent(nil, totals); b != nil || q != nil {
		t.Errorf("no registry: %v %v", b, q)
	}
}

// Each count Silent judges is a registered Signal or Context name, its pages within its Page list.
func TestEveryViewCountsMatchTheRegistry(t *testing.T) {
	seen := map[string]bool{}
	for _, e := range everyViewCounts {
		n, ok := observability.Lookup(e.name)
		if !ok {
			t.Errorf("%s is not registered", e.name)
			continue
		}
		if seen[e.name] {
			t.Errorf("%s is listed twice", e.name)
		}
		seen[e.name] = true
		if n.Report != observability.ReportSignal && n.Report != observability.ReportContext {
			t.Errorf("%s is report kind %d", e.name, n.Report)
		}
		pages, every := pageList(n.Page)
		if every || len(pages) == 0 || len(e.pages) == 0 {
			t.Errorf("%s has no Page list (%q) or no pages listed", e.name, n.Page)
		}
		for _, p := range e.pages {
			if !slices.Contains(pages, p) {
				t.Errorf("%s: page %s is not in its Page list %q", e.name, p, n.Page)
			}
		}
		if n.Family != observability.FamilyServer {
			t.Errorf("%s: traffic is read from page.view, so it must be a server name", e.name)
		}
	}
}

func TestProblems(t *testing.T) {
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	healthy := HealthInput{Now: now, Instance: "magic",
		Counters: []observability.InstanceHealth{{Instance: "magic", LastFlush: now.Add(-2 * time.Minute)}},
		Jobs:     []observability.JobRun{{Instance: "magic", Job: "fold", Result: "ok", At: now.Add(-7 * time.Hour)}},
		JobNames: []string{"fold"}}
	if p := Problems(healthy); len(p) != 0 {
		t.Fatalf("a healthy site has problems: %v", p)
	}

	sick := healthy
	sick.Counters = []observability.InstanceHealth{{Instance: "magic", LastFlush: now.Add(-11 * time.Minute), Dropped: 12, FlushFailed: 2}}
	sick.Jobs = []observability.JobRun{
		{Instance: "lorcana", Job: "fold", Result: "ok", At: now.Add(-50 * time.Hour)},
		{Instance: "lorcana", Job: "fold", Result: "fail", At: now.Add(-2 * time.Hour)},
	}
	sick.JobNames = []string{"fold", "stock"}
	sick.Broken = []string{"search.pool", "go.click"}
	got := Problems(sick)
	want := []string{
		"Counters: last saved 11:49 UTC on Nov 11",
		"Counters: 12 events dropped since yesterday",
		"Counters: 2 saves failed since yesterday",
		"Job fold: last run failed, 10:00 UTC on Nov 11",
		"Job stock: no run in 14 days",
		"2 counts missing for 30 days although their pages were used",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got  %q\nwant %q", got, want)
	}

	other := healthy
	other.Instance = "pokemon"
	if p := Problems(other); len(p) != 1 || p[0] != "Counters: nothing written by pokemon since yesterday" {
		t.Errorf("an instance with no rows: %v", p)
	}
}

func TestProblemsThresholds(t *testing.T) {
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	in := func(flush, ok time.Duration) HealthInput {
		return HealthInput{Now: now, Instance: "magic",
			Counters: []observability.InstanceHealth{{Instance: "magic", LastFlush: now.Add(-flush)}},
			Jobs:     []observability.JobRun{{Instance: "magic", Job: "fold", Result: "ok", At: now.Add(-ok)}},
			JobNames: []string{"fold"}}
	}
	if p := Problems(in(10*time.Minute, 36*time.Hour)); len(p) != 0 {
		t.Errorf("at the limits: %v", p)
	}
	p := Problems(in(10*time.Minute+time.Second, 36*time.Hour+time.Second))
	if !slices.Equal(p, []string{"Counters: last saved 11:49 UTC on Nov 11", "Job fold: last ran 23:59 UTC on Nov 9"}) {
		t.Errorf("past the limits: %q", p)
	}
	// a row with no flush at all
	noFlush := in(time.Minute, time.Hour)
	noFlush.Counters[0].LastFlush = time.Time{}
	if p := Problems(noFlush); !slices.Equal(p, []string{"Counters: nothing saved since yesterday"}) {
		t.Errorf("no flush: %q", p)
	}
	one := in(time.Minute, time.Hour)
	one.Broken = []string{"search.pool"}
	if p := Problems(one); !slices.Equal(p, []string{"1 count missing for 30 days although its pages were used"}) {
		t.Errorf("one broken name: %q", p)
	}
}

// A run that stood aside or lost its fail row writes no ok: an old ok is the failure.
func TestProblemsJobs(t *testing.T) {
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	run := func(inst, result string, ago time.Duration) observability.JobRun {
		return observability.JobRun{Instance: inst, Job: "fold", Result: result, At: now.Add(-ago)}
	}
	cases := []struct {
		name string
		runs []observability.JobRun
		want string
	}{
		{"several ok a night", []observability.JobRun{run("magic", "ok", time.Hour), run("lorcana", "ok", 2*time.Hour)}, ""},
		{"ok after a fail", []observability.JobRun{run("magic", "fail", 3*time.Hour), run("magic", "ok", time.Hour)}, ""},
		{"the newest on any instance decides", []observability.JobRun{run("magic", "ok", 5*time.Hour), run("lorcana", "fail", time.Hour)}, "Job fold: last run failed, 11:00 UTC on Nov 11"},
		{"a tie: the job finished", []observability.JobRun{run("magic", "fail", time.Hour), run("lorcana", "ok", time.Hour)}, ""},
		{"only an old ok", []observability.JobRun{run("magic", "ok", 40*time.Hour)}, "Job fold: last ran 20:00 UTC on Nov 9"},
		{"only a fail", []observability.JobRun{run("magic", "fail", 40*time.Hour)}, "Job fold: last run failed, 20:00 UTC on Nov 9"},
		{"another job's rows", []observability.JobRun{{Instance: "magic", Job: "stock", Result: "ok", At: now}}, "Job fold: no run in 14 days"},
		{"an unknown result", []observability.JobRun{run("magic", "maybe", time.Hour)}, "Job fold: no run in 14 days"},
	}
	for _, tc := range cases {
		p := Problems(HealthInput{Now: now, Instance: "magic", Jobs: tc.runs, JobNames: []string{"fold"},
			Counters: []observability.InstanceHealth{{Instance: "magic", LastFlush: now}}})
		var want []string
		if tc.want != "" {
			want = []string{tc.want}
		}
		if !slices.Equal(p, want) {
			t.Errorf("%s: got %q, want %q", tc.name, p, want)
		}
	}
}

func TestJobNote(t *testing.T) {
	if JobNote("stock") != "Scheduled only where the user-state database is configured." || JobNote("fold") != "" {
		t.Errorf("notes: %q %q", JobNote("stock"), JobNote("fold"))
	}
}

// The jobs Health lists are the registry's job.run scopes, each with a result it can judge.
func TestHealthJobsMatchTheRegistry(t *testing.T) {
	n, ok := observability.Lookup("job.run")
	if !ok || !slices.Contains(n.Scopes, "stock") || !slices.Contains(n.Enum, "ok") || !slices.Contains(n.Enum, "fail") {
		t.Errorf("job.run = %+v", n)
	}
}

func TestJobStateOf(t *testing.T) {
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	night := time.Date(2026, 11, 11, 0, 40, 0, 0, time.UTC)
	run := func(inst, result string, at time.Time) observability.JobRun {
		return observability.JobRun{Instance: inst, Job: "fold", Result: result, At: at}
	}
	for _, c := range []struct {
		label          string
		runs           []observability.JobRun
		status, newest string
		lastOK         time.Time
		problem        string
	}{
		{"an ok and a fail in the same minute", []observability.JobRun{run("a", "fail", night), run("b", "ok", night)}, JobOK, "b/ok", night, ""},
		{"a fail after the last ok", []observability.JobRun{run("a", "ok", night), run("a", "fail", night.Add(time.Hour))}, JobFailed, "a/fail", night, "Job fold: last run failed, 01:40 UTC on Nov 11"},
		{"more than one ok a night", []observability.JobRun{run("a", "ok", night), run("b", "ok", night.Add(time.Minute))}, JobOK, "b/ok", night.Add(time.Minute), ""},
		{"no run at all", nil, JobNoRun, "/", time.Time{}, "Job fold: no run in 14 days"},
		{"another job and an unknown result", []observability.JobRun{{Job: "stock", Result: "ok", At: night}, run("a", "skipped", night)}, JobNoRun, "/", time.Time{}, "Job fold: no run in 14 days"},
		{"an ok exactly at the threshold", []observability.JobRun{run("a", "ok", now.Add(-StaleJob))}, JobOK, "a/ok", now.Add(-StaleJob), ""},
		{"an ok a second past it", []observability.JobRun{run("a", "ok", now.Add(-StaleJob-time.Second))}, JobOverdue, "a/ok", now.Add(-StaleJob - time.Second), "Job fold: last ran 23:59 UTC on Nov 9"},
	} {
		st := JobStateOf("fold", c.runs, now)
		if st.Status != c.status || st.Newest.Instance+"/"+st.Newest.Result != c.newest || !st.LastOK.At.Equal(c.lastOK) || st.Threshold != StaleJob {
			t.Errorf("%s: %+v", c.label, st)
		}
		if got := st.Problem(); got != c.problem {
			t.Errorf("%s: problem %q, want %q", c.label, got, c.problem)
		}
		probs := Problems(HealthInput{Now: now, Instance: "a", Counters: []observability.InstanceHealth{{Instance: "a", LastFlush: now}}, Jobs: c.runs, JobNames: []string{"fold"}})
		if (c.problem == "") != (len(probs) == 0) || (c.problem != "" && probs[0] != st.Problem()) {
			t.Errorf("%s: Problems %v, state %q", c.label, probs, st.Problem())
		}
	}
}

func TestFlushStale(t *testing.T) {
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		last time.Time
		want bool
	}{{time.Time{}, true}, {now, false}, {now.Add(-StaleFlush), false}, {now.Add(-StaleFlush - time.Second), true}} {
		if got := FlushStale(now, c.last); got != c.want {
			t.Errorf("FlushStale(%v) = %v", c.last, got)
		}
	}
}
