package main

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/observability"
)

func TestArbitApply(t *testing.T) {
	set := arbitState{Toggles: map[string]bool{}, MinSpread: arbitBound{Set: true, Value: 20}}
	zero := arbitState{Toggles: map[string]bool{}}
	for i, c := range []struct {
		form url.Values
		st   arbitState
		want string
	}{
		{url.Values{"f": {"1"}, "toggles_on": {"rl,syp"}, "minspread": {"20"}}, set, "apply"},
		{url.Values{"f": {"1"}, "toggles_on": {"rl,syp"}}, zero, "apply"}, // the form, submitted at defaults
		{url.Values{"f": {"1"}, "source": {"CK"}, "reset": {"1"}}, zero, "reset"},
		{url.Values{"f": {"1"}, "source": {"CK"}}, zero, ""},                                     // a store link at the defaults
		{url.Values{"f": {"1"}, "source": {"CK"}, "reset": {"1"}, "minspread": {"20"}}, set, ""}, // reset by hand beside a limit
		{url.Values{"f": {"1"}, "source": {"CK"}, "minspread": {"20"}}, set, ""},                 // a store or sort link
		{url.Values{"source": {"CK"}, "reset": {"1"}}, zero, ""},                                 // no marker
		{url.Values{"source": {"CK"}}, set, ""},                                                  // state from the cookie
		{url.Values{}, zero, ""},
	} {
		if got := arbitApply(c.form, c.st); got != c.want {
			t.Errorf("case %d: got %q, want %q", i, got, c.want)
		}
	}
}

func TestArbitFacts(t *testing.T) {
	landing := arbitFacts(arbitRun{page: "global", excluded: 6})
	wantFacts(t, landing, []fact{newFact("global", "arbit.view", "landing"), newFact("global", "arbit.excluded_vendors", "5-9")})

	// Every toggle the form shows is in Toggles after an Apply; only nocollector and
	// tradable are off the reverse page's defaults, and legit is not shown.
	st := arbitState{
		Toggles:   map[string]bool{"nocollector": true, "rl": false, "tradable": false, "legit": true},
		MinSpread: arbitBound{Set: true, Value: 20}, MaxSell: arbitBound{Set: true, Value: 0},
		Rarities: arbitPick{Set: true, Values: []string{"mythic"}},
	}
	store := arbitFacts(arbitRun{
		page: "reverse", form: url.Values{"f": {"1"}, "toggles_on": {"rl,nocollector,tradable"}}, state: st,
		mode: arbitMode{Reverse: true}, source: "CK", sort: "spread",
		sections: 12, elapsed: 2 * time.Second,
	})
	wantFacts(t, store, []fact{
		newFact("reverse", "arbit.view", "store"), newFact("reverse", "arbit.source", "CK"), newFact("reverse", "arbit.apply", "apply"),
		newFact("reverse", "arbit.bound", "maxsell"), newFact("reverse", "arbit.bound", "minspread"),
		newFact("reverse", "arbit.pick", "rarity"),
		newFact("reverse", "arbit.toggle", "nocollector"), newFact("reverse", "arbit.toggle", "tradable"),
		newFact("reverse", "arbit.sort", "spread"), newFact("reverse", "arbit.excluded_vendors", "0"),
		newFact("reverse", "arbit.sections", "10-19"), newFact("reverse", "arbit.duration", "<5s"),
	})
}

// A reader who never changed a toggle counts none, whatever the form posted.
func TestArbitTogglesCountOnlyAChoice(t *testing.T) {
	for _, c := range []struct {
		name    string
		mode    arbitMode
		toggles map[string]bool
		want    []string
	}{
		{"nothing set", arbitMode{Global: true}, map[string]bool{}, nil},
		{"an untouched Apply on global", arbitMode{Global: true}, map[string]bool{"rl": false, "legit": true, "syp": false}, nil},
		{"an untouched Apply on global sealed", arbitMode{Global: true, Sealed: true}, map[string]bool{"stable": true, "decklists": false}, nil},
		{"an untouched Apply on reverse", arbitMode{Reverse: true}, map[string]bool{"tradable": true, "rl": false}, nil},
		{"turned on", arbitMode{}, map[string]bool{"rl": true, "abu4h": true, "nooversize": false}, []string{"rl", "abu4h"}},
		{"a default turned off", arbitMode{Global: true}, map[string]bool{"legit": false}, []string{"legit"}},
		{"another page's option rides along", arbitMode{}, map[string]bool{"tradable": false, "legit": false}, nil},
		{"the other kind of source's option", arbitMode{Sealed: true}, map[string]bool{"rl": true}, nil},
	} {
		run := arbitRun{page: "arbit", source: "CK", sort: "profitability", mode: c.mode, state: arbitState{Toggles: c.toggles}}
		var got []string
		for _, f := range arbitFacts(run) {
			if f.name == "arbit.toggle" {
				got = append(got, f.value)
			}
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: toggles %v, want %v", c.name, got, c.want)
		}
	}
}

func TestArbitPage(t *testing.T) {
	for _, c := range []struct {
		global, reverse bool
		want            string
	}{
		{false, false, "arbit"}, {false, true, "reverse"}, {true, false, "global"},
	} {
		if got := arbitPage(c.global, c.reverse); got != c.want {
			t.Errorf("arbitPage(%v, %v) = %q, want %q", c.global, c.reverse, got, c.want)
		}
	}
}

// The registry lists exactly the keys the code reads.
func TestArbitEnumsMatchTheCode(t *testing.T) {
	for name, keys := range map[string][]string{
		"arbit.bound": arbitBoundKeys, "arbit.pick": arbitPickKeys,
		"arbit.toggle": FilterOptKeys, "arbit.sort": arbitSorts,
	} {
		entry, _ := observability.Lookup(name)
		if !slices.Equal(slices.Sorted(slices.Values(entry.Enum)), slices.Sorted(slices.Values(keys))) {
			t.Errorf("%s lists %v, the code has %v", name, entry.Enum, keys)
		}
	}
}

// quietArbitLogs gives the arbitrage pages' loggers a discard writer.
func quietArbitLogs(t *testing.T) {
	t.Helper()
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	for _, name := range []string{"Arbitrage", "Global"} {
		if LogPages[name] == nil {
			LogPages[name] = log.New(io.Discard, "", 0)
			t.Cleanup(func() { delete(LogPages, name) })
		}
	}
}

func TestArbitLandingIsCounted(t *testing.T) {
	// DevMode so render reads templates from disk
	withSigMode(t, true, false)
	quietArbitLogs(t)
	rows := withFeatureCounter(t)
	req := httptest.NewRequest(http.MethodGet, "/arbit", nil)
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.AddCookie(&http.Cookie{Name: "ArbitVendorsList", Value: "A,,B"})
	testSite.Arbit(httptest.NewRecorder(), req)
	got := rows.rows()
	wantRow(t, got, "arbit", "arbit.view", "landing", 1)
	wantRow(t, got, "arbit", "arbit.excluded_vendors", "1-4", 1)
	wantNoRow(t, got, "arbit.source")
}

// A script's fetch of the page is no page view; the same request as a document is.
func TestArbitFetchIsNotCounted(t *testing.T) {
	withSigMode(t, true, false)
	quietArbitLogs(t)
	serve := func(t *testing.T, dest string) []observability.Row {
		rows := withFeatureCounter(t)
		req := httptest.NewRequest(http.MethodGet, "/global", nil)
		req.Header.Set("Sec-Fetch-Dest", dest)
		testSite.Global(httptest.NewRecorder(), req)
		return rows.rows()
	}
	wantRow(t, serve(t, "document"), "global", "arbit.view", "landing", 1)
	wantNoRow(t, serve(t, "empty"), "arbit.view")
}

// A store view counts its source, the reset marker and a toggle turned off.
func TestArbitStoreViewIsCounted(t *testing.T) {
	withSigMode(t, true, false)
	quietArbitLogs(t)
	seedReverseScrapers(t, "card-a")
	rows := withFeatureCounter(t)
	req := httptest.NewRequest(http.MethodGet, "/reverse?source=REVBUY&f=1&reset=1", nil)
	req.Header.Set("Sec-Fetch-Dest", "document")
	rec := httptest.NewRecorder()
	testSite.Reverse(rec, req)
	got := rows.rows()
	wantRow(t, got, "reverse", "arbit.view", "store", 1)
	wantRow(t, got, "reverse", "arbit.source", "REVBUY", 1)
	wantRow(t, got, "reverse", "arbit.apply", "reset", 1)
	wantRow(t, got, "reverse", "arbit.sort", "profitability", 1)
	wantRow(t, got, "reverse", "arbit.excluded_vendors", "0", 1)
	wantNoRow(t, got, "arbit.toggle")
	if len(find(got, "arbit.sections")) != 1 || len(find(got, "arbit.duration")) != 1 {
		t.Errorf("sections and duration rows: %+v", got)
	}

	// The page's reset link carries the marker; no store link does.
	body := rec.Body.String()
	if !strings.Contains(body, `href="?source=REVBUY&f=1&reset=1">Restore defaults`) {
		t.Error("the Restore defaults link carries no reset marker")
	}
	if strings.Count(body, "reset=1") != 1 {
		t.Errorf("reset=1 appears %d times, want only on the Restore defaults link", strings.Count(body, "reset=1"))
	}
}
