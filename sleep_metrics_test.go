package main

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/mtgban-website/internal/salesvelocity"
	"github.com/mtgban/mtgban-website/observability"
)

func TestSleepersFacts(t *testing.T) {
	wantFacts(t, sleepersFacts(sleepersRun{page: "index", editions: true}),
		[]fact{newFact("", "sleepers.page", "index"), newFact("", "sleepers.lists", "editions")})
	wantFacts(t, sleepersFacts(sleepersRun{page: "gap", ref: "MKMTrend", target: "CK", sellers: true, elapsed: 80 * time.Millisecond}),
		[]fact{newFact("", "sleepers.page", "gap"), newFact("", "sleepers.gap", "preset"), newFact("", "sleepers.ref", "MKMTrend"),
			newFact("", "sleepers.target", "CK"), newFact("", "sleepers.lists", "sellers"), newFact("", "sleepers.duration", "<200ms")})
	custom := sleepersFacts(sleepersRun{page: "gap", ref: "CK", target: "MKMTrend"})
	if custom[1] != newFact("", "sleepers.gap", "custom") {
		t.Errorf("a reversed pair is not a preset: %v", custom[1])
	}
	wantFacts(t, sleepersFacts(sleepersRun{page: "hotlist", sellers: true, vendors: true, editions: true, elapsed: 6 * time.Second}),
		[]fact{newFact("", "sleepers.page", "hotlist"), newFact("", "sleepers.lists", "sellers"), newFact("", "sleepers.lists", "vendors"),
			newFact("", "sleepers.lists", "editions"), newFact("", "sleepers.duration", "5s+")})
}

// The preset links both templates render are the presets the code knows.
func TestSleepersPresetsMatchTheTemplates(t *testing.T) {
	re := regexp.MustCompile(`\?page=gap&ref=(\w+)&target=(\w+)`)
	for _, file := range []string{"templates/sleep.html", "templates/mobile/sleep.html"} {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		links := re.FindAllStringSubmatch(string(src), -1)
		if len(links) != len(sleepersGapPresets) {
			t.Errorf("%s has %d preset links, the code %d", file, len(links), len(sleepersGapPresets))
		}
		for _, m := range links {
			if !slices.Contains(sleepersGapPresets, [2]string{m[1], m[2]}) {
				t.Errorf("%s links a pair the code does not list: %s, %s", file, m[1], m[2])
			}
		}
	}
}

// A hide list counts only when its cookie names something.
func TestSleepersListKept(t *testing.T) {
	for in, want := range map[string]bool{"": false, ",": false, "CK": true, ",CK,": true} {
		if got := sleepersListKept(in); got != want {
			t.Errorf("sleepersListKept(%q) = %v, want %v", in, got, want)
		}
	}
}

// quietSleepersLog discards the Sleepers page log for one test.
func quietSleepersLog(t *testing.T) {
	t.Helper()
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Sleepers"] == nil {
		LogPages["Sleepers"] = log.New(io.Discard, "", 0)
		t.Cleanup(func() { delete(LogPages, "Sleepers") })
	}
}

// The index counts its hide lists; velocity with no sales is the index; the redirect and a fetch count nothing.
func TestSleepersIndexIsCounted(t *testing.T) {
	quietSleepersLog(t)
	withSigMode(t, true, false)
	setSalesVelocityStore(t, &salesvelocity.Store{})
	serve := func(t *testing.T, target, dest string) []observability.Row {
		rows := withFeatureCounter(t)
		req := httptest.NewRequest(http.MethodGet, target, nil)
		req.Header.Set("Sec-Fetch-Dest", dest)
		req.AddCookie(&http.Cookie{Name: "SleepersVendorsList", Value: "CK"})
		req.AddCookie(&http.Cookie{Name: "SleepersSellersList", Value: ","})
		testSite.Sleepers(httptest.NewRecorder(), req)
		return rows.rows()
	}
	t.Run("index", func(t *testing.T) {
		got := serve(t, "/sleepers?page=velocity", "document")
		wantRow(t, got, "", "sleepers.page", "index", 1)
		wantRow(t, got, "", "sleepers.lists", "vendors", 1)
		if n := len(find(got, "sleepers.lists")); n != 1 {
			t.Errorf("%d sleepers.lists rows, want 1", n)
		}
		wantNoRow(t, got, "sleepers.duration")
	})
	t.Run("options", func(t *testing.T) {
		wantNoRow(t, serve(t, "/sleepers?page=options", "document"), "sleepers.page")
	})
	t.Run("fetch", func(t *testing.T) {
		wantNoRow(t, serve(t, "/sleepers", "empty"), "sleepers.page")
	})
}

// A content-warning card's click only reveals it, so its link carries no count.
func TestSleepersContentWarningCardIsNotCounted(t *testing.T) {
	pv := PageVars{Title: "Sleepers", Subtitle: "Reprint", UserNav: &NavElem{}, Metadata: cardMetadata{
		"plain":  {Name: "Plain", SearchURL: "/search?q=plain"},
		"warned": {Name: "Warned", SearchURL: "/search?q=warned", HasContentWarning: true},
	}}
	pv.Sleepers = map[string][]string{"S": {"plain", "warned"}}
	pv.SleepersKeys = []string{"S"}
	pv.SleepersColors = []string{"#fff"}
	out := renderPage(t, "sleep.html", false, pv)
	if !strings.Contains(out, `<a href="/search?q=plain" data-track="ui.sleepers.card">`) {
		t.Error("a plain card's link is not counted")
	}
	if !strings.Contains(out, `<a href="/search?q=warned">`) {
		t.Error("a content-warning card's link carries a count")
	}
}
