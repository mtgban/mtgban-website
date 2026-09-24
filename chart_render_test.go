package main

import (
	"strings"
	"testing"
)

// renderChartPage executes search.html the way production does and returns the
// page, so the assertions below are about what a browser is actually sent.
func renderChartPage(t *testing.T, pv PageVars) string {
	t.Helper()
	saved := DevMode
	DevMode = false
	t.Cleanup(func() { DevMode = saved })

	cache, err := buildTemplateCache()
	if err != nil {
		t.Fatalf("templates failed to parse: %v", err)
	}
	tmpl, ok := cache["search.html"]
	if !ok {
		t.Fatal("search.html missing from the template cache")
	}
	var b strings.Builder
	if err := tmpl.Execute(&b, pv); err != nil {
		t.Fatalf("executing search.html: %v", err)
	}
	return b.String()
}

// chartPageVars is a single-card chart page with one provider and one gap.
func chartPageVars() PageVars {
	const id = "ban:790"
	return PageVars{
		SearchRan: true,
		// The chart renders inside the results, so the page needs a result to
		// render it in: a chart page is a search for the charted card.
		AllKeys:         []string{id},
		SearchQuery:     "Test Card",
		ChartID:         id,
		ChartIDs:        []string{id},
		ChartIDsCSV:     id,
		MaxChartCards:   len(multiCardPalette),
		MaxLookbackDays: 3650,
		ChartLoadedDays: defaultChartRange,
		AxisLabels:      []string{"2026-09-24", "2026-09-23", "2026-09-22"},
		Datasets: []Dataset{{
			Name:      "TCG Low",
			Color:     "rgb(54, 162, 235)",
			Reference: "TCG Low",
			Data: []ChartPoint{
				{Price: 12.34, Known: true},
				{},
				{Price: 11, Known: true},
			},
		}},
		Metadata: map[string]GenericCard{id: {Name: "Test Card"}},
		// The base template dereferences these unconditionally; a handler
		// always fills them in before rendering.
		BetaNav: &NavElem{Name: "Beta", Link: "/beta"},
	}
}

// The series reaches the browser as numbers and nulls. The sentinel string this
// used to emit had to be coerced back to a number on arrival and cost thirteen
// bytes per gap, which on a long chart is most of the payload.
func TestChartPageRendersGapsAsNull(t *testing.T) {
	page := renderChartPage(t, chartPageVars())

	if strings.Contains(page, "Number.NaN") {
		t.Error("page still carries the Number.NaN sentinel")
	}
	if !strings.Contains(page, "[12.34,null,11]") {
		t.Error("page does not carry the series as numbers and nulls; looked for [12.34,null,11]")
	}
}

// squashSpaces collapses runs of whitespace. html/template pads a number
// interpolated into a script with spaces so it cannot merge with the token
// beside it, which is invisible to a browser and noise to an assertion.
func squashSpaces(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// The page tells the front-end how much history it rendered, because that is
// what decides whether a wider range has to be fetched or is already in hand.
func TestChartPageDeclaresWhatItLoaded(t *testing.T) {
	page := squashSpaces(renderChartPage(t, chartPageVars()))

	for _, want := range []string{
		"var chartLoadedDays = 180 ;",
		"var chartMaxDays = 3650 ;",
		`var chartRosterIDs = "ban:790";`,
		"/js/chart-range.js",
		"new ChartRangeLoader(",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("page is missing %q", want)
		}
	}
}

// A chart rendered at six months can gain checkpoints when it widens to ten
// years, so the toggles have to exist before the widening rather than only
// where the rendered window already crossed one.
func TestChartPageKeepsCheckpointTogglesForAWidenableChart(t *testing.T) {
	pv := chartPageVars() // no Checkpoints, 180 rendered of 3650 allowed
	page := renderChartPage(t, pv)
	if !strings.Contains(page, `<p class="chart-checkpoint-toggles"`) {
		t.Error("a chart that can widen renders no checkpoint toggles")
	}
	if !strings.Contains(page, `class="chart-checkpoint-toggles" style="display: none;"`) {
		t.Error("toggles for a chart with no checkpoints yet should start hidden")
	}

	// A chart that cannot widen and has no checkpoints needs no toggles at all.
	pv.MaxLookbackDays = 180
	if page := renderChartPage(t, pv); strings.Contains(page, `<p class="chart-checkpoint-toggles"`) {
		t.Error("a chart that cannot widen and has no checkpoints still renders toggles")
	}
}

// A viewer whose tier reaches no further than the window the page renders can
// never need a wider one, so nothing should ever be fetched for them.
func TestChartPageLoadsEverythingForANarrowTier(t *testing.T) {
	pv := chartPageVars()
	pv.MaxLookbackDays = 30
	pv.ChartLoadedDays = 30
	page := squashSpaces(renderChartPage(t, pv))

	if !strings.Contains(page, "var chartLoadedDays = 30 ;") ||
		!strings.Contains(page, "var chartMaxDays = 30 ;") {
		t.Error("a 30-day tier should render its whole window")
	}
}
