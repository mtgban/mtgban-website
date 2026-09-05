package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// axisLabels builds the axis the way the archive walk does: today first,
// backwards.
func axisLabels(n int) []string {
	labels := make([]string, n)
	for i := range labels {
		labels[i] = fmt.Sprintf("2026-%02d-%02d", 9-i/30, 28-i%28)
	}
	return labels
}

// The axis is built newest first because that is the order the archive is
// walked in. A chart reads the other way, and the values have to turn with it
// or every line is drawn backwards.
func TestChartImageSpecReadsOldestFirst(t *testing.T) {
	labels := []string{"2026-03-03", "2026-03-02", "2026-03-01"}
	cards := []multiCardInput{{
		Name: "A Card",
		Datasets: []Dataset{{
			Name:  "TCG Low",
			Color: "#5b8def",
			Data:  []string{"3", "2", "1"},
		}},
	}}

	spec := chartImageSpec(labels, cards, 183)

	if got := spec.Labels; got[0] != "2026-03-01" || got[2] != "2026-03-03" {
		t.Errorf("the axis runs %v, want oldest first", got)
	}
	if len(spec.Series) != 1 {
		t.Fatalf("got %d series, want 1", len(spec.Series))
	}
	if got := spec.Series[0].Data; got[0] != 1 || got[2] != 3 {
		t.Errorf("the values run %v, want them turned with the axis", got)
	}
	if spec.Title != "A Card" {
		t.Errorf("the title is %q", spec.Title)
	}
}

// A day with no price is written the way the page's JavaScript would read it.
// The renderer wants a gap, and a gap is a NaN.
func TestChartImageSpecTurnsMissingDaysIntoGaps(t *testing.T) {
	cards := []multiCardInput{{
		Name: "A Card",
		Datasets: []Dataset{{
			Name: "TCG Low", Color: "#5b8def",
			Data: []string{"4", "Number.NaN", "2", ""},
		}},
	}}

	spec := chartImageSpec([]string{"d", "c", "b", "a"}, cards, 183)
	if len(spec.Series) != 1 {
		t.Fatalf("got %d series, want 1", len(spec.Series))
	}

	data := spec.Series[0].Data
	if !math.IsNaN(data[0]) || !math.IsNaN(data[2]) {
		t.Errorf("the days with no price came through as %v", data)
	}
	if data[1] != 2 || data[3] != 4 {
		t.Errorf("the days with a price came through as %v", data)
	}
}

// A series that is nothing but gaps is a provider that never carried the card:
// drawn, it is a name in the legend with no line under it.
func TestChartImageSpecDropsSeriesWithNothingInThem(t *testing.T) {
	cards := []multiCardInput{{
		Name: "A Card",
		Datasets: []Dataset{
			{Name: "Empty", Color: "#ffffff", Data: []string{"Number.NaN", "Number.NaN"}},
			{Name: "TCG Low", Color: "#5b8def", Data: []string{"1", "2"}},
		},
	}}

	spec := chartImageSpec([]string{"b", "a"}, cards, 183)
	if len(spec.Series) != 1 || spec.Series[0].Name != "TCG Low" {
		t.Errorf("got %d series: %+v", len(spec.Series), spec.Series)
	}
}

// A roster of eight cards times every provider carrying them is a legend
// nobody reads.
func TestChartImageSpecCapsTheLines(t *testing.T) {
	var datasets []Dataset
	for i := 0; i < ChartImageMaxSeries*3; i++ {
		datasets = append(datasets, Dataset{
			Name: fmt.Sprintf("Provider %d", i), Color: "#5b8def",
			Data: []string{"1", "2"},
		})
	}
	spec := chartImageSpec([]string{"b", "a"}, []multiCardInput{{Name: "A", Datasets: datasets}}, 183)
	if len(spec.Series) != ChartImageMaxSeries {
		t.Errorf("drew %d lines, want at most %d", len(spec.Series), ChartImageMaxSeries)
	}
}

// Nothing to draw is still an image, and it says which card it found nothing
// for.
func TestChartImageSpecSurvivesAnEmptyRead(t *testing.T) {
	spec := chartImageSpec(nil, nil, 183)
	if spec.Title == "" {
		t.Error("an empty chart has no title at all")
	}
	if len(spec.Series) != 0 || len(spec.Labels) != 0 {
		t.Error("an empty read produced something to draw")
	}
}

func TestChartImageTitleNamesTheRoster(t *testing.T) {
	one := []multiCardInput{{Name: "Ragavan"}}
	two := []multiCardInput{{Name: "Ragavan"}, {Name: "Bolt"}}
	many := []multiCardInput{{Name: "Ragavan"}, {Name: "Bolt"}, {Name: "Brainstorm"}}

	if got := chartImageTitle(one); got != "Ragavan" {
		t.Errorf("one card is titled %q", got)
	}
	if got := chartImageTitle(two); !strings.Contains(got, "Ragavan") || !strings.Contains(got, "Bolt") {
		t.Errorf("two cards are titled %q", got)
	}
	if got := chartImageTitle(many); !strings.Contains(got, "2 more") {
		t.Errorf("three cards are titled %q, want the rest counted", got)
	}
}

// The window is the promise the subtitle makes, and the cap is six months.
func TestChartImageSubtitleNamesTheWindow(t *testing.T) {
	if got := chartImageSubtitle(ChartImageMaxDays); !strings.Contains(got, "6 months") {
		t.Errorf("the default window reads %q", got)
	}
	if got := chartImageSubtitle(30); !strings.Contains(got, "weeks") {
		t.Errorf("a month reads %q", got)
	}
}

// The endpoint answers before it reaches the archive when there is nothing to
// chart, so an unfurl of a malformed link is not a database round-trip.
func TestChartImageAPIRefusesAnEmptyRoster(t *testing.T) {
	rec := httptest.NewRecorder()
	ChartImageAPI(rec, httptest.NewRequest(http.MethodGet, "/api/chart/image.png", nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("an empty roster answered %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

// A whole render, from what the archive hands over to the bytes that go out.
func TestChartImageRendersFromArchiveShapedData(t *testing.T) {
	const days = 120
	labels := axisLabels(days)

	newestFirst := make([]string, days)
	for i := range newestFirst {
		if i > 30 && i < 45 {
			newestFirst[i] = "Number.NaN"
			continue
		}
		newestFirst[i] = fmt.Sprintf("%g", 20+float64(days-i)/8)
	}

	spec := chartImageSpec(labels, []multiCardInput{{
		Name:     "Ragavan, Nimble Pilferer",
		Datasets: []Dataset{{Name: "TCG Low", Color: "#5b8def", Data: newestFirst}},
	}}, ChartImageMaxDays)

	if len(spec.Series) != 1 || len(spec.Series[0].Data) != days {
		t.Fatalf("the spec carries %d series", len(spec.Series))
	}
	// The archive hands the newest day over first, and here it is the dearest.
	// Turned to run oldest first, the cheapest day has to lead.
	oldest, newest := spec.Series[0].Data[0], spec.Series[0].Data[days-1]
	if oldest >= newest {
		t.Errorf("the series runs %g to %g, want it turned to run oldest first", oldest, newest)
	}
}

// The unfurl of a chart page is the chart: a photo envelope pointing at the
// rendered image, not a card and not a block of prices.
func TestChartOEmbedAnswersWithThePicture(t *testing.T) {
	rec := httptest.NewRecorder()
	writeChartOEmbed(rec, []string{"card-a", "card-b"},
		map[string]string{"card-a": "unknown-id"}, "card-a,card-b")

	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("answered as %q", got)
	}

	var envelope struct {
		Type   string `json:"type"`
		Title  string `json:"title"`
		URL    string `json:"url"`
		Width  int    `json:"width"`
		Height int    `json:"height"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("the envelope is not JSON: %v", err)
	}

	if envelope.Type != "photo" {
		t.Errorf("the envelope is a %q, want a photo so the graph is shown whole", envelope.Type)
	}
	if !strings.Contains(envelope.URL, "/api/chart/image.png") {
		t.Errorf("the envelope points at %q", envelope.URL)
	}
	if !strings.Contains(envelope.URL, "chart=card-a%2Ccard-b") {
		t.Errorf("the image is not asked for the roster the page plots: %q", envelope.URL)
	}
	if envelope.Width == 0 || envelope.Height == 0 {
		t.Error("a photo envelope with no size is one a client cannot lay out")
	}
	if !strings.Contains(envelope.Title, "1 more") {
		t.Errorf("the title is %q, want the rest of the roster counted", envelope.Title)
	}
}

// A roster of one is named for the card, not counted.
func TestChartRosterTitleNamesASingleCard(t *testing.T) {
	if got := chartRosterTitle([]string{"only"}, nil); got != "only" {
		t.Errorf("a single card is titled %q", got)
	}
	if got := chartRosterTitle(nil, nil); got == "" {
		t.Error("an empty roster has no title at all")
	}
}

// An unfurl carries no signature, and the signature is what gates charting on
// the page. The picture is not the page, so a chart link still previews as one
// - without this the whole path was dead in production, where every unfurl is
// an unsigned request.
func TestChartUnfurlSurvivesAnUnsignedRequest(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	defer func(check bool, dev bool) { SigCheck, DevMode = check, dev }(SigCheck, DevMode)
	SigCheck, DevMode = true, false
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Search"] == nil {
		LogPages["Search"] = log.New(io.Discard, "", 0)
		defer delete(LogPages, "Search")
	}

	card := mtgmatcher.GetUUIDs()[0]
	page := "https://mtgban.com/search?chart=" + card
	target := "/search/oembed?format=json&url=" + url.QueryEscape(page)

	rec := httptest.NewRecorder()
	Search(rec, httptest.NewRequest(http.MethodGet, target, nil))

	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("an unsigned unfurl answered as %q, want the chart envelope", got)
	}

	var envelope struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("the envelope is not JSON: %v", err)
	}
	if envelope.Type != "photo" || !strings.Contains(envelope.URL, "/api/chart/image.png") {
		t.Errorf("answered with a %q pointing at %q", envelope.Type, envelope.URL)
	}
}

// A page with neither a query nor a chart is still nothing to unfurl.
func TestOEmbedRefusesAPageItCannotName(t *testing.T) {
	if len(mtgmatcher.GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	target := "/search/oembed?format=json&url=" + url.QueryEscape("https://mtgban.com/search")
	rec := httptest.NewRecorder()
	Search(rec, httptest.NewRequest(http.MethodGet, target, nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("a bare page answered %d, want %d", rec.Code, http.StatusNotFound)
	}
}
