package main

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
)

// A request can raise more than one notice: a chart roster cut to the cap,
// then a search that finds nothing or too much, then a chart with no data.
// The page shows every one, in the order raised, each on its own line.
func TestSearchPageShowsEveryNotice(t *testing.T) {
	skipWithoutDatastore(t)
	withSigMode(t, true, false)
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Search"] == nil {
		LogPages["Search"] = log.New(io.Discard, "", 0)
		defer delete(LogPages, "Search")
	}

	set, err := backend().GetSet("M10")
	if err != nil {
		t.Skip("no M10")
	}
	var ids []string
	for _, card := range set.Cards {
		ids = append(ids, card.UUID)
		if len(ids) == 11 {
			break
		}
	}
	if len(ids) < 11 {
		t.Skip("M10 has too few cards")
	}
	eleven := strings.Join(ids, ",")
	unmatched := "00000000-0000-0000-0000-000000000000"

	capped := "Charts show up to 10 cards; the extras were left off."
	dropped := "One of the charted cards could not be matched to a printing and was left out."
	for _, probe := range []struct {
		name   string
		page   string
		mobile bool
		want   []string
	}{
		{"a capped roster and a search that finds nothing", "/search?q=zzzqx&chart=" + eleven, false, []string{capped, NoCardsMessage}},
		{"a capped roster and a search that finds too much", "/search?q=" + url.QueryEscape("t:creature") + "&chart=" + eleven, false, []string{capped, TooManyMessage}},
		{"on a phone, a capped roster and a search that finds too much", "/search?q=" + url.QueryEscape("t:creature") + "&chart=" + eleven, true, []string{capped, TooManyMessage}},
		{"a capped roster, an unmatched card and no chart data", "/search?chart=" + strings.Join(ids[:9], ",") + "," + unmatched + "," + strings.Join(ids[9:], ","), false, []string{capped, dropped, "No chart data available"}},
		{"a capped roster in the chart picker with a pinned bar that finds nothing", "/search?modal=1&scope=" + url.QueryEscape("s:LEA cn:99999") + "&chart=" + eleven, true, []string{capped, NoResultsMessage}},
	} {
		req := httptest.NewRequest(http.MethodGet, probe.page, nil)
		if probe.mobile {
			req.AddCookie(&http.Cookie{Name: "MobileView", Value: "true"})
		}
		w := httptest.NewRecorder()
		testSite.Search(w, req)

		want := strings.Join(probe.want, "<br>")
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("%s: the page does not show %q", probe.name, want)
		}
	}
}

// A sealed page can list several products whose simulated values spread
// too widely. It cautions once, after what the request raised before it.
func TestSealedCautionShowsOnce(t *testing.T) {
	skipWithoutDatastore(t)
	withSigMode(t, true, false)
	keepScrapers(t)
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Search"] == nil {
		LogPages["Search"] = log.New(io.Discard, "", 0)
		defer delete(LogPages, "Search")
	}

	set, err := backend().GetSet("M10")
	if err != nil || len(set.SealedProduct) < 2 || len(set.Cards) < 11 {
		t.Skip("M10 lacks the products or cards this needs")
	}
	var cards []string
	for _, card := range set.Cards[:11] {
		cards = append(cards, card.UUID)
	}
	products := []string{set.SealedProduct[0].UUID, set.SealedProduct[1].UUID}

	// Both products carry a sealed EV row, and the simulation behind it
	// spreads past IQRThreshold.
	now := time.Now()
	priced := func(price, iqr float64) mtgban.InventoryRecord {
		inventory := mtgban.InventoryRecord{}
		for _, id := range products {
			entry := &mtgban.InventoryEntry{Conditions: "NM", Price: price, Quantity: 1}
			if iqr > 0 {
				entry.ExtraValues = map[string]float64{"iqr": iqr}
			}
			inventory.Add(id, entry)
		}
		return inventory
	}
	info := func(shorthand, name string) mtgban.ScraperInfo {
		return mtgban.ScraperInfo{Shorthand: shorthand, Name: name, SealedMode: true, MetadataOnly: true, InventoryTimestamp: &now}
	}
	sellers := []mtgban.Seller{
		mtgban.NewSellerFromInventory(priced(60, 0), info("TCGLowEV", "TCG Low EV")),
		mtgban.NewSellerFromInventory(priced(58, IQRThreshold+50), info("TCGLowSim", "TCG Low Sim")),
	}
	sellersPtr.Store(&sellers)
	scraperIndexPtr.Store(buildScraperIndex(map[string]map[string][]string{"sealed_ev": {"retail": {"TCGLowEV", "TCGLowSim"}}}))

	page := "/sealed?q=" + url.QueryEscape("s:M10") + "&chart=" + strings.Join(cards, ",")
	w := httptest.NewRecorder()
	testSite.Search(w, httptest.NewRequest(http.MethodGet, page, nil))
	body := w.Body.String()

	capped := "Charts show up to 10 cards; the extras were left off."
	caution := "CAUTION - This search includes products with a high IQR, please check the FAQs to understand how it may impact the computed values"
	shown := strings.Count(body, caution)
	if shown != 1 {
		t.Errorf("the caution shows %d times, want once", shown)
	}
	if !strings.Contains(body, capped+"<br>"+caution) {
		t.Error("the caution does not follow the cap note")
	}
}

// A roster's dropped cards are counted in the notice, or named as one.
func TestChartIDsDroppedNotice(t *testing.T) {
	for _, c := range []struct {
		dropped, total int
		why, want      string
	}{
		{1, 3, "failed to load", "One of the charted cards failed to load and was left out."},
		{2, 3, "failed to load", "2 of the 3 charted cards failed to load and were left out."},
		{1, 2, "could not be matched to a printing", "One of the charted cards could not be matched to a printing and was left out."},
		{10, 10, "could not be matched to a printing", "10 of the 10 charted cards could not be matched to a printing and were left out."},
	} {
		got := chartIDsDroppedNotice(c.dropped, c.total, c.why)
		if got != c.want {
			t.Errorf("%d of %d %s: %q, want %q", c.dropped, c.total, c.why, got, c.want)
		}
	}
}
