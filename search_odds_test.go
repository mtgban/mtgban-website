package main

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

// productWithVariableCards finds a product whose variable reading answers
// with cards rather than with the packs it wraps - a Fat Pack might hold its
// boosters, and the odds are of the cards inside those, not of the boosters -
// and whose cards are not all equally likely, so that an order means something.
func productWithVariableCards(t *testing.T) *mtgmatcher.CardObject {
	t.Helper()
	for _, code := range backend().GetAllSets() {
		set, err := backend().GetSet(code)
		if err != nil {
			continue
		}
		for _, product := range set.SealedProduct {
			if !backend().SealedHasDecklist(code, product.UUID) ||
				!backend().SealedIsRandom(code, product.UUID) {
				continue
			}
			co, err := backend().GetUUID(product.UUID)
			if err != nil {
				continue
			}
			config := parseSearchOptionsNG(`variable:"`+co.Name+`"`, nil, nil, nil)
			found, err := searchAndFilter(config)
			if err != nil || !containsSingles(found) {
				continue
			}
			odds := dropOdds(config)
			distinct := map[float64]bool{}
			for _, uuid := range found {
				if rate, ok := odds[uuid]; ok {
					distinct[rate] = true
				}
			}
			if len(distinct) > 1 {
				return co
			}
		}
	}
	return nil
}

// Only the variable reading asks how likely each card is: the fixed list is
// certain, and everything a product can hold mixes the two.
func TestDropOddsAnswerTheVariableReadingOnly(t *testing.T) {
	if len(backend().GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	co := productWithVariableCards(t)
	if co == nil {
		t.Skip("this datastore has no product whose variable reading holds cards")
	}

	for _, mode := range []string{ContentsAll, ContentsFixed} {
		config := parseSearchOptionsNG(mode+`:"`+co.Name+`"`, nil, nil, nil)
		if odds := dropOdds(config); odds != nil {
			t.Errorf("the %s reading carries odds for %d cards", mode, len(odds))
		}
	}
	if dropOdds(SearchConfig{}) != nil {
		t.Error("an ordinary search carries odds")
	}

	config := parseSearchOptionsNG(`variable:"`+co.Name+`"`, nil, nil, nil)
	odds := dropOdds(config)
	if len(odds) == 0 {
		t.Fatalf("%s opens into nothing", co.Name)
	}
	for uuid, rate := range odds {
		if rate <= 0 {
			t.Errorf("%s comes out of %s at %v", uuid, co.Name, rate)
		}
	}

	// And the cards the reading finds are the ones it answers for. Not
	// every one: a Countdown Kit upgrades cards to foil at a chance the data
	// cannot express, and those foils have no odds to show.
	found, err := searchAndFilter(config)
	if err != nil {
		t.Fatal(err)
	}
	var known int
	for _, uuid := range found {
		if _, ok := odds[uuid]; ok {
			known++
		}
	}
	if known == 0 {
		t.Errorf("none of the %d cards %s might hold has odds", len(found), co.Name)
	}
}

// An average count prints as a bare number with the decimals it needs and no
// more, and never a percentage - the same card counted from more than one
// slot can pass 1, past what a chance could mean.
func TestFormatExpectedCount(t *testing.T) {
	for _, tt := range []struct {
		count float64
		want  string
	}{
		{1, "1"},
		{0.2, "0.2"},
		{0.125, "0.12"},
		{0.0007, "0"},
		{1.5, "1.5"},
	} {
		if got := formatExpectedCount(tt.count); got != tt.want {
			t.Errorf("%v prints as %q, want %q", tt.count, got, tt.want)
		}
	}
}

// On the page, each card the product might hold carries its expected count
// of copies as an index row, and the sort puts the fewest-expected card
// first - a variable search is for finding the card expected in the fewest
// copies, not the commons already obvious from their sheer number under
// every other sort.
func TestVariableReadingShowsAndSortsByDropRate(t *testing.T) {
	if len(backend().GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	defer func(dev, sig bool) { DevMode, SigCheck = dev, sig }(DevMode, SigCheck)
	DevMode, SigCheck = true, false
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Search"] == nil {
		LogPages["Search"] = log.New(io.Discard, "", 0)
		defer delete(LogPages, "Search")
	}
	co := productWithVariableCards(t)
	if co == nil {
		t.Skip("this datastore has no product whose variable reading holds cards")
	}
	query := `variable:"` + co.Name + `"`
	odds := dropOdds(parseSearchOptionsNG(query, nil, nil, nil))

	page := httptest.NewRecorder()
	Search(page, httptest.NewRequest(http.MethodGet, "/search?q="+url.QueryEscape(query)+"&sort=odds", nil))
	body := page.Body.String()

	if !strings.Contains(body, "Avg Copies") {
		t.Fatal("no average-count row on the page")
	}
	if !strings.Contains(body, `sort=odds`) || !strings.Contains(body, `data-lucide="copy"`) {
		t.Error("no button to sort by drop rate")
	}

	// The cards in page order, each once.
	var seen []string
	last := map[string]bool{}
	for _, m := range regexp.MustCompile(`data-card-id="([^"]+)"`).FindAllStringSubmatch(body, -1) {
		if !last[m[1]] {
			last[m[1]] = true
			seen = append(seen, m[1])
		}
	}
	if len(seen) < 2 {
		t.Skipf("%s shows %d cards, not enough to order", co.Name, len(seen))
	}

	// A card odds never covered is not a card with none, so it belongs
	// after every card the rate is actually known for, not among them at
	// whatever a missing entry's zero value happens to compare as.
	var covered int
	for _, id := range seen {
		if _, has := odds[id]; !has {
			break
		}
		covered++
	}
	if covered < 2 {
		t.Fatalf("only %d of %d shown cards carry a rate, not enough to order", covered, len(seen))
	}
	for _, id := range seen[covered:] {
		if _, has := odds[id]; has {
			t.Errorf("%s carries a rate but is shown after cards that don't", id)
			break
		}
	}
	for i := 1; i < covered; i++ {
		if odds[seen[i-1]] > odds[seen[i]] {
			t.Errorf("%s (%v) is shown before %s (%v)", seen[i-1], odds[seen[i-1]], seen[i], odds[seen[i]])
			break
		}
	}
	// And the rate the first card shows is its own.
	first := strings.Index(body, `data-card-id="`+seen[0]+`"`)
	second := strings.Index(body, `data-card-id="`+seen[1]+`"`)
	if !strings.Contains(body[first:second], formatExpectedCount(odds[seen[0]])) {
		t.Errorf("the first card shows no %s", formatExpectedCount(odds[seen[0]]))
	}
}

// The button sits beside the three readings, on the variable one alone.
func TestDropRateButtonRendersOnTheVariableReading(t *testing.T) {
	views := &ContentsViews{
		Product:  "Secret Lair Drop Special Guest Junji Ito English",
		Mode:     ContentsVariable,
		All:      `contents:"Secret Lair Drop Special Guest Junji Ito English"`,
		Fixed:    `decklist:"Secret Lair Drop Special Guest Junji Ito English"`,
		Variable: `variable:"Secret Lair Drop Special Guest Junji Ito English"`,
	}
	for _, mobile := range []bool{false, true} {
		out := renderPage(t, "search.html", mobile, PageVars{
			BetaNav:     &NavElem{},
			IsMobile:    mobile,
			SearchQuery: views.Variable,
			SearchRan:   true,
			SearchSort:  "odds",
			TotalUnique: 4,
			AllKeys:     []string{"a"},
			Contents:    views,
		})
		if !strings.Contains(out, `data-lucide="copy"`) {
			t.Errorf("mobile=%v: no drop rate button", mobile)
		}
		if !strings.Contains(out, `sort=odds`) {
			t.Errorf("mobile=%v: the button does not sort by odds", mobile)
		}

		views.Mode = ContentsFixed
		out = renderPage(t, "search.html", mobile, PageVars{
			BetaNav:     &NavElem{},
			IsMobile:    mobile,
			SearchQuery: views.Fixed,
			SearchRan:   true,
			TotalUnique: 4,
			AllKeys:     []string{"a"},
			Contents:    views,
		})
		if strings.Contains(out, `data-lucide="copy"`) {
			t.Errorf("mobile=%v: the fixed reading offers a drop rate sort", mobile)
		}
		views.Mode = ContentsVariable
	}
}

// A card is bought back, never sold, at the rate it might come out of a
// pack at - the fixed and floating offers under Sellers all price a copy
// already in hand - so the row belongs with what someone would buy it back
// for, not with those.
func TestDropRateShowsOnlyOnTheBuyersSide(t *testing.T) {
	if len(backend().GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	defer func(dev, sig bool) { DevMode, SigCheck = dev, sig }(DevMode, SigCheck)
	DevMode, SigCheck = true, false
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Search"] == nil {
		LogPages["Search"] = log.New(io.Discard, "", 0)
		defer delete(LogPages, "Search")
	}
	co := productWithVariableCards(t)
	if co == nil {
		t.Skip("this datastore has no product whose variable reading holds cards")
	}
	query := `variable:"` + co.Name + `"`
	odds := dropOdds(parseSearchOptionsNG(query, nil, nil, nil))

	page := httptest.NewRecorder()
	Search(page, httptest.NewRequest(http.MethodGet, "/search?q="+url.QueryEscape(query), nil))
	body := page.Body.String()

	// data-card-id repeats within a card's own block (chart and favorite
	// buttons carry it too); data-chart-id only opens the header, so it is
	// what actually bounds one card's markup from the next.
	blocks := strings.Split(body, `data-chart-id="`)
	var checked int
	for _, block := range blocks[1:] {
		id := strings.SplitN(block, `"`, 2)[0]
		rate, has := odds[id]
		if !has {
			continue
		}
		sellers := strings.Index(block, ">Sellers<")
		buyers := strings.Index(block, ">Buyers<")
		if sellers < 0 || buyers < 0 {
			t.Errorf("%s has no Sellers/Buyers split", id)
			continue
		}
		if strings.Contains(block[sellers:buyers], "Avg Copies") {
			t.Errorf("%s's sellers side shows a drop rate too", id)
		}
		if !strings.Contains(block[buyers:], formatExpectedCount(rate)) {
			t.Errorf("%s's buyers side does not show %s", id, formatExpectedCount(rate))
		}
		checked++
		if checked >= 5 {
			break
		}
	}
	if checked == 0 {
		t.Fatal("no card with odds was found on the page")
	}
}

// A synthetic row has no scraper to compare a card's hotlist store against or
// to send an admin's fix to. An empty Shorthand would equal a card's own
// empty HotlistStore, putting Card Kingdom's 3-month star on a row that is
// not Card Kingdom's - the buyers side alone calls buylist_badge at all, so
// it is the only side that could show it.
func TestDropRateDoesNotBorrowACKBadgeOrAFixLink(t *testing.T) {
	if len(backend().GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	defer func(dev, sig bool) { DevMode, SigCheck = dev, sig }(DevMode, SigCheck)
	DevMode, SigCheck = true, false
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Search"] == nil {
		LogPages["Search"] = log.New(io.Discard, "", 0)
		defer delete(LogPages, "Search")
	}
	co := productWithVariableCards(t)
	if co == nil {
		t.Skip("this datastore has no product whose variable reading holds cards")
	}
	query := `variable:"` + co.Name + `"`
	odds := dropOdds(parseSearchOptionsNG(query, nil, nil, nil))

	page := httptest.NewRecorder()
	Search(page, httptest.NewRequest(http.MethodGet, "/search?q="+url.QueryEscape(query), nil))
	body := page.Body.String()

	blocks := strings.Split(body, `data-chart-id="`)
	var checked int
	for _, block := range blocks[1:] {
		id := strings.SplitN(block, `"`, 2)[0]
		if _, has := odds[id]; !has {
			continue
		}
		buyers := strings.Index(block, ">Buyers<")
		if buyers < 0 {
			continue
		}
		dr := strings.Index(block[buyers:], "Avg Copies")
		if dr < 0 {
			t.Errorf("%s has no Avg Copies row on the buyers side", id)
			continue
		}
		rowStart := buyers + dr
		rowEnd := rowStart + 500
		if rowEnd > len(block) {
			rowEnd = len(block)
		}
		row := block[rowStart:rowEnd]
		if strings.Contains(row, "emoji") {
			t.Errorf("%s's Avg Copies row wears the hotlist badge", id)
		}
		if strings.Contains(row, "fixstore=AvgCopies") {
			t.Errorf("%s's Avg Copies row offers a fix link", id)
		}
		checked++
		if checked >= 5 {
			break
		}
	}
	if checked == 0 {
		t.Fatal("no card with odds was found on the page")
	}
}

// The row's visibility is not tied to the sort: every sort mode shows the
// same number of Avg Copies rows, and the pill only reorders them.
func TestDropRateVisibilityDoesNotDependOnSort(t *testing.T) {
	if len(backend().GetUUIDs()) == 0 {
		t.Skip("no datastore loaded")
	}
	defer func(dev, sig bool) { DevMode, SigCheck = dev, sig }(DevMode, SigCheck)
	DevMode, SigCheck = true, false
	if LogPages == nil {
		LogPages = map[string]*log.Logger{}
	}
	if LogPages["Search"] == nil {
		LogPages["Search"] = log.New(io.Discard, "", 0)
		defer delete(LogPages, "Search")
	}
	co := productWithVariableCards(t)
	if co == nil {
		t.Skip("this datastore has no product whose variable reading holds cards")
	}
	query := `variable:"` + co.Name + `"`

	var counts []int
	for _, sort := range []string{"", "chrono", "alpha", "number", "odds"} {
		u := "/search?q=" + url.QueryEscape(query)
		if sort != "" {
			u += "&sort=" + sort
		}
		page := httptest.NewRecorder()
		Search(page, httptest.NewRequest(http.MethodGet, u, nil))
		counts = append(counts, strings.Count(page.Body.String(), "Avg Copies"))
	}
	for i := 1; i < len(counts); i++ {
		if counts[i] != counts[0] {
			t.Errorf("sort changed the number of Avg Copies rows: %v", counts)
			break
		}
	}
	if counts[0] == 0 {
		t.Fatal("no Avg Copies rows on the page at all")
	}
}
