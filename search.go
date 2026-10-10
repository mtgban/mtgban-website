package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	cm "github.com/mtgban/go-cardmarket"

	"github.com/BlueMonday/go-scryfall"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/go-mtgban/tcgplayer"
	"github.com/mtgban/mtgban-website/internal/embed"
	"github.com/mtgban/mtgban-website/internal/suggest"
)

const (
	MaxSearchQueryLen = 1000
	MaxSearchResults  = 100
	TooLongMessage    = "Your query planeswalked away, try a shorter one"
	TooManyMessage    = "Too many results, try adjusting your filters"
	NoResultsMessage  = "No products matching your search could be found"
	NoPromosMessage   = "No products matching your search could be found - some promos may be hidden"
	NoCardsMessage    = "No products matching your search could be found"

	MaxSearchTotalResults = 10000
)

var (
	defaultSellerPriorityOpt = []string{"TCGMarket", "TCGLow", "TCGSealed"}
	defaultVendorPriorityOpt = []string{"CK", "SCG", "SS"}
)

type SearchEntry struct {
	ScraperName  string
	Shorthand    string
	Price        float64
	Credit       float64
	MarketCredit float64
	Ratio        float64
	Quantity     int
	URL          string
	NoQuantity   bool
	BundleIcon   string

	// Listings is TCGplayer's sellers/copies for the grade, on the TCGplayer
	// store's rows (tcglistings.go), and ListingsTitle says what they count.
	Listings      string
	ListingsTitle string

	// PriceUnit says what the number in this row's price slot is worth: an
	// offer to rank and show as currency (the zero value), a store's count
	// of copies wanted (the scraper declares it), or a synthetic row's
	// expected count of copies (built here). PriceSymbol/PriceAmount spell
	// it; IsOffer says whether it belongs in the ranking at all.
	PriceUnit PriceUnit

	Country string

	Secondary float64

	// IsEV marks a row produced by the sealed expected-value collapse. The
	// EV/Median/StdDev columns only mean anything for those, so the header
	// naming them follows this rather than the mere presence of index rows.
	IsEV bool

	ExtraValues map[string]float64

	Locked bool
}

// marketValue is what a buylist offer is worth on the market: its store
// credit at the market rate, or its cash price where the store pays no
// credit or its credit has no market rate.
func (e SearchEntry) marketValue() float64 {
	if e.MarketCredit == 0 {
		return e.Price
	}
	return e.MarketCredit
}

// PriceUnit is what SearchEntry.PriceUnit names: what a row's price slot
// measures, since not every row's number is a dollar amount to rank.
type PriceUnit int

const (
	PriceUnitDollar        PriceUnit = iota // an offer: ranked, shown as currency
	PriceUnitCount                          // a store's want-count, shown as # N
	PriceUnitExpectedCount                  // an average count of copies, shown as a bare number
)

// quantityUnit reads a scraper's own QuantityPriority flag into the unit its
// rows carry - the only place that boundary is crossed, so a name change on
// either side of it stays a one-line fix.
func quantityUnit(quantityPriority bool) PriceUnit {
	if quantityPriority {
		return PriceUnitCount
	}
	return PriceUnitDollar
}

// IsOffer reports whether a row's price is a real offer: ranked against the
// others' and worth comparing to a reference like a 90-day high.
func (e SearchEntry) IsOffer() bool {
	return e.PriceUnit == PriceUnitDollar
}

// PriceSymbol is the mark before a row's price-slot amount: a dollar sign
// for an offer, a hash before a want-count, or nothing before an expected
// count, which is not a currency and not a count of anything on a shelf.
func (e SearchEntry) PriceSymbol() string {
	switch e.PriceUnit {
	case PriceUnitCount:
		return "#"
	case PriceUnitExpectedCount:
		return ""
	default:
		if e.Price == 0 {
			return ""
		}
		return "$"
	}
}

// PriceAmount is the number itself, spelled the way its unit is: two
// decimals for an offer, a bare count for a want-count, or an expected count
// trimmed to as many decimals as it needs - never a percentage, since
// summing the same card across more than one slot can carry it past what a
// probability could mean.
func (e SearchEntry) PriceAmount() string {
	switch e.PriceUnit {
	case PriceUnitCount:
		return strconv.Itoa(e.Quantity)
	case PriceUnitExpectedCount:
		return formatExpectedCount(e.Price)
	default:
		if e.Price == 0 {
			return ""
		}
		return fmt.Sprintf("%.2f", e.Price)
	}
}

// PriceLabel is PriceSymbol and PriceAmount joined as one string, for a
// price cell that isn't styled as two spans: a space between them where the
// unit leads with a symbol, none where it doesn't - an expected count
// carries no mark of its own, so there is nothing to space it from.
func (e SearchEntry) PriceLabel() string {
	symbol, amount := e.PriceSymbol(), e.PriceAmount()
	if amount == "" {
		return ""
	}
	if symbol == "" {
		return amount
	}
	return symbol + " " + amount
}

var AllConditions = []mtgban.Condition{"INDEX", mtgban.NM, mtgban.SP, mtgban.MP, mtgban.HP, mtgban.PO}

// scopeFilters reads the pinned bar into the filters it contributes.
//
// The two bars are parsed apart and merged as filters, never as text.
// The finish shorthand reads the literal last byte of a query - the
// backtick of "abrade`" is what makes it foil and altfoil - and the bot
// syntax splits on position, so gluing the two strings together would
// quietly change what the main bar said.
//
// Parsed without the reader's display options, unlike the main query:
// hidePromos and hidePrelPack add filters of their own, and the main
// query's parse has already added them. A second set here would only
// collide with the first.
//
// Only filters come back: a card name typed into the pinned bar is
// dropped, because pinning a name is what the main bar is for. A bar
// that yields nothing at all is a bar the search will ignore, which is
// the one thing the reader has to be told.
func scopeFilters(b *mtgmatcher.Backend, scope string) []FilterElem {
	if scope == "" {
		return nil
	}
	return parseSearchOptionsNG(b, scope, nil, nil, nil).CardFilters
}

// applySearchScope folds the pinned bar's filters into the search the
// main bar asked for. Every one of them, whatever the main bar says.
//
// Nothing here decides that one of two filters was not meant. Filters
// are ANDed, so a pinned "s:sos" under a typed "s:mh3" does answer
// nothing - but that is what the reader asked for twice, and the empty
// page names the bar that narrowed it and offers to drop it, which is a
// better answer than quietly searching for something else. Dropping one
// side is the version with no way back: the results look ordinary and
// the bar reads as applied while it is not.
//
// It is also the only rule that stays true of filters we do not model.
// Deciding which of two filters wins means knowing whether they share
// an axis - two editions do, "is foil" and "is promo" do not, and the
// site's own links write is: - and every guess at that was wrong for
// somebody. A reader who hides promos lost every finish they pinned to
// one such guess.
func applySearchScope(config *SearchConfig, pinned []FilterElem) {
	if len(pinned) == 0 {
		return
	}
	// A query that names its own cards, or that we hand to another
	// syntax whole, is not ours to narrow.
	if config.SearchMode == "hashing" || config.SearchMode == "scryfall" {
		return
	}

	config.CardFilters = append(config.CardFilters, pinned...)
}

// searchSuggestions adapts a parsed search that found nothing into the
// suggest package's inputs.
func searchSuggestions(b *mtgmatcher.Backend, rawQuery string, config SearchConfig, sealed bool) (string, []suggest.AltSearch) {
	return suggest.Build(suggest.Params{
		RawQuery:       rawQuery,
		CleanQuery:     config.CleanQuery,
		SearchMode:     config.SearchMode,
		AppliedFilters: config.AppliedFilters,
		Sealed:         sealed,
		Backend:        b,
	})
}

// searchFallback re-reads a search whose name matched nothing, in the order a
// searcher is likely to have meant it. "metal" names no card, but on the games
// that print treatments as promo types it names a finish, and a storefront
// lists the card under it. Failing that the word is read as a set: someone
// typing "shadows" wants what is in the sets called that.
//
// Every filter the query already carried is kept, so "s:OGN metal" still means
// that set; only the name is read a second way. A hashing search names its own
// cards and is left alone.
func searchFallback(ds *datastore, config SearchConfig) []string {
	if config.CleanQuery == "" || config.SearchMode == "hashing" {
		return nil
	}

	query := config.CleanQuery
	config.CleanQuery = ""
	config.FullQuery = ""
	base := slices.Clone(config.CardFilters)

	if promoTypes := promoTypeMatches(ds.backend, query); len(promoTypes) > 0 {
		config.CardFilters = append(slices.Clone(base), FilterElem{
			Name:   "is",
			Values: promoTypes,
		})
		if keys, err := searchAndFilter(ds, config); err == nil && len(keys) > 0 {
			return keys
		}
	}

	// A set the query already narrowed to is not up for reinterpretation:
	// "s:OGN shadows" asked about OGN, and answering with every set named
	// shadows would throw away what the searcher did say.
	if _, narrowed := editionSeedCodes(base); narrowed {
		return nil
	}

	if codes := setCodeMatches(ds.backend, query); len(codes) > 0 {
		config.CardFilters = append(slices.Clone(base), FilterElem{
			Name:   "edition",
			Values: codes,
		})
		if keys, err := searchAndFilter(ds, config); err == nil && len(keys) > 0 {
			return keys
		}
	}

	return nil
}

// isValidChartID reports whether a chart= piece is a plausibly chartable id: a
// mtgmatcher id, a ban:/tcg:/scryfall:/mtgjson: prefixed id, a bare number (a
// TCGplayer id), or something shaped like an mtgjson uuid. Full resolution
// happens at render time.
//
// The uuid shape has to pass even when mtgmatcher does not carry it, because
// resolution has a fallback for exactly that case: a printing the datastore
// retired but the archive still holds prices for charts from our own history.
// Refusing it here is what decides it never gets asked about.
func isValidChartID(b *mtgmatcher.Backend, part string) bool {
	if _, err := b.GetUUID(part); err == nil {
		return true
	}
	switch prefix, _ := splitIDPrefix(part); prefix {
	case "ban", "tcg", "scryfall", "mtgjson":
		return true
	}
	if maybeUUIDString(part) {
		return true
	}
	_, err := strconv.Atoi(part)
	return err == nil
}

// magicFinishSearchID re-tags an mtgjson uuid with the finish of the variant it
// came from. The variants table stores the finish beside the base uuid, while
// mtgmatcher gives each finish its own id ("_f", "_e"), so handing the bare uuid
// back to the search always lands on the nonfoil printing. Falls back to the
// uuid when the finish has no id of its own.
func magicFinishSearchID(b *mtgmatcher.Backend, uuid string, foil, etched bool) string {
	if matched, err := b.MatchID(uuid, foil, etched); err == nil {
		return matched
	}
	return uuid
}

// chartIDsDroppedNotice tells the reader that part of the roster was left out
// of the chart and why.
func chartIDsDroppedNotice(dropped, total int, why string) string {
	if dropped == 1 {
		return "One of the charted cards " + why + " and was left out."
	}
	return fmt.Sprintf("%d of the %d charted cards %s and were left out.", dropped, total, why)
}

// chartSearchID names the results-table row for a roster id. The resolved
// target already knows it - resolving is what reads the archive, and the chart
// needs that same answer - so the table and the chart cannot disagree about
// which printing a roster id means.
//
// A target is nil when nothing resolved, and on a deployment with no archive at
// all, where the matcher can still map a plain id. ok=false means the id is
// handed back as it came: the results table will find no row for it, so the
// card drops out of the page it was asked for. The caller says so rather than
// letting it vanish.
func chartSearchID(b *mtgmatcher.Backend, id string, target *chartTarget) (string, bool) {
	if target != nil {
		if target.SearchID != "" {
			return target.SearchID, true
		}
		// The resolver already tried every id space it knows and came back
		// without a row id, so there is no row. Asking the matcher again
		// from the raw string second-guesses that, and the raw string is
		// exactly what cannot be read twice: a ban_id and a TCGplayer
		// product id can be the same number, which is the trap
		// resolveChartTarget's precedence exists to avoid.
		return id, false
	}

	// Nothing resolved, so there is no archive to have resolved against -
	// a deployment without one, where the matcher still places a plain id.
	if _, err := b.GetUUID(id); err == nil {
		return id, true // already a matcher id (bare uuid / variant string)
	}
	prefix, val := splitIDPrefix(id)
	// ban: names our own surrogate. That integer means nothing to the
	// matcher's external map, where the same number belongs to a product.
	if prefix == "ban" {
		return id, false
	}

	// tcg:, scryfall:, mtgjson:, or a bare id mtgmatcher maps through its external
	// id table (a TCGplayer product id, a Scryfall id, or an mtgjson uuid).
	if matched, merr := b.MatchID(val); merr == nil {
		return matched, true
	}
	return id, false
}

// parseChartIDs splits a chart=... param (comma-separated UUIDs) into a
// validated, de-duplicated list. Pieces that don't resolve via mtgmatcher are
// dropped silently, mirroring how single-UUID chart= used to be handled.
//
// The roster is capped at the palette size: the multi-card chart can only
// render that many distinguishable lines, and it bounds the per-UUID DB
// fan-out (a resolution and a price read per card) triggered on this public
// handler by a crafted many-UUID chart= URL. truncated reports whether at
// least one otherwise-valid, distinct card was dropped for exceeding the cap,
// so the caller can tell the user instead of silently swallowing it.
func parseChartIDs(b *mtgmatcher.Backend, chartParam string) (ids []string, truncated bool) {
	if chartParam == "" {
		return nil, false
	}
	for _, part := range strings.Split(chartParam, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !isValidChartID(b, part) {
			continue
		}
		if slices.Contains(ids, part) {
			continue
		}
		if len(ids) >= len(multiCardPalette) {
			truncated = true
			break
		}
		ids = append(ids, part)
	}
	return ids, truncated
}

// SearchVars are the PageVars fields only the search page fills and reads.
type SearchVars struct {
	Embed struct {
		OEmbedURL    string
		PageURL      string
		Title        string
		ImageURL     string
		ImageCropURL string
		Description  string
		RetailLabel  string
		RetailPrice  float64
		BuylistLabel string
		BuylistPrice float64
	}

	AllKeys        []string
	CardQuantities map[string]int
	ListingLocked  bool
	SearchSort     string
	AlphaSort      string
	CondKeys       []mtgban.Condition
	FoundSellers   map[string]map[mtgban.Condition][]SearchEntry
	FoundVendors   map[string]map[mtgban.Condition][]SearchEntry
	SetKeyrunes    map[string]string
	NoSort         bool
	HasAvailable   bool
	// A search ran for this request. Not the same as SearchQuery being set:
	// a pinned filter searches on its own, and the page has results to draw
	// (or an empty-handed answer to give) with the box above it empty.
	SearchRan    bool
	CanFixSearch bool

	// Suggestions shown when a search returns no results
	DidYouMean         string
	AltSearches        []suggest.AltSearch
	CanDownloadCSV     bool
	DefaultTab         string
	DefaultView        mtgban.Condition
	MobileSearchLayout string
	OfflineModeAllowed bool
	MaxLookbackDays    int
	// ChartLoadedDays is how much history the page actually rendered inline:
	// the window the chart first draws, or everything the tier allows when
	// that window holds no prices. The front-end fetches the rest from
	// /api/chart only if the viewer asks for a wider range.
	ChartLoadedDays   int
	AxisLabels        []string
	Datasets          []Dataset
	Checkpoints       []ChartCheckpoint
	ChartID           string
	ChartIDs          []string
	MaxChartCards     int
	ChartReferences   []string
	Alternative       string
	StocksURL         string
	AltEtchedID       string
	EditionFilterList []EditionEntry

	SearchQuery string

	// The sticky filter bar: what the searcher pinned once and does not
	// retype, kept apart from SearchQuery so either bar can change without
	// disturbing the other. CanScope is what draws it at all, since the
	// navbar is shared with pages that run no search.
	SearchScope string
	CanScope    bool
	// The bar holds something that parses to no filter at all, so the
	// search passes over it whole.
	ScopeIgnored bool

	// The switch between the three readings of a sealed product's contents,
	// nil unless the search is one of them over a product that has all three
	Contents *ContentsViews

	FlatEditions []FlatEditionEntry
	IsMultiChart bool

	EditionSort []string
	EditionList map[string][]EditionEntry
	IsSealed    bool
	TotalSets   int
	TotalCards  int
	TotalUnique int

	// CanAlerts says the reader's ACL grants the Alerts page and an
	// allowance, so result rows may offer the alert link.
	CanAlerts bool

	// Printings is each result's printings row for the sidebar, from
	// cardPrintings.
	Printings map[string]string

	// Notices are what the page tells the reader about this request, in the
	// order they were raised: why a search shows few or no cards, what a
	// chart left out, a caution about the figures. Each is a sentence of its
	// own, and none replaces another.
	Notices []string
}

func (s *site) Search(w http.ResponseWriter, r *http.Request) {
	ds := s.datastore()
	b := ds.backend
	sig := verifiedSignature(r)

	pageVars := genPageNav(s, r, "Search", sig)
	pageVars.CanAlerts, pageVars.CanFixSearch = searchReader(s, r)

	blocklistRetail, blocklistBuylist, _ := getSearchBlocklists(r, sig)

	query := strings.TrimSpace(r.FormValue("q"))
	// The pinned bar lives in the url alone, so a page opened without it
	// starts with nothing pinned.
	scope := strings.TrimSpace(r.FormValue("scope"))
	pinned := scopeFilters(b, scope)
	pageVars.SearchScope = scope
	pageVars.CanScope = true
	// Something is pinned, and none of it is a filter: the search will pass
	// over it whole, and the bar has to say so rather than sit there looking
	// like it is doing the work.
	pageVars.ScopeIgnored = scope != "" && len(pinned) == 0

	pageVars.IsSealed = r.URL.Path == "/sealed"
	isSetsPage := r.URL.Path == "/sets"

	// A pinned filter names a set of cards the same way a query does, so a
	// bar with something in it is a search even when the box above it is
	// empty: searchAndFilter already seeds from an edition, a number or a
	// store when there is no text to search. A bar the parser made no filter
	// of is not one - it would seed nothing and find nothing, which the
	// landing page says better than an empty result does.
	//
	// The editions tree on /sets is a page rather than a placeholder waiting
	// for a query, so it keeps its own empty state either way.
	scopeOnly := query == "" && len(pinned) > 0 && !isSetsPage

	pageVars.HasAvailable = len(b.GetSealedUUIDs()) > 0
	_, pageVars.OfflineModeAllowed = offlineModeAllowed(r)
	// Only the mobile page lists the stores in its own settings drawer; the
	// desktop modal asks /api/settings/modal for them when it opens.
	if pageVars.IsMobile {
		pageVars.SellerKeys, pageVars.VendorKeys = searchSettingsKeys()
	}

	page := r.FormValue("page")
	if page == "options" {
		http.Redirect(w, r, r.URL.Path+"?settings=1", http.StatusFound)
		return
	}

	// For open mode (Any), disable history charts and keep each card's
	// stores in name order, whatever the listing priority cookie says
	pageVars.DisableChart = sig == "" && SigCheck
	pageVars.ListingLocked = pageVars.DisableChart
	pageVars.SealedContents = sealedContentsPref(readCookie(r, "SearchSealedContents"))
	fillSearchPrefs(&pageVars.SearchVars, r)

	if len(query) > MaxSearchQueryLen {
		pageVars.ErrorMessage = TooLongMessage

		render(w, "search.html", pageVars)
		return
	}

	roster, query := fillChartRoster(&pageVars.SearchVars, r, b, query, pageVars.DisableChart)
	pageVars.ModalMode = roster.modal
	pageVars.ChartIDsCSV = strings.Join(roster.ids, ",")
	landing := query == "" && !scopeOnly
	pageVars.Title = searchTitle(pageVars.Title, roster.id != "", pageVars.IsSealed, isSetsPage && landing)

	// If neither bar holds anything there is nothing to do
	if landing {
		sortOpt := r.FormValue("sort")
		if isSetsPage {
			pageVars.SortOption = sortOpt
		}
		tmpl := fillSearchLanding(&pageVars.SearchVars, ds, isSetsPage, sortOpt)
		render(w, tmpl, pageVars)
		return
	}

	// Past here the request is a search, whichever bar asked for it. The page
	// draws results rather than the landing panes on the strength of this
	// rather than of a query being present, since a scope-only search has
	// none - including when it finds nothing, which is a result too.
	pageVars.SearchRan = true

	start := time.Now()

	miscSearchOpts := readSearchMiscOpts(r)
	preferFlavor := miscSearchOpts.has("preferFlavor")

	// Keep track of what was searched
	pageVars.SearchQuery = query
	pageVars.Embed.PageURL = absoluteURL(r, r.URL.String())
	// Point the consumer at the very page it is unfurling: a fixed /search?q=
	// names a different url than og:url on /sealed, or under any parameter
	// the reader arrived with.
	pageVars.Embed.OEmbedURL = absoluteURL(r, "/search/oembed?format=json&url="+url.QueryEscape(pageVars.Embed.PageURL))
	pageVars.CondKeys = AllConditions
	pageVars.ShowUpsell = !miscSearchOpts.has("noUpsell")

	config := parseSearchOptionsNG(b, query, blocklistRetail, blocklistBuylist, miscSearchOpts)
	applySearchScope(&config, pinned)
	if pageVars.IsSealed {
		config.SearchMode = "sealed"
	}

	// Only a reader whose signature was checked gets the custom buylist
	canUploadCustom, _ := strconv.ParseBool(GetParamFromSig(sig, "UploadCustom"))
	config.CustomBuylist = canUploadCustom || (DevMode && !SigCheck)

	pageVars.CleanSearchQuery = config.CleanQuery
	pageVars.SearchSort = readSearchSort(r, config)
	pageVars.NoSort = config.SortMode != ""

	result := runSearch(r, ds, config)
	if result.message != "" {
		pageVars.Notices = append(pageVars.Notices, result.message)
	}
	if len(result.keys) == 0 {
		pageVars.PopularSearches = getPopularSearches(ds)
		pageVars.DidYouMean, pageVars.AltSearches = searchSuggestions(b, query, config, pageVars.IsSealed)
		render(w, "search.html", pageVars)
		return
	}
	pageVars.CardHashes = result.hashes

	// Allow displaying the "search all" link only when something
	// was searched and no options were specified for it
	pageVars.CanShowAll = !pageVars.IsSealed && config.CleanQuery != "" && (len(config.CardFilters) != 0 || len(config.UUIDs) != 0)

	if pageVars.IsMobile && !pageVars.IsSealed {
		pageVars.EditionFilterList = editionsForSearch(ds, result.keys)
	}

	// Sort sets as requested, default to chronological
	shown := orderSearchKeys(r, ds, result, pageVars.SearchSort)
	pageVars.ReverseMode = shown.reversed
	pageVars.Pagination = shown.pagination

	pageVars.Metadata, pageVars.Printings = searchMetadata(b, shown.keys, preferFlavor)

	// Optionally sort according to price
	if !pageVars.ListingLocked && readCookie(r, "SearchListingPriority") != "stores" {
		sortOfferRows(r, shown.keys, result)
	}

	preview := searchPreview(r, b, shown.keys, result)
	fillEmbed(&pageVars.SearchVars, pageVars.Metadata, b, preview, shown.keys)

	rebuildIndexRows(&pageVars.SearchVars, pageVars.Metadata, b, config, shown.keys, result)

	fillSearchResults(&pageVars.SearchVars, b, query, config, result, shown.keys)

	// CHART ALL THE THINGS
	if roster.id != "" {
		fillChartPage(&pageVars.SearchVars, pageVars.Metadata, r, ds, roster)
	}

	notifyFromSearch(r, query, roster, start)

	if DevMode {
		start = time.Now()
	}
	render(w, "search.html", pageVars)
	if DevMode {
		log.Println("render took", time.Since(start))
	}
}

// searchTitle names the page for what it shows: a chart, the sealed products,
// the editions tree, or a search. A chart of sealed products is a chart.
func searchTitle(title string, charting, sealed, editions bool) string {
	switch {
	case charting:
		return strings.Replace(title, "Search", "Chart", 1)
	case sealed:
		return strings.Replace(title, "Search", "Sealed Search", 1)
	case editions:
		return strings.Replace(title, "Search", "Editions", 1)
	}
	return title
}

// searchMetadata reads what the page shows of each card on it: its details,
// and its printings row for the sidebar. It does not use cardMetadata.add,
// because ChartID is set before the card is stored.
func searchMetadata(b *mtgmatcher.Backend, keys []string, preferFlavor bool) (cardMetadata, map[string]string) {
	metadata := cardMetadata{}
	printings := map[string]string{}

	// Load up image links and other metadata
	for _, cardID := range keys {
		_, found := metadata[cardID]
		if found {
			continue
		}
		card := uuid2card(b, cardID, preferFlavor)
		// Search results chart cards, so upgrade the chart handle to the cached
		// ban:<id> here rather than inside uuid2card, which also feeds pages
		// that never chart.
		card.ChartID = chartIDForCard(b, cardID)
		metadata[cardID] = card
		printings[cardID] = cardPrintings(b, cardID)
	}

	return metadata, printings
}

// SearchOEmbed answers an oEmbed consumer unfurling a search page with the
// preview of that page's search, in json.
func (s *site) SearchOEmbed(w http.ResponseWriter, r *http.Request) {
	ds := s.datastore()
	b := ds.backend

	// A consumer that cannot read what we would send is told so rather
	// than handed json it did not ask for.
	switch r.FormValue("format") {
	case "", "json":
	default:
		oembedError(w, http.StatusNotImplemented)
		return
	}

	// An oEmbed provider answers for its own pages only. Any other host
	// is a url we cannot speak for, so it gets the same answer as a page
	// that carries no search at all.
	u, err := url.Parse(r.FormValue("url"))
	if err != nil || !trustedHostname(u.Host) {
		oembedError(w, http.StatusNotFound)
		return
	}

	// The search runs on the request a reader with the consumer's cookies
	// would send for the page, so it reads the page's own query, sort,
	// order, page of results and pinned bar as the page does.
	page := r.Clone(r.Context())
	page.URL = u
	page.Form = u.Query()

	query := strings.TrimSpace(page.FormValue("q"))
	if query == "" || len(query) > MaxSearchQueryLen {
		oembedError(w, http.StatusNotFound)
		return
	}

	// An unfurl is shown to everyone who sees the link, and noSigning
	// checked no signature: quote the stores any reader is shown.
	blocklistRetail, blocklistBuylist := getDefaultBlocklists("")

	miscSearchOpts := append(readSearchMiscOpts(page), "oembed")

	config := parseSearchOptionsNG(b, query, blocklistRetail, blocklistBuylist, miscSearchOpts)
	applySearchScope(&config, scopeFilters(b, strings.TrimSpace(page.FormValue("scope"))))
	if page.URL.Path == "/sealed" {
		config.SearchMode = "sealed"
	}

	result := runSearch(page, ds, config)
	if len(result.keys) == 0 {
		oembedError(w, http.StatusNotFound)
		return
	}
	keys := orderSearchKeys(page, ds, result, readSearchSort(page, config)).keys
	sortOfferRows(page, keys, result)

	payload, err := json.Marshal(searchPreview(page, b, keys, result))
	if err != nil {
		oembedError(w, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(payload)
}

// searchPreview is the preview of a search's first cards, with their
// cheapest offers.
func searchPreview(r *http.Request, b *mtgmatcher.Backend, allKeys []string, result searchResults) *embed.OEmbed {
	// Every card is quoted with its own index prices: one shared list would
	// print the first card's numbers under every other card's heading.
	return embed.Generate(b, externalURL(r), allKeys, func(cardID string) string {
		return editionTitle(b, cardID)
	}, func(cardID string) []embed.Entry {
		return EmbedSellerEntries(result.sellers, cardID, true)
	})
}

// searchReader is what the page offers this reader: the alerts link when the
// navbar offers alerts and their tier has an allowance, and the admins' Fix
// toggle.
func searchReader(s *site, r *http.Request) (canAlerts, canFix bool) {
	sig := verifiedSignature(r)

	sigParams := parseSig(sig)
	if navOffers(s, sigParams, "Alerts") {
		canAlerts = alertAllowance(sigParams) > 0
	}

	// Admins get a per-result "Fix" toggle that surfaces a Fix link on every
	// store, deep-linking into the overrides builder.
	canAdmin, _ := strconv.ParseBool(GetParamFromSig(sig, "Admin"))
	return canAlerts, canAdmin || (DevMode && !SigCheck)
}

// fillSearchPrefs puts the reader's search preferences on the page: from
// their cookies, and from their signature what their tier may see and
// download.
func fillSearchPrefs(pageVars *SearchVars, r *http.Request) {
	sig := verifiedSignature(r)

	// Not only for the chart page: every mobile results page carries the
	// chart drawer, whose range select locks what the tier does not reach.
	pageVars.MaxLookbackDays = chartLookback(sig).Days()

	pageVars.DefaultTab = readCookie(r, "SearchDefaultTab")
	pageVars.DefaultView = mtgban.Condition(readCookie(r, "SearchDefaultView"))
	pageVars.MobileSearchLayout = readCookie(r, "MobileSearchLayout")

	// The Alphabetical button asks for the sort grouped by set where that is
	// the reader's saved default, and for plain alpha otherwise
	pageVars.AlphaSort = "alpha"
	if readCookie(r, "SearchDefaultSort") == "hybrid" {
		pageVars.AlphaSort = "hybrid"
	}

	// Load whether a user can download CSV and validate the query parameter
	canDownloadCSV, _ := strconv.ParseBool(GetParamFromSig(sig, "SearchDownloadCSV"))
	canDownloadCSV = canDownloadCSV || (DevMode && !SigCheck)
	pageVars.CanDownloadCSV = canDownloadCSV
}

// readSearchSort is the order a search asks for: the one its own syntax
// names, else the sort parameter, else the reader's saved default.
func readSearchSort(r *http.Request, config SearchConfig) string {
	if config.SortMode != "" {
		return config.SortMode
	}

	asked := r.FormValue("sort")
	if asked == "" {
		return readCookie(r, "SearchDefaultSort")
	}
	return asked
}

// fillChartRoster reads the chart= roster: it puts the roster on the page for
// the add-to-chart affordance, and when chart= comes alone, it returns the
// roster to chart and turns the query into its cards' search ids. A reader
// the charts are locked to gets no roster.
func fillChartRoster(pageVars *SearchVars, r *http.Request, b *mtgmatcher.Backend, query string, locked bool) (chartRoster, string) {
	chartParam := r.FormValue("chart")

	// The front-end enforces the same cap when batching cards, so let the JS
	// disable the affordance at the boundary instead of dropping silently.
	pageVars.MaxChartCards = len(multiCardPalette)

	roster := chartRoster{
		modal: r.FormValue("modal") == "1",
		// Roster id -> resolved search id, computed once per request: a ban:<id>
		// resolution costs a DB round-trip and each id is consulted three times
		// (results query, display query, metadata aliasing).
		searchIDs: map[string]string{},
		targets:   chartTargetCache{},
	}
	var chartTruncated bool
	roster.ids, chartTruncated = parseChartIDs(b, chartParam)
	if len(roster.ids) > 0 && !locked {
		// A crafted or over-long chart= URL that names more cards than the chart
		// can render lands here; say so rather than silently dropping the tail.
		if chartTruncated {
			pageVars.Notices = append(pageVars.Notices, fmt.Sprintf("Charts show up to %d cards; the extras were left off.", len(multiCardPalette)))
		}

		// Always expose the chart roster so the "add to chart" affordance on
		// result rows can target it even when we're rendering a regular search
		// (e.g. the user typed a query while on a chart page).
		pageVars.ChartIDs = roster.ids

		// Only enter chart-render mode when chart= is alone (no q=). With both
		// present the user is searching for cards to add to the chart, so we
		// keep the chart roster as context but render the search results page.
		// In modal mode the iframe is the add-to-chart picker, so never render
		// a chart inside it even when no query is set yet.
		if query == "" && !roster.modal {
			roster.id = roster.ids[0]
			// Drive the results table off the same trimmed/validated IDs the
			// chart plots (not the raw chartParam), so a URL like
			// ?chart=uuidA,%20uuidB doesn't leave card B off the results/remove
			// controls just because fixupIDs won't trim the leading space.
			searchIDs := make([]string, len(roster.ids))
			var unresolved int
			for i, id := range roster.ids {
				searchID, ok := chartSearchID(b, id, roster.targets.target(r.Context(), b, id))
				if !ok {
					unresolved++
				}
				searchIDs[i] = searchID
				roster.searchIDs[id] = searchIDs[i]
			}
			// An id that resolved to nothing matches no row, so the card is
			// simply absent from the table below the chart. Say which way it
			// went: a roster the user built by hand, or a link they were sent,
			// otherwise comes back quietly short.
			if unresolved > 0 {
				pageVars.Notices = append(pageVars.Notices, chartIDsDroppedNotice(unresolved, len(roster.ids), "could not be matched to a printing"))
			}
			query = strings.Join(searchIDs, ",")
		}
	} else {
		// Stay on the same probable query page
		if query == "" {
			query = chartParam
		}
		roster.ids = nil
	}

	return roster, query
}

// fillSearchLanding fills the page for a request with nothing to search: the
// sealed list on /sealed, the editions tree on /sets in sortOpt's order, else
// the search landing. It returns the template to render it with.
func fillSearchLanding(pageVars *SearchVars, ds *datastore, isSetsPage bool, sortOpt string) string {
	editions := ds.editions
	// Hijack sealed list
	if pageVars.IsSealed {
		pageVars.EditionSort = editions.SealedEditionsSorted
		pageVars.EditionList = editions.SealedEditionsList
		return "search.html"
	} else if isSetsPage {
		pageVars.TotalSets = editions.TotalSets
		pageVars.TotalCards = editions.TotalCards
		pageVars.TotalUnique = editions.TotalUnique

		sortedKeys := sortedEditionKeys(editions, sortOpt)

		pageVars.FlatEditions = flattenEditions(sortedKeys, editions.TreeEditionsMap)

		return "sets.html"
	}

	pageVars.SetKeyrunes = getSetKeyrunes(ds.backend)
	return "search.html"
}

// sortedEditionKeys orders the editions tree for /sets: in the tree's own
// order, or by name or by size as sortOpt asks.
func sortedEditionKeys(editions *editionsSnapshot, sortOpt string) []string {
	sortedKeys := editions.TreeEditionsKeys

	if sortOpt == "name" {
		namedSort := make([]string, len(editions.TreeEditionsKeys))
		copy(namedSort, editions.TreeEditionsKeys)
		sort.SliceStable(namedSort, func(i, j int) bool {
			return strings.ToLower(editions.TreeEditionsMap[namedSort[i]][0].Name) < strings.ToLower(editions.TreeEditionsMap[namedSort[j]][0].Name)
		})
		sortedKeys = namedSort
	} else if sortOpt == "size" {
		sizeSort := make([]string, len(editions.TreeEditionsKeys))
		copy(sizeSort, editions.TreeEditionsKeys)
		sort.SliceStable(sizeSort, func(i, j int) bool {
			if editions.TreeEditionsMap[sizeSort[i]][0].Size == editions.TreeEditionsMap[sizeSort[j]][0].Size {
				return strings.ToLower(editions.TreeEditionsMap[sizeSort[i]][0].Name) < strings.ToLower(editions.TreeEditionsMap[sizeSort[j]][0].Name)
			}
			return editions.TreeEditionsMap[sizeSort[i]][0].Size > editions.TreeEditionsMap[sizeSort[j]][0].Size
		})
		sortedKeys = sizeSort
	}

	return sortedKeys
}

// searchResults are the cards a search found and what each is offered at.
// hashes lists every card found, a decklist's repeats included, and keys each
// card once; the two share an array unless a repeat was folded, so ordering
// keys in place orders hashes with it. total is how many cards matched when
// that is not len(keys), copies counts the repeats of a folded card, and
// message says why the search shows none of them, or not all.
type searchResults struct {
	keys    []string
	hashes  []string
	copies  map[string]int
	total   int
	sellers map[string]map[mtgban.Condition][]SearchEntry
	vendors map[string]map[mtgban.Condition][]SearchEntry
	odds    map[string]float64
	message string
}

// runSearch runs the search and collects each card's offers.
func runSearch(r *http.Request, ds *datastore, config SearchConfig) searchResults {
	b := ds.backend

	var result searchResults

	// Perform search
	allKeys, err := searchAndFilter(ds, config)
	if err != nil {
		// No card carries the name, so read it another way before giving up.
		// Only here: further down the results are empty because the cards that
		// were found carry no listing, which is a fact about stock rather than
		// an invitation to answer a different question.
		allKeys = searchFallback(ds, config)
		if len(allKeys) == 0 {
			result.message = NoCardsMessage
			return result
		}
	}

	// Limit results to avoid hogging the website with large queries
	if len(allKeys) > MaxSearchTotalResults {
		result.total = len(allKeys)
		result.message = TooManyMessage
		allKeys = allKeys[:MaxSearchTotalResults]
	}

	result.sellers, result.vendors = searchParallelNG(allKeys, config)

	// Append the virtual custom buylist when enabled in the upload settings
	if config.CustomBuylist && !config.SkipBuylist {
		searchCustomBuylist(b, r, allKeys, result.vendors)
	}

	// Filter away any empty result
	allKeys = PostSearchFilter(config, allKeys, result.sellers, result.vendors)

	// Early exit if there no matches are found
	if len(allKeys) == 0 {
		result.message = NoResultsMessage
		miscSearchOpts := readSearchMiscOpts(r)
		if miscSearchOpts.has("hidePromos") || miscSearchOpts.has("hidePrelPack") {
			result.message = NoPromosMessage
		}
		return result
	}

	// hashes carries the full result list (with the per-copy repeats that
	// decklist/hashing searches produce) so transferring to the Uploader keeps
	// the quantities. Rendering shows each unique card once, so dedupe the keys
	// used for display — otherwise a 4-of card is drawn (and linked) 4 times.
	// Only multi-result hashing searches can repeat a key (hashing also serves
	// single-uuid lookups), so skip the work for everything else.
	result.hashes = allKeys
	result.keys = allKeys
	if config.SearchMode == "hashing" && len(allKeys) > 1 {
		if uniqueKeys := dedupeKeys(allKeys); len(uniqueKeys) < len(allKeys) {
			if result.total == 0 {
				result.total = len(allKeys)
			}
			// Record how many copies each card had so the deduped block can show it.
			result.copies = make(map[string]int, len(uniqueKeys))
			for _, k := range allKeys {
				result.copies[k]++
			}
			result.keys = uniqueKeys
		}
	}

	result.odds = dropOdds(b, config)

	return result
}

// fillSearchResults puts the cards found on the page: the page of them with
// their offers, how many there are, and the contents switch for a sealed
// product that has one.
func fillSearchResults(pageVars *SearchVars, b *mtgmatcher.Backend, query string, config SearchConfig, result searchResults, keys []string) {
	// Offered once the search has found cards to switch between. A product
	// that holds nothing but other products answers with those products: rows
	// on the page, but not cards, and reading them another way finds nothing.
	if containsSingles(b, result.keys) {
		pageVars.Contents = contentsViews(b, query, config)
	}

	// Only used in hashing searches, fill in data with what is available
	if config.FullQuery != "" {
		pageVars.SearchQuery = config.FullQuery
	}

	pageVars.TotalUnique = len(result.keys)
	pageVars.TotalCards = result.total
	pageVars.CardQuantities = result.copies
	pageVars.AllKeys = keys
	pageVars.FoundSellers = result.sellers
	pageVars.FoundVendors = result.vendors
}

// searchPage is the page of results to show: its cards in the order asked
// for, whether that order is reversed, and where the page sits among the rest.
type searchPage struct {
	keys       []string
	reversed   bool
	pagination Pagination
}

// orderSearchKeys sorts the results as the reader asked and returns the page
// of them to show. The sort works in place: CardHashes is the same slice, and
// the Uploader transfer posts it in this order.
func orderSearchKeys(r *http.Request, ds *datastore, result searchResults, sortMode string) searchPage {
	var shown searchPage
	shown.reversed = sortSearchKeys(r, ds, result.keys, result.odds, sortMode)

	// If results can't fit in one page, chunk response and enable pagination
	shown.keys = result.keys
	if len(shown.keys) > MaxSearchResults {
		pageIndex, _ := strconv.Atoi(r.FormValue("p"))
		shown.keys, shown.pagination = Paginate(result.keys, pageIndex, MaxSearchResults, MaxSearchTotalResults)
	}

	return shown
}

// sortSearchKeys orders keys in place as the reader asked, odds being what a
// variable search's cards are expected at, and says whether it reversed them.
func sortSearchKeys(r *http.Request, ds *datastore, allKeys []string, odds map[string]float64, sortMode string) bool {
	b := ds.backend
	sortData := resolveSortingData(b, allKeys)
	switch sortMode {
	case "odds":
		// Ascending by default, unlike every other field here: what a
		// variable search is for is finding the card expected in the fewest
		// copies, and that card sorts to the top only this way round.
		//
		// A card never covered is not a card expected at zero - a missing
		// entry and a real zero read the same off the map, and an ascending
		// sort would otherwise put every uncovered card ahead of the ones
		// an expected count is actually known for. Missing sorts last
		// regardless of direction, ranked among itself by the fallback the
		// other fields use.
		sort.Slice(allKeys, func(i, j int) bool {
			oddsI, hasI := odds[allKeys[i]]
			oddsJ, hasJ := odds[allKeys[j]]
			if hasI != hasJ {
				return hasI
			}
			if !hasI || oddsI == oddsJ {
				return cmpSets(sortData[allKeys[i]], sortData[allKeys[j]])
			}
			return oddsI < oddsJ
		})
	case "alpha":
		sort.Slice(allKeys, func(i, j int) bool {
			return cmpSetsAlphabetical(sortData[allKeys[i]], sortData[allKeys[j]])
		})
	case "hybrid":
		fileReprintsUnderParent(sortData, ds.editions.ReprintParents)
		sort.Slice(allKeys, func(i, j int) bool {
			return cmpSetsAlphabeticalSet(sortData[allKeys[i]], sortData[allKeys[j]])
		})
	case "number":
		sort.Slice(allKeys, func(i, j int) bool {
			return cmpNumberAndFinish(sortData[allKeys[i]], sortData[allKeys[j]], false)
		})
	case "retail":
		retSellers := defaultSellerPriorityOpt
		retSeller := readCookie(r, "SearchSellersPriority")
		if retSeller != "" {
			retSellers = append([]string{retSeller}, defaultSellerPriorityOpt...)
		}

		prices := resolveBestPrices(allKeys, retSellers, price4seller)
		sort.Slice(allKeys, func(i, j int) bool {
			priceI, priceJ := prices[allKeys[i]], prices[allKeys[j]]
			if priceI == priceJ {
				return cmpSets(sortData[allKeys[i]], sortData[allKeys[j]])
			}
			return priceI > priceJ
		})
	case "buylist":
		blVendors := defaultVendorPriorityOpt
		blVendor := readCookie(r, "SearchVendorsPriority")
		if blVendor != "" {
			blVendors = append([]string{blVendor}, defaultVendorPriorityOpt...)
		}

		buyPrices := resolveBestPrices(allKeys, blVendors, price4vendor)
		retPrices := resolveBestPrices(allKeys, defaultSellerPriorityOpt, price4seller)
		sort.Slice(allKeys, func(i, j int) bool {
			priceI, priceJ := buyPrices[allKeys[i]], buyPrices[allKeys[j]]
			if priceI != priceJ {
				return priceI > priceJ
			}
			priceI, priceJ = retPrices[allKeys[i]], retPrices[allKeys[j]]
			if priceI != priceJ {
				return priceI > priceJ
			}
			return cmpSets(sortData[allKeys[i]], sortData[allKeys[j]])
		})
	default:
		sort.Slice(allKeys, func(i, j int) bool {
			return cmpSets(sortData[allKeys[i]], sortData[allKeys[j]])
		})
	}

	// Invert the slice if requested
	reversed, _ := strconv.ParseBool(r.FormValue("reverse"))
	if reversed {
		for i, j := 0, len(allKeys)-1; i < j; i, j = i+1, j-1 {
			allKeys[i], allKeys[j] = allKeys[j], allKeys[i]
		}
	}

	return reversed
}

// sortOfferRows orders each card's offers in place, condition by condition:
// retail cheapest first, buylists by the reader's listing priority.
func sortOfferRows(r *http.Request, allKeys []string, result searchResults) {
	blSortPref := readCookie(r, "SearchListingPriority")

	for _, cardID := range allKeys {
		// This skips INDEX and PO conditions
		for _, cond := range mtgban.DefaultGradeTags {
			_, found := result.sellers[cardID][cond]
			if found {
				sort.Slice(result.sellers[cardID][cond], func(i, j int) bool {
					return result.sellers[cardID][cond][i].Price < result.sellers[cardID][cond][j].Price
				})
			}
			_, found = result.vendors[cardID][cond]
			if found {
				switch blSortPref {
				default:
					sort.Slice(result.vendors[cardID][cond], func(i, j int) bool {
						if result.vendors[cardID][cond][i].Price == result.vendors[cardID][cond][j].Price {
							if result.vendors[cardID][cond][i].Credit == result.vendors[cardID][cond][j].Credit {
								return result.vendors[cardID][cond][i].MarketCredit > result.vendors[cardID][cond][j].MarketCredit
							}
							return result.vendors[cardID][cond][i].Credit > result.vendors[cardID][cond][j].Credit
						}
						return result.vendors[cardID][cond][i].Price > result.vendors[cardID][cond][j].Price
					})
				case "credit":
					sort.Slice(result.vendors[cardID][cond], func(i, j int) bool {
						if result.vendors[cardID][cond][i].Credit == result.vendors[cardID][cond][j].Credit {
							return result.vendors[cardID][cond][i].MarketCredit > result.vendors[cardID][cond][j].MarketCredit
						}
						return result.vendors[cardID][cond][i].Credit > result.vendors[cardID][cond][j].Credit
					})
				case "market":
					sort.Slice(result.vendors[cardID][cond], func(i, j int) bool {
						return result.vendors[cardID][cond][i].marketValue() > result.vendors[cardID][cond][j].marketValue()
					})
				}
			}
		}
	}
}

// fillEmbed fills the page's link preview: the title the oEmbed answer
// carries, and the first card's image, description and a retail and a
// buylist reference price.
func fillEmbed(pageVars *SearchVars, metadata cardMetadata, b *mtgmatcher.Backend, preview *embed.OEmbed, allKeys []string) {
	pageVars.Embed.Title = preview.Title
	if len(allKeys) > 0 {
		pageVars.Embed.ImageURL = metadata[allKeys[0]].FullImageURL
		pageVars.Embed.ImageCropURL = pageVars.Embed.ImageURL

		co, err := b.GetUUID(allKeys[0])
		if err == nil {
			// A sealed product has no printings line, so it says what it is
			// instead. Either way this is prose: the preview panel reads as
			// bold-styled unicode, which is Discord's alphabet and nobody
			// else's.
			if len(co.Printings) > 0 {
				pageVars.Embed.Description = fmt.Sprintf("Printed in %s.", embed.PrintingsLine(co.Printings))
			} else {
				pageVars.Embed.Description = fmt.Sprintf("%s - %s", co.Name, editionTitle(b, allKeys[0]))
			}
			imgCrop := co.Images["crop"]
			if imgCrop != "" {
				pageVars.Embed.ImageCropURL = imgCrop
			}
		}

		// Name the store each price came from rather than assuming which
		// ones this site carries: an instance without them would otherwise
		// print "N/A" under the name of a marketplace it never loaded.
		pageVars.Embed.RetailLabel, pageVars.Embed.RetailPrice = sellerReference(allKeys[0], "TCGMarket")
		pageVars.Embed.BuylistLabel, pageVars.Embed.BuylistPrice = vendorReference(allKeys[0], "CK")
	}
}

// rebuildIndexRows replaces each card's INDEX rows with its collapsed
// reference rows and the fallback marketplace links, adds the average-count
// row to its buylist, and where the listing is locked, locks the offers a
// logged-out reader may not see.
func rebuildIndexRows(pageVars *SearchVars, metadata cardMetadata, b *mtgmatcher.Backend, config SearchConfig, allKeys []string, result searchResults) {
	cautioned := false

	// When the user asked to drop index data (skip:index), don't synthesize the
	// no-price TCGplayer/CardMarket fallback links below.
	skipIndex := false
	for _, f := range config.StoreFilters {
		if f.Name == "index" && !f.Negate {
			skipIndex = true
			break
		}
	}

	// The two fallback rows below stand in for a price this site does not
	// have, with a link to go and look it up - which is worth offering only
	// where the site carries that marketplace at all.
	hasTCGScraper := marketplaceLoaded("TCG")
	hasMKMScraper := marketplaceLoaded("MKM")

	// Rebuild each card's INDEX rows. collapseIndex/collapseSealedEV scan the
	// array themselves, so there's no per-entry dispatch here — just collapse
	// each known source directly and pass the rest through, then sort the
	// resulting reference rows alphabetically by store name.
	for _, cardID := range allKeys {
		indexArray := result.sellers[cardID]["INDEX"]
		evShorts := scraperStoreConfig()["sealed_ev"]["retail"]

		tcgRow, hasTCG := collapseIndex(indexArray, "TCGLow", "TCGMarket", "", "", "TCG (Low / Market)")
		mkmRow, hasMKM := collapseIndex(indexArray, "MKMLow", "MKMTrend", "Cardmarket Low", "Cardmarket Trend", "CM (Low / Trend)")
		evRows, hasEV := collapseSealedEV(indexArray, evShorts)

		var tmp []SearchEntry
		if hasTCG {
			tmp = append(tmp, tcgRow)
		}
		if hasMKM {
			tmp = append(tmp, mkmRow)
		}
		tmp = append(tmp, evRows...)

		// Pass through everything the collapsers didn't consume.
		consumed := append([]string{"TCGLow", "TCGMarket", "MKMLow", "MKMTrend"}, evShorts...)
		tmp = append(tmp, passthroughIndex(indexArray, consumed)...)

		// A card is bought back, never sold, at the count it might come out
		// of a pack at, so the row sits with what someone would buy it back
		// for rather than with the offers to sell it. It is a count, not a
		// chance: the same card drawn from more than one slot is added in,
		// same as an EV row sums every slot's contribution to a price, so a
		// common enough card averages more than one copy per product and
		// reads as such rather than as a percentage past what one can mean.
		// "(est.)" says the number is read off that count, not off a shelf,
		// the same qualifier an estimated buylist quote already wears.
		count, ok := result.odds[cardID]
		if ok {
			if result.vendors[cardID] == nil {
				result.vendors[cardID] = map[mtgban.Condition][]SearchEntry{}
			}
			result.vendors[cardID]["INDEX"] = append(result.vendors[cardID]["INDEX"], SearchEntry{
				ScraperName: "Avg Copies (est.)",
				// A real shorthand, so it reads as its own scraper rather
				// than an empty one: buylist_badge compares Shorthand
				// against a card's hotlist store, and both default to "",
				// which put Card Kingdom's 3-month star on every row for a
				// card that isn't hotlisted.
				Shorthand:  "AvgCopies",
				Price:      count,
				PriceUnit:  PriceUnitExpectedCount,
				NoQuantity: true,
			})
		}

		if hasEV && !cautioned && getTCGSimulationIQR(cardID) > IQRThreshold {
			pageVars.Notices = append(pageVars.Notices, "CAUTION - This search includes products with a high IQR, please check the FAQs to understand how it may impact the computed values")
			cautioned = true
		}

		// If no TCG reference was present, we manually add one to get the link
		if !hasTCG && hasTCGScraper && !metadata[cardID].Sealed && !skipIndex {
			var link string
			if metadata[cardID].TCGId == "" {
				link = "https://www.tcgplayer.com/search/all/product?q=" + url.QueryEscape(metadata[cardID].Name) + "&utm_medium=" + Affiliates().Codes["TCG"] + "&utm_source=" + Affiliates().Codes["TCG"]
			} else {
				tcgID, _ := strconv.Atoi(metadata[cardID].TCGId)

				link = tcgplayer.GenerateProductURL(tcgID, "", Affiliates().Codes["TCG"], "", "", false)
			}
			tmp = append(tmp, SearchEntry{
				ScraperName: "TCGplayer",
				URL:         link,
				NoQuantity:  true,
			})
		}

		// Same for CM
		if !hasMKM && hasMKMScraper && !metadata[cardID].Sealed && !skipIndex {
			co, err := b.GetUUID(cardID)
			if err == nil {
				var link string

				game := cm.GameFromName(string(Config().Game))
				id, err := strconv.Atoi(co.Identifiers["mcmId"])
				if err != nil || id == 0 {
					// Cardmarket names the game in every product path, so the
					// name-only fallback has to carry it too.
					link = cm.SearchURL(game, metadata[cardID].Name, cm.URLOption{
						Signed:    cm.None,
						Altered:   cm.None,
						Affiliate: Affiliates().Codes["MKM"],
					})
				} else {
					foil := cm.Any
					if co.Foil || co.Etched {
						foil = cm.Only
					}
					link = cm.BuildURL(game, id, cm.URLOption{
						Foil:    foil,
						Signed:  cm.None,
						Altered: cm.None,
						// Note that Chinese languages are spelled
						// differently, they will be skipped
						Language:  cm.LanguageFromName(co.Language),
						Affiliate: Affiliates().Codes["MKM"],
					})
				}
				tmp = append(tmp, SearchEntry{
					ScraperName: "CardMarket",
					URL:         link,
					NoQuantity:  true,
				})
			}
		}

		// Show the index reference rows in alphabetical order by store name.
		sort.SliceStable(tmp, func(i, j int) bool {
			return strings.ToLower(tmp[i].ScraperName) < strings.ToLower(tmp[j].ScraperName)
		})

		// In case there are no results at all
		if result.sellers[cardID] == nil {
			result.sellers[cardID] = map[mtgban.Condition][]SearchEntry{}
		}
		result.sellers[cardID]["INDEX"] = tmp

		if pageVars.ListingLocked {
			hide := Config().SearchHideNonAffiliates
			gateNonAffiliates(result.sellers[cardID], Affiliates().List, hide)
			gateNonAffiliates(result.vendors[cardID], Affiliates().BuylistList, hide)
		}
	}
}

// gateNonAffiliates locks, in one card's offers for a logged-out reader,
// every entry whose store is not in affiliates; with hide, it removes them
// instead, and a condition left with none. Index/reference prices stay
// visible to everyone.
func gateNonAffiliates(conds map[mtgban.Condition][]SearchEntry, affiliates []string, hide bool) {
	for cond, entries := range conds {
		if cond == "INDEX" {
			continue
		}
		if !hide {
			for i := range entries {
				entries[i].Locked = !slices.Contains(affiliates, entries[i].Shorthand)
			}
			continue
		}
		entries = slices.DeleteFunc(entries, func(entry SearchEntry) bool {
			return !slices.Contains(affiliates, entry.Shorthand)
		})
		if len(entries) == 0 {
			delete(conds, cond)
			continue
		}
		conds[cond] = entries
	}
}

// notifyFromSearch posts the search to the user webhook and logs it: what was
// searched, where the request came from, who asked and how long it took.
func notifyFromSearch(r *http.Request, query string, roster chartRoster, start time.Time) {
	sig := verifiedSignature(r)

	var source string
	notifyTitle := "search"
	utm := r.FormValue("utm_source")
	if utm == "banbot" {
		id := r.FormValue("utm_affiliate")
		source = fmt.Sprintf("banbot (%s)", id)
	} else if utm == "autocard" {
		source = "autocard anywhere"
	} else if roster.id != "" {
		source = "chart page"
		notifyTitle = "chart"
	} else {
		u, err := url.Parse(r.Referer())
		if err != nil {
			log.Println(err)
			source = "n/a"
		} else {
			if strings.Contains(u.Host, "mtgban") {
				source = u.Path
			} else {
				// Avoid automatic URL expansion in Discord
				source = fmt.Sprintf("<%s>", u.String())
			}
		}
	}
	user := GetParamFromSig(sig, "UserEmail")
	if user == "" {
		user = fmt.Sprintf("anonymous (%s / %s)", r.Header.Get("X-Forwarded-For"), r.RemoteAddr)
	}
	msg := fmt.Sprintf("[%s] from %s by %s (took %v)", query, source, user, time.Since(start))
	UserNotify(notifyTitle, msg)
	LogPages["Search"].Println(msg)
}

// fillChartPage fills a chart page for the roster: the display query, the
// roster's card details, the chart from the long-form price tables, and the
// single card's sidebar. It adds the roster's ban ids to metadata, which
// holds the results by their matcher ids.
func fillChartPage(pageVars *SearchVars, metadata cardMetadata, r *http.Request, ds *datastore, roster chartRoster) {
	b := ds.backend
	isMultiChart := len(roster.ids) > 1

	chartEditions := ds.editions
	pageVars.EditionSort = chartEditions.SealedEditionsSorted
	pageVars.EditionList = chartEditions.SealedEditionsList

	// Rebuild a display query from the (first) chart card. Use the resolved
	// mtgmatcher id (a ban:<id> doesn't parse as a query), so SearchQuery is
	// non-empty and the template renders the results+chart layout rather than
	// the empty-query editions browse.
	cfg := parseSearchOptionsNG(b, roster.searchIDs[roster.id], nil, nil, nil)
	pageVars.SearchQuery = cfg.FullQuery

	// Retrieve data
	pageVars.ChartID = roster.id
	pageVars.IsMultiChart = isMultiChart

	// The template keys card metadata off ChartID and the roster ids, but the
	// results Metadata map is keyed by the resolved mtgmatcher id. Alias each
	// ban:<id> roster entry to its resolved card so those lookups resolve.
	for _, id := range roster.ids {
		sid := roster.searchIDs[id]
		if sid == "" || sid == id {
			continue
		}
		card, found := metadata[sid]
		if found {
			metadata[id] = card
		}
	}

	if PricesArchiveDB == nil {
		pageVars.Notices = append(pageVars.Notices, "No chart data available")
	} else {
		fillLongFormChart(pageVars, r, ds, roster)
	}

	// Sidebar foil/etched switch and Stocks link are inherently per-card,
	// and sealed products have no foil/etched variants, so leave them empty
	// and let the sidebar's self-checks hide them. The switches key off the
	// resolved mtgmatcher id, since a ban:<id> roster entry means nothing to
	// the matcher.
	if !isMultiChart {
		fillChartSidebar(pageVars, metadata, b, roster)
	}
}

// fillLongFormChart charts the roster from the long-form price tables, over
// the window the viewer last chose, widened to the whole history when the
// cards have no prices inside it.
func fillLongFormChart(pageVars *SearchVars, r *http.Request, ds *datastore, roster chartRoster) {
	b := ds.backend
	sig := verifiedSignature(r)
	isMultiChart := len(roster.ids) > 1

	// Render the window the chart draws, taken from the viewer's own
	// last choice so it is not drawn once and redrawn at theirs. A
	// roster's select starts on "All", so absent a choice it renders
	// the lot. See docs/chart-page-loading.md.
	lb, maxDays := chartWindow(sig, chartInitialRange(r, isMultiChart))
	pageVars.ChartLoadedDays = lb.Days()

	// Generic path: resolve every roster id to a target and chart it by
	// whatever providers have data — one path for every game, keyed on the
	// cached ban_id. The ?chart= url keeps the mtgmatcher id (the search
	// UI's identity for favorites/roster/legend); the ban_id is internal.
	//
	// Resolution stays here, on the request's own goroutine, because
	// roster.targets is an unlocked per-request map; only the archive
	// reads that follow are issued together.
	resolved := make([]chartSeries, 0, len(roster.ids))
	for _, id := range roster.ids {
		target := roster.targets.target(r.Context(), b, id)
		if target == nil {
			continue
		}
		resolved = append(resolved, chartSeries{CardID: id, Name: target.Name, target: target})
	}
	series := fetchRosterPrices(r.Context(), resolved, lb)
	// An empty window hides the chart and the select that could widen it,
	// so a card whose prices all predate the window reads the ceiling. A
	// read that failed is not an empty window, so it is not retried wider.
	priced := slices.ContainsFunc(series, func(cs chartSeries) bool { return len(cs.Prices) > 0 })
	if lb.Days() < maxDays && archiveAnswered(series) && !priced {
		lb, _ = chartWindow(sig, 0)
		pageVars.ChartLoadedDays = lb.Days()
		series = fetchRosterPrices(r.Context(), resolved, lb)
	}

	plot := plotSeries(ds, series, lb, isMultiChart)
	if plot.axis == nil {
		pageVars.Notices = append(pageVars.Notices, "No chart data available")
	} else {
		pageVars.AxisLabels = plot.axis
		pageVars.Datasets = plot.datasets
		pageVars.ChartReferences = plot.references
		pageVars.Checkpoints = plot.checkpoints
		// A card the archive did not answer for is missing from the chart,
		// which says nothing about its prices: never call such a chart
		// empty, and when the rest drew, say what was left out.
		failed := readFailures(series)
		switch {
		case len(pageVars.Datasets) == 0 && failed > 0:
			pageVars.Notices = append(pageVars.Notices, "Failed to load chart")
		case len(pageVars.Datasets) == 0:
			pageVars.Notices = append(pageVars.Notices, "No chart data available")
		case failed > 0:
			pageVars.Notices = append(pageVars.Notices, chartIDsDroppedNotice(failed, len(roster.ids), "failed to load"))
		}
	}
}

// fillChartSidebar sets the single card's foil and etched switches and its
// Stocks link, all of which a sealed product goes without.
func fillChartSidebar(pageVars *SearchVars, metadata cardMetadata, b *mtgmatcher.Backend, roster chartRoster) {
	searchID := roster.searchIDs[roster.id]
	co, gerr := b.GetUUID(searchID)
	if gerr == nil && !co.Sealed {
		altID, err := b.Match(&mtgmatcher.InputCard{
			ID:   searchID,
			Foil: !co.Foil,
		})
		if err == nil && altID != searchID {
			pageVars.Alternative = altID
		}

		altID, err = b.Match(&mtgmatcher.InputCard{
			ID:        searchID,
			Variation: "Etched",
		})
		if err == nil && altID != searchID {
			pageVars.AltEtchedID = altID
		}

		pageVars.StocksURL = metadata[roster.id].StocksURL
	}
}

// chartRoster is the cards a chart page names: the ids in its chart=
// parameter, the one the page charts first (none when it draws no chart),
// the search id each resolved to, and their chart targets. modal says the
// page is the add-to-chart picker, which never draws a chart.
type chartRoster struct {
	modal     bool
	id        string
	ids       []string
	searchIDs map[string]string
	targets   chartTargetCache
}

// chartTargetCache resolves roster ids to chart targets once per request. The
// results table and the chart both need this, and it is the archive
// round-trip that makes it worth doing once: the page used to ask for the
// same card twice, and a roster did so per card. Owned by one request alone,
// so a plain map with no locking - a nil entry is a resolution that already
// failed and is not retried.
type chartTargetCache map[string]*chartTarget

// target returns the chart target of a roster id, resolving it on first ask.
func (cache chartTargetCache) target(ctx context.Context, b *mtgmatcher.Backend, id string) *chartTarget {
	if target, asked := cache[id]; asked {
		return target
	}
	target, err := resolveChartTarget(ctx, b, id)
	if err != nil {
		target = nil
	}
	cache[id] = target
	return target
}

// marketplaceLoaded reports whether this site serves a seller from the named
// scraper family. Sellers only: the rows it gates stand in for a reference
// price, which is a seller's to give.
func marketplaceLoaded(family string) bool {
	for _, seller := range GetSellers() {
		if seller.Info().Family == family {
			return true
		}
	}

	return false
}

// collapseIndex folds a paired low/market reference (e.g. TCGLow + TCGMarket)
// from a card's INDEX entries into a single row: the low price as the primary
// and the market price as the secondary, under the merged label. The first of
// each shorthand is used (so repeats are deduped), and the pair merges
// regardless of the order the two entries appear in. When only one side is
// present it's returned on its own, renamed to its solo label (an empty solo
// label keeps the scraper's own name). Returns false when neither is found.
func collapseIndex(entries []SearchEntry, lowShort, marketShort, lowSolo, marketSolo, merged string) (SearchEntry, bool) {
	var low, market *SearchEntry
	for i := range entries {
		switch entries[i].Shorthand {
		case lowShort:
			if low == nil {
				low = &entries[i]
			}
		case marketShort:
			if market == nil {
				market = &entries[i]
			}
		}
	}

	switch {
	case low != nil && market != nil:
		row := *low
		row.Secondary = market.Price
		row.ScraperName = merged
		return row, true
	case low != nil:
		row := *low
		if lowSolo != "" {
			row.ScraperName = lowSolo
		}
		return row, true
	case market != nil:
		row := *market
		if marketSolo != "" {
			row.ScraperName = marketSolo
		}
		return row, true
	default:
		return SearchEntry{}, false
	}
}

// collapseSealedEV folds the sealed expected-value rows from a card's INDEX
// entries into one row per price source: an EV entry and its Sim sibling,
// paired by the shorthand they share but for that suffix (MKMEV and MKMSim),
// become EV price primary and simulated price secondary. evShorts is the set
// of sealed-EV scraper shorthands. Returns the collapsed rows and whether any
// EV entry was present (so the caller can flag a high-IQR caution).
func collapseSealedEV(entries []SearchEntry, evShorts []string) (rows []SearchEntry, seen bool) {
	pos := map[string]int{}
	for i := range entries {
		if !slices.Contains(evShorts, entries[i].Shorthand) {
			continue
		}
		seen = true

		source, isSim := strings.CutSuffix(entries[i].Shorthand, "Sim")
		source = strings.TrimSuffix(source, "EV")

		idx, found := pos[source]
		if !found {
			rows = append(rows, entries[i])
			idx = len(rows) - 1
			pos[source] = idx
			rows[idx].IsEV = true
		}

		if isSim {
			rows[idx].Secondary = entries[i].Price
			rows[idx].ExtraValues = entries[i].ExtraValues
		} else {
			rows[idx].Price = entries[i].Price
		}
	}
	return rows, seen
}

// passthroughIndex returns the INDEX entries whose shorthand isn't in consumed
// — i.e. everything not already folded into a collapsed row — preserving their
// original order.
func passthroughIndex(entries []SearchEntry, consumed []string) []SearchEntry {
	var out []SearchEntry
	for i := range entries {
		if slices.Contains(consumed, entries[i].Shorthand) {
			continue
		}
		out = append(out, entries[i])
	}
	return out
}

// sellerEntryFound reports whether a seller's entry for a card passes a
// search's condition and price filters. An index's entries carry no
// condition, so only its price is filtered.
func sellerEntryFound(info mtgban.ScraperInfo, cardID string, entry mtgban.InventoryEntry, config SearchConfig) bool {
	if !info.MetadataOnly && shouldSkipEntryNG(entry, config.EntryFilters) {
		return false
	}
	return !shouldSkipPriceNG(cardID, entry, config.PriceFilters, info.Shorthand)
}

// vendorEntryFound reports whether a vendor's entry for a card passes a
// search's condition and price filters.
func vendorEntryFound(info mtgban.ScraperInfo, cardID string, entry mtgban.BuylistEntry, config SearchConfig) bool {
	if shouldSkipEntryNG(entry, config.EntryFilters) {
		return false
	}
	return !shouldSkipPriceNG(cardID, entry, config.PriceFilters, info.Shorthand)
}

func searchSellersNG(cardIDs []string, config SearchConfig) (foundSellers map[string]map[mtgban.Condition][]SearchEntry) {
	// Allocate memory
	foundSellers = map[string]map[mtgban.Condition][]SearchEntry{}

	// Decklist/hashing searches repeat a key once per copy; the output is
	// keyed by the unique card, so walking a repeated key could only append
	// the same rows once more
	cardIDs = dedupeKeys(cardIDs)

	// Search sellers
	for _, seller := range GetSellers() {
		if shouldSkipStoreNG(seller, config.StoreFilters) {
			continue
		}

		// Get inventory
		inventory := seller.Inventory()

		// Fetch the seller info (a struct copy) and its display name once
		// per store instead of once per entry
		info := seller.Info()
		name := scraperName(info.Shorthand)

		for _, cardID := range cardIDs {
			entries, found := inventory[cardID]
			if !found {
				continue
			}

			// Loop thorugh available conditions
			for _, entry := range entries {
				if !sellerEntryFound(info, cardID, entry, config) {
					continue
				}

				// Check if card already has any entry
				_, found := foundSellers[cardID]
				if !found {
					foundSellers[cardID] = map[mtgban.Condition][]SearchEntry{}
				}

				// Set conditions - handle the special TCG one that appears
				// at the top of the results
				conditions := entry.Conditions
				if info.MetadataOnly {
					conditions = "INDEX"
				}

				icon := Config().ScraperConfig.Icons[info.Shorthand]

				// Prepare all the deets
				res := SearchEntry{
					ScraperName: name,
					Shorthand:   info.Shorthand,
					Price:       entry.Price,
					Quantity:    entry.Quantity,
					URL:         entry.URL,
					NoQuantity:  info.NoQuantityInventory || info.MetadataOnly,
					BundleIcon:  icon,
					PriceUnit:   quantityUnit(info.QuantityPriority),
					Country:     Country2flag[info.CountryFlag],
					ExtraValues: entry.ExtraValues,
				}
				if info.CreditMultiplier > 0 {
					res.Credit = entry.Price / info.CreditMultiplier
				}
				if info.Shorthand == tcgListingsStore {
					res.Listings, res.ListingsTitle = tcgListingsFor(cardID, conditions)
				}

				// Touchdown
				foundSellers[cardID][conditions] = append(foundSellers[cardID][conditions], res)
			}
		}
	}

	return
}

func searchVendorsNG(cardIDs []string, config SearchConfig) (foundVendors map[string]map[mtgban.Condition][]SearchEntry) {
	foundVendors = map[string]map[mtgban.Condition][]SearchEntry{}

	cardIDs = dedupeKeys(cardIDs)

	for _, vendor := range GetVendors() {
		if shouldSkipStoreNG(vendor, config.StoreFilters) {
			continue
		}

		buylist := vendor.Buylist()

		// Fetch the vendor info and its display name once per store, like
		// in searchSellersNG
		info := vendor.Info()
		name := scraperName(info.Shorthand)

		for _, cardID := range cardIDs {
			entries, found := buylist[cardID]
			if !found {
				continue
			}

			for _, entry := range entries {
				if !vendorEntryFound(info, cardID, entry, config) {
					continue
				}

				_, found = foundVendors[cardID]
				if !found {
					foundVendors[cardID] = map[mtgban.Condition][]SearchEntry{}
				}

				conditions := entry.Conditions
				if info.MetadataOnly && !info.SealedMode {
					conditions = "INDEX"
				}

				icon := Config().ScraperConfig.Icons[info.Shorthand]

				res := SearchEntry{
					ScraperName:  name,
					Shorthand:    info.Shorthand,
					Price:        entry.BuyPrice,
					Credit:       entry.BuyPrice * info.CreditMultiplier,
					MarketCredit: entry.BuyPrice * info.CreditMultiplier * Config().BuylistMarketCredit[info.Shorthand],
					Ratio:        entry.PriceRatio,
					Quantity:     entry.Quantity,
					URL:          entry.URL,
					BundleIcon:   icon,
					PriceUnit:    quantityUnit(info.QuantityPriority),
					Country:      Country2flag[info.CountryFlag],
				}

				foundVendors[cardID][conditions] = append(foundVendors[cardID][conditions], res)
			}
		}
	}

	return
}

// Append a virtual buylist to search results, priced off the reference
// seller inventories according to the custom buylist rule settings
func searchCustomBuylist(b *mtgmatcher.Backend, r *http.Request, cardIDs []string, foundVendors map[string]map[mtgban.Condition][]SearchEntry) {
	customOpts := strings.Split(readCookie(r, "UploadCustomOpts"), ",")
	if !slices.Contains(customOpts, "enabled") {
		return
	}

	rate, _ := strconv.ParseFloat(readCookie(r, "UploadCustomRate"), 64)
	if rate <= 0 {
		return
	}
	minPrice, _ := strconv.ParseFloat(readCookie(r, "UploadCustomMinPrice"), 64)

	customSeller := readCookie(r, "UploadCustomBuyer")
	customSealedSeller := readCookie(r, "UploadCustomSealedBuyer")
	singles, _ := findSellerInventory(customSeller)
	sealed, _ := findSellerInventory(customSealedSeller)

	// Index price sources have a single meaningful price, while regular
	// retailers list one price per condition
	isIndex := slices.Contains(UploadIndexComparePriceList, customSeller)

	// Decklist/hashing searches repeat a key once per copy; foundVendors is
	// keyed by the unique card, so dedupe to avoid appending an entry per copy.
	for _, cardID := range dedupeKeys(cardIDs) {
		co, err := b.GetUUID(cardID)
		if err != nil {
			continue
		}

		ref := singles
		if co.Sealed {
			ref = sealed
		}
		if ref == nil {
			continue
		}
		entries, found := ref[cardID]
		if !found || len(entries) == 0 {
			continue
		}

		// The rule applies to the best available price
		if entries[0].Price == 0 || entries[0].Price < minPrice {
			continue
		}

		if foundVendors[cardID] == nil {
			foundVendors[cardID] = map[mtgban.Condition][]SearchEntry{}
		}

		for _, entry := range entries {
			if entry.Price == 0 {
				continue
			}
			condition := mtgban.Condition("INDEX")
			if !isIndex {
				condition = entry.Conditions
			}
			foundVendors[cardID][condition] = append(foundVendors[cardID][condition], SearchEntry{
				ScraperName: "Custom Buylist",
				Shorthand:   "CUSTOM",
				Price:       entry.Price * rate,
			})
		}
	}
}

// dedupeKeys returns the keys with duplicates removed, preserving first-seen
// order. It allocates a new slice so the caller's original (e.g. CardHashes)
// keeps its repeats.
func dedupeKeys(keys []string) []string {
	seen := make(map[string]struct{}, len(keys))
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	return out
}

// editionSeedCodes returns the set codes of the first filter that exactly
// bounds the result set: a non-negated edition filter that applies to every
// set. Anything else (negations, ApplyTo-scoped filters) cannot seed.
func editionSeedCodes(filters []FilterElem) ([]string, bool) {
	for i := range filters {
		if filters[i].Name == "edition" && !filters[i].Negate &&
			filters[i].ApplyTo == nil && len(filters[i].Values) > 0 {
			return filters[i].Values, true
		}
	}
	return nil, false
}

// The three readings of a sealed product's contents: everything it can hold,
// only what it always holds, only what it might. They name the filter that
// searches for each.
const (
	ContentsAll      = "contents"
	ContentsFixed    = "decklist"
	ContentsVariable = "variable"
)

// containsSingles answers whether a result set holds a card, as opposed to
// holding only the products that cards come in.
func containsSingles(b *mtgmatcher.Backend, cardIDs []string) bool {
	for _, cardID := range cardIDs {
		co, err := b.GetUUID(cardID)
		if err == nil && !co.Sealed {
			return true
		}
	}

	return false
}

// ContentsViews is the switch between those three, for a product that has
// something on both sides of it.
type ContentsViews struct {
	// The product, for the titles that say what is being switched
	Product string

	// Which reading is showing
	Mode string

	// The query for each, the current one included
	All      string
	Fixed    string
	Variable string
}

// contentsViews answers whether a contents:/decklist:/variable: search can be
// read another way, and with which queries.
//
// A drop that can hold bonus cards lists every one of them beside the few it
// always holds - a Secret Lair's cards arrive buried in the ones that might
// come with them. Only where all three readings mean something: a product with
// nothing guaranteed has no fixed list, one with no bonus cards has no
// variable list, and neither has anything to switch between.
// dropOdds is the expected number of copies of each card opening the
// product a variable search asked about yields, on average, summed where a
// card can come out more than one way - which is why it is a count and not
// a chance: a common enough card, drawn from more than one slot, averages
// more than one copy per product, past what any single chance could read
// as. Nil for every other search.
//
// Asked of the matcher on each request rather than kept from load: over
// every product in the datastore it answers in half a second, the slowest
// single product in 4ms and the slowest with a variable part in 1.4ms,
// against a search that then prices every card found.
func dropOdds(b *mtgmatcher.Backend, config SearchConfig) map[string]float64 {
	if config.ContentsMode != ContentsVariable || config.ContentsProduct == "" {
		return nil
	}
	co, err := b.GetUUID(config.ContentsProduct)
	if err != nil {
		LogPages["Search"].Println("dropOdds:", config.ContentsProduct, err)
		return nil
	}
	probs, err := b.GetProbabilitiesForSealed(co.SetCode, co.UUID)
	if err != nil {
		LogPages["Search"].Println("dropOdds:", co.Name, err)
		return nil
	}

	counts := make(map[string]float64, len(probs))
	for _, prob := range probs {
		counts[prob.UUID] += prob.Probability
	}
	return counts
}

func contentsViews(b *mtgmatcher.Backend, query string, config SearchConfig) *ContentsViews {
	if config.ContentsProduct == "" || config.ContentsMode == "" {
		return nil
	}

	co, err := b.GetUUID(config.ContentsProduct)
	if err != nil {
		return nil
	}
	if !b.SealedHasDecklist(co.SetCode, co.UUID) {
		return nil
	}
	if !b.SealedIsRandom(co.SetCode, co.UUID) {
		return nil
	}

	// The filter is swapped in the query as it was typed, so whatever else it
	// carries is carried over with it.
	swap := func(to string) string {
		return strings.Replace(query, config.ContentsMode+":", to+":", 1)
	}

	return &ContentsViews{
		Product:  co.Name,
		Mode:     config.ContentsMode,
		All:      swap(ContentsAll),
		Fixed:    swap(ContentsFixed),
		Variable: swap(ContentsVariable),
	}
}

// numberSeedUUIDs returns the uuids of the first filter that exactly bounds
// the result set by collector number, and whether one did.
//
// The disqualifications are the edition seed's, for the edition seed's
// reasons: a negated filter names what to leave out rather than what to keep,
// and an ApplyTo-scoped one passes every card outside its scope untouched, so
// neither bounds anything. A filter carrying subfilters is a range, which
// names no key of its own.
func numberSeedUUIDs(numbers *numbersSnapshot, filters []FilterElem) ([]string, bool) {
	if numbers == nil {
		return nil, false
	}
	for i := range filters {
		if filters[i].Negate || filters[i].ApplyTo != nil ||
			len(filters[i].Values) == 0 || len(filters[i].Subfilters) != 0 {
			continue
		}
		var buckets []map[string][]string
		switch filters[i].Name {
		case "number", "number_total":
			buckets = append(buckets, numbers.loose, numbers.strict)
		case "number_strict":
			buckets = append(buckets, numbers.strict)
		default:
			continue
		}
		// Values are already prepared by fixupNumberNG for the filter.
		// Use them verbatim, just as the scan does, and a number_total
		// value by its number too, for the scan to check the total.
		var uuids []string
		for _, value := range filters[i].Values {
			for _, bucket := range buckets {
				uuids = append(uuids, bucket[value]...)
				if filters[i].Name == "number_total" {
					uuids = append(uuids, bucket[strings.Split(value, "/")[0]]...)
				}
			}
		}
		return dedupeKeys(uuids), true
	}
	return nil, false
}

// storeSeedUUIDs returns the uuids a plain store:/seller:/vendor: query
// names, and whether one did. That filter ("vendor:TEST") is a PostFilter,
// not a CardFilter - shouldSkipPostNG only runs once every store's pricing
// for a candidate has already been fetched, well after this function
// returns - so on its own it bounds nothing at this stage the way an edition
// or number filter does. Without a seed here, the empty-query fallback below
// degrades to the whole datastore, and every card in it gets a full pass
// over every loaded scraper only to be thrown away later by the very filter
// that could have picked its candidates directly to begin with.
//
// The first store-naming ("any") PostFilter present seeds. Other
// PostFilters can ride alongside it - an automatic "hide empty" from qty>
// or skip:empty, or a second store filter from seller:/vendor: combined -
// and still run later via PostSearchFilter exactly as they would have
// without this seed; this only needs a pool guaranteed to contain the final
// answer, not the smallest one a second filter could in principle produce.
// Disqualified the same way a number filter is when negated: -vendor:TEST
// names what a card must not have among possibly many others it does, which
// is not a set this can name by enumerating one store's keys - and a
// negated store filter carries no Values to enumerate regardless.
func storeSeedUUIDs(b *mtgmatcher.Backend, config SearchConfig) ([]string, bool) {
	var f *FilterPostElem
	for i := range config.PostFilters {
		if config.PostFilters[i].Name == "any" && len(config.PostFilters[i].Values) > 0 {
			f = &config.PostFilters[i]
			break
		}
	}
	if f == nil {
		return nil, false
	}

	// Callers only reach this for card-scoped modes (see searchAndFilter),
	// so a sealed listing - most stores carry only one or the other, but
	// nothing here can assume that of an arbitrary shorthand - is dropped
	// rather than handed to a mode that otherwise never returns one.
	var uuids []string
	addCard := func(cardID string) {
		co, err := b.GetUUID(cardID)
		if err != nil || co.Sealed {
			return
		}
		uuids = append(uuids, cardID)
	}
	if !f.OnlyForVendor {
		for _, seller := range GetSellers() {
			if !slices.Contains(f.Values, strings.ToLower(seller.Info().Shorthand)) {
				continue
			}
			for cardID := range seller.Inventory() {
				addCard(cardID)
			}
		}
	}
	if !f.OnlyForSeller {
		for _, vendor := range GetVendors() {
			if !slices.Contains(f.Values, strings.ToLower(vendor.Info().Shorthand)) {
				continue
			}
			for cardID := range vendor.Buylist() {
				addCard(cardID)
			}
		}
	}
	// A store filter is applicable the moment it names a shorthand to seed
	// from, whether or not that shorthand turns out to match a registered
	// scraper or carry the requested card: same principle as the edition and
	// number seeds above, seeded-but-empty answers "found nothing" directly
	// rather than falling back to the whole pool to rediscover the same
	// emptiness the slow way.
	return dedupeKeys(uuids), true
}

func searchAndFilter(ds *datastore, config SearchConfig) ([]string, error) {
	query := config.CleanQuery
	filters := config.CardFilters

	var uuids []string
	var seeded bool
	var err error

	// With no text to search, the mode switch below degrades to seeding
	// from the whole uuid pool. A positive edition filter names its exact
	// result set, so seed from the set index instead: s:EXP,INV becomes
	// the union of two set buckets. Only the modes whose empty-query
	// fallback is the full pool are eligible, and the seeded uuids flow
	// into the same filtering loop as every other search.
	//
	// A seed that finds nothing has still answered. Reading that as "did
	// not seed" sent the search back to the whole pool to rediscover the
	// same emptiness.
	if query == "" {
		if codes, ok := editionSeedCodes(filters); ok {
			for _, code := range codes {
				switch config.SearchMode {
				case "", "prefix", "any":
					uuids = append(uuids, ds.backend.GetUUIDsInSet(code)...)
					seeded = true
				case "sealed":
					uuids = append(uuids, ds.backend.GetSealedUUIDsInSet(code)...)
					seeded = true
				}
			}
		}
		// A number bounds the set the same way an edition does, and the
		// numbers snapshot holds cards alone, so the sealed modes keep to
		// the set index above.
		if !seeded {
			switch config.SearchMode {
			case "", "prefix", "any":
				uuids, seeded = numberSeedUUIDs(ds.numbers, filters)
			}
		}
		// A plain store:/seller:/vendor: query names its own exact result
		// set the same way. Kept to the same modes as the number seed above:
		// a store's inventory can hold sealed products and cards both (a
		// store dealing in both normally registers as two scrapers, one per
		// SealedMode, but nothing here can assume that of an arbitrary
		// shorthand), and only these modes already mean "cards, not sealed
		// product listings" on their own - seeding them here keeps that
		// scoping rather than handing the sealed page a card row or a
		// regular search a sealed one.
		if !seeded {
			switch config.SearchMode {
			case "", "prefix", "any":
				uuids, seeded = storeSeedUUIDs(ds.backend, config)
			}
		}
	}

	if !seeded {
		switch config.SearchMode {
		case "exact":
			uuids, err = ds.backend.SearchEquals(query)
		case "any":
			uuids, err = ds.backend.SearchContains(query)
		case "prefix":
			uuids, err = ds.backend.SearchHasPrefix(query)
		case "hashing":
			uuids = config.UUIDs
		case "regexp":
			uuids, err = ds.backend.SearchRegexp(query)
		case "sealed":
			uuids, err = ds.backend.SearchSealedEquals(query)
			if err != nil {
				uuids, err = ds.backend.SearchSealedContains(query)
			}
		case "scryfall":
			uuids, err = searchScryfall(ds.backend, query)
		case "mixed":
			uuids, err = ds.backend.SearchSealedEquals(query)
			if err != nil {
				uuids, err = ds.backend.SearchSealedContains(query)
			}
			moreUUIDs, _ := ds.backend.SearchEquals(query)
			uuids = append(uuids, moreUUIDs...)
		default:
			uuids, err = ds.backend.SearchEquals(query)
			// An exact name match can be a red herring: "serra" names a
			// Vanguard card, so "s:leb serra" would stop at it and then
			// filter it out, finding nothing. When the filters reject every
			// exact match, widen to the prefix pool - exactly what the
			// query would have used had the exact name not existed. The
			// surviving exact matches return directly so the filters run
			// once either way.
			if err == nil && len(filters) != 0 {
				selected := filterUUIDs(ds.backend, uuids, filters)
				if len(selected) != 0 {
					return selected, nil
				}
				moreUUIDs, moreErr := ds.backend.SearchHasPrefix(query)
				if moreErr == nil {
					uuids = moreUUIDs
				}
			}
			if err != nil {
				uuids, err = ds.backend.SearchHasPrefix(query)
				if err != nil {
					uuids, err = ds.backend.SearchRegexp(query)
				}
			}
		}
		// attemptMatch reads the query as a card name, which is no answer on
		// the sealed tab: what is asked there is which product carries the
		// name, and none is a better answer than a card nobody asked for.
		if err != nil && config.SearchMode != "sealed" {
			uuids, err = attemptMatch(ds.backend, query)
		}
		if err != nil {
			return nil, err
		}
	}

	return filterUUIDs(ds.backend, uuids, filters), nil
}

// filterUUIDs returns the uuids that pass every card filter.
func filterUUIDs(b *mtgmatcher.Backend, uuids []string, filters []FilterElem) []string {
	var selected []string
	for _, uuid := range uuids {
		if shouldSkipCardNG(b, uuid, filters) {
			continue
		}
		selected = append(selected, uuid)
	}
	return selected
}

func editionsForSearch(ds *datastore, allKeys []string) []EditionEntry {
	codes := map[string]bool{}
	seenNames := map[string]bool{}
	for _, cardID := range allKeys {
		co, err := ds.backend.GetUUID(cardID)
		if err != nil || seenNames[co.Name] {
			continue
		}
		seenNames[co.Name] = true
		printings, err := ds.backend.Printings4Card(co.Name)
		if err != nil {
			continue
		}
		for _, code := range printings {
			codes[code] = true
		}
	}
	if len(codes) == 0 {
		return nil
	}

	editions := ds.editions
	out := make([]EditionEntry, 0, len(codes))
	for code := range codes {
		if entry, ok := editions.AllEditionsMap[code]; ok {
			out = append(out, entry)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}

// addFinishVariants appends id's foil and etched finishes to uuids, skipping
// any that don't exist, equal id, or are already present.
func addFinishVariants(b *mtgmatcher.Backend, uuids []string, id string) []string {
	foilID, _ := b.MatchID(id, true)
	etchedID, _ := b.MatchID(id, false, true)
	for _, otherFinishID := range []string{foilID, etchedID} {
		if otherFinishID != "" && otherFinishID != id && !slices.Contains(uuids, otherFinishID) {
			uuids = append(uuids, otherFinishID)
		}
	}
	return uuids
}

func searchScryfall(b *mtgmatcher.Backend, query string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(time.Second*30))
	defer cancel()

	client, err := scryfall.NewClient()
	if err != nil {
		return nil, err
	}

	i := 1
	var out []string
	for {
		sco := scryfall.SearchCardsOptions{
			Unique:        scryfall.UniqueModePrints,
			IncludeExtras: true,
			Page:          i,
		}

		result, err := client.SearchCards(ctx, query, sco)
		if err != nil {
			return nil, err
		}

		// Sort through the results, add the possible foil and etched variants
		for _, card := range result.Cards {
			id := b.ConvertID(mtgmatcher.IDSpaceScryfall, card.ID)
			if id == "" {
				continue
			}
			if !slices.Contains(out, id) {
				out = append(out, id)
			}
			out = addFinishVariants(b, out, id)
		}

		// Exit the loop when there are no more results
		// or when too many got pulled in
		if !result.HasMore || i > 5 {
			break
		}
		i++
	}

	return out, nil
}

// Try searching for cards usign the Match algorithm
func attemptMatch(b *mtgmatcher.Backend, query string) ([]string, error) {
	var uuids []string
	uuid, err := b.Match(&mtgmatcher.InputCard{
		Name: query,
	})
	if err != nil {
		var alias *mtgmatcher.AliasingError
		if errors.As(err, &alias) {
			uuids = alias.Probe()
		} else {
			// Unsupported case, give up
			return nil, err
		}
	} else {
		uuids = append(uuids, uuid)
	}

	// Repeat for foil and etched (only add if not previously found)
	// Add as needed depending on the previous query result
	for _, id := range uuids {
		uuids = addFinishVariants(b, uuids, id)
	}

	return uuids, nil
}

func searchParallelNG(cardIDs []string, config SearchConfig) (foundSellers map[string]map[mtgban.Condition][]SearchEntry, foundVendors map[string]map[mtgban.Condition][]SearchEntry) {
	// Initialize up front so callers can always assign into them; when retail or
	// buylist is skipped the corresponding search is never run and the map would
	// otherwise stay nil, panicking on the first write (e.g. the INDEX block).
	foundSellers = map[string]map[mtgban.Condition][]SearchEntry{}
	foundVendors = map[string]map[mtgban.Condition][]SearchEntry{}

	// Each scan recovers its own panic, which then costs only its side: the
	// map it would have filled stays empty.
	var wg sync.WaitGroup
	wg.Go(func() {
		defer recoverJob("search sellers scan")
		if !config.SkipRetail {
			foundSellers = searchSellersNG(cardIDs, config)
		}
	})
	wg.Go(func() {
		defer recoverJob("search vendors scan")
		if !config.SkipBuylist {
			foundVendors = searchVendorsNG(cardIDs, config)
		}
	})

	wg.Wait()

	return
}

type SortingData struct {
	co          *mtgmatcher.CardObject
	releaseDate time.Time
	parentCode  string

	// Lowercased fields the comparators order by, so the N log N
	// comparisons don't re-lower them every time.
	nameLower    string
	editionLower string

	// The edition the hybrid sort files this card under: its own, or its
	// parent's for an edition that reprints the parent's card list.
	groupLower string
	reprint    bool

	// The set code the card's number is written after (setCodePrefix),
	// which the default order reads before the number.
	numberPrefix string
}

func getSortingData(b *mtgmatcher.Backend, uuid string) (*SortingData, error) {
	co, err := b.GetUUID(uuid)
	if err != nil {
		return nil, err
	}
	set, err := b.GetSet(co.SetCode)
	if err != nil {
		return nil, err
	}
	releaseDate, err := b.CardReleaseDate(uuid)
	if err != nil {
		return nil, err
	}
	sorting := &SortingData{
		co:           co,
		releaseDate:  releaseDate,
		parentCode:   set.ParentCode,
		nameLower:    strings.ToLower(co.Name),
		editionLower: strings.ToLower(co.Edition),
	}
	sorting.groupLower = sorting.editionLower
	sorting.numberPrefix = setCodePrefix(co.Number)
	return sorting, nil
}

// setCodePrefix is the set code a collector number is written after, ""
// for none: the part before the last dash, holding a letter, with a digit
// after the dash. So a year, "2024-10", and a variant, "2J-b", have none.
// No game's set code ends in three digits; "LGS360-FUN001" is a card's own
// number with a variant behind it.
func setCodePrefix(number string) string {
	dash := strings.LastIndex(number, "-")
	if dash < 0 {
		return ""
	}
	prefix := number[:dash]
	if !strings.ContainsFunc(prefix, unicode.IsLetter) ||
		!strings.ContainsFunc(number[dash+1:], func(r rune) bool { return !isNotDigit(r) }) {
		return ""
	}
	digits := len(prefix) - len(strings.TrimRightFunc(prefix, func(r rune) bool { return !isNotDigit(r) }))
	if digits >= 3 {
		return ""
	}
	return prefix
}

// fileReprintsUnderParent has the hybrid sort file every card of an
// edition in parents (editionsSnapshot.ReprintParents) under its parent.
func fileReprintsUnderParent(sortData map[string]*SortingData, parents map[string]string) {
	for _, sorting := range sortData {
		if sorting == nil {
			continue
		}
		parent, found := parents[sorting.co.SetCode]
		if found {
			sorting.groupLower = parent
			sorting.reprint = true
		}
	}
}

// resolveSortingData resolves the sorting data of every given id up
// front, so the N log N comparisons of a sort look each card up instead
// of re-resolving it every time they see it; a sort visits all of its
// elements, so nothing is saved by resolving lazily. Unknown ids get a
// nil entry, which the cmp* comparators order like the lookup error it
// stands for.
func resolveSortingData(b *mtgmatcher.Backend, cardIDs []string) map[string]*SortingData {
	data := make(map[string]*SortingData, len(cardIDs))
	for _, cardID := range cardIDs {
		_, found := data[cardID]
		if found {
			continue
		}
		sorting, _ := getSortingData(b, cardID)
		data[cardID] = sorting
	}
	return data
}

// resolveBestPrices records the highest price every given id fetches
// among the listed stores: each price4seller/price4vendor call walks
// the scraper list, so the price sorts must not repeat it per
// comparison, let alone N log N times.
func resolveBestPrices(cardIDs []string, stores []string, price4 func(cardId, shorthand string) float64) map[string]float64 {
	prices := make(map[string]float64, len(cardIDs))
	for _, cardID := range cardIDs {
		_, found := prices[cardID]
		if found {
			continue
		}
		var best float64
		for _, store := range stores {
			price := price4(cardID, store)
			if price > best {
				best = price
			}
		}
		prices[cardID] = best
	}
	return prices
}

// cmpNumberAndFinish sorts cards by their collector number and finish
// (nonfoil-foil-etched); nil data (an unknown id) sorts like the lookup
// error it stands for.
func cmpNumberAndFinish(sortingI, sortingJ *SortingData, strip bool) bool {
	if sortingI == nil || sortingJ == nil {
		return false
	}
	cI := sortingI.co
	cJ := sortingJ.co

	numI := cI.Card.Number
	numJ := cJ.Card.Number

	// If their number is the same, nonfoil, foil, then etched, and within a
	// finish by promo types, whatever their count: one key, so one order
	if numI == numJ {
		finishI, finishJ := finishOrder(cI), finishOrder(cJ)
		if finishI != finishJ {
			return finishI < finishJ
		}
		// They are presorted anyway
		promos := slices.Compare(cI.PromoTypes, cJ.PromoTypes)
		if promos != 0 {
			return promos < 0
		}
	}

	// Every number is read one way, so a sort sees one order: comparing
	// plain numbers by value and the rest as strings put 800, 1553 and
	// 1553★ in a loop. Stripped, only the value of the digits counts first.
	if strip {
		valI, hasI := digitsValue(numI)
		valJ, hasJ := digitsValue(numJ)
		if hasI != hasJ {
			return hasI
		}
		if valI != valJ {
			return valI < valJ
		}
	} else if c := cmpNaturally(numI, numJ); c != 0 {
		return c < 0
	}

	// At this point, numbers look pretty similar, check for languages
	if cI.Card.Language != cJ.Card.Language {
		return cI.Card.Language < cJ.Card.Language
	}
	natural := cmpNaturally(numI, numJ)
	if natural != 0 {
		return natural < 0
	}
	// Two finishes the flags above read alike (holofoil, reverse holofoil),
	// then the uuid, so no two printings tie and the order is total.
	if cI.Finish != cJ.Finish {
		return cI.Finish < cJ.Finish
	}
	return cI.UUID < cJ.UUID
}

// finishOrder ranks a printing's finish for the number sort: nonfoil,
// foil, then etched.
func finishOrder(co *mtgmatcher.CardObject) int {
	switch {
	case co.Etched:
		return 2
	case co.Foil:
		return 1
	}
	return 0
}

// cmpNaturally orders collector numbers as a reader does: runs of digits by
// their value and everything else as written, so 800 < 1553 < 1553★ and
// 12 < A-5. Readings that tie fall back to the strings, keeping it total.
func cmpNaturally(a, b string) int {
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		if !isDigit(a[i]) || !isDigit(b[j]) {
			if a[i] != b[j] {
				return cmp.Compare(a[i], b[j])
			}
			i++
			j++
			continue
		}
		startI, startJ := i, j
		for i < len(a) && isDigit(a[i]) {
			i++
		}
		for j < len(b) && isDigit(b[j]) {
			j++
		}
		runI := strings.TrimLeft(a[startI:i], "0")
		runJ := strings.TrimLeft(b[startJ:j], "0")
		if len(runI) != len(runJ) {
			return cmp.Compare(len(runI), len(runJ))
		}
		c := strings.Compare(runI, runJ)
		if c != 0 {
			return c
		}
	}
	c := cmp.Compare(len(a)-i, len(b)-j)
	if c != 0 {
		return c
	}
	return strings.Compare(a, b)
}

// digitsValue is the value of a number's first run of digits, and whether
// it has one.
func digitsValue(number string) (int, bool) {
	start := strings.IndexFunc(number, func(r rune) bool { return !isNotDigit(r) })
	if start < 0 {
		return 0, false
	}
	end := start
	for end < len(number) && isDigit(number[end]) {
		end++
	}
	value, err := strconv.Atoi(number[start:end])
	return value, err == nil
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

// Sort cards grouping them by edition, and then by their collector number
func sortSets(b *mtgmatcher.Backend, uuidI, uuidJ string) bool {
	sortingI, _ := getSortingData(b, uuidI)
	sortingJ, _ := getSortingData(b, uuidJ)
	return cmpSets(sortingI, sortingJ)
}

// cmpSets is sortSets over already-resolved sorting data.
func cmpSets(sortingI, sortingJ *SortingData) bool {
	if sortingI == nil || sortingJ == nil {
		return false
	}
	cI, setDateI := sortingI.co, sortingI.releaseDate
	cJ, setDateJ := sortingJ.co, sortingJ.releaseDate

	// If the two sets have the same release date, let's dig more
	if setDateI.Equal(setDateJ) {
		// If they are part of the same edition, check for their collector number
		// taking their foiling into consideration
		if cI.Edition == cJ.Edition {
			// Special case for sealed products
			if cI.Sealed && cJ.Sealed {
				// Always keep these products in this order
				for _, prodTag := range []string{"Booster Box", "Booster Pack", "Bundle", "Fat Pack"} {
					bbI := strings.Contains(cI.Name, prodTag) && !strings.Contains(cI.Name, "Case")
					bbJ := strings.Contains(cJ.Name, prodTag) && !strings.Contains(cJ.Name, "Case")
					if bbI && !bbJ {
						return true
					} else if !bbI && bbJ {
						return false
					}
				}

				// Keep Cases and sets last
				bbI := strings.Contains(cI.Name, "Case") || strings.Contains(cI.Name, "Display") || strings.Contains(cI.Name, "Set of")
				bbJ := strings.Contains(cJ.Name, "Case") || strings.Contains(cJ.Name, "Display") || strings.Contains(cJ.Name, "Set of")
				if bbI && !bbJ {
					return false
				} else if !bbI && bbJ {
					return true
				}

				return sortingI.nameLower < sortingJ.nameLower
			}

			// Numbers with a set code prefix sort by prefix, after the plain
			// ones, so a prefix's digits never interleave two prefixes.
			c := cmpNaturally(sortingI.numberPrefix, sortingJ.numberPrefix)
			if c != 0 {
				return c < 0
			}
			return cmpNumberAndFinish(sortingI, sortingJ, true)
			// For the special case of set promos, always keeps them after
		} else if sortingI.parentCode == "" && sortingJ.parentCode != "" {
			return true
		} else if sortingJ.parentCode == "" && sortingI.parentCode != "" {
			return false
		}
		return sortingI.editionLower < sortingJ.editionLower
	}

	return setDateI.After(setDateJ)
}

// cmpSetsAlphabetical sorts cards by their names, trying to keep cards
// grouped by edition, following the same rules as sortSets.
//
// The English name is what orders the list, even for a card displayed
// under its localized name. A Japanese printing keyed on its own name
// lands wherever the first code point of the kanji happens to fall,
// which is not an order anybody reading an A-to-Z list is following;
// and a localized name, Latin script or not, files the card away from
// the English printing it reprints - "Pocion de alabastro" would sit
// under P, chapters away from "Alabaster Potion".
func cmpSetsAlphabetical(sortingI, sortingJ *SortingData) bool {
	if sortingI == nil || sortingJ == nil {
		return false
	}
	cI, setDateI := sortingI.co, sortingI.releaseDate
	cJ, setDateJ := sortingJ.co, sortingJ.releaseDate

	if cI.Name == cJ.Name {
		if setDateI.Equal(setDateJ) {
			// Same number in two editions is a tie the number can't break
			if cI.Edition != cJ.Edition && cI.Card.Number == cJ.Card.Number {
				return cmpSets(sortingI, sortingJ)
			}
			// We need not to strip to keep set ordered wrt Promos etc
			return cmpNumberAndFinish(sortingI, sortingJ, false)
		}

		return setDateI.After(setDateJ)
	}

	return sortingI.nameLower < sortingJ.nameLower
}

// cmpSetsAlphabeticalSet sorts cards by their names, keeping cards grouped
// by edition alphabetically. An edition reprinting its parent's card list
// sorts right after the parent, once fileReprintsUnderParent has run.
func cmpSetsAlphabeticalSet(sortingI, sortingJ *SortingData) bool {
	if sortingI == nil || sortingJ == nil {
		return false
	}
	cI := sortingI.co
	cJ := sortingJ.co

	if cI.SetCode == cJ.SetCode {
		return cmpSetsAlphabetical(sortingI, sortingJ)
	}
	if sortingI.groupLower != sortingJ.groupLower {
		return sortingI.groupLower < sortingJ.groupLower
	}
	if sortingI.reprint != sortingJ.reprint {
		return sortingJ.reprint
	}

	return sortingI.editionLower < sortingJ.editionLower
}
