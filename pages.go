package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/mtgban-website/internal/dsreload"
	"github.com/mtgban/mtgban-website/internal/jobs"
	"github.com/mtgban/mtgban-website/internal/suggest"
	"github.com/mtgban/mtgban-website/internal/tmplparse"
	"github.com/mtgban/mtgban-website/observability"
)

// UsageDashboard holds the telemetry aggregates rendered on /admin?page=usage.
type UsageDashboard struct {
	Since       time.Time
	IncludeBots bool
	Instance    string
	TopPages    []observability.PathAgg
	ByTier      []observability.TierAgg
	ByDevice    []observability.DeviceAgg
	SubViews    []observability.PathAgg
}

type PageVars struct {
	Pagination

	Nav      []NavElem
	ExtraNav []NavElem
	BetaNav  *NavElem

	PatreonIDs   map[string]string
	PatreonURL   string
	PatreonLogin bool

	// The tier of whoever is reading, lowercased, for the navbar to tint
	// itself by. Empty for a reader who is not signed in.
	UserTier string
	Hash     string

	IsMobile bool

	// GatewayURL is the API gateway's origin, for links to its account and admin pages.
	GatewayURL string

	// HandoffOrigins are the sites the upload handoff page will take a card
	// list from. It reads them rather than naming one itself, so the list
	// lives in Go where it can be tested.
	HandoffOrigins []string

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

	Title          string
	ErrorMessage   string
	WarningMessage string
	InfoMessage    string
	UsageStats     *UsageDashboard

	AllKeys        []string
	CardQuantities map[string]int
	SearchQuery    string
	SearchBest     bool
	ListingLocked  bool
	SearchSort     string
	CondKeys       []mtgban.Condition
	FoundSellers   map[string]map[mtgban.Condition][]SearchEntry
	FoundVendors   map[string]map[mtgban.Condition][]SearchEntry
	Metadata       map[string]GenericCard
	SetKeyrunes    map[string]string
	NoSort         bool
	HasSettings    bool
	HasAvailable   bool
	ShowUpsell     bool

	PopularSearches []PopularSearch
	Changelog       []changelogGroup
	ChangelogError  string

	CanShowAll       bool
	CleanSearchQuery string

	// The sticky filter bar: what the searcher pinned once and does not
	// retype, kept apart from SearchQuery so either bar can change without
	// disturbing the other. CanScope is what draws it at all, since the
	// navbar is shared with pages that run no search.
	SearchScope string
	CanScope    bool
	// The bar holds something that parses to no filter at all, so the
	// search passes over it whole.
	ScopeIgnored bool
	// A search ran for this request. Not the same as SearchQuery being set:
	// a pinned filter searches on its own, and the page has results to draw
	// (or an empty-handed answer to give) with the box above it empty.
	SearchRan bool

	// The switch between the three readings of a sealed product's contents,
	// nil unless the search is one of them over a product that has all three
	Contents *ContentsViews
	// Which reading a product's link opens, from the reader's settings
	SealedContents string

	CheckpointsText    string
	ACLText            string
	ACLSource          string
	AffiliatesText     string
	AffiliatesSource   string
	KeyOverridesText   string
	OverrideStores     []string
	OverrideFixStore   string
	OverrideFixKind    string
	OverrideWrongCard  *OverrideCard
	OverrideCandidates []OverrideCard
	CanFixSearch       bool

	// Suggestions shown when a search returns no results
	DidYouMean  string
	AltSearches []suggest.AltSearch

	ScraperShort   string
	CanDownloadCSV bool

	Arb                []Arbitrage
	DirectStockNote    string
	ArbitOptKeys       []string
	ArbitOptConfig     map[string]FilterOpt
	ArbitFilters       map[string]bool
	SortOption         string
	GlobalMode         bool
	ReverseMode        bool
	DefaultTab         string
	DefaultView        mtgban.Condition
	MobileSearchLayout string

	Page               string
	Subtitle           string
	ToC                []NewspaperPage
	Headings           []Heading
	Cards              []GenericCard
	Table              []NewspaperResult
	IsOneDay           bool
	CanSwitchDay       bool
	SortDir            string
	OffsetCards        int
	FilterSet          string
	Editions           []string
	FlatEditions       []FlatEditionEntry
	FilterRarity       string
	FilterBucket       string
	FilterFinish       string
	Rarities           []string
	CardHashes         []string
	EditionsMap        map[string]EditionEntry
	EditionsCategories []string
	EditionsByCategory map[string][]EditionEntry
	PickerID           string
	OfflineModeAllowed bool

	CanFilterByPrice bool
	FilterMinPrice   float64
	FilterMaxPrice   float64

	CanFilterByPercentage bool
	FilterMinPercChange   float64
	FilterMaxPercChange   float64

	Sleepers       map[string][]string
	SleepersKeys   []string
	SleepersColors []string

	Tables          [][][]string
	Jobs            []jobs.Row
	LastUpdate      time.Time
	DatastoreReload dsreload.State
	LastNews        time.Time
	LastStash       time.Time
	Uptime          string
	DiskStatus      string
	MemoryStatus    string
	LatestHash      string
	Tiers           []string
	Finishes        []string

	SelectableField bool
	SelectableLabel string

	DisableChart    bool
	MaxLookbackDays int
	// ChartLoadedDays is how much history the page actually rendered inline:
	// the window the chart first draws, or everything the tier allows when
	// that window holds no prices. The front-end fetches the rest from
	// /api/chart only if the viewer asks for a wider range.
	ChartLoadedDays int
	AxisLabels      []string
	Datasets        []Dataset
	Checkpoints     []ChartCheckpoint
	ChartID         string
	ChartIDs        []string
	ChartIDsCSV     string
	MaxChartCards   int
	IsMultiChart    bool
	ChartReferences []string
	ModalMode       bool
	Alternative     string
	StocksURL       string
	AltEtchedID     string

	EditionSort       []string
	EditionList       map[string][]EditionEntry
	EditionFilterList []EditionEntry
	IsSealed          bool
	TotalSets         int
	TotalCards        int
	TotalUnique       int

	// UPLOAD
	// All the scrapers in singles/sealed mode
	AllScraperKeys []string
	// All the singles scrapers
	ScraperKeys []string
	IndexKeys   []string
	// All the sealed scrapers
	SealedScraperKeys []string
	SealedIndexKeys   []string

	// All the index prices that can be toggled, and the subset the user
	// enabled (shared between Retail and Buylist, they are references)
	IndexAllKeys         []string
	EnabledIndexes       []string
	SealedIndexAllKeys   []string
	EnabledSealedIndexes []string

	// Additional sources for index keys if needed
	AltKeys          []string
	SellerKeys       []string
	VendorKeys       []string
	SealedSellerKeys []string
	SealedVendorKeys []string
	ModalSellerKeys  []string
	ModalVendorKeys  []string
	UploadEntries    []UploadEntry

	// UnpackSealed counts the rows holding a decklist, which is what decides
	// whether the results offer to open them. The contents themselves are
	// resolved when the offer is taken, not before.
	UnpackSealed int

	// UnpackedFrom counts the products this list is the contents of, and is
	// how the results say they are that rather than an upload: the rest of
	// what was uploaded is deliberately not here.
	UnpackedFrom         int
	IsBuylist            bool
	TotalEntries         map[string]float64
	EnabledSellers       []string
	EnabledVendors       []string
	EnabledSealedSellers []string
	EnabledSealedVendors []string
	CanBuylist           bool
	MagicOnlyExports     bool
	CanChangeStores      bool
	CanUploadCustom      bool
	CanPublishStore      bool
	RemoteLinkURL        string
	TotalQuantity        int
	Optimized            map[string][]OptimizedUploadEntry
	OptimizedKeys        []string
	IgnorePrices         bool
	OptimizedTotals      map[string]float64
	HighestTotal         float64
	MissingCounts        map[string]int
	MissingPrices        map[string]float64
	ResultPrices         map[string]map[string]float64
	UploadQuery          string
	// Original link of a remote-URL upload, so the results header can
	// point back at the source
	UploadSourceURL string
	// Upload singles/sealed/not-found split
	SinglesEntries    []UploadEntry
	SealedEntries     []UploadEntry
	NotFoundEntries   []UploadEntry
	SinglesQuantity   int
	SealedQuantity    int
	SinglesHighest    float64
	SealedHighest     float64
	ShowResultTabs    bool
	ShowAllTab        bool
	DefaultResultView string

	// One section per opened product, replacing the category split when the
	// list was unpacked
	UnpackedSections []UnpackedSection

	// Price-movers screener payload (nil on non-screener pages).
	Screener *ScreenerVars

	// API plans page payload (nil elsewhere)
	API *APIPlansVars

	// Alerts page payload (nil elsewhere)
	AlertsPage *AlertsPageVars
	// CanAlerts says the reader's ACL grants the Alerts page and an
	// allowance, so result rows may offer the alert link.
	CanAlerts bool
}

func genPageNav(s *site, r *http.Request, activeTab, sig string) PageVars {
	// Decode the sig once; this function reads it for expiry, every nav
	// feature, and the user email, and each GetParamFromSig call would
	// re-parse the whole thing.
	sigParams := parseSig(sig)
	expires, _ := strconv.ParseInt(sigParams.Get("Expires"), 10, 64)
	msg := ""
	showPatreonLogin := false
	origin := requestOrigin(r)
	if sig != "" {
		if expires < time.Now().Unix() {
			msg = ErrMsgExpired
		}
	} else if origin != "" {
		showPatreonLogin = true
	}

	// These values need to be set for every rendered page
	// In particular the Patreon variables are needed because the signature
	// could expire in any page, and the button url needs these parameters
	patreonURL := ""
	if origin != "" {
		patreonURL = origin + "/auth"
	}
	pageVars := PageVars{
		Title:        "BAN " + activeTab,
		ErrorMessage: msg,

		PatreonIDs:   Config().Patreon.Client,
		PatreonURL:   patreonURL,
		PatreonLogin: showPatreonLogin,
		Hash:         BuildCommit,
		GatewayURL:   Config().APIGateway.URL,

		// Read off the signature that is already parsed above, so the navbar
		// can wear the tier without asking anybody
		UserTier: strings.ToLower(sigParams.Get("UserTier")),
	}

	if Config().Game != DefaultGame {
		// Append which game this site is for
		pageVars.Title += " - " + mtgmatcher.Title(string(Config().Game))

		// Charts for a non-Magic game are served only by the long-form read
		// path; the legacy wide table is mtgjson-uuid keyed and has no rows for
		// them. Until reads flip on, keep the chart UI hidden rather than show
		// buttons that resolve to an always-empty chart.
		if !Config().TimeseriesConfig.LongFormReads {
			pageVars.DisableChart = true
		}
	}
	// Allocate a new navigation bar
	pageVars.Nav = make([]NavElem, len(DefaultNav))
	copy(pageVars.Nav, DefaultNav)

	// Enable buttons according to the enabled features
	for _, feat := range OrderNav {
		_, noAuth := ACL()["Any"][feat]
		validSig := expires > time.Now().Unix()
		devMode := DevMode && !SigCheck
		alwaysOnDev := DevMode && ExtraNavs[feat].AlwaysOnForDev
		if !validSig && !devMode && !noAuth {
			continue
		}

		allowed := devMode || noAuth || alwaysOnDev
		if !allowed {
			allowed, _ = strconv.ParseBool(sigParams.Get(feat))
		}

		if !allowed {
			continue
		}

		// A hidden section takes its subpages with it: they are reached
		// through it, and half a section is worse than none.
		if ExtraNavs[feat].ShouldHide != nil && ExtraNavs[feat].ShouldHide(s) {
			continue
		}

		pageVars.Nav = append(pageVars.Nav, *ExtraNavs[feat])
		for _, subPage := range ExtraNavs[feat].SubPages {
			if subPage.ShouldHide != nil && subPage.ShouldHide(s) {
				continue
			}
			pageVars.Nav = append(pageVars.Nav, subPage)
		}
	}

	mainNavIndex := 0
	for i := range pageVars.Nav {
		if pageVars.Nav[i].Name == activeTab {
			mainNavIndex = i
			break
		}
	}
	pageVars.Nav[mainNavIndex].Active = true
	pageVars.Nav[mainNavIndex].Class = "active"
	// Surface the active page's HasSettings on PageVars so the navbar
	// template can pre-resolve the gear button's state without the
	// inline script having to maintain a duplicate list of paths.
	pageVars.HasSettings = pageVars.Nav[mainNavIndex].HasSettings

	// CanAlerts says the reader's tier has the Alerts page and an
	// allowance, so result rows may offer the alert link.
	for _, n := range pageVars.Nav {
		if n.Name == "Alerts" {
			pageVars.CanAlerts = alertAllowance(sigParams) > 0
			break
		}
	}

	// Add user information if needed, or public
	user := sigParams.Get("UserEmail")
	if user == "" {
		if !showPatreonLogin {
			user = "Anonymous"
		}
		_, noAuth := ACL()["Any"][pageVars.Nav[mainNavIndex].Name]
		if noAuth {
			user = ""
		}
	}

	extra := NavElem{
		Active: true,
		Class:  "beta",
		Short:  user,
		Link:   "javascript:void(0)",
	}
	pageVars.BetaNav = &extra
	return pageVars
}

// TemplateCache holds pre-parsed templates keyed by their base name.
// Populated at startup in production; nil in DevMode (re-parsed per request).
var TemplateCache map[string]*template.Template

func renderTemplateFiles(tmpl string, isMobile bool) (baseName string, files []string) {
	name := path.Base(tmpl)

	// Check for mobile-specific template override
	if isMobile {
		mobileTmpl := fmt.Sprintf("mobile/%s", tmpl)
		mobilePath := fmt.Sprintf("templates/%s", mobileTmpl)
		if _, err := os.Stat(mobilePath); err == nil {
			tmpl = mobileTmpl
			name = path.Base(tmpl)
		}
	}

	// Select base template
	base := "templates/base.html"
	if name == "home.html" && !isMobile {
		base = "templates/base-landing.html"
	} else if isMobile {
		mobileBase := "templates/mobile/base-mobile.html"
		if _, err := os.Stat(mobileBase); err == nil {
			base = mobileBase
		}
	}

	files = []string{base, fmt.Sprintf("templates/%s", tmpl)}

	// Always include the navbar partial
	navbarPartial := "templates/partials/navbar.html"
	if isMobile {
		mobileNavbar := "templates/mobile/partials/navbar.html"
		if _, err := os.Stat(mobileNavbar); err == nil {
			navbarPartial = mobileNavbar
		}
	}
	files = append(files, navbarPartial)

	// The set symbol is drawn by desktop and mobile pages alike, and each is
	// built from its own base, so the block cannot live in one of them.
	files = append(files, "templates/partials/set-symbol.html")

	// Include settings-modal partial only for desktop pages that define a "settings-content" block.
	if !isMobile {
		switch name {
		case "search.html":
			files = append(files,
				"templates/partials/settings-modal.html",
				"templates/partials/settings-stores-grouped.html",
				"templates/partials/editions-picker.html",
			)
		case "arbit.html":
			files = append(files,
				"templates/partials/settings-modal.html",
				"templates/partials/settings-stores-grouped.html",
			)
		case "upload.html":
			files = append(files, "templates/partials/settings-modal.html")
		case "sleep.html", "news.html":
			files = append(files,
				"templates/partials/settings-modal.html",
				"templates/partials/editions-picker.html",
			)
		case "admin.html":
			files = append(files, "templates/partials/admin-usage.html")
		}
	}

	// Add other partials as needed
	if name == "search.html" {
		files = append(files, "templates/partials/search-landing.html")
	}
	if name == "search.html" || name == "alerts.html" {
		files = append(files, "templates/partials/alert-modal.html")
	}
	if name == "arbit.html" {
		files = append(files, "templates/partials/sussy-price.html")
	}
	if name == "guide.html" {
		files = append(files, "templates/partials/guide-faq.html")
	}
	if name == "home.html" || name == "search.html" || name == "upload_handoff.html" {
		files = append(files, "templates/partials/patreon-login.html")
	}
	if name == "alerts.html" {
		files = append(files, "templates/partials/alerts-body.html")
	}

	return path.Base(base), files
}

func buildTemplateCache() (map[string]*template.Template, error) {
	if DevMode {
		return nil, nil
	}

	pages, err := filepath.Glob("templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("glob error: %w", err)
	}

	cache := make(map[string]*template.Template, len(pages)*2)
	for _, page := range pages {
		name := filepath.Base(page)
		for _, mobile := range []bool{false, true} {
			key := name
			if mobile {
				key = "mobile/" + name
			}
			baseName, files := renderTemplateFiles(name, mobile)
			t, err := tmplparse.ParseFiles(baseName, files, funcMap)
			if err != nil {
				return nil, fmt.Errorf("parsing %s (mobile=%v): %w", name, mobile, err)
			}
			cache[key] = t
		}
	}
	return cache, nil
}

func render(w http.ResponseWriter, tmpl string, pageVars PageVars) {
	name := path.Base(tmpl)

	if DevMode {
		// Hot-reload: re-parse from disk every request
		baseName, files := renderTemplateFiles(tmpl, pageVars.IsMobile)
		t, err := tmplparse.ParseFiles(baseName, files, funcMap)
		if err != nil {
			log.Print("template parsing error: ", err)
			return
		}
		err = t.ExecuteTemplate(w, baseName, pageVars)
		if err != nil {
			log.Print("template executing error: ", err)
		}
		return
	}

	// Production: use cached templates
	key := name
	if pageVars.IsMobile {
		key = "mobile/" + name
	}
	t, found := TemplateCache[key]
	if !found {
		log.Printf("template cache: %q not found", key)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	baseName := t.Name()
	err := t.ExecuteTemplate(w, baseName, pageVars)
	if err != nil {
		log.Print("template executing error: ", err)
	}
}
