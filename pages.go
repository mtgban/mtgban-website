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

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/mtgban-website/internal/tmplparse"
)

type NavElem struct {
	// Whether or not this the current active tab
	Active bool

	// For subtabs, define which is the current active sub-tab
	Class string

	// Endpoint of this page
	Link string

	// Name of this page
	Name string

	// Icon or seller shorthand
	Short string

	// One-line subtitle shown on the Tools dropdown tile
	Description string

	// Response handler
	Handle func(*site, http.ResponseWriter, *http.Request)

	// Which page to render
	Page string

	// Whether this tab should always be enabled in DevMode
	AlwaysOnForDev bool

	// Allow to receive POST requests
	CanPOST bool

	// Alternative endpoints connected to this handler
	SubPages []NavElem

	// Condition upon which the page should not be made visible. Reads the
	// site's current datastore for visibility only.
	ShouldHide func(*site) bool

	// True for pages whose settings modal has bindings (mirrors
	// PAGE_BINDINGS in js/settings.js). Used by the navbar inline
	// script to pre-resolve the gear button's enabled state so it
	// doesn't transition from is-disabled → enabled at load time.
	HasSettings bool
}

var DefaultNav = []NavElem{
	{
		Name:  "Home",
		Short: "🏡",
		Link:  "/",
		Page:  "home.html",
	},
	{
		Name:        "Changelog",
		Short:       "📝",
		Description: "See what changed recently",
		Link:        "/changelog",
		Page:        "changelog.html",
	},
}

// List of keys that may be present or not, and when present they are
// guaranteed not to be user-editable)
var OptionalFields = []string{
	"UserName",
	"UserEmail",
	"UserEmailUnverified",
	"UserTier",
	"SearchDisabled",
	"SearchBuylistDisabled",
	"SearchDownloadCSV",
	"SearchChartDelete",
	"SearchChartLoopback",
	"ArbitEnabled",
	"ArbitDisabledVendors",
	"NewsEnabled",
	"NewsLarge",
	"UploadBuylistEnabled",
	"UploadChangeStoresEnabled",
	"UploadOptimizer",
	"UploadNoLimit",
	"UploadCustom",
	"UploadPublish",
	"AnyEnabled",
	"AnyExperimentsEnabled",
	"AnySpread",
	"APImode",
	"SleepersCYOA",
	"SearchOfflineMode",
	"AlertsMax",
}

// The key matches the query parameter of the permissions defined in sign()
// These enable/disable the relevant pages
var OrderNav = []string{
	"Search",
	"Newspaper",
	"Screener",
	"Sleepers",
	"Upload",
	"Global",
	"Arbit",
	"Reverse",
	"Alerts",
	"API",
	"Admin",
}

// The Loggers where each page may log to
var LogPages map[string]*log.Logger

// All the page properties
var ExtraNavs map[string]*NavElem

func init() {
	ExtraNavs = map[string]*NavElem{
		"Search": {
			Name:        "Search",
			Short:       "🔍",
			Description: "Find a card by name",
			Link:        "/search",
			Handle:      (*site).Search,
			Page:        "search.html",
			HasSettings: true,
			SubPages: []NavElem{
				{
					Name:        "Sets",
					Short:       "📦",
					Description: "Browse every set on file",
					Link:        "/sets",
				},
				{
					Name:        "Sealed",
					Short:       "🧱",
					Description: "Sealed product search",
					Link:        "/sealed",
					HasSettings: true,
					ShouldHide: func(s *site) bool {
						return len(s.backend().GetSealedUUIDs()) == 0
					},
				},
			},
		},
		"Newspaper": {
			Name:        "Newspaper",
			Short:       "🗞️",
			Description: "Market movers & recent activity",
			Link:        "/newspaper",
			Handle:      (*site).Newspaper,
			Page:        "news.html",
			HasSettings: true,
			// Every page of it is built from the cached uuids, so with none
			// the section is a stack of empty tables. A game with no
			// newspaper data, or one whose database was never configured,
			// gets no entry rather than a dead end. The cron rebuilds the
			// cache every three hours, so it appears on its own once the
			// data does.
			ShouldHide: func(*site) bool {
				return len(GetNewspaperUUIDs()) == 0
			},
			SubPages: []NavElem{
				{
					Name:        "TCG Syp List",
					Short:       "📋",
					Description: "Cards TCGplayer wants now",
					Link:        "/newspaper?page=syp",
					HasSettings: true,
					ShouldHide: func(*site) bool {
						_, err := findVendorBuylist("SYP")
						return err != nil
					},
				},
			},
		},
		"Screener": {
			Name:        "Screener (Beta)",
			Short:       "🔎",
			Description: "Find cards by price movement over time",
			Link:        "/screener",
			Handle:      (*site).Screener,
			Page:        "screener.html",
		},
		"Sleepers": {
			Name:        "Sleepers",
			Short:       "💤",
			Description: "Under-the-radar picks",
			Link:        "/sleepers",
			Handle:      (*site).Sleepers,
			Page:        "sleep.html",
			HasSettings: true,
		},
		"Upload": {
			Name:        "Upload",
			Short:       "🚢",
			Description: "Bulk price your collection",
			Link:        "/upload",
			Handle:      (*site).Upload,
			Page:        "upload.html",
			HasSettings: true,
			CanPOST:     true,
		},
		"Global": {
			Name:        "Global",
			Short:       "🌍",
			Description: "Cross-region price view",
			Link:        "/global",
			Handle:      (*site).Global,
			Page:        "arbit.html",
			HasSettings: true,
		},
		"Arbit": {
			Name:        "Arbitrage",
			Short:       "📈",
			Description: "Buy low, sell high spreads",
			Link:        "/arbit",
			Handle:      (*site).Arbit,
			Page:        "arbit.html",
			HasSettings: true,
		},
		"Reverse": {
			Name:        "Reverse",
			Short:       "📉",
			Description: "Reverse-direction arbitrage",
			Link:        "/reverse",
			Handle:      (*site).Reverse,
			Page:        "arbit.html",
			HasSettings: true,
		},
		"Alerts": {
			Name:        "Alerts",
			Short:       "🔔",
			Description: "Price alerts delivered to Discord",
			Link:        "/alerts",
			Handle:      (*site).Alerts,
			Page:        "alerts.html",
			// No store, no alerts: the page and its result-row links go.
			ShouldHide: func(s *site) bool { return s.alerts.Store() == nil },
		},
		"API": {
			Name:        "API",
			Short:       "🔑",
			Description: "Price data API plans and access",
			Link:        "/api-plans",
			Handle:      (*site).APIPlans,
			Page:        "api-plans.html",
			// The handoffs are reached from the plans page, never from the navbar.
			SubPages: []NavElem{
				{Name: "APITrial", Link: "/api-trial", ShouldHide: func(*site) bool { return true }},
				{Name: "APILogin", Link: "/api-login", ShouldHide: func(*site) bool { return true }},
			},
		},
		"Admin": {
			Name:        "Admin",
			Short:       "❌",
			Description: "Restricted control panel",
			Link:        "/admin",
			Handle:      (*site).Admin,
			Page:        "admin.html",

			CanPOST:        true,
			AlwaysOnForDev: true,
		},
	}
}

type PageVars struct {
	Pagination
	// Each page's own fields: only that page fills them, and only its
	// templates read them.
	AdminVars
	NewsVars
	SearchVars
	UploadVars

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

	Title          string
	ErrorMessage   string
	WarningMessage string
	InfoMessage    string

	SearchQuery string
	Metadata    map[string]GenericCard
	HasSettings bool
	ShowUpsell  bool

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

	// The switch between the three readings of a sealed product's contents,
	// nil unless the search is one of them over a product that has all three
	Contents *ContentsViews
	// Which reading a product's link opens, from the reader's settings
	SealedContents string

	ScraperShort string

	Arb             []Arbitrage
	DirectStockNote string
	ArbitOptKeys    []string
	ArbitOptConfig  map[string]FilterOpt
	ArbitFilters    map[string]bool
	SortOption      string
	GlobalMode      bool
	ReverseMode     bool

	Page               string
	Subtitle           string
	Cards              []GenericCard
	SortDir            string
	Editions           []string
	FlatEditions       []FlatEditionEntry
	Rarities           []string
	CardHashes         []string
	EditionsMap        map[string]EditionEntry
	EditionsCategories []string
	EditionsByCategory map[string][]EditionEntry
	PickerID           string

	CanFilterByPrice bool

	Sleepers       map[string][]string
	SleepersKeys   []string
	SleepersColors []string

	LastUpdate time.Time
	Tiers      []string
	Finishes   []string

	DisableChart bool
	ChartIDsCSV  string
	IsMultiChart bool
	ModalMode    bool

	EditionSort []string
	EditionList map[string][]EditionEntry
	IsSealed    bool
	TotalSets   int
	TotalCards  int
	TotalUnique int

	SellerKeys      []string
	VendorKeys      []string
	ModalSellerKeys []string
	ModalVendorKeys []string

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
