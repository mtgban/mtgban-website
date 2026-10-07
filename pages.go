package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
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

	// The settings modal tab this page opens on: search, upload, arbit,
	// global, reverse, news or sleep. Empty for a page with no settings of its own.
	SettingsTab string
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
			SettingsTab: "search",
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
					SettingsTab: "search",
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
			SettingsTab: "news",
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
					SettingsTab: "news",
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
			SettingsTab: "sleep",
		},
		"Upload": {
			Name:        "Upload",
			Short:       "🚢",
			Description: "Bulk price your collection",
			Link:        "/upload",
			Handle:      (*site).Upload,
			Page:        "upload.html",
			SettingsTab: "upload",
			CanPOST:     true,
		},
		"Global": {
			Name:        "Global",
			Short:       "🌍",
			Description: "Cross-region price view",
			Link:        "/global",
			Handle:      (*site).Global,
			Page:        "arbit.html",
			SettingsTab: "global",
		},
		"Arbit": {
			Name:        "Arbitrage",
			Short:       "📈",
			Description: "Buy low, sell high spreads",
			Link:        "/arbit",
			Handle:      (*site).Arbit,
			Page:        "arbit.html",
			SettingsTab: "arbit",
		},
		"Reverse": {
			Name:        "Reverse",
			Short:       "📉",
			Description: "Reverse-direction arbitrage",
			Link:        "/reverse",
			Handle:      (*site).Reverse,
			Page:        "arbit.html",
			SettingsTab: "reverse",
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
	ArbitVars
	NewsVars
	SearchVars
	SleepVars
	UploadVars

	Nav     []NavElem
	UserNav *NavElem

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

	Metadata   cardMetadata
	ShowUpsell bool

	// SettingsTab is the modal tab the gear opens on this page
	SettingsTab string

	PopularSearches []PopularSearch
	Changelog       []changelogGroup
	ChangelogError  string

	CanShowAll       bool
	CleanSearchQuery string

	// Which reading a product's link opens, from the reader's settings
	SealedContents string

	ScraperShort string

	Arb         []Arbitrage
	SortOption  string
	ReverseMode bool

	Page       string
	Subtitle   string
	Cards      []GenericCard
	SortDir    string
	Editions   []string
	CardHashes []string

	CanFilterByPrice bool

	LastUpdate time.Time
	Tiers      []string

	DisableChart bool
	ChartIDsCSV  string
	ModalMode    bool

	SellerKeys []string
	VendorKeys []string

	// Price-movers screener payload (nil on non-screener pages).
	Screener *ScreenerVars

	// API plans page payload (nil elsewhere)
	API *APIPlansVars

	// Alerts page payload (nil elsewhere)
	AlertsPage *AlertsPageVars
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
	}
	// Allocate a new navigation bar
	pageVars.Nav = make([]NavElem, len(DefaultNav))
	copy(pageVars.Nav, DefaultNav)

	// Enable buttons according to the enabled features
	for _, feat := range OrderNav {
		if !navOffers(s, sigParams, feat) {
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
	pageVars.SettingsTab = pageVars.Nav[mainNavIndex].SettingsTab

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

	pageVars.UserNav = &NavElem{Short: user}
	return pageVars
}

// navOffers reports whether the navbar offers the page feat to the reader
// signed with sigParams: an open page, a development build, or a grant on a
// signature that has not expired, and never a page the site hides or the
// registry lacks.
func navOffers(s *site, sigParams url.Values, feat string) bool {
	nav, found := ExtraNavs[feat]
	if !found {
		return false
	}

	expires, _ := strconv.ParseInt(sigParams.Get("Expires"), 10, 64)
	_, noAuth := ACL()["Any"][feat]
	validSig := expires > time.Now().Unix()
	devMode := DevMode && !SigCheck
	alwaysOnDev := DevMode && nav.AlwaysOnForDev
	if !validSig && !devMode && !noAuth {
		return false
	}

	allowed := devMode || noAuth || alwaysOnDev
	if !allowed {
		allowed, _ = strconv.ParseBool(sigParams.Get(feat))
	}

	if !allowed {
		return false
	}

	// A hidden section takes its subpages with it: they are reached
	// through it, and half a section is worse than none.
	return nav.ShouldHide == nil || !nav.ShouldHide(s)
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

	// Every desktop page carries the settings modal's shell; its body is
	// fetched from /api/settings/modal on open
	if !isMobile {
		files = append(files, "templates/partials/settings-modal.html")
		if name == "admin.html" {
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
		files = append(files,
			"templates/partials/guide-overview.html",
			"templates/partials/guide-palette.html",
			"templates/partials/guide-syntax.html",
			"templates/partials/guide-api.html",
			"templates/partials/guide-faq.html",
		)
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

	baseName, files := settingsBodyFiles()
	t, err := tmplparse.ParseFiles(baseName, files, funcMap)
	if err != nil {
		return nil, fmt.Errorf("parsing settings body: %w", err)
	}
	cache[settingsBodyKey] = t

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
