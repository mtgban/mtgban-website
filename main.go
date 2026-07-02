package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	"database/sql"

	"github.com/NYTimes/gziphandler"
	"github.com/hashicorp/go-cleanhttp"
	_ "github.com/lib/pq"
	"github.com/mtgban/mtgban-website/observability"
	"github.com/mtgban/mtgban-website/timeseries"
	"github.com/mtgban/mtgban-website/userstate"

	"github.com/leemcloughlin/logfile"
	"golang.org/x/oauth2/google"
	"gopkg.in/Iwark/spreadsheet.v2"
	"gopkg.in/robfig/cron.v2"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/simplecloud"

	_ "net/http/pprof"
)

// UsageDashboard holds the telemetry aggregates rendered on /admin?page=usage.
type UsageDashboard struct {
	Since       time.Time
	IncludeBots bool
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

	PatreonIds   map[string]string
	PatreonURL   string
	PatreonLogin bool
	Hash         string

	IsMobile bool

	Embed struct {
		OEmbedURL    string
		PageURL      string
		Title        string
		Contents     string
		ImageURL     string
		ImageCropURL string
		Description  string
		RetailPrice  float64
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
	SearchSort     string
	CondKeys       []string
	FoundSellers   map[string]map[string][]SearchEntry
	FoundVendors   map[string]map[string][]SearchEntry
	Metadata       map[string]GenericCard
	PromoTags      []string
	SetKeyrunes    map[string]string
	NoSort         bool
	NoSettings     bool
	HasSettings    bool
	HasAvailable   bool
	CardBackURL    string
	ShowUpsell     bool

	PopularSearches []PopularSearch

	CanShowAll         bool
	CleanSearchQuery   string
	CheckpointsText    string
	KeyOverridesText   string
	OverrideStores     []string
	OverrideFixStore   string
	OverrideFixKind    string
	OverrideWrongCard  *OverrideCard
	OverrideCandidates []OverrideCard
	CanFixSearch       bool

	// Suggestions shown when a search returns no results
	DidYouMean  string
	AltSearches []AltSearch

	ScraperShort   string
	HasAffiliate   bool
	CanDownloadCSV bool

	Arb            []Arbitrage
	ArbitOptKeys   []string
	ArbitOptConfig map[string]FilterOpt
	ArbitFilters   map[string]bool
	ArbitOptTests  map[string]bool
	SortOption     string
	GlobalMode     bool
	ReverseMode    bool
	DefaultTab     string
	DefaultView    string

	Page               string
	Subtitle           string
	ToC                []NewspaperPage
	Headings           []Heading
	Cards              []GenericCard
	Table              []NewspaperResult
	IsOneDay           bool
	CanSwitchDay       bool
	SortDir            string
	LargeTable         bool
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

	CanFilterByPrice bool
	FilterMinPrice   float64
	FilterMaxPrice   float64

	CanFilterByPercentage bool
	FilterMinPercChange   float64
	FilterMaxPercChange   float64

	Sleepers       map[string][]string
	SleepersKeys   []string
	SleepersColors []string

	Headers      [][]string
	Tables       [][][]string
	LastUpdate   time.Time
	LastNews     time.Time
	LastStash    time.Time
	CurrentTime  time.Time
	Uptime       string
	DiskStatus   string
	MemoryStatus string
	LatestHash   string
	Tiers        []string
	Finishes     []string

	SelectableField bool
	DisableLinks    bool

	DisableChart    bool
	MaxLookbackDays int
	AxisLabels      []string
	Datasets        []Dataset
	Checkpoints     []ChartCheckpoint
	ChartID         string
	Alternative     string
	StocksURL       string
	AltEtchedId     string

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

	// Additional sources for index keys if needed
	AltKeys              []string
	SellerKeys           []string
	VendorKeys           []string
	SealedSellerKeys     []string
	SealedVendorKeys     []string
	ModalSellerKeys      []string
	ModalVendorKeys      []string
	UploadEntries        []UploadEntry
	IsBuylist            bool
	TotalEntries         map[string]float64
	EnabledSellers       []string
	EnabledVendors       []string
	EnabledSealedSellers []string
	EnabledSealedVendors []string
	CanBuylist           bool
	CanChangeStores      bool
	CanUploadCustom      bool
	RemoteLinkURL        string
	TotalQuantity        int
	Optimized            map[string][]OptimizedUploadEntry
	IgnorePrices         bool
	OptimizedTotals      map[string]float64
	HighestTotal         float64
	MissingCounts        map[string]int
	MissingPrices        map[string]float64
	ResultPrices         map[string]map[string]float64
	UploadQuery          string
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

	// Price-movers screener payload (nil on non-screener pages).
	Screener *ScreenerVars
}

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
	Handle func(w http.ResponseWriter, r *http.Request)

	// Which page to render
	Page string

	// Whether this tab should always be enabled in DevMode
	AlwaysOnForDev bool

	// Enable page when running offline
	AllowOffline bool

	// Allow to receive POST requests
	CanPOST bool

	// Alternative endpoints connected to this handler
	SubPages []NavElem

	// Condition upon which the page should not be made visible
	ShouldHide func() bool

	// True for pages whose settings modal has bindings (mirrors
	// PAGE_BINDINGS in js/settings.js). Used by the navbar inline
	// script to pre-resolve the gear button's enabled state so it
	// doesn't transition from is-disabled → enabled at load time.
	HasSettings bool
}

var DefaultNav = []NavElem{
	NavElem{
		Name:  "Home",
		Short: "🏡",
		Link:  "/",
		Page:  "home.html",
	},
}

// List of keys that may be present or not, and when present they are
// guaranteed not to be user-editable)
var OptionalFields = []string{
	"UserName",
	"UserEmail",
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
	"AnyEnabled",
	"AnyExperimentsEnabled",
	"AnySpread",
	"APImode",
	"SleepersCYOA",
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
			Handle:      Search,
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
					ShouldHide: func() bool {
						return len(mtgmatcher.GetSealedUUIDs()) == 0
					},
				},
			},
			AllowOffline: true,
		},
		"Newspaper": {
			Name:        "Newspaper",
			Short:       "🗞️",
			Description: "Market movers & recent activity",
			Link:        "/newspaper",
			Handle:      Newspaper,
			Page:        "news.html",
			HasSettings: true,
			SubPages: []NavElem{
				{
					Name:        "TCG Syp List",
					Short:       "📋",
					Description: "Cards TCGplayer wants now",
					Link:        "/newspaper?page=syp",
					HasSettings: true,
					ShouldHide: func() bool {
						_, err := findVendorBuylist("SYP")
						return err != nil
					},
				},
			},
		},
		"Screener": {
			Name:        "Screener",
			Short:       "🔎",
			Description: "Find cards by price move over time",
			Link:        "/screener",
			Handle:      Screener,
			Page:        "screener.html",
		},
		"Sleepers": {
			Name:        "Sleepers",
			Short:       "💤",
			Description: "Under-the-radar picks",
			Link:        "/sleepers",
			Handle:      Sleepers,
			Page:        "sleep.html",
			HasSettings: true,
		},
		"Upload": {
			Name:        "Upload",
			Short:       "🚢",
			Description: "Bulk price your collection",
			Link:        "/upload",
			Handle:      Upload,
			Page:        "upload.html",
			HasSettings: true,
			CanPOST:     true,
		},
		"Global": {
			Name:        "Global",
			Short:       "🌍",
			Description: "Cross-region price view",
			Link:        "/global",
			Handle:      Global,
			Page:        "arbit.html",
			HasSettings: true,
		},
		"Arbit": {
			Name:        "Arbitrage",
			Short:       "📈",
			Description: "Buy low, sell high spreads",
			Link:        "/arbit",
			Handle:      Arbit,
			Page:        "arbit.html",
			HasSettings: true,
		},
		"Reverse": {
			Name:        "Reverse",
			Short:       "📉",
			Description: "Reverse-direction arbitrage",
			Link:        "/reverse",
			Handle:      Reverse,
			Page:        "arbit.html",
			HasSettings: true,
		},
		"Admin": {
			Name:        "Admin",
			Short:       "❌",
			Description: "Restricted control panel",
			Link:        "/admin",
			Handle:      Admin,
			Page:        "admin.html",

			CanPOST:        true,
			AlwaysOnForDev: true,
			AllowOffline:   true,
		},
	}
}

var Config ConfigType

type ConfigType struct {
	OfflineKey    string `json:"offline_key,omitempty"`
	Port          string `json:"port"`
	DatastorePath string `json:"datastore_path"`
	Datastore     struct {
		BackupPath      string `json:"backup_path"`
		BucketAccessKey string `json:"bucket_access_key"`
		BucketSecretKey string `json:"bucket_access_secret"`
		CheckpointsPath string `json:"checkpoints_path"`
	} `json:"datastore"`
	Game                   string             `json:"game"`
	CardBackImage          string             `json:"card_back_image"`
	ScraperConfig          ScraperConfig      `json:"scraper_config"`
	TimeseriesConfig       TimeseriesConfig   `json:"timeseries_config"`
	NewNewspaperConfigLine string             `json:"new_newspaper_config_line"`
	DiscordHook            string             `json:"discord_hook"`
	DiscordNotifHook       string             `json:"discord_notif_hook"`
	DiscordAPINotifHook    string             `json:"discord_api_notif_hook"`
	DiscordInviteLink      string             `json:"discord_invite_link"`
	Affiliate              map[string]string  `json:"affiliate"`
	AffiliatesList         []string           `json:"affiliates_list"`
	AffiliatesBuylistList  []string           `json:"affiliates_buylist_list"`
	Api                    map[string]string  `json:"api"`
	ApiDemoStores          []string           `json:"api_demo_stores"`
	DiscordToken           string             `json:"discord_token"`
	ArbitDefaultSellers    []string           `json:"arbit_default_sellers"`
	ArbitBlockVendors      []string           `json:"arbit_block_vendors"`
	SearchRetailBlockList  []string           `json:"search_block_list"`
	SearchBuylistBlockList []string           `json:"search_buylist_block_list"`
	SleepersBlockList      []string           `json:"sleepers_block_list"`
	UploadSealedBlockList  []string           `json:"upload_sealed_block_list"`
	GlobalAllowList        []string           `json:"global_allow_list"`
	GlobalProbeList        []string           `json:"global_probe_list"`
	Patreon                PatreonConfig      `json:"patreon"`
	ApiUserSecrets         map[string]string  `json:"api_user_secrets"`
	GoogleCredentials      string             `json:"google_credentials"`
	BuylistMarketCredit    map[string]float64 `json:"buylist_market_credit"`

	PopularSearches []PopularSearchEntry `json:"popular_searches"`

	ACL map[string]map[string]map[string]string `json:"acl"`

	Uploader map[string]string `json:"uploader"`

	// The location of the configuation file
	sourcePath string

	SqlConfig           *timeseries.SqlConfig `json:"sql_config"`
	UserStateConfig     *userstate.SqlConfig  `json:"user_state_config"`
	ObservabilityConfig *timeseries.SqlConfig `json:"observability_config"`
}

var DevMode bool
var SigCheck bool
var SkipPrices bool
var SkipNewspaper bool
var LogDir string

// Timestamps written by background goroutines (datastore reload, stash
// cron, newspaper cron) and read by the admin dashboard. Held behind
// atomic.Pointer so concurrent reads can't observe a torn time.Time
// (it's a 24-byte struct, not a single word).
var (
	lastDatastoreUpdatePtr atomic.Pointer[time.Time]
	lastStashUpdatePtr     atomic.Pointer[time.Time]
	lastNewspaperUpdatePtr atomic.Pointer[time.Time]
)

// SetLastDatastoreUpdate / SetLastStashUpdate / SetLastNewspaperUpdate
// publish a new timestamp atomically.
func SetLastDatastoreUpdate(t time.Time) { lastDatastoreUpdatePtr.Store(&t) }
func SetLastStashUpdate(t time.Time)     { lastStashUpdatePtr.Store(&t) }
func SetLastNewspaperUpdate(t time.Time) { lastNewspaperUpdatePtr.Store(&t) }

// GetLastDatastoreUpdate / GetLastStashUpdate / GetLastNewspaperUpdate
// return the most recent timestamp, or the zero time if none has been
// published yet.
func GetLastDatastoreUpdate() time.Time { return loadTime(lastDatastoreUpdatePtr.Load()) }
func GetLastStashUpdate() time.Time     { return loadTime(lastStashUpdatePtr.Load()) }
func GetLastNewspaperUpdate() time.Time { return loadTime(lastNewspaperUpdatePtr.Load()) }

func loadTime(p *time.Time) time.Time {
	if p == nil {
		return time.Time{}
	}
	return *p
}

var NewNewspaperDB *sql.DB

var PricesArchiveDB *timeseries.Client

var UserStateDB *userstate.Client

var ObservabilityDB *observability.Client
var ObservabilityRecorder *observability.Recorder

var GoogleDocsClient *http.Client

var ConfigBucket simplecloud.ReadWriter

// External address from which server is reachable, loaded at the first request
var ServerURL string

const (
	DefaultServerPort    = "8080"
	DefaultConfigPath    = "config.json"
	DefaultSecret        = "NotVerySecret!"
	DefaultGame          = "magic"
	DefaultServerURL     = "http://www.mtgban.com"
	DefaultDatastorePath = "AllPrintings.json.xz"

	DefaultSignatureDuration = 11 * 24 * time.Hour
)

// Cache for a week as these assets either never change or have a snapshot key in the URL
func ServeFile(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=86400")
	http.ServeFile(w, r, r.URL.Path[1:])
}

func genPageNav(activeTab, sig string) PageVars {
	exp := GetParamFromSig(sig, "Expires")
	expires, _ := strconv.ParseInt(exp, 10, 64)
	msg := ""
	showPatreonLogin := false
	if sig != "" {
		if expires < time.Now().Unix() {
			msg = ErrMsgExpired
		}
	} else {
		showPatreonLogin = true
	}

	// These values need to be set for every rendered page
	// In particular the Patreon variables are needed because the signature
	// could expire in any page, and the button url needs these parameters
	pageVars := PageVars{
		Title:        "BAN " + activeTab,
		ErrorMessage: msg,

		PatreonIds:   Config.Patreon.Client,
		PatreonURL:   ServerURL + "/auth",
		PatreonLogin: showPatreonLogin,
		Hash:         BuildCommit,
	}

	if Config.Game != DefaultGame {
		// Append which game this site is for
		pageVars.Title += " - " + mtgmatcher.Title(Config.Game)

		// Charts are available only for one game
		pageVars.DisableChart = true
	}
	if Config.OfflineKey != "" {
		pageVars.DisableChart = true
	}

	// Set card back
	pageVars.CardBackURL = Config.CardBackImage

	// Allocate a new navigation bar
	pageVars.Nav = make([]NavElem, len(DefaultNav))
	copy(pageVars.Nav, DefaultNav)

	// Enable buttons according to the enabled features
	for _, feat := range OrderNav {
		_, noAuth := Config.ACL["Any"][feat]
		validSig := expires > time.Now().Unix()
		devMode := DevMode && !SigCheck
		alwaysOnDev := DevMode && ExtraNavs[feat].AlwaysOnForDev
		offline := Config.OfflineKey != "" && ExtraNavs[feat].AllowOffline

		if !validSig && !devMode && !noAuth {
			continue
		}

		allowed := devMode || noAuth || alwaysOnDev || offline
		if !allowed {
			param := GetParamFromSig(sig, feat)
			allowed, _ = strconv.ParseBool(param)
		}

		if !allowed {
			continue
		}

		if Config.OfflineKey != "" && !ExtraNavs[feat].AllowOffline {
			continue
		}

		pageVars.Nav = append(pageVars.Nav, *ExtraNavs[feat])
		for _, subPage := range ExtraNavs[feat].SubPages {
			if subPage.ShouldHide != nil && subPage.ShouldHide() {
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

	// Add user information if needed, or public
	user := GetParamFromSig(sig, "UserEmail")
	if user == "" {
		if !showPatreonLogin {
			user = "Anonymous"
		}
		_, noAuth := Config.ACL["Any"][pageVars.Nav[mainNavIndex].Name]
		if noAuth {
			user = ""
		}
	}

	if Config.OfflineKey != "" {
		user = "Offline Mode"
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

func preloadConfig(configPath string) error {
	if configPath == "" {
		configPath = os.Getenv("BAN_CONFIG_PATH")
	}
	if configPath == "" {
		configPath = DefaultConfigPath
	}

	// Save source, so we can reload later
	Config.sourcePath = configPath

	u, err := url.Parse(Config.sourcePath)
	if err != nil {
		return err
	}

	var bucket simplecloud.ReadWriter

	switch u.Scheme {
	case "":
		bucket = &simplecloud.FileBucket{}
	case "b2":
		bucket, err = simplecloud.NewB2Client(context.Background(), os.Getenv("BAN_CONFIG_KEY"), os.Getenv("BAN_CONFIG_SECRET"), u.Host)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported path scheme %s", u.Scheme)
	}

	ConfigBucket = bucket
	return nil
}

func loadVars(port, datastorePath, offlineKey string) error {
	// Preload
	Config.Game = DefaultGame
	Config.OfflineKey = offlineKey

	reader, err := simplecloud.InitReader(context.Background(), ConfigBucket, Config.sourcePath)
	if err != nil {
		return err
	}
	defer reader.Close()

	// Load from config file
	err = json.NewDecoder(reader).Decode(&Config)
	if err != nil && !DevMode {
		return err
	}

	// The -port and -ds flags, when provided, override whatever the config
	// file set. This must happen after the decode above, which would otherwise
	// clobber the flag values with the config's fields (breaking blue-green
	// deploys that run instances on distinct ports).
	if port != "" {
		Config.Port = port
	}
	if datastorePath != "" {
		Config.DatastorePath = datastorePath
	}

	// Ensure needed defaults
	if Config.Port == "" {
		log.Println("Server port not configured, listening on", DefaultServerPort)
		Config.Port = DefaultServerPort
	}
	if Config.Game == "" {
		log.Println("Game not configured, defaulting to", DefaultGame)
		Config.Game = DefaultGame
	}
	if Config.DatastorePath == "" {
		log.Println("Datastore path not configured, using", DefaultDatastorePath)
		Config.DatastorePath = DefaultDatastorePath
	}

	// Load from env
	v := os.Getenv("BAN_SECRET")
	if v == "" {
		log.Printf("BAN_SECRET not set, using a default one")
		os.Setenv("BAN_SECRET", DefaultSecret)
	}

	return nil
}

func openDBs() (err error) {
	if Config.SqlConfig == nil {
		log.Println("no SQL configuration set, Charts won't be available")
	} else {
		PricesArchiveDB, err = timeseries.NewClient(*Config.SqlConfig)
		if err != nil {
			log.Println("error creating a SQL client:", err)
			return err
		}
	}

	if Config.UserStateConfig == nil {
		log.Println("no user_state configuration set, cross-device sync won't be available")
	} else {
		UserStateDB, err = userstate.NewClient(*Config.UserStateConfig)
		if err != nil {
			log.Println("error creating a user_state SQL client:", err)
			return err
		}
	}

	if Config.ObservabilityConfig == nil {
		log.Println("no observability configuration set, telemetry won't be recorded")
	} else if obsDB, oerr := observability.NewClient(*Config.ObservabilityConfig); oerr != nil {
		log.Println("observability disabled, init failed:", oerr)
	} else {
		ObservabilityDB = obsDB
		ObservabilityRecorder = observability.NewRecorder(obsDB)
		log.Println("observability telemetry enabled")
	}

	if Config.NewNewspaperConfigLine == "" {
		log.Println("no DB address set, Newspaper won't be loaded")
	} else {
		NewNewspaperDB, err = sql.Open("postgres", Config.NewNewspaperConfigLine)
		if err != nil {
			return err
		}
	}

	return nil
}

func loadGoogleCredentials() (*http.Client, error) {
	if Config.GoogleCredentials == "" {
		log.Println("no google credentials, skipping")
		return nil, nil
	}

	u, err := url.Parse(Config.GoogleCredentials)
	if err != nil {
		return nil, err
	}

	reader, err := simplecloud.InitReader(context.Background(), ConfigBucket, u.Path)
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	conf, err := google.JWTConfigFromJSON(data, spreadsheet.Scope)
	if err != nil {
		return nil, err
	}

	return conf.Client(context.Background()), nil
}

func loadDatastore(ds string) error {
	log.Println("Loading datastore from", ds)

	u, err := url.Parse(ds)
	if err != nil {
		return err
	}

	var bucket simplecloud.Reader

	switch u.Scheme {
	case "":
		bucket = &simplecloud.FileBucket{}
	case "b2":
		b2Bucket, err := simplecloud.NewB2Client(context.Background(), Config.Datastore.BucketAccessKey, Config.Datastore.BucketSecretKey, u.Host)
		if err != nil {
			return err
		}
		b2Bucket.ConcurrentDownloads = 20

		bucket = b2Bucket
	case "http", "https":
		httpBucket, err := simplecloud.NewHTTPBucket(cleanhttp.DefaultClient(), ds)
		if err != nil {
			return err
		}

		bucket = httpBucket
	default:
		return fmt.Errorf("unsupported path scheme %s", u.Scheme)
	}

	reader, err := simplecloud.InitReader(context.Background(), bucket, ds)
	if err != nil {
		return err
	}
	defer reader.Close()

	err = mtgmatcher.LoadDatastore(reader)
	if err != nil {
		return err
	}

	ServerNotify("init", "Datastore installed")
	SetLastDatastoreUpdate(time.Now())
	go updateStaticData()
	go cacheNewspaper()
	go buildPaletteSetsCache()

	return nil
}

func main() {
	configFilePath := flag.String("cfg", "", "Load configuration file")
	port := flag.String("port", "", "Override server port")
	datastore := flag.String("ds", "", "Override datastore path")

	flag.BoolVar(&DevMode, "dev", false, "Enable developer mode")
	sigCheck := flag.Bool("sig", false, "Enable signature verification")
	flag.BoolVar(&SkipPrices, "noload", false, "Do not load price data")
	flag.BoolVar(&SkipNewspaper, "nonews", false, "Do not load newspaper data")
	flag.StringVar(&LogDir, "log", "logs", "Directory for scrapers logs")
	offline := flag.String("offline", "", "API key to run in offline mode")

	flag.Parse()

	// Initial state
	SigCheck = true
	if DevMode {
		SigCheck = *sigCheck
	}

	// load necessary environmental variables
	err := preloadConfig(*configFilePath)
	if err != nil {
		log.Fatalln("unable to preload config file:", err)
	}
	err = loadVars(*port, *datastore, *offline)
	if err != nil {
		if DevMode || Config.OfflineKey != "" {
			log.Println("unable to load config file:", Config.sourcePath, "- using safe defaults")
		} else {
			log.Fatalln("unable to load config file:", err)
		}
	}

	// Load the per-seller UUID overrides applied when scrapers (re)load.
	err = loadKeyOverrides()
	if err != nil {
		log.Println("unable to load key overrides:", err)
	}

	_, err = os.Stat(LogDir)
	if errors.Is(err, os.ErrNotExist) {
		err = os.MkdirAll(LogDir, 0700)
	}
	if err != nil {
		log.Fatalln("unable to create necessary folders", err)
	}
	LogPages = map[string]*log.Logger{}

	GoogleDocsClient, err = loadGoogleCredentials()
	if err != nil {
		log.Fatalln("error creating a Google client:", err)
	}

	err = openDBs()
	if err != nil {
		log.Fatalln("error opening databases:", err)
	}

	err = reloadCheckpoints()
	if err != nil {
		log.Printf("checkpoints: initial load failed: %v", err)
	}

	// Parse templates once in production
	templateCache, err = buildTemplateCache()
	if err != nil {
		log.Fatalln("template cache:", err)
	}

	// load website up
	go func() {
		err := loadDatastore(Config.DatastorePath)
		if err != nil {
			log.Fatalln("error loading datastore:", err)
		}
	}()

	if SkipPrices {
		log.Println("no prices loaded as requested")
	} else if Config.OfflineKey != "" {
		go func() {
			log.Println("Loading scrapers from API")
			err := loadScrapersAPI(context.Background(), Config.OfflineKey)
			if err != nil {
				log.Fatalln("error loading scrapers:", err)
			}

			// Update set values after loading prices
			runSealedAnalysis()
		}()
	} else {
		go func() {
			log.Println("Loading", len(Config.ScraperConfig.Config), "Scrapers")
			err := loadScrapersNG(Config.ScraperConfig)
			if err != nil {
				log.Fatalln("error loading scrapers:", err)
			}

			// Update set values after loading prices
			runSealedAnalysis()
		}()
	}

	if !DevMode {
		// Set up new refreshes as needed
		c := cron.New()

		// Take a snapshot twice a day
		c.AddFunc("0 */12 * * *", stashInTimeseries)

		// Update set values with new prices
		c.AddFunc("30 */12 * * *", runSealedAnalysis)

		// Reload DB Newspaper every 3 hours
		c.AddFunc("33 */3 * * *", cacheNewspaper)

		c.Start()
	}

	err = setupDiscord()
	if err != nil {
		log.Println("Error connecting to discord", err)
	}

	// Serve everything in known folders as a file
	http.HandleFunc("/css/", ServeFile)
	http.HandleFunc("/img/", ServeFile)
	http.HandleFunc("/js/", ServeFile)
	http.HandleFunc("/favicon.ico", ServeFile)

	// custom redirector
	http.HandleFunc("/go/", Redirect)
	http.HandleFunc("/http:/", UploadURLRedirect)
	http.HandleFunc("/https:/", UploadURLRedirect)
	http.HandleFunc("/random", RandomSearch)
	http.HandleFunc("/randomsealed", RandomSealedSearch)
	http.HandleFunc("/discord", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, Config.DiscordInviteLink, http.StatusFound)
	})

	// when navigating to /home it should serve the home page
	http.Handle("/", noSigning(http.HandlerFunc(Home)))

	// Public guide page
	http.Handle("/guide", noSigning(http.HandlerFunc(Guide)))

	// Public privacy policy (cookie + Amazon Associates disclosures)
	http.Handle("/privacy", noSigning(http.HandlerFunc(Privacy)))

	// Mobile/desktop view toggle
	http.HandleFunc("/toggle-mobile", toggleMobileView)

	for _, nav := range ExtraNavs {
		if Config.OfflineKey != "" && !nav.AllowOffline {
			continue
		}

		// Set up logging
		logFile, err := logfile.New(&logfile.LogFile{
			FileName:    path.Join(LogDir, nav.Name+".log"),
			MaxSize:     500 * 1024,
			Flags:       logfile.FileOnly,
			OldVersions: 2,
		})
		if err != nil {
			log.Printf("Failed to create logFile for %s: %s", nav.Name, err)
			LogPages[nav.Name] = log.New(os.Stderr, "", log.LstdFlags)
		} else {
			LogPages[nav.Name] = log.New(logFile, "", log.LstdFlags)
		}

		// Set up the handler
		handler := enforceSigning(http.HandlerFunc(nav.Handle))
		http.Handle(nav.Link, handler)

		// Add any additional endpoints to it
		for _, subPage := range nav.SubPages {
			http.Handle(subPage.Link, handler)
		}
	}

	http.Handle("/search/oembed", noSigning(http.HandlerFunc(Search)))
	http.Handle("/api/mtgban/search/", enforceAPISigning(http.HandlerFunc(SearchAPI)))
	http.Handle("/api/mtgban/", enforceAPISigning(http.HandlerFunc(PriceAPI)))
	http.Handle("/api/tcgplayer/", enforceSigning(http.HandlerFunc(TCGHandler)))
	http.Handle("/api/cardmarket/", enforceSigning(http.HandlerFunc(MKMHandler)))
	http.Handle("/api/search/", enforceSigning(http.HandlerFunc(SearchAPI)))
	http.Handle("/api/suggest", noSigning(http.HandlerFunc(SuggestAPI)))
	http.Handle("/api/chart/", noSigning(http.HandlerFunc(ChartDataAPI)))
	http.Handle("/api/prices/", enforceSigning(http.HandlerFunc(BatchPricesAPI)))
	http.Handle("/api/userstate/", noSigning(gziphandler.GzipHandler(http.HandlerFunc(UserStateAPI))))
	http.Handle("/api/opensearch.xml", noSigning(http.HandlerFunc(OpenSearchDesc)))
	http.Handle("/api/load/datastore", noSigning(http.HandlerFunc(LoadDatastoreFromCloud)))
	http.Handle("/api/load/", enforceAPISigning(http.HandlerFunc(LoadFromCloud)))
	http.Handle("/api/palette/card/", noSigning(http.HandlerFunc(PaletteCardMeta)))
	http.Handle("/api/palette/sealed/", noSigning(http.HandlerFunc(PaletteSealed)))
	http.Handle("/api/palette/sets.json", noSigning(http.HandlerFunc(PaletteSets)))
	http.Handle("/api/palette/stores.json", noSigning(http.HandlerFunc(PaletteStores)))

	http.HandleFunc("/auth", Auth)

	// /healthz: returns 200 only if dependencies are OK.
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		uuids := len(mtgmatcher.GetUUIDs())
		sellers, vendors := len(GetSellers()), len(GetVendors())
		if uuids == 0 || sellers == 0 || vendors == 0 {
			log.Printf("healthz: not ready (uuids=%d, sellers=%d, vendors=%d)", uuids, sellers, vendors)
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	srv := &http.Server{
		Addr: ":" + Config.Port,
	}

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		err := srv.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()

	<-done

	// Close any zombie connection and perform any extra cleanup
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer func() {
		ServerNotify("shutdown", "Server cleaning up...")
		ObservabilityRecorder.Close()
		cleanupDiscord()
		cancel()
	}()

	err = srv.Shutdown(ctx)
	if err != nil {
		ServerNotify("shutdown", "Server shutdown failed: "+err.Error())
		return
	}
	ServerNotify("shutdown", "Server shutdown correctly")
}

// templateCache holds pre-parsed templates keyed by their base name.
// Populated at startup in production; nil in DevMode (re-parsed per request).
var templateCache map[string]*template.Template

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

	// Include settings-modal partial only for desktop pages that define a "settings-content" block.
	if !isMobile {
		switch name {
		case "search.html", "arbit.html":
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
	if name == "guide.html" {
		files = append(files, "templates/partials/guide-faq.html")
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
			t, err := template.New(baseName).Funcs(funcMap).ParseFiles(files...)
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
		t, err := template.New(baseName).Funcs(funcMap).ParseFiles(files...)
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
	t, found := templateCache[key]
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
