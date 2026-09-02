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
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"database/sql"

	_ "github.com/lib/pq"
	"github.com/mtgban/mtgban-website/internal/offline"
	"github.com/mtgban/mtgban-website/internal/offlineapi"
	"github.com/mtgban/mtgban-website/internal/palette"
	"github.com/mtgban/mtgban-website/internal/suggest"
	"github.com/mtgban/mtgban-website/internal/tmplparse"
	"github.com/mtgban/mtgban-website/observability"
	"github.com/mtgban/mtgban-website/tcgcsv"
	"github.com/mtgban/mtgban-website/tcgcsvd"
	"github.com/mtgban/mtgban-website/timeseries"
	"github.com/mtgban/mtgban-website/userstate"

	"github.com/leemcloughlin/logfile"
	"golang.org/x/oauth2/google"
	"gopkg.in/Iwark/spreadsheet.v2"
	"gopkg.in/robfig/cron.v2"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	_ "github.com/mtgban/go-mtgban/mtgmatcher/games"
	"github.com/mtgban/mtgban-website/internal/dsreload"
	"github.com/mtgban/simplecloud"

	_ "net/http/pprof"
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
	AltSearches []suggest.AltSearch

	ScraperShort   string
	HasAffiliate   bool
	CanDownloadCSV bool

	Arb                []Arbitrage
	ArbitOptKeys       []string
	ArbitOptConfig     map[string]FilterOpt
	ArbitFilters       map[string]bool
	ArbitOptTests      map[string]bool
	SortOption         string
	GlobalMode         bool
	ReverseMode        bool
	DefaultTab         string
	DefaultView        string
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
	"SearchOfflineMode",
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
			// Every page of it is built from the cached uuids, so with none
			// the section is a stack of empty tables. A game with no
			// newspaper data, or one whose database was never configured,
			// gets no entry rather than a dead end. The cron rebuilds the
			// cache every three hours, so it appears on its own once the
			// data does.
			ShouldHide: func() bool {
				return len(GetNewspaperUUIDs()) == 0
			},
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
			Name:        "Screener (Beta)",
			Short:       "🔎",
			Description: "Find cards by price movement over time",
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
	Offline struct {
		ManifestPath string `json:"manifest_path"`
		ImagesPath   string `json:"images_path"`
	} `json:"offline"`
	BucketKeys map[string]BucketKey `json:"bucket_keys"`

	Game         string `json:"game"`
	InstanceName string `json:"instance_name"`

	// FormatEvents are the game-wide chart markers no ban list reports - a
	// format launching, say. Everything else on the checkpoint timeline comes
	// from the ban list document or the set registry.
	FormatEvents           []FormatEvent      `json:"format_events,omitempty"`
	ScraperConfig          ScraperConfig      `json:"scraper_config"`
	TimeseriesConfig       TimeseriesConfig   `json:"timeseries_config"`
	DiscordHook            string             `json:"discord_hook"`
	DiscordNotifHook       string             `json:"discord_notif_hook"`
	DiscordAPINotifHook    string             `json:"discord_api_notif_hook"`
	DiscordInviteLink      string             `json:"discord_invite_link"`
	Affiliate              map[string]string  `json:"affiliate"`
	AffiliatesList         []string           `json:"affiliates_list"`
	AffiliatesBuylistList  []string           `json:"affiliates_buylist_list"`
	API                    map[string]string  `json:"api"`
	APIDemoStores          []string           `json:"api_demo_stores"`
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
	APIUserSecrets         map[string]string  `json:"api_user_secrets"`
	GoogleCredentials      string             `json:"google_credentials"`
	BuylistMarketCredit    map[string]float64 `json:"buylist_market_credit"`

	PopularSearches []PopularSearchEntry `json:"popular_searches"`

	ACL map[string]map[string]map[string]string `json:"acl"`

	Uploader map[string]string `json:"uploader"`

	SQLConfig             *timeseries.SQLConfig `json:"sql_config"`
	UserStateConfig       *userstate.SQLConfig  `json:"user_state_config"`
	ObservabilityConfig   *timeseries.SQLConfig `json:"observability_config"`
	NewNewspaperSQLConfig *timeseries.SQLConfig `json:"new_newspaper_sql_config"`

	TCGCSVConfig *tcgcsv.Config `json:"tcgcsv_config"`

	// The location of the configuation file (always last)
	sourcePath string
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

// ServerContext lives as long as this process serves and is cancelled when the
// shutdown signal arrives, at the same moment the HTTP server starts draining.
// Background work that belongs to the process rather than to a request — the
// crons, the admin buttons that hand a job to a goroutine — runs under it, so a
// stop reaches a job that is mid-crawl instead of only reaching the listener.
var ServerContext, stopServerContext = context.WithCancel(context.Background())

var NewNewspaperDB *sql.DB

var PricesArchiveDB *timeseries.Client

var UserStateDB *userstate.Client

var ObservabilityDB *observability.Client
var ObservabilityRecorder *observability.Recorder

var GoogleDocsClient *http.Client

var ConfigBucket simplecloud.ReadWriter

// Cache for offlineImagesFactory: the bucket client is reused because image requests are hot.
var (
	offlineImagesBucketMu     sync.Mutex
	offlineImagesBucketCur    simplecloud.ReadWriter
	offlineImagesBucketBase   string
	offlineImagesBucketKey    string
	offlineImagesBucketSecret string
)

func offlineImagesFactory(ctx context.Context) (simplecloud.ReadWriter, string, error) {
	base := Config.Offline.ImagesPath
	if base == "" {
		return nil, "", errors.New("offline.images_path not configured")
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, "", err
	}
	var key, secret string
	if u.Scheme == "b2" {
		key, secret = bucketCredentials(u.Host)
	}

	offlineImagesBucketMu.Lock()
	defer offlineImagesBucketMu.Unlock()
	if offlineImagesBucketCur != nil && offlineImagesBucketBase == base &&
		offlineImagesBucketKey == key && offlineImagesBucketSecret == secret {
		return offlineImagesBucketCur, base, nil
	}

	var bucket simplecloud.ReadWriter
	switch {
	// A one-letter scheme is a Windows drive path; fail loud so misconfigured
	// Windows absolute paths (broken by simplecloud v0.0.9) are caught early.
	case len(u.Scheme) == 1:
		return nil, "", errors.New("offline.images_path: Windows absolute paths are broken by simplecloud v0.0.9 (drive letter stripped); use a relative path until the upstream fix lands")
	case u.Scheme == "":
		bucket = &simplecloud.FileBucket{}
	case u.Scheme == "b2":
		bucket, err = simplecloud.NewB2Client(ctx, key, secret, u.Host)
		if err != nil {
			return nil, "", err
		}
	default:
		return nil, "", fmt.Errorf("unsupported offline images path scheme: %s", u.Scheme)
	}
	offlineImagesBucketCur, offlineImagesBucketBase = bucket, base
	offlineImagesBucketKey, offlineImagesBucketSecret = key, secret
	return bucket, base, nil
}

// offlineImagesDownloadAuth issues a B2 download authorization covering the
// mirrored image tree, along with the URL those objects hang off, so clients
// read image bytes straight from the bucket instead of through this process.
// Only a B2-backed tree can issue one; anything else has no way to hand out
// scoped, expiring read access.
func offlineImagesDownloadAuth(ctx context.Context, valid time.Duration) (string, string, time.Time, error) {
	bucket, base, err := offlineImagesFactory(ctx)
	if err != nil {
		return "", "", time.Time{}, err
	}
	b2bucket, ok := bucket.(*simplecloud.B2Bucket)
	if !ok {
		return "", "", time.Time{}, fmt.Errorf("offline: %s cannot issue download authorizations", base)
	}
	u, err := url.Parse(base)
	if err != nil {
		return "", "", time.Time{}, err
	}
	prefix := strings.Trim(u.Path, "/")
	token, err := b2bucket.Bucket.AuthToken(ctx, prefix, valid)
	if err != nil {
		return "", "", time.Time{}, err
	}
	downloadBase := strings.TrimSuffix(b2bucket.Bucket.BaseURL(), "/") + "/file/" + b2bucket.Bucket.Name()
	if prefix != "" {
		downloadBase += "/" + prefix
	}
	// B2 dates the window from when it issued the token, so this is the
	// client's cue to re-ask rather than a guarantee.
	return downloadBase, token, time.Now().Add(valid), nil
}

// offlineService wires the offline API endpoints to the live scraper state.
var offlineService = offlineapi.NewService(offlineapi.Deps{
	Allow: offlineModeAllowed,

	CanonicalSetCode: func(setCode string) (string, error) {
		set, err := mtgmatcher.GetSet(setCode)
		if err != nil {
			return "", err
		}
		return set.Code, nil
	},

	BuildSetPayload: func(setCode string, stores []string) (*offline.SetPayload, error) {
		set, err := mtgmatcher.GetSet(setCode)
		if err != nil {
			return nil, err
		}
		retail := getSellerPrices("", stores, set.Code, nil, "", true, true, false, "")
		buylist := getVendorPrices("", stores, set.Code, nil, "", true, true, false, "")
		for id, m := range getSellerPrices("", stores, set.Code, nil, "", true, true, true, "") {
			if retail[id] == nil {
				retail[id] = m
				continue
			}
			for store, entry := range m {
				retail[id][store] = entry
			}
		}
		for id, m := range getVendorPrices("", stores, set.Code, nil, "", true, true, true, "") {
			if buylist[id] == nil {
				buylist[id] = m
				continue
			}
			for store, entry := range m {
				buylist[id][store] = entry
			}
		}
		return banprice2offline(set.Code, time.Now().UTC(), retail, buylist), nil
	},

	EnabledStores: func() []string {
		var all []string
		for _, seller := range GetSellers() {
			shorthand := seller.Info().Shorthand
			if !slices.Contains(Config.SearchRetailBlockList, shorthand) && !slices.Contains(all, shorthand) {
				all = append(all, shorthand)
			}
		}
		for _, vendor := range GetVendors() {
			shorthand := vendor.Info().Shorthand
			if !slices.Contains(Config.SearchBuylistBlockList, shorthand) && !slices.Contains(all, shorthand) {
				all = append(all, shorthand)
			}
		}
		return all
	},

	Sellers: GetSellers,
	Vendors: GetVendors,

	ScraperName:       scraperName,
	CardObjectSources: cardobject2sources,

	ManifestBucket: func(ctx context.Context) (simplecloud.ReadWriter, string, error) {
		omPath := Config.Offline.ManifestPath
		if omPath == "" {
			return nil, "", errors.New("offline.manifest_path not configured")
		}
		u, err := url.Parse(omPath)
		if err != nil {
			return nil, "", err
		}
		switch {
		case u.Scheme == "" || len(u.Scheme) == 1:
			return &simplecloud.FileBucket{}, omPath, nil
		case u.Scheme == "b2":
			bucket, err := newB2ClientFor(ctx, u.Host)
			return bucket, omPath, err
		default:
			return nil, "", fmt.Errorf("unsupported offline manifest path scheme: %s", u.Scheme)
		}
	},

	ImagesManifestBucket: func(ctx context.Context) (simplecloud.ReadWriter, string, error) {
		bucket, base, err := offlineImagesFactory(ctx)
		if err != nil {
			return nil, "", err
		}
		return bucket, offlineapi.JoinBucketPath(base, "images-manifest.json"), nil
	},

	ImagesBucket: offlineImagesFactory,

	ImagesDownloadAuth: offlineImagesDownloadAuth,

	Game: func() string { return Config.Game },

	ManifestPathConfigured: func() bool { return Config.Offline.ManifestPath != "" },
	ImagesPathConfigured:   func() bool { return Config.Offline.ImagesPath != "" },

	WatermarkSecret: func() []byte { return []byte(os.Getenv("BAN_SECRET")) },

	RetailBlockList:  func() []string { return Config.SearchRetailBlockList },
	BuylistBlockList: func() []string { return Config.SearchBuylistBlockList },
})

// paletteService wires the command-palette endpoints to the live scraper lists,
// the newspaper page registry, and the arbit filter options.
var paletteService = &palette.Service{
	PromoAliases: func() map[string]string {
		return isKnownPromo
	},
	FinishLabel: func(finish string) string {
		// A treatment is a promo type on Magic, and the game spells its own
		// promo types better than any rule could - "Step-and-Compleat",
		// "Oil Slick foil", "Dragon Scale Foil". PromoTypeLabel title-cases
		// the token when it has no spelling of its own, which is worse than
		// the finish rule, so take it only where it actually says something.
		if slices.Contains(altFoilTags, finish) {
			label := mtgmatcher.PromoTypeLabel(finish)
			if label != mtgmatcher.Title(finish) {
				return label
			}
		}
		return spellFinish(finish)
	},
	FoilTreatments: func() []string {
		return altFoilTags
	},
	Sellers: GetSellers,
	Vendors: GetVendors,
	NewspaperPages: func() []palette.NewspaperPage {
		pages := GetNewspaperPages()
		out := make([]palette.NewspaperPage, 0, len(pages))
		for _, page := range pages {
			out = append(out, palette.NewspaperPage{Title: page.Title, Option: page.Option})
		}
		return out
	},
	ArbitFilters: func() []palette.ArbitFilter {
		out := make([]palette.ArbitFilter, 0, len(FilterOptKeys))
		for _, key := range FilterOptKeys {
			cfg, ok := FilterOptConfig[key]
			if !ok {
				continue
			}
			out = append(out, palette.ArbitFilter{Key: key, Title: cfg.Title, ArbitOnly: cfg.ArbitOnly})
		}
		return out
	},
}

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
	// Decode the sig once; this function reads it for expiry, every nav
	// feature, and the user email, and each GetParamFromSig call would
	// re-parse the whole thing.
	sigParams := parseSig(sig)
	expires, _ := strconv.ParseInt(sigParams.Get("Expires"), 10, 64)
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

		PatreonIDs:   Config.Patreon.Client,
		PatreonURL:   ServerURL + "/auth",
		PatreonLogin: showPatreonLogin,
		Hash:         BuildCommit,
	}

	if Config.Game != DefaultGame {
		// Append which game this site is for
		pageVars.Title += " - " + mtgmatcher.Title(Config.Game)

		// Charts for a non-Magic game are served only by the long-form read
		// path; the legacy wide table is mtgjson-uuid keyed and has no rows for
		// them. Until reads flip on, keep the chart UI hidden rather than show
		// buttons that resolve to an always-empty chart.
		if !Config.TimeseriesConfig.LongFormReads {
			pageVars.DisableChart = true
		}
	}
	if Config.OfflineKey != "" {
		pageVars.DisableChart = true
	}

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
			allowed, _ = strconv.ParseBool(sigParams.Get(feat))
		}

		if !allowed {
			continue
		}

		if Config.OfflineKey != "" && !ExtraNavs[feat].AllowOffline {
			continue
		}

		// A hidden section takes its subpages with it: they are reached
		// through it, and half a section is worse than none.
		if ExtraNavs[feat].ShouldHide != nil && ExtraNavs[feat].ShouldHide() {
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
	user := sigParams.Get("UserEmail")
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

	// Build the game-agnostic chart provider registry from the dataset config.
	buildProviderRegistry()

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
		log.Println("BAN_SECRET not set, using a default one")
		os.Setenv("BAN_SECRET", DefaultSecret)
	}

	return nil
}

func openDBs() (err error) {
	if Config.SQLConfig == nil {
		log.Println("no SQL configuration set, Charts won't be available")
	} else {
		PricesArchiveDB, err = timeseries.NewClient(*Config.SQLConfig)
		if err != nil {
			return fmt.Errorf("error opening the timeseries SQL client: %w", err)
		}
		// Best-effort: create the multi-game tcg_prices/tcg_products tables if
		// they're missing. Only when TCGCSV ingestion is configured, so plain
		// chart deployments don't pay two startup DDL round-trips and materialize
		// a dozen tables/partitions they never use. Non-fatal so a read-only or
		// unprivileged DB user can't block startup; ingestion re-checks the
		// schema before it runs.
		if Config.TCGCSVConfig != nil {
			if serr := PricesArchiveDB.EnsureTCGSchema(context.Background()); serr != nil {
				log.Println("warning: could not ensure tcg_prices schema:", serr)
			}
			if serr := PricesArchiveDB.EnsureTCGProductsSchema(context.Background()); serr != nil {
				log.Println("warning: could not ensure tcg_products schema:", serr)
			}
		}
		// Long-form dual-write: make sure the current and next month's price
		// partitions exist ahead of any write. Writes-only (creates partitions).
		if Config.TimeseriesConfig.LongFormWrites {
			now := time.Now()
			if serr := PricesArchiveDB.EnsurePricePartition(context.Background(), now); serr != nil {
				log.Println("warning: could not ensure current price partition:", serr)
			}
			if serr := PricesArchiveDB.EnsurePricePartition(context.Background(), now.AddDate(0, 1, 0)); serr != nil {
				log.Println("warning: could not ensure next price partition:", serr)
			}
		}
	}

	if Config.UserStateConfig == nil {
		log.Println("no user_state configuration set, cross-device sync won't be available")
	} else {
		UserStateDB, err = userstate.NewClient(*Config.UserStateConfig)
		if err != nil {
			return fmt.Errorf("error opening the user_state SQL client: %w", err)
		}
	}

	observabilityInstance = Config.InstanceName

	if Config.ObservabilityConfig == nil {
		log.Println("no observability configuration set, telemetry won't be recorded")
	} else if observabilityInstance == "" {
		log.Println("observability disabled: instance_name not set in config")
	} else if obsDB, oerr := observability.NewClient(*Config.ObservabilityConfig); oerr != nil {
		log.Println("observability disabled, init failed:", oerr)
	} else {
		ObservabilityDB = obsDB
		ObservabilityRecorder = observability.NewRecorder(obsDB)
		log.Println("observability telemetry enabled")
	}

	if Config.NewNewspaperSQLConfig != nil {
		NewNewspaperDB, err = Config.NewNewspaperSQLConfig.OpenDB()
		if err != nil {
			return fmt.Errorf("error opening the new_newspaper SQL client: %w", err)
		}
	} else {
		log.Println("no DB address set, Newspaper won't be loaded")
	}

	return nil
}

func loadGoogleCredentials() (*http.Client, error) {
	if Config.GoogleCredentials == "" {
		log.Println("no google credentials, skipping")
		return nil, nil
	}

	// By its own path rather than through ConfigBucket: this read used to take
	// the url apart and ask the config bucket for the path half, so credentials
	// named in another bucket were fetched from the config one, and a local
	// path was read from wherever the config happened to live.
	reader, err := openBucketPath(context.Background(), Config.GoogleCredentials)
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

// Bucket serving the datastore and any other file living alongside it,
// created once at startup
func loadDatastore(ds string) error {
	log.Println("Loading datastore from", ds)

	reader, err := openBucketPath(context.Background(), ds)
	if err != nil {
		return err
	}
	defer reader.Close()

	// LoadDatastore would read the file whole and try every registered loader.
	backend, err := mtgmatcher.Open(datastoreGame(), reader)
	if err != nil {
		return err
	}
	mtgmatcher.SetGlobalDatastore(backend)

	ServerNotify("init", "Datastore installed")
	SetLastDatastoreUpdate(time.Now())
	go rebuildSuggestIndex()
	go updateStaticData()
	go cacheNewspaper()
	go paletteService.BuildSetsCache()
	go paletteService.BuildPromosCache()
	go paletteService.BuildFinishesCache()

	return nil
}

// datastoreReloads owns the one datastore reload that may be under way.
var datastoreReloads dsreload.Tracker

// StartDatastoreReload loads the datastore in the background, reporting
// whether this call is the one that started it. See dsreload.Tracker.Start.
//
// The path is all it takes: openBucketPath reads the backend off the scheme,
// so a datastore and a backup living in different places are the same call.
func StartDatastoreReload(path, source string) bool {
	return datastoreReloads.Start(source, path, func() error {
		err := loadDatastore(path)
		if err != nil {
			return err
		}
		// What the endpoint used to do once the load returned. The offline
		// manifest is derived from the datastore, so a reload that leaves it
		// alone leaves it describing the previous one; the admin action never
		// asked for the refresh at all, and now does.
		ServerNotify("reload", "Datastore reloaded from "+path)
		offlineService.RequestRefresh()
		return nil
	})
}

// datastoreGame names the game whose loader reads this site's datastore. An
// unset game is the default one, the same reading the rest of the site gives
// it.
func datastoreGame() string {
	if Config.Game == "" {
		return DefaultGame
	}
	return Config.Game
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

	tcgcsvBackfill := flag.Bool("tcgcsv-backfill", false, "Backfill tcg_prices from tcgcsv archives, then exit")
	tcgcsvFrom := flag.String("tcgcsv-from", "", "Backfill start date YYYY-MM-DD (default: earliest archive, 2024-02-08; an explicit date fetches the whole range, bypassing the resume cursor)")
	tcgcsvTo := flag.String("tcgcsv-to", "", "Backfill end date YYYY-MM-DD (default: today)")
	tcgcsvForce := flag.Bool("tcgcsv-force", false, "Re-ingest dates already stored (ignore the resume cursor)")
	tcgcsvCategories := flag.String("tcgcsv-categories", "", "Restrict the backfill to these TCGplayer category ids, comma-separated (default: every configured game)")
	tcgcsvDaily := flag.Bool("tcgcsv-daily", false, "Run the daily tcgcsv ingest once, then exit")
	tcgcsvProducts := flag.Bool("tcgcsv-products", false, "Sync the tcgcsv product catalog once, then exit")

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

	loadRarityBadges()

	// Maintenance mode: ingest tcgcsv prices, then exit without standing up the
	// web server. Needs only the config and the price DB. The same jobs run as
	// their own process via cmd/tcgcsvd, which needs neither this binary nor its
	// datastore; these flags stay for the deployments already driving them.
	if *tcgcsvBackfill || *tcgcsvDaily || *tcgcsvProducts {
		if err := openDBs(); err != nil {
			log.Fatalln("error opening databases:", err)
		}
		if err := initTCGCSVService(); err != nil {
			log.Fatalln("tcgcsv:", err)
		}
		// The ingest resolves a ban_id per price row, so warm the categories
		// it is about to write. No catalog is loaded on this path and none is
		// needed: config names every category, and there is no site here whose
		// own game would add one.
		warmVariantCacheIfEnabled()
		var err error
		switch {
		case *tcgcsvBackfill:
			err = TCGCSVService.Backfill(context.Background(), tcgcsvd.BackfillOptions{
				From: *tcgcsvFrom, To: *tcgcsvTo, Categories: *tcgcsvCategories, Force: *tcgcsvForce,
			})
		case *tcgcsvDaily:
			err = TCGCSVService.IngestLatest(context.Background())
		case *tcgcsvProducts:
			err = TCGCSVService.SyncProducts(context.Background())
		}
		if err != nil {
			log.Fatalln("tcgcsv:", err)
		}
		os.Exit(0)
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

	// tcgcsv ingestion is optional: a deployment with no configured games or no
	// price database simply doesn't get the crons or the admin button.
	if err := initTCGCSVService(); err != nil {
		log.Println("tcgcsv ingestion disabled:", err)
	}

	err = reloadCheckpoints()
	if err != nil {
		log.Printf("checkpoints: initial load failed: %v", err)
	}

	if sec := os.Getenv("BAN_SECRET"); !DevMode && (sec == "" || sec == DefaultSecret) {
		log.Println("offline: BAN_SECRET is defaulted, price watermarks are predictable")
	}

	if err := offlineService.LoadPersisted(context.Background()); err != nil {
		log.Println("offline: manifest load failed:", err)
	}

	// Parse templates once in production
	TemplateCache, err = buildTemplateCache()
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
			// runSealedAnalysis loads the catalog, which is what names this
			// site's own TCGplayer category, so the variant scope is only
			// complete now.
			warmVariantCacheIfEnabled()
			offlineService.RefreshManifest()
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
			// runSealedAnalysis loads the catalog, which is what names this
			// site's own TCGplayer category, so the variant scope is only
			// complete now.
			warmVariantCacheIfEnabled()
			offlineService.RefreshManifest()
		}()
	}

	// Runtime manifest refreshes funnel through one debounced goroutine.
	offlineService.StartRefresher()

	if !DevMode {
		// Set up new refreshes as needed
		c := cron.New()

		// Take a snapshot twice a day
		c.AddFunc("0 */12 * * *", stashInTimeseries)

		// Update set values with new prices
		c.AddFunc("30 */12 * * *", runSealedAnalysis)

		// Reload DB Newspaper every 3 hours
		c.AddFunc("33 */3 * * *", cacheNewspaper)

		// Backstop refresh; reloads normally drive this via RequestRefresh.
		c.AddFunc("20 */12 * * *", offlineService.RequestRefresh)

		// Pull the latest tcgcsv snapshot daily (after its ~20:00 UTC refresh).
		// The job gates on tcgcsv's last-updated, so it no-ops until there's a
		// newer snapshot regardless of the exact fire time. Registered only when
		// the ingestion service came up: without a configured game or a price DB
		// every fire would fail, posting a recurring spurious failure to the
		// notification channel. Deployments that run cmd/tcgcsvd on its own can
		// leave tcgcsv_config out here and let the crons stay unregistered; the
		// standalone process takes the same cross-process crawl lock either way.
		if TCGCSVService != nil {
			c.AddFunc("0 21 * * *", stashTCGCSVPrices)
			// Product metadata changes rarely; refresh the catalog weekly.
			c.AddFunc("0 22 * * 1", stashTCGCSVProducts)
		}

		// Refresh the chart checkpoints. Magic reads its ban markers from a
		// document published outside this project, so a B&R announcement only
		// reaches the charts when something re-reads it -- and the boot-time
		// load is not that, on a process that stays up for weeks. It doubles as
		// the retry for a boot-time load that failed: a fetch that never
		// succeeded leaves the index empty and every chart without its markers.
		c.AddFunc("15 */6 * * *", refreshCheckpoints)

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
	http.HandleFunc("/robots.txt", ServeFile)
	// Dedicated handler: the service worker must revalidate on every deploy
	http.HandleFunc("/sw.js", ServeServiceWorker)

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

	// Offline shell page, precached by the service worker
	http.Handle("/offline", noSigning(http.HandlerFunc(OfflinePage)))

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
	http.Handle("/api/userstate/", noSigning(http.HandlerFunc(UserStateAPI)))
	http.Handle("/api/opensearch.xml", noSigning(http.HandlerFunc(OpenSearchDesc)))
	http.Handle("/api/load/datastore", noSigning(http.HandlerFunc(LoadDatastoreFromCloud)))
	http.Handle("/api/load/", enforceAPISigning(http.HandlerFunc(LoadFromCloud)))
	http.Handle("/api/palette/card/", noSigning(http.HandlerFunc(paletteService.CardMeta)))
	http.Handle("/api/palette/sealed/", noSigning(http.HandlerFunc(paletteService.Sealed)))
	http.Handle("/api/palette/sets.json", noSigning(http.HandlerFunc(paletteService.Sets)))
	http.Handle("/api/palette/stores.json", noSigning(http.HandlerFunc(paletteService.Stores)))
	http.Handle("/api/palette/promos.json", noSigning(http.HandlerFunc(paletteService.Promos)))
	http.Handle("/api/palette/finishes.json", noSigning(http.HandlerFunc(paletteService.Finishes)))
	http.Handle("/api/offline/", noSigning(http.HandlerFunc(offlineService.Handle)))

	http.Handle("/monroecards", http.RedirectHandler("/screener", http.StatusFound))

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

	// pprof registered itself on the default mux at import time, so its
	// routes cannot be wrapped individually like the other pages; steer
	// them through the standard signing middleware (plus the Admin grant)
	// here instead, and everything else straight to the mux
	debugHandler := enforceSigning(adminOnly(http.DefaultServeMux))
	srv := &http.Server{
		Addr: ":" + Config.Port,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/debug") {
				debugHandler.ServeHTTP(w, r)
				return
			}
			http.DefaultServeMux.ServeHTTP(w, r)
		}),
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

	// Wind down the background jobs alongside the listener: an ingest that is
	// mid-crawl stops at its next checkpoint instead of running into the exit.
	stopServerContext()

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
	if name == "arbit.html" {
		files = append(files, "templates/partials/sussy-badge.html")
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
