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
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"database/sql"

	_ "github.com/lib/pq"
	"github.com/mtgban/mtgban-website/apisig"
	"github.com/mtgban/mtgban-website/internal/alerts"
	"github.com/mtgban/mtgban-website/internal/jobs"
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

	"github.com/mtgban/go-mtgban/mtgban"
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

// liveConfig holds the config requests read. A load, a save or a new API
// key publishes a new value whole; nothing writes into the live one.
var liveConfig = func() *atomic.Pointer[ConfigType] {
	var p atomic.Pointer[ConfigType]
	p.Store(&ConfigType{})
	return &p
}()

// Config returns the live config, for reading only.
func Config() *ConfigType { return liveConfig.Load() }

// configMu serializes what changes the config while the site serves - a
// reload, an editor save, a new API key - each whole: what it reads of the
// live config, its file I/O and its publish, so none lands inside another.
// Readers never take it. The file I/O gives up after configFileTimeout, so a
// bucket that stops answering holds the lock that long at most.
var configMu sync.Mutex

// configFileTimeout bounds each read and write of the config file.
const configFileTimeout = 30 * time.Second

// APIGatewayConfig locates the API gateway the pricing page hands off to.
type APIGatewayConfig struct {
	// URL is the gateway's public origin, no trailing slash
	URL string `json:"url"`
	// Games are the gateway's configured games, what the configurator offers
	Games []mtgmatcher.Game `json:"games"`
}

// DiscordConfig contains the bot connection, community links, channel IDs,
// and webhook destinations used by the website.
type DiscordConfig struct {
	BotToken             string `json:"bot_token"`
	GuildID              string `json:"guild_id"`
	InviteURL            string `json:"invite_url"`
	ChangelogChannelID   string `json:"changelog_channel_id"`
	DevelopmentChannelID string `json:"development_channel_id"`
	RecapChannelID       string `json:"recap_channel_id"`
	ChatChannelID        string `json:"chat_channel_id"`
	UserWebhookURL       string `json:"user_webhook_url"`
	ServerWebhookURL     string `json:"server_webhook_url"`
	APIWebhookURL        string `json:"api_webhook_url"`
}

type ConfigType struct {
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

	Game         mtgmatcher.Game `json:"game"`
	InstanceName string          `json:"instance_name"`
	SiteURL      string          `json:"site_url"`

	// FormatEvents are the game-wide chart markers no ban list reports - a
	// format launching, say. Everything else on the checkpoint timeline comes
	// from the ban list document or the set registry.
	FormatEvents           []FormatEvent      `json:"format_events,omitempty"`
	ScraperConfig          ScraperConfig      `json:"scraper_config"`
	TimeseriesConfig       TimeseriesConfig   `json:"timeseries_config"`
	Discord                DiscordConfig      `json:"discord"`
	API                    map[string]string  `json:"api"`
	APIDemoStores          []string           `json:"api_demo_stores"`
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

	// ACL and the Patreon grants each live in their own file; a path may be
	// shared between deployments or belong to one, which is a choice about
	// the data, not the code. AffiliatesPath does the same for the
	// affiliate data, which every game shares: a store a game doesn't
	// carry never matches its list entries. These locate the files; see
	// common.go for the readers and writers.
	ACLPath           string `json:"acl_path"`
	PatreonGrantsPath string `json:"patreon_grants_path"`
	AffiliatesPath    string `json:"affiliates_path"`

	Uploader map[string]string `json:"uploader"`

	SQLConfig             *timeseries.SQLConfig `json:"sql_config"`
	UserStateConfig       *userstate.SQLConfig  `json:"user_state_config"`
	ObservabilityConfig   *timeseries.SQLConfig `json:"observability_config"`
	NewNewspaperSQLConfig *timeseries.SQLConfig `json:"new_newspaper_sql_config"`

	TCGCSVConfig *tcgcsv.Config   `json:"tcgcsv_config"`
	APIGateway   APIGatewayConfig `json:"api_gateway"`

	// The location of the configuation file (always last)
	sourcePath string
}

// UnmarshalJSON accepts the pre-discord-section keys during migration. New
// configuration should use the nested discord object; legacy deployments can
// roll forward without having to change their secrets in the same release.
func (c *ConfigType) UnmarshalJSON(data []byte) error {
	type configAlias ConfigType
	legacy := struct {
		*configAlias
		DiscordHook               string `json:"discord_hook"`
		DiscordNotifHook          string `json:"discord_notif_hook"`
		DiscordAPINotifHook       string `json:"discord_api_notif_hook"`
		DiscordInviteLink         string `json:"discord_invite_link"`
		DiscordChangelogChannelID string `json:"discord_changelog_channel_id"`
		DiscordToken              string `json:"discord_token"`
	}{configAlias: (*configAlias)(c)}

	if err := json.Unmarshal(data, &legacy); err != nil {
		return err
	}
	if c.Discord.UserWebhookURL == "" {
		c.Discord.UserWebhookURL = legacy.DiscordHook
	}
	if c.Discord.ServerWebhookURL == "" {
		c.Discord.ServerWebhookURL = legacy.DiscordNotifHook
	}
	if c.Discord.APIWebhookURL == "" {
		c.Discord.APIWebhookURL = legacy.DiscordAPINotifHook
	}
	if c.Discord.InviteURL == "" {
		c.Discord.InviteURL = legacy.DiscordInviteLink
	}
	if c.Discord.ChangelogChannelID == "" {
		c.Discord.ChangelogChannelID = legacy.DiscordChangelogChannelID
	}
	if c.Discord.BotToken == "" {
		c.Discord.BotToken = legacy.DiscordToken
	}
	c.Discord.applyDefaults()
	return nil
}

var DevMode bool
var SigCheck bool
var SkipPrices bool
var SkipNewspaper bool
var LogDir string

// Timestamps written by background goroutines (stash cron, newspaper cron)
// and read by the admin dashboard. Held behind atomic.Pointer so concurrent
// reads can't observe a torn time.Time (it's a 24-byte struct, not a single
// word). The datastore's own timestamp lives on the published datastore
// instead - see datastore.go's loadedAt field.
var (
	lastStashUpdatePtr     atomic.Pointer[time.Time]
	lastNewspaperUpdatePtr atomic.Pointer[time.Time]
)

// SetLastStashUpdate / SetLastNewspaperUpdate publish a new timestamp
// atomically.
func SetLastStashUpdate(t time.Time)     { lastStashUpdatePtr.Store(&t) }
func SetLastNewspaperUpdate(t time.Time) { lastNewspaperUpdatePtr.Store(&t) }

// GetLastStashUpdate / GetLastNewspaperUpdate return the most recent
// timestamp, or the zero time if none has been published yet.
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
	base := Config().Offline.ImagesPath
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

// paletteNewspaperPages lists the newspaper views the command palette
// offers as jump targets, those the newspaper shows on this deployment. It
// reads the pages as declared: cacheNewspaper refreshes a page's results,
// never its title or option.
func paletteNewspaperPages() []palette.NewspaperPage {
	out := make([]palette.NewspaperPage, 0, len(newspaperPagesInitial))
	for _, page := range newspaperPagesInitial {
		if !page.shown() {
			continue
		}
		out = append(out, palette.NewspaperPage{Title: page.Title, Option: page.Option})
	}
	return out
}

// paletteArbitFilters lists the arbitrage filter options the command
// palette offers on the "arbit", "reverse" or "global" page, in display
// order: those the page shows some reader, for a sealed source or not.
func paletteArbitFilters(variant string) []palette.ArbitFilter {
	globalMode, reverseMode := variant == "global", variant == "reverse"
	// Only arbit and reverse have readers who see the beta options: Global
	// never sets scraperCompareOpts.AnyOptionEnabled
	canShowAll := !globalMode

	out := make([]palette.ArbitFilter, 0, len(FilterOptKeys))
	for _, key := range FilterOptKeys {
		cfg, ok := FilterOptConfig[key]
		if !ok {
			continue
		}
		shown := cfg.Shown(globalMode, reverseMode, canShowAll, false) ||
			cfg.Shown(globalMode, reverseMode, canShowAll, true)
		if !shown {
			continue
		}
		out = append(out, palette.ArbitFilter{Key: key, Title: cfg.Title})
	}
	return out
}

const (
	DefaultServerPort    = "8080"
	DefaultConfigPath    = "config.json"
	DefaultSecret        = "NotVerySecret!"
	DefaultGame          = mtgmatcher.GameMagic
	DefaultServerURL     = apisig.DefaultLink
	DefaultExternalURL   = "https://mtgban.com"
	DefaultAPIGatewayURL = "https://api.mtgban.com"
	DefaultDatastorePath = "AllPrintings.json.xz"

	DefaultSignatureDuration = 11 * 24 * time.Hour
)

// Cache for a week as these assets either never change or have a snapshot key in the URL
func ServeFile(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=86400")
	http.ServeFile(w, r, r.URL.Path[1:])
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

func preloadConfig(configPath string) error {
	if configPath == "" {
		configPath = os.Getenv("BAN_CONFIG_PATH")
	}
	if configPath == "" {
		configPath = DefaultConfigPath
	}

	// Save source, so we can reload later
	liveConfig.Store(&ConfigType{sourcePath: configPath})

	u, err := url.Parse(Config().sourcePath)
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

// loadVars reads the config file into a new config, giving up after
// configFileTimeout, sets the port and paths given over it, and makes it the
// live one through finishConfig. Once the site serves, its caller holds
// configMu; startup calls it before anything else runs.
func loadVars(port, datastorePath, aclPath, grantsPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), configFileTimeout)
	defer cancel()
	reader, err := simplecloud.InitReader(ctx, ConfigBucket, Config().sourcePath)
	if err != nil {
		return err
	}
	defer reader.Close()

	// Decode into a fresh value, not the live one: decoding merges, so a map
	// key or a field the file no longer has would survive a reload.
	config := ConfigType{Game: DefaultGame, sourcePath: Config().sourcePath}
	err = json.NewDecoder(reader).Decode(&config)
	if err != nil && !DevMode {
		return err
	}
	applyOverrides(&config, port, datastorePath, aclPath, grantsPath)
	finishConfig(config)
	return nil
}

// reloadConfig reloads the config file for the admin page's ?reboot=config,
// keeping the running port and paths. It reads them under configMu, so they
// are the ones any save it waited on set.
func reloadConfig() error {
	configMu.Lock()
	defer configMu.Unlock()
	return loadVars(Config().Port, Config().DatastorePath, Config().ACLPath, Config().PatreonGrantsPath)
}

// applyOverrides sets config's port and datastore, ACL and grants paths to
// the values given, over whatever the config file said; an empty one leaves
// the file's. Startup passes the flags, reloadConfig the running values. It must
// follow the decode, which would otherwise clobber them (breaking blue-green
// deploys that run instances on distinct ports).
func applyOverrides(config *ConfigType, port, datastorePath, aclPath, grantsPath string) {
	if port != "" {
		config.Port = port
	}
	if datastorePath != "" {
		config.DatastorePath = datastorePath
	}
	if aclPath != "" {
		config.ACLPath = aclPath
	}
	if grantsPath != "" {
		config.PatreonGrantsPath = grantsPath
	}
}

// finishConfig defaults what a newly loaded config left unset and makes it
// the live one, whole; then it rebuilds the chart provider registry from it
// and defaults BAN_SECRET when the environment has none.
func finishConfig(config ConfigType) {
	if config.Port == "" {
		log.Println("Server port not configured, listening on", DefaultServerPort)
		config.Port = DefaultServerPort
	}
	if config.Game == "" {
		log.Println("Game not configured, defaulting to", DefaultGame)
		config.Game = DefaultGame
	}
	if config.DatastorePath == "" {
		log.Println("Datastore path not configured, using", DefaultDatastorePath)
		config.DatastorePath = DefaultDatastorePath
	}
	applyAPIGatewayDefaults(&config.APIGateway, config.Game)

	liveConfig.Store(&config)

	// Build the game-agnostic chart provider registry from the dataset config.
	buildProviderRegistry()

	// Load from env
	v := os.Getenv("BAN_SECRET")
	if v == "" {
		log.Println("BAN_SECRET not set, using a default one")
		os.Setenv("BAN_SECRET", DefaultSecret)
	}

	if apiGatewaySecret() == "" {
		log.Println("api_user_secrets has no " + apiGatewayUser + " entry, API trial and sign-in handoff disabled")
	}
}

// applyAPIGatewayDefaults fills api_gateway so the pricing page always has a
// target; game is this deployment's own game, added to the default game list.
func applyAPIGatewayDefaults(c *APIGatewayConfig, game mtgmatcher.Game) {
	if c.URL == "" {
		c.URL = DefaultAPIGatewayURL
	}
	c.URL = strings.TrimRight(c.URL, "/")
	if !strings.HasPrefix(c.URL, "http://") && !strings.HasPrefix(c.URL, "https://") {
		log.Printf("api_gateway.url must be absolute, using %s", DefaultAPIGatewayURL)
		c.URL = DefaultAPIGatewayURL
	}
	if len(c.Games) == 0 {
		c.Games = []mtgmatcher.Game{DefaultGame}
		if game != "" && game != DefaultGame {
			c.Games = append(c.Games, game)
		}
	}
}

func (s *site) openDBs() (err error) {
	if Config().SQLConfig == nil {
		log.Println("no SQL configuration set, Charts won't be available")
	} else {
		PricesArchiveDB, err = timeseries.NewClient(*Config().SQLConfig)
		if err != nil {
			return fmt.Errorf("error opening the timeseries SQL client: %w", err)
		}
		// Best-effort: create the multi-game tcg_prices/tcg_products tables if
		// they're missing. Only when TCGCSV ingestion is configured, so plain
		// chart deployments don't pay two startup DDL round-trips and materialize
		// a dozen tables/partitions they never use. Non-fatal so a read-only or
		// unprivileged DB user can't block startup; ingestion re-checks the
		// schema before it runs.
		if Config().TCGCSVConfig != nil {
			if serr := PricesArchiveDB.EnsureTCGSchema(context.Background()); serr != nil {
				log.Println("warning: could not ensure tcg_prices schema:", serr)
			}
			if serr := PricesArchiveDB.EnsureTCGProductsSchema(context.Background()); serr != nil {
				log.Println("warning: could not ensure tcg_products schema:", serr)
			}
		}
		// Long-form dual-write: make sure the current and next month's price
		// partitions exist ahead of any write. Writes-only (creates partitions).
		if Config().TimeseriesConfig.LongFormWrites {
			now := time.Now()
			if serr := PricesArchiveDB.EnsurePricePartition(context.Background(), now); serr != nil {
				log.Println("warning: could not ensure current price partition:", serr)
			}
			if serr := PricesArchiveDB.EnsurePricePartition(context.Background(), now.AddDate(0, 1, 0)); serr != nil {
				log.Println("warning: could not ensure next price partition:", serr)
			}
		}
	}

	if Config().UserStateConfig == nil {
		log.Println("no user_state configuration set, cross-device sync won't be available")
	} else {
		UserStateDB, err = userstate.NewClient(*Config().UserStateConfig)
		if err != nil {
			return fmt.Errorf("error opening the user_state SQL client: %w", err)
		}
		// Non-fatal: a schema or privilege problem leaves the service
		// without a store, which hides the page and no-ops the evaluator.
		alertsDB, alertsErr := alerts.New(UserStateDB.DB())
		if alertsErr != nil {
			log.Println("alerts: store unavailable:", alertsErr)
		} else {
			s.alerts.SetStore(alertsDB)
		}
	}

	observabilityInstance = Config().InstanceName

	if Config().ObservabilityConfig == nil {
		log.Println("no observability configuration set, telemetry won't be recorded")
	} else if observabilityInstance == "" {
		log.Println("observability disabled: instance_name not set in config")
	} else if obsDB, oerr := observability.NewClient(*Config().ObservabilityConfig); oerr != nil {
		log.Println("observability disabled, init failed:", oerr)
	} else {
		ObservabilityDB = obsDB
		ObservabilityRecorder = observability.NewRecorder(obsDB)
		log.Println("observability telemetry enabled")
	}

	if Config().NewNewspaperSQLConfig != nil {
		NewNewspaperDB, err = Config().NewNewspaperSQLConfig.OpenDB()
		if err != nil {
			return fmt.Errorf("error opening the new_newspaper SQL client: %w", err)
		}
	} else {
		log.Println("no DB address set, Newspaper won't be loaded")
	}

	return nil
}

func loadGoogleCredentials() (*http.Client, error) {
	if Config().GoogleCredentials == "" {
		log.Println("no google credentials, skipping")
		return nil, nil
	}

	// By its own path rather than through ConfigBucket: this read used to take
	// the url apart and ask the config bucket for the path half, so credentials
	// named in another bucket were fetched from the config one, and a local
	// path was read from wherever the config happened to live.
	reader, err := openBucketPath(context.Background(), Config().GoogleCredentials)
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

// datastoreGame names the game whose loader reads this site's datastore. An
// unset game is the default one, the same reading the rest of the site gives
// it.
func datastoreGame() mtgmatcher.Game {
	if Config().Game == "" {
		return DefaultGame
	}
	return Config().Game
}

// splitStores reads a -stores value: comma-separated, each name trimmed of
// spaces, empty names dropped.
func splitStores(value string) []string {
	var stores []string
	for _, store := range strings.Split(value, ",") {
		store = strings.TrimSpace(store)
		if store != "" {
			stores = append(stores, store)
		}
	}
	return stores
}

func main() {
	configFilePath := flag.String("cfg", "", "Load configuration file")
	port := flag.String("port", "", "Override server port")
	dsPath := flag.String("ds", "", "Override datastore path")
	aclPath := flag.String("acl", "", "Override access table path")
	grantsPath := flag.String("grants", "", "Override Patreon grants path")
	dumpsDir := flag.String("dumps", "", "Read scraper dumps from this local directory instead of the mtgban-dumps bucket")

	flag.BoolVar(&DevMode, "dev", false, "Enable developer mode")
	sigCheck := flag.Bool("sig", false, "Enable signature verification")
	flag.BoolVar(&SkipPrices, "noload", false, "Do not load price data")
	storesFlag := flag.String("stores", "", "Load only these stores' dumps, comma-separated (default: scraper_config.stores, else every store)")
	flag.BoolVar(&SkipNewspaper, "nonews", false, "Do not load newspaper data")
	alertsSend := flag.Bool("alerts-send", false, "Deliver alert DMs in dev mode")
	flag.StringVar(&LogDir, "log", "logs", "Directory for scrapers logs")

	tcgcsvBackfill := flag.Bool("tcgcsv-backfill", false, "Backfill tcg_prices from tcgcsv archives, then exit (archives are withdrawn upstream: stores the current snapshot instead when the range covers it)")
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
	err = loadVars(*port, *dsPath, *aclPath, *grantsPath)
	if err != nil {
		if DevMode {
			log.Println("unable to load config file:", Config().sourcePath, "- using safe defaults")
			// loadVars returned before applying the flags and the defaults.
			config := *Config()
			applyOverrides(&config, *port, *dsPath, *aclPath, *grantsPath)
			finishConfig(config)
		} else {
			log.Fatalln("unable to load config file:", err)
		}
	}

	// The access table and the grant list, from their own paths or from what
	// the config carried. A deployment that cannot read its access table has
	// no way to tell an admin from anyone else, so this is fatal for the same
	// reason a missing config is.
	err = loadCommonConfig(context.Background())
	if err != nil {
		if DevMode {
			log.Println("unable to load the shared config:", err)
		} else {
			log.Fatalln("unable to load the shared config:", err)
		}
	}

	loadRarityBadges()

	s := newSite()
	s.alertsSend = *alertsSend

	// Maintenance mode: ingest tcgcsv prices, then exit without standing up the
	// web server. Needs only the config and the price DB. The same jobs run as
	// their own process via cmd/tcgcsvd, which needs neither this binary nor its
	// datastore; these flags stay for the deployments already driving them.
	if *tcgcsvBackfill || *tcgcsvDaily || *tcgcsvProducts {
		dbErr := s.openDBs()
		if dbErr != nil {
			log.Fatalln("error opening databases:", dbErr)
		}
		tcgErr := initTCGCSVService(s)
		if tcgErr != nil {
			log.Fatalln("tcgcsv:", tcgErr)
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

	// Before the loads start, so the alerts store is in for their pokes.
	err = s.openDBs()
	if err != nil {
		log.Fatalln("error opening databases:", err)
	}

	// Pick up access table / grant saves made by the peer deployments
	// sharing the price database.
	startAccessReloadListener()

	// tcgcsv ingestion is optional: a deployment with no configured games or no
	// price database simply doesn't get the crons or the admin button.
	err = initTCGCSVService(s)
	if err != nil {
		log.Println("tcgcsv ingestion disabled:", err)
	}

	err = reloadCheckpoints()
	if err != nil {
		log.Printf("checkpoints: initial load failed: %v", err)
	}

	if sec := os.Getenv("BAN_SECRET"); !DevMode && (sec == "" || sec == DefaultSecret) {
		log.Println("offline: BAN_SECRET is defaulted, price watermarks are predictable")
	}

	err = s.offline.LoadPersisted(context.Background())
	if err != nil {
		log.Println("offline: manifest load failed:", err)
	}

	// Parse templates once in production
	TemplateCache, err = buildTemplateCache()
	if err != nil {
		log.Fatalln("template cache:", err)
	}

	// Load through the tracker: a panic is recovered and recorded rather than
	// killing the process, and a reload requested before this finishes is
	// queued to follow it instead of racing it.
	datastoreLoaded := make(chan struct{})
	s.reloads.Start("startup", Config().DatastorePath, func() error {
		// Closed on a panic too, so the prices below never wait forever.
		defer close(datastoreLoaded)
		err := s.loadDatastore(Config().DatastorePath)
		if err != nil {
			log.Fatalln("error loading datastore:", err)
		}
		return nil
	})

	if SkipPrices {
		log.Println("no prices loaded as requested")
	} else {
		stores := splitStores(*storesFlag)
		if len(stores) == 0 {
			stores = Config().ScraperConfig.Stores
		}
		// Opened before the loader and the server start, so a request that
		// reloads a store finds DataBucket already set.
		var bucket simplecloud.Reader
		if *dumpsDir != "" {
			// A missing directory would list nothing and load nothing.
			_, err := os.Stat(*dumpsDir)
			if err != nil {
				log.Fatalln("error opening the dumps directory:", err)
			}
			bucket = &simplecloud.FileBucket{Root: *dumpsDir}
		} else {
			b2, err := openDumpsBucket(context.Background())
			if err != nil {
				log.Fatalln("error opening the dumps bucket:", err)
			}
			bucket = b2
		}
		DataBucket = bucket
		go func() {
			log.Println("Loading scrapers")
			err := loadScrapersNG(bucket, stores)
			if err != nil {
				log.Fatalln("error loading scrapers:", err)
			}
			// Card Kingdom's stock history and buylist signals (ckbuylist.go),
			// where the prices just loaded include CK's buylist.
			if ckAvailable() {
				go tracked(jobCKSignals, s.refreshCKSignals)()
			}

			// Update set values after loading prices. The analysis reads the
			// backend it starts with, so it waits for the datastore: read
			// from a bucket, it can arrive after the prices.
			<-datastoreLoaded
			// Alerts wait for both the datastore and the prices.
			s.alerts.RequestEvaluate(alerts.SideRetail, alerts.SideBuylist)
			finish := backgroundJobs.Start(jobSetAnalysis)
			s.runSealedAnalysis()
			finish(nil)
			// runSealedAnalysis loads the catalog, which is what names this
			// site's own TCGplayer category, so the variant scope is only
			// complete now.
			warmVariantCacheIfEnabled()
			s.offline.RefreshManifest()
		}()
	}

	// Runtime manifest refreshes funnel through one debounced goroutine, each
	// under tracked so that one that panics does not end the loop.
	s.offline.StartRefresher(func(_ string, fn func()) func() { return tracked(jobOffline, fn) })

	if !DevMode {
		// Set up new refreshes as needed. The library runs each job on a bare
		// goroutine, where a panic would end the process: tracked reports it
		// instead, and the job runs again at its next time.
		c := cron.New()
		// addJob schedules fn at spec as the background job name, whose runs
		// and schedule the admin dashboard and the staleness alarm read.
		addJob := func(spec, name string, fn func()) {
			schedule, err := cron.Parse(spec)
			if err != nil {
				log.Fatalln("cron", name, err)
			}
			backgroundJobs.Schedule(name, schedule.Next)
			c.Schedule(schedule, cron.FuncJob(tracked(name, fn)))
		}

		// Take a snapshot twice a day
		addJob("0 */12 * * *", jobStash, s.stashInTimeseries)

		// Update set values with new prices
		addJob("30 */12 * * *", jobSetAnalysis, s.runSealedAnalysis)

		// Reload DB Newspaper every 3 hours
		addJob("33 */3 * * *", jobNewspaper, s.cacheNewspaper)

		// Rebuild CK's buylist signals, reloading its stock history once the
		// newspaper has a new day; until then that is one indexed MAX(date).
		// Only where the site serves CK's buylist, which is known once the
		// prices load: its runs, schedule and row start with that.
		ckSchedule, err := cron.Parse("45 * * * *")
		if err != nil {
			log.Fatalln("cron", jobCKSignals, err)
		}
		ckJob := tracked(jobCKSignals, s.refreshCKSignals)
		c.Schedule(ckSchedule, cron.FuncJob(func() {
			if !ckAvailable() {
				return
			}
			backgroundJobs.Schedule(jobCKSignals, ckSchedule.Next)
			ckJob()
		}))

		// Reload TCGplayer's sellers and copies per grade once the newspaper
		// finishes a scrape; until then that is one MAX(calc_date).
		addJob("50 * * * *", jobTCGListings, s.loadTCGListings)

		// Backstop refresh; reloads normally drive this via RequestRefresh.
		c.AddFunc("20 */12 * * *", recovered("cron RequestRefresh", s.offline.RequestRefresh))

		// Pull the latest tcgcsv snapshot daily (after its ~20:00 UTC refresh).
		// The job gates on tcgcsv's last-updated, so it no-ops until there's a
		// newer snapshot regardless of the exact fire time. Registered only when
		// the ingestion service came up: without a configured game or a price DB
		// every fire would fail, posting a recurring spurious failure to the
		// notification channel. Deployments that run cmd/tcgcsvd on its own can
		// leave tcgcsv_config out here and let the crons stay unregistered; the
		// standalone process takes the same cross-process crawl lock either way.
		if TCGCSVService != nil {
			addJob("0 21 * * *", jobTCGCSVPrices, stashTCGCSVPrices)
			// Product metadata changes rarely; refresh the catalog weekly.
			addJob("0 22 * * 1", jobTCGCSVProducts, stashTCGCSVProducts)
		}

		// Refresh the chart checkpoints. Magic reads its ban markers from a
		// document published outside this project, so a B&R announcement only
		// reaches the charts when something re-reads it -- and the boot-time
		// load is not that, on a process that stays up for weeks. It doubles as
		// the retry for a boot-time load that failed: a fetch that never
		// succeeded leaves the index empty and every chart without its markers.
		addJob("15 */6 * * *", jobCheckpoints, refreshCheckpoints)

		// Alarm on a store whose retail or buylist data has gone stale (see
		// staleness.go); notifies only on the transition, so this can run
		// often without repeating itself.
		addJob("0 * * * *", jobStaleness, checkStaleness)
		// And on a background job turning bad, the same way.
		c.AddFunc("0 * * * *", recovered("cron checkJobHealth", checkJobHealth))

		c.Start()
	}

	err = s.setupDiscord()
	if err != nil {
		log.Println("Error connecting to discord", err)
	}

	// Price alerts re-evaluate after a burst of installs settles.
	s.startAlertEvaluator()

	// Serve everything in known folders as a file
	http.HandleFunc("/css/", ServeFile)
	http.HandleFunc("/img/", ServeFile)
	http.HandleFunc("/js/", ServeFile)
	http.HandleFunc("/favicon.ico", ServeFile)
	http.HandleFunc("/robots.txt", ServeFile)
	// Dedicated handler: the service worker must revalidate on every deploy
	http.HandleFunc("/sw.js", ServeServiceWorker)

	// custom redirector
	http.HandleFunc("/go/", s.Redirect)
	http.HandleFunc("/http:/", UploadURLRedirect)
	http.HandleFunc("/https:/", UploadURLRedirect)
	http.HandleFunc("/card/", s.CardRedirect)
	http.HandleFunc("/sealed/", s.SealedRedirect)
	http.HandleFunc("/random", s.RandomSearch)
	http.HandleFunc("/randomsealed", s.RandomSealedSearch)
	http.HandleFunc("/discord", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, Config().Discord.InviteURL, http.StatusFound)
	})

	// Public changelog sourced from the Discord announcement channel.
	http.Handle("/changelog", noSigning(http.HandlerFunc(s.Changelog)))

	// when navigating to /home it should serve the home page
	http.Handle("/", noSigning(http.HandlerFunc(s.Home)))

	// Public guide page
	http.Handle("/guide", noSigning(http.HandlerFunc(s.Guide)))

	// Public privacy policy (cookie + Amazon Associates disclosures)
	http.Handle("/privacy", noSigning(http.HandlerFunc(s.Privacy)))

	// Offline shell page, precached by the service worker
	http.Handle("/offline", noSigning(http.HandlerFunc(s.OfflinePage)))

	// Mobile/desktop view toggle
	http.HandleFunc("/toggle-mobile", toggleMobileView)

	for _, nav := range ExtraNavs {
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
		var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nav.Handle(s, w, r)
		})
		handler = enforceSigning(s, handler)
		http.Handle(nav.Link, handler)

		// Add any additional endpoints to it
		for _, subPage := range nav.SubPages {
			http.Handle(subPage.Link, handler)
		}
	}

	// The upload handoff sits under /upload but is its own page: the nav
	// entry registers an exact path, so it needs naming here.
	//
	// Served without the signing middleware, which would answer a reader
	// who has no signature with the home page. This one is worth reaching
	// signed out: somebody sent here by an extension arrives knowing
	// nothing about the site, and the page can say what it is and what it
	// would take to use it. It grants nothing by being read - the rows it
	// receives are posted to /upload, which is enforced as it always was -
	// and it checks the signature itself before it agrees to receive any.
	http.Handle("/upload/handoff", noSigning(http.HandlerFunc(s.UploadHandoff)))

	http.Handle("/search/oembed", noSigning(http.HandlerFunc(s.Search)))
	http.Handle("/api/mtgban/search/", enforceAPISigning(http.HandlerFunc(s.SearchAPI)))
	http.Handle("/api/mtgban/", enforceAPISigning(http.HandlerFunc(s.PriceAPI)))
	http.Handle("/api/tcgplayer/", enforceSigning(s, http.HandlerFunc(s.TCGHandler)))
	http.Handle("/api/cardmarket/", enforceSigning(s, http.HandlerFunc(s.MKMHandler)))
	http.Handle("/api/search/", enforceSigning(s, http.HandlerFunc(s.SearchAPI)))
	http.Handle("/api/mtgmatcher/raw/", enforceSigning(s, http.HandlerFunc(s.RawCardAPI)))
	http.Handle("/api/suggest", noSigning(http.HandlerFunc(s.SuggestAPI)))
	http.Handle("/api/chart/", noSigning(http.HandlerFunc(s.ChartDataAPI)))
	http.Handle("/api/prices/", enforceSigning(s, http.HandlerFunc(s.BatchPricesAPI)))
	http.Handle("/api/userstate/", noSigning(http.HandlerFunc(UserStateAPI)))
	// Its closures read the live datastore and prices per request.
	http.Handle("/api/alerts/", noSigning(s.alerts.API()))
	http.Handle("/api/opensearch.xml", noSigning(http.HandlerFunc(OpenSearchDesc)))
	http.Handle("/api/load/datastore", noSigning(http.HandlerFunc(s.LoadDatastoreFromCloud)))
	http.Handle("/api/load/", enforceAPISigning(http.HandlerFunc(s.LoadFromCloud)))
	http.Handle("/api/palette/card/", noSigning(http.HandlerFunc(s.palette.CardMeta)))
	http.Handle("/api/palette/sealed/", noSigning(http.HandlerFunc(s.palette.Sealed)))
	http.Handle("/api/palette/sets.json", noSigning(http.HandlerFunc(s.palette.Sets)))
	http.Handle("/api/palette/stores.json", noSigning(http.HandlerFunc(s.palette.Stores)))
	// The gateway reads the store families without a signature, so this
	// cannot hang off the API page: a sub-page is served unsigned only when
	// the ACL's Any tier grants the page (see enforceSigning).
	http.Handle("/api-plans/stores.json", noSigning(http.HandlerFunc(APIStores)))
	http.Handle("/api/palette/promos.json", noSigning(http.HandlerFunc(s.palette.Promos)))
	http.Handle("/api/palette/finishes.json", noSigning(http.HandlerFunc(s.palette.Finishes)))
	http.Handle("/api/offline/", noSigning(http.HandlerFunc(s.offline.Handle)))

	http.Handle("/monroecards", http.RedirectHandler("/screener", http.StatusFound))

	http.HandleFunc("/auth", s.Auth)

	// /healthz: returns 200 only if dependencies are OK.
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		uuids := len(s.backend().GetUUIDs())
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
	debugHandler := enforceSigning(s, adminOnly(http.DefaultServeMux))
	srv := &http.Server{
		Addr: ":" + Config().Port,
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

	// Which signal arrived, and how long the process had been up for. Every
	// stop used to read alike from here, so a deploy, someone's Ctrl-C, and a
	// libc upgrade bouncing the service through needrestart were told apart
	// only by the wall clock - and the one worth knowing about is the one
	// nobody remembers doing.
	sig := <-done
	ServerNotify("shutdown", "Server asked to stop ("+sig.String()+") after "+uptime()+" of uptime")

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
	if name == "alerts.html" {
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
