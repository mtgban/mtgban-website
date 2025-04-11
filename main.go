package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"database/sql"

	_ "github.com/go-sql-driver/mysql"
	"github.com/leemcloughlin/logfile"
	"golang.org/x/exp/slices"
	"golang.org/x/oauth2/google"
	"gopkg.in/Iwark/spreadsheet.v2"
	cron "gopkg.in/robfig/cron.v2"

	"github.com/mtgban/go-mtgban/mtgban"
)

type PageVars struct {
	Pagination

	Nav      []NavElem
	ExtraNav []NavElem

	ShowLogin bool
	Hash      string

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
	LastUpdate     string

	AllKeys      []string
	SearchQuery  string
	SearchBest   bool
	SearchSort   string
	CondKeys     []string
	FoundSellers map[string]map[string][]SearchEntry
	FoundVendors map[string]map[string][]SearchEntry
	Metadata     map[string]GenericCard
	PromoTags    []string
	NoSort       bool
	HasAvailable bool
	CardBackURL  string
	ShowUpsell   bool

	CanShowAll       bool
	CleanSearchQuery string

	ScraperShort   string
	HasAffiliate   bool
	CanDownloadCSV bool
	ShowSYP        bool

	Arb            []Arbitrage
	ArbitOptKeys   []string
	ArbitOptConfig map[string]FilterOpt
	ArbitFilters   map[string]bool
	ArbitOptTests  map[string]bool
	SortOption     string
	GlobalMode     bool
	ReverseMode    bool

	Page         string
	Subtitle     string
	ToC          []NewspaperPage
	Headings     []Heading
	Cards        []GenericCard
	Table        [][]string
	HasReserved  bool
	HasStocks    bool
	HasSypList   bool
	IsOneDay     bool
	CanSwitchDay bool
	SortDir      string
	LargeTable   bool
	OffsetCards  int
	FilterSet    string
	Editions     []string
	FilterRarity string
	Rarities     []string
	CardHashes   []string
	EditionsMap  map[string]EditionEntry

	PageMessage string
	PageType    string

	CanFilterByPrice bool
	FilterMinPrice   float64
	FilterMaxPrice   float64

	CanFilterByPercentage bool
	FilterMinPercChange   float64
	FilterMaxPercChange   float64

	Sleepers       map[string][]string
	SleepersKeys   []string
	SleepersColors []string

	Headers      []string
	OtherHeaders []string
	OtherTable   [][]string
	CurrentTime  time.Time
	Uptime       string
	DiskStatus   string
	MemoryStatus string
	LatestHash   string
	Tiers        []string
	DemoKey      string

	SelectableField bool
	DisableLinks    bool

	DisableChart bool
	AxisLabels   []string
	Datasets     []*Dataset
	ChartID      string
	Alternative  string
	StocksURL    string
	AltEtchedId  string

	EditionSort []string
	EditionList map[string][]EditionEntry
	IsSealed    bool
	IsSets      bool
	TotalSets   int
	TotalCards  int
	TotalUnique int

	ScraperKeys     []string
	IndexKeys       []string
	SellerKeys      []string
	VendorKeys      []string
	UploadEntries   []UploadEntry
	IsBuylist       bool
	TotalEntries    map[string]float64
	EnabledSellers  []string
	EnabledVendors  []string
	CanBuylist      bool
	CanChangeStores bool
	RemoteLinkURL   string
	TotalQuantity   int
	Optimized       map[string][]OptimizedUploadEntry
	OptimizedTotals map[string]float64
	HighestTotal    float64
	MissingCounts   map[string]int
	MissingPrices   map[string]float64
	ResultPrices    map[string]map[string]float64
	IsLoggedIn      bool
	UserEmail       string
	UserTier        string
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

	// Response handler
	Handle func(w http.ResponseWriter, r *http.Request)

	// Which page to render
	Page string

	// Whether this tab should always be enabled in DevMode
	AlwaysOnForDev bool

	// Allow to receive POST requests
	CanPOST bool

	// Alternative endpoints connected to this handler
	SubPages []string

	// Whether authentication is disabled for the endpoint
	NoAuth bool
}

var startTime = time.Now()

var DefaultNav = []NavElem{
	NavElem{
		Name:    "Home",
		Short:   "🏡",
		Link:    "/",
		Page:    "home.html",
		CanPOST: true,
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
	"ArbitEnabled",
	"ArbitDisabledVendors",
	"NewsEnabled",
	"UploadBuylistEnabled",
	"UploadChangeStoresEnabled",
	"UploadOptimizer",
	"UploadNoLimit",
	"AnyEnabled",
	"AnyExperimentsEnabled",
	"APImode",
}

// The key matches the query parameter of the permissions defined in sign()
// These enable/disable the relevant pages
var OrderNav = []string{
	"Search",
	"Newspaper",
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
			Name:     "Search",
			Short:    "🔍",
			Link:     "/search",
			Handle:   Search,
			Page:     "search.html",
			SubPages: []string{"/sets", "/sealed"},
		},
		"Newspaper": {
			Name:   "Newspaper",
			Short:  "🗞️",
			Link:   "/newspaper",
			Handle: Newspaper,
			Page:   "news.html",
		},
		"Sleepers": {
			Name:   "Sleepers",
			Short:  "💤",
			Link:   "/sleepers",
			Handle: Sleepers,
			Page:   "sleep.html",
		},
		"Upload": {
			Name:    "Upload",
			Short:   "🚢",
			Link:    "/upload",
			Handle:  Upload,
			Page:    "upload.html",
			CanPOST: true,
		},
		"Global": {
			Name:   "Global",
			Short:  "🌍",
			Link:   "/global",
			Handle: Global,
			Page:   "arbit.html",
		},
		"Arbit": {
			Name:   "Arbitrage",
			Short:  "📈",
			Link:   "/arbit",
			Handle: Arbit,
			Page:   "arbit.html",
		},
		"Reverse": {
			Name:   "Reverse",
			Short:  "📉",
			Link:   "/reverse",
			Handle: Reverse,
			Page:   "arbit.html",
		},
		"Admin": {
			Name:   "Admin",
			Short:  "❌",
			Link:   "/admin",
			Handle: Admin,
			Page:   "admin.html",

			CanPOST:        true,
			AlwaysOnForDev: true,
		},
	}
}

var Config ConfigType

type ConfigType struct {
	Port                   string            `json:"port"`
	DatastorePath          string            `json:"datastore_path"`
	Game                   string            `json:"game"`
	DBAddress              string            `json:"db_address"`
	RedisAddr              string            `json:"redis_addr"`
	DiscordHook            string            `json:"discord_hook"`
	DiscordNotifHook       string            `json:"discord_notif_hook"`
	DiscordInviteLink      string            `json:"discord_invite_link"`
	Affiliate              map[string]string `json:"affiliate"`
	AffiliatesList         []string          `json:"affiliates_list"`
	AffiliatesBuylistList  []string          `json:"affiliates_buylist_list"`
	Api                    map[string]string `json:"api"`
	ApiDemoStores          []string          `json:"api_demo_stores"`
	DiscordToken           string            `json:"discord_token"`
	DiscordAllowList       []string          `json:"discord_allowlist"`
	ArbitDefaultSellers    []string          `json:"arbit_default_sellers"`
	ArbitBlockVendors      []string          `json:"arbit_block_vendors"`
	SearchRetailBlockList  []string          `json:"search_block_list"`
	SearchBuylistBlockList []string          `json:"search_buylist_block_list"`
	SleepersBlockList      []string          `json:"sleepers_block_list"`
	GlobalAllowList        []string          `json:"global_allow_list"`
	GlobalProbeList        []string          `json:"global_probe_list"`
	Patreon                struct {
		Secret map[string]string `json:"secret"`
		Grants []struct {
			Category string `json:"category"`
			Email    string `json:"email"`
			Name     string `json:"name"`
			Tier     string `json:"tier"`
		} `json:"grants"`
	} `json:"patreon"`
	ApiUserSecrets    map[string]string `json:"api_user_secrets"`
	GoogleCredentials string            `json:"google_credentials"`
	Auth              struct {
		Domain          string   `json:"domain"`
		Port            string   `json:"port"`
		SecureCookies   bool     `json:"secure_cookies"`
		CookieDomain    string   `json:"cookie_domain"`
		CSRFSecret      string   `json:"csrf_secret"`
		SignatureTTL    int      `json:"signature_ttl"`
		LoginRateLimit  int      `json:"login_rate_limit"`
		SignupRateLimit int      `json:"signup_rate_limit"`
		APIRateLimit    int      `json:"api_rate_limit"`
		PublicRateLimit int      `json:"public_rate_limit"`
		Prefix          string   `json:"log_prefix"`
		Key             string   `json:"supabase_anon_key"`
		RoleKey         string   `json:"supabase_role_key"`
		Secret          string   `json:"supabase_jwt_secret"`
		Url             string   `json:"supabase_url"`
		ExemptRoutes    []string `json:"exempt_routes"`
		ExemptPrefixes  []string `json:"exempt_prefixes"`
		ExemptSuffixes  []string `json:"exempt_suffixes"`
		AssetsPath      string   `json:"assets_path"`
		ACL             struct {
			Tiers map[string]map[string]map[string]string `json:"tier"`
			Roles map[string]map[string]map[string]string `json:"role"`
		} `json:"acl"`
	} `json:"auth"`
	ACL struct {
		Tiers map[string]map[string]map[string]string `json:"tier"`
		Roles map[string]map[string]map[string]string `json:"role"`
	} `json:"acl"`
	SessionFile string `json:"session_file"`
	Uploader    struct {
		Moxfield string `json:"moxfield"`
	} `json:"uploader"`

	// Disable parallel loading during bootstrap
	SlowStart bool `json:"slow_start"`

	/* The location of the configuation file */
	filePath string
}

var DevMode bool
var SigCheck bool
var SkipInitialRefresh bool
var SkipPrices bool
var BenchMode bool
var LogDir string
var LastUpdate string
var DatabaseLoaded bool
var Sellers []mtgban.Seller
var Vendors []mtgban.Vendor

// Contains all the set value computations shown on sealed products
var Infos map[string]mtgban.InventoryRecord

var SealedEditionsSorted []string
var SealedEditionsList map[string][]EditionEntry
var AllEditionsKeys []string
var AllEditionsMap map[string]EditionEntry
var TreeEditionsKeys []string
var TreeEditionsMap map[string][]EditionEntry
var ReprintsKeys []string
var ReprintsMap map[string][]ReprintEntry

var TotalSets, TotalCards, TotalUnique int

var Newspaper3dayDB *sql.DB
var Newspaper1dayDB *sql.DB

var GoogleDocsClient *http.Client

var banACL BanACL

var authService *AuthService

const (
	DefaultConfigPort    = "8080"
	DefaultDatastorePath = "allprintings5.json"
	DefaultConfigPath    = "config.json"
	DefaultSecret        = "NotVerySecret!"
)

func Favicon(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "img/favicon/favicon.ico")
}

// FileSystem custom file system handler
type FileSystem struct {
	fs http.FileSystem
}

// ServeHTTP implements the http.Handler interface and ensures proper MIME types
func (fs FileSystem) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Get the file path from the request URL, stripping any query parameters
	path := r.URL.Path
	if strings.Contains(path, "?") {
		path = strings.Split(path, "?")[0]
	}

	// Set content type based on file extension before the file is served
	ext := filepath.Ext(path)
	if ext == ".css" {
		// Always set CSS files to text/css
		w.Header().Set("Content-Type", "text/css")
		log.Printf("Serving CSS file: %s with Content-Type: text/css", path)
	} else {
		switch ext {
		case ".js":
			w.Header().Set("Content-Type", "application/javascript")
		case ".png":
			w.Header().Set("Content-Type", "image/png")
		case ".jpg", ".jpeg":
			w.Header().Set("Content-Type", "image/jpeg")
		case ".svg":
			w.Header().Set("Content-Type", "image/svg+xml")
		case ".ico":
			w.Header().Set("Content-Type", "image/x-icon")
		case ".woff":
			w.Header().Set("Content-Type", "font/woff")
		case ".woff2":
			w.Header().Set("Content-Type", "font/woff2")
		}
	}

	// Let the default file server handle the rest
	http.FileServer(fs.fs).ServeHTTP(w, r)
}

// Open opens the file at name from the underlying http.FileSystem
func (fs FileSystem) Open(name string) (http.File, error) {
	// Clean the path to prevent directory traversal
	name = path.Clean(name)

	// Try to open the file
	f, err := fs.fs.Open(name)
	if err != nil {
		return nil, err
	}

	// Check if it's a directory
	stat, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}

	// If it's a directory, try to serve the index.html file
	if stat.IsDir() {
		// Close the directory file
		f.Close()

		// Try to open the index.html file
		indexPath := path.Join(name, "index.html")
		index, err := fs.fs.Open(indexPath)
		if err != nil {
			return nil, err
		}

		// Return the index file wrapped with correct MIME type
		return &FileWithCorrectMimeType{index, indexPath}, nil
	}

	// Return the file wrapped with correct MIME type
	return &FileWithCorrectMimeType{f, name}, nil
}

// FileWithCorrectMimeType wraps http.File to ensure correct MIME type detection
type FileWithCorrectMimeType struct {
	http.File
	path string
}

// Stat returns file info with correct content type
func (f *FileWithCorrectMimeType) Stat() (os.FileInfo, error) {
	stat, err := f.File.Stat()
	if err != nil {
		return nil, err
	}
	return &FileInfoWithCorrectMimeType{stat, f.path}, nil
}

// FileInfoWithCorrectMimeType wraps os.FileInfo to provide content type info
type FileInfoWithCorrectMimeType struct {
	os.FileInfo
	path string
}

// ContentType returns the MIME type based on file extension
func (fi *FileInfoWithCorrectMimeType) ContentType() string {
	ext := filepath.Ext(fi.path)
	switch ext {
	case ".css":
		return "text/css"
	case ".js":
		return "application/javascript"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	case ".svg":
		return "image/svg+xml"
	case ".ico":
		return "image/x-icon"
	case ".woff":
		return "font/woff"
	case ".woff2":
		return "font/woff2"
	case ".ttf":
		return "font/ttf"
	case ".html", ".htm":
		return "text/html"
	case ".json":
		return "application/json"
	default:
		return "application/octet-stream"
	}
}

func genPageNav(activeTab string, r *http.Request, sig string) PageVars {
	pageVars := PageVars{
		Title:        "BAN " + activeTab,
		LastUpdate:   LastUpdate,
		Hash:         BuildCommit,
		ShowLogin:    false,
		ErrorMessage: "",
	}

	if Config.Game != "" {
		// Append which game this site is for
		pageVars.Title += " - " + Config.Game
		// Charts are available only for one game
		pageVars.DisableChart = true
	}

	// Set card back URL based on game
	switch Config.Game {
	case mtgban.GameMagic:
		pageVars.CardBackURL = "https://cards.scryfall.io/back.png"
	case mtgban.GameLorcana:
		pageVars.CardBackURL = "img/backs/lorcana.webp"
	default:
		pageVars.CardBackURL = "img/backs/default.png"
	}

	// Initialize user authentication state
	var session *UserSession
	var isLoggedIn bool
	var userEmail, userTier string

	// Try to get session if auth service is available
	if authService != nil && authService.SessionManager != nil {
		session, _ = authService.SessionManager.GetSession(r)
	}

	// Check authentication status
	if session != nil && !time.Now().After(session.ExpiresAt) {
		// Valid session
		isLoggedIn = true
		userEmail = session.Email
		userTier = session.Tier
	} else if sig != "" {
		// Fallback to signature-based auth if session not available
		exp := GetParamFromSig(sig, "Expires")
		if exp != "" {
			expires, _ := strconv.ParseInt(exp, 10, 64)
			if expires > time.Now().Unix() || (DevMode && !SigCheck) {
				userEmail = GetParamFromSig(sig, "UserEmail")
				userTier = GetParamFromSig(sig, "UserTier")
				isLoggedIn = userEmail != ""
			} else {
				pageVars.ErrorMessage = ErrMsgExpired
			}
		}
	}

	// Update page variables
	pageVars.IsLoggedIn = isLoggedIn
	pageVars.UserEmail = userEmail
	pageVars.UserTier = userTier

	if !isLoggedIn {
		pageVars.ShowLogin = true
	}

	// Initialize navigation
	if DefaultNav != nil {
		pageVars.Nav = make([]NavElem, len(DefaultNav))
		copy(pageVars.Nav, DefaultNav)
	} else {
		pageVars.Nav = []NavElem{}
	}

	// Add navigation items
	if OrderNav != nil && ExtraNavs != nil {
		for _, feat := range OrderNav {
			navItem, exists := ExtraNavs[feat]
			if !exists || navItem == nil {
				continue
			}

			// Show if public or user has permission
			showNavItem := navItem.NoAuth

			if isLoggedIn && !showNavItem {
				if authService != nil && authService.PermissionManager != nil {
					showNavItem = authService.PermissionManager.HasPermission(session, feat)
				} else {
					// Fallback to signature permissions
					param := GetParamFromSig(sig, feat)
					allowed, _ := strconv.ParseBool(param)
					showNavItem = allowed || (DevMode && (navItem.AlwaysOnForDev || !SigCheck))
				}
			}

			if showNavItem {
				pageVars.Nav = append(pageVars.Nav, *navItem)
			}
		}
	}

	// Set active tab
	mainNavIndex := -1
	for i := range pageVars.Nav {
		if pageVars.Nav[i].Name == activeTab {
			mainNavIndex = i
			break
		}
	}

	if mainNavIndex >= 0 && mainNavIndex < len(pageVars.Nav) {
		pageVars.Nav[mainNavIndex].Active = true
		pageVars.Nav[mainNavIndex].Class = "active"

		// Add beta warning if applicable
		if pageVars.ShowLogin && pageVars.Nav[mainNavIndex].NoAuth {
			extra := NavElem{
				Active: true,
				Class:  "beta",
				Short:  "Beta Public Access",
				Link:   "javascript:void(0)",
			}
			pageVars.Nav = append(pageVars.Nav, extra)
		}
	}

	return pageVars
}

func loadVars(cfg, port, datastore string) error {
	// Load from config file
	file, err := os.Open(cfg)
	if !DevMode && err != nil {
		return err
	}
	if err == nil {
		defer file.Close()

		err = json.NewDecoder(file).Decode(&Config)
		if err != nil {
			return err
		}
	}

	// Load from command line
	if port != "" {
		Config.Port = port
	}
	if Config.Port == "" {
		Config.Port = DefaultConfigPort
	}

	if datastore != "" {
		Config.DatastorePath = datastore
	}
	if Config.DatastorePath == "" {
		if Config.Game != "" {
			return errors.New("no datastore specified for non-default game")
		}
		Config.DatastorePath = DefaultDatastorePath
	}

	// Load from env
	v := os.Getenv("BAN_SECRET")
	if v == "" {
		log.Printf("BAN_SECRET not set, using a default one")
		os.Setenv("BAN_SECRET", DefaultSecret)
	}

	InventoryDir = path.Join("cache_inv", Config.Game)
	BuylistDir = path.Join("cache_bl", Config.Game)

	return nil
}

func openDBs() (err error) {
	Newspaper3dayDB, err = sql.Open("mysql", Config.DBAddress+"/three_day_newspaper")
	if err != nil {
		return err
	}
	Newspaper1dayDB, err = sql.Open("mysql", Config.DBAddress+"/newspaper")
	if err != nil {
		return err
	}
	return nil
}

func loadGoogleCredentials(credentials string) (*http.Client, error) {
	data, err := os.ReadFile(credentials)
	if err != nil {
		return nil, err
	}

	conf, err := google.JWTConfigFromJSON(data, spreadsheet.Scope)
	if err != nil {
		return nil, err
	}

	return conf.Client(context.Background()), nil
}

// A specialized middleware to ensure CSS files are served with the correct MIME type
func cssMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if this is a request for a CSS file (regardless of query parameters)
		if strings.HasSuffix(strings.Split(r.URL.Path, "?")[0], ".css") {
			// Force the Content-Type header for CSS files
			w.Header().Set("Content-Type", "text/css")
			log.Printf("CSS middleware: serving %s with Content-Type: text/css", r.URL.Path)
		}

		// Call the next handler
		next.ServeHTTP(w, r)
	})
}

func main() {
	flag.StringVar(&Config.filePath, "cfg", DefaultConfigPath, "Load configuration file")
	port := flag.String("port", "", "Override server port")
	datastore := flag.String("ds", "", "Override datastore path")
	flag.BoolVar(&DevMode, "dev", false, "Enable developer mode")
	sigCheck := flag.Bool("sig", false, "Enable signature verification")
	skipInitialRefresh := flag.Bool("skip", true, "Skip initial refresh")
	flag.BoolVar(&SkipPrices, "noload", false, "Do not load price data")
	flag.StringVar(&LogDir, "log", "logs", "Directory for scrapers logs")

	flag.Parse()

	// Initial state
	SkipInitialRefresh = false
	SigCheck = true
	if DevMode {
		SigCheck = *sigCheck
		SkipInitialRefresh = *skipInitialRefresh
	}
	// Load necessary environmental variables
	err := loadVars(Config.filePath, *port, *datastore)
	if err != nil {
		log.Fatalln("unable to load config file:", err)
	}

	// Create necessary directories
	_, err = os.Stat(LogDir)
	if errors.Is(err, os.ErrNotExist) {
		err = os.MkdirAll(LogDir, 0700)
	}
	if err != nil {
		log.Fatalln("unable to create necessary folders", err)
	}
	LogPages = map[string]*log.Logger{}

	// Initialize Google client
	GoogleDocsClient, err = loadGoogleCredentials(Config.GoogleCredentials)
	if err != nil {
		if DevMode {
			log.Println("error creating a Google client:", err)
		} else {
			log.Fatalln("error creating a Google client:", err)
		}
	}

	// Open databases
	err = openDBs()
	if err != nil {
		if DevMode {
			log.Println("error opening databases:", err)
		} else {
			log.Fatalln("error opening databases:", err)
		}
	}

	authConfig := AuthConfig{
		Domain:          Config.Auth.Domain,
		Port:            Config.Auth.Port,
		SecureCookies:   Config.Auth.SecureCookies,
		CookieDomain:    Config.Auth.CookieDomain,
		CSRFSecret:      Config.Auth.CSRFSecret,
		SignatureTTL:    time.Duration(Config.Auth.SignatureTTL) * time.Second,
		LoginRateLimit:  Config.Auth.LoginRateLimit,
		SignupRateLimit: Config.Auth.SignupRateLimit,
		APIRateLimit:    Config.Auth.APIRateLimit,
		PublicRateLimit: Config.Auth.PublicRateLimit,
		SupabaseRoleKey: Config.Auth.RoleKey,
		SupabaseURL:     Config.Auth.Url,
		SupabaseAnonKey: Config.Auth.Key,
		SupabaseSecret:  Config.Auth.Secret,
		LogPrefix:       Config.Auth.Prefix,
		ExemptRoutes:    Config.Auth.ExemptRoutes,
		ExemptPrefixes:  Config.Auth.ExemptPrefixes,
		ExemptSuffixes:  Config.Auth.ExemptSuffixes,
		DebugMode:       DevMode,
		AssetsPath:      Config.Auth.AssetsPath,
		ACL: ACLConfig{
			Tiers: Config.Auth.ACL.Tiers,
			Roles: Config.Auth.ACL.Roles,
		},
	}

	authService, err := NewAuthService(authConfig)

	if err != nil {
		log.Fatalf("Failed to create auth service: %v", err)
	}

	if err := authService.Initialize(); err != nil {
		log.Fatalf("Failed to initialize auth service: %v", err)
	}

	// Load the ACL
	err = authService.GetBanACL(&banACL)
	if err != nil {
		authService.Logger.Println("error loading ACL:", err)
	}

	authService.BanACL = &banACL

	// Start background data loading
	go func() {
		var err error

		log.Println("Loading", Config.DatastorePath)
		err = loadDatastore()
		if err != nil {
			log.Fatalln("error loading datastore:", err)
		}

		loadScrapers()

		DatabaseLoaded = true

		// Nothing else to do if hacking around
		if DevMode {
			return
		}

		// Set up new refreshes as needed
		c := cron.New()

		// Times are in UTC

		// Refresh everything daily at 2am (after MTGJSON update)
		c.AddFunc("35 11 * * *", loadScrapers)
		// Refresh CK at every 3th hour, 40 minutes past the hour (7 times in total)
		c.AddFunc("40 */3 * * *", reloadCK)
		// Refresh TCG at every 3th hour, 45 minutes past the hour (7 times in total)
		c.AddFunc("45 */3 * * *", reloadTCG)
		// Refresh SCG at every 8th hour, 50 minutes past the hour (3 times in total)
		c.AddFunc("50 */6 * * *", reloadSCG)
		// Refresh CSI & MP a second time
		c.AddFunc("25 23 * * *", reloadCSI)
		c.AddFunc("20 23 * * *", reloadMP)

		// MTGJSON builds go live 7am EST, pull the update 30 minutes after
		c.AddFunc("30 11 * * *", func() {
			log.Println("Reloading MTGJSONv5")
			err := loadDatastore()
			if err != nil {
				log.Println(err)
			}
		})

		// Clean up the csv cache every 3 days
		c.AddFunc("0 0 */3 * *", deleteOldCache)

		c.Start()
	}()

	err = setupDiscord()
	if err != nil {
		log.Println("Error connecting to discord", err)
	}

	// Set seed in case we need to do random operations
	rand.Seed(time.Now().UnixNano())

	// Serve static files with specialized CSS handling
	cssHandler := cssMiddleware(&FileSystem{http.Dir("css")})
	http.Handle("/css/", http.StripPrefix("/css/", cssHandler))
	http.Handle("/img/", http.StripPrefix("/img/", &FileSystem{http.Dir("img")}))
	http.Handle("/js/", http.StripPrefix("/js/", &FileSystem{http.Dir("js")}))

	// Custom redirects
	http.HandleFunc("/go/", Redirect)
	http.HandleFunc("/random", RandomSearch)
	http.HandleFunc("/randomsealed", RandomSealedSearch)
	http.HandleFunc("/discord", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, Config.DiscordInviteLink, http.StatusFound)
	})

	// Home page - no authentication required
	http.Handle("/", (http.HandlerFunc(Home)))

	// Register routes for each navigation item
	for key, nav := range ExtraNavs {
		// Set up logging
		logFile, err := logfile.New(&logfile.LogFile{
			FileName:    path.Join(LogDir, key+".log"),
			MaxSize:     500 * 1024,
			Flags:       logfile.FileOnly,
			OldVersions: 2,
		})
		if err != nil {
			log.Printf("Failed to create logFile for %s: %s", key, err)
			LogPages[key] = log.New(os.Stderr, "", log.LstdFlags)
		} else {
			LogPages[key] = log.New(logFile, "", log.LstdFlags)
		}

		_, ExtraNavs[key].NoAuth = Config.Auth.ACL.Tiers["free"][key]

		// Use the new auth service for handling routes
		var handler http.Handler
		if nav.NoAuth {
			// No authentication required
			handler = http.HandlerFunc(nav.Handle)
		} else {
			// Use AuthWrapper middleware
			handler = http.HandlerFunc((nav.Handle))
		}

		http.Handle(nav.Link, handler)

		// Add any additional endpoints to it
		for _, subPage := range nav.SubPages {
			http.Handle(subPage, handler)
		}
	}

	// API endpoints
	http.Handle("/search/oembed", (http.HandlerFunc(Search)))
	http.Handle("/api/mtgban/", (http.HandlerFunc(PriceAPI)))
	http.Handle("/api/mtgjson/ck.json", (http.HandlerFunc(API)))
	http.Handle("/api/tcgplayer/", (http.HandlerFunc(TCGHandler)))
	http.Handle("/api/search/", (http.HandlerFunc(SearchAPI)))
	http.Handle("/api/cardkingdom/pricelist.json", (http.HandlerFunc(CKMirrorAPI)))
	http.Handle("/api/suggest", (http.HandlerFunc(SuggestAPI)))
	http.Handle("/api/opensearch.xml", (http.HandlerFunc(OpenSearchDesc)))
	http.Handle("/api/search-json/", http.HandlerFunc(SearchAPIJSON))

	// Favicon handler
	http.HandleFunc("/favicon.ico", Favicon)
	http.Handle("/img/opensearch.xml", (http.HandlerFunc(OpenSearchDesc)))

	// Create and start the server
	srv := &http.Server{
		Addr: ":" + Config.Port,
	}

	// Handle graceful shutdown
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

func render(w http.ResponseWriter, tmpl string, pageVars PageVars) {
	funcMap := template.FuncMap{
		"inc": func(i, j int) int {
			return i + j
		},
		"dec": func(i, j int) int {
			return i - j
		},
		"mul": func(i float64, j int) float64 {
			return i * float64(j)
		},
		"mulf": func(i, j float64) float64 {
			return i * j
		},
		"print_perc": func(s string) string {
			n, _ := strconv.ParseFloat(s, 64)
			return fmt.Sprintf("%0.2f %%", n*100)
		},
		"print_price": func(s string) string {
			n, _ := strconv.ParseFloat(s, 64)
			return fmt.Sprintf("$ %0.2f", n)
		},
		"scraper_name": func(s string) string {
			return ScraperNames[s]
		},
		"slice_has": func(s []string, p string) bool {
			return slices.Contains(s, p)
		},
		"has_prefix": func(s, p string) bool {
			return strings.HasPrefix(s, p)
		},
		"contains": func(s, p string) bool {
			return strings.Contains(s, p)
		},
		"triple_column_start": func(i int, length int) bool {
			return i == 0 || i == length/3 || i == length*2/3
		},
		"triple_column_end": func(i int, length int) bool {
			return i == length/3-1 || i == length*2/3-1 || i == length-1
		},
		"load_partner": func(s string) string {
			return Config.Affiliate[s]
		},
		"uuid2ckid": func(s string) string {
			bl, err := findVendorBuylist("CK")
			if err != nil {
				return ""
			}
			entries, found := bl[s]
			if !found {
				return ""
			}
			return entries[0].OriginalId
		},
		"uuid2tcgid": func(s string) string {
			return findTCGproductId(s)
		},
		"isSussy": func(m map[string]float64, s string) bool {
			_, found := m[s]
			return found
		},
		"color2hex": func(s string) string {
			color, found := colorValues[s]
			if !found {
				return "#111111"
			}
			return color
		},
		"credit_factor": func(s string) float64 {
			for _, vendor := range Vendors {
				if vendor != nil && vendor.Info().Shorthand == s {
					return vendor.Info().CreditMultiplier
				}
			}
			return 0
		},
		"tcg_market_price": func(s string) float64 {
			return getTCGMarketPrice(s)
		},
		"base64enc": func(s string) string {
			return base64.StdEncoding.EncodeToString([]byte(s))
		},
		"lower": strings.ToLower,
	}

	// Give each template a name
	name := path.Base(tmpl)
	// Prefix the name passed in with templates/
	tmplPath := fmt.Sprintf("templates/%s", tmpl)
	navbarPath := "templates/navbar.html"

	// Parse the template file held in the templates folder, add any Funcs to parsing
	t, err := template.New(name).Funcs(funcMap).ParseFiles(tmplPath, navbarPath)
	if err != nil {
		log.Print("template parsing error: ", err)
		return
	}

	// Execute the template and pass in the variables to fill the gaps
	err = t.Execute(w, pageVars)
	if err != nil {
		log.Print("template executing error: ", err)
	}
}
