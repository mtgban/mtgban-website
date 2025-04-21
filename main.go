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
	UserRole        string
	UserTier        string

	IsImpersonating     bool
	ImpersonationTarget string
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

// optional list of keys that are guaranteed not to be user-editable if present
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
			Name:           "Admin",
			Short:          "❌",
			Link:           "/admin",
			Handle:         Admin,
			Page:           "admin.html",
			CanPOST:        true,
			AlwaysOnForDev: true,
		},
	}
}

var Config ConfigType

type ConfigType struct {
	Port                   string            `json:"port"`
	DefaultHost            string            `json:"default_host"`
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
	Auth              AuthConfig        `json:"auth"`
	ACL               ACLConfig         `json:"acl"`
	Uploader          struct {
		Moxfield string `json:"moxfield"`
	} `json:"uploader"`

	// Disable parallel loading during bootstrap
	SlowStart bool `json:"slow_start"`

	/* The location of the configuation file */
	filePath string
}

type ACLConfig struct {
	Tiers map[string]map[string]map[string]string `json:"tier"`
	Roles map[string]map[string]map[string]string `json:"role"`
}

var DevMode bool
var DebugMode bool
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
	// Set content type based on file extension
	ext := filepath.Ext(path)
	if mimeType := getMimeType(ext); mimeType != "" {
		w.Header().Set("Content-Type", mimeType)
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
		f.Close()
		indexPath := path.Join(name, "index.html")
		if index, err := fs.fs.Open(indexPath); err == nil {
			return index, nil
		}
		return nil, err
	}

	return f, nil
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
	if Config.Auth.DebugMode == "true" {
		DebugMode = true
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

func main() {
	flag.StringVar(&Config.filePath, "cfg", DefaultConfigPath, "Load configuration file")
	port := flag.String("port", "", "Override server port")
	datastore := flag.String("ds", "", "Override datastore path")
	flag.BoolVar(&DevMode, "dev", false, "Enable developer mode")
	flag.BoolVar(&DebugMode, "debug", false, "Enable debug mode")
	sigCheck := flag.Bool("sig", false, "Enable signature verification")
	skipInitialRefresh := flag.Bool("skip", true, "Skip initial refresh")
	flag.BoolVar(&SkipPrices, "noload", false, "Do not load price data")
	flag.StringVar(&LogDir, "log", "logs", "Directory for scrapers logs")

	// parse flags
	flag.Parse()

	// Load necessary environmental variables
	err := loadVars(Config.filePath, *port, *datastore)
	if err != nil {
		log.Fatalln("unable to load config file:", err)
	}

	// Apply overrides
	if *port != "" {
		Config.Port = *port
	}
	if *datastore != "" {
		Config.DatastorePath = *datastore
	}

	// Initial state settings
	SkipInitialRefresh = false
	SigCheck = true
	if DevMode {
		SigCheck = *sigCheck
		SkipInitialRefresh = *skipInitialRefresh
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

	// Precompute all nav states
	precomputeNavigation()

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

	// Initialize auth service
	authConfig := initAuthConfig()

	authService, err := NewAuthService(authConfig, ExtraNavs)
	if err != nil {
		log.Fatalf("Failed to create auth service: %v", err)
	}

	// Load the BanACL data into the authService
	err = authService.LoadBanACL()
	if err != nil {
		authService.Logger.Fatalf("CRITICAL: Failed to load BAN ACL: %v. Authorization checks may fail.", err)
	}

	banACL = BanACL{Users: make(map[string]*BanUser)}
	if authService.ACL != nil {
		for _, user := range authService.ACL.Users {
			banACL.Users[user.UserData.Email] = user
		}
	}

	// setup secret rotation
	authService.CSRF.RotateSecret(time.Duration(Config.Auth.CSRFInterval) * time.Hour)

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
	rand.New(rand.NewSource(time.Now().UnixNano()))

	// setup http server with authService
	srv := setupServer(authService)

	// Wait for shutdown signal
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		err := srv.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()

	<-done

	// Perform graceful shutdown
	gracefulShutdown(srv)

}

// gracefulShutdown performs a graceful server shutdown
func gracefulShutdown(srv *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer func() {
		ServerNotify("shutdown", "Server cleaning up...")
		cleanupDiscord()
		cancel()
	}()

	err := srv.Shutdown(ctx)
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
