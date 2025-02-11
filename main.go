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
	"runtime"
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
	"github.com/mtgban/mtgban-website/auth/models"
	"github.com/mtgban/mtgban-website/auth/repo"
	"github.com/mtgban/mtgban-website/auth/service"
)

const (
	ErrTooMany    = "Too many requests"
	ErrUnauth     = "Unauthorized"
	ErrBanned     = "This feature is BANned"
	ErrMsg        = "Please sign in to access this feature"
	ErrMsgPlus    = "You need higher permissions to access this feature"
	ErrMsgDenied  = "Something went wrong while accessing this page"
	ErrMsgExpired = "Your session has expired, please sign in again"
	ErrMsgRestart = "Website is restarting, please try again in a few minutes"
	ErrMsgUseAPI  = "Slow down, you're making too many requests! For heavy data use consider the BAN API"
)

type PageVars struct {
	Pagination

	Nav      []NavElem
	ExtraNav []NavElem

	Hash string

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

var authService *service.AuthService

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
	DevSellers             []string          `json:"dev_sellers"`
	ArbitDefaultSellers    []string          `json:"arbit_default_sellers"`
	ArbitBlockVendors      []string          `json:"arbit_block_vendors"`
	SearchRetailBlockList  []string          `json:"search_block_list"`
	SearchBuylistBlockList []string          `json:"search_buylist_block_list"`
	SleepersBlockList      []string          `json:"sleepers_block_list"`
	GlobalAllowList        []string          `json:"global_allow_list"`
	GlobalProbeList        []string          `json:"global_probe_list"`
	ApiUserSecrets         map[string]string `json:"api_user_secrets"`
	GoogleCredentials      string            `json:"google_credentials"`

	ACL map[string]models.UserRole `json:"acl"`

	Uploader struct {
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

const (
	DefaultConfigPort = "8080"
	DefaultSecret     = "NotVerySecret!"
)

func recoverPanic(r *http.Request, w http.ResponseWriter) {
	errPanic := recover()
	if errPanic != nil {
		log.Println("panic occurred:", errPanic)

		// Restrict stack size to fit into discord message
		buf := make([]byte, 1<<16)
		runtime.Stack(buf, true)
		if len(buf) > 1024 {
			buf = buf[:1024]
		}

		var msg string
		err, ok := errPanic.(error)
		if ok {
			msg = err.Error()
		} else {
			msg = "unknown error"
		}
		ServerNotify("panic", msg, true)
		ServerNotify("panic", string(buf))
		ServerNotify("panic", "source request: "+r.URL.String())

		http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func noSigning(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer recoverPanic(r, w)
		next.ServeHTTP(w, r)
	})
}

func enforceAPISigning(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer recoverPanic(r, w)

		w.Header().Add("RateLimit-Limit", fmt.Sprint(APIRequestsPerSec))
		w.Header().Add("Content-Type", "application/json")

		token := extractToken(r)
		if token == "" {
			http.Error(w, `{"error": "missing token"}`, http.StatusUnauthorized)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		user, err := authService.GetUserFromToken(ctx, token)
		if err != nil {
			http.Error(w, `{"error": "invalid or expired token"}`, http.StatusUnauthorized)
			return
		}

		if !authService.HasRequiredRole(user.Role, models.RoleApi) {
			http.Error(w, `{"error": "insufficient permissions"}`, http.StatusForbidden)
			return
		}

		ctx = context.WithValue(ctx, models.UserContextKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func enforceSigning(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer recoverPanic(r, w)

		token := extractToken(r)
		pageVars := genPageNav("Error", token)

		if !UserRateLimiter.allow(getUserEmail(token)) && r.URL.Path != "/admin" {
			pageVars.Title = ErrTooMany
			pageVars.ErrorMessage = ErrMsgUseAPI
			render(w, "home.html", pageVars)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		user, err := authService.GetUserFromToken(ctx, token)
		if err != nil {
			pageVars.Title = ErrUnauth
			pageVars.ErrorMessage = ErrMsg
			render(w, "home.html", pageVars)
			return
		}

		for _, navName := range OrderNav {
			nav := ExtraNavs[navName]
			if r.URL.Path == nav.Link {
				if !authService.HasRequiredRole(user.Role, getRequiredRole(navName)) {
					pageVars = genPageNav(nav.Name, token)
					pageVars.Title = ErrBanned
					pageVars.ErrorMessage = ErrMsgPlus
					render(w, nav.Page, pageVars)
					return
				}
				break
			}
		}

		ctx = context.WithValue(ctx, models.UserContextKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Helper functions for auth
func extractToken(r *http.Request) string {
	token := r.Header.Get("Authorization")
	if token != "" {
		return strings.TrimPrefix(token, "Bearer ")
	}

	token = r.URL.Query().Get("token")
	if token != "" {
		return token
	}

	cookie, err := r.Cookie("MTGBAN")
	if err == nil {
		return cookie.Value
	}

	return ""
}

func getUserEmail(token string) string {
	if token == "" {
		return ""
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	user, err := authService.GetUserFromToken(ctx, token)
	if err != nil {
		return ""
	}

	return user.Email
}

func getRequiredRole(navName string) models.UserRole {
	role, exists := Config.ACL[navName]
	if !exists {
		return models.RoleFree
	}
	return role
}

func Favicon(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "img/favicon/favicon.ico")
}

// FileSystem custom file system handler
type FileSystem struct {
	httpfs http.FileSystem
}

// Open opens file
func (fs *FileSystem) Open(path string) (http.File, error) {
	f, err := fs.httpfs.Open(path)
	if err != nil {
		return nil, err
	}

	s, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if s.IsDir() {
		index := strings.TrimSuffix(path, "/") + "/index.html"
		_, err := fs.httpfs.Open(index)
		if err != nil {
			return nil, err
		}
	}

	return f, nil
}

func genPageNav(activeTab, token string) PageVars {
	pageVars := PageVars{
		Title:      "BAN " + activeTab,
		LastUpdate: LastUpdate,
		Hash:       BuildCommit,
	}

	if Config.Game != "" {
		pageVars.Title += " - " + Config.Game
		pageVars.DisableChart = true
	}

	switch Config.Game {
	case mtgban.GameMagic:
		pageVars.CardBackURL = "https://cards.scryfall.io/back.png"
	case mtgban.GameLorcana:
		pageVars.CardBackURL = "img/backs/lorcana.webp"
	default:
		panic("no pageVars.CardBackURL set")
	}

	// Allocate a new navigation bar
	pageVars.Nav = make([]NavElem, len(DefaultNav))
	copy(pageVars.Nav, DefaultNav)

	ctx := context.Background()
	user, err := authService.GetUserFromToken(ctx, token)
	if err == nil && user != nil {
		for _, feat := range OrderNav {
			if authService.HasRequiredRole(user.Role, getRequiredRole(feat)) ||
				(DevMode && !SigCheck) ||
				ExtraNavs[feat].NoAuth {
				pageVars.Nav = append(pageVars.Nav, *ExtraNavs[feat])
			}
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

	return pageVars
}

func loadVars(cfg string) error {
	// Load from command line
	file, err := os.Open(cfg)
	if err != nil {
		return err
	}
	defer file.Close()

	d := json.NewDecoder(file)
	err = d.Decode(&Config)
	if err != nil {
		return err
	}

	Config.filePath = cfg

	if Config.Port == "" {
		Config.Port = DefaultConfigPort
	}

	if Config.DatastorePath == "" {
		return errors.New("missing datastore path")
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

const DefaultConfigPath = "config.json"

func main() {
	config := flag.String("cfg", DefaultConfigPath, "Load configuration file")
	devMode := flag.Bool("dev", false, "Enable developer mode")
	sigCheck := flag.Bool("sig", false, "Enable signature verification")
	skipInitialRefresh := flag.Bool("skip", true, "Skip initial refresh")
	noload := flag.Bool("noload", false, "Do not load price data")
	logdir := flag.String("log", "logs", "Directory for scrapers logs")
	port := flag.String("port", "", "Override server port")
	datastore := flag.String("ds", "", "Override datastore path")
	supabaseURL := os.Getenv("SUPABASE_URL")
	supabaseKey := os.Getenv("SUPABASE_ANON_KEY")

	flag.Parse()
	DevMode = *devMode
	SkipPrices = *noload
	SigCheck = true
	if DevMode {
		SigCheck = *sigCheck
		SkipInitialRefresh = *skipInitialRefresh
	}
	LogDir = *logdir

	// load necessary environmental variables
	err := loadVars(*config)
	if err != nil {
		log.Fatalln("unable to load config file:", err)
	}
	if *port != "" {
		Config.Port = *port
	}
	if *datastore != "" {
		Config.DatastorePath = *datastore
	}

	_, err = os.Stat(LogDir)
	if errors.Is(err, os.ErrNotExist) {
		err = os.MkdirAll(LogDir, 0700)
	}
	if err != nil {
		log.Fatalln("unable to create necessary folders", err)
	}
	LogPages = map[string]*log.Logger{}

	GoogleDocsClient, err = loadGoogleCredentials(Config.GoogleCredentials)
	if err != nil {
		if DevMode {
			log.Println("error creating a Google client:", err)
		} else {
			log.Fatalln("error creating a Google client:", err)
		}
	}

	err = openDBs()
	if err != nil {
		if DevMode {
			log.Println("error opening databases:", err)
		} else {
			log.Fatalln("error opening databases:", err)
		}
	}

	client := repo.InitSupabaseClient(supabaseURL, supabaseKey)
	authService, err = service.NewAuthService(client, nil, nil)
	if err != nil {
		if DevMode {
			log.Println("Failed to initialize auth service:", err)
		} else {
			log.Fatalln("Failed to initialize auth service:", err)
		}
	}

	// load website up
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

		// Slean up the csv cache every 3 days
		c.AddFunc("0 0 */3 * *", deleteOldCache)

		c.Start()
	}()

	err = setupDiscord()
	if err != nil {
		log.Println("Error connecting to discord", err)
	}

	// Set seed in case we need to do random operations
	rand.Seed(time.Now().UnixNano())

	// serve everything in known folders as a file
	http.Handle("/css/", http.StripPrefix("/css/", http.FileServer(&FileSystem{http.Dir("css")})))
	http.Handle("/img/", http.StripPrefix("/img/", http.FileServer(&FileSystem{http.Dir("img")})))
	http.Handle("/js/", http.StripPrefix("/js/", http.FileServer(&FileSystem{http.Dir("js")})))

	// custom redirector
	http.HandleFunc("/go/", Redirect)
	http.HandleFunc("/random", RandomSearch)
	http.HandleFunc("/randomsealed", RandomSealedSearch)
	http.HandleFunc("/discord", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, Config.DiscordInviteLink, http.StatusFound)
	})

	// when navigating to /home it should serve the home page
	http.Handle("/", noSigning(http.HandlerFunc(Home)))

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

		role, hasRole := Config.ACL[key]
		ExtraNavs[key].NoAuth = !hasRole || role == models.RoleFree

		// Set up the handler
		handler := enforceSigning(http.HandlerFunc(nav.Handle))
		if nav.NoAuth {
			handler = noSigning(http.HandlerFunc(nav.Handle))
		}
		http.Handle(nav.Link, handler)

		// Add any additional endpoints to it
		for _, subPage := range nav.SubPages {
			http.Handle(subPage, handler)
		}
	}
	http.Handle("/search/oembed", noSigning(http.HandlerFunc(Search)))
	http.Handle("/api/mtgban/", enforceAPISigning(http.HandlerFunc(PriceAPI)))
	http.Handle("/api/mtgjson/ck.json", enforceAPISigning(http.HandlerFunc(API)))
	http.Handle("/api/tcgplayer/", enforceSigning(http.HandlerFunc(TCGHandler)))
	http.Handle("/api/search/", enforceSigning(http.HandlerFunc(SearchAPI)))
	http.Handle("/api/cardkingdom/pricelist.json", noSigning(http.HandlerFunc(CKMirrorAPI)))
	http.Handle("/api/suggest", noSigning(http.HandlerFunc(SuggestAPI)))
	http.Handle("/api/opensearch.xml", noSigning(http.HandlerFunc(OpenSearchDesc)))
	// compat
	http.Handle("/img/opensearch.xml", noSigning(http.HandlerFunc(OpenSearchDesc)))

	http.HandleFunc("/favicon.ico", Favicon)

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
		if err := authService.Shutdown(ctx); err != nil {
			log.Printf("Error shutting down auth service: %v", err)
		}
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
	}

	// Give each template a name
	name := path.Base(tmpl)
	// Prefix the name passed in with templates/
	tmpl = fmt.Sprintf("templates/%s", tmpl)

	// Parse the template file held in the templates folder, add any Funcs to parsing
	t, err := template.New(name).Funcs(funcMap).ParseFiles(tmpl)
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
