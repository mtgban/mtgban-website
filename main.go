package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"

	"database/sql"

	storage "cloud.google.com/go/storage"
	_ "github.com/go-sql-driver/mysql"
	secrets "github.com/mtgban/mtgban-website/secretsmanager"

	bigquery "cloud.google.com/go/bigquery"
	firebase "firebase.google.com/go/v4"
	"github.com/leemcloughlin/logfile"
	"golang.org/x/exp/slices"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
	"gopkg.in/Iwark/spreadsheet.v2"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
)

type PageVars struct {
	Nav      []NavElem
	ExtraNav []NavElem

	PatreonId    string
	PatreonURL   string
	PatreonLogin bool
	ShowPromo    bool
	EnableFree   bool

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

	CanShowAll       bool
	CleanSearchQuery string

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

	Page         string
	ToC          []NewspaperPage
	Headings     []Heading
	Cards        []GenericCard
	Table        [][]string
	HasReserved  bool
	HasStocks    bool
	HasSypList   bool
	IsOneDay     bool
	CanSwitchDay bool
	TotalIndex   int
	CurrentIndex int
	PrevIndex    int
	NextIndex    int
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
	Tables       [][][]string
	CurrentTime  time.Time
	Uptime       string
	DiskStatus   string
	MemoryStatus string
	LatestHash   string
	CacheSize    int
	Tiers        []string
	DemoKey      string

	AxisLabels  []string
	Datasets    []*Dataset
	ChartID     string
	Alternative string
	StocksURL   string
	AltEtchedId string

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

	OptimizedEditions map[string][]OptimizedUploadEntry
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
}

var startTime = time.Now()

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
	"SearchSealed",
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
var ExtraNavs map[string]NavElem

func init() {
	ExtraNavs = map[string]NavElem{
		"Search": NavElem{
			Name:   "Search",
			Short:  "🔍",
			Link:   "/search",
			Handle: Search,
			Page:   "search.html",
		},
		"Newspaper": NavElem{
			Name:   "Newspaper",
			Short:  "🗞️",
			Link:   "/newspaper",
			Handle: Newspaper,
			Page:   "news.html",
		},
		"Sleepers": NavElem{
			Name:   "Sleepers",
			Short:  "💤",
			Link:   "/sleepers",
			Handle: Sleepers,
			Page:   "sleep.html",
		},
		"Upload": NavElem{
			Name:    "Upload",
			Short:   "🚢",
			Link:    "/upload",
			Handle:  Upload,
			Page:    "upload.html",
			CanPOST: true,
		},
		"Global": NavElem{
			Name:   "Global",
			Short:  "🌍",
			Link:   "/global",
			Handle: Global,
			Page:   "arbit.html",
		},
		"Arbit": NavElem{
			Name:   "Arbitrage",
			Short:  "📈",
			Link:   "/arbit",
			Handle: Arbit,
			Page:   "arbit.html",
		},
		"Reverse": NavElem{
			Name:   "Reverse",
			Short:  "📉",
			Link:   "/reverse",
			Handle: Reverse,
			Page:   "arbit.html",
		},
		"Admin": NavElem{
			Name:   "Admin",
			Short:  "❌",
			Link:   "/admin",
			Handle: Admin,
			Page:   "admin.html",

			AlwaysOnForDev: true,
		},
	}
}

var Config AppConfig

type AppConfig struct {
	Port                   string            `json:"port"`
	DBAddress              string            `json:"db_address"`
	RedisAddr              string            `json:"redis_addr"`
	DiscordHook            string            `json:"discord_hook"`
	DiscordNotifHook       string            `json:"discord_notif_hook"`
	DiscordInviteLink      string            `json:"discord_invite_link"`
	Affiliate              map[string]string `json:"affiliate"`
	AffiliatesList         []string          `json:"affiliates_list"`
	Api                    map[string]string `json:"api"`
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
	Patreon                struct {
		Secret map[string]string `json:"secret"`
		Emails map[string]string `json:"emails"`
	} `json:"patreon"`
	ApiUserSecrets         map[string]string  `json:"api_user_secrets"`
	GoogleCredentials      string             `json:"google_credentials"`
	GCSServiceAccount      secrets.SecretInfo `json:"gcsServiceAccount"`
	FirebaseServiceAccount secrets.SecretInfo `json:"firebaseServiceAccount"`
	BigQueryServiceAccount secrets.SecretInfo `json:"bigQueryServiceAccount"`

	ACL map[string]map[string]map[string]string `json:"acl"`

	FreeEnable   bool   `json:"free_enable"`
	FreeLevel    string `json:"free_level"`
	FreeHostname string `json:"free_hostname"`

	Uploader struct {
		ServiceAccount string `json:"service_account"`
		BucketName     string `json:"bucket_name"`
		ProjectID      string `json:"project_id"`
		DatasetID      string `json:"dataset_id"`
	} `json:"uploader"`

	Scrapers map[string][]struct {
		HasRedis   bool   `json:"has_redis,omitempty"`
		RedisIndex int    `json:"redis_index,omitempty"`
		TableName  string `json:"table_name"`
		mtgban.ScraperInfo
	} `json:"scrapers"`

	/* The location of the configuation file */
	filePath string
}

var (
	DevMode        bool
	SigCheck       bool
	BenchMode      bool
	FreeSignature  string
	LogDir         string
	LastUpdate     string
	DatabaseLoaded bool
	Sellers        []mtgban.Seller
	Vendors        []mtgban.Vendor
	Infos          map[string]mtgban.InventoryRecord

	SealedEditionsSorted               []string
	SealedEditionsList                 map[string][]EditionEntry
	AllEditionsKeys                    []string
	AllEditionsMap                     map[string]EditionEntry
	TreeEditionsKeys                   []string
	TreeEditionsMap                    map[string][]EditionEntry
	ReprintsKeys                       []string
	ReprintsMap                        map[string][]ReprintEntry
	TotalSets, TotalCards, TotalUnique int

	Newspaper3dayDB *sql.DB
	Newspaper1dayDB *sql.DB

	GCSBucketClient  *storage.Client
	GoogleDocsClient *http.Client
	FirebaseApp      *firebase.App
	BigQueryClient   *bigquery.Client
)

const (
	DefaultConfigPort = "8080"
	DefaultSecret     = "NotVerySecret!"
)

var err error

func loadConfig() error {
	localConfigPath := os.Getenv("CONFIG_PATH")
	if localConfigPath != "" {
		// Attempt to load from a local file
		config, err := loadConfigFromFile(localConfigPath)
		if err == nil {
			log.Println("Loaded local config")
			applyDefaults(config)
			Config = *config
			return nil
		}
		log.Printf("Unable to load local config: %v", err)
	}
	return loadConfigFromSecretManager()
}

// Loads configuration from the specified local file
func loadConfigFromFile(filePath string) (*AppConfig, error) {
	file, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("file not found or unable to read: %v", err)
	}

	var config AppConfig
	if err := json.Unmarshal(file, &config); err != nil {
		return nil, fmt.Errorf("unable to unmarshal JSON into struct: %v", err)
	}

	return &config, nil
}

// Loads configuration from Google Secret Manager
func loadConfigFromSecretManager() error {
	log.Printf("Accessing Secrets..")
	ctx := context.Background()
	projectID := os.Getenv("PROJECT_ID")
	configSecret := os.Getenv("CONFIG_SECRET")
	configVersion := os.Getenv("CONFIG_VERSION")
	if projectID == "" || configSecret == "" {
		return fmt.Errorf("PROJECT_ID or CONFIG_SECRET environment variables are not set")
	}
	secretId := fmt.Sprintf("projects/%s/secrets/%s/versions/%v", projectID, configSecret, configVersion)

	configJSON, err := secrets.RetrieveSecretAsString(ctx, secretId)
	if err != nil {
		return fmt.Errorf("config file not loaded from Secret Manager: %v", err)
	}

	if err := json.Unmarshal([]byte(configJSON), &Config); err != nil {
		return fmt.Errorf("error unmarshalling configuration from Secret Manager: %v", err)
	}

	applyDefaults(&Config)
	return nil
}

// apply certain default values if not set
func applyDefaults(config *AppConfig) {
	if config.Port == "" {
		config.Port = DefaultConfigPort
	}
	if os.Getenv("BAN_SECRET") == "" {
		log.Printf("BAN_SECRET not set, using a default one")
		os.Setenv("BAN_SECRET", DefaultSecret)
	}

	if config.FreeEnable {
		if config.FreeLevel == "" {
			config.FreeLevel = "free"
		}
		if config.FreeHostname == "" {
			config.FreeHostname = "localhost"
		}
	}
}

func createBigQueryClient(ctx context.Context, projectId string, creds []byte) (*bigquery.Client, error) {
	credentials, err := google.CredentialsFromJSON(ctx, creds, bigquery.Scope)
	if err != nil {
		return nil, fmt.Errorf("failed to create credentials from JSON: %v", err)
	}
	return bigquery.NewClient(ctx, projectId, option.WithCredentials(credentials))
}

func createStorageClient(ctx context.Context, projectId string, creds []byte) (*storage.Client, error) {
	credentials, err := google.CredentialsFromJSON(ctx, creds, storage.ScopeFullControl)
	if err != nil {
		return nil, fmt.Errorf("failed to create credentials from JSON: %v", err)
	}
	return storage.NewClient(ctx, option.WithCredentials(credentials))
}

// with Config struct now populated => fetch and init service clients
func initCredentials(ctx context.Context, config AppConfig) {
	serviceAccounts := map[string]secrets.SecretInfo{
		"GCSBucket": config.GCSServiceAccount,
		"BigQuery":  config.BigQueryServiceAccount,
	}
	for serviceAccount, secretInfo := range serviceAccounts {
		secret := secrets.SecretInfo{
			Name:      secretInfo.Name,
			Version:   secretInfo.Version,
			MountPath: secretInfo.MountPath,
		}
		credentials, err := secrets.CreateAuthenticatedClient(ctx, Config.ProjectId, secret)
		if err != nil {
			log.Fatalf("Failed to create authenticated client: %v", err)
		}
		switch serviceAccount {
		case "GCSBucket":
			GCSBucketClient, err = createStorageClient(ctx, Config.ProjectId, credentials.JSON)
			if GCSBucketClient == nil {
				log.Fatalf("Failed to create GCS client: %v", err)
			}
		case "BigQuery":
			BigQueryClient, err = createBigQueryClient(ctx, Config.ProjectId, credentials.JSON)
			if BigQueryClient == nil {
				log.Fatalf("Failed to create BigQuery client: %v", err)
			}
		default:
			log.Fatalf("Unknown service account: %s", serviceAccount)
		}
	}
}

func Favicon(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "img/misc/favicon.ico")
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
		LastUpdate:   LastUpdate,

		PatreonId:    PatreonClientId,
		PatreonURL:   PatreonHost,
		PatreonLogin: showPatreonLogin,
		EnableFree:   Config.FreeEnable,
	}

	// Allocate a new navigation bar
	pageVars.Nav = make([]NavElem, len(DefaultNav))
	copy(pageVars.Nav, DefaultNav)

	// Enable buttons according to the enabled features
	if expires > time.Now().Unix() || (DevMode && !SigCheck) {
		for _, feat := range OrderNav {
			param := GetParamFromSig(sig, feat)
			allowed, _ := strconv.ParseBool(param)
			if DevMode && ExtraNavs[feat].AlwaysOnForDev {
				allowed = true
			}
			if allowed || (DevMode && !SigCheck) {
				pageVars.Nav = append(pageVars.Nav, ExtraNavs[feat])
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

func fetchMtgjson(ctx context.Context) {
	cmd := exec.Command("sh", "get-mtgjson.sh")
	cmd.Dir = "./"
	err := cmd.Start()
	if err != nil {
		log.Fatalf("Error starting command: %v", err)
	}

	err = cmd.Wait()
	if err != nil {
		log.Fatalf("Error waiting for command: %v", err)
	}
}

func main() {
	ctx := context.Background()
	devMode := flag.Bool("dev", false, "Enable developer mode")
	sigCheck := flag.Bool("sig", false, "Enable signature verification")
	skipInitialRefresh := flag.Bool("skip", false, "Skip initial refresh")
	noloadCache := flag.Bool("noload", false, "Do not load cached price data")
	logdir := flag.String("log", "logs", "Directory for scrapers logs")
	port := flag.String("port", "", "Override server port")
	flag.Parse()

	DevMode = *devMode
	SigCheck = true

	if DevMode {
		SigCheck = *sigCheck
	}

	LogDir = *logdir

	_, err := os.Stat("allprintings5.json")
	if os.IsNotExist(err) {
		fetchMtgjson(ctx)
	}

	// load necessary environmental variables
	if err := loadConfig(); err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	initCredentials(ctx, Config)

	GoogleDocsClient, err = loadGoogleCredentials(Config.GoogleCredentials)

	if *port != "" {
		Config.Port = *port
	}

	if err := openDBs(); err != nil {
		log.Printf("Failed to open database connection: %v", err)
	}

	// Cache a  signature
	if Config.FreeEnable {
		host := Config.FreeHostname
		level := Config.FreeLevel
		if host == "" || level == "" {
			log.Fatalln("missing parameter for free level")
		}
		host += ":" + Config.Port
		_, found := Config.ACL[level]
		if !found {
			log.Fatalln("level", level, "not found in the ACL config")
		}
		FreeSignature = sign(Config.FreeHostname, level, nil)
		log.Println("Running in free mode")
	}

	if _, err := os.Stat(LogDir); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(LogDir, 0700); err != nil {
			log.Fatalf("Unable to create log directory: %v", err)
		}
	}
	LogPages = map[string]*log.Logger{}

	err = openDBs()
	if err != nil {
		if DevMode {
			log.Println("error opening databases:", err)
		} else {
			log.Fatalln("error opening databases:", err)
		}
	}

	// load website up
	go func() {
		go func() {
			log.Println("Loading MTGJSONv5")
			err := loadDatastore()
			if err != nil {
				log.Fatalln("error loading mtgjson:", err)
			}
		}()

		// Try loading prices
		if *noloadCache {
			log.Println("Skipping cache loading as requested")
			DatabaseLoaded = true
			return
		}
		log.Println("Loading cache")
		err := startup()
		if err != nil {
			log.Fatalln("error loading cache:", err)
		}

		if *skipInitialRefresh {
			log.Println("Skipping prices refresh as requested")
			return
		}
		log.Println("Loading BQ")
		err = loadBQ(BigQueryClient)
		if err != nil {
			log.Println("error loading bq:", err)
		}

		// Nothing else to do if hacking around
		if DevMode {
			return
		}
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

		// Set up the handler
		http.Handle(nav.Link, enforceSigning(http.HandlerFunc(nav.Handle)))
	}

	http.Handle("/sets", enforceSigning(http.HandlerFunc(Search)))
	http.Handle("/sealed", enforceSigning(http.HandlerFunc(Search)))

	http.Handle("/api/bq/refresh/", enforceAPISigning(http.HandlerFunc(RefreshTable)))
	http.Handle("/api/mtgban/", enforceAPISigning(http.HandlerFunc(PriceAPI)))
	http.Handle("/api/mtgjson/ck.json", enforceAPISigning(http.HandlerFunc(API)))
	http.Handle("/api/tcgplayer/lastsold/", enforceSigning(http.HandlerFunc(TCGLastSoldAPI)))
	http.Handle("/api/cardkingdom/pricelist.json", noSigning(http.HandlerFunc(CKMirrorAPI)))
	http.HandleFunc("/favicon.ico", Favicon)
	http.HandleFunc("/auth", Auth)

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
		cleanupDiscord()
		cancel()
		log.Println("BAN Server shut down")
	}()

	err = srv.Shutdown(ctx)
	if err != nil {
		log.Fatalf("Server Shutdown Failed: %s", err.Error())
	}
	log.Println("BAN Server shutting down...")
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
		"print_perc": func(s string) string {
			n, _ := strconv.ParseFloat(s, 64)
			return fmt.Sprintf("%0.2f %%", n*100)
		},
		"print_price": func(s string) string {
			n, _ := strconv.ParseFloat(s, 64)
			return fmt.Sprintf("$ %0.2f", n)
		},
		"seller_name": func(s string) string {
			for _, scraperData := range Config.Scrapers["sellers"] {
				if s == scraperData.Shorthand {
					return scraperData.Name
				}
			}
			return ""
		},
		"vendor_name": func(s string) string {
			for _, scraperData := range Config.Scrapers["vendors"] {
				if s == scraperData.Shorthand {
					return scraperData.Name
				}
			}
			return ""
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
		"tolower": func(s string) string {
			return strings.ToLower(s)
		},
		"load_partner": func(s string) string {
			return Config.Affiliate[s]
		},
		"uuid2ckid": func(s string) string {
			for _, vendor := range Vendors {
				if vendor == nil || vendor.Info().Shorthand != "CK" {
					continue
				}
				bl, err := vendor.Buylist()
				if err != nil {
					return ""
				}
				entries, found := bl[s]
				if !found {
					return ""
				}
				return entries[0].CustomFields["CKID"]
			}
			return ""
		},
		"uuid2tcgid": func(s string) string {
			co, err := mtgmatcher.GetUUID(s)
			if err != nil {
				return ""
			}
			tcgId := co.Identifiers["tcgplayerProductId"]
			if co.Etched {
				id, found := co.Identifiers["tcgplayerEtchedProductId"]
				if found {
					tcgId = id
				}
			}
			return tcgId
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
