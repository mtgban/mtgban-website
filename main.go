package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"database/sql"

	_ "github.com/lib/pq"
	"github.com/mtgban/mtgban-website/apisig"
	"github.com/mtgban/mtgban-website/internal/alerts"
	"github.com/mtgban/mtgban-website/internal/palette"
	"github.com/mtgban/mtgban-website/observability"
	"github.com/mtgban/mtgban-website/tcgcsv"
	"github.com/mtgban/mtgban-website/timeseries"
	"github.com/mtgban/mtgban-website/userstate"

	"golang.org/x/oauth2/google"
	"gopkg.in/Iwark/spreadsheet.v2"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	_ "github.com/mtgban/go-mtgban/mtgmatcher/games"
	"github.com/mtgban/simplecloud"

	_ "net/http/pprof"
)

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
	// Mail is the sender alert mail goes out as; the Resend key is env only.
	Mail struct {
		From string `json:"from"`
	} `json:"mail"`
	BucketKeys map[string]BucketKey `json:"bucket_keys"`

	Game         mtgmatcher.Game `json:"game"`
	InstanceName string          `json:"instance_name"`

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
	DefaultMailFrom      = "MTGBAN <no-reply@mtgban.com>"

	DefaultSignatureDuration = 11 * 24 * time.Hour
)

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

// reloadConfig reloads the config file for the admin page's ?tool=config,
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
	if config.Mail.From == "" {
		config.Mail.From = DefaultMailFrom
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
		// Long-form writes: make sure the current and next month's price
		// partitions exist ahead of any write. Writes-only (creates partitions).
		if longFormWrites() {
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
	alertsSend := flag.Bool("alerts-send", false, "Deliver alert DMs and mail in dev mode")
	flag.StringVar(&LogDir, "log", "logs", "Directory for scrapers logs")

	var maintenance tcgcsvMaintenance
	flag.BoolVar(&maintenance.backfill, "tcgcsv-backfill", false, "Backfill tcg_prices from tcgcsv archives, then exit (archives are withdrawn upstream: stores the current snapshot instead when the range covers it)")
	flag.StringVar(&maintenance.backfillOptions.From, "tcgcsv-from", "", "Backfill start date YYYY-MM-DD (default: earliest archive, 2024-02-08; an explicit date fetches the whole range, bypassing the resume cursor)")
	flag.StringVar(&maintenance.backfillOptions.To, "tcgcsv-to", "", "Backfill end date YYYY-MM-DD (default: today)")
	flag.BoolVar(&maintenance.backfillOptions.Force, "tcgcsv-force", false, "Re-ingest dates already stored (ignore the resume cursor)")
	flag.StringVar(&maintenance.backfillOptions.Categories, "tcgcsv-categories", "", "Restrict the backfill to these TCGplayer category ids, comma-separated (default: every configured game)")
	flag.BoolVar(&maintenance.daily, "tcgcsv-daily", false, "Run the daily tcgcsv ingest once, then exit")
	flag.BoolVar(&maintenance.products, "tcgcsv-products", false, "Sync the tcgcsv product catalog once, then exit")

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

	if maintenance.backfill || maintenance.daily || maintenance.products {
		s.runTCGCSVMaintenance(maintenance)
	}

	// Before the evaluator or any route can read them.
	s.loadAlertMail()

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
		s.startScraperLoad(*dumpsDir, stores, datastoreLoaded)
	}

	// Runtime manifest refreshes funnel through one debounced goroutine, each
	// under tracked so that one that panics does not end the loop.
	s.offline.StartRefresher(func(_ string, fn func()) func() { return tracked(jobOffline, fn) })

	if !DevMode {
		s.startCrons()
	}

	err = s.setupDiscord()
	if err != nil {
		log.Println("Error connecting to discord", err)
	}

	// Price alerts re-evaluate after a burst of installs settles.
	s.startAlertEvaluator()

	s.registerRoutes()

	s.serve()
}

// serve answers on the configured port until a signal asks the process to
// stop, then shuts the server and the background work down.
func (s *site) serve() {
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

	err := srv.Shutdown(ctx)
	if err != nil {
		ServerNotify("shutdown", "Server shutdown failed: "+err.Error())
		return
	}
	ServerNotify("shutdown", "Server shutdown correctly")
}
