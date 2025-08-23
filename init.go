package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/leemcloughlin/logfile"
	"golang.org/x/exp/maps"

	"github.com/mtgban/go-mtgban/abugames"
	"github.com/mtgban/go-mtgban/cardkingdom"
	"github.com/mtgban/go-mtgban/cardmarket"
	"github.com/mtgban/go-mtgban/cardtrader"
	"github.com/mtgban/go-mtgban/coolstuffinc"
	"github.com/mtgban/go-mtgban/magiccorner"
	"github.com/mtgban/go-mtgban/manapool"
	"github.com/mtgban/go-mtgban/miniaturemarket"
	"github.com/mtgban/go-mtgban/mintcard"
	"github.com/mtgban/go-mtgban/mtgseattle"
	"github.com/mtgban/go-mtgban/sealedev"
	"github.com/mtgban/go-mtgban/starcitygames"
	"github.com/mtgban/go-mtgban/strikezone"
	"github.com/mtgban/go-mtgban/tcgplayer"
	"github.com/mtgban/go-mtgban/trollandtoad"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
)

const (
	// from TCGIndex
	TCG_LOW        = "TCG Low"
	TCG_MARKET     = "TCG Market"
	TCG_DIRECT_LOW = "TCG Direct Low"

	// from TCGMrkt
	TCG_MAIN   = "TCG Player"
	TCG_DIRECT = "TCG Direct"

	// from TCGDirectNet
	TCG_DIRECT_NET = "TCG Direct (net)"

	// from MKMIndex
	MKM_LOW   = "MKM Low"
	MKM_TREND = "MKM Trend"

	// from CT
	CT_STANDARD = "Card Trader"
	CT_ZERO     = "Card Trader Zero"
	CT_1DR      = "Card Trader 1DR"

	SkipRefreshCooldown    = 2 * time.Hour
	DefaultUploaderTimeout = 60 * time.Second
)

var InventoryDir string
var BuylistDir string

func loadDatastore() error {
	allPrintingsReader, err := os.Open(Config.DatastorePath)
	if err != nil {
		return err
	}
	defer allPrintingsReader.Close()

	err = mtgmatcher.LoadDatastore(allPrintingsReader)
	if err != nil {
		return err
	}

	if Config.Game == "" {
		SKUMap, err = loadSkuMap(Config.Api["tcg_skus_path"])
		if err != nil {
			return err
		}
	}

	return nil
}

func loadSkuMap(path string) (tcgplayer.SKUMap, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	log.Println("Loading SKU map from", path)
	return tcgplayer.LoadTCGSKUs(file)
}
func loadInventoryFromFile(fname string) (mtgban.Seller, error) {
	// Get file path from symlink
	link, err := os.Readlink(fname)
	if err != nil {
		return nil, err
	}

	// Validate we're loading the right thing
	baseName := filepath.Base(fname)
	linkedName := filepath.Base(link)
	if strings.Replace(baseName, "-latest", "", 1) != linkedName {
		return nil, errors.New("invalid link")
	}

	log.Println("File dump found:", link)
	return loadSellerFromFile(link)
}

func loadSellerFromFile(fname string) (mtgban.Seller, error) {
	file, err := os.Open(fname)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return mtgban.ReadSellerFromJSON(file)
}

func dumpInventoryToFile(seller mtgban.Seller, currentDir, fname string) error {
	outName := path.Join(currentDir, seller.Info().Shorthand+".json")

	// Create dump file
	err := dumpSellerToFile(seller, outName)
	if err != nil {
		return err
	}

	// Link dumpfile to the latest available source
	os.Remove(fname)
	return os.Symlink(outName, fname)
}

func dumpSellerToFile(seller mtgban.Seller, fname string) error {
	file, err := os.Create(fname)
	if err != nil {
		return err
	}
	defer file.Close()

	return mtgban.WriteSellerToJSON(seller, file)
}

func loadBuylistFromFile(fname string) (mtgban.Vendor, error) {
	// Get file path from symlink
	link, err := os.Readlink(fname)
	if err != nil {
		return nil, err
	}

	log.Println("File dump found:", link)
	return loadVendorFromFile(link)
}

func loadVendorFromFile(fname string) (mtgban.Vendor, error) {
	file, err := os.Open(fname)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return mtgban.ReadVendorFromJSON(file)
}

func dumpBuylistToFile(vendor mtgban.Vendor, currentDir, fname string) error {
	outName := path.Join(currentDir, vendor.Info().Shorthand+".json")

	// Create dump file
	err := dumpVendorToFile(vendor, outName)
	if err != nil {
		return err
	}

	// Link dumpfile to the latest available source
	os.Remove(fname)
	return os.Symlink(outName, fname)
}

func dumpVendorToFile(vendor mtgban.Vendor, fname string) error {
	file, err := os.Create(fname)
	if err != nil {
		return err
	}
	defer file.Close()

	return mtgban.WriteVendorToJSON(vendor, file)
}

type scraperOption struct {
	// Scraper is busy, and there are active network requests
	busy atomic.Bool

	// Load data for this scraper in dev mode too
	DevEnabled bool

	// Disable any Vendor functionality associated with this scraper
	OnlySeller bool

	// Disable any Seller functionality associated with this scraper
	OnlyVendor bool

	// The initialization function used to allocate and initialize needed resources
	Init func(logger *log.Logger) (mtgban.Scraper, error)

	// For Market scrapers, list the sub-sellers that should be preserved
	Keepers []string

	// For Trader scrapers, list the sub-vendors that should be preserved
	KeepersBL []string

	// The redis DBs where to stash data
	// For classic inventory/buylist the key is just "retail" and "buylist",
	// while for Market scrapers, the key is the name of the subseller
	RDBs map[string]*redis.Client

	// Save inventory data from this scraper to the associated redis DB
	StashInventory bool

	// Save buylist data from this scraper to the associated redis DB
	StashBuylist bool

	// Save market data from this scraper to the associated redis DB
	StashMarkets bool

	// Save trader data from this scraper to the associated redis DB
	StashTraders bool

	// Log where scrapers... log
	Logger *log.Logger
}

// Returns true if we flipped from false -> true (i.e., we acquired it).
func (s *scraperOption) TryStart() bool {
	return s.busy.CompareAndSwap(false, true)
}

func (s *scraperOption) Done() {
	s.busy.Store(false)
}

func (s *scraperOption) Busy() bool {
	return s.busy.Load()
}

// Map of indices for all scrapers stashed in the db
var DBs = map[string]int{
	"ck_retail":     0,
	"ck_buylist":    1,
	"tcg_low":       2,
	"tcg_market":    3,
	"mkm_low":       4,
	"mkm_trend":     5,
	"starcitygames": 6,
	"abugames":      7,
	"tcglow_ev":     8,
	"csi_buylist":   9,
}

var ScraperOptions map[string]*scraperOption

var allScraperOptions = map[string]map[string]*scraperOption{
	"":        mtgScraperOptions,
	"Lorcana": lorcanaScraperOptions,
}

var SKUMap tcgplayer.SKUMap

var mtgScraperOptions = map[string]*scraperOption{
	"abugames": &scraperOption{
		Init: func(logger *log.Logger) (mtgban.Scraper, error) {
			scraper := abugames.NewScraper()
			scraper.LogCallback = logger.Printf
			return scraper, nil
		},
		StashTraders: true,
		RDBs: map[string]*redis.Client{
			"ABUGames": redis.NewClient(&redis.Options{
				Addr: Config.RedisAddr,
				DB:   DBs["abugames"],
			}),
		},
		KeepersBL: abugames.NewScraper().TraderNames(),
	},
	"cardkingdom": &scraperOption{
		DevEnabled: true,
		Init: func(logger *log.Logger) (mtgban.Scraper, error) {
			scraper := cardkingdom.NewScraper()
			scraper.LogCallback = logger.Printf
			scraper.Partner = Config.Affiliate["CK"]
			return scraper, nil
		},
		StashInventory: true,
		StashBuylist:   true,
		RDBs: map[string]*redis.Client{
			"retail": redis.NewClient(&redis.Options{
				Addr: Config.RedisAddr,
				DB:   DBs["ck_retail"],
			}),
			"buylist": redis.NewClient(&redis.Options{
				Addr: Config.RedisAddr,
				DB:   DBs["ck_buylist"],
			}),
		},
	},
	"coolstuffinc": &scraperOption{
		Init: func(logger *log.Logger) (mtgban.Scraper, error) {
			scraper := coolstuffinc.NewScraper(coolstuffinc.GameMagic)
			scraper.LogCallback = logger.Printf
			scraper.Partner = Config.Affiliate["CSI"]
			return scraper, nil
		},
		StashBuylist: true,
		RDBs: map[string]*redis.Client{
			"buylist": redis.NewClient(&redis.Options{
				Addr: Config.RedisAddr,
				DB:   DBs["csi_buylist"],
			}),
		},
	},
	"starcitygames": &scraperOption{
		Init: func(logger *log.Logger) (mtgban.Scraper, error) {
			scraper := starcitygames.NewScraper(starcitygames.GameMagic, Config.Api["scg_guid"], Config.Api["scg_bearer"])
			scraper.LogCallback = logger.Printf
			scraper.Affiliate = Config.Affiliate["SCG"]
			return scraper, nil
		},
		StashBuylist: true,
		RDBs: map[string]*redis.Client{
			"buylist": redis.NewClient(&redis.Options{
				Addr: Config.RedisAddr,
				DB:   DBs["starcitygames"],
			}),
		},
	},
	"strikezone": &scraperOption{
		DevEnabled: true,
		Init: func(logger *log.Logger) (mtgban.Scraper, error) {
			scraper := strikezone.NewScraper(strikezone.GameMagic)
			scraper.LogCallback = logger.Printf
			return scraper, nil
		},
	},
	"trollandtoad": &scraperOption{
		Init: func(logger *log.Logger) (mtgban.Scraper, error) {
			scraper := trollandtoad.NewScraper()
			scraper.LogCallback = logger.Printf
			return scraper, nil
		},
	},
	"tcg_market": &scraperOption{
		DevEnabled: true,
		Init: func(logger *log.Logger) (mtgban.Scraper, error) {
			scraper, err := tcgplayer.NewScraperMarket(Config.Api["tcg_public"], Config.Api["tcg_private"])
			if err != nil {
				return nil, err
			}
			scraper.Affiliate = Config.Affiliate["TCG"]
			scraper.LogCallback = logger.Printf
			scraper.MaxConcurrency = 6

			scraper.SKUsData = SKUMap
			return scraper, nil
		},
		Keepers:   []string{TCG_MAIN, TCG_DIRECT},
		KeepersBL: []string{TCG_DIRECT_NET},
	},
	"tcg_index": &scraperOption{
		DevEnabled: true,
		Init: func(logger *log.Logger) (mtgban.Scraper, error) {
			scraper, err := tcgplayer.NewScraperIndex(Config.Api["tcg_public"], Config.Api["tcg_private"])
			if err != nil {
				return nil, err
			}
			scraper.Affiliate = Config.Affiliate["TCG"]
			scraper.LogCallback = logger.Printf
			scraper.MaxConcurrency = 4
			return scraper, nil
		},
		Keepers: []string{
			TCG_LOW,
			TCG_MARKET,
			TCG_DIRECT_LOW,
		},
		StashMarkets: true,
		RDBs: map[string]*redis.Client{
			"TCGLow": redis.NewClient(&redis.Options{
				Addr: Config.RedisAddr,
				DB:   DBs["tcg_low"],
			}),
			"TCGMarket": redis.NewClient(&redis.Options{
				Addr: Config.RedisAddr,
				DB:   DBs["tcg_market"],
			}),
		},
	},
	"magiccorner": &scraperOption{
		Init: func(logger *log.Logger) (mtgban.Scraper, error) {
			scraper, err := magiccorner.NewScraper()
			if err != nil {
				return nil, err
			}
			scraper.LogCallback = logger.Printf
			return scraper, nil
		},
	},
	"cardmarket": &scraperOption{
		Init: func(logger *log.Logger) (mtgban.Scraper, error) {
			scraper, err := cardmarket.NewScraperIndex(cardmarket.GameIdMagic, Config.Api["mkm_app_token"], Config.Api["mkm_app_secret"])
			if err != nil {
				return nil, err
			}
			scraper.Affiliate = Config.Affiliate["MKM"]
			scraper.LogCallback = logger.Printf
			return scraper, nil
		},
		Keepers:      []string{MKM_LOW, MKM_TREND},
		StashMarkets: true,
		RDBs: map[string]*redis.Client{
			"MKMLow": redis.NewClient(&redis.Options{
				Addr: Config.RedisAddr,
				DB:   DBs["mkm_low"],
			}),
			"MKMTrend": redis.NewClient(&redis.Options{
				Addr: Config.RedisAddr,
				DB:   DBs["mkm_trend"],
			}),
		},
	},
	"cardtrader": &scraperOption{
		Init: func(logger *log.Logger) (mtgban.Scraper, error) {
			scraper, err := cardtrader.NewScraperMarket(cardtrader.GameIdMagic, Config.Api["cardtrader"])
			if err != nil {
				return nil, err
			}
			scraper.LogCallback = logger.Printf
			scraper.ShareCode = Config.Affiliate["CT"]
			return scraper, nil
		},
		Keepers: []string{
			CT_STANDARD,
			CT_ZERO,
			CT_1DR,
		},
	},
	"mtgseattle": &scraperOption{
		OnlySeller: true,
		Init: func(logger *log.Logger) (mtgban.Scraper, error) {
			scraper := mtgseattle.NewScraper()
			scraper.LogCallback = logger.Printf
			return scraper, nil
		},
	},
	"cardkingdom_sealed": &scraperOption{
		DevEnabled: true,
		Init: func(logger *log.Logger) (mtgban.Scraper, error) {
			scraper := cardkingdom.NewScraperSealed()
			scraper.LogCallback = logger.Printf
			scraper.Partner = Config.Affiliate["CK"]
			return scraper, nil
		},
		StashInventory: true,
		StashBuylist:   true,
		RDBs: map[string]*redis.Client{
			"retail": redis.NewClient(&redis.Options{
				Addr: Config.RedisAddr,
				DB:   DBs["ck_retail"],
			}),
			"buylist": redis.NewClient(&redis.Options{
				Addr: Config.RedisAddr,
				DB:   DBs["ck_buylist"],
			}),
		},
	},
	"tcg_sealed": &scraperOption{
		DevEnabled: true,
		Init: func(logger *log.Logger) (mtgban.Scraper, error) {
			scraper, err := tcgplayer.NewScraperSealed(Config.Api["tcg_public"], Config.Api["tcg_private"])
			if err != nil {
				return nil, err
			}
			scraper.Affiliate = Config.Affiliate["TCG"]
			scraper.LogCallback = logger.Printf
			scraper.MaxConcurrency = 4

			scraper.SKUsData = SKUMap
			return scraper, nil
		},
		StashInventory: true,
		RDBs: map[string]*redis.Client{
			"retail": redis.NewClient(&redis.Options{
				Addr: Config.RedisAddr,
				DB:   DBs["tcg_low"],
			}),
		},
	},
	"cardmarket_sealed": &scraperOption{
		Init: func(logger *log.Logger) (mtgban.Scraper, error) {
			scraper, err := cardmarket.NewScraperSealed(Config.Api["mkm_app_token"], Config.Api["mkm_app_secret"])
			if err != nil {
				return nil, err
			}
			scraper.Affiliate = Config.Affiliate["MKM"]
			scraper.LogCallback = logger.Printf
			return scraper, nil
		},
		StashInventory: true,
		RDBs: map[string]*redis.Client{
			"retail": redis.NewClient(&redis.Options{
				Addr: Config.RedisAddr,
				DB:   DBs["mkm_low"],
			}),
		},
	},
	"sealed_ev": &scraperOption{
		DevEnabled: true,
		Init: func(logger *log.Logger) (mtgban.Scraper, error) {
			scraper := sealedev.NewScraper(Config.Api["ban_api_key"])
			scraper.FastMode = DevMode
			scraper.Affiliate = Config.Affiliate["TCG"]
			scraper.BuylistAffiliate = Config.Affiliate["CK"]
			scraper.LogCallback = logger.Printf
			return scraper, nil
		},
		Keepers:      sealedev.NewScraper("").MarketNames(),
		StashMarkets: true,
		RDBs: map[string]*redis.Client{
			"TCGLowEV": redis.NewClient(&redis.Options{
				Addr: Config.RedisAddr,
				DB:   DBs["tcglow_ev"],
			}),
		},
	},
	"cardtrader_sealed": &scraperOption{
		Init: func(logger *log.Logger) (mtgban.Scraper, error) {
			scraper, err := cardtrader.NewScraperSealed(Config.Api["cardtrader"])
			if err != nil {
				return nil, err
			}
			scraper.LogCallback = logger.Printf
			scraper.ShareCode = Config.Affiliate["CT"]
			return scraper, nil
		},
		Keepers: []string{
			CT_STANDARD,
			CT_ZERO,
			CT_1DR,
		},
	},
	"starcitygames_sealed": &scraperOption{
		Init: func(logger *log.Logger) (mtgban.Scraper, error) {
			scraper := starcitygames.NewScraperSealed(Config.Api["scg_guid"], Config.Api["scg_bearer"])
			scraper.LogCallback = logger.Printf
			scraper.Affiliate = Config.Affiliate["SCG"]
			return scraper, nil
		},
	},
	"coolstuffinc_sealed": &scraperOption{
		Init: func(logger *log.Logger) (mtgban.Scraper, error) {
			scraper := coolstuffinc.NewScraperSealed()
			scraper.LogCallback = logger.Printf
			scraper.Partner = Config.Affiliate["CSI"]
			return scraper, nil
		},
	},
	"miniaturemarket_sealed": &scraperOption{
		Init: func(logger *log.Logger) (mtgban.Scraper, error) {
			scraper := miniaturemarket.NewScraperSealed()
			scraper.LogCallback = logger.Printf
			return scraper, nil
		},
	},
	"tcg_syplist": {
		DevEnabled: true,
		Init: func(logger *log.Logger) (mtgban.Scraper, error) {
			scraper := tcgplayer.NewScraperSYP(Config.Api["tcg_auth"])
			scraper.LogCallback = logger.Printf
			scraper.Affiliate = Config.Affiliate["TCG"]
			scraper.SKUsData = SKUMap
			return scraper, nil
		},
	},
	"abugames_sealed": &scraperOption{
		Init: func(logger *log.Logger) (mtgban.Scraper, error) {
			scraper := abugames.NewScraperSealed()
			scraper.LogCallback = logger.Printf
			return scraper, nil
		},
		KeepersBL: []string{"ABU Games", "ABU Games (credit)"},
	},
	"mintcard": &scraperOption{
		Init: func(logger *log.Logger) (mtgban.Scraper, error) {
			scraper := mintcard.NewScraper()
			scraper.LogCallback = logger.Printf
			return scraper, nil
		},
	},
	"manapool": &scraperOption{
		Init: func(logger *log.Logger) (mtgban.Scraper, error) {
			scraper := manapool.NewScraper()
			scraper.LogCallback = logger.Printf
			scraper.Partner = Config.Affiliate["MP"]
			return scraper, nil
		},
	},
	"manapool_sealed": &scraperOption{
		DevEnabled: true,
		Init: func(logger *log.Logger) (mtgban.Scraper, error) {
			scraper := manapool.NewScraperSealed()
			scraper.LogCallback = logger.Printf
			scraper.Partner = Config.Affiliate["MP"]
			return scraper, nil
		},
	},
}

var lorcanaScraperOptions = map[string]*scraperOption{
	"tcg_index_lorcana": &scraperOption{
		DevEnabled: true,
		Init: func(logger *log.Logger) (mtgban.Scraper, error) {
			scraper, err := tcgplayer.NewLorcanaIndex(Config.Api["tcg_public"], Config.Api["tcg_private"])
			if err != nil {
				return nil, err
			}
			scraper.Affiliate = Config.Affiliate["TCG"]
			scraper.LogCallback = logger.Printf
			scraper.MaxConcurrency = 4
			return scraper, nil
		},
		Keepers: []string{
			TCG_LOW,
			TCG_MARKET,
		},
	},
	"tcg_market_lorcana": &scraperOption{
		DevEnabled: true,
		Init: func(logger *log.Logger) (mtgban.Scraper, error) {
			scraper, err := tcgplayer.NewLorcanaScraper(Config.Api["tcg_public"], Config.Api["tcg_private"])
			if err != nil {
				return nil, err
			}
			scraper.Affiliate = Config.Affiliate["TCG"]
			scraper.LogCallback = logger.Printf
			scraper.MaxConcurrency = 6
			return scraper, nil
		},
	},
	"coolstuffinc_lorcana": &scraperOption{
		DevEnabled: true,
		Init: func(logger *log.Logger) (mtgban.Scraper, error) {
			scraper := coolstuffinc.NewScraper(coolstuffinc.GameLorcana)
			scraper.LogCallback = logger.Printf
			scraper.Partner = Config.Affiliate["CSI"]
			return scraper, nil
		},
	},
	"starcitygames_lorcana": &scraperOption{
		DevEnabled: true,
		Init: func(logger *log.Logger) (mtgban.Scraper, error) {
			scraper := starcitygames.NewScraper(starcitygames.GameLorcana, Config.Api["scg_guid"], Config.Api["scg_bearer"])
			scraper.LogCallback = logger.Printf
			scraper.Affiliate = Config.Affiliate["SCG"]
			return scraper, nil
		},
	},
	"cardmarket_lorcana": &scraperOption{
		DevEnabled: true,
		Init: func(logger *log.Logger) (mtgban.Scraper, error) {
			scraper, err := cardmarket.NewScraperIndex(cardmarket.GameIdLorcana, Config.Api["mkm_app_token"], Config.Api["mkm_app_secret"])
			if err != nil {
				return nil, err
			}
			scraper.Affiliate = Config.Affiliate["MKM"]
			scraper.LogCallback = logger.Printf
			return scraper, nil
		},
		Keepers: []string{MKM_LOW, MKM_TREND},
	},
	"cardtrader_lorcana": &scraperOption{
		DevEnabled: true,
		Init: func(logger *log.Logger) (mtgban.Scraper, error) {
			scraper, err := cardtrader.NewScraperMarket(cardtrader.GameIdLorcana, Config.Api["cardtrader"])
			if err != nil {
				return nil, err
			}
			scraper.LogCallback = logger.Printf
			scraper.ShareCode = Config.Affiliate["CT"]
			return scraper, nil
		},
		Keepers: []string{
			CT_STANDARD,
			CT_ZERO,
		},
	},
	"strikezone_lorcana": &scraperOption{
		DevEnabled: true,
		Init: func(logger *log.Logger) (mtgban.Scraper, error) {
			scraper := strikezone.NewScraper(strikezone.GameLorcana)
			scraper.LogCallback = logger.Printf
			return scraper, nil
		},
	},
}

// Associate Scraper shorthands to ScraperOptions keys
var ScraperMap map[string]string

// Assiciate Scraper shorthands to Scraper Names
var ScraperNames map[string]string

// A default scale for converting non-NM prices to NM
var defaultGradeMap = map[string]float64{
	"NM": 1, "SP": 1.25, "MP": 1.67, "HP": 2.5, "PO": 4,
}

// Create log and ScraperMap
func loadOptions() {
	if ScraperMap == nil {
		ScraperMap = map[string]string{}
	}
	for key, opt := range ScraperOptions {
		if SkipPrices {
			ScraperOptions[key].DevEnabled = false
		}

		if DevMode && !opt.DevEnabled {
			continue
		}

		// Create the destination logfile if not existing
		if opt.Logger == nil {
			logFile, err := logfile.New(&logfile.LogFile{
				FileName:    path.Join(LogDir, key+".log"),
				MaxSize:     500 * 1024,       // 500K duh!
				Flags:       logfile.FileOnly, // Default append
				OldVersions: 1,
			})
			if err != nil {
				log.Printf("Failed to create logFile for %s: %s", key, err)
				opt.Logger = log.New(os.Stderr, "", log.LstdFlags)
				continue
			}
			opt.Logger = log.New(logFile, "", log.LstdFlags)
		}

		scraper, err := opt.Init(opt.Logger)
		if err != nil {
			continue
		}
		if scraper.Info().Game != Config.Game {
			continue
		}

		// Custom untangling
		for _, keepers := range [][]string{opt.Keepers, opt.KeepersBL} {
			for _, name := range keepers {
				ScraperMap[name] = key
			}
		}

		ScraperMap[scraper.Info().Shorthand] = key
	}
}

func loadScrapers() {
	init := !DatabaseLoaded
	if init {
		ServerNotify("init", "loading started")
	} else {
		ServerNotify("refresh", "full refresh started")
	}

	currentDir := path.Join(InventoryDir, fmt.Sprintf("%03d", time.Now().YearDay()))
	mkDirIfNotExisting(currentDir)

	newbc := mtgban.NewClient()

	// Keep track of the names used in the options table, so that we can
	// reference the mutex more freely
	if ScraperMap == nil {
		ScraperMap = map[string]string{}
	}
	if ScraperNames == nil {
		ScraperNames = map[string]string{}
	}
	if ScraperOptions == nil {
		ScraperOptions = allScraperOptions[Config.Game]
	}

	loadOptions()

	for key, opt := range ScraperOptions {
		if DevMode && !opt.DevEnabled {
			continue
		}

		if BenchMode && Config.Game != "" {
			continue
		}

		scraper, err := opt.Init(opt.Logger)
		if err != nil {
			msg := fmt.Sprintf("error initializing %s: %s", key, err.Error())
			ServerNotify("init", msg, true)
			continue
		}
		if scraper.Info().Game != Config.Game {
			continue
		}

		log.Println("Initialized " + key)

		ScraperMap[scraper.Info().Shorthand] = key
		ScraperNames[scraper.Info().Shorthand] = scraper.Info().Name

		if len(opt.Keepers) > 0 || len(opt.KeepersBL) > 0 {
			if !opt.OnlyVendor {
				if len(opt.Keepers) == 0 {
					newbc.RegisterSeller(scraper)
				}
				for _, keeper := range opt.Keepers {
					multi := scraper.(mtgban.Market)
					multiInfo := multi.InfoForScraper(keeper)
					newbc.RegisterMarket(multi, keeper)
					ScraperMap[multiInfo.Shorthand] = key
					ScraperNames[multiInfo.Shorthand] = keeper
				}
			}
			if !opt.OnlySeller {
				if len(opt.KeepersBL) == 0 {
					newbc.RegisterVendor(scraper)
				}
				for _, keeper := range opt.KeepersBL {
					multi := scraper.(mtgban.Trader)
					multiInfo := multi.InfoForScraper(keeper)
					newbc.RegisterTrader(multi, keeper)
					ScraperMap[multiInfo.Shorthand] = key
					ScraperNames[multiInfo.Shorthand] = keeper
				}
			}
		} else if opt.OnlySeller {
			newbc.RegisterSeller(scraper)
		} else if opt.OnlyVendor {
			newbc.RegisterVendor(scraper)
		} else {
			newbc.Register(scraper)
		}
	}

	if SkipPrices {
		log.Println("no prices loaded as requested")
		return
	}

	msg := fmt.Sprintln("Scraper Map table:")
	keys := maps.Keys(ScraperMap)
	sort.Strings(keys)
	for _, key := range keys {
		msg += fmt.Sprintf("- %s -> `%s`\n", key, ScraperMap[key])
	}
	ServerNotify("init", msg)

	loadSellers(newbc)
	loadVendors(newbc)

	if BenchMode {
		return
	}

	go updateStaticData()

	if init {
		ServerNotify("init", "loading completed")
	} else {
		ServerNotify("refresh", "full refresh completed")
	}
}

func updateStaticData() {
	SealedEditionsSorted, SealedEditionsList = getSealedEditions()
	AllEditionsKeys, AllEditionsMap = getAllEditions()
	TreeEditionsKeys, TreeEditionsMap = getTreeEditions()
	ReprintsKeys, ReprintsMap = getReprintsGlobal()

	TotalSets = len(AllEditionsKeys)
	TotalUnique = len(mtgmatcher.GetUUIDs())
	var totalCards int
	for _, key := range AllEditionsKeys {
		totalCards += AllEditionsMap[key].Size
	}
	TotalCards = totalCards

	go runSealedAnalysis()

	// Load prices for API users
	if !DevMode {
		if Config.Game == "" {
			go prepareCKAPI()
		}
	}

	LastUpdate = time.Now().Format(time.RFC3339)
}

func loadSellers(newbc *mtgban.BanClient) {
	newSellers := newbc.Sellers()

	// Allocate enough space for the global pointers
	if Sellers == nil {
		Sellers = newSellers
	}

	log.Println("Sellers table")
	var msgS string
	for i := range newSellers {
		msgS += fmt.Sprintf("%d ", i)
		if newSellers[i] == nil {
			msgS += "<nil>\n"
			continue
		}
		msgS += fmt.Sprintf("%s - %s\n", newSellers[i].Info().Name, newSellers[i].Info().Shorthand)
	}
	ServerNotify("init", msgS)

	defer recoverPanicScraper()

	init := !DatabaseLoaded
	currentDir := path.Join(InventoryDir, fmt.Sprintf("%03d", time.Now().YearDay()))
	mkDirIfNotExisting(currentDir)

	var wg sync.WaitGroup

	// Load Sellers
	for i := range newSellers {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()

			// Find where our seller resides in the global array
			sellerIndex := -1
			for j, seller := range Sellers {
				if seller != nil && newSellers[i].Info().Shorthand == seller.Info().Shorthand {
					sellerIndex = j
					break
				}
			}

			shorthand := newSellers[i].Info().Shorthand
			log.Println("seller", shorthand, "is at position", sellerIndex)
			opts := ScraperOptions[ScraperMap[shorthand]]

			fname := path.Join(InventoryDir, shorthand+"-latest.json")
			if init && fileExists(fname) {
				seller, err := loadInventoryFromFile(fname)
				if err != nil {
					log.Println(err)
					return
				}
				if sellerIndex < 0 {
					Sellers = append(Sellers, seller)
				} else {
					Sellers[sellerIndex] = seller
				}

				inv, _ := seller.Inventory()
				log.Printf("seller %s was loaded from file with %d entries", shorthand, len(inv))
			} else {
				// If the old scraper data is old enough, pull from the new scraper
				// and update it in the global slice
				if sellerIndex < 0 || // Sellers[] != nil is checked above
					time.Since(*Sellers[sellerIndex].Info().InventoryTimestamp) > SkipRefreshCooldown {
					ServerNotify("reload", "Loading from seller "+shorthand)
					start := time.Now()
					err := updateSellerAtPosition(newSellers[i], sellerIndex, true)
					if err != nil {
						msg := fmt.Sprintf("seller %s - %s", shorthand, err.Error())
						ServerNotify("reload", msg, true)
						return
					}
					log.Println("seller", shorthand, "was loaded from scraper, took", time.Since(start))
					opts.Logger.Println("Loaded from scraper")
				} else {
					opts.Logger.Println("Data is recent enough, skipping scraping")
				}

				// Stash data to DB if requested
				if opts.StashInventory || (opts.StashMarkets && opts.RDBs[shorthand] != nil) {
					start := time.Now()
					log.Println("Stashing", shorthand, "inventory data to DB")
					inv, _ := newSellers[i].Inventory()

					dbName := "retail"
					if opts.RDBs[shorthand] != nil {
						dbName = shorthand
					}

					key := newSellers[i].Info().InventoryTimestamp.Format("2006-01-02")
					for uuid, entries := range inv {
						// Adjust price through defaultGradeMap in case NM is not available
						price := entries[0].Price * defaultGradeMap[entries[0].Conditions]
						// Use NX because the price might have already been set using more accurate
						// information (instead of the derivation above)
						err := opts.RDBs[dbName].HSetNX(context.Background(), uuid, key, price).Err()
						if err != nil {
							ServerNotify("redis", err.Error())
							break
						}
					}
					log.Println("Took", time.Since(start))
				}

				err := dumpInventoryToFile(newSellers[i], currentDir, fname)
				if err != nil {
					log.Println(err)
					return
				}
				opts.Logger.Println("Saved to file", fname)
			}
			log.Println(shorthand, "seller -- OK")
		}(i)

		// If not in initilization mode, run the routines sequentially
		if !init || !Config.FastStart {
			wg.Wait()
		}
	}

	if init {
		if Config.FastStart {
			wg.Wait()
		}

		// Sort the sellers arrays by name
		//
		// Note that pointers are shared between these two arrays,
		// things like Price Ratio (bl data depending on inv data)
		// still work just fine, even if we don't use them in the
		// global arrays in the end.
		//
		// Also perform it after synchronizing to make sure everything
		// is loaded up just fine
		sort.Slice(Sellers, func(i, j int) bool {
			if Sellers[i].Info().Name == Sellers[j].Info().Name {
				return Sellers[i].Info().Shorthand < Sellers[j].Info().Shorthand
			}
			return Sellers[i].Info().Name < Sellers[j].Info().Name
		})
	}
}

func loadVendors(newbc *mtgban.BanClient) {
	newVendors := newbc.Vendors()

	if Vendors == nil {
		Vendors = newVendors
	}

	log.Println("Vendors table")
	var msgV string
	for i := range newVendors {
		msgV += fmt.Sprintf("%d ", i)
		if newVendors[i] == nil {
			msgV += "<nil>\n"
			continue
		}
		msgV += fmt.Sprintf("%s - %s\n", newVendors[i].Info().Name, newVendors[i].Info().Shorthand)
	}
	ServerNotify("init", msgV)

	defer recoverPanicScraper()

	init := !DatabaseLoaded
	currentDir := path.Join(BuylistDir, fmt.Sprintf("%03d", time.Now().YearDay()))
	mkDirIfNotExisting(currentDir)

	var wg sync.WaitGroup
	// Load Vendors
	for i := range newVendors {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()

			// Find where our vendor resides in the global array
			vendorIndex := -1
			for j, vendor := range Vendors {
				if vendor != nil && newVendors[i].Info().Shorthand == vendor.Info().Shorthand {
					vendorIndex = j
					break
				}
			}

			shorthand := newVendors[i].Info().Shorthand
			log.Println("vendor", shorthand, "is at position", vendorIndex)
			opts := ScraperOptions[ScraperMap[shorthand]]

			fname := path.Join(BuylistDir, shorthand+"-latest.json")
			if init && fileExists(fname) {
				vendor, err := loadBuylistFromFile(fname)
				if err != nil {
					log.Println(err)
					return
				}
				if vendorIndex < 0 {
					Vendors = append(Vendors, vendor)
				} else {
					Vendors[vendorIndex] = vendor
				}

				bl, _ := vendor.Buylist()
				log.Printf("vendor %s was loaded from file with %d entries", shorthand, len(bl))
				opts.Logger.Println("Loaded from file")
			} else {
				// If the old scraper data is old enough, pull from the new scraper
				// and update it in the global slice
				if vendorIndex < 0 || time.Since(*Vendors[vendorIndex].Info().BuylistTimestamp) > SkipRefreshCooldown {
					ServerNotify("reload", "Loading from vendor "+shorthand)
					start := time.Now()
					err := updateVendorAtPosition(newVendors[i], vendorIndex, true)
					if err != nil {
						msg := fmt.Sprintf("vendor %s - %s", shorthand, err.Error())
						ServerNotify("reload", msg, true)
						return
					}
					log.Println("vendor", shorthand, "was loaded from scraper, took", time.Since(start))
					opts.Logger.Println("Loaded from scraper")
				} else {
					opts.Logger.Println("Data is recent enough, skipping scraping")
				}

				// Stash data to DB if requested
				if opts.StashBuylist || (opts.StashTraders && opts.RDBs[shorthand] != nil) {
					start := time.Now()
					log.Println("Stashing", shorthand, "buylist data to DB")
					bl, _ := newVendors[i].Buylist()

					dbName := "buylist"
					if opts.RDBs[shorthand] != nil {
						dbName = shorthand
					}

					key := newVendors[i].Info().BuylistTimestamp.Format("2006-01-02")
					for uuid, entries := range bl {
						err := opts.RDBs[dbName].HSet(context.Background(), uuid, key, entries[0].BuyPrice).Err()
						if err != nil {
							ServerNotify("redis", err.Error())
							break
						}
					}
					log.Println("Took", time.Since(start))
				}

				err := dumpBuylistToFile(newVendors[i], currentDir, fname)
				if err != nil {
					log.Println(err)
					return
				}
				opts.Logger.Println("Saved to file", fname)
			}
			log.Println(shorthand, "vendor -- OK")
		}(i)

		if !init || !Config.FastStart {
			wg.Wait()
		}
	}

	if init {
		if Config.FastStart {
			wg.Wait()
		}

		sort.Slice(Vendors, func(i, j int) bool {
			if Vendors[i].Info().Name == Vendors[j].Info().Name {
				return Vendors[i].Info().Shorthand < Vendors[j].Info().Shorthand
			}
			return Vendors[i].Info().Name < Vendors[j].Info().Name
		})
	}
}

func recoverPanicScraper() {
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

		return
	}
}
