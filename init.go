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
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/leemcloughlin/logfile"

	"github.com/mtgban/go-mtgban/abugames"
	"github.com/mtgban/go-mtgban/cardkingdom"
	"github.com/mtgban/go-mtgban/cardmarket"
	"github.com/mtgban/go-mtgban/cardtrader"
	"github.com/mtgban/go-mtgban/coolstuffinc"
	"github.com/mtgban/go-mtgban/magiccorner"
	"github.com/mtgban/go-mtgban/miniaturemarket"
	"github.com/mtgban/go-mtgban/mtgseattle"
	"github.com/mtgban/go-mtgban/mtgstocks"
	"github.com/mtgban/go-mtgban/ninetyfive"
	"github.com/mtgban/go-mtgban/sealedev"
	"github.com/mtgban/go-mtgban/starcitygames"
	"github.com/mtgban/go-mtgban/strikezone"
	"github.com/mtgban/go-mtgban/tcgplayer"
	"github.com/mtgban/go-mtgban/toamagic"
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
	TCG_MAIN    = "TCG Player"
	TCG_DIRECT  = "TCG Direct"
	TCG_BUYLIST = "TCG Player Market"

	// from TCGDirectNet
	TCG_DIRECT_NET = "TCG Direct (net)"

	// from MKMIndex
	MKM_LOW   = "MKM Low"
	MKM_TREND = "MKM Trend"

	// from CT
	CT_STANDARD        = "Card Trader"
	CT_ZERO            = "Card Trader Zero"
	CT_STANDARD_SEALED = "Card Trader Sealed"
	CT_ZERO_SEALED     = "Card Trader Zero Sealed"

	SkipRefreshCooldown    = 2 * time.Hour
	DefaultUploaderTimeout = 60 * time.Second

	AllPrintingsFileName = "allprintings5.json"

	InventoryDir = "cache_inv"
	BuylistDir   = "cache_bl"
)

func loadDatastore() error {
	allPrintingsReader, err := os.Open(AllPrintingsFileName)
	if err != nil {
		return err
	}
	defer allPrintingsReader.Close()

	return mtgmatcher.LoadDatastore(allPrintingsReader)
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

func uploadSeller(seller mtgban.Seller, currentDir string) error {
	if GCSBucketClient == nil {
		return errors.New("no bucket configuration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), DefaultUploaderTimeout)
	defer cancel()

	outName := path.Join(currentDir, seller.Info().Shorthand+".json")
	wc := GCSBucketClient.Bucket(Config.Uploader.BucketName).Object(outName).NewWriter(ctx)
	wc.ContentType = "application/json"
	defer wc.Close()

	err := mtgban.WriteSellerToJSON(seller, wc)
	if err != nil {
		return err
	}

	configMutex.Lock()
	_, found := SellersConfigMap[seller.Info().Shorthand]
	if !found {
		SellersConfigMap[seller.Info().Shorthand] = &ScraperConfig{}
	}
	SellersConfigMap[seller.Info().Shorthand].Name = seller.Info().Name
	SellersConfigMap[seller.Info().Shorthand].Shorthand = seller.Info().Shorthand
	SellersConfigMap[seller.Info().Shorthand].Path = outName
	uploadScrapersConfig(SellersConfigMap, "sellers.json")
	configMutex.Unlock()

	return nil
}

func uploadVendor(vendor mtgban.Vendor, currentDir string) error {
	if GCSBucketClient == nil {
		return errors.New("no bucket configuration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), DefaultUploaderTimeout)
	defer cancel()

	outName := path.Join(currentDir, vendor.Info().Shorthand+".json")
	wc := GCSBucketClient.Bucket(Config.Uploader.BucketName).Object(outName).NewWriter(ctx)
	wc.ContentType = "application/json"
	defer wc.Close()

	err := mtgban.WriteVendorToJSON(vendor, wc)
	if err != nil {
		return err
	}

	configMutex.Lock()
	_, found := VendorsConfigMap[vendor.Info().Shorthand]
	if !found {
		VendorsConfigMap[vendor.Info().Shorthand] = &ScraperConfig{}
	}
	VendorsConfigMap[vendor.Info().Shorthand].Name = vendor.Info().Name
	VendorsConfigMap[vendor.Info().Shorthand].Shorthand = vendor.Info().Shorthand
	VendorsConfigMap[vendor.Info().Shorthand].Path = outName
	uploadScrapersConfig(VendorsConfigMap, "vendors.json")
	configMutex.Unlock()

	return nil
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
	Busy bool

	// The mutex to programmatically make a scraper busy
	Mutex sync.Mutex

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

	// For Market scrapers, list the buylists that should be preserved
	KeepersBL string

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

	// Log where scrapers... log
	Logger *log.Logger
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
}

var ScraperOptions = map[string]*scraperOption{
	"abugames": &scraperOption{
		Init: func(logger *log.Logger) (mtgban.Scraper, error) {
			scraper := abugames.NewScraper()
			scraper.LogCallback = logger.Printf
			return scraper, nil
		},
		StashBuylist: true,
		RDBs: map[string]*redis.Client{
			"buylist": redis.NewClient(&redis.Options{
				Addr: Config.RedisAddr,
				DB:   DBs["abugames"],
			}),
		},
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
			scraper := coolstuffinc.NewScraperOfficial(Config.Api["csi_token"])
			scraper.LogCallback = logger.Printf
			scraper.Partner = Config.Affiliate["CSI"]
			return scraper, nil
		},
	},
	"ninetyfive": &scraperOption{
		Init: func(logger *log.Logger) (mtgban.Scraper, error) {
			scraper, _ := ninetyfive.NewScraper(false)
			scraper.LogCallback = logger.Printf
			return scraper, nil
		},
	},
	"starcitygames": &scraperOption{
		Init: func(logger *log.Logger) (mtgban.Scraper, error) {
			scraper := starcitygames.NewScraper(Config.Api["scg_guid"], Config.Api["scg_bearer"])
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
			scraper := strikezone.NewScraper()
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
			scraper := tcgplayer.NewScraperMarket(Config.Api["tcg_public"], Config.Api["tcg_private"])
			scraper.Affiliate = Config.Affiliate["TCG"]
			scraper.LogCallback = logger.Printf
			scraper.MaxConcurrency = 5
			return scraper, nil
		},
		Keepers:   []string{TCG_MAIN, TCG_DIRECT},
		KeepersBL: TCG_BUYLIST,
	},
	"tcg_index": &scraperOption{
		DevEnabled: true,
		Init: func(logger *log.Logger) (mtgban.Scraper, error) {
			scraper := tcgplayer.NewScraperIndex(Config.Api["tcg_public"], Config.Api["tcg_private"])
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
			TCG_LOW: redis.NewClient(&redis.Options{
				Addr: Config.RedisAddr,
				DB:   DBs["tcg_low"],
			}),
			TCG_MARKET: redis.NewClient(&redis.Options{
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
			scraper, err := cardmarket.NewScraperIndex(Config.Api["mkm_app_token"], Config.Api["mkm_app_secret"])
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
			MKM_LOW: redis.NewClient(&redis.Options{
				Addr: Config.RedisAddr,
				DB:   DBs["mkm_low"],
			}),
			MKM_TREND: redis.NewClient(&redis.Options{
				Addr: Config.RedisAddr,
				DB:   DBs["mkm_trend"],
			}),
		},
	},
	"cardtrader": &scraperOption{
		Init: func(logger *log.Logger) (mtgban.Scraper, error) {
			scraper, err := cardtrader.NewScraperMarket(Config.Api["cardtrader"])
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
	"mtgseattle": &scraperOption{
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
			scraper := tcgplayer.NewScraperSealed(Config.Api["tcg_public"], Config.Api["tcg_private"])
			scraper.Affiliate = Config.Affiliate["TCG"]
			scraper.LogCallback = logger.Printf
			scraper.MaxConcurrency = 4
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
	"toamagic": &scraperOption{
		OnlyVendor: true,
		Init: func(logger *log.Logger) (mtgban.Scraper, error) {
			scraper := toamagic.NewScraper()
			scraper.LogCallback = logger.Printf
			return scraper, nil
		},
	},
	"tcg_direct_net": &scraperOption{
		DevEnabled: true,
		Init: func(logger *log.Logger) (mtgban.Scraper, error) {
			scraper := tcgplayer.NewTCGDirectNet()
			return scraper, nil
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
			"TCG Low EV": redis.NewClient(&redis.Options{
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
			CT_STANDARD_SEALED,
			CT_ZERO_SEALED,
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

		// Custom untangling
		for _, name := range opt.Keepers {
			ScraperMap[name] = key
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

	if SellersConfigMap == nil {
		SellersConfigMap = map[string]*ScraperConfig{}
	}
	if VendorsConfigMap == nil {
		VendorsConfigMap = map[string]*ScraperConfig{}
	}

	loadOptions()

	for key, opt := range ScraperOptions {
		if DevMode && !opt.DevEnabled {
			continue
		}

		log.Println("Initializing " + key)
		scraper, err := opt.Init(opt.Logger)
		if err != nil {
			msg := fmt.Sprintf("error initializing %s: %s", key, err.Error())
			ServerNotify("init", msg, true)
			continue
		}

		ScraperMap[scraper.Info().Shorthand] = key
		ScraperNames[scraper.Info().Shorthand] = scraper.Info().Name

		if len(opt.Keepers) != 0 {
			if !opt.OnlyVendor {
				for _, keeper := range opt.Keepers {
					newbc.RegisterMarket(scraper, keeper)
					ScraperMap[keeper] = key
					ScraperNames[keeper] = keeper
				}
			}
			if !opt.OnlySeller {
				newbc.RegisterVendor(scraper)
			}
		} else if opt.OnlySeller {
			newbc.RegisterSeller(scraper)
		} else if opt.OnlyVendor {
			newbc.RegisterVendor(scraper)
		} else {
			newbc.Register(scraper)
		}
	}

	// Sort the sellers/vendors arrays by name
	//
	// Note that pointers are shared between these two arrays,
	// things like Price Ratio (bl data depending on inv data)
	// still work just fine, even if we don't use them in the
	// global arrays in the end.
	newSellers := newbc.Sellers()
	sort.Slice(newSellers, func(i, j int) bool {
		if newSellers[i].Info().Name == newSellers[j].Info().Name {
			return newSellers[i].Info().Shorthand < newSellers[j].Info().Shorthand
		}
		return newSellers[i].Info().Name < newSellers[j].Info().Name
	})
	newVendors := newbc.Vendors()
	sort.Slice(newVendors, func(i, j int) bool {
		if newVendors[i].Info().Name == newVendors[j].Info().Name {
			return newVendors[i].Info().Shorthand < newVendors[j].Info().Shorthand
		}
		return newVendors[i].Info().Name < newVendors[j].Info().Name
	})

	// Allocate enough space for the global pointers
	// Sellers are managed a bit differently due to the presence of markets
	// that break the 1:1 assumption
	if Sellers == nil {
		Sellers = make([]mtgban.Seller, 0, len(newSellers))
	}
	if Vendors == nil {
		Vendors = make([]mtgban.Vendor, len(newVendors))
	}

	updateStaticData()

	if SkipPrices {
		log.Println("no prices loaded as requested")
		return
	}

	log.Println("Scraper Map table")
	var msgM string
	for key, val := range ScraperMap {
		msgM += fmt.Sprintf("%s -> %s\n", key, val)
	}
	ServerNotify("init", msgM)

	log.Println("Sellers table")
	var msgS string
	for i := range newSellers {
		msgS += fmt.Sprintf("%d ", i)
		if newSellers[i] == nil {
			msgS += "<nil>\n"
			continue
		}
		msgS += fmt.Sprintf("%s %s\n", newSellers[i].Info().Name, newSellers[i].Info().Shorthand)
	}
	ServerNotify("init", msgS)
	loadSellers(newSellers)

	loadTCGDirectNet(newVendors)

	log.Println("Vendors table")
	var msgV string
	for i := range newVendors {
		msgV += fmt.Sprintf("%d ", i)
		if newVendors[i] == nil {
			msgV += "<nil>\n"
			continue
		}
		msgV += fmt.Sprintf("%s %s\n", newVendors[i].Info().Name, newVendors[i].Info().Shorthand)
	}
	ServerNotify("init", msgV)
	loadVendors(newVendors)

	if BenchMode {
		return
	}

	if init {
		ServerNotify("init", "loading completed")
	} else {
		ServerNotify("refresh", "full refresh completed")
	}
}

func updateStaticData() {
	if Infos == nil {
		Infos = map[string]mtgban.InventoryRecord{}
	}

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

	if !SkipInitialRefresh {
		go loadInfos()
	}
	go runSealedAnalysis()

	// Load prices for API users
	if !DevMode {
		go prepareCKAPI()
	}

	LastUpdate = time.Now().Format(time.RFC3339)
}

func loadSellers(newSellers []mtgban.Seller) {
	defer recoverPanicScraper()

	init := !DatabaseLoaded
	currentDir := path.Join(InventoryDir, fmt.Sprintf("%03d", time.Now().YearDay()))
	mkDirIfNotExisting(currentDir)

	// Load Sellers
	for i := range newSellers {
		// Find where our seller resides in the global array
		sellerIndex := -1
		for j, seller := range Sellers {
			if seller != nil && newSellers[i].Info().Shorthand == seller.Info().Shorthand {
				sellerIndex = j
				break
			}
		}

		log.Println(newSellers[i].Info().Name, newSellers[i].Info().Shorthand, "Inventory at position", sellerIndex)

		fname := path.Join(InventoryDir, newSellers[i].Info().Shorthand+"-latest.json")
		if init && fileExists(fname) {
			seller, err := loadInventoryFromFile(fname)
			if err != nil {
				log.Println(err)
				continue
			}
			if sellerIndex < 0 {
				Sellers = append(Sellers, seller)
			} else {
				Sellers[sellerIndex] = seller
			}

			inv, _ := seller.Inventory()
			log.Printf("Loaded from file with %d entries", len(inv))
		} else {
			shorthand := newSellers[i].Info().Shorthand
			opts := ScraperOptions[ScraperMap[shorthand]]

			// If the old scraper data is old enough, pull from the new scraper
			// and update it in the global slice
			if sellerIndex < 0 || // Sellers[] != nil is checked above
				time.Since(*Sellers[sellerIndex].Info().InventoryTimestamp) > SkipRefreshCooldown {
				ServerNotify("reload", "Loading from seller "+shorthand)
				start := time.Now()
				err := updateSellerAtPosition(newSellers[i], sellerIndex, true)
				if err != nil {
					msg := fmt.Sprintf("seller %s %s - %s", newSellers[i].Info().Name, shorthand, err.Error())
					ServerNotify("reload", msg, true)
					continue
				}
				log.Println("Took", time.Since(start))
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
				continue
			}
			opts.Logger.Println("Saved to file")

			targetDir := path.Join(InventoryDir, time.Now().Format("2006-01-02/15"))
			err = uploadSeller(newSellers[i], targetDir)
			if err != nil {
				log.Println(err)
				continue
			}
			opts.Logger.Println("Uploaded to the cloud")
		}
		log.Println("-- OK")
	}
}

func loadVendors(newVendors []mtgban.Vendor) {
	defer recoverPanicScraper()

	init := !DatabaseLoaded
	currentDir := path.Join(BuylistDir, fmt.Sprintf("%03d", time.Now().YearDay()))
	mkDirIfNotExisting(currentDir)

	// Load Vendors
	for i := range newVendors {
		log.Println(newVendors[i].Info().Name, newVendors[i].Info().Shorthand, "Buylist")

		fname := path.Join(BuylistDir, newVendors[i].Info().Shorthand+"-latest.json")
		if init && fileExists(fname) {
			vendor, err := loadBuylistFromFile(fname)
			if err != nil {
				log.Println(err)
				continue
			}
			Vendors[i] = vendor

			bl, _ := vendor.Buylist()
			log.Printf("Loaded from file with %d entries", len(bl))
		} else {
			opts := ScraperOptions[ScraperMap[newVendors[i].Info().Shorthand]]

			// If the old scraper data is old enough, pull from the new scraper
			// and update it in the global slice
			if Vendors[i] == nil || time.Since(*Vendors[i].Info().BuylistTimestamp) > SkipRefreshCooldown {
				ServerNotify("reload", "Loading from vendor "+newVendors[i].Info().Shorthand)
				start := time.Now()
				err := updateVendorAtPosition(newVendors[i], i, true)
				if err != nil {
					msg := fmt.Sprintf("vendor %s %s - %s", newVendors[i].Info().Name, newVendors[i].Info().Shorthand, err.Error())
					ServerNotify("reload", msg, true)
					continue
				}
				log.Println("Took", time.Since(start))
			}

			// Stash data to DB if requested
			if opts.StashBuylist {
				start := time.Now()
				log.Println("Stashing", Vendors[i].Info().Shorthand, "buylist data to DB")
				bl, _ := Vendors[i].Buylist()
				key := Vendors[i].Info().BuylistTimestamp.Format("2006-01-02")
				for uuid, entries := range bl {
					err := opts.RDBs["buylist"].HSet(context.Background(), uuid, key, entries[0].BuyPrice).Err()
					if err != nil {
						ServerNotify("redis", err.Error())
						break
					}
				}
				log.Println("Took", time.Since(start))
			}

			err := dumpBuylistToFile(Vendors[i], currentDir, fname)
			if err != nil {
				log.Println(err)
				continue
			}
			opts.Logger.Println("Saved to file")

			targetDir := path.Join(BuylistDir, time.Now().Format("2006-01-02/15"))
			err = uploadVendor(Vendors[i], targetDir)
			if err != nil {
				log.Println(err)
				continue
			}
			opts.Logger.Println("Uploaded to the cloud")
		}
		log.Println("-- OK")
	}
}

func loadInfos() {
	log.Println("Loading infos")

	// MTGSTOCKS
	loadInfoScraper(mtgstocks.NewScraper())

	// TCGSYP
	scraper := tcgplayer.NewScraperSYP()
	scraper.Affiliate = Config.Affiliate["TCG"]
	loadInfoScraper(scraper)

	ServerNotify("refresh", "infos refreshed")
}

func loadInfoScraper(seller mtgban.Seller) {
	inv, err := seller.Inventory()
	if err != nil {
		log.Println(err)
		return
	}
	Infos[seller.Info().Shorthand] = inv
	log.Println("Infos loaded:", seller.Info().Name)
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
