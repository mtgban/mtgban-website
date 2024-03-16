package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path"
	"sort"
	"sync"
	"time"

	"cloud.google.com/go/bigquery"
	"github.com/go-redis/redis/v8"
	"google.golang.org/api/iterator"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/go-mtgban/mtgstocks"
	"github.com/mtgban/go-mtgban/tcgplayer"
)

type dbElement struct {
	UUID string `json:"uuid"`
	mtgban.InventoryEntry
	mtgban.BuylistEntry `json:"-"`
}

var defaultGradeMap = map[string]float64{
	"NM": 1, "SP": 1.25, "MP": 1.67, "HP": 2.5, "PO": 4,
}

func (e *dbElement) Load(v []bigquery.Value, schema bigquery.Schema) error {
	for i, field := range schema {
		if v[i] == nil {
			continue
		}

		switch field.Name {
		case "CKTitle", "CKID", "CKFoil", "CKSKU", "CKEdition",
			"SCGName", "SCGEdition", "SCGLanguage", "SCGFinish":
			strVal, ok := v[i].(string)
			if !ok {
				return fmt.Errorf("expected string for %s, got %T", field.Name, v[i])
			}
			if e.BuylistEntry.CustomFields == nil {
				e.BuylistEntry.CustomFields = map[string]string{}
			}
			e.BuylistEntry.CustomFields[field.Name] = strVal

		case "price_ratio", "trade_price", "buy_price", "price":
			floatVal, ok := v[i].(float64)
			if !ok {
				// value might be int
				if intVal, ok := v[i].(int64); ok {
					floatVal = float64(intVal)
				} else {
					return fmt.Errorf("expected float64 for %s, got %T", field.Name, v[i])
				}
			}
			switch field.Name {
			case "price_ratio":
				e.BuylistEntry.PriceRatio = floatVal
			case "trade_price":
				e.BuylistEntry.TradePrice = floatVal
			case "buy_price":
				e.BuylistEntry.BuyPrice = floatVal
			case "price":
				e.InventoryEntry.Price = floatVal
			}

		case "url", "conditions", "UUID":
			strVal, ok := v[i].(string)
			if !ok {
				return fmt.Errorf("expected string for %s, got %T", field.Name, v[i])
			}
			switch field.Name {
			case "url":
				e.InventoryEntry.URL = strVal
				e.BuylistEntry.URL = strVal
			case "conditions":
				e.InventoryEntry.Conditions = strVal
				e.BuylistEntry.Conditions = strVal
			case "UUID":
				e.UUID = strVal
			}

		case "quantity":
			intVal, ok := v[i].(int64)
			if !ok {
				return fmt.Errorf("expected int64 for quantity, got %T", v[i])
			}
			e.InventoryEntry.Quantity = int(intVal)
			e.BuylistEntry.Quantity = int(intVal)
		}
	}

	return nil
}

const SellersPath = "sellers"
const VendorsPath = "vendors"

func startup() error {
	errS, errV := mkDirIfNotExisting(SellersPath), mkDirIfNotExisting(VendorsPath)
	if errS != nil || errV != nil {
		return errors.New("unable to create cache folders")
	}

	var sellers []mtgban.Seller
	var vendors []mtgban.Vendor

	now := time.Now()
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		files, err := os.ReadDir(SellersPath)
		if err != nil {
			log.Println(err.Error())
			return
		}

		for _, fileInfo := range files {
			seller, err := loadSellerFromFile(path.Join(SellersPath, fileInfo.Name()))
			if err != nil {
				log.Println(err.Error())
				continue
			}
			sellers = append(sellers, seller)
		}

		sort.Slice(sellers, func(i, j int) bool {
			if sellers[i].Info().Name == sellers[j].Info().Name {
				return sellers[i].Info().Shorthand < sellers[j].Info().Shorthand
			}
			return sellers[i].Info().Name < sellers[j].Info().Name
		})
		Sellers = sellers

		wg.Done()
	}()

	go func() {
		files, err := os.ReadDir(VendorsPath)
		if err != nil {
			log.Println(err.Error())
			return
		}

		for _, fileInfo := range files {
			vendor, err := loadVendorFromFile(path.Join(VendorsPath, fileInfo.Name()))
			if err != nil {
				log.Println(err.Error())
				continue
			}
			vendors = append(vendors, vendor)
		}

		sort.Slice(vendors, func(i, j int) bool {
			if vendors[i].Info().Name == vendors[j].Info().Name {
				return vendors[i].Info().Shorthand < vendors[j].Info().Shorthand
			}
			return vendors[i].Info().Name < vendors[j].Info().Name
		})
		Vendors = vendors

		wg.Done()
	}()

	wg.Wait()

	if len(Sellers) > 0 && len(Vendors) > 0 {
		DatabaseLoaded = true
		log.Println("DB loaded from cache in", time.Since(now), "with", len(Sellers), "sellers and", len(Vendors), "vendors")
	}
	return nil
}

func loadInventoryFromTable(client *bigquery.Client, tableName string) (mtgban.InventoryRecord, error) {
	if tableName == "" {
		return nil, errors.New("empty table name")
	}

	inv := mtgban.InventoryRecord{}

	// Load the table and iterate on the rows
	table := client.Dataset(Config.Uploader.DatasetID).Table(tableName)
	it := table.Read(context.Background())
	for {
		var element dbElement

		// Load db item into our own data type
		err := it.Next(&element)
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		// Convert into the expected format
		inv[element.UUID] = append(inv[element.UUID], element.InventoryEntry)
	}

	return inv, nil
}

func loadBuylistFromTable(client *bigquery.Client, tableName string) (mtgban.BuylistRecord, error) {
	if tableName == "" {
		return nil, errors.New("empty table name")
	}

	bl := mtgban.BuylistRecord{}
	table := client.Dataset(Config.Uploader.DatasetID).Table(tableName)
	it := table.Read(context.Background())
	for {
		var element dbElement

		err := it.Next(&element)
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		bl[element.UUID] = append(bl[element.UUID], element.BuylistEntry)
	}
	return bl, nil
}

type LoadSummary struct {
	SuccessCount int
	TotalCount   int
	Errors       []error
	ErrorTables  []string
}

func newLoadSummary(totalCount int) *LoadSummary {
	return &LoadSummary{
		TotalCount: totalCount,
	}
}

func (ls *LoadSummary) RecordSuccess() {
	ls.SuccessCount++
}

func (ls *LoadSummary) RecordError(err error, tableName string) {
	ls.Errors = append(ls.Errors, err)
	ls.ErrorTables = append(ls.ErrorTables, tableName)
}

func (ls *LoadSummary) LogSummary(side string, startTime time.Time) {
	if len(ls.Errors) == 0 {
		log.Printf("%s: All %d tables loaded successfully in %s.\n", side, ls.SuccessCount, time.Since(startTime))
	} else {
		log.Printf("%s: Encountered errors in %d/%d tables.\n", side, len(ls.Errors), ls.TotalCount)
		for _, err := range ls.Errors {
			log.Println(err)
		}
	}
}

func loadBQ(client *bigquery.Client) error {
	var sellers []mtgban.Seller
	var vendors []mtgban.Vendor

	// Set up a context and a BigQuery client.
	ctx := context.Background()
	if err != nil {
		return err
	}

	now := time.Now()
	sellerSummary := newLoadSummary(len(Config.Scrapers["sellers"]))
	vendorSummary := newLoadSummary(len(Config.Scrapers["vendors"]))
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		var subWg sync.WaitGroup
		channel := make(chan mtgban.Seller)

		for _, scraperData := range Config.Scrapers["sellers"] {
			scraperData := scraperData
			subWg.Add(1)
			go func() {
				defer subWg.Done()

				//log.Println("Loading seller", scraperData.TableName)
				now := time.Now()

				inv, err := loadInventoryFromTable(client, scraperData.TableName)
				if err != nil {
					//ServerNotify("BQ "+scraperData.TableName, err.Error())
					sellerSummary.RecordError(err, scraperData.TableName)
					return
				}
				//log.Println(scraperData.TableName, "took", time.Since(now), "for", len(inv), "items")

				// Create the metadata portion
				info := scraperData.ScraperInfo
				now = time.Now()
				info.InventoryTimestamp = &now

				// Send result on channel
				channel <- mtgban.NewSellerFromInventory(inv, info)
				sellerSummary.RecordSuccess()

				// Stash data to redis if requested
				if scraperData.HasRedis {
					redisClient := redis.NewClient(&redis.Options{
						Addr: "localhost:6379",
						DB:   scraperData.RedisIndex,
					})
					// Check redis is running
					_, err := redisClient.Ping(ctx).Result()
					if err != nil {
						log.Println("redis" + err.Error())
						return
					}

					start := time.Now()
					key := now.Format("2006-01-02")
					log.Println("Stashing", scraperData.Name, scraperData.Shorthand, "inventory data to DB")

					for uuid, entries := range inv {
						// Adjust price through defaultGradeMap in case NM is not available
						price := entries[0].Price * defaultGradeMap[entries[0].Conditions]
						err := redisClient.HSet(context.Background(), uuid, key, price).Err()
						if err != nil {
							ServerNotify("redis", err.Error())
							break
						}
					}
					log.Println("Redis for", scraperData.Shorthand, "inventory took", time.Since(start))
				}
			}()
		}

		// Sync to wait for all results above before closing channel
		go func() {
			subWg.Wait()
			close(channel)
		}()

		// Read data frome the goroutines spawned above
		for seller := range channel {
			sellers = append(sellers, seller)

			// Dump files
			err := dumpSellerToFile(seller, path.Join(SellersPath, seller.Info().Shorthand+".json"))
			if err != nil {
				log.Println(err.Error())
			}
		}

		// Sort array
		sort.Slice(sellers, func(i, j int) bool {
			if sellers[i].Info().Name == sellers[j].Info().Name {
				return sellers[i].Info().Shorthand < sellers[j].Info().Shorthand
			}
			return sellers[i].Info().Name < sellers[j].Info().Name
		})

		// Update main array
		Sellers = sellers

		// Signal we're done
		wg.Done()
	}()

	go func() {
		var subWg sync.WaitGroup
		channel := make(chan mtgban.Vendor)

		for _, scraperData := range Config.Scrapers["vendors"] {
			scraperData := scraperData
			subWg.Add(1)
			go func() {
				defer subWg.Done()

				//log.Println("Loading vendor", scraperData.TableName)
				now := time.Now()

				bl, err := loadBuylistFromTable(client, scraperData.TableName)
				if err != nil {
					//ServerNotify("BQ "+scraperData.TableName, err.Error())
					vendorSummary.RecordError(err, scraperData.TableName)
					return
				}
				//log.Println(scraperData.TableName, "took", time.Since(now), "for", len(bl), "items")

				info := scraperData.ScraperInfo
				now = time.Now()
				info.BuylistTimestamp = &now

				channel <- mtgban.NewVendorFromBuylist(bl, info)
				vendorSummary.RecordSuccess()

				if scraperData.HasRedis {
					redisClient := redis.NewClient(&redis.Options{
						Addr: "localhost:6379",
						DB:   scraperData.RedisIndex,
					})
					_, err := redisClient.Ping(ctx).Result()
					if err != nil {
						log.Println("redis" + err.Error())
						return
					}

					start := time.Now()
					log.Println("Stashing", scraperData.Name, scraperData.Shorthand, "buylist data to DB")

					key := now.Format("2006-01-02")
					for uuid, entries := range bl {
						err := redisClient.HSet(context.Background(), uuid, key, entries[0].BuyPrice).Err()
						if err != nil {
							ServerNotify("redis", err.Error())
							break
						}
					}
					log.Println("Redis for", scraperData.Shorthand, "buylist took", time.Since(start))
				}
			}()
		}

		go func() {
			subWg.Wait()
			close(channel)
		}()

		for vendor := range channel {
			vendors = append(vendors, vendor)

			err := dumpVendorToFile(vendor, path.Join(VendorsPath, vendor.Info().Shorthand+".json"))
			if err != nil {
				log.Println(err.Error())
			}
		}

		sort.Slice(vendors, func(i, j int) bool {
			if vendors[i].Info().Name == vendors[j].Info().Name {
				return vendors[i].Info().Shorthand < vendors[j].Info().Shorthand
			}
			return vendors[i].Info().Name < vendors[j].Info().Name
		})
		Vendors = vendors

		wg.Done()
	}()

	wg.Wait()
	sellerSummary.LogSummary("Sellers", now)
	vendorSummary.LogSummary("Vendors", now)

	if len(sellers) == 0 || len(vendors) == 0 {
		return errors.New("nothing got loaded")
	}

	DatabaseLoaded = true
	LastUpdate = time.Now().Format(time.RFC3339)
	//	log.Println("DB loaded from BQ in", time.Since(now), "with", len(Sellers), "sellers and", len(Vendors), "vendors")

	go updateStaticData()

	return nil
}

func updateScraper(tableName string) error {
	var found bool
	var idx int
	var group string
	for group = range Config.Scrapers {
		for i, scraperData := range Config.Scrapers[group] {
			if scraperData.TableName == tableName {
				idx = i
				found = true
				break
			}
		}
		if found {
			break
		}
	}
	if !found {
		return errors.New("not found")
	}

	ctx := context.Background()
	client, err := bigquery.NewClient(ctx, Config.ProjectId)
	if err != nil {
		return err
	}

	now := time.Now()
	info := Config.Scrapers[group][idx].ScraperInfo
	if group == "sellers" {
		inv, err := loadInventoryFromTable(client, tableName)
		if err != nil {
			return err
		}
		info.InventoryTimestamp = &now
		for i := range Sellers {
			if Sellers[i].Info().Shorthand == info.Shorthand {
				Sellers[i] = mtgban.NewSellerFromInventory(inv, info)
				break
			}
		}
	} else if group == "vendors" {
		bl, err := loadBuylistFromTable(client, tableName)
		if err != nil {
			return err
		}
		info.BuylistTimestamp = &now
		for i := range Vendors {
			if Vendors[i].Info().Shorthand == info.Shorthand {
				Vendors[i] = mtgban.NewVendorFromBuylist(bl, info)
				break
			}
		}
	}

	return nil
}

func updateStaticData() {
	if Infos == nil {
		Infos = map[string]mtgban.InventoryRecord{}
	}

	SealedEditionsSorted, SealedEditionsList = getSealedEditions()
	AllEditionsKeys, AllEditionsMap = getAllEditions()
	TreeEditionsKeys, TreeEditionsMap = getTreeEditions()

	TotalSets = len(AllEditionsKeys)
	TotalUnique = len(mtgmatcher.GetUUIDs())
	var totalCards int
	for _, key := range AllEditionsKeys {
		totalCards += AllEditionsMap[key].Size
	}
	TotalCards = totalCards

	go loadInfos()
	go runSealedAnalysis()

	// Load prices for API users
	if !DevMode {
		go prepareCKAPI()
	}
}

func loadInfos() {
	log.Println("Loading infos")

	for _, seller := range []mtgban.Seller{
		mtgstocks.NewScraper(),
		mtgstocks.NewScraperIndex(),
		tcgplayer.NewScraperSYP(),
	} {
		loadInfoScraper(seller)
	}
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

func loadDatastore() error {
	allPrintingsReader, err := os.Open(AllPrintingsFileName)
	if err != nil {
		return err
	}
	defer allPrintingsReader.Close()

	return mtgmatcher.LoadDatastore(allPrintingsReader)
}

func loadSellerFromFile(fname string) (mtgban.Seller, error) {
	file, err := os.Open(fname)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return mtgban.ReadSellerFromJSON(file)
}

func dumpSellerToFile(seller mtgban.Seller, fname string) error {
	file, err := os.Create(fname)
	if err != nil {
		return err
	}
	defer file.Close()

	return mtgban.WriteSellerToJSON(seller, file)
}

func loadVendorFromFile(fname string) (mtgban.Vendor, error) {
	file, err := os.Open(fname)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return mtgban.ReadVendorFromJSON(file)
}

func dumpVendorToFile(vendor mtgban.Vendor, fname string) error {
	file, err := os.Create(fname)
	if err != nil {
		return err
	}
	defer file.Close()

	return mtgban.WriteVendorToJSON(vendor, file)
}
