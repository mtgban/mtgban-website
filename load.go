package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/url"
	"path/filepath"
	"slices"
	"strings"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/simplecloud"
)

var DataBucket simplecloud.Reader

// Slice containing all the loaded retail data
var Sellers []mtgban.Seller

// Slice containing all the loaded buylist data
var Vendors []mtgban.Vendor

type ScraperConfig struct {
	BucketAccessKey  string `json:"bucket_access_key"`
	BucketSecretKey  string `json:"bucket_access_secret"`
	BucketPath       string `json:"bucket_path"`
	BucketFileFormat string `json:"bucket_file_format"`

	Config map[string]map[string][]string `json:"config"`

	Icons        map[string]string `json:"icons"`
	NameOverride map[string]string `json:"name_override"`
}

func loadScrapersNG(config ScraperConfig) error {
	u, err := url.Parse(config.BucketPath)
	if err != nil {
		return err
	}

	switch u.Scheme {
	case "":
		DataBucket = &simplecloud.FileBucket{}
	case "b2":
		b2Bucket, err := simplecloud.NewB2Client(context.Background(), config.BucketAccessKey, config.BucketSecretKey, u.Host)
		if err != nil {
			return err
		}
		b2Bucket.ConcurrentDownloads = 20

		DataBucket = b2Bucket
	default:
		return fmt.Errorf("unsupported path scheme %s", u.Scheme)
	}

	for name, scrapersConfig := range config.Config {
		for kind, list := range scrapersConfig {
			for _, shorthand := range list {
				err := loadScraper(DataBucket, config.BucketPath, Config.Game, name, kind, shorthand, config.BucketFileFormat)
				if err != nil {
					log.Println(err)
					continue
				}
			}
		}
	}

	ServerNotify("reload", "Server loaded")

	return nil
}

func loadScraper(bucket simplecloud.Reader, path, game, name, kind, shorthand, format string) error {
	u, err := url.Parse(path)
	if err != nil {
		return err
	}

	u.Path = filepath.Join(game, name, kind, shorthand) + "." + format

	log.Println("loading", u.String())

	reader, err := simplecloud.InitReader(context.TODO(), bucket, u.String())
	if err != nil {
		return err
	}
	defer reader.Close()

	switch kind {
	case "retail":
		scraper, err := mtgban.ReadSellerFromJSON(reader)
		if err != nil {
			return err
		}
		updateSellers(scraper)
	case "buylist":
		scraper, err := mtgban.ReadVendorFromJSON(reader)
		if err != nil {
			return err
		}
		updateVendors(scraper)
	}

	return nil
}

func updateSellers(scraper mtgban.Scraper) {
	sellerIndex := -1
	for i, seller := range Sellers {
		if seller.Info().Shorthand == scraper.Info().Shorthand {
			sellerIndex = i
			break
		}
	}

	err := updateSellerAtPosition(scraper.(mtgban.Seller), sellerIndex)
	if err != nil {
		msg := fmt.Sprintf("seller %s %s - %s", scraper.Info().Name, scraper.Info().Shorthand, err.Error())
		ServerNotify("refresh", msg, true)
		return
	}

	msg := fmt.Sprintf("%s inventory updated at position %d", scraper.Info().Shorthand, sellerIndex)
	ServerNotify("refresh", msg)

	return
}

func updateSellerAtPosition(seller mtgban.Seller, i int) error {
	// Save seller in global array
	if i < 0 {
		Sellers = append(Sellers, seller)

		// Keep slices sorted
		slices.SortFunc(Sellers, func(a, b mtgban.Seller) int {
			ret := strings.Compare(a.Info().Name, b.Info().Name)
			if ret == 0 {
				ret = strings.Compare(a.Info().Shorthand, b.Info().Shorthand)
			}
			return ret
		})
		return nil
	}

	// Check timestamp
	if seller.Info().InventoryTimestamp.Before(*Sellers[i].Info().InventoryTimestamp) {
		return errors.New("new inventory is older than current one")
	}

	// Load inventory
	inv := seller.Inventory()

	// Do not update in case the new inventory wasn't completely loaded
	// for example due to API problems
	old := Sellers[i].Inventory()
	if len(inv) > 0 && len(inv) < len(old)/2 {
		return errors.New("new inventory is missing too many entries")
	}

	Sellers[i] = seller

	return nil
}

func updateVendors(scraper mtgban.Scraper) {
	vendorIndex := -1
	for i, vendor := range Vendors {
		if vendor.Info().Shorthand == scraper.Info().Shorthand {
			vendorIndex = i
			break
		}
	}

	err := updateVendorAtPosition(scraper.(mtgban.Vendor), vendorIndex)
	if err != nil {
		msg := fmt.Sprintf("vendor %s %s - %s", scraper.Info().Name, scraper.Info().Shorthand, err.Error())
		ServerNotify("refresh", msg, true)
		return
	}

	msg := fmt.Sprintf("%s buylist updated at position %d", scraper.Info().Shorthand, vendorIndex)
	ServerNotify("refresh", msg)

	return
}

func updateVendorAtPosition(vendor mtgban.Vendor, i int) error {
	// Save vendor in global array
	if i < 0 {
		Vendors = append(Vendors, vendor)

		// Keep slices sorted
		slices.SortFunc(Vendors, func(a, b mtgban.Vendor) int {
			ret := strings.Compare(a.Info().Name, b.Info().Name)
			if ret == 0 {
				ret = strings.Compare(a.Info().Shorthand, b.Info().Shorthand)
			}
			return ret
		})
		return nil
	}

	// Check timestamp
	if vendor.Info().BuylistTimestamp.Before(*Vendors[i].Info().BuylistTimestamp) {
		return errors.New("new buylist is older than current one")
	}

	// Load buylist
	bl := vendor.Buylist()

	// Do not update in case the new buylist wasn't completely loaded
	// for example due to API problems
	old := Vendors[i].Buylist()
	if len(bl) > 0 && len(bl) < len(old)/2 {
		return errors.New("new buylist is missing too many entries")
	}

	Vendors[i] = vendor

	return nil
}
