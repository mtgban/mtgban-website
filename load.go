package main

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/Backblaze/blazer/b2"
	"github.com/dsnet/compress/bzip2"
	cleanhttp "github.com/hashicorp/go-cleanhttp"
	xzReader "github.com/xi2/xz"

	"github.com/mtgban/go-mtgban/mtgban"
)

var B2Bucket *b2.Bucket

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
	case "", "http", "https":
	case "b2":
		if B2Bucket == nil {
			client, err := b2.NewClient(context.Background(), config.BucketAccessKey, config.BucketSecretKey)
			if err != nil {
				return err
			}

			B2Bucket, err = client.Bucket(context.Background(), u.Host)
			if err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unsupported path scheme %s", u.Scheme)
	}

	for name, scrapersConfig := range config.Config {
		for kind, list := range scrapersConfig {
			for _, shorthand := range list {
				err := loadScraper(config.BucketPath, Config.Game, name, kind, shorthand, config.BucketFileFormat)
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

func loadScraper(path, game, name, kind, shorthand, format string) error {
	u, err := url.Parse(path)
	if err != nil {
		return err
	}

	u.Path = filepath.Join(game, name, kind, shorthand) + "." + format

	log.Println("loading", u.String())

	reader, err := loadData(u.String())
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

func loadData(pathOpt string) (io.ReadCloser, error) {
	var reader io.ReadCloser

	u, err := url.Parse(pathOpt)
	if err != nil {
		return nil, err
	}
	switch u.Scheme {
	case "http", "https":
		resp, err := cleanhttp.DefaultClient().Get(pathOpt)
		if err != nil {
			return nil, err
		}

		reader = resp.Body
	case "b2":
		src := strings.TrimPrefix(u.Path, "/")
		obj := B2Bucket.Object(src).NewReader(context.Background())
		obj.ConcurrentDownloads = 20

		reader = obj
	default:
		file, err := os.Open(pathOpt)
		if err != nil {
			return nil, err
		}

		reader = file
	}

	if strings.HasSuffix(pathOpt, "xz") {
		xzReader, err := xzReader.NewReader(reader, 0)
		if err != nil {
			return nil, err
		}
		reader = io.NopCloser(xzReader)
	} else if strings.HasSuffix(pathOpt, "bz2") {
		bz2Reader, err := bzip2.NewReader(reader, nil)
		if err != nil {
			return nil, err
		}
		reader = bz2Reader
	} else if strings.HasSuffix(pathOpt, "gz") {
		zipReader, err := gzip.NewReader(reader)
		if err != nil {
			return nil, err
		}
		reader = zipReader
	}

	return reader, err
}

func updateSellers(scraper mtgban.Scraper) {
	sellerIndex := -1
	for i, seller := range Sellers {
		if seller != nil && seller.Info().Shorthand == scraper.Info().Shorthand {
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
		return nil
	}

	// Check timestamp
	if seller.Info().InventoryTimestamp.Before(*Sellers[i].Info().InventoryTimestamp) {
		return errors.New("new inventory is older than current one")
	}

	// Load inventory
	inv, err := seller.Inventory()
	if err != nil {
		return err
	}

	// Do not update in case the new inventory wasn't completely loaded
	// for example due to API problems
	old, _ := Sellers[i].Inventory()
	if len(inv) > 0 && len(inv) < len(old)/2 {
		return errors.New("new inventory is missing too many entries")
	}

	// Make sure the input seller is _only_ a Seller and not anything
	// else, so that filtering works like expected
	outSeller := mtgban.NewSellerFromInventory(inv, seller.Info())

	// Save seller in global array
	if i < 0 {
		Sellers = append(Sellers, outSeller)
	} else {
		Sellers[i] = outSeller
	}

	return nil
}

func updateVendors(scraper mtgban.Scraper) {
	vendorIndex := -1
	for i, vendor := range Vendors {
		if vendor != nil && vendor.Info().Shorthand == scraper.Info().Shorthand {
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
		return nil
	}

	// Check timestamp
	if vendor.Info().BuylistTimestamp.Before(*Vendors[i].Info().BuylistTimestamp) {
		return errors.New("new buylist is older than current one")
	}

	// Load buylist
	bl, err := vendor.Buylist()
	if err != nil {
		return err
	}

	// Do not update in case the new buylist wasn't completely loaded
	// for example due to API problems
	old, _ := Vendors[i].Buylist()
	if len(bl) > 0 && len(bl) < len(old)/2 {
		return errors.New("new buylist is missing too many entries")
	}

	// Save vendor in global array, making sure it's _only_ a Vendor
	// and not anything esle, so that filtering works like expected
	outVendor := mtgban.NewVendorFromBuylist(bl, vendor.Info())

	// Save vendor in global array
	if i < 0 {
		Vendors = append(Vendors, outVendor)
	} else {
		Vendors[i] = outVendor
	}

	return nil
}
