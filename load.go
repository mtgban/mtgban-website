package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"path"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/simplecloud"
)

const (
	// Maximum time allowed for a single scraper file download+parse.
	// Normal loads complete in <2s; this guards against hung B2 connections
	// that would otherwise block the reload goroutine indefinitely and
	// cause the GC to stall (pinning CPU).
	scraperLoadTimeout = 2 * time.Minute

	// Number of retry attempts for a failed/timed-out scraper load.
	scraperLoadRetries = 3
)

var DataBucket simplecloud.Reader

// Snapshots of the loaded retail and buylist data. Held behind atomic.Pointer
// so readers always observe a fully-constructed, immutable slice and writers
// publish via a single atomic store. Mutating the slice returned by
// GetSellers/GetVendors is a bug — treat it as read-only.
var (
	sellersPtr atomic.Pointer[[]mtgban.Seller]
	vendorsPtr atomic.Pointer[[]mtgban.Vendor]

	// Serializes writers so concurrent updateSellers/updateVendors calls
	// don't lose each other's changes during the read-modify-publish cycle.
	scrapersWriteMu sync.Mutex
)

// GetSellers returns the current sellers snapshot. The returned slice is
// shared and MUST NOT be modified by callers.
func GetSellers() []mtgban.Seller {
	p := sellersPtr.Load()
	if p == nil {
		return nil
	}
	return *p
}

// GetVendors returns the current vendors snapshot. The returned slice is
// shared and MUST NOT be modified by callers.
func GetVendors() []mtgban.Vendor {
	p := vendorsPtr.Load()
	if p == nil {
		return nil
	}
	return *p
}

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

	var loaded int
	var failed []string

	for name, scrapersConfig := range config.Config {
		for kind, list := range scrapersConfig {
			for _, shorthand := range list {
				err := loadScraperWithRetry(DataBucket, config.BucketPath, Config.Game, name, kind, shorthand, config.BucketFileFormat)
				if err != nil {
					failed = append(failed, fmt.Sprintf("%s/%s/%s: %s", name, kind, shorthand, err))
					continue
				}
				loaded++
			}
		}
	}

	// No @here: at startup nothing has loaded yet, so an absent scraper is
	// the ordinary state rather than news. Breakage worth waking someone for
	// is a scraper that was serving and stopped, which is the reload path.
	ServerNotify("reload", loadSummary(loaded, failed))

	return nil
}

func loadSummary(loaded int, failed []string) string {
	var b strings.Builder

	slices.Sort(failed)

	fmt.Fprintf(&b, "Server loaded %d/%d scrapers", loaded, loaded+len(failed))
	if len(failed) > 0 {
		fmt.Fprintf(&b, "\nnot loaded (%d): %s", len(failed), strings.Join(failed, "; "))
	}

	return b.String()
}

// isTimeout reports whether err is the hung-connection case scraperLoadTimeout
// exists to catch, which is the only thing worth a second attempt here: the B2
// client already retries what it considers transient before returning, and
// everything else, an unpublished dump most of all, is permanent.
func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func loadScraperWithRetry(bucket simplecloud.Reader, base, game, name, kind, shorthand, format string) error {
	var lastErr error
	for attempt := range scraperLoadRetries {
		if attempt > 0 {
			delay := time.Duration(attempt) * 5 * time.Second
			log.Printf("retrying %s/%s/%s (attempt %d/%d) after %v",
				name, kind, shorthand, attempt+1, scraperLoadRetries, delay)
			time.Sleep(delay)
		}

		lastErr = loadScraper(bucket, base, game, name, kind, shorthand, format)
		if lastErr == nil {
			return nil
		}
		if !isTimeout(lastErr) {
			return lastErr
		}

		log.Printf("load %s/%s/%s timed out: %v", name, kind, shorthand, lastErr)
	}
	return lastErr
}

func loadScraper(bucket simplecloud.Reader, base, game, name, kind, shorthand, format string) error {
	u, err := url.Parse(base)
	if err != nil {
		return err
	}

	u.Path = path.Join(game, name, kind, shorthand) + "." + format

	log.Println("loading", u.String())

	ctx, cancel := context.WithTimeout(context.Background(), scraperLoadTimeout)
	defer cancel()

	reader, err := simplecloud.InitReader(ctx, bucket, u.String())
	if err != nil {
		return err
	}

	// Force-close reader when context deadline expires, unblocking any
	// in-progress Read() that the context alone cannot interrupt.
	go func() {
		<-ctx.Done()
		reader.Close()
	}()

	switch kind {
	case "retail":
		scraper, err := mtgban.ReadSellerFromJSON(reader)
		if err != nil {
			cancel()
			reader.Close()
			return err
		}
		updateSellers(scraper)
	case "buylist":
		scraper, err := mtgban.ReadVendorFromJSON(reader)
		if err != nil {
			cancel()
			reader.Close()
			return err
		}
		updateVendors(scraper)
	}

	cancel()
	reader.Close()
	return nil
}

func updateSellers(scraper mtgban.Scraper) {
	seller := applyInventoryOverrides(scraper.(mtgban.Seller))

	scrapersWriteMu.Lock()
	defer scrapersWriteMu.Unlock()

	current := GetSellers()

	sellerIndex := -1
	for i, s := range current {
		if s.Info().Shorthand == seller.Info().Shorthand {
			sellerIndex = i
			break
		}
	}

	next, err := buildNextSellers(current, seller, sellerIndex)
	if err != nil {
		msg := fmt.Sprintf("seller %s %s - %s", scraper.Info().Name, scraper.Info().Shorthand, err.Error())
		ServerNotify("refresh", msg, true)
		return
	}
	sellersPtr.Store(&next)

	msg := fmt.Sprintf("%s inventory updated at position %d", scraper.Info().Shorthand, sellerIndex)
	ServerNotify("refresh", msg)
}

func buildNextSellers(current []mtgban.Seller, seller mtgban.Seller, i int) ([]mtgban.Seller, error) {
	if i < 0 {
		next := make([]mtgban.Seller, len(current)+1)
		copy(next, current)
		next[len(current)] = seller

		slices.SortFunc(next, func(a, b mtgban.Seller) int {
			ret := strings.Compare(a.Info().Name, b.Info().Name)
			if ret == 0 {
				ret = strings.Compare(a.Info().Shorthand, b.Info().Shorthand)
			}
			return ret
		})
		return next, nil
	}

	if seller.Info().InventoryTimestamp.Before(*current[i].Info().InventoryTimestamp) {
		return nil, errors.New("new inventory is older than current one")
	}

	inv := seller.Inventory()
	old := current[i].Inventory()
	if len(inv) > 0 && len(inv) < len(old)/2 && len(old) > 100 {
		return nil, errors.New("new inventory is missing too many entries")
	}

	next := make([]mtgban.Seller, len(current))
	copy(next, current)
	next[i] = seller
	return next, nil
}

func updateVendors(scraper mtgban.Scraper) {
	vendor := applyBuylistOverrides(scraper.(mtgban.Vendor))

	scrapersWriteMu.Lock()
	defer scrapersWriteMu.Unlock()

	current := GetVendors()

	vendorIndex := -1
	for i, v := range current {
		if v.Info().Shorthand == vendor.Info().Shorthand {
			vendorIndex = i
			break
		}
	}

	next, err := buildNextVendors(current, vendor, vendorIndex)
	if err != nil {
		msg := fmt.Sprintf("vendor %s %s - %s", scraper.Info().Name, scraper.Info().Shorthand, err.Error())
		ServerNotify("refresh", msg, true)
		return
	}
	vendorsPtr.Store(&next)

	msg := fmt.Sprintf("%s buylist updated at position %d", scraper.Info().Shorthand, vendorIndex)
	ServerNotify("refresh", msg)
}

func buildNextVendors(current []mtgban.Vendor, vendor mtgban.Vendor, i int) ([]mtgban.Vendor, error) {
	if i < 0 {
		next := make([]mtgban.Vendor, len(current)+1)
		copy(next, current)
		next[len(current)] = vendor

		slices.SortFunc(next, func(a, b mtgban.Vendor) int {
			ret := strings.Compare(a.Info().Name, b.Info().Name)
			if ret == 0 {
				ret = strings.Compare(a.Info().Shorthand, b.Info().Shorthand)
			}
			return ret
		})
		return next, nil
	}

	if vendor.Info().BuylistTimestamp.Before(*current[i].Info().BuylistTimestamp) {
		return nil, errors.New("new buylist is older than current one")
	}

	bl := vendor.Buylist()
	old := current[i].Buylist()
	if len(bl) > 0 && len(bl) < len(old)/2 && len(old) > 100 {
		return nil, errors.New("new buylist is missing too many entries")
	}

	next := make([]mtgban.Vendor, len(current))
	copy(next, current)
	next[i] = vendor
	return next, nil
}
