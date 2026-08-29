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

	// How many scrapers are fetched at once during a full load. Each one in
	// flight holds a decoded inventory, so the ceiling here is memory rather
	// than anything the bucket imposes.
	scraperLoadConcurrency = 6

	// blazer's range parallelism within a single object. It multiplies with
	// the fan-out above, hence lower than what a serial loader could afford.
	bucketConcurrentDownloads = 4
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
		b2Bucket.ConcurrentDownloads = bucketConcurrentDownloads

		DataBucket = b2Bucket
	default:
		return fmt.Errorf("unsupported path scheme %s", u.Scheme)
	}

	type scraperLoad struct {
		name      string
		kind      string
		shorthand string
	}

	var loads []scraperLoad
	for name, scrapersConfig := range config.Config {
		for kind, list := range scrapersConfig {
			for _, shorthand := range list {
				loads = append(loads, scraperLoad{name, kind, shorthand})
			}
		}
	}

	type loadResult struct {
		entry string
		err   error
	}

	var loaded int
	var failed []string

	// The tally needs no lock: WorkerPool runs consume on this goroutine, and
	// publishing is already serialized by updateSellers/updateVendors. A load
	// that fails travels as a result rather than as the worker's error, since
	// the summary reports it and loadScraperWithRetry has already logged it.
	mtgban.WorkerPool(context.Background(), scraperLoadConcurrency, loads,
		func(ctx context.Context, load scraperLoad, results chan<- loadResult) error {
			err := loadScraperWithRetry(DataBucket, config.BucketPath, Config.Game, load.name, load.kind, load.shorthand, config.BucketFileFormat)
			results <- loadResult{
				entry: fmt.Sprintf("%s/%s/%s", load.name, load.kind, load.shorthand),
				err:   err,
			}
			return nil
		},
		func(result loadResult) {
			if result.err != nil {
				failed = append(failed, fmt.Sprintf("%s: %s", result.entry, result.err))
				return
			}
			loaded++
		},
		nil,
	)

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
	inv := seller.Inventory()

	// A dump holding nothing is the most broken one there is, and it used to be
	// the only one accepted without question: the shrink check below asks for
	// half the previous size, which no empty dump can fail, and a first
	// registration is not checked at all. Refuse it here, so a scraper that
	// published nothing keeps serving what it had instead of answering every
	// lookup with "no".
	if len(inv) == 0 {
		return nil, errors.New("new inventory has no entries")
	}

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

	old := current[i].Inventory()
	if len(inv) < len(old)/2 && len(old) > 100 {
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
	bl := vendor.Buylist()

	// Empty is refused for the same reason as an inventory, and it matters more
	// here: the buylist metrics reduce over whatever this record holds, so an
	// empty one does not report "no card qualifies", it reports nothing at all
	// and takes the hotlist down with it.
	if len(bl) == 0 {
		return nil, errors.New("new buylist has no entries")
	}

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

	old := current[i].Buylist()
	if len(bl) < len(old)/2 && len(old) > 100 {
		return nil, errors.New("new buylist is missing too many entries")
	}

	next := make([]mtgban.Vendor, len(current))
	copy(next, current)
	next[i] = vendor
	return next, nil
}
