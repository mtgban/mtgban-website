package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"maps"
	"net"
	"path"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"
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

	// dumpsBucket is where bantool publishes every game's dumps, each at
	// <game>/<store>/<kind>/<shorthand>.<dumpFormat>.
	dumpsBucket = "mtgban-dumps"
	dumpFormat  = "json.xz"
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
	Icons        map[string]string `json:"icons"`
	NameOverride map[string]string `json:"name_override"`
	Stores       []string          `json:"stores"`
}

// scraperIndex is a snapshot of what the dumps bucket publishes: byStore is
// store -> kind -> shorthands, byShorthand is the reverse lookup the admin
// dashboard uses. Immutable once published.
type scraperIndex struct {
	byStore     map[string]map[string][]string
	byShorthand map[string]string
}

func newScraperIndex() *scraperIndex {
	return &scraperIndex{byStore: map[string]map[string][]string{}, byShorthand: map[string]string{}}
}

// add records one dump. Safe to call more than once for the same triple.
func (idx *scraperIndex) add(store, kind, shorthand string) {
	if idx.byStore[store] == nil {
		idx.byStore[store] = map[string][]string{}
	}
	if !slices.Contains(idx.byStore[store][kind], shorthand) {
		idx.byStore[store][kind] = append(idx.byStore[store][kind], shorthand)
	}
	idx.byShorthand[shorthand] = store
}

// replaceStore replaces store's entries with kinds, dropping any shorthand
// not in kinds from the reverse lookup.
func (idx *scraperIndex) replaceStore(store string, kinds map[string][]string) {
	for sh, s := range idx.byShorthand {
		if s == store {
			delete(idx.byShorthand, sh)
		}
	}
	delete(idx.byStore, store)
	for kind, list := range kinds {
		for _, sh := range list {
			idx.add(store, kind, sh)
		}
	}
}

// buildScraperIndex derives a scraperIndex - including the reverse
// shorthand->store lookup - from a store -> kind -> shorthands map, the shape
// a listing produces and tests already build by hand.
func buildScraperIndex(byStore map[string]map[string][]string) *scraperIndex {
	idx := newScraperIndex()
	for store, kinds := range byStore {
		for kind, list := range kinds {
			for _, sh := range list {
				idx.add(store, kind, sh)
			}
		}
	}
	return idx
}

// scraperIndexPtr holds the currently published scraperIndex, next to
// sellersPtr/vendorsPtr above. Only loadScrapersNG (full replace) and
// updateScraperIndexStore (single-store replace) publish to it.
var scraperIndexPtr atomic.Pointer[scraperIndex]

// emptyScraperIndex is served before the first listing publishes.
var emptyScraperIndex = newScraperIndex()

// currentScraperIndex returns the live scraperIndex, or an empty one before
// the first load. Never nil.
func currentScraperIndex() *scraperIndex {
	idx := scraperIndexPtr.Load()
	if idx != nil {
		return idx
	}
	return emptyScraperIndex
}

// scraperStoreConfig returns the current store -> kind -> shorthands map.
// Callers must not mutate it.
func scraperStoreConfig() map[string]map[string][]string {
	return currentScraperIndex().byStore
}

// scraperStoreOf returns the store that publishes shorthand, per the last
// listing - the dashboard's per-row "Id" column.
func scraperStoreOf(shorthand string) (string, bool) {
	store, ok := currentScraperIndex().byShorthand[shorthand]
	return store, ok
}

// updateScraperIndexStore replaces store's entry in the published index
// with kinds. It copies the current maps rather than rebuilding them, so
// the store takes the shorthands it publishes and every other entry keeps
// its owner. Serialized on scrapersWriteMu.
func updateScraperIndexStore(store string, kinds map[string][]string) {
	scrapersWriteMu.Lock()
	defer scrapersWriteMu.Unlock()

	current := currentScraperIndex()
	next := newScraperIndex()
	maps.Copy(next.byStore, current.byStore)
	maps.Copy(next.byShorthand, current.byShorthand)
	next.replaceStore(store, kinds)
	scraperIndexPtr.Store(next)
}

// parseDumpKey parses a bucket key of the form
// "<game>/<store>/<kind>/<shorthand>.json.xz", or reports ok=false for a
// stray object, a wrong kind, or the wrong extension.
func parseDumpKey(key string, game mtgmatcher.Game) (store, kind, shorthand string, ok bool) {
	rest, ok := strings.CutPrefix(key, string(game)+"/")
	if !ok {
		return "", "", "", false
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 3 {
		return "", "", "", false
	}
	store, kind, filename := parts[0], parts[1], parts[2]
	if kind != "retail" && kind != "buylist" {
		return "", "", "", false
	}
	shorthand, ok = strings.CutSuffix(filename, "."+dumpFormat)
	if !ok || store == "" || shorthand == "" {
		return "", "", "", false
	}
	return store, kind, shorthand, true
}

// listDumps lists every dump under prefix and returns it as a scraperIndex,
// parsing each key against game+"/" regardless of how much further prefix
// narrows it. bucket must implement simplecloud.Lister.
func listDumps(ctx context.Context, bucket simplecloud.Reader, game mtgmatcher.Game, prefix string) (*scraperIndex, error) {
	lister, ok := bucket.(simplecloud.Lister)
	if !ok {
		return nil, fmt.Errorf("%T cannot list dumps", bucket)
	}

	idx := newScraperIndex()
	for obj, err := range lister.List(ctx, prefix) {
		if err != nil {
			return nil, err
		}
		store, kind, shorthand, ok := parseDumpKey(obj.Key, game)
		if !ok {
			log.Printf("ignoring unrecognized dump key %q", obj.Key)
			continue
		}
		idx.add(store, kind, shorthand)
	}
	return idx, nil
}

// listDumpsWithRetry is listDumps with loadScraperWithRetry's policy: each
// attempt times out after scraperLoadTimeout, and only a timeout is
// retried.
func listDumpsWithRetry(bucket simplecloud.Reader, game mtgmatcher.Game, prefix string) (*scraperIndex, error) {
	var lastErr error
	for attempt := range scraperLoadRetries {
		if attempt > 0 {
			delay := time.Duration(attempt) * 5 * time.Second
			log.Printf("retrying listing %s (attempt %d/%d) after %v", prefix, attempt+1, scraperLoadRetries, delay)
			time.Sleep(delay)
		}

		ctx, cancel := context.WithTimeout(context.Background(), scraperLoadTimeout)
		idx, err := listDumps(ctx, bucket, game, prefix)
		cancel()
		if err == nil {
			return idx, nil
		}
		lastErr = err
		if !isTimeout(lastErr) {
			return nil, lastErr
		}
		log.Printf("listing %s timed out: %v", prefix, lastErr)
	}
	return nil, lastErr
}

// openDumpsBucket opens dumpsBucket with its bucket_keys key pair.
func openDumpsBucket(ctx context.Context) (*simplecloud.B2Bucket, error) {
	bucket, err := newB2ClientFor(ctx, dumpsBucket)
	if err != nil {
		return nil, err
	}
	bucket.ConcurrentDownloads = bucketConcurrentDownloads
	return bucket, nil
}

// onlyStores narrows idx to stores, logging each one it does not list. It
// adds them sorted, the order a listing adds them in, so a shorthand two of
// them publish keeps the owner the full listing gives it.
func onlyStores(idx *scraperIndex, stores []string) *scraperIndex {
	log.Println("Loading only these stores:", strings.Join(stores, ", "))

	next := newScraperIndex()
	for _, store := range slices.Sorted(slices.Values(stores)) {
		kinds, found := idx.byStore[store]
		if !found {
			log.Println("Store", store, "is not in the dumps listing")
			continue
		}
		for kind, list := range kinds {
			for _, shorthand := range list {
				next.add(store, kind, shorthand)
			}
		}
	}
	return next
}

// loadScrapersNG lists the dumps in bucket, publishes the index and loads
// every dump. A non-empty stores narrows both to those stores.
func loadScrapersNG(bucket simplecloud.Reader, stores []string) error {
	idx, err := listDumpsWithRetry(bucket, Config().Game, string(Config().Game)+"/")
	if err != nil {
		return fmt.Errorf("listing dumps: %w", err)
	}
	if len(stores) > 0 {
		idx = onlyStores(idx, stores)
	}

	// Publish before loading, so no reader sees every store as unknown
	// during the load, and a concurrent /api/load isn't overwritten.
	scrapersWriteMu.Lock()
	scraperIndexPtr.Store(idx)
	scrapersWriteMu.Unlock()

	type scraperLoad struct {
		name      string
		kind      string
		shorthand string
	}

	var loads []scraperLoad
	for name, scrapersConfig := range idx.byStore {
		for kind, list := range scrapersConfig {
			for _, shorthand := range list {
				loads = append(loads, scraperLoad{name, kind, shorthand})
			}
		}
	}
	log.Println("Loading", len(loads), "scrapers")

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
			err := loadScraperWithRetry(bucket, Config().Game, load.name, load.kind, load.shorthand)
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

func loadScraperWithRetry(bucket simplecloud.Reader, game mtgmatcher.Game, name, kind, shorthand string) error {
	var lastErr error
	for attempt := range scraperLoadRetries {
		if attempt > 0 {
			delay := time.Duration(attempt) * 5 * time.Second
			log.Printf("retrying %s/%s/%s (attempt %d/%d) after %v",
				name, kind, shorthand, attempt+1, scraperLoadRetries, delay)
			time.Sleep(delay)
		}

		lastErr = loadScraper(bucket, game, name, kind, shorthand)
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

func loadScraper(bucket simplecloud.Reader, game mtgmatcher.Game, name, kind, shorthand string) error {
	key := path.Join(string(game), name, kind, shorthand) + "." + dumpFormat

	log.Println("loading", key)

	ctx, cancel := context.WithTimeout(context.Background(), scraperLoadTimeout)
	defer cancel()

	reader, err := simplecloud.InitReader(ctx, bucket, key)
	if err != nil {
		return err
	}

	// Force-close reader when context deadline expires, unblocking any
	// in-progress Read() that the context alone cannot interrupt.
	go func() {
		<-ctx.Done()
		reader.Close()
	}()

	var installErr error
	switch kind {
	case "retail":
		scraper, err := mtgban.ReadSellerFromJSON(reader)
		if err != nil {
			cancel()
			reader.Close()
			return err
		}
		installErr = updateSellers(scraper)
	case "buylist":
		scraper, err := mtgban.ReadVendorFromJSON(reader)
		if err != nil {
			cancel()
			reader.Close()
			return err
		}
		installErr = updateVendors(scraper)
	}

	cancel()
	reader.Close()
	// CK's buylist signals are computed from its buylist and stock.
	if installErr == nil && strings.EqualFold(shorthand, "CK") {
		rebuildCKSignals()
	}
	return installErr
}

// updateSellers installs the seller over its registered slot, answering with
// the refusal where buildNextSellers turns the swap down. The caller is what
// carries the answer back to whoever asked for the load - the reload
// endpoint used to write its "ok" before this decision was made, so a
// refused install was invisible to the workflow that pinged it and only the
// notification channel knew.
func updateSellers(scraper mtgban.Scraper) error {
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
		return err
	}
	sellersPtr.Store(&next)

	msg := fmt.Sprintf("%s inventory updated at position %d", scraper.Info().Shorthand, sellerIndex)
	ServerNotify("refresh", msg)
	return nil
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

// updateVendors is updateSellers for the buylist side.
func updateVendors(scraper mtgban.Scraper) error {
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
		return err
	}
	vendorsPtr.Store(&next)

	msg := fmt.Sprintf("%s buylist updated at position %d", scraper.Info().Shorthand, vendorIndex)
	ServerNotify("refresh", msg)
	return nil
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
