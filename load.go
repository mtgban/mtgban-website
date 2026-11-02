package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"maps"
	"net"
	"os"
	"path"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mtgban/go-mtgban/matcher"
	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/mtgban-website/internal/alerts"
	"github.com/mtgban/mtgban-website/internal/mkmidparser"
	"github.com/mtgban/mtgban-website/internal/sessionstore"
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

// prices is one published snapshot of the loaded stores: the retail and
// buylist sides, the by-shorthand index over them, the Cardmarket product
// ids the retail side prices and the dumps the bucket listed. A writer
// builds the next one whole and publishes it in a single Store, so a reader
// sees sides and indexes from the same publish. Nothing in a published
// value is changed in place: the slices GetSellers and GetVendors return
// are shared and read-only.
type prices struct {
	sellers  []mtgban.Seller
	vendors  []mtgban.Vendor
	index    storeIndex
	mkmIDs   mkmidparser.Index
	scrapers scraperIndex
}

var (
	// pricesPtr holds the published snapshot, nil until the first publish.
	pricesPtr atomic.Pointer[prices]

	// emptyPrices is served until then, so currentPrices is never nil
	// whatever reads first.
	emptyPrices = newPrices(nil, nil, *newScraperIndex())

	// Serializes writers so concurrent publishes don't lose each other's
	// changes during the read-build-publish cycle.
	scrapersWriteMu sync.Mutex
)

// currentPrices returns the published snapshot, or the empty one before the
// first publish. Never nil.
func currentPrices() *prices {
	p := pricesPtr.Load()
	if p == nil {
		return emptyPrices
	}
	return p
}

// newPrices builds the snapshot to publish from its parts, indexing the
// stores by shorthand and the Cardmarket shelves by product id.
func newPrices(sellers []mtgban.Seller, vendors []mtgban.Vendor, scrapers scraperIndex) *prices {
	return &prices{
		sellers:  sellers,
		vendors:  vendors,
		index:    buildStoreIndex(sellers, vendors),
		mkmIDs:   mkmidparser.Build(sellers),
		scrapers: scrapers,
	}
}

// GetSellers returns the current sellers snapshot. The returned slice is
// shared and MUST NOT be modified by callers.
func GetSellers() []mtgban.Seller {
	return currentPrices().sellers
}

// GetVendors returns the current vendors snapshot. The returned slice is
// shared and MUST NOT be modified by callers.
func GetVendors() []mtgban.Vendor {
	return currentPrices().vendors
}

// storeIndex is the by-shorthand lookup over one snapshot's sides, keyed
// both exactly and in lower case so each lookup keeps the match the scan it
// replaced made. It is built with the snapshot it indexes, so it cannot
// describe another one.
type storeIndex struct {
	// seller and vendor are keyed by the exact shorthand, sellerFold and
	// vendorFold by its lower case.
	seller     map[string]mtgban.Seller
	vendor     map[string]mtgban.Vendor
	sellerFold map[string]mtgban.Seller
	vendorFold map[string]mtgban.Vendor
}

// currentStoreIndex returns the published snapshot's index.
func currentStoreIndex() *storeIndex {
	return &currentPrices().index
}

// buildStoreIndex indexes the stores by shorthand. First wins on a
// duplicate, as the scans this replaced did.
func buildStoreIndex(sellers []mtgban.Seller, vendors []mtgban.Vendor) storeIndex {
	idx := storeIndex{
		seller:     make(map[string]mtgban.Seller, len(sellers)),
		vendor:     make(map[string]mtgban.Vendor, len(vendors)),
		sellerFold: make(map[string]mtgban.Seller, len(sellers)),
		vendorFold: make(map[string]mtgban.Vendor, len(vendors)),
	}
	for _, seller := range sellers {
		key := seller.Info().Shorthand
		if _, dup := idx.seller[key]; !dup {
			idx.seller[key] = seller
		}
		key = strings.ToLower(key)
		if _, dup := idx.sellerFold[key]; !dup {
			idx.sellerFold[key] = seller
		}
	}
	for _, vendor := range vendors {
		key := vendor.Info().Shorthand
		if _, dup := idx.vendor[key]; !dup {
			idx.vendor[key] = vendor
		}
		key = strings.ToLower(key)
		if _, dup := idx.vendorFold[key]; !dup {
			idx.vendorFold[key] = vendor
		}
	}
	return idx
}

// scraperInfo returns the loaded store with exactly this shorthand, seller
// first, as the scans it replaces did.
func scraperInfo(shorthand string) (mtgban.ScraperInfo, bool) {
	idx := currentStoreIndex()
	if seller, ok := idx.seller[shorthand]; ok {
		return seller.Info(), true
	}
	if vendor, ok := idx.vendor[shorthand]; ok {
		return vendor.Info(), true
	}
	return mtgban.ScraperInfo{}, false
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

// currentScraperIndex returns the published snapshot's scraperIndex, empty
// before the first listing. Never nil.
func currentScraperIndex() *scraperIndex {
	return &currentPrices().scrapers
}

// publishScrapers publishes the snapshot with scrapers in place of the
// listing it holds. Only loadScrapersNG (full replace) and
// updateScraperIndexStore (single-store replace) call it, holding
// scrapersWriteMu.
func publishScrapers(scrapers scraperIndex) {
	next := *currentPrices()
	next.scrapers = scrapers
	pricesPtr.Store(&next)
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
	publishScrapers(*next)
}

// parseDumpKey parses a bucket key of the form
// "<game>/<store>/<kind>/<shorthand>.json.xz", or reports ok=false for a
// stray object, a wrong kind, or the wrong extension.
func parseDumpKey(key string, game matcher.Game) (store, kind, shorthand string, ok bool) {
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
func listDumps(ctx context.Context, bucket simplecloud.Reader, game matcher.Game, prefix string) (*scraperIndex, error) {
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
func listDumpsWithRetry(bucket simplecloud.Reader, game matcher.Game, prefix string) (*scraperIndex, error) {
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

// startScraperLoad opens the dumps, in dumpsDir or else the mtgban-dumps
// bucket, and loads the stores' prices from them in the background; the jobs
// that also need the datastore wait for datastoreLoaded. Failing to open or
// to load ends the process.
func (s *site) startScraperLoad(dumpsDir string, stores []string, datastoreLoaded <-chan struct{}) {
	// Opened before the loader and the server start, so a request that
	// reloads a store finds DataBucket already set.
	var bucket simplecloud.Reader
	if dumpsDir != "" {
		// A missing directory would list nothing and load nothing.
		_, err := os.Stat(dumpsDir)
		if err != nil {
			log.Fatalln("error opening the dumps directory:", err)
		}
		bucket = &simplecloud.FileBucket{Root: dumpsDir}
	} else {
		b2, err := openDumpsBucket(context.Background())
		if err != nil {
			log.Fatalln("error opening the dumps bucket:", err)
		}
		bucket = b2
	}
	DataBucket = bucket
	go func() {
		log.Println("Loading scrapers")
		err := loadScrapersNG(bucket, stores)
		if err != nil {
			log.Fatalln("error loading scrapers:", err)
		}
		// Card Kingdom's stock history and buylist signals (ckbuylist.go),
		// where the prices just loaded include CK's buylist.
		if ckAvailable() {
			go tracked(jobCKSignals, s.refreshCKSignals)()
		}

		// Update set values after loading prices. The analysis reads the
		// backend it starts with, so it waits for the datastore: read
		// from a bucket, it can arrive after the prices.
		<-datastoreLoaded
		// Alerts wait for both the datastore and the prices.
		s.pricesLoaded.Store(true)
		s.alerts.RequestEvaluate(alerts.SideRetail, alerts.SideBuylist)
		finish := backgroundJobs.Start(jobSetAnalysis)
		s.runSealedAnalysis()
		finish(nil)
		// runSealedAnalysis loads the catalog, which is what names this
		// site's own TCGplayer category, so the variant scope is only
		// complete now.
		warmVariantCacheIfEnabled()
		s.offline.RefreshManifest()
	}()
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
	publishScrapers(*idx)
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

	// A dump already past DropAfter is not served even for the hour until
	// the staleness job would drop it.
	dropStaleStores(time.Now())

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

func loadScraperWithRetry(bucket simplecloud.Reader, game matcher.Game, name, kind, shorthand string) error {
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

func loadScraper(bucket simplecloud.Reader, game matcher.Game, name, kind, shorthand string) error {
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

// errDroppedDump is updateSellers' and updateVendors' answer for a dropped
// store's dump that droppedDump keeps out: not a failure, nothing installed.
var errDroppedDump = errors.New("dump is undated, past DropAfter or no newer than when the store was dropped")

// updateSellers installs the seller over its registered slot, answering with
// the refusal where buildNextSellers turns the swap down. It posts nothing:
// the caller reports the answer, once, to whoever asked for the load.
func updateSellers(scraper mtgban.Scraper) error {
	seller := applyInventoryOverrides(scraper.(mtgban.Seller))

	scrapersWriteMu.Lock()
	defer scrapersWriteMu.Unlock()

	p := currentPrices()
	current := p.sellers

	sellerIndex := -1
	for i, s := range current {
		if s.Info().Shorthand == seller.Info().Shorthand {
			sellerIndex = i
			break
		}
	}

	// Any reload lists a dropped store again; its old dump stays out quietly
	if sellerIndex < 0 && droppedDump(sessionstore.Retail, seller.Info().Shorthand, seller.Info().InventoryTimestamp, time.Now()) {
		log.Printf("%s inventory left out: %s", seller.Info().Shorthand, errDroppedDump)
		return errDroppedDump
	}

	next, err := buildNextSellers(current, seller, sellerIndex)
	if err != nil {
		return err
	}
	pricesPtr.Store(newPrices(next, p.vendors, p.scrapers))

	log.Printf("%s inventory updated at position %d", scraper.Info().Shorthand, sellerIndex)
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
	// The age checks below, the staleness alarm and every stash read it
	if seller.Info().InventoryTimestamp == nil {
		return nil, errors.New("new inventory names no time")
	}

	if i < 0 {
		// A store back from a drop is held to the size it had then
		dropped := droppedEntries(sessionstore.Retail, seller.Info().Shorthand)
		if len(inv) < dropped/2 && dropped > 100 {
			return nil, errors.New("new inventory is missing too many entries")
		}

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

	p := currentPrices()
	current := p.vendors

	vendorIndex := -1
	for i, v := range current {
		if v.Info().Shorthand == vendor.Info().Shorthand {
			vendorIndex = i
			break
		}
	}

	if vendorIndex < 0 && droppedDump(sessionstore.Buylist, vendor.Info().Shorthand, vendor.Info().BuylistTimestamp, time.Now()) {
		log.Printf("%s buylist left out: %s", vendor.Info().Shorthand, errDroppedDump)
		return errDroppedDump
	}

	next, err := buildNextVendors(current, vendor, vendorIndex)
	if err != nil {
		return err
	}
	pricesPtr.Store(newPrices(p.sellers, next, p.scrapers))

	log.Printf("%s buylist updated at position %d", scraper.Info().Shorthand, vendorIndex)
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
	if vendor.Info().BuylistTimestamp == nil {
		return nil, errors.New("new buylist names no time")
	}

	if i < 0 {
		// A store back from a drop is held to the size it had then
		dropped := droppedEntries(sessionstore.Buylist, vendor.Info().Shorthand)
		if len(bl) < dropped/2 && dropped > 100 {
			return nil, errors.New("new buylist is missing too many entries")
		}

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
