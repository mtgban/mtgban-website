package main

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
)

// fixtureBuys is a vendor named shorthand buying each card at its price.
func fixtureBuys(shorthand string, prices map[string]float64) mtgban.Vendor {
	buylist := mtgban.BuylistRecord{}
	for cardID, price := range prices {
		buylist[cardID] = []mtgban.BuylistEntry{{Conditions: "NM", BuyPrice: price}}
	}
	return mtgban.NewVendorFromBuylist(buylist, mtgban.ScraperInfo{Shorthand: shorthand})
}

// TestArbitCacheFollowsPublishes holds a comparison across publishes that
// keep both its stores, and a view with another store as price source
// while that one stays too, compares again once one is replaced, and drops everything on
// a new backend.
func TestArbitCacheFollowsPublishes(t *testing.T) {
	b := fixtureBackend("FIXA", "Fixture Arbit", "2024-01-01", [][2]string{{"Fixture Arbit", "1"}})
	seller := mtgban.NewSellerFromInventory(mtgban.InventoryRecord{
		"FIXA-1": {{Conditions: "NM", Price: 5, Quantity: 1}},
	}, mtgban.ScraperInfo{Shorthand: "SEL"})
	vendor := fixtureBuys("VEN", map[string]float64{"FIXA-1": 8})
	priced := mtgban.NewSellerFromInventory(nil, mtgban.ScraperInfo{Shorthand: "PRC"})
	opts := &mtgban.ArbitOpts{MinSpread: MinSpread}
	view := arbitView{}
	sourced := arbitView{filters: "sourced", priceSources: "PRC"}

	withPrices(t, []mtgban.Seller{seller, priced}, []mtgban.Vendor{vendor})
	p := currentPrices()
	rows := p.arbitRows(b, view, opts, seller, vendor)
	if len(rows) != 1 || rows[0].CardID != "FIXA-1" {
		t.Fatalf("rows = %v, want FIXA-1 once", rows)
	}
	again := p.arbitRows(b, view, opts, seller, vendor)
	if &again[0] != &rows[0] {
		t.Error("the same comparison was run twice")
	}
	p.arbitRows(b, sourced, opts, seller, vendor)

	// A store the snapshot does not publish is compared, not held.
	custom := fixtureBuys("VEN", map[string]float64{"FIXA-1": 9})
	if rows := p.arbitRows(b, view, opts, seller, custom); len(rows) != 1 || rows[0].BuylistEntry.BuyPrice != 9 {
		t.Errorf("custom rows = %v", rows)
	}
	if len(p.arbit.entries) != 2 {
		t.Errorf("%d comparisons held, want 2", len(p.arbit.entries))
	}

	other := fixtureBuys("OTH", nil)
	withPrices(t, []mtgban.Seller{seller, priced}, []mtgban.Vendor{vendor, other})
	p = currentPrices()
	again = p.arbitRows(b, view, opts, seller, vendor)
	if &again[0] != &rows[0] {
		t.Error("SEL against VEN compared again though neither store changed")
	}
	_, found := p.arbit.entries[arbitKey{view: sourced, source: seller, scraper: vendor}]
	if !found {
		t.Error("a view priced from PRC was dropped though PRC did not change")
	}

	repriced := mtgban.NewSellerFromInventory(nil, mtgban.ScraperInfo{Shorthand: "PRC"})
	withPrices(t, []mtgban.Seller{seller, repriced}, []mtgban.Vendor{vendor, other})
	p = currentPrices()
	_, found = p.arbit.entries[arbitKey{view: sourced, source: seller, scraper: vendor}]
	if found {
		t.Error("a view priced from PRC was carried past PRC's reload")
	}
	_, found = p.arbit.entries[arbitKey{view: view, source: seller, scraper: vendor}]
	if !found {
		t.Error("PRC's reload dropped a view not priced from it")
	}

	cheaper := fixtureBuys("VEN", map[string]float64{"FIXA-1": 4})
	withPrices(t, []mtgban.Seller{seller, repriced}, []mtgban.Vendor{cheaper, other})
	p = currentPrices()
	_, found = p.arbit.entries[arbitKey{view: view, source: seller, scraper: vendor}]
	if found {
		t.Error("the replaced VEN's comparison was carried to the new snapshot")
	}
	if rows := p.arbitRows(b, view, opts, seller, cheaper); len(rows) != 0 {
		t.Errorf("after VEN dropped its price, rows = %v", rows)
	}

	reloaded := fixtureBackend("FIXA", "Fixture Arbit", "2024-01-01", [][2]string{{"Fixture Arbit", "1"}})
	p.arbitRows(reloaded, view, opts, seller, other)
	if len(p.arbit.entries) != 1 {
		t.Errorf("%d comparisons held after a new backend, want only its own", len(p.arbit.entries))
	}
}

// TestArbitCacheKeepsBudget drops the comparison asked for least recently
// once the rows held pass the budget.
func TestArbitCacheKeepsBudget(t *testing.T) {
	b := fixtureBackend("FIXA", "Fixture Arbit", "2024-01-01", [][2]string{{"Fixture Arbit", "1"}})
	seller := mtgban.NewSellerFromInventory(mtgban.InventoryRecord{
		"FIXA-1": {{Conditions: "NM", Price: 5, Quantity: 1}},
	}, mtgban.ScraperInfo{Shorthand: "SEL"})
	first := fixtureBuys("ONE", map[string]float64{"FIXA-1": 8})
	second := fixtureBuys("TWO", map[string]float64{"FIXA-1": 9})
	withPrices(t, []mtgban.Seller{seller}, []mtgban.Vendor{first, second})
	p := currentPrices()
	p.arbit.budget = 1
	opts := &mtgban.ArbitOpts{MinSpread: MinSpread}

	p.arbitRows(b, arbitView{}, opts, seller, first)
	p.arbitRows(b, arbitView{}, opts, seller, second)
	_, found := p.arbit.entries[arbitKey{source: seller, scraper: first}]
	if found || len(p.arbit.entries) != 1 || p.arbit.held != 1 {
		t.Errorf("held %d rows in %d comparisons, ONE still held: %v", p.arbit.held, len(p.arbit.entries), found)
	}
}

// TestArbitCacheCountsEmptyComparisons holds a comparison with no rows
// against the budget too, so views that find nothing do not pile up.
func TestArbitCacheCountsEmptyComparisons(t *testing.T) {
	b := fixtureBackend("FIXA", "Fixture Arbit", "2024-01-01", [][2]string{{"Fixture Arbit", "1"}})
	seller := mtgban.NewSellerFromInventory(nil, mtgban.ScraperInfo{Shorthand: "SEL"})
	vendor := fixtureBuys("VEN", nil)
	withPrices(t, []mtgban.Seller{seller}, []mtgban.Vendor{vendor})
	p := currentPrices()
	p.arbit.budget = 2
	opts := &mtgban.ArbitOpts{MinSpread: MinSpread}

	for _, filters := range []string{"a", "b", "c", "d"} {
		p.arbitRows(b, arbitView{filters: filters}, opts, seller, vendor)
	}
	if len(p.arbit.entries) != 2 || p.arbit.held != 2 {
		t.Errorf("held %d rows in %d empty comparisons, want 2 in 2", p.arbit.held, len(p.arbit.entries))
	}
}

// panickySeller is a seller whose inventory panics while panics is set.
type panickySeller struct {
	mtgban.Seller
	panics bool
}

func (s *panickySeller) Inventory() mtgban.InventoryRecord {
	if s.panics {
		panic("inventory")
	}
	return s.Seller.Inventory()
}

// TestArbitCacheAsksAgainAfterAPanic does not hold a comparison that
// panicked as one with no rows: the next request compares again.
func TestArbitCacheAsksAgainAfterAPanic(t *testing.T) {
	b := fixtureBackend("FIXA", "Fixture Arbit", "2024-01-01", [][2]string{{"Fixture Arbit", "1"}})
	seller := &panickySeller{Seller: mtgban.NewSellerFromInventory(mtgban.InventoryRecord{
		"FIXA-1": {{Conditions: "NM", Price: 5, Quantity: 1}},
	}, mtgban.ScraperInfo{Shorthand: "SEL"}), panics: true}
	vendor := fixtureBuys("VEN", map[string]float64{"FIXA-1": 8})
	withPrices(t, []mtgban.Seller{seller}, []mtgban.Vendor{vendor})
	p := currentPrices()
	opts := &mtgban.ArbitOpts{MinSpread: MinSpread}

	func() {
		defer func() { _ = recover() }()
		p.arbitRows(b, arbitView{}, opts, seller, vendor)
		t.Fatal("the comparison did not panic")
	}()
	seller.panics = false
	if rows := p.arbitRows(b, arbitView{}, opts, seller, vendor); len(rows) != 1 {
		t.Errorf("rows after a panic = %v, want FIXA-1 once", rows)
	}
}

// stallingSeller is a seller whose first inventory read closes entered,
// waits for release to close and panics. Every later read answers.
type stallingSeller struct {
	mtgban.Seller
	entered, release chan struct{}
	reads            atomic.Int32
}

func newStallingSeller(seller mtgban.Seller) *stallingSeller {
	return &stallingSeller{Seller: seller, entered: make(chan struct{}), release: make(chan struct{})}
}

func (s *stallingSeller) Inventory() mtgban.InventoryRecord {
	if s.reads.Add(1) == 1 {
		close(s.entered)
		<-s.release
		panic("inventory")
	}
	return s.Seller.Inventory()
}

// TestArbitCacheWaiterComparesAfterAPanic gives a request that waited on a
// comparison that panicked under another the rows, not none.
func TestArbitCacheWaiterComparesAfterAPanic(t *testing.T) {
	b := fixtureBackend("FIXA", "Fixture Arbit", "2024-01-01", [][2]string{{"Fixture Arbit", "1"}})
	seller := newStallingSeller(mtgban.NewSellerFromInventory(mtgban.InventoryRecord{
		"FIXA-1": {{Conditions: "NM", Price: 5, Quantity: 1}},
	}, mtgban.ScraperInfo{Shorthand: "SEL"}))
	vendor := fixtureBuys("VEN", map[string]float64{"FIXA-1": 8})
	withPrices(t, []mtgban.Seller{seller}, []mtgban.Vendor{vendor})
	p := currentPrices()
	opts := &mtgban.ArbitOpts{MinSpread: MinSpread}

	go func() {
		defer func() { _ = recover() }()
		p.arbitRows(b, arbitView{}, opts, seller, vendor)
	}()
	<-seller.entered
	waiter := make(chan []mtgban.ArbitEntry, 1)
	go func() { waiter <- p.arbitRows(b, arbitView{}, opts, seller, vendor) }()
	waitForStack(t, "arbitRows", "Once).doSlow", "lockSlow")
	close(seller.release)

	select {
	case rows := <-waiter:
		if len(rows) != 1 {
			t.Errorf("the waiter's rows = %v, want FIXA-1 once", rows)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the waiter never answered")
	}
}

// TestArbitEngineKey shares one key between states that differ only in
// limits the row filter applies, and not between states the engine sees
// differently.
func TestArbitEngineKey(t *testing.T) {
	m := arbitMode{}
	base := arbitState{}
	rowOnly := arbitState{MinSell: arbitBound{Set: true, Value: 5}, MaxBuy: arbitBound{Set: true, Value: 50}, Sort: "spread"}
	if base.engineKey(m) != rowOnly.engineKey(m) {
		t.Error("a sell and buy limit changed the engine key")
	}
	for name, st := range map[string]arbitState{
		"spread":    {MinSpread: arbitBound{Set: true, Value: 40}},
		"grades":    {Conditions: arbitPick{Set: true, Values: []string{"NM"}}},
		"toggle on": {Toggles: map[string]bool{"rl": true}},
	} {
		if st.engineKey(m) == base.engineKey(m) {
			t.Errorf("%s left the engine key unchanged", name)
		}
	}
}

// TestArbitCacheKeysDirectStock files a comparison buying Direct's stock
// under the listings that stock was built from.
func TestArbitCacheKeysDirectStock(t *testing.T) {
	b := fixtureBackend("FIXA", "Fixture Arbit", "2024-01-01", [][2]string{{"Fixture Arbit", "1"}})
	direct := mtgban.NewSellerFromInventory(mtgban.InventoryRecord{
		"FIXA-1": {{Conditions: "NM", Price: 5, Quantity: 1}},
	}, mtgban.ScraperInfo{Shorthand: tcgDirectStore})
	vendor := fixtureBuys("VEN", map[string]float64{"FIXA-1": 8})
	withPrices(t, []mtgban.Seller{direct}, []mtgban.Vendor{vendor})
	setTestTCGDirect(t, map[string]*tcgListings{})
	p := currentPrices()
	opts := &mtgban.ArbitOpts{MinSpread: MinSpread}

	stocked := withDirectStock(direct)
	p.arbitRows(b, arbitView{}, opts, stocked, vendor)
	snap := stocked.(*directStockSeller).snap
	if snap == nil {
		t.Fatal("the stock was built from no listings")
	}
	_, found := p.arbit.entries[arbitKey{source: direct, scraper: vendor, direct: snap}]
	if !found {
		t.Error("the comparison is not filed under the listings its stock came from")
	}
}

// TestArbitCacheDropsReplacedListings carries a comparison built from the
// current Direct listings, or none, to the next snapshot, and drops one
// built from listings a reload replaced.
func TestArbitCacheDropsReplacedListings(t *testing.T) {
	b := fixtureBackend("FIXA", "Fixture Arbit", "2024-01-01", [][2]string{{"Fixture Arbit", "1"}})
	direct := mtgban.NewSellerFromInventory(mtgban.InventoryRecord{
		"FIXA-1": {{Conditions: "NM", Price: 5, Quantity: 1}},
	}, mtgban.ScraperInfo{Shorthand: tcgDirectStore})
	seller := mtgban.NewSellerFromInventory(mtgban.InventoryRecord{
		"FIXA-1": {{Conditions: "NM", Price: 5, Quantity: 1}},
	}, mtgban.ScraperInfo{Shorthand: "SEL"})
	vendor := fixtureBuys("VEN", map[string]float64{"FIXA-1": 8})
	opts := &mtgban.ArbitOpts{MinSpread: MinSpread}
	stores := []mtgban.Seller{direct, seller}
	vendors := []mtgban.Vendor{vendor}

	setTestTCGDirect(t, map[string]*tcgListings{})
	withPrices(t, stores, vendors)
	p := currentPrices()
	stocked := withDirectStock(direct)
	p.arbitRows(b, arbitView{}, opts, stocked, vendor)
	p.arbitRows(b, arbitView{}, opts, seller, vendor)
	replaced := stocked.(*directStockSeller).snap
	if replaced == nil {
		t.Fatal("the stock was built from no listings")
	}

	setTestTCGDirect(t, map[string]*tcgListings{})
	withPrices(t, stores, vendors)
	p = currentPrices()
	_, found := p.arbit.entries[arbitKey{source: direct, scraper: vendor, direct: replaced}]
	if found {
		t.Error("a comparison built from replaced listings was carried")
	}
	_, found = p.arbit.entries[arbitKey{source: seller, scraper: vendor}]
	if !found {
		t.Error("a comparison built from no listings was dropped")
	}

	stocked = withDirectStock(direct)
	p.arbitRows(b, arbitView{}, opts, stocked, vendor)
	current := stocked.(*directStockSeller).snap
	if current == replaced {
		t.Fatal("the stock was built from the replaced listings")
	}
	withPrices(t, stores, vendors)
	p = currentPrices()
	_, found = p.arbit.entries[arbitKey{source: direct, scraper: vendor, direct: current}]
	if !found {
		t.Error("a comparison built from the current listings was dropped")
	}
}

// BenchmarkArbitPages is the arbit and reverse pages end to end for CK,
// after one view has filled whatever they keep. It needs stores loaded,
// which TestMain does from a B2 key pair in the environment.
func BenchmarkArbitPages(b *testing.B) {
	if len(currentPrices().sellers) == 0 {
		b.Skip("no stores loaded; B2_KEY_ID and B2_APP_KEY load them")
	}
	readyToRender(b)
	saved := LogPages["Arbitrage"]
	b.Cleanup(func() { LogPages["Arbitrage"] = saved })
	LogPages["Arbitrage"] = log.New(io.Discard, "", 0)
	// Dev mode without signatures opens every source to the request.
	savedDev, savedSig := DevMode, SigCheck
	b.Cleanup(func() { DevMode, SigCheck = savedDev, savedSig })
	DevMode, SigCheck = true, false

	pages := []struct {
		url    string
		handle func(*site, http.ResponseWriter, *http.Request)
	}{
		{"/arbit?source=CK", (*site).Arbit},
		{"/reverse?source=CK", (*site).Reverse},
	}
	for _, page := range pages {
		b.Run(page.url, func(b *testing.B) {
			req := httptest.NewRequest(http.MethodGet, page.url, nil)
			page.handle(testSite, httptest.NewRecorder(), req)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				rec := httptest.NewRecorder()
				page.handle(testSite, rec, req)
				if rec.Code != http.StatusOK {
					b.Fatalf("answered %d", rec.Code)
				}
			}
		})
	}
}

// TestArbitViewPriceSources names the price sources of Global's default
// toggles, in one order however the applied toggles come out.
func TestArbitViewPriceSources(t *testing.T) {
	singles := arbitMode{Global: true}
	priceSources := newArbitView(arbitState{}, singles).priceSources
	if priceSources != "TCGMarket" {
		t.Errorf("Global singles priced from %q, want TCGMarket", priceSources)
	}
	sealed := arbitMode{Global: true, Sealed: true}
	priceSources = newArbitView(arbitState{}, sealed).priceSources
	if priceSources != "TCGLowSim" {
		t.Errorf("Global sealed priced from %q, want TCGLowSim", priceSources)
	}
	all := arbitState{Toggles: map[string]bool{"syp": true, "stocks": true}}
	for range 20 {
		priceSources = newArbitView(all, singles).priceSources
		if priceSources != "STKS,SYP,TCGMarket" {
			t.Fatalf("priced from %q, want STKS,SYP,TCGMarket", priceSources)
		}
	}
}
