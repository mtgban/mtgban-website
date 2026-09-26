package main

import (
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"

	"github.com/mtgban/mtgban-website/internal/sessionstore"
	"github.com/mtgban/mtgban-website/timeseries"
)

// walkSnapshotPrices is the half of a snapshot both games share: which scrapers
// count, how a condition scales a price, which date a scrape lands on. It reads
// the served snapshots and the session registry, so every test here starts from
// keepScrapers, which empties both and puts them back afterwards.

// snapshotVisit is one call walkSnapshotPrices made, flattened for comparison.
type snapshotVisit struct {
	CardID   string
	Dataset  string
	Provider int16
	Date     string
	Price    float64
}

// collectSnapshotVisits runs the walk over the served snapshots and returns
// what it visited, keyed for assertions rather than in visit order.
func collectSnapshotVisits(start time.Time) map[string]snapshotVisit {
	got := map[string]snapshotVisit{}
	walkSnapshotPrices(start, func(card *mtgmatcher.CardObject, config DatasetConfig, date string, price float64) {
		got[config.PublicName] = snapshotVisit{
			CardID: card.UUID, Dataset: config.PublicName,
			Provider: config.Provider, Date: date, Price: price,
		}
	})
	return got
}

// serveSeller publishes one seller holding a single card at one price.
func serveSeller(shorthand, cardID string, entry mtgban.InventoryEntry, ts time.Time) mtgban.Seller {
	inv := mtgban.InventoryRecord{cardID: []mtgban.InventoryEntry{entry}}
	return mtgban.NewSellerFromInventory(inv, mtgban.ScraperInfo{
		Name: shorthand, Shorthand: shorthand, InventoryTimestamp: &ts,
	})
}

// serveVendor is serveSeller for the buylist side.
func serveVendor(shorthand, cardID string, entry mtgban.BuylistEntry, ts time.Time) mtgban.Vendor {
	bl := mtgban.BuylistRecord{cardID: []mtgban.BuylistEntry{entry}}
	return mtgban.NewVendorFromBuylist(bl, mtgban.ScraperInfo{
		Name: shorthand, Shorthand: shorthand, BuylistTimestamp: &ts,
	})
}

// serve publishes the given scrapers as the site's current snapshots.
func serve(sellers []mtgban.Seller, vendors []mtgban.Vendor) {
	sellersPtr.Store(&sellers)
	vendorsPtr.Store(&vendors)
}

// A dataset claims a scraper by shorthand, on whichever side it named it. The
// same shorthand can be a seller and a vendor at once (CSI and SCG are both),
// and the retail and buylist lists decide which price each dataset gets.
func TestWalkSnapshotPricesMatchesEachSideByShorthand(t *testing.T) {
	ids := nRealUUIDs(t, 1)
	keepScrapers(t)
	withDatasets(t, []DatasetConfig{
		{Retail: []string{"ZZCSI"}, PublicName: "Retail side", Provider: timeseries.ProviderTCGLow},
		{Buylist: []string{"ZZCSI"}, PublicName: "Buylist side", Provider: timeseries.ProviderCSIBuylist},
	})

	now := time.Now()
	serve(
		[]mtgban.Seller{serveSeller("ZZCSI", ids[0], mtgban.InventoryEntry{Price: 10, Conditions: "NM"}, now)},
		[]mtgban.Vendor{serveVendor("ZZCSI", ids[0], mtgban.BuylistEntry{BuyPrice: 4, Conditions: "NM"}, now)},
	)

	got := collectSnapshotVisits(now)
	if len(got) != 2 {
		t.Fatalf("expected both sides visited, got %+v", got)
	}
	if v := got["Retail side"]; v.Price != 10 || v.Provider != timeseries.ProviderTCGLow {
		t.Errorf("retail visit = %+v, want price 10 on the TCG Low provider", v)
	}
	if v := got["Buylist side"]; v.Price != 4 || v.Provider != timeseries.ProviderCSIBuylist {
		t.Errorf("buylist visit = %+v, want price 4 on the CSI provider", v)
	}
}

// A scraper no dataset names contributes nothing, which is what keeps an
// unconfigured store out of the archive.
func TestWalkSnapshotPricesIgnoresUnclaimedScrapers(t *testing.T) {
	ids := nRealUUIDs(t, 1)
	keepScrapers(t)
	withDatasets(t, []DatasetConfig{
		{Retail: []string{"ZZWANTED"}, PublicName: "Wanted", Provider: timeseries.ProviderTCGLow},
	})

	now := time.Now()
	serve([]mtgban.Seller{
		serveSeller("ZZWANTED", ids[0], mtgban.InventoryEntry{Price: 3, Conditions: "NM"}, now),
		serveSeller("ZZOTHER", ids[0], mtgban.InventoryEntry{Price: 99, Conditions: "NM"}, now),
	}, nil)

	got := collectSnapshotVisits(now)
	if len(got) != 1 {
		t.Fatalf("only the claimed scraper should be visited, got %+v", got)
	}
	if got["Wanted"].Price != 3 {
		t.Errorf("visited price = %v, want 3 from ZZWANTED", got["Wanted"].Price)
	}
}

// A non-NM price is scaled to its NM equivalent by defaultGradeMap, so a
// played copy doesn't record the card as cheaper than it is.
func TestWalkSnapshotPricesScalesByCondition(t *testing.T) {
	ids := nRealUUIDs(t, 1)
	for _, tc := range []struct {
		conditions string
		price      float64
		want       float64
	}{
		{"NM", 10, 10},
		{"SP", 10, 12.5},
		{"MP", 10, 16.7},
		{"HP", 10, 25},
		{"PO", 10, 40},
	} {
		t.Run(tc.conditions, func(t *testing.T) {
			keepScrapers(t)
			withDatasets(t, []DatasetConfig{
				{Retail: []string{"ZZG"}, PublicName: "Graded", Provider: timeseries.ProviderTCGLow},
			})
			now := time.Now()
			serve([]mtgban.Seller{serveSeller("ZZG", ids[0],
				mtgban.InventoryEntry{Price: tc.price, Conditions: tc.conditions}, now)}, nil)

			got := collectSnapshotVisits(now)["Graded"]
			// The map's factors are exact decimals but the product is binary
			// floating point, so compare with a tolerance rather than ==.
			if diff := got.Price - tc.want; diff > 0.0001 || diff < -0.0001 {
				t.Errorf("%s price = %v, want %v", tc.conditions, got.Price, tc.want)
			}
		})
	}
}

// A scraper that knows the real NM price of a played copy puts it in
// CustomFields, and that wins over scaling the played price up by a guess.
func TestWalkSnapshotPricesPrefersTheScrapersOwnRetailPrice(t *testing.T) {
	ids := nRealUUIDs(t, 1)
	keepScrapers(t)
	withDatasets(t, []DatasetConfig{
		{Retail: []string{"ZZR"}, PublicName: "Retail", Provider: timeseries.ProviderTCGLow},
	})

	now := time.Now()
	serve([]mtgban.Seller{serveSeller("ZZR", ids[0], mtgban.InventoryEntry{
		Price:        10, // would scale to 12.50 as SP
		Conditions:   "SP",
		CustomFields: map[string]string{"RetailPrice": "11.25"},
	}, now)}, nil)

	if got := collectSnapshotVisits(now)["Retail"].Price; got != 11.25 {
		t.Errorf("price = %v, want the scraper's own 11.25 rather than the scaled 12.50", got)
	}
}

// The override is for a played copy. An NM entry is already the NM price, so
// the field is ignored rather than allowed to contradict it.
func TestWalkSnapshotPricesKeepsAnNMPriceOverTheOverride(t *testing.T) {
	ids := nRealUUIDs(t, 1)
	keepScrapers(t)
	withDatasets(t, []DatasetConfig{
		{Retail: []string{"ZZR"}, PublicName: "Retail", Provider: timeseries.ProviderTCGLow},
	})

	now := time.Now()
	serve([]mtgban.Seller{serveSeller("ZZR", ids[0], mtgban.InventoryEntry{
		Price:        10,
		Conditions:   "NM",
		CustomFields: map[string]string{"RetailPrice": "99"},
	}, now)}, nil)

	if got := collectSnapshotVisits(now)["Retail"].Price; got != 10 {
		t.Errorf("price = %v, want 10: the override is for played copies", got)
	}
}

// A zero price is absence, not a free card, so it never reaches the archive.
func TestWalkSnapshotPricesSkipsZeroPrices(t *testing.T) {
	ids := nRealUUIDs(t, 1)
	keepScrapers(t)
	withDatasets(t, []DatasetConfig{
		{Retail: []string{"ZZS"}, PublicName: "Seller", Provider: timeseries.ProviderTCGLow},
		{Buylist: []string{"ZZV"}, PublicName: "Vendor", Provider: timeseries.ProviderCSIBuylist},
	})

	now := time.Now()
	serve(
		[]mtgban.Seller{serveSeller("ZZS", ids[0], mtgban.InventoryEntry{Price: 0, Conditions: "NM"}, now)},
		[]mtgban.Vendor{serveVendor("ZZV", ids[0], mtgban.BuylistEntry{BuyPrice: 0, Conditions: "NM"}, now)},
	)

	if got := collectSnapshotVisits(now); len(got) != 0 {
		t.Errorf("a zero price should not be visited, got %+v", got)
	}
}

// A store an admin published from an upload lives in memory only. It can carry
// the shorthand of a dataset's real scraper, so the snapshot has to skip it or
// one upload would be written to the archive as that store's price history.
func TestWalkSnapshotPricesSkipsSessionStores(t *testing.T) {
	ids := nRealUUIDs(t, 1)
	keepScrapers(t)
	withDatasets(t, []DatasetConfig{
		{Retail: []string{"ZZSESS"}, PublicName: "Session", Provider: timeseries.ProviderTCGLow},
		{Retail: []string{"ZZREAL"}, PublicName: "Control", Provider: timeseries.ProviderTCGMarket},
	})

	now := time.Now()
	// A normally-served seller on a second dataset is the control: it proves
	// the walk ran and found what it should, so an empty session result is the
	// skip working rather than the setup failing.
	serve([]mtgban.Seller{serveSeller("ZZREAL", ids[0],
		mtgban.InventoryEntry{Price: 7, Conditions: "NM"}, now)}, nil)

	// Publishing goes through the real hooks, so the session store joins the
	// served sellers exactly as an admin's upload would.
	if _, err := Sessions.Publish(sessionstore.Retail, sessionInfo("ZZSESS"),
		[]UploadEntry{{CardID: ids[0], OriginalPrice: 99}}); err != nil {
		t.Fatalf("publishing the session store: %s", err)
	}

	got := collectSnapshotVisits(now)
	if _, stashed := got["Session"]; stashed {
		t.Errorf("a session store was stashed: %+v", got["Session"])
	}
	if got["Control"].Price != 7 {
		t.Errorf("control = %+v, want the served seller's 7: the walk has to have run", got["Control"])
	}
}

// The date is the scrape's, not the run's: a dump that predates today keeps its
// own observation date instead of being recorded as today's price.
func TestWalkSnapshotPricesTakesTheDateFromTheScrape(t *testing.T) {
	ids := nRealUUIDs(t, 1)
	keepScrapers(t)
	withDatasets(t, []DatasetConfig{
		{Retail: []string{"ZZOLD"}, PublicName: "Stale", Provider: timeseries.ProviderTCGLow},
	})

	now := time.Now()
	stale := now.AddDate(0, 0, -3)
	serve([]mtgban.Seller{serveSeller("ZZOLD", ids[0],
		mtgban.InventoryEntry{Price: 5, Conditions: "NM"}, stale)}, nil)

	want := stale.Format("2006-01-02")
	if got := collectSnapshotVisits(now)["Stale"].Date; got != want {
		t.Errorf("date = %q, want the scrape's own %q", got, want)
	}
}
