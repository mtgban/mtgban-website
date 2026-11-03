package main

import (
	"io"
	"log"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/mtgban/go-mtgban/mtgban"
)

func TestSleepersLayoutSkipsPlaytest(t *testing.T) {
	skipWithoutDatastore(t)
	playtest := backend().GetUUIDsInSet("CMB1")[0]
	plain := somePlainCardUUIDs(t, 2)
	registerTestSeller(t, testSite, "TCGLow", append(plain, playtest))

	sleepers, err := sleepersLayout(backend(), currentPrices(), map[string]int{playtest: 100, plain[0]: 50, plain[1]: 2})
	if err != nil {
		t.Fatal(err)
	}
	for _, cardIDs := range sleepers {
		if slices.Contains(cardIDs, playtest) {
			t.Errorf("playtest card %s listed among the sleepers", playtest)
		}
	}
}

// TestSleeperTiersFollowPublishes counts a vendor buying above a seller's
// price, then publishes around it: a pair whose stores stay published keeps
// its hits, one whose vendor is replaced is gone from the new snapshot and
// counted again from the new value, and a new backend starts over.
func TestSleeperTiersFollowPublishes(t *testing.T) {
	b := fixtureBackend("FIXS", "Fixture Sleepers", "2024-01-01", [][2]string{
		{"Fixture Sleeper", "1"},
		{"Fixture Sleeper Two", "2"},
	})
	for _, co := range b.UUIDs {
		co.Language = "English"
	}
	seller := mtgban.NewSellerFromInventory(mtgban.InventoryRecord{
		"FIXS-1": {{Conditions: "NM", Price: 5, Quantity: 1}},
		"FIXS-2": {{Conditions: "NM", Price: 5, Quantity: 1}},
	}, mtgban.ScraperInfo{Shorthand: "SEL"})
	buys := func(shorthand string, prices map[string]float64) mtgban.Vendor {
		buylist := mtgban.BuylistRecord{}
		for cardID, price := range prices {
			buylist[cardID] = []mtgban.BuylistEntry{{Conditions: "NM", BuyPrice: price}}
		}
		return mtgban.NewVendorFromBuylist(buylist, mtgban.ScraperInfo{Shorthand: shorthand})
	}
	vendor := buys("VEN", map[string]float64{"FIXS-1": 8})

	withPrices(t, []mtgban.Seller{seller}, []mtgban.Vendor{vendor})
	tiers := getTiers(b, currentPrices(), nil, nil, nil)
	if !maps.Equal(tiers, map[string]int{"FIXS-1": 1}) {
		t.Fatalf("tiers = %v, want FIXS-1 counted once", tiers)
	}
	held := currentPrices().sleepers.pairs[sleeperPair{seller: seller, vendor: vendor}]

	// The reader's filters pick from the same hits.
	if tiers := getTiers(b, currentPrices(), nil, []string{"VEN"}, nil); len(tiers) != 0 {
		t.Errorf("VEN blocked, yet tiers = %v", tiers)
	}
	if tiers := getTiers(b, currentPrices(), nil, nil, []string{"FIXS"}); len(tiers) != 0 {
		t.Errorf("FIXS skipped, yet tiers = %v", tiers)
	}

	other := buys("OTH", map[string]float64{"FIXS-2": 9})
	withPrices(t, []mtgban.Seller{seller}, []mtgban.Vendor{vendor, other})
	tiers = getTiers(b, currentPrices(), nil, nil, nil)
	if !maps.Equal(tiers, map[string]int{"FIXS-1": 1, "FIXS-2": 1}) {
		t.Errorf("after OTH joined, tiers = %v", tiers)
	}
	if currentPrices().sleepers.pairs[sleeperPair{seller: seller, vendor: vendor}] != held {
		t.Error("SEL/VEN was computed again though neither store changed")
	}

	cheaper := buys("VEN", map[string]float64{"FIXS-1": 4})
	withPrices(t, []mtgban.Seller{seller}, []mtgban.Vendor{cheaper, other})
	tiers = getTiers(b, currentPrices(), nil, nil, nil)
	if !maps.Equal(tiers, map[string]int{"FIXS-2": 1}) {
		t.Errorf("after VEN dropped its price, tiers = %v", tiers)
	}
	_, found := currentPrices().sleepers.pairs[sleeperPair{seller: seller, vendor: vendor}]
	if found {
		t.Error("the replaced VEN's pair is still held")
	}

	held = currentPrices().sleepers.pairs[sleeperPair{seller: seller, vendor: other}]
	reloaded := fixtureBackend("FIXS", "Fixture Sleepers", "2024-01-01", [][2]string{
		{"Fixture Sleeper", "1"},
		{"Fixture Sleeper Two", "2"},
	})
	for _, co := range reloaded.UUIDs {
		co.Language = "English"
	}
	getTiers(reloaded, currentPrices(), nil, nil, nil)
	if currentPrices().sleepers.pairs[sleeperPair{seller: seller, vendor: other}] == held {
		t.Error("SEL/OTH kept across a new backend")
	}
}

// BenchmarkSleepersMismatch is the mismatch page end to end, after one view
// has filled whatever it keeps. It needs stores loaded, which TestMain does
// from a B2 key pair in the environment.
func BenchmarkSleepersMismatch(b *testing.B) {
	if len(currentPrices().sellers) == 0 {
		b.Skip("no stores loaded; B2_KEY_ID and B2_APP_KEY load them")
	}
	readyToRender(b)
	saved := LogPages["Sleepers"]
	b.Cleanup(func() { LogPages["Sleepers"] = saved })
	LogPages["Sleepers"] = log.New(io.Discard, "", 0)

	req := httptest.NewRequest(http.MethodGet, "/sleepers?page=mismatch", nil)
	testSite.Sleepers(httptest.NewRecorder(), req)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		rec := httptest.NewRecorder()
		testSite.Sleepers(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("answered %d", rec.Code)
		}
	}
}
