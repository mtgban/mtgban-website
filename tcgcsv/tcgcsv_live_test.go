package tcgcsv

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestTCGCSVLive hits the real tcgcsv.com service for Lorcana. It is skipped
// unless TCGCSV_LIVE is set, so ordinary `go test` and CI never make network
// calls. Run with:
//
//	TCGCSV_LIVE=1 go test ./tcgcsv/ -run TestTCGCSVLive -v
func TestTCGCSVLive(t *testing.T) {
	if os.Getenv("TCGCSV_LIVE") == "" {
		t.Skip("TCGCSV_LIVE not set; skipping live tcgcsv.com test")
	}
	c := NewClient(Config{UserAgent: "mtgban-website-test/1.0 (+https://mtgban.com)"})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	updated, err := c.LastUpdated(ctx)
	if err != nil {
		t.Fatalf("LastUpdated: %v", err)
	}
	if updated.Before(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("LastUpdated = %v, implausibly old", updated)
	}
	t.Logf("tcgcsv last updated: %s", updated.Format(time.RFC3339))

	groups, err := c.Groups(ctx, CategoryLorcana)
	if err != nil {
		t.Fatalf("Groups(Lorcana): %v", err)
	}
	if len(groups) == 0 {
		t.Fatal("expected at least one Lorcana group")
	}
	t.Logf("Lorcana groups: %d", len(groups))

	// Find a group that actually has prices (skip unreleased sets), then sanity
	// check the products/prices join key.
	var withPrices int
	for _, g := range groups {
		prices, err := c.Prices(ctx, CategoryLorcana, g.GroupID)
		if err != nil {
			t.Fatalf("Prices(%d): %v", g.GroupID, err)
		}
		if len(prices) == 0 {
			continue
		}
		withPrices = g.GroupID
		for _, p := range prices {
			if p.ProductID == 0 || p.SubTypeName == "" {
				t.Errorf("price row missing join key: %+v", p)
			}
		}
		break
	}
	if withPrices == 0 {
		t.Fatal("no Lorcana group returned any prices")
	}

	products, err := c.Products(ctx, CategoryLorcana, withPrices)
	if err != nil {
		t.Fatalf("Products(%d): %v", withPrices, err)
	}
	if len(products) == 0 {
		t.Fatalf("group %d had prices but no products", withPrices)
	}
	t.Logf("group %d: %d products", withPrices, len(products))
}

func TestFetchPriceArchiveLive(t *testing.T) {
	if os.Getenv("TCGCSV_LIVE") == "" {
		t.Skip("TCGCSV_LIVE not set; skipping live tcgcsv.com archive test")
	}
	c := NewClient(Config{UserAgent: "mtgban-website-test/1.0 (+https://mtgban.com)"})
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// The epoch archive exists and contains Lorcana prices; the category filter
	// must exclude every other game's prices.
	byCat, found, err := c.FetchPriceArchive(ctx, ArchiveEpoch, map[int]bool{CategoryLorcana: true})
	if err != nil {
		t.Fatalf("FetchPriceArchive(epoch): %v", err)
	}
	if !found {
		t.Fatal("epoch archive reported not found")
	}
	for cat := range byCat {
		if cat != CategoryLorcana {
			t.Errorf("category filter leaked category %d", cat)
		}
	}
	prices := byCat[CategoryLorcana]
	if len(prices) == 0 {
		t.Fatal("no Lorcana prices in epoch archive")
	}
	for _, p := range prices {
		if p.ProductID == 0 || p.SubTypeName == "" {
			t.Errorf("archive price missing join key: %+v", p)
		}
	}
	t.Logf("epoch Lorcana archive prices: %d", len(prices))

	// A date before the epoch has no archive: found=false, not an error.
	if _, found, err := c.FetchPriceArchive(ctx, ArchiveEpoch.AddDate(0, 0, -1), nil); err != nil {
		t.Fatalf("pre-epoch FetchPriceArchive: %v", err)
	} else if found {
		t.Error("expected no archive before the epoch")
	}
}
