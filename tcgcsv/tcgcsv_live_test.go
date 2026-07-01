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
