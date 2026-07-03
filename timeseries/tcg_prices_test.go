package timeseries

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestBuildTCGUpsertQuery(t *testing.T) {
	price := 1.23
	rows := make([]TCGPriceRow, 3)
	for i := range rows {
		rows[i] = TCGPriceRow{
			Date:        "2024-02-08",
			CategoryID:  71,
			ProductID:   100 + i,
			SubTypeName: "Normal",
			MarketPrice: &price,
		}
	}

	q, args := buildTCGUpsertQuery(rows)

	if len(args) != len(rows)*tcgColsPerRow {
		t.Errorf("got %d args, want %d", len(args), len(rows)*tcgColsPerRow)
	}
	if !strings.Contains(q, "ON CONFLICT (date, category_id, product_id, sub_type_name)") {
		t.Errorf("query missing conflict target:\n%s", q)
	}
	if !strings.Contains(q, "low_price        = EXCLUDED.low_price") {
		t.Errorf("query should overwrite (not COALESCE) price columns:\n%s", q)
	}
	// Highest placeholder equals the arg count, and never crosses the cap.
	last := fmt.Sprintf("$%d", len(rows)*tcgColsPerRow)
	if !strings.Contains(q, last) {
		t.Errorf("query missing final placeholder %s:\n%s", last, q)
	}
	if strings.Contains(q, fmt.Sprintf("$%d", len(rows)*tcgColsPerRow+1)) {
		t.Errorf("query has more placeholders than args:\n%s", q)
	}
}

func TestDedupeTCGPriceRows(t *testing.T) {
	first, last := 1.00, 2.00
	other := 3.00
	rows := []TCGPriceRow{
		{Date: "2024-02-08", CategoryID: 71, ProductID: 100, SubTypeName: "Normal", MarketPrice: &first},
		{Date: "2024-02-08", CategoryID: 71, ProductID: 200, SubTypeName: "Normal", MarketPrice: &other},
		// Same key as the first row (e.g. a product listed under two groups): last wins.
		{Date: "2024-02-08", CategoryID: 71, ProductID: 100, SubTypeName: "Normal", MarketPrice: &last},
		// Same product/date but a different sub-type is a distinct key, kept.
		{Date: "2024-02-08", CategoryID: 71, ProductID: 100, SubTypeName: "Foil", MarketPrice: &other},
	}

	got := dedupeTCGPriceRows(rows)
	if len(got) != 3 {
		t.Fatalf("got %d rows, want 3: %+v", len(got), got)
	}
	// First-seen order preserved: (100,Normal), (200,Normal), (100,Foil).
	if got[0].ProductID != 100 || got[0].SubTypeName != "Normal" {
		t.Errorf("row 0 = %+v, want product 100 Normal", got[0])
	}
	if got[0].MarketPrice == nil || *got[0].MarketPrice != last {
		t.Errorf("dedup kept first, not last: market = %v, want %v", got[0].MarketPrice, last)
	}
	if got[1].ProductID != 200 || got[2].SubTypeName != "Foil" {
		t.Errorf("unexpected order/keys: %+v", got)
	}
}

// A read-only client must never touch the database: these calls short-circuit
// before dereferencing the (nil) connection.
func TestTCGWritesReadOnly(t *testing.T) {
	c := &Client{readOnly: true}
	ctx := context.Background()

	n, err := c.UpsertTCGPrices(ctx, []TCGPriceRow{{Date: "2024-02-08"}}, 0)
	if err != nil || n != 0 {
		t.Errorf("read-only UpsertTCGPrices = (%d, %v), want (0, nil)", n, err)
	}
	if err := c.UpsertTCGPrice(ctx, TCGPriceRow{Date: "2024-02-08"}); err != nil {
		t.Errorf("read-only UpsertTCGPrice err = %v, want nil", err)
	}
	if err := c.EnsureTCGSchema(ctx); err != nil {
		t.Errorf("read-only EnsureTCGSchema err = %v, want nil", err)
	}
}
