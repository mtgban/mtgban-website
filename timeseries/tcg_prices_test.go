package timeseries

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestClampTCGBatchSize(t *testing.T) {
	cases := []struct{ in, want int }{
		{0, tcgMaxBatch},
		{-5, tcgMaxBatch},
		{500, 500},
		{tcgMaxBatch, tcgMaxBatch},
		{tcgMaxBatch + 1, tcgMaxBatch},
		{1_000_000, tcgMaxBatch},
	}
	for _, tc := range cases {
		if got := clampTCGBatchSize(tc.in); got != tc.want {
			t.Errorf("clampTCGBatchSize(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestTCGBatchBounds(t *testing.T) {
	if b := tcgBatchBounds(0, 0); b != nil {
		t.Errorf("expected nil bounds for 0 rows, got %v", b)
	}

	// Fewer rows than a batch collapse to a single batch.
	if b := tcgBatchBounds(500, 0); len(b) != 1 || b[0] != [2]int{0, 500} {
		t.Errorf("unexpected bounds for 500 rows: %v", b)
	}

	// More than one max batch must split, covering every row exactly once and
	// never exceeding the parameter limit.
	total := tcgMaxBatch*2 + 37
	bounds := tcgBatchBounds(total, 0)
	if len(bounds) != 3 {
		t.Fatalf("expected 3 batches for %d rows, got %d: %v", total, len(bounds), bounds)
	}
	prevEnd := 0
	for i, b := range bounds {
		if b[0] != prevEnd {
			t.Errorf("batch %d starts at %d, expected %d", i, b[0], prevEnd)
		}
		size := b[1] - b[0]
		if size > tcgMaxBatch {
			t.Errorf("batch %d has %d rows, exceeds max %d", i, size, tcgMaxBatch)
		}
		if size*tcgColsPerRow > 65535 {
			t.Errorf("batch %d uses %d params, exceeds 65535", i, size*tcgColsPerRow)
		}
		prevEnd = b[1]
	}
	if prevEnd != total {
		t.Errorf("batches cover %d rows, expected %d", prevEnd, total)
	}

	// An explicit small batch size is honored.
	if b := tcgBatchBounds(10, 4); len(b) != 3 || b[0] != [2]int{0, 4} || b[2] != [2]int{8, 10} {
		t.Errorf("unexpected bounds for batchSize 4 over 10 rows: %v", b)
	}
}

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
