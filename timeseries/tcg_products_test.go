package timeseries

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestTCGProductBatchBounds(t *testing.T) {
	if b := tcgProductBatchBounds(0, 0); b != nil {
		t.Errorf("expected nil bounds for 0 rows, got %v", b)
	}
	// Split past one max batch: contiguous, non-overlapping, under the cap.
	total := tcgProductMaxBatch*2 + 11
	bounds := tcgProductBatchBounds(total, 0)
	if len(bounds) != 3 {
		t.Fatalf("expected 3 batches for %d rows, got %d: %v", total, len(bounds), bounds)
	}
	prevEnd := 0
	for i, b := range bounds {
		if b[0] != prevEnd {
			t.Errorf("batch %d starts at %d, expected %d", i, b[0], prevEnd)
		}
		if size := b[1] - b[0]; size*tcgProductColsPerRow > 65535 {
			t.Errorf("batch %d uses %d params, exceeds 65535", i, size*tcgProductColsPerRow)
		}
		prevEnd = b[1]
	}
	if prevEnd != total {
		t.Errorf("batches cover %d rows, expected %d", prevEnd, total)
	}
}

func TestBuildTCGProductsUpsertQuery(t *testing.T) {
	products := []TCGProduct{
		{ProductID: 454229, CategoryID: 71, GroupID: 17690, Name: "Cruella De Vil", Number: "4", Rarity: "Promo"},
		{ProductID: 454231, CategoryID: 71, GroupID: 17690, Name: "Genie"},
	}
	q, args := buildTCGProductsUpsertQuery(products)
	if len(args) != len(products)*tcgProductColsPerRow {
		t.Errorf("got %d args, want %d", len(args), len(products)*tcgProductColsPerRow)
	}
	if !strings.Contains(q, "ON CONFLICT (product_id) DO UPDATE SET") {
		t.Errorf("query missing conflict target:\n%s", q)
	}
	if !strings.Contains(q, "synced_at   = now()") {
		t.Errorf("query should refresh synced_at:\n%s", q)
	}
	last := fmt.Sprintf("$%d", len(products)*tcgProductColsPerRow)
	if !strings.Contains(q, last) {
		t.Errorf("query missing final placeholder %s:\n%s", last, q)
	}
}

func TestTCGProductsReadOnly(t *testing.T) {
	c := &Client{readOnly: true}
	ctx := context.Background()
	if n, err := c.UpsertTCGProducts(ctx, []TCGProduct{{ProductID: 1}}, 0); err != nil || n != 0 {
		t.Errorf("read-only UpsertTCGProducts = (%d, %v), want (0, nil)", n, err)
	}
	if err := c.EnsureTCGProductsSchema(ctx); err != nil {
		t.Errorf("read-only EnsureTCGProductsSchema err = %v, want nil", err)
	}
}
