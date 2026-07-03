package timeseries

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

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

func TestDedupeTCGProducts(t *testing.T) {
	products := []TCGProduct{
		{ProductID: 454229, Name: "Cruella De Vil"},
		{ProductID: 454231, Name: "Genie"},
		{ProductID: 454229, Name: "Cruella De Vil (corrected)"}, // dup product_id: last wins
	}
	got := dedupeTCGProducts(products)
	if len(got) != 2 {
		t.Fatalf("got %d products, want 2: %+v", len(got), got)
	}
	if got[0].ProductID != 454229 || got[0].Name != "Cruella De Vil (corrected)" {
		t.Errorf("row 0 = %+v, want product 454229 with the last name", got[0])
	}
	if got[1].ProductID != 454231 {
		t.Errorf("row 1 = %+v, want product 454231", got[1])
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
