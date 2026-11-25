package salesvelocity

import (
	"slices"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
)

// saleOrders is an order a day at each price, newest first.
func saleOrders(now time.Time, cents ...uint32) []Order {
	var orders []Order
	for i, c := range cents {
		orders = append(orders, Order{At: uint32(now.AddDate(0, 0, -i-1).Unix()), Cents: c, Qty: 1})
	}
	return orders
}

// The median sale is the middle of the recent orders' prices, with a minimum
// of orders, none of them old, each counted once.
func TestMedianSale(t *testing.T) {
	now := recentNow
	bulk := saleOrders(now, 1000, 900, 800, 700, 600)
	bulk[0].Qty = 500
	aged := saleOrders(now, 1000, 900, 800, 700, 600)
	aged[4].At = uint32(now.AddDate(0, 0, -90).Unix())
	old := slices.Clone(aged)
	old[4].At--
	twenty := make([]uint32, recentDepth)
	for i := range twenty {
		twenty[i] = uint32(2000 - 100*i)
	}

	tests := []struct {
		name   string
		orders []Order
		want   float64
	}{
		{"none", nil, 0},
		{"too few", saleOrders(now, 1000, 900, 800, 700), 0},
		{"the middle order", saleOrders(now, 800, 600, 1000, 700, 900), 8},
		{"between the middle two", saleOrders(now, 100, 600, 300, 500, 200, 400), 3.50},
		{"all the orders kept", saleOrders(now, twenty...), 10.50},
		{"a stray sale does not move it", saleOrders(now, 90000, 600, 800, 700, 900), 8},
		{"a bulk order counts once", bulk, 8},
		{"rounded to the cent", saleOrders(now, 100, 100, 101, 102, 200, 200), 1.02},
		{"as old as it goes", aged, 8},
		{"too old to count", old, 0},
		{"at no price", saleOrders(now, 0, 0, 0, 0, 0), 0},
	}
	for _, tt := range tests {
		kept := slices.Clone(tt.orders)
		got := medianSale(tt.orders, now)
		if got != tt.want {
			t.Errorf("%s: %v, want %v", tt.name, got, tt.want)
		}
		if !slices.Equal(tt.orders, kept) {
			t.Errorf("%s: the snapshot's orders were changed", tt.name)
		}
	}
}

// MedianSaleVendor prices each of the seller's cards at its median sale per grade,
// NM leading at no price where it has too few orders.
func TestMedianSaleVendor(t *testing.T) {
	now := recentNow
	graded := &Recent{}
	graded.Grades[0] = saleOrders(now, 1250, 1250, 1250, 1250, 1250)
	graded.Grades[1] = saleOrders(now, 9000, 9000)
	graded.Grades[2] = saleOrders(now, 334, 334, 334, 334, 334)
	played := &Recent{}
	played.Grades[1] = saleOrders(now, 500, 500, 500, 500, 500)
	box := &Recent{}
	box.Grades[5] = saleOrders(now, 12000, 12000, 12000, 12000, 12000)
	snap := &RecentSnapshot{Cards: map[string]*Recent{
		"graded": graded, "played": played, "box": box, "unlisted": graded,
	}}

	bl := func(grade mtgban.Condition, price float64) mtgban.BuylistEntry {
		return mtgban.BuylistEntry{Conditions: grade, BuyPrice: price}
	}
	want := map[string][]mtgban.BuylistEntry{
		"graded": {bl("NM", 12.50), bl("MP", 3.34)},
		"played": {bl("NM", 0), bl("SP", 5)},
		"box":    {bl("NM", 120)},
	}

	stock := mtgban.InventoryRecord{}
	for _, id := range []string{"graded", "played", "box", "unsold"} {
		stock[id] = []mtgban.InventoryEntry{{Conditions: "NM", Price: 1}}
	}
	vendor := snap.MedianSaleVendor(mtgban.NewSellerFromInventory(stock, mtgban.ScraperInfo{SealedMode: true}), now)
	if vendor == nil {
		t.Fatal("no vendor")
	}
	if vendor.Info().Shorthand != MedianSaleStore || !vendor.Info().SealedMode {
		t.Errorf("info %+v, want %s trading the seller's side", vendor.Info(), MedianSaleStore)
	}
	got := vendor.Buylist()
	if len(got) != len(want) {
		t.Errorf("%d cards priced, want %d: %v", len(got), len(want), got)
	}
	for id, entries := range want {
		same := slices.EqualFunc(got[id], entries, func(a, b mtgban.BuylistEntry) bool {
			return a.Conditions == b.Conditions && a.BuyPrice == b.BuyPrice
		})
		if !same {
			t.Errorf("%s priced %v, want %v", id, got[id], entries)
		}
	}

	unsold := mtgban.InventoryRecord{"unsold": stock["unsold"]}
	none := snap.MedianSaleVendor(mtgban.NewSellerFromInventory(unsold, mtgban.ScraperInfo{}), now)
	if none != nil {
		t.Errorf("a vendor with nothing sold: %v", none.Buylist())
	}
	var empty *RecentSnapshot
	none = empty.MedianSaleVendor(mtgban.NewSellerFromInventory(stock, mtgban.ScraperInfo{}), now)
	if none != nil {
		t.Errorf("a vendor before the first load: %v", none.Buylist())
	}
}
