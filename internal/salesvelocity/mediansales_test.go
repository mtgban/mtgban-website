package salesvelocity

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/mtgban/go-mtgban/matcher"
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
func TestMedianSales(t *testing.T) {
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
		got := medianSales(tt.orders, now)
		if got != tt.want {
			t.Errorf("%s: %v, want %v", tt.name, got, tt.want)
		}
		if !slices.Equal(tt.orders, kept) {
			t.Errorf("%s: the snapshot's orders were changed", tt.name)
		}
	}
}

// MedianSalesVendor prices each of the seller's cards at its median sale per
// grade the seller lists, NM leading at no price where it lists none or has
// too few orders.
func TestMedianSalesVendor(t *testing.T) {
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
		"graded NM": graded, "graded MP": graded, "played NM": played,
	}}

	bl := func(grade mtgban.Condition, price float64) mtgban.BuylistEntry {
		return mtgban.BuylistEntry{Conditions: grade, BuyPrice: price}
	}
	want := map[string][]mtgban.BuylistEntry{
		"graded":    {bl("NM", 12.50), bl("MP", 3.34)},
		"graded NM": {bl("NM", 12.50)},
		"graded MP": {bl("NM", 0), bl("MP", 3.34)},
		"played":    {bl("NM", 0), bl("SP", 5)},
		"box":       {bl("NM", 120)},
	}

	listed := func(grades ...mtgban.Condition) []mtgban.InventoryEntry {
		var entries []mtgban.InventoryEntry
		for _, grade := range grades {
			entries = append(entries, mtgban.InventoryEntry{Conditions: grade, Price: 1})
		}
		return entries
	}
	stock := mtgban.InventoryRecord{
		"graded":    listed("NM", "SP", "MP", "HP", "PO"),
		"graded NM": listed("NM"),
		"graded MP": listed("MP", "MP"),
		"played":    listed("SP"),
		"played NM": listed("NM"),
		"box":       listed("NM"),
		"unsold":    listed("NM"),
	}
	vendor := snap.MedianSalesVendor(mtgban.NewSellerFromInventory(stock, mtgban.ScraperInfo{SealedMode: true}), now)
	if vendor == nil {
		t.Fatal("no vendor")
	}
	if vendor.Info().Shorthand != MedianSalesStore || !vendor.Info().SealedMode {
		t.Errorf("info %+v, want %s trading the seller's side", vendor.Info(), MedianSalesStore)
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
	none := snap.MedianSalesVendor(mtgban.NewSellerFromInventory(unsold, mtgban.ScraperInfo{}), now)
	if none != nil {
		t.Errorf("a vendor with nothing sold: %v", none.Buylist())
	}
	var empty *RecentSnapshot
	none = empty.MedianSalesVendor(mtgban.NewSellerFromInventory(stock, mtgban.ScraperInfo{}), now)
	if none != nil {
		t.Errorf("a vendor before the first load: %v", none.Buylist())
	}
}

// Arbit reads a vendor's price in the grade of the copy alone, so the prices
// of the listed grades draw every row those of all the grades draw.
func TestMedianSalesArbitRows(t *testing.T) {
	now := recentNow
	b := &matcher.Backend{UUIDs: map[string]*matcher.CardObject{}}
	snap := &RecentSnapshot{Cards: map[string]*Recent{}}
	stock, everyGrade := mtgban.InventoryRecord{}, mtgban.InventoryRecord{}
	// A card for each set of grades sold and each set of grades listed
	for sold := range 32 {
		for listed := range 32 {
			id := fmt.Sprintf("%05b %05b", sold, listed)
			r := &Recent{}
			for i := range 5 {
				entry := mtgban.InventoryEntry{Conditions: mtgban.Condition(Grades[i]), Price: 1, Quantity: 1}
				everyGrade[id] = append(everyGrade[id], entry)
				if listed&(1<<i) != 0 {
					stock[id] = append(stock[id], entry)
				}
				if sold&(1<<i) != 0 {
					cents := uint32(1000 - 100*i)
					r.Grades[i] = saleOrders(now, cents, cents, cents, cents, cents)
				}
			}
			snap.Cards[id] = r
			b.UUIDs[id] = &matcher.CardObject{}
		}
	}

	seller := mtgban.NewSellerFromInventory(stock, mtgban.ScraperInfo{})
	got := medianSalesRows(b, snap.MedianSalesVendor(seller, now), seller)
	want := medianSalesRows(b, snap.MedianSalesVendor(mtgban.NewSellerFromInventory(everyGrade, mtgban.ScraperInfo{}), now), seller)
	// Each of the 5 grades is both sold and listed on a quarter of the cards
	if len(want) != 5*1024/4 {
		t.Fatalf("%d rows, want %d", len(want), 5*1024/4)
	}
	if !slices.Equal(got, want) {
		t.Errorf("%d rows from the listed grades, %d from every grade, or they differ", len(got), len(want))
	}
}

// medianSalesRows are the rows of seller against vendor, one line each.
func medianSalesRows(b *matcher.Backend, vendor mtgban.Vendor, seller mtgban.Seller) []string {
	var rows []string
	for _, row := range mtgban.Arbit(b, &mtgban.ArbitOpts{}, vendor, seller) {
		rows = append(rows, fmt.Sprintf("%+v", row))
	}
	slices.Sort(rows)
	return rows
}
