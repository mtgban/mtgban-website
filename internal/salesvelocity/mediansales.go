package salesvelocity

import (
	"slices"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
)

// MedianSalesStore is the shorthand MedianSalesVendor's prices go by.
const MedianSalesStore = "TCGSales"

// MedianSalesTip says what MedianSalesVendor's prices are.
const MedianSalesTip = "Median of recent TCGplayer sales in the condition\nFrom 5 to 20 orders in the last 90 days\nBefore fees and shipping"

const (
	// The fewest orders a grade is priced from, and how far back they go.
	medianSalesMin  = 5
	medianSalesDays = 90
)

// MedianSalesVendor is the median sale as a store buying the cards seller sells,
// each grade seller lists at its own price, nil when none of them has enough
// orders.
func (s *RecentSnapshot) MedianSalesVendor(seller mtgban.Seller, now time.Time) mtgban.Vendor {
	info := mtgban.ScraperInfo{
		Name:       "TCG Median Sales",
		Shorthand:  MedianSalesStore,
		SealedMode: seller.Info().SealedMode,
	}
	buylist := mtgban.BuylistRecord{}
	for cardID, stock := range seller.Inventory() {
		r, found := s.For(cardID)
		if !found {
			continue
		}
		entries := r.medianSalesEntries(stock, now)
		if len(entries) > 0 {
			buylist[cardID] = entries
		}
	}
	if len(buylist) == 0 {
		return nil
	}
	return mtgban.NewVendorFromBuylist(buylist, info)
}

// medianSalesEntries is r's median sale in each grade stock lists with enough
// orders, a sealed product's Unopened as NM. NM leads, at no price when it is
// not listed or has too few: mtgban.Arbit reads the first entry as NM, drops a
// trade at no price, and prices a copy in its own grade alone.
func (r *Recent) medianSalesEntries(stock []mtgban.InventoryEntry, now time.Time) []mtgban.BuylistEntry {
	entries := []mtgban.BuylistEntry{{Conditions: mtgban.NM}}
	for i, orders := range r.Grades {
		grade := mtgban.Condition(Grades[i])
		if Grades[i] == unopened {
			grade = mtgban.NM
		}
		if len(orders) < medianSalesMin || !listsGrade(stock, grade) {
			continue
		}
		price := medianSales(orders, now)
		if price == 0 {
			continue
		}
		if grade == mtgban.NM {
			entries[0].BuyPrice = price
			continue
		}
		entries = append(entries, mtgban.BuylistEntry{
			Conditions: grade,
			BuyPrice:   price,
		})
	}
	if len(entries) == 1 && entries[0].BuyPrice == 0 {
		return nil
	}
	return entries
}

// listsGrade reports whether stock has a copy in grade.
func listsGrade(stock []mtgban.InventoryEntry, grade mtgban.Condition) bool {
	for i := range stock {
		if stock[i].Conditions == grade {
			return true
		}
	}
	return false
}

// medianSales is the median price of the recent orders, the middle two's
// average for an even number, each order counted once whatever its copies,
// in dollars to the cent, 0 with too few orders.
func medianSales(orders []Order, now time.Time) float64 {
	since := now.AddDate(0, 0, -medianSalesDays).Unix()
	var buf [recentDepth]uint32
	cents := buf[:0]
	for _, o := range orders {
		if int64(o.At) >= since {
			cents = append(cents, o.Cents)
		}
	}
	if len(cents) < medianSalesMin {
		return 0
	}
	slices.Sort(cents)
	low, high := uint64(cents[(len(cents)-1)/2]), uint64(cents[len(cents)/2])
	return float64((low+high+1)/2) / 100
}
