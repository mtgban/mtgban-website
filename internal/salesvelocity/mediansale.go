package salesvelocity

import (
	"slices"
	"time"

	"github.com/mtgban/go-mtgban/mtgban"
)

// MedianSaleStore is the shorthand MedianSaleVendor's prices go by.
const MedianSaleStore = "TCGSales"

// MedianSaleTip says what MedianSaleVendor's prices are.
const MedianSaleTip = "Median of recent TCGplayer sales in the condition\nFrom 5 to 20 orders in the last 90 days\nBefore fees and shipping"

const (
	// The fewest orders a grade is priced from, and how far back they go.
	medianSaleMin  = 5
	medianSaleDays = 90
)

// MedianSaleVendor is the median sale as a store buying the cards seller sells,
// each grade at its own price, nil when none of them has enough orders.
func (s *RecentSnapshot) MedianSaleVendor(seller mtgban.Seller, now time.Time) mtgban.Vendor {
	info := mtgban.ScraperInfo{
		Name:       "TCG Median Sale",
		Shorthand:  MedianSaleStore,
		SealedMode: seller.Info().SealedMode,
	}
	buylist := mtgban.BuylistRecord{}
	for cardID := range seller.Inventory() {
		r, found := s.For(cardID)
		if !found {
			continue
		}
		entries := r.medianSaleEntries(now)
		if len(entries) > 0 {
			buylist[cardID] = entries
		}
	}
	if len(buylist) == 0 {
		return nil
	}
	return mtgban.NewVendorFromBuylist(buylist, info)
}

// medianSaleEntries is r's median sale in each grade with enough orders, a sealed
// product's Unopened as NM. NM leads, at no price when it has too few:
// mtgban.Arbit reads the first entry as NM and drops a trade at no price.
func (r *Recent) medianSaleEntries(now time.Time) []mtgban.BuylistEntry {
	entries := []mtgban.BuylistEntry{{Conditions: mtgban.NM}}
	for i, orders := range r.Grades {
		price := medianSale(orders, now)
		if price == 0 {
			continue
		}
		if i == 0 || Grades[i] == unopened {
			entries[0].BuyPrice = price
			continue
		}
		entries = append(entries, mtgban.BuylistEntry{
			Conditions: mtgban.Condition(Grades[i]),
			BuyPrice:   price,
		})
	}
	if len(entries) == 1 && entries[0].BuyPrice == 0 {
		return nil
	}
	return entries
}

// medianSale is the median price of the recent orders, the middle two's
// average for an even number, each order counted once whatever its copies,
// in dollars to the cent, 0 with too few orders.
func medianSale(orders []Order, now time.Time) float64 {
	since := now.AddDate(0, 0, -medianSaleDays).Unix()
	var buf [recentDepth]uint32
	cents := buf[:0]
	for _, o := range orders {
		if int64(o.At) >= since {
			cents = append(cents, o.Cents)
		}
	}
	if len(cents) < medianSaleMin {
		return 0
	}
	slices.Sort(cents)
	low, high := uint64(cents[(len(cents)-1)/2]), uint64(cents[len(cents)/2])
	return float64((low+high+1)/2) / 100
}
