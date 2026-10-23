package main

import (
	"slices"

	"github.com/mtgban/go-mtgban/mtgban"
	"github.com/mtgban/go-mtgban/mtgmatcher"

	"github.com/mtgban/mtgban-website/internal/alerts"
)

// alertPickedOnlyStores are watched only by an alert that names them.
// TCGDirectNet is what a card nets sold through TCGplayer Direct, not an
// offer to buy it, so an alert on every buylist leaves it out.
var alertPickedOnlyStores = []string{"TCGDirectNet"}

// alertStorePrices lists every non-index store of the card's kind (sealed
// or singles) outside the blocklist, so an alert can watch a store not
// offering the card yet; those carry no prices. Quantity is not asked:
// SCG and CSI publish none on their buylists.
func alertStorePrices(cardID string, sealed bool, side alerts.Side, blocklist []string) []alerts.StorePrice {
	var out []alerts.StorePrice
	add := func(info mtgban.ScraperInfo, entries []mtgban.GenericEntry) {
		if info.MetadataOnly || info.SealedMode != sealed || slices.Contains(blocklist, info.Shorthand) {
			return
		}
		prices := map[string]float64{}
		for _, e := range entries {
			if e.Pricing() > 0 {
				_, seen := prices[string(e.Condition())]
				if !seen {
					prices[string(e.Condition())] = e.Pricing()
				}
			}
		}
		out = append(out, alerts.StorePrice{
			Shorthand: info.Shorthand, Name: scraperName(info.Shorthand), Prices: prices,
			PickedOnly: slices.Contains(alertPickedOnlyStores, info.Shorthand),
		})
	}
	if side == alerts.SideRetail {
		for _, seller := range GetSellers() {
			entries := seller.Inventory()[cardID]
			generic := make([]mtgban.GenericEntry, len(entries))
			for i := range entries {
				generic[i] = entries[i]
			}
			add(seller.Info(), generic)
		}
		return out
	}
	for _, vendor := range GetVendors() {
		entries := vendor.Buylist()[cardID]
		generic := make([]mtgban.GenericEntry, len(entries))
		for i := range entries {
			generic[i] = entries[i]
		}
		add(vendor.Info(), generic)
	}
	return out
}

// alertCardSnapshot is the display snapshot kept on the alert row.
func alertCardSnapshot(b *mtgmatcher.Backend, cardID string) (alerts.Card, bool, bool) {
	co, err := b.GetUUID(cardID)
	if err != nil {
		return alerts.Card{}, false, false
	}
	finish := co.Finish
	if finish == "" {
		finish = "nonfoil"
	}
	return alerts.Card{Name: co.Name, Set: co.SetCode, Number: co.Number, Finish: finish}, co.Sealed, true
}
