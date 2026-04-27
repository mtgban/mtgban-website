package main

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"

	"github.com/mtgban/go-mtgban/mtgmatcher"
)

type PriceResult struct {
	SellPrice  *float64 `json:"sellPrice"`
	SellVendor string   `json:"sellVendor,omitempty"`
	BuyPrice   *float64 `json:"buyPrice"`
	BuyVendor  string   `json:"buyVendor,omitempty"`
	ImageURL   string   `json:"imageURL,omitempty"`
}

func BatchPricesAPI(w http.ResponseWriter, r *http.Request) {
	sig := getSignatureFromCookies(r)
	blocklistRetail, blocklistBuylist := getDefaultBlocklists(sig)

	idsParam := r.FormValue("ids")
	if idsParam == "" {
		http.Error(w, "missing ids parameter", http.StatusBadRequest)
		return
	}

	ids := strings.Split(idsParam, ",")
	if len(ids) > 50 {
		ids = ids[:50]
	}

	results := map[string]PriceResult{}

	for _, cardId := range ids {
		cardId = strings.TrimSpace(cardId)
		if cardId == "" {
			continue
		}

		var result PriceResult

		// Find best NM sell price (lowest)
		var bestSellPrice float64
		var bestSellName string
		for _, seller := range Sellers {
			if slices.Contains(blocklistRetail, seller.Info().Shorthand) {
				continue
			}
			if seller.Info().MetadataOnly {
				continue
			}
			inventory := seller.Inventory()
			entries, found := inventory[cardId]
			if !found {
				continue
			}
			for _, entry := range entries {
				if entry.Conditions != "NM" {
					continue
				}
				if entry.Price > 0 && (bestSellPrice == 0 || entry.Price < bestSellPrice) {
					bestSellPrice = entry.Price
					name := seller.Info().Name
					if override, ok := Config.ScraperConfig.NameOverride[name]; ok {
						name = override
					}
					bestSellName = name
				}
			}
		}
		if bestSellPrice > 0 {
			result.SellPrice = &bestSellPrice
			result.SellVendor = bestSellName
		}

		// Find best NM buy price (highest buylist)
		var bestBuyPrice float64
		var bestBuyName string
		for _, vendor := range Vendors {
			if slices.Contains(blocklistBuylist, vendor.Info().Shorthand) {
				continue
			}
			if vendor.Info().MetadataOnly {
				continue
			}
			buylist := vendor.Buylist()
			entries, found := buylist[cardId]
			if !found {
				continue
			}
			for _, entry := range entries {
				if entry.Conditions != "NM" {
					continue
				}
				if entry.BuyPrice > bestBuyPrice {
					bestBuyPrice = entry.BuyPrice
					name := vendor.Info().Name
					if override, ok := Config.ScraperConfig.NameOverride[name]; ok {
						name = override
					}
					bestBuyName = name
				}
			}
		}
		if bestBuyPrice > 0 {
			result.BuyPrice = &bestBuyPrice
			result.BuyVendor = bestBuyName
		}

		// Prefer thumbnail for inline favorites/recents render; fall back to full.
		if co, err := mtgmatcher.GetUUID(cardId); err == nil {
			if img, ok := co.Images["thumbnail"]; ok && img != "" {
				result.ImageURL = img
			} else if img, ok := co.Images["full"]; ok {
				result.ImageURL = img
			}
		}

		results[cardId] = result
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	json.NewEncoder(w).Encode(results)
}
