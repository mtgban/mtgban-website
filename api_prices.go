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
	// During warmup every answer would be empty; a 503 makes clients retry
	// later instead of caching blank prices and images for their tiles
	if !dataReady() {
		w.Header().Set("Cache-Control", "no-store")
		errorResponse(w, http.StatusServiceUnavailable, "not ready")
		return
	}

	sig := getSignatureFromCookies(r)
	blocklistRetail, blocklistBuylist := getDefaultBlocklists(sig)

	idsParam := r.FormValue("ids")
	if idsParam == "" {
		errorResponse(w, http.StatusBadRequest, "missing ids parameter")
		return
	}

	ids := strings.Split(idsParam, ",")
	if len(ids) > 50 {
		ids = ids[:50]
	}

	results := map[string]PriceResult{}

	// Clean the ids once up front
	cardIDs := make([]string, 0, len(ids))
	for _, cardID := range ids {
		cardID = strings.TrimSpace(cardID)
		if cardID == "" {
			continue
		}
		cardIDs = append(cardIDs, cardID)
	}

	// Walk each store once for all ids, rather than every store per id:
	// the Info() copies and blocklist checks are per store, and each
	// store's record map is probed once per id.
	bestSell := map[string]PriceResult{}
	for _, seller := range GetSellers() {
		info := seller.Info()
		if info.MetadataOnly || slices.Contains(blocklistRetail, info.Shorthand) {
			continue
		}
		name := info.Name
		if override, ok := Config.ScraperConfig.NameOverride[name]; ok {
			name = override
		}
		inventory := seller.Inventory()
		for _, cardID := range cardIDs {
			entries, found := inventory[cardID]
			if !found {
				continue
			}
			for _, entry := range entries {
				if entry.Conditions != "NM" {
					continue
				}
				best := bestSell[cardID]
				// Lowest NM sell price wins
				if entry.Price > 0 && (best.SellPrice == nil || entry.Price < *best.SellPrice) {
					price := entry.Price
					best.SellPrice = &price
					best.SellVendor = name
					bestSell[cardID] = best
				}
			}
		}
	}

	bestBuy := map[string]PriceResult{}
	for _, vendor := range GetVendors() {
		info := vendor.Info()
		if info.MetadataOnly || slices.Contains(blocklistBuylist, info.Shorthand) {
			continue
		}
		name := info.Name
		if override, ok := Config.ScraperConfig.NameOverride[name]; ok {
			name = override
		}
		buylist := vendor.Buylist()
		for _, cardID := range cardIDs {
			entries, found := buylist[cardID]
			if !found {
				continue
			}
			for _, entry := range entries {
				if entry.Conditions != "NM" {
					continue
				}
				best := bestBuy[cardID]
				// Highest NM buy price wins
				if entry.BuyPrice > 0 && (best.BuyPrice == nil || entry.BuyPrice > *best.BuyPrice) {
					price := entry.BuyPrice
					best.BuyPrice = &price
					best.BuyVendor = name
					bestBuy[cardID] = best
				}
			}
		}
	}

	for _, cardID := range cardIDs {
		result := PriceResult{
			SellPrice:  bestSell[cardID].SellPrice,
			SellVendor: bestSell[cardID].SellVendor,
			BuyPrice:   bestBuy[cardID].BuyPrice,
			BuyVendor:  bestBuy[cardID].BuyVendor,
		}

		// Prefer thumbnail for inline favorites/recents render; fall back to full.
		if co, err := mtgmatcher.GetUUID(cardID); err == nil {
			if img, ok := co.Images["thumbnail"]; ok && img != "" {
				result.ImageURL = img
			} else if img, ok := co.Images["full"]; ok {
				result.ImageURL = img
			}
		}

		results[cardID] = result
	}

	// A response carrying no data at all (every id unknown or priceless)
	// is not worth poisoning caches with - serve it uncached
	hasData := false
	for _, result := range results {
		if result.SellPrice != nil || result.BuyPrice != nil || result.ImageURL != "" {
			hasData = true
			break
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if hasData {
		w.Header().Set("Cache-Control", "public, max-age=300")
	} else {
		w.Header().Set("Cache-Control", "no-store")
	}
	json.NewEncoder(w).Encode(results)
}
