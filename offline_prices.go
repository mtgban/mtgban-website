package main

import (
	"compress/gzip"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/mtgban-website/internal/offline"
)

// condMap flattens the closed-vocabulary conditions struct into the payload map.
func condMap(c *BanConditions) map[string]float64 {
	var out map[string]float64
	for _, tag := range conditionTags {
		if v := c.Get(tag); v != 0 {
			if out == nil {
				out = make(map[string]float64)
			}
			out[tag] = v
		}
	}
	return out
}

// qtyMap is the quantity counterpart of condMap.
func qtyMap(q *BanQuantities) map[string]int {
	var out map[string]int
	for _, tag := range conditionTags {
		if v := q.Get(tag); v != 0 {
			if out == nil {
				out = make(map[string]int)
			}
			out[tag] = v
		}
	}
	return out
}

// banprice2offline maps the BanPrice shape 1:1 onto the payload shape.
func banprice2offline(setCode string, snapshot time.Time, retail, buylist map[string]map[string]*BanPrice) *offline.SetPayload {
	conv := func(section map[string]map[string]*BanPrice) map[string]map[string]*offline.PriceEntry {
		out := make(map[string]map[string]*offline.PriceEntry, len(section))
		for uuid, byStore := range section {
			entries := make(map[string]*offline.PriceEntry, len(byStore))
			for store, bp := range byStore {
				entries[store] = &offline.PriceEntry{
					Regular:    bp.Regular,
					Foil:       bp.Foil,
					Etched:     bp.Etched,
					Sealed:     bp.Sealed,
					Cond:       bp.Cond,
					Qty:        bp.Qty,
					QtyFoil:    bp.QtyFoil,
					QtyEtched:  bp.QtyEtched,
					QtySealed:  bp.QtySealed,
					Conditions: condMap(bp.Conditions),
					Quantities: qtyMap(bp.Quantities),
				}
			}
			out[uuid] = entries
		}
		return out
	}
	return &offline.SetPayload{
		SetCode:  setCode,
		Snapshot: snapshot,
		Retail:   conv(retail),
		Buylist:  conv(buylist),
	}
}

// offlineEnabledStores intersects the optional stores param with every
// non-blocklisted scraper, mirroring PriceAPI's ALL_ACCESS branch.
func offlineEnabledStores(r *http.Request) []string {
	var all []string
	for _, seller := range GetSellers() {
		shorthand := seller.Info().Shorthand
		if !slices.Contains(Config.SearchRetailBlockList, shorthand) && !slices.Contains(all, shorthand) {
			all = append(all, shorthand)
		}
	}
	for _, vendor := range GetVendors() {
		shorthand := vendor.Info().Shorthand
		if !slices.Contains(Config.SearchBuylistBlockList, shorthand) && !slices.Contains(all, shorthand) {
			all = append(all, shorthand)
		}
	}

	filter := r.FormValue("stores")
	if filter == "" {
		return all
	}
	var out []string
	for _, shorthand := range strings.Split(filter, ",") {
		if slices.Contains(all, shorthand) {
			out = append(out, shorthand)
		}
	}
	return out
}

// serveOfflinePrices builds, watermarks, and streams one set's payload.
func serveOfflinePrices(w http.ResponseWriter, r *http.Request, email, rest string) {
	setCode := strings.TrimSuffix(rest, ".bin")
	set, err := mtgmatcher.GetSet(setCode)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	stores := offlineEnabledStores(r)

	retail := getSellerPrices("", stores, set.Code, nil, "", true, true, false, "")
	buylist := getVendorPrices("", stores, set.Code, nil, "", true, true, false, "")
	for id, m := range getSellerPrices("", stores, set.Code, nil, "", true, true, true, "") {
		if retail[id] == nil {
			retail[id] = m
			continue
		}
		for store, entry := range m {
			retail[id][store] = entry
		}
	}
	for id, m := range getVendorPrices("", stores, set.Code, nil, "", true, true, true, "") {
		if buylist[id] == nil {
			buylist[id] = m
			continue
		}
		for store, entry := range m {
			buylist[id][store] = entry
		}
	}

	snapshot := time.Now().UTC()
	if sv, found := offlineManifestStore.Get().Sets[set.Code]; found {
		if t, err := time.Parse(time.RFC3339, sv.Version); err == nil {
			snapshot = t
		}
	}

	payload := banprice2offline(set.Code, snapshot, retail, buylist)
	secret := os.Getenv("BAN_SECRET")
	if secret == "" {
		log.Println("offline: BAN_SECRET empty, watermark not attributable")
	}
	offline.Watermark([]byte(secret), email, payload)

	data, err := offline.Encode(payload)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Set("Cache-Control", "private, no-store")
	gz := gzip.NewWriter(w)
	gz.Write(data)
	gz.Close()
}
