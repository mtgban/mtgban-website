package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/hashicorp/go-cleanhttp"

	"github.com/mtgban/go-mtgban/mtgban"
)

const (
	banAPIURL  = "https://%s.mtgban.com/api/mtgban/%s.json?tag=tags&conds=true&qty=true&sig=%s"
	banNameURL = "https://%s.mtgban.com/api/mtgban/stores.json?sig=%s"
)

func loadScrapersAPI(ctx context.Context, apiKey string) error {
	retail := map[string]mtgban.InventoryRecord{}
	buylist := map[string]mtgban.BuylistRecord{}
	var retailMeta, buylistMeta []string
	var timestamp time.Time

	log.Println("Querying names")
	storeNames, err := buildStoreNames(ctx, apiKey)
	if err != nil {
		return err
	}

	for _, mode := range []string{"all", "sealed"} {
		log.Println("Querying prices for", mode)
		resp, err := queryBANapi(ctx, apiKey, mode)
		if err != nil {
			return err
		}
		timestamp = resp.Meta.Date
		log.Println("Retrieved", len(resp.Retail), len(resp.Buylist), "ids with prices")

		for uuid, stores := range resp.Retail {
			for id, result := range stores {
				if retail[id] == nil {
					retail[id] = mtgban.InventoryRecord{}
				}

				if mode == "sealed" {
					retail[id].Add(uuid, &mtgban.InventoryEntry{
						Quantity: result.QtySealed,
						Price:    result.Sealed,
						URL:      resp.Meta.BaseURL + "/go/" + id + "/" + uuid,
					})

					if result.QtySealed == 0 {
						retailMeta = append(retailMeta, id)
					}

					continue
				}

				if result.Cond == "" {
					retailMeta = append(retailMeta, id)
				}

				for cond, price := range result.Conditions {
					if price == 0 {
						continue
					}
					retail[id].Add(uuid, &mtgban.InventoryEntry{
						Conditions: strings.Split(cond, "_")[0],
						Quantity:   result.Quantities[cond],
						Price:      price,
						URL:        resp.Meta.BaseURL + "/go/" + id + "/" + uuid,
					})
				}
			}
		}
		for uuid, stores := range resp.Buylist {
			for id, result := range stores {
				if buylist[id] == nil {
					buylist[id] = mtgban.BuylistRecord{}
				}

				if mode == "sealed" {
					buylist[id].Add(uuid, &mtgban.BuylistEntry{
						Quantity: result.QtySealed,
						BuyPrice: result.Sealed,
						URL:      resp.Meta.BaseURL + "/go/" + id + "/" + uuid,
					})
					continue
				}

				if result.Cond == "" {
					buylistMeta = append(buylistMeta, id)
				}

				for cond, price := range result.Conditions {
					if price == 0 {
						continue
					}
					buylist[id].Add(uuid, &mtgban.BuylistEntry{
						Conditions: strings.Split(cond, "_")[0],
						Quantity:   result.Quantities[cond],
						BuyPrice:   price,
						URL:        resp.Meta.BaseURL + "/go/b/" + id + "/" + uuid,
					})
				}
			}
		}
	}

	log.Println("Building slices in memory")
	for store, inventory := range retail {
		seller := mtgban.NewSellerFromInventory(inventory, mtgban.ScraperInfo{
			Name:               storeNames[store],
			Shorthand:          store,
			InventoryTimestamp: &timestamp,
			MetadataOnly:       slices.Contains(retailMeta, store),
			Game:               Config.Game,
		})

		updateSellers(seller)
	}
	for store, buylist := range buylist {
		vendor := mtgban.NewVendorFromBuylist(buylist, mtgban.ScraperInfo{
			Name:             storeNames[store],
			Shorthand:        store,
			BuylistTimestamp: &timestamp,
			MetadataOnly:     slices.Contains(buylistMeta, store),
			Game:             Config.Game,
		})
		updateVendors(vendor)
	}

	return nil
}

func buildStoreNames(ctx context.Context, apiKey string) (map[string]string, error) {
	storeNames := map[string]string{}

	bases, err := queryNames(ctx, false, apiKey)
	if err != nil {
		return nil, err
	}
	names, err := queryNames(ctx, true, apiKey)
	if err != nil {
		return nil, err
	}
	if len(bases) != len(names) {
		return nil, fmt.Errorf("bases (%d) and names (%d) have different length", len(bases), len(names))
	}

	for i, base := range bases {
		storeNames[base] = names[i]
	}
	return storeNames, nil
}

func queryNames(ctx context.Context, names bool, apiKey string) ([]string, error) {
	link := fmt.Sprintf(banNameURL, Config.Game, apiKey)
	if names {
		link += "&tag=names"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, link, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := cleanhttp.DefaultClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var response []string
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func queryBANapi(ctx context.Context, apiKey, mode string) (*PriceAPIOutput, error) {
	link := fmt.Sprintf(banAPIURL, Config.Game, mode, apiKey)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, link, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := cleanhttp.DefaultClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var response PriceAPIOutput
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}
