package main

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"sync/atomic"

	"github.com/mtgban/go-mtgban/mtgmatcher"
	"github.com/mtgban/mtgban-website/tcgcsv"
	"github.com/mtgban/mtgban-website/timeseries"
)

// productToRow maps a tcgcsv product into a tcg_products catalog row, pulling
// the collector number and rarity out of the game-specific extendedData.
func productToRow(categoryID int, p tcgcsv.Product) timeseries.TCGProduct {
	return timeseries.TCGProduct{
		ProductID:  p.ProductID,
		CategoryID: categoryID,
		GroupID:    p.GroupID,
		Name:       p.Name,
		CleanName:  p.CleanName,
		Number:     p.Extended("Number"),
		Rarity:     p.Extended("Rarity"),
		ImageURL:   p.ImageURL,
		URL:        p.URL,
		ModifiedOn: p.ModifiedOn,
	}
}

// tcgcsvProductsStashing gates concurrent product syncs (cron + CLI).
var tcgcsvProductsStashing atomic.Bool

// stashTCGCSVProducts runs syncTCGProducts under a single-flight guard.
func stashTCGCSVProducts() {
	if !tcgcsvProductsStashing.CompareAndSwap(false, true) {
		log.Println("stashTCGCSVProducts: another product sync is already running, skipping")
		return
	}
	defer tcgcsvProductsStashing.Store(false)

	if err := syncTCGProducts(context.Background()); err != nil {
		log.Println("tcgcsv product sync:", err)
	}
}

// syncTCGProducts refreshes the tcg_products catalog for every configured game
// from tcgcsv's live products endpoints. Product metadata (names, numbers,
// rarities) is largely stable, so this runs on a slower cadence than prices.
func syncTCGProducts(ctx context.Context) error {
	client, err := tcgcsvClient()
	if err != nil {
		return err
	}
	if err := PricesArchiveDB.EnsureTCGProductsSchema(ctx); err != nil {
		return err
	}

	var total int
	for _, g := range Config.TCGCSVConfig.Games {
		groups, err := client.Groups(ctx, g.CategoryID)
		if err != nil {
			return fmt.Errorf("tcgcsv: groups for category %d: %w", g.CategoryID, err)
		}

		var rows []timeseries.TCGProduct
		for _, grp := range groups {
			products, err := client.Products(ctx, g.CategoryID, grp.GroupID)
			if err != nil {
				return fmt.Errorf("tcgcsv: products for %d/%d: %w", g.CategoryID, grp.GroupID, err)
			}
			for _, p := range products {
				rows = append(rows, productToRow(g.CategoryID, p))
			}
		}
		if len(rows) == 0 {
			continue
		}

		n, err := PricesArchiveDB.UpsertTCGProducts(ctx, rows, 0)
		if err != nil {
			return fmt.Errorf("tcgcsv: upsert products for category %d: %w", g.CategoryID, err)
		}
		total += n
		log.Printf("tcgcsv products: category %d, %d products (%d groups)", g.CategoryID, n, len(groups))
		logTCGProductMatchReport(g.CategoryID, rows)
	}

	log.Printf("tcgcsv product sync complete: %d products", total)
	return nil
}

// logTCGProductMatchReport reports how many synced products resolve to a loaded
// card identity via mtgmatcher's external-id map. It is meaningful only on a
// deployment whose datastore is the matching game (e.g. a Lorcana datastore for
// category 71); elsewhere it will resolve few or none, which is expected until
// the display work runs a per-game backend.
func logTCGProductMatchReport(categoryID int, products []timeseries.TCGProduct) {
	var matched int
	var sampleUnmatched []string
	for _, p := range products {
		if mtgmatcher.ExternalUUID(strconv.Itoa(p.ProductID)) != "" {
			matched++
		} else if len(sampleUnmatched) < 3 {
			sampleUnmatched = append(sampleUnmatched, fmt.Sprintf("%d %q", p.ProductID, p.Name))
		}
	}
	log.Printf("tcgcsv products: category %d, %d/%d resolve to a loaded card identity (unmatched sample: %v)",
		categoryID, matched, len(products), sampleUnmatched)
}
