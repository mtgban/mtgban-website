package main

import (
	"context"
	"errors"
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
		ServerNotify("tcgcsv", fmt.Sprintf("product sync error: %s", err))
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

	// Sync each game independently so one game's failure doesn't strand the rest;
	// collect the failures and report them together.
	var total int
	var errs []error
	games := Config.TCGCSVConfig.Games
	for _, g := range games {
		n, err := syncTCGProductsForGame(ctx, client, g.CategoryID)
		if err != nil {
			log.Printf("tcgcsv products: category %d failed: %v", g.CategoryID, err)
			errs = append(errs, fmt.Errorf("category %d: %w", g.CategoryID, err))
			continue
		}
		total += n
	}

	if len(errs) > 0 {
		log.Printf("tcgcsv product sync: %d products, %d of %d game(s) failed",
			total, len(errs), len(games))
		return fmt.Errorf("tcgcsv product sync: %d of %d game(s) failed: %w",
			len(errs), len(games), errors.Join(errs...))
	}
	log.Printf("tcgcsv product sync complete: %d products", total)
	return nil
}

// syncTCGProductsForGame pulls and upserts one game's catalog, returning the
// number of products written (0 when the game reports none).
func syncTCGProductsForGame(ctx context.Context, client *tcgcsv.Client, categoryID int) (int, error) {
	groups, err := client.Groups(ctx, categoryID)
	if err != nil {
		return 0, fmt.Errorf("groups: %w", err)
	}

	var rows []timeseries.TCGProduct
	for _, grp := range groups {
		products, err := client.Products(ctx, categoryID, grp.GroupID)
		if err != nil {
			return 0, fmt.Errorf("products for group %d: %w", grp.GroupID, err)
		}
		for _, p := range products {
			rows = append(rows, productToRow(categoryID, p))
		}
	}
	if len(rows) == 0 {
		return 0, nil
	}

	n, err := PricesArchiveDB.UpsertTCGProducts(ctx, rows, 0)
	if err != nil {
		return 0, fmt.Errorf("upsert: %w", err)
	}
	log.Printf("tcgcsv products: category %d, %d products (%d groups)", categoryID, n, len(groups))
	logTCGProductMatchReport(categoryID, rows)
	return n, nil
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
