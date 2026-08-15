package tcgcsvd

import (
	"context"
	"errors"
	"fmt"
	"log"

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

// IsStashingProducts reports whether a product sync is currently running in
// this process.
func (s *Service) IsStashingProducts() bool { return s.productsStashing.Load() }

// StashProducts runs SyncProducts under the single-flight guard and the shared
// crawl lock. It is the cron/CLI entry point.
func (s *Service) StashProducts() {
	if !s.productsStashing.CompareAndSwap(false, true) {
		log.Println("tcgcsv StashProducts: another product sync is already running, skipping")
		return
	}
	defer s.productsStashing.Store(false)

	err := s.WithCrawlLock("tcgcsv StashProducts", func() error {
		return s.SyncProducts(context.Background())
	})
	if err != nil {
		log.Println("tcgcsv product sync:", err)
		s.notifyf("product sync error: %s", err)
	}
}

// SyncProducts refreshes the tcg_products catalog for every configured game
// from tcgcsv's live products endpoints. Product metadata (names, numbers,
// rarities) is largely stable, so this runs on a slower cadence than prices.
func (s *Service) SyncProducts(ctx context.Context) error {
	// Fail loudly rather than report success while writing nothing: the upsert is
	// a silent no-op on a read-only client, so a product sync against a read-only
	// replica would otherwise exit 0 having synced nothing. Mirrors the guard in
	// IngestLatest and backfill.
	if s.store.ReadOnly() {
		return errors.New("tcgcsv: price database is read-only; nothing would be written")
	}
	if err := s.store.EnsureTCGProductsSchema(ctx); err != nil {
		return err
	}

	// Sync each game independently so one game's failure doesn't strand the rest;
	// collect the failures and report them together.
	var total int
	var errs []error
	for _, g := range s.games {
		n, err := s.syncProductsForGame(ctx, g.CategoryID)
		if err != nil {
			log.Printf("tcgcsv products: category %d failed: %v", g.CategoryID, err)
			errs = append(errs, fmt.Errorf("category %d: %w", g.CategoryID, err))
			continue
		}
		total += n
	}

	if len(errs) > 0 {
		log.Printf("tcgcsv product sync: %d products, %d of %d game(s) failed",
			total, len(errs), len(s.games))
		return fmt.Errorf("tcgcsv product sync: %d of %d game(s) failed: %w",
			len(errs), len(s.games), errors.Join(errs...))
	}
	log.Printf("tcgcsv product sync complete: %d products", total)
	return nil
}

// syncProductsForGame pulls and upserts one game's catalog, returning the
// number of products written (0 when the game reports none).
func (s *Service) syncProductsForGame(ctx context.Context, categoryID int) (int, error) {
	groups, err := s.client.Groups(ctx, categoryID)
	if err != nil {
		return 0, fmt.Errorf("groups: %w", err)
	}

	var rows []timeseries.TCGProduct
	for _, grp := range groups {
		products, err := s.client.Products(ctx, categoryID, grp.GroupID)
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

	n, err := s.store.UpsertTCGProducts(ctx, rows, 0)
	if err != nil {
		return 0, fmt.Errorf("upsert: %w", err)
	}
	log.Printf("tcgcsv products: category %d, %d products (%d groups)", categoryID, n, len(groups))
	if s.report != nil {
		s.report(categoryID, rows)
	}
	return n, nil
}
