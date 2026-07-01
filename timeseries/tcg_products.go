package timeseries

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"strings"
)

//go:embed schema_tcg_products.sql
var tcgProductsSchemaSQL string

// TCGProduct is one row of the tcg_products catalog table: the metadata behind
// a TCGplayer product that tcg_prices rows reference by product_id.
type TCGProduct struct {
	ProductID  int    `json:"product_id"`
	CategoryID int    `json:"category_id"`
	GroupID    int    `json:"group_id"`
	Name       string `json:"name"`
	CleanName  string `json:"clean_name"`
	Number     string `json:"number"`
	Rarity     string `json:"rarity"`
	ImageURL   string `json:"image_url"`
	URL        string `json:"url"`
	ModifiedOn string `json:"modified_on"`
}

const (
	tcgProductColsPerRow = 10
	tcgProductMaxBatch   = 65535 / tcgProductColsPerRow // ~6553
)

const tcgProductColumns = `
	product_id, category_id, group_id, name, clean_name,
	number, rarity, image_url, url, modified_on`

// EnsureTCGProductsSchema creates the tcg_products table and its index if
// missing. Idempotent; a no-op on a read-only client.
func (c *Client) EnsureTCGProductsSchema(ctx context.Context) error {
	if c.readOnly {
		return nil
	}
	if _, err := c.db.ExecContext(ctx, tcgProductsSchemaSQL); err != nil {
		return fmt.Errorf("timeseries: ensure tcg_products schema: %w", err)
	}
	return nil
}

// UpsertTCGProducts inserts or overwrites catalog rows in parameter-limited
// batches, refreshing synced_at. No-op on a read-only client.
func (c *Client) UpsertTCGProducts(ctx context.Context, products []TCGProduct, batchSize int) (int, error) {
	if c.readOnly {
		return 0, nil
	}
	if len(products) == 0 {
		return 0, nil
	}

	var total int
	var errs []error
	for _, b := range tcgProductBatchBounds(len(products), batchSize) {
		n, err := c.upsertTCGProductBatch(ctx, products[b[0]:b[1]])
		total += n
		if err != nil {
			errs = append(errs, fmt.Errorf("batch starting at row %d: %w", b[0], err))
		}
	}
	return total, errors.Join(errs...)
}

func (c *Client) upsertTCGProductBatch(ctx context.Context, batch []TCGProduct) (int, error) {
	q, args := buildTCGProductsUpsertQuery(batch)
	res, err := c.db.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// GetTCGProduct returns a single catalog row, or sql.ErrNoRows if absent.
func (c *Client) GetTCGProduct(ctx context.Context, productID int) (TCGProduct, error) {
	q := `SELECT` + tcgProductColumns + ` FROM tcg_products WHERE product_id = $1`
	var p TCGProduct
	err := c.db.QueryRowContext(ctx, q, productID).Scan(
		&p.ProductID, &p.CategoryID, &p.GroupID, &p.Name, &p.CleanName,
		&p.Number, &p.Rarity, &p.ImageURL, &p.URL, &p.ModifiedOn,
	)
	return p, err
}

// CountTCGProducts returns how many catalog rows a category has.
func (c *Client) CountTCGProducts(ctx context.Context, categoryID int) (int, error) {
	var n int
	err := c.db.QueryRowContext(ctx,
		`SELECT count(*) FROM tcg_products WHERE category_id = $1`, categoryID).Scan(&n)
	return n, err
}

func clampTCGProductBatchSize(batchSize int) int {
	if batchSize <= 0 || batchSize > tcgProductMaxBatch {
		return tcgProductMaxBatch
	}
	return batchSize
}

func tcgProductBatchBounds(total, batchSize int) [][2]int {
	if total <= 0 {
		return nil
	}
	batchSize = clampTCGProductBatchSize(batchSize)
	var bounds [][2]int
	for start := 0; start < total; start += batchSize {
		end := start + batchSize
		if end > total {
			end = total
		}
		bounds = append(bounds, [2]int{start, end})
	}
	return bounds
}

// buildTCGProductsUpsertQuery builds a multi-VALUES upsert for one batch, with
// product_id as the conflict target. Every field (including synced_at) is
// overwritten so a re-sync reflects tcgcsv's current catalog.
func buildTCGProductsUpsertQuery(batch []TCGProduct) (string, []any) {
	valueClauses := make([]string, 0, len(batch))
	args := make([]any, 0, len(batch)*tcgProductColsPerRow)

	for i := range batch {
		offset := i * tcgProductColsPerRow
		valueClauses = append(valueClauses, fmt.Sprintf(
			"($%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d)",
			offset+1, offset+2, offset+3, offset+4, offset+5,
			offset+6, offset+7, offset+8, offset+9, offset+10,
		))
		p := batch[i]
		args = append(args,
			p.ProductID, p.CategoryID, p.GroupID, p.Name, p.CleanName,
			p.Number, p.Rarity, p.ImageURL, p.URL, p.ModifiedOn,
		)
	}

	q := `INSERT INTO tcg_products (` + tcgProductColumns + `
		) VALUES ` + strings.Join(valueClauses, ",") + `
		ON CONFLICT (product_id) DO UPDATE SET
			category_id = EXCLUDED.category_id,
			group_id    = EXCLUDED.group_id,
			name        = EXCLUDED.name,
			clean_name  = EXCLUDED.clean_name,
			number      = EXCLUDED.number,
			rarity      = EXCLUDED.rarity,
			image_url   = EXCLUDED.image_url,
			url         = EXCLUDED.url,
			modified_on = EXCLUDED.modified_on,
			synced_at   = now()`
	return q, args
}
