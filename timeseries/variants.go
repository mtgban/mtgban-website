package timeseries

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
)

// Provider ids in the providers lookup table (see db_migration/02_seed_providers.sql).
// These are stable and referenced by config.json's per-dataset "provider" field.
const (
	ProviderCKRetail     int16 = 1
	ProviderCKBuylist    int16 = 2
	ProviderTCGLow       int16 = 3
	ProviderTCGMarket    int16 = 4
	ProviderTCGMid       int16 = 5
	ProviderTCGHigh      int16 = 6
	ProviderTCGDirectLow int16 = 7
	ProviderMKMLow       int16 = 8
	ProviderMKMTrend     int16 = 9
	ProviderSCGBuylist   int16 = 10
	ProviderABUBuylist   int16 = 11
	ProviderCSIBuylist   int16 = 12
	ProviderSealedEV     int16 = 13
)

// MagicVariant is the language-aware, condition-agnostic identity of a Magic
// printing in the variants table. NormalizeUUID / NormalizeLanguage must have
// been applied before it is used as a cache key or a lookup, or the live write
// path mints duplicate variants the backfill won't match (plan 17.4).
type MagicVariant struct {
	MtgjsonUUID string
	IsFoil      bool
	IsEtched    bool
	IsAlt       bool
	Language    string
}

func (v MagicVariant) normalized() MagicVariant {
	v.MtgjsonUUID = NormalizeUUID(v.MtgjsonUUID)
	v.Language = *NormalizeLanguage(&v.Language)
	return v
}

// TCGVariant is the identity of a non-Magic (TCGplayer-keyed) product printing.
// SubType is stored as "" (never NULL) so partial-index NULL-distinctness can't
// admit duplicates (plan 17.2).
type TCGVariant struct {
	CategoryID int
	ProductID  int
	SubType    string
}

// variantCache maps a normalized variant identity to its ban_id. It is shared by
// the 12h stash cron (via the admin button too) and the daily tcgcsv ingest,
// which can run at once, so access is concurrency-safe. Misses mint the variant
// with INSERT ... ON CONFLICT DO NOTHING so cross-process races resolve to one row.
type variantCache struct {
	magic sync.Map // MagicVariant -> int64
	tcg   sync.Map // TCGVariant   -> int64
}

// WarmVariantCache bulk-loads every existing variant into the in-memory cache in
// one query, so a stash of ~150k printings resolves without ~150k round-trips.
// Only genuinely new printings then miss and mint. Safe to call repeatedly.
func (c *Client) WarmVariantCache(ctx context.Context) error {
	rows, err := c.db.QueryContext(ctx, `
		SELECT ban_id, mtgjson_uuid, is_foil, is_etched, is_alt, language,
		       tcgp_category_id, tcgp_product_id, tcgp_sub_type
		FROM variants`)
	if err != nil {
		return err
	}
	defer rows.Close()

	var loadedMagic, loadedTCG int
	for rows.Next() {
		var banID int64
		var uuid sql.NullString
		var isFoil, isEtched, isAlt bool
		var language string
		var catID, prodID sql.NullInt64
		var subType sql.NullString
		if err := rows.Scan(&banID, &uuid, &isFoil, &isEtched, &isAlt, &language,
			&catID, &prodID, &subType); err != nil {
			return err
		}
		if uuid.Valid {
			c.variants.magic.Store(MagicVariant{
				MtgjsonUUID: uuid.String, IsFoil: isFoil, IsEtched: isEtched,
				IsAlt: isAlt, Language: language,
			}, banID)
			loadedMagic++
		} else if prodID.Valid {
			c.variants.tcg.Store(TCGVariant{
				CategoryID: int(catID.Int64), ProductID: int(prodID.Int64),
				SubType: subType.String,
			}, banID)
			loadedTCG++
		}
	}
	return rows.Err()
}

// ResolveMagicBanID returns the ban_id for a Magic variant, minting it if new.
// Reads/writes the in-memory cache; a miss upserts (ON CONFLICT DO NOTHING) so
// concurrent callers and other processes converge on one row.
func (c *Client) ResolveMagicBanID(ctx context.Context, v MagicVariant) (int64, error) {
	v = v.normalized()
	if id, ok := c.variants.magic.Load(v); ok {
		return id.(int64), nil
	}
	// Insert-returning on a fresh variant (one round-trip); on conflict it returns
	// no rows and we fetch the existing id in a second, separately-committed
	// statement — which always sees a concurrently-inserted row, unlike a
	// same-snapshot SELECT folded into the INSERT via a CTE.
	var banID int64
	err := c.db.QueryRowContext(ctx, `
		INSERT INTO variants (mtgjson_uuid, is_foil, is_etched, is_alt, language)
		VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (mtgjson_uuid, is_foil, is_etched, is_alt, language)
		    WHERE mtgjson_uuid IS NOT NULL DO NOTHING
		RETURNING ban_id`,
		v.MtgjsonUUID, v.IsFoil, v.IsEtched, v.IsAlt, v.Language,
	).Scan(&banID)
	if err == sql.ErrNoRows {
		err = c.db.QueryRowContext(ctx, `
			SELECT ban_id FROM variants
			 WHERE mtgjson_uuid=$1 AND is_foil=$2 AND is_etched=$3 AND is_alt=$4 AND language=$5`,
			v.MtgjsonUUID, v.IsFoil, v.IsEtched, v.IsAlt, v.Language,
		).Scan(&banID)
	}
	if err != nil {
		return 0, fmt.Errorf("resolve magic ban_id %+v: %w", v, err)
	}
	c.variants.magic.Store(v, banID)
	return banID, nil
}

// ResolveTCGBanID returns the ban_id for a non-Magic variant, minting it if new.
func (c *Client) ResolveTCGBanID(ctx context.Context, v TCGVariant) (int64, error) {
	if id, ok := c.variants.tcg.Load(v); ok {
		return id.(int64), nil
	}
	var banID int64
	err := c.db.QueryRowContext(ctx, `
		INSERT INTO variants (tcgp_category_id, tcgp_product_id, tcgp_sub_type)
		VALUES ($1,$2,$3)
		ON CONFLICT (tcgp_category_id, tcgp_product_id, tcgp_sub_type)
		    WHERE tcgp_product_id IS NOT NULL DO NOTHING
		RETURNING ban_id`,
		v.CategoryID, v.ProductID, v.SubType,
	).Scan(&banID)
	if err == sql.ErrNoRows {
		err = c.db.QueryRowContext(ctx, `
			SELECT ban_id FROM variants
			 WHERE tcgp_category_id=$1 AND tcgp_product_id=$2 AND tcgp_sub_type=$3`,
			v.CategoryID, v.ProductID, v.SubType,
		).Scan(&banID)
	}
	if err != nil {
		return 0, fmt.Errorf("resolve tcg ban_id %+v: %w", v, err)
	}
	c.variants.tcg.Store(v, banID)
	return banID, nil
}
