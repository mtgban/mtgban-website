package timeseries

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
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
	// tcgByProduct maps a TCGplayer product id to its canonical ban_id (the
	// "Normal" sub-type, else the smallest ban_id), so a rendered non-Magic card
	// resolves its ban_id from memory by product id alone — the read-path analogue
	// of magic's uuid-keyed lookup, with no per-card DB round-trip. Mirrors
	// LookupTCGBanID's precedence.
	tcgByProduct sync.Map // int (product id) -> int64
	// tcgSubTypesByProduct maps a TCGplayer product id to every sub-type it is
	// priced under and that sub-type's ban_id. One product covers all of a card's
	// finishes (Lorcana's "Normal" / "Cold Foil" / "Holofoil", Riftbound's
	// "Normal" / "Foil"), so a caller that knows which finish it is rendering
	// needs the whole set to pick its own row instead of the canonical one.
	// Warm-time only, like tcgByProduct: the maps are built once and never
	// mutated, so readers can use them without copying.
	tcgSubTypesByProduct sync.Map // int (product id) -> map[string]int64
}

// VariantScope names the slice of the variants table a process actually uses.
// Every deployment shares one table, so warming it whole is not the harmless
// default it looks like: it hands a Lorcana site Magic's uuids and nine other
// games' products, ~120MB of maps it can only miss on. The zero value does load
// everything, for a caller that cannot name its game.
type VariantScope struct {
	// Magic includes every mtgjson-keyed variant.
	Magic bool
	// TCGCategoryIDs includes the non-Magic variants filed under those
	// TCGplayer categories: the site's own game, plus every category the
	// process ingests (an ingest resolves a ban_id per price row, and a row
	// outside the cache costs a round-trip).
	TCGCategoryIDs []int
}

// VariantCounts reports what a warm loaded, per identity kind. The package does
// no logging of its own, so this is how a caller sees whether its scope
// resolved to the rows it expected — a category id that matches nothing loads
// zero and degrades to a per-card round-trip rather than failing.
type VariantCounts struct {
	Magic int
	TCG   int
}

const warmVariantSelect = `SELECT ban_id, mtgjson_uuid, is_foil, is_etched, is_alt, language,
		       tcgp_category_id, tcgp_product_id, tcgp_sub_type
		FROM variants`

// buildWarmVariantQuery renders the scope as a WHERE clause. Both predicates
// match a partial unique index (variants_mtg_uk on mtgjson_uuid IS NOT NULL,
// variants_tcg_uk leading with tcgp_category_id), so a single-game scope reads
// its own rows rather than the table.
func buildWarmVariantQuery(scope VariantScope) (string, []any) {
	var conds []string
	var args []any
	if scope.Magic {
		conds = append(conds, "mtgjson_uuid IS NOT NULL")
	}
	if len(scope.TCGCategoryIDs) > 0 {
		placeholders := make([]string, len(scope.TCGCategoryIDs))
		for i, id := range scope.TCGCategoryIDs {
			placeholders[i] = fmt.Sprintf("$%d", i+1)
			args = append(args, id)
		}
		conds = append(conds, "tcgp_category_id IN ("+strings.Join(placeholders, ",")+")")
	}
	if len(conds) == 0 {
		return warmVariantSelect, nil
	}
	return warmVariantSelect + "\n\t\t WHERE " + strings.Join(conds, " OR "), args
}

// WarmVariantCache bulk-loads the scoped variants into the in-memory cache in
// one query, so a stash of ~150k printings resolves without ~150k round-trips.
// Only genuinely new printings then miss and mint. Safe to call repeatedly.
func (c *Client) WarmVariantCache(ctx context.Context, scope VariantScope) (VariantCounts, error) {
	query, args := buildWarmVariantQuery(scope)
	rows, err := c.db.QueryContext(ctx, query, args...)
	if err != nil {
		return VariantCounts{}, err
	}
	defer rows.Close()

	// Best canonical ban_id per product id, resolved after the scan since rows
	// arrive unordered: prefer the "Normal" sub-type, else the smallest ban_id
	// (matching LookupTCGBanID's ORDER BY).
	type tcgBest struct {
		banID  int64
		normal bool
	}
	byProduct := map[int]tcgBest{}
	subTypesByProduct := map[int]map[string]int64{}

	var counts VariantCounts
	for rows.Next() {
		var banID int64
		var uuid sql.NullString
		var isFoil, isEtched, isAlt bool
		var language string
		var catID, prodID sql.NullInt64
		var subType sql.NullString
		if err := rows.Scan(&banID, &uuid, &isFoil, &isEtched, &isAlt, &language,
			&catID, &prodID, &subType); err != nil {
			return VariantCounts{}, err
		}
		if uuid.Valid {
			c.variants.magic.Store(MagicVariant{
				MtgjsonUUID: uuid.String, IsFoil: isFoil, IsEtched: isEtched,
				IsAlt: isAlt, Language: language,
			}, banID)
			counts.Magic++
		} else if prodID.Valid {
			c.variants.tcg.Store(TCGVariant{
				CategoryID: int(catID.Int64), ProductID: int(prodID.Int64),
				SubType: subType.String,
			}, banID)
			counts.TCG++

			pid := int(prodID.Int64)
			isNormal := subType.String == "Normal"
			if cur, ok := byProduct[pid]; !ok ||
				(isNormal && !cur.normal) ||
				(isNormal == cur.normal && banID < cur.banID) {
				byProduct[pid] = tcgBest{banID: banID, normal: isNormal}
			}
			if subTypesByProduct[pid] == nil {
				subTypesByProduct[pid] = map[string]int64{}
			}
			// A duplicate sub-type can only come from a second category filing
			// the same product id; keep the smaller ban_id, as above.
			if cur, ok := subTypesByProduct[pid][subType.String]; !ok || banID < cur {
				subTypesByProduct[pid][subType.String] = banID
			}
		}
	}
	if err := rows.Err(); err != nil {
		return VariantCounts{}, err
	}
	for pid, best := range byProduct {
		c.variants.tcgByProduct.Store(pid, best.banID)
	}
	for pid, subTypes := range subTypesByProduct {
		c.variants.tcgSubTypesByProduct.Store(pid, subTypes)
	}
	return counts, nil
}

// CachedTCGBanID returns the canonical ban_id for a non-Magic TCGplayer product
// if it is already in the in-memory cache, without touching the DB. It is the
// non-Magic counterpart of CachedMagicBanID: the read-side lookup that stamps a
// ban_id onto a rendered card by product id alone (no per-card round-trip). A miss
// (new product, or an unwarmed cache) returns ok=false and the caller falls back
// to the game-native id.
func (c *Client) CachedTCGBanID(productID int) (int64, bool) {
	if id, ok := c.variants.tcgByProduct.Load(productID); ok {
		return id.(int64), true
	}
	return 0, false
}

// CachedTCGSubTypeBanIDs returns every sub-type a product is priced under and
// that sub-type's ban_id, from the in-memory cache. A card's finish is not in
// the variants row itself — it is the sub-type — so this is what lets a caller
// chart the foil printing instead of the product's canonical (usually "Normal")
// one. The returned map is shared and must not be modified. A miss (new product,
// unwarmed cache) returns ok=false.
func (c *Client) CachedTCGSubTypeBanIDs(productID int) (map[string]int64, bool) {
	if m, ok := c.variants.tcgSubTypesByProduct.Load(productID); ok {
		return m.(map[string]int64), true
	}
	return nil, false
}

// LookupTCGSubTypeBanIDs is CachedTCGSubTypeBanIDs against the DB, for the
// single-card paths where a round-trip is affordable and a cold cache (or a
// product ingested since warm-up) should still chart the right finish.
func (c *Client) LookupTCGSubTypeBanIDs(ctx context.Context, productID int) (map[string]int64, error) {
	rows, err := c.db.QueryContext(ctx, `
		SELECT ban_id, tcgp_sub_type FROM variants
		 WHERE tcgp_product_id=$1 ORDER BY ban_id ASC`, productID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	subTypes := map[string]int64{}
	for rows.Next() {
		var banID int64
		var subType sql.NullString
		if err := rows.Scan(&banID, &subType); err != nil {
			return nil, err
		}
		// Ascending ban_id, so the first row of a sub-type duplicated across
		// categories wins, matching the warm cache.
		if _, ok := subTypes[subType.String]; !ok {
			subTypes[subType.String] = banID
		}
	}
	return subTypes, rows.Err()
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

// VariantInfo is a variants row resolved by ban_id: either a Magic printing
// (MtgjsonUUID set) or a non-Magic TCGplayer product (TCGProductID set). It is
// the bridge from a ban_id back to a chartable/displayable identity.
type VariantInfo struct {
	BanID         int64
	MtgjsonUUID   string // "" for non-Magic
	IsFoil        bool
	IsEtched      bool
	IsAlt         bool
	Language      string
	TCGCategoryID int    // 0 for Magic
	TCGProductID  int    // 0 for Magic
	TCGSubType    string // "" for Magic
}

// IsMagic reports whether the variant is a Magic printing (has an mtgjson uuid).
func (v VariantInfo) IsMagic() bool { return v.MtgjsonUUID != "" }

// LookupVariant returns the identity for a ban_id, ok=false if no such variant.
// Used to chart/display a ban: id and to route Magic vs non-Magic handling.
func (c *Client) LookupVariant(ctx context.Context, banID int64) (VariantInfo, bool, error) {
	v := VariantInfo{BanID: banID}
	var uuid, subType sql.NullString
	var catID, prodID sql.NullInt64
	err := c.db.QueryRowContext(ctx, `
		SELECT mtgjson_uuid, is_foil, is_etched, is_alt, language,
		       tcgp_category_id, tcgp_product_id, tcgp_sub_type
		FROM variants WHERE ban_id=$1`, banID).Scan(
		&uuid, &v.IsFoil, &v.IsEtched, &v.IsAlt, &v.Language,
		&catID, &prodID, &subType)
	if err == sql.ErrNoRows {
		return VariantInfo{}, false, nil
	}
	if err != nil {
		return VariantInfo{}, false, err
	}
	v.MtgjsonUUID = uuid.String
	v.TCGCategoryID = int(catID.Int64)
	v.TCGProductID = int(prodID.Int64)
	v.TCGSubType = subType.String
	return v, true, nil
}

// LookupMagicBanIDByUUID resolves a bare mtgjson uuid to the canonical Magic
// ban_id (preferring the base printing: language empty, non-foil, non-etched,
// non-alt; else the smallest match). It lets a uuid that is in our price history
// but retired from the current mtgmatcher datastore still chart. ok=false if the
// uuid has no variant.
func (c *Client) LookupMagicBanIDByUUID(ctx context.Context, uuid string) (int64, bool, error) {
	uuid = NormalizeUUID(uuid)
	var banID int64
	err := c.db.QueryRowContext(ctx, `
		SELECT ban_id FROM variants
		 WHERE mtgjson_uuid=$1
		 ORDER BY (language='' AND is_alt=false AND is_foil=false AND is_etched=false) DESC, ban_id ASC
		 LIMIT 1`, uuid).Scan(&banID)
	if err == sql.ErrNoRows {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return banID, true, nil
}

// LookupTCGBanID resolves a bare TCGplayer product id to a canonical non-Magic
// variant, preferring sub-type "Normal" (the base printing) and otherwise the
// smallest ban_id. ok=false when the product has no ingested variant. For a
// precise sub-type, chart the ban: id directly instead.
func (c *Client) LookupTCGBanID(ctx context.Context, productID int) (VariantInfo, bool, error) {
	v := VariantInfo{TCGProductID: productID}
	var catID sql.NullInt64
	var subType sql.NullString
	err := c.db.QueryRowContext(ctx, `
		SELECT ban_id, tcgp_category_id, tcgp_sub_type FROM variants
		 WHERE tcgp_product_id=$1
		 ORDER BY (tcgp_sub_type='Normal') DESC, ban_id ASC LIMIT 1`, productID).Scan(
		&v.BanID, &catID, &subType)
	if err == sql.ErrNoRows {
		return VariantInfo{}, false, nil
	}
	if err != nil {
		return VariantInfo{}, false, err
	}
	v.TCGCategoryID = int(catID.Int64)
	v.TCGSubType = subType.String
	return v, true, nil
}

// CachedMagicBanID returns the ban_id for a Magic variant if it is already in the
// in-memory cache, without touching the DB or minting. It is the read-side lookup
// for stamping a ban_id onto rendered cards (no per-card round-trip); warm the
// cache once with WarmVariantCache. A miss (new printing, or an unwarmed cache)
// returns ok=false and the caller falls back to the uuid path.
func (c *Client) CachedMagicBanID(v MagicVariant) (int64, bool) {
	v = v.normalized()
	if id, ok := c.variants.magic.Load(v); ok {
		return id.(int64), true
	}
	return 0, false
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
