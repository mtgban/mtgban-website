-- tcgplayer_nonmagic_product_prices holds multi-game price history sourced from TCGCSV (tcgcsv.com),
-- keyed by TCGplayer product id and printing sub-type rather than mtgjson uuid.
-- This is the game-agnostic counterpart to product_prices: one row per
-- (date, category, product, sub-type), where category_id is the TCGplayer
-- category (e.g. 71 = Disney Lorcana, 1 = Magic).
--
-- The table is LIST-partitioned by category_id. Games never share rows and every
-- query is category-scoped, so each game lives in its own partition: vacuum,
-- analyze, and planner statistics stay per-game, and a whole game can be dropped
-- or backfilled in isolation. The known TCGplayer categories get a dedicated
-- partition below; (*Client).EnsureTCGCategoryPartition creates one on demand for
-- any configured game not listed here, and the default partition catches anything
-- that still has no dedicated partition (e.g. the live test's sentinel).
--
-- Applied idempotently at startup by (*Client).EnsureTCGSchema; kept here as the
-- human-readable reference for the table.
create table if not exists public.tcgplayer_nonmagic_product_prices (
    "date"           date not null,
    category_id      integer not null,
    product_id       integer not null,
    sub_type_name    text not null,
    low_price        numeric(10, 2) null,
    mid_price        numeric(10, 2) null,
    high_price       numeric(10, 2) null,
    market_price     numeric(10, 2) null,
    direct_low_price numeric(10, 2) null,
    primary key ("date", category_id, product_id, sub_type_name)
) partition by list (category_id);

-- Catch-all for categories without a dedicated partition, so an unconfigured
-- category (or the live test's sentinel) still routes instead of erroring.
create table if not exists public.tcgplayer_nonmagic_product_prices_default
    partition of public.tcgplayer_nonmagic_product_prices default;

-- Dedicated partitions for the known TCGplayer categories (the tcgcsv package's
-- Category* constants). Pre-creating them means every game we ingest owns its
-- partition from the first insert, so no rows land in the default partition and
-- later need moving to attach one. Categories 21, 69, 70 are junk per tcgcsv and
-- intentionally omitted. Adding a game is one line here plus a config entry; the
-- names match EnsureTCGCategoryPartition's tcgplayer_nonmagic_product_prices_cat_<id> so it no-ops here.
create table if not exists public.tcgplayer_nonmagic_product_prices_cat_1  partition of public.tcgplayer_nonmagic_product_prices for values in (1);   -- Magic
create table if not exists public.tcgplayer_nonmagic_product_prices_cat_2  partition of public.tcgplayer_nonmagic_product_prices for values in (2);   -- Yu-Gi-Oh!
create table if not exists public.tcgplayer_nonmagic_product_prices_cat_3  partition of public.tcgplayer_nonmagic_product_prices for values in (3);   -- Pokemon
create table if not exists public.tcgplayer_nonmagic_product_prices_cat_16 partition of public.tcgplayer_nonmagic_product_prices for values in (16);  -- Cardfight Vanguard
create table if not exists public.tcgplayer_nonmagic_product_prices_cat_27 partition of public.tcgplayer_nonmagic_product_prices for values in (27);  -- Dragon Ball Super CCG
create table if not exists public.tcgplayer_nonmagic_product_prices_cat_62 partition of public.tcgplayer_nonmagic_product_prices for values in (62);  -- Flesh & Blood
create table if not exists public.tcgplayer_nonmagic_product_prices_cat_63 partition of public.tcgplayer_nonmagic_product_prices for values in (63);  -- Digimon
create table if not exists public.tcgplayer_nonmagic_product_prices_cat_68 partition of public.tcgplayer_nonmagic_product_prices for values in (68);  -- One Piece
create table if not exists public.tcgplayer_nonmagic_product_prices_cat_71 partition of public.tcgplayer_nonmagic_product_prices for values in (71);  -- Disney Lorcana
create table if not exists public.tcgplayer_nonmagic_product_prices_cat_79 partition of public.tcgplayer_nonmagic_product_prices for values in (79);  -- Star Wars Unlimited
create table if not exists public.tcgplayer_nonmagic_product_prices_cat_89 partition of public.tcgplayer_nonmagic_product_prices for values in (89);  -- Riftbound

-- Product/sub-type history and latest-price lookups (WHERE category_id,
-- product_id, sub_type_name ORDER BY date). Declared on the partitioned parent so
-- every partition, existing and future, inherits a matching index.
create index if not exists idx_tcgplayer_nonmagic_product_prices_lookup on
    public.tcgplayer_nonmagic_product_prices using btree (category_id, product_id, sub_type_name, "date");

-- Per-category date cursors for resumable backfill and the daily freshness gate
-- (MIN/MAX(date) WHERE category_id).
create index if not exists idx_tcgplayer_nonmagic_product_prices_category_date on
    public.tcgplayer_nonmagic_product_prices using btree (category_id, "date");
