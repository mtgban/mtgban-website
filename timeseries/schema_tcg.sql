-- tcg_prices holds multi-game price history sourced from TCGCSV (tcgcsv.com),
-- keyed by TCGplayer product id and printing sub-type rather than mtgjson uuid.
-- This is the game-agnostic counterpart to product_prices: one row per
-- (date, category, product, sub-type), where category_id is the TCGplayer
-- category (e.g. 71 = Disney Lorcana, 1 = Magic).
--
-- Applied idempotently at startup by (*Client).EnsureTCGSchema; kept here as the
-- human-readable reference for the table.
create table if not exists public.tcg_prices (
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
);

-- Product/sub-type history and latest-price lookups (WHERE category_id,
-- product_id, sub_type_name ORDER BY date).
create index if not exists idx_tcg_prices_lookup on
    public.tcg_prices using btree (category_id, product_id, sub_type_name, "date");

-- Per-category date cursors for resumable backfill and the daily freshness gate
-- (MIN/MAX(date) WHERE category_id).
create index if not exists idx_tcg_prices_category_date on
    public.tcg_prices using btree (category_id, "date");
