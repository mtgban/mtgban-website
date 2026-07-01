-- tcg_products is the catalog metadata behind tcg_prices: one row per TCGplayer
-- product, carrying the human-facing name/number/rarity and image so a
-- product_id in tcg_prices can be resolved to a real card. Sourced from
-- tcgcsv's live products endpoints (archives carry prices only).
--
-- Applied idempotently at startup by (*Client).EnsureTCGProductsSchema.
create table if not exists public.tcg_products (
    product_id  integer not null,
    category_id integer not null,
    group_id    integer not null,
    name        text not null,
    clean_name  text,
    number      text,
    rarity      text,
    image_url   text,
    url         text,
    modified_on text,
    synced_at   timestamptz not null default now(),
    primary key (product_id)
);

-- Browse/count a game's catalog (WHERE category_id[, group_id]).
create index if not exists idx_tcg_products_category on
    public.tcg_products using btree (category_id, group_id);
