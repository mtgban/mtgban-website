create table public.product_prices (
    "date" date not null,
    mtgjson_uuid uuid not null,
    is_foil bool default false not null,
    is_etched bool default false not null,
    "language" text default ''::text not null,
    is_alt bool default false not null,
    cardkingdom_buylist_price numeric(10, 2) null,
    tcgplayer_market_price numeric(10, 2) null,
    tcgplayer_low_price numeric(10, 2) null,
    cardkingdom_retail_price numeric(10, 2) null,
    cardmarket_low_price numeric(10, 2) null,
    cardmarket_trend_price numeric(10, 2) null,
    starcitygames_buylist_price numeric(10, 2) null,
    abu_buylist_price numeric(10, 2) null,
    coolstuffinc_buylist_price numeric(10, 2) null,
    tcgplayer_low_sealed_expected_value numeric(10, 2) null
);

create unique index idx_unique_price_entry on
    public.product_prices
    using btree (date,
    mtgjson_uuid,
    is_foil,
    is_etched,
    language,
    is_alt);

create index idx_uuid_date on
    public.product_prices
    using btree (mtgjson_uuid,
    date);