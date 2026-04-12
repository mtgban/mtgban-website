CREATE TABLE IF NOT EXISTS product_prices (
    date                                DATE     NOT NULL,
    mtgjson_uuid                        TEXT     NOT NULL,
    is_foil                             BOOLEAN  NOT NULL DEFAULT FALSE,
    language                            TEXT,
    is_alt                              BOOLEAN  NOT NULL DEFAULT FALSE,

    cardkingdom_buylist_price            NUMERIC(10, 2),
    tcgplayer_market_price               NUMERIC(10, 2),
    tcgplayer_low_price                  NUMERIC(10, 2),
    cardkingdom_retail_price             NUMERIC(10, 2),
    cardmarket_low_price                 NUMERIC(10, 2),
    cardmarket_trend_price               NUMERIC(10, 2),
    starcitygames_buylist_price          NUMERIC(10, 2),
    abu_buylist_price                    NUMERIC(10, 2),
    coolstuffinc_buylist_price           NUMERIC(10, 2),
    tcgplayer_low_sealed_expected_value  NUMERIC(10, 2),

    PRIMARY KEY (date, mtgjson_uuid, is_foil, language, is_alt)
);

CREATE INDEX IF NOT EXISTS idx_product_prices_uuid ON product_prices (mtgjson_uuid);
