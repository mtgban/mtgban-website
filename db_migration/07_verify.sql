-- Backfill parity verification (plan 7.5 / 17.10). Heavy: full scans of both
-- source tables + one scan of prices. Run after the backfill completes.
-- Providers 3/4 are shared, so the new-side counts are scoped to Magic vs
-- non-Magic via the variants join (mtgjson_uuid IS NOT NULL / tcgp_product_id IS NOT NULL).
\timing on

\echo === MAGIC parity: source non-null,>0 cells per provider vs prices rows ===
WITH magic_src AS (
    SELECT unnest(ARRAY[1,2,3,4,8,9,10,11,12,13]) AS provider,
           unnest(ARRAY[
               count(*) FILTER (WHERE cardkingdom_retail_price > 0),
               count(*) FILTER (WHERE cardkingdom_buylist_price > 0),
               count(*) FILTER (WHERE tcgplayer_low_price > 0),
               count(*) FILTER (WHERE tcgplayer_market_price > 0),
               count(*) FILTER (WHERE cardmarket_low_price > 0),
               count(*) FILTER (WHERE cardmarket_trend_price > 0),
               count(*) FILTER (WHERE starcitygames_buylist_price > 0),
               count(*) FILTER (WHERE abu_buylist_price > 0),
               count(*) FILTER (WHERE coolstuffinc_buylist_price > 0),
               count(*) FILTER (WHERE tcgplayer_low_sealed_expected_value > 0)
           ]) AS src_count
    FROM public.product_prices
),
magic_new AS (
    SELECT p.provider, count(*) AS new_count
    FROM public.prices p
    JOIN public.variants v ON v.ban_id = p.ban_id
    WHERE v.mtgjson_uuid IS NOT NULL
    GROUP BY p.provider
)
SELECT s.provider, pr.shorthand, s.src_count, coalesce(n.new_count,0) AS new_count,
       coalesce(n.new_count,0) - s.src_count AS diff
FROM magic_src s
LEFT JOIN magic_new n USING (provider)
JOIN public.providers pr ON pr.id = s.provider
ORDER BY s.provider;

\echo === NON-MAGIC parity: source non-null,>0 cells per provider vs prices rows ===
WITH nm_src AS (
    SELECT unnest(ARRAY[3,4,5,6,7]) AS provider,
           unnest(ARRAY[
               count(*) FILTER (WHERE low_price > 0),
               count(*) FILTER (WHERE market_price > 0),
               count(*) FILTER (WHERE mid_price > 0),
               count(*) FILTER (WHERE high_price > 0),
               count(*) FILTER (WHERE direct_low_price > 0)
           ]) AS src_count
    FROM public.tcgplayer_nonmagic_product_prices
),
nm_new AS (
    SELECT p.provider, count(*) AS new_count
    FROM public.prices p
    JOIN public.variants v ON v.ban_id = p.ban_id
    WHERE v.tcgp_product_id IS NOT NULL
    GROUP BY p.provider
)
SELECT s.provider, pr.shorthand, s.src_count, coalesce(n.new_count,0) AS new_count,
       coalesce(n.new_count,0) - s.src_count AS diff
FROM nm_src s
LEFT JOIN nm_new n USING (provider)
JOIN public.providers pr ON pr.id = s.provider
ORDER BY s.provider;

\echo === totals ===
SELECT 'prices_rows' AS metric, count(*) AS value FROM public.prices;
