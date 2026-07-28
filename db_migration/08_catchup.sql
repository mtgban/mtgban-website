-- Reconciliation catch-up (run at cutover, before flipping reads).
--
-- The backfill is a point-in-time snapshot, but the live crons keep writing to
-- product_prices / tcgplayer_nonmagic_product_prices during and after it. So the
-- long tables drift behind by the rows added since the variants snapshot / each
-- month chunk ran (e.g. new printings minted on the backfill's start day that the
-- variant-join couldn't match). Parity verification (07) shows this as a small
-- negative diff on the most-recently-written providers.
--
-- This script re-mints any new variants and re-inserts the recent window into
-- prices with ON CONFLICT DO NOTHING, so only the missing rows are added. It is
-- idempotent and safe to re-run. Set :since to comfortably before the backfill
-- start (default 2026-07-01 covers the whole drift window as of the migration).
--
--   psql ... -v since=2026-07-01 -f 08_catchup.sql
--
-- Once long-form dual-write is enabled and has run a full cycle, drift stops and
-- this only needs to close the one-time gap between backfill and dual-write.
\if :{?since}
\else
  \set since '2026-07-01'
\endif
\timing on
\echo Catch-up since :since
SET synchronous_commit = off;
SET work_mem = '256MB';

-- 1) Re-mint any variants that appeared since the snapshot (idempotent).
INSERT INTO public.variants (mtgjson_uuid, is_foil, is_etched, is_alt, language)
SELECT DISTINCT mtgjson_uuid, is_foil, is_etched, is_alt, language
FROM public.product_prices WHERE date >= DATE :'since'
ON CONFLICT (mtgjson_uuid, is_foil, is_etched, is_alt, language)
    WHERE mtgjson_uuid IS NOT NULL DO NOTHING;

INSERT INTO public.variants (tcgp_category_id, tcgp_product_id, tcgp_sub_type)
SELECT DISTINCT category_id, product_id, coalesce(sub_type_name,'')
FROM public.tcgplayer_nonmagic_product_prices WHERE date >= DATE :'since'
ON CONFLICT (tcgp_category_id, tcgp_product_id, tcgp_sub_type)
    WHERE tcgp_product_id IS NOT NULL DO NOTHING;

-- 2) Magic: re-insert the recent window, filling only missing (ban_id,date,provider).
\echo Magic catch-up ...
INSERT INTO public.prices (ban_id, date, provider, price)
SELECT v.ban_id, src.date, u.provider, u.price
FROM public.product_prices src
JOIN public.variants v
  ON v.mtgjson_uuid = src.mtgjson_uuid AND v.is_foil = src.is_foil
 AND v.is_etched = src.is_etched AND v.is_alt = src.is_alt AND v.language = src.language
CROSS JOIN LATERAL (VALUES
    (1::smallint,  src.cardkingdom_retail_price),
    (2::smallint,  src.cardkingdom_buylist_price),
    (3::smallint,  src.tcgplayer_low_price),
    (4::smallint,  src.tcgplayer_market_price),
    (8::smallint,  src.cardmarket_low_price),
    (9::smallint,  src.cardmarket_trend_price),
    (10::smallint, src.starcitygames_buylist_price),
    (11::smallint, src.abu_buylist_price),
    (12::smallint, src.coolstuffinc_buylist_price),
    (13::smallint, src.tcgplayer_low_sealed_expected_value)
) AS u(provider, price)
WHERE src.date >= DATE :'since' AND u.price > 0
ON CONFLICT (ban_id, date, provider) DO NOTHING;

-- 3) Non-Magic: same, per category so partition pruning + the (category,date)
--    index keep the scan cheap. Loops all dedicated category partitions.
--    :'since' is not substituted inside a $$-quoted DO body, so pass it through a
--    session GUC and read it with current_setting().
\echo Non-Magic catch-up ...
SET catchup.since = :'since';
DO $$
DECLARE
  cat int;
  since_date text := current_setting('catchup.since');
BEGIN
  FOR cat IN
    SELECT regexp_replace(c.relname,'^tcgplayer_nonmagic_product_prices_cat_','')::int
    FROM pg_inherits i JOIN pg_class c ON c.oid=i.inhrelid
    JOIN pg_class p ON p.oid=i.inhparent
    WHERE p.relname='tcgplayer_nonmagic_product_prices' AND c.relname ~ '_cat_[0-9]+$'
  LOOP
    EXECUTE format($q$
      INSERT INTO public.prices (ban_id, date, provider, price)
      SELECT v.ban_id, src.date, u.provider, u.price
      FROM public.tcgplayer_nonmagic_product_prices src
      JOIN public.variants v
        ON v.tcgp_category_id = src.category_id AND v.tcgp_product_id = src.product_id
       AND v.tcgp_sub_type = src.sub_type_name
      CROSS JOIN LATERAL (VALUES
          (3::smallint, src.low_price), (4::smallint, src.market_price),
          (5::smallint, src.mid_price), (6::smallint, src.high_price),
          (7::smallint, src.direct_low_price)
      ) AS u(provider, price)
      WHERE src.category_id = %s AND src.date >= DATE %L AND u.price > 0
      ON CONFLICT (ban_id, date, provider) DO NOTHING$q$, cat, since_date);
  END LOOP;
END $$;

\echo Catch-up done. Re-run 07_verify.sql to confirm parity.
