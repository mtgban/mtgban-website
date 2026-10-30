-- The second gate, in the price archive (the sql_config database): EXPLAIN
-- ANALYZE of the three reads the swap could slow, against prices or
-- prices_v2. See README.md. Run from this directory, on the direct port, for
-- both tables in the same hour, and keep both outputs:
--
--   psql -v table=prices -v ban=123456 -f 06_gate.sql
--   psql -v table=prices_v2 -v ban=123456 -f 06_gate.sql
--   psql -v table=prices_v2 -v ban=123456 -v provider=10 -f 06_gate.sql
--
-- The shapes are the Go client's, with the table substituted: the buylist
-- aggregate of GetAggregatePriceStatsLong (provider, default 2, over the
-- last 90 days), the movers rows of buildMoverRowsQuery for Magic (provider
-- 3, a seven-day window anchored on price_dates as moverAnchor does, min
-- price 5), and the chart read hgetAllByBanIDQuery for ban over ten years.
-- ban should be an id nothing has read lately, the same for both tables.
-- Read-only: it runs in a READ ONLY transaction and rolls back.
-- Raises when table is not prices or prices_v2, when ban or provider is not
-- a positive integer, and when price_dates has no Magic anchor days.

\set ON_ERROR_STOP on
-- Command tags stay out of the output; the plans still print.
\set QUIET on
SET client_min_messages = warning;
SET statement_timeout = '10min';
\if :{?table}
\else
\set table ''
\endif
\if :{?ban}
\else
\set ban ''
\endif
\if :{?provider}
\else
\set provider 2
\endif

-- The arguments are checked once, before anything is read.
SELECT :'table' IN ('prices', 'prices_v2') AND to_regclass('public.' || :'table') IS NOT NULL AS table_valid,
       :'ban' ~ '^[1-9][0-9]{0,18}$' AS ban_valid,
       :'provider' ~ '^[1-9][0-9]{0,4}$' AS provider_valid \gset
\if :table_valid
\else
\echo table must be prices or prices_v2 and exist, got :table
DO $$ BEGIN RAISE EXCEPTION 'table must be prices or prices_v2, nothing read'; END $$;
\endif
\if :ban_valid
\else
\echo ban must be a positive integer, got :ban
DO $$ BEGIN RAISE EXCEPTION 'ban must be a positive integer, nothing read'; END $$;
\endif
\if :provider_valid
\else
\echo provider must be a positive integer, got :provider
DO $$ BEGIN RAISE EXCEPTION 'provider must be a positive integer, nothing read'; END $$;
\endif

BEGIN READ ONLY;

-- moverAnchor: Magic's newest day under provider 3, then the newest a week before it.
SELECT coalesce(l.latest::text, '') AS latest,
       coalesce((SELECT max(date) FROM public.price_dates
                 WHERE provider = 3 AND category = 1 AND date <= l.latest - 7)::text, '') AS prior
FROM (SELECT max(date) AS latest FROM public.price_dates WHERE provider = 3 AND category = 1) l \gset
SELECT :'latest' <> '' AND :'prior' <> '' AS anchors_found \gset
\if :anchors_found
\else
\echo price_dates has no two Magic days a week apart under provider 3
DO $$ BEGIN RAISE EXCEPTION 'price_dates has no Magic anchor days, nothing read'; END $$;
\endif

SELECT :'table' AS gate_table, :'ban'::bigint AS ban, :'provider'::int AS aggregate_provider,
       current_date - 90 AS aggregate_since, :'latest'::date AS movers_latest,
       :'prior'::date AS movers_prior, now() AS run_at;

\echo === buylist aggregate (GetAggregatePriceStatsLong)
EXPLAIN (ANALYZE, BUFFERS, SUMMARY)
SELECT v.mtgban_id,
       MAX(p.price)                                          AS max_price,
       MIN(p.price)                                          AS min_price,
       percentile_disc(0.9) WITHIN GROUP (ORDER BY p.price)  AS p90_price,
       COUNT(*)                                              AS sample_count,
       COALESCE(MAX(p.price) FILTER (WHERE p.date < current_date), 0)  AS prior_max
  FROM public.:"table" p
  JOIN variants v ON v.ban_id = p.ban_id
 WHERE p.provider = :'provider'::smallint AND p.date >= current_date - 90 AND p.price > 0
   AND v.mtgban_id IS NOT NULL
 GROUP BY v.mtgban_id;

\echo === movers rows, Magic (buildMoverRowsQuery)
EXPLAIN (ANALYZE, BUFFERS, SUMMARY)
WITH cur AS MATERIALIZED (
    SELECT ban_id, price FROM public.:"table"
     WHERE provider = 3 AND date = :'latest'::date AND price >= 5
),
old AS MATERIALIZED (
    SELECT ban_id, price FROM public.:"table"
     WHERE provider = 3 AND date = :'prior'::date AND price >= 0
)
SELECT v.mtgjson_uuid, v.is_foil, v.is_etched,
       v.tcgp_product_id, v.tcgp_sub_type,
       cur.price, old.price
  FROM cur JOIN old USING (ban_id)
  JOIN variants v ON v.ban_id = cur.ban_id
 WHERE v.mtgjson_uuid IS NOT NULL AND v.language = '' AND NOT v.is_alt;

\echo === chart read, ten years (hgetAllByBanIDQuery)
EXPLAIN (ANALYZE, BUFFERS, SUMMARY)
SELECT date, provider, price FROM public.:"table"
 WHERE ban_id = :'ban'::bigint AND date >= current_date - 3650;

ROLLBACK;
