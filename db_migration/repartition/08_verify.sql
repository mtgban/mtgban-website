-- Compare prices with prices_old in the price archive (the sql_config
-- database) after 07_swap.sql and the catch-up from prices_old. See
-- README.md. Run from this directory, on the direct port, off-peak (it
-- counts both whole tables):
--
--   psql -v since=2026-10-29 -v swap=2026-11-02 -f 08_verify.sql
--
-- since and swap (YYYY-MM-DD) are required: the day the first catch-up
-- started from, and the day of the swap. Writers reach only prices after
-- the swap, so the days are read in three bands. Before the swap (since <=
-- date < swap) prices must hold every row of prices_old, matched by key, and
-- may hold more: a writer resumed after the hold can still file a day before
-- the swap (tcgcsv's last refresh, a stale scrape's own date). From the swap
-- on, prices must hold at least the rows and as late a day as prices_old per
-- provider. Before since (date < since), per month and provider, prices
-- must hold at least the rows of prices_old: a row dated there but written
-- after its month was copied is missing otherwise, and only the rows where
-- that fails are listed, with one line for all whose prices_covers is the
-- pass.
-- Then each whole table's count, prices's at least prices_old's;
-- then prices's partitions with their size, and whether its two parent
-- indexes are valid. One REPEATABLE READ READ ONLY transaction, so every
-- section reads the same snapshot.
-- Raises when since or swap is not a date, when swap is before since, and
-- when prices or prices_old is missing.

\set ON_ERROR_STOP on
-- Command tags stay out of the output; the report SELECTs still print.
\set QUIET on
SET client_min_messages = warning;
SET statement_timeout = '4h';
\if :{?since}
\else
\set since ''
\endif
\if :{?swap}
\else
\set swap ''
\endif

-- The arguments are checked once, before anything is read.
SELECT coalesce(pg_input_is_valid(nullif(:'since', ''), 'date') AND :'since' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$', false) AS since_shaped,
       coalesce(pg_input_is_valid(nullif(:'swap', ''), 'date') AND :'swap' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$', false) AS swap_shaped,
       to_regclass('public.prices') IS NOT NULL AND to_regclass('public.prices_old') IS NOT NULL AS tables_found \gset
\if :since_shaped
\else
\echo since must be a date, got :since
DO $$ BEGIN RAISE EXCEPTION 'since must be a date, nothing read'; END $$;
\endif
\if :swap_shaped
\else
\echo swap must be a date, got :swap
DO $$ BEGIN RAISE EXCEPTION 'swap must be a date, nothing read'; END $$;
\endif
SELECT :'swap'::date >= :'since'::date AS swap_after_since \gset
\if :swap_after_since
\else
\echo swap must be on or after since
DO $$ BEGIN RAISE EXCEPTION 'swap must be on or after since, nothing read'; END $$;
\endif
\if :tables_found
\else
\echo prices and prices_old must both exist
DO $$ BEGIN RAISE EXCEPTION 'prices or prices_old does not exist, nothing read'; END $$;
\endif

BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;

\echo === before the swap: since <= date < swap, every row of prices_old in prices, per provider
-- By key, not by count: the rows writers add here could offset one missing.
SELECT coalesce(a.provider, b.provider) AS provider,
       a.n AS prices_rows, b.n AS prices_old_rows,
       a.last_date AS prices_last, b.last_date AS prices_old_last,
       coalesce(m.n, 0) AS missing, m.n IS NULL AS prices_covers
FROM (SELECT provider, count(*) AS n, max(date) AS last_date FROM public.prices
      WHERE date >= :'since'::date AND date < :'swap'::date GROUP BY provider) a
FULL JOIN (SELECT provider, count(*) AS n, max(date) AS last_date FROM public.prices_old
           WHERE date >= :'since'::date AND date < :'swap'::date GROUP BY provider) b
  ON a.provider = b.provider
LEFT JOIN (SELECT o.provider, count(*) AS n FROM public.prices_old o
           WHERE o.date >= :'since'::date AND o.date < :'swap'::date
             AND NOT EXISTS (SELECT 1 FROM public.prices p
                             WHERE (p.ban_id, p.date, p.provider) = (o.ban_id, o.date, o.provider))
           GROUP BY o.provider) m
  ON m.provider = coalesce(a.provider, b.provider)
ORDER BY 1;

\echo === from the swap on: date >= swap, prices covers prices_old per provider
SELECT coalesce(a.provider, b.provider) AS provider,
       a.n AS prices_rows, b.n AS prices_old_rows,
       a.last_date AS prices_last, b.last_date AS prices_old_last,
       coalesce(a.n >= b.n AND a.last_date >= b.last_date, b.n IS NULL) AS prices_covers
FROM (SELECT provider, count(*) AS n, max(date) AS last_date FROM public.prices
      WHERE date >= :'swap'::date GROUP BY provider) a
FULL JOIN (SELECT provider, count(*) AS n, max(date) AS last_date FROM public.prices_old
           WHERE date >= :'swap'::date GROUP BY provider) b
  ON a.provider = b.provider
ORDER BY 1;

-- A row dated before since but written after its month was copied (a stale
-- store's stash files its own scrape date) is in no band above.
\echo === before since: date < since, prices covers prices_old per month and provider
\echo === (the rows where it does not, then one line for all, whose prices_covers is the pass)
WITH g AS (
    SELECT coalesce(a.month, b.month) AS month, coalesce(a.provider, b.provider) AS provider,
           coalesce(a.n, 0) AS prices_rows, coalesce(b.n, 0) AS prices_old_rows,
           coalesce(a.n, 0) >= coalesce(b.n, 0) AS prices_covers
    FROM (SELECT date_trunc('month', date)::date AS month, provider, count(*) AS n FROM public.prices
          WHERE date < :'since'::date GROUP BY 1, 2) a
    FULL JOIN (SELECT date_trunc('month', date)::date AS month, provider, count(*) AS n FROM public.prices_old
               WHERE date < :'since'::date GROUP BY 1, 2) b
      ON a.month = b.month AND a.provider = b.provider
)
SELECT month, provider, prices_rows, prices_old_rows, prices_covers
FROM (SELECT 0 AS k, month::text AS month, provider, prices_rows, prices_old_rows, prices_covers
      FROM g WHERE NOT prices_covers
      UNION ALL
      SELECT 1, format('all %s month-provider pairs', count(*)), NULL,
             sum(prices_rows), sum(prices_old_rows), coalesce(bool_and(prices_covers), true)
      FROM g) r
ORDER BY k, month, provider;

\echo === whole tables: prices holds at least prices_old
SELECT t.prices_rows, t.prices_old_rows, t.prices_rows >= t.prices_old_rows AS prices_covers
FROM (SELECT (SELECT count(*) FROM public.prices) AS prices_rows,
             (SELECT count(*) FROM public.prices_old) AS prices_old_rows) t;

SELECT c.relname AS partition, pg_get_expr(c.relpartbound, c.oid) AS bounds,
       pg_size_pretty(pg_relation_size(c.oid)) AS heap, pg_relation_size(c.oid) AS heap_bytes
FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
WHERE i.inhparent = 'public.prices'::regclass
ORDER BY c.relname;

SELECT c.relname AS parent_index, i.indisvalid
FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
WHERE i.indrelid = 'public.prices'::regclass
ORDER BY c.relname;

COMMIT;
