-- Drop the non-Magic wide table tcgplayer_nonmagic_product_prices and its
-- partitions from the price archive (the sql_config database). Nothing reads
-- or writes it since the ingest gates on price_dates. See README.md. Run from
-- this directory; nothing is kept unless apply=1:
--
--   psql -v apply=0 -f drop_nonmagic.sql    report and roll back
--   psql -v apply=1 -f drop_nonmagic.sql    commit
--
-- Not yet run. Do not run it before the soak and the volume snapshot
-- README.md names. The only rollback is that snapshot.
-- Do not run a build that still calls EnsureTCGSchema after it, the site or
-- /usr/local/bin/tcgcsvd: it recreates the table and writes to it again.
-- Re-running is safe: with the table gone it reports so and exits.

\set ON_ERROR_STOP on
-- Command tags stay out of the output; the report SELECTs still print.
\set QUIET on
\if :{?apply}
\else
\set apply 0
\endif

-- apply is normalised once; any value but 0 or 1 is refused.
SELECT :'apply' IN ('0', '1') AS apply_valid, :'apply' = '1' AS apply_on \gset
\if :apply_valid
\else
\echo apply must be 0 or 1, got :apply
DO $$ BEGIN RAISE EXCEPTION 'apply must be 0 or 1, nothing dropped'; END $$;
\endif

SELECT to_regclass('public.tcgplayer_nonmagic_product_prices') IS NOT NULL AS present \gset

\if :present
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '15min';
LOCK TABLE public.tcgplayer_nonmagic_product_prices IN ACCESS EXCLUSIVE MODE;

-- The categories, read by skipping along the (category_id, date) index.
CREATE TEMP TABLE wide_categories ON COMMIT DROP AS
WITH RECURSIVE cats AS (
    SELECT min(category_id) AS category_id FROM public.tcgplayer_nonmagic_product_prices
    UNION ALL
    SELECT (SELECT min(category_id) FROM public.tcgplayer_nonmagic_product_prices
            WHERE category_id > cats.category_id)
    FROM cats WHERE cats.category_id IS NOT NULL
)
SELECT category_id FROM cats WHERE category_id IS NOT NULL;

CREATE TEMP TABLE wide_freshness ON COMMIT DROP AS
SELECT c.category_id, w.last_wide, d.last_long
FROM wide_categories c
CROSS JOIN LATERAL (SELECT max(date) AS last_wide FROM public.tcgplayer_nonmagic_product_prices
                    WHERE category_id = c.category_id) w
CROSS JOIN LATERAL (SELECT max(date) AS last_long FROM public.price_dates
                    WHERE category = c.category_id AND provider BETWEEN 3 AND 7) d;

-- Every wide day price_dates still keeps, per category, missing from price_dates.
CREATE TEMP TABLE wide_gaps ON COMMIT DROP AS
SELECT c.category_id, g.day
FROM wide_categories c
CROSS JOIN LATERAL (
    WITH RECURSIVE days AS (
        SELECT min(date) AS day FROM public.tcgplayer_nonmagic_product_prices
        WHERE category_id = c.category_id AND date >= current_date - interval '13 months'
        UNION ALL
        SELECT (SELECT min(date) FROM public.tcgplayer_nonmagic_product_prices
                WHERE category_id = c.category_id AND date > days.day)
        FROM days WHERE days.day IS NOT NULL
    )
    SELECT day FROM days WHERE day IS NOT NULL
    EXCEPT
    SELECT date FROM public.price_dates
    WHERE category = c.category_id AND provider BETWEEN 3 AND 7
) g;

SELECT f.category_id, f.last_wide, f.last_long,
       (SELECT count(*) FROM wide_gaps g WHERE g.category_id = f.category_id) AS missing_days
FROM wide_freshness f ORDER BY f.category_id;

-- Nothing the wide table holds may be newer than the long tables, and no day
-- price_dates keeps may be missing from it.
DO $$
DECLARE
    r record;
    bad text := '';
BEGIN
    FOR r IN SELECT * FROM wide_freshness ORDER BY category_id LOOP
        IF r.last_long IS NULL OR r.last_wide > r.last_long THEN
            bad := bad || format(' category %s (wide %s, long %s)', r.category_id, r.last_wide, coalesce(r.last_long::text, 'none'));
        END IF;
    END LOOP;
    IF bad <> '' THEN
        RAISE EXCEPTION 'the wide table is newer than price_dates, nothing dropped:%', bad;
    END IF;
    FOR r IN
        SELECT category_id, count(*) AS n, (array_agg(day ORDER BY day))[1:5] AS first_days
        FROM wide_gaps GROUP BY category_id ORDER BY category_id
    LOOP
        bad := bad || format(' category %s (%s days, first %s)', r.category_id, r.n, array_to_string(r.first_days, ', '));
    END LOOP;
    IF bad <> '' THEN
        RAISE EXCEPTION 'wide days missing from price_dates, nothing dropped:%', bad;
    END IF;
END $$;

SELECT c.relname, pg_size_pretty(pg_total_relation_size(c.oid)) AS size
FROM pg_class c
WHERE c.oid = 'public.tcgplayer_nonmagic_product_prices'::regclass
   OR c.oid IN (SELECT inhrelid FROM pg_inherits WHERE inhparent = 'public.tcgplayer_nonmagic_product_prices'::regclass)
ORDER BY c.relname;

-- apply reaches the DO block as a setting, since a $$ body takes no psql variable.
SELECT set_config('drop_nonmagic.apply', :'apply_on', true) \gset
DO $$
BEGIN
    IF current_setting('drop_nonmagic.apply')::boolean THEN
        DROP TABLE public.tcgplayer_nonmagic_product_prices;
    END IF;
END $$;

\if :apply_on
COMMIT;
\echo committed
\else
ROLLBACK;
\echo dry run: rolled back, pass -v apply=1 to commit
\endif
\else
\echo tcgplayer_nonmagic_product_prices does not exist, nothing to do
\endif
