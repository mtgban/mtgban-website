-- Create prices_v2 in the price archive (the sql_config database): an empty
-- copy of prices partitioned by ban_id range, one partition per row of
-- migration.repartition_bounds and one per category in variants. See
-- README.md. Run from this directory after 01_census.sql; nothing is kept
-- unless apply=1:
--
--   psql -v apply=0 -f 02_create.sql    list the partitions, roll back
--   psql -v apply=1 -f 02_create.sql    commit
--   psql -v apply=1 -v tablespace=fast -f 02_create.sql
--
-- The tablespace is optional; the partitions inherit it from the parent.
-- No indexes and no constraints: they come after the copy.
-- Raises when the bounds are empty, when prices is already partitioned by
-- ban_id, and on a clash in bounds: a table under a planned name that is not
-- that partition, or a missing partition overlapping one prices_v2 has.
-- Re-running is safe: what exists is left alone. Run it again, rows copied
-- or not, whenever a category appears in variants before the swap (a new
-- game's ingest), or the copy and the catch-up fail on its rows with no
-- partition of prices_v2; the dry run lists the one it would add.

\set ON_ERROR_STOP on
-- Command tags stay out of the output; the report SELECTs still print.
\set QUIET on
-- A second run would otherwise print a notice per existing table.
SET client_min_messages = warning;
\if :{?apply}
\else
\set apply 0
\endif
\if :{?tablespace}
\else
\set tablespace ''
\endif

-- apply is normalised once; any value but 0 or 1 is refused.
SELECT :'apply' IN ('0', '1') AS apply_valid, :'apply' = '1' AS apply_on \gset
\if :apply_valid
\else
\echo apply must be 0 or 1, got :apply
DO $$ BEGIN RAISE EXCEPTION 'apply must be 0 or 1, nothing created'; END $$;
\endif

BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '15min';

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM migration.repartition_bounds) THEN
        RAISE EXCEPTION 'migration.repartition_bounds is empty, run 01_census.sql, nothing created';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_partitioned_table p
               JOIN pg_attribute a ON a.attrelid = p.partrelid AND a.attnum = p.partattrs[0]
               WHERE p.partrelid = 'public.prices'::regclass AND a.attname = 'ban_id') THEN
        RAISE EXCEPTION 'prices is already partitioned by ban_id, nothing created';
    END IF;
END $$;

-- The sequence cuts, then a block per category in variants (or already in prices).
CREATE TEMP TABLE plan ON COMMIT DROP AS
SELECT name, lo, hi FROM migration.repartition_bounds
UNION ALL
SELECT 'prices_cat_' || n, n::bigint << 40, (n + 1)::bigint << 40
FROM (SELECT ban_id >> 40 AS n FROM variants WHERE ban_id >= (1::bigint << 40)
      UNION
      SELECT category FROM migration.census WHERE category IS NOT NULL) c;

-- A table under a planned name must be that partition of prices_v2, bounds alike.
DO $$
DECLARE
    bad text;
BEGIN
    SELECT string_agg(p.name, ' ' ORDER BY p.name) INTO bad
    FROM plan p
    JOIN pg_class c ON c.relname = p.name AND c.relnamespace = 'public'::regnamespace
    WHERE NOT EXISTS (
        SELECT 1 FROM pg_inherits i
        WHERE i.inhrelid = c.oid AND i.inhparent = to_regclass('public.prices_v2')
          AND pg_get_expr(c.relpartbound, c.oid) = format('FOR VALUES FROM (%L) TO (%L)', p.lo, p.hi));
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION 'a table exists under a planned name with other bounds, nothing created: %', bad;
    END IF;
    -- A partition to create must not overlap one there (a census re-run).
    SELECT string_agg(p.name || ' overlaps ' || c.relname, ', ' ORDER BY p.name) INTO bad
    FROM plan p
    JOIN pg_inherits i ON i.inhparent = to_regclass('public.prices_v2')
    JOIN pg_class c ON c.oid = i.inhrelid
    CROSS JOIN LATERAL regexp_match(pg_get_expr(c.relpartbound, c.oid),
                                    '^FOR VALUES FROM \(''?(-?[0-9]+)''?\) TO \(''?(-?[0-9]+)''?\)$') b
    WHERE to_regclass('public.' || quote_ident(p.name)) IS NULL
      AND p.lo < b[2]::bigint AND b[1]::bigint < p.hi;
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION 'a partition to create overlaps one prices_v2 has, nothing created: %', bad;
    END IF;
END $$;

SELECT p.name, p.lo, p.hi,
       CASE WHEN to_regclass('public.' || quote_ident(p.name)) IS NULL THEN 'create' ELSE 'exists' END AS action
FROM plan p ORDER BY p.lo;
SELECT count(*) AS partitions,
       count(*) FILTER (WHERE to_regclass('public.' || quote_ident(name)) IS NULL) AS to_create
FROM plan;

-- apply and the tablespace reach the DO block as settings, since a $$ body takes no psql variable.
SELECT set_config('create.apply', :'apply_on', true),
       set_config('create.tablespace', :'tablespace', true) \gset
DO $$
DECLARE
    ts text := current_setting('create.tablespace');
    r record;
BEGIN
    IF NOT current_setting('create.apply')::boolean THEN
        RETURN;
    END IF;
    EXECUTE 'CREATE TABLE IF NOT EXISTS public.prices_v2 (LIKE public.prices) PARTITION BY RANGE (ban_id)'
            || CASE WHEN ts <> '' THEN format(' TABLESPACE %I', ts) ELSE '' END;
    FOR r IN SELECT name, lo, hi FROM plan ORDER BY lo LOOP
        EXECUTE format('CREATE TABLE IF NOT EXISTS public.%I PARTITION OF public.prices_v2 FOR VALUES FROM (%s) TO (%s)',
                       r.name, r.lo, r.hi);
    END LOOP;
END $$;

\if :apply_on
COMMIT;
\echo committed
\else
ROLLBACK;
\echo dry run: rolled back, pass -v apply=1 to commit
\endif
