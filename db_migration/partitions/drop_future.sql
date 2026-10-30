-- Drop the empty future partitions of prices in the price archive (the
-- sql_config database): every month from the one after next on. Writers
-- create their own months now (UpsertLongPrices). See README.md. Run from this
-- directory; nothing is kept unless apply=1:
--
--   psql -v apply=0 -f drop_future.sql    report and roll back
--   psql -v apply=1 -f drop_future.sql    commit
--
-- Not yet run. Do not run it before every writer is on the build that
-- creates its own partitions, or a stash lands in prices_default.
-- Do not run a writer that does not create its own partitions after it:
-- its first write past next month lands in prices_default.
-- Re-running is safe: with no such partition left it reports none.

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

BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '15min';
-- One lock on the parent covers every drop below.
LOCK TABLE public.prices IN ACCESS EXCLUSIVE MODE;

-- The default partition has no date bound and never matches.
CREATE TEMP TABLE candidates ON COMMIT DROP AS
SELECT c.relname::text AS relname,
       pg_get_expr(c.relpartbound, c.oid) AS bound,
       substring(pg_get_expr(c.relpartbound, c.oid) from '''(\d{4}-\d{2}-\d{2})''')::date AS lower_bound
FROM pg_inherits i
JOIN pg_class c ON c.oid = i.inhrelid
WHERE i.inhparent = 'public.prices'::regclass;

DELETE FROM candidates
WHERE lower_bound IS NULL
   OR lower_bound < (date_trunc('month', current_date) + interval '2 months')::date;

-- A row in one means a stash already ran past the pre-created months.
DO $$
DECLARE
    r record;
    has_rows boolean;
    full_list text := '';
BEGIN
    FOR r IN SELECT relname FROM candidates ORDER BY relname LOOP
        EXECUTE format('SELECT EXISTS (SELECT 1 FROM public.%I)', r.relname) INTO has_rows;
        IF has_rows THEN
            full_list := full_list || ' ' || r.relname;
        END IF;
    END LOOP;
    IF full_list <> '' THEN
        RAISE EXCEPTION 'partitions holding rows, nothing dropped:%', full_list;
    END IF;
END $$;

SELECT relname, bound FROM candidates ORDER BY relname;
SELECT (SELECT count(*) FROM pg_inherits WHERE inhparent = 'public.prices'::regclass) AS partitions_now,
       (SELECT count(*) FROM candidates) AS candidates,
       (SELECT count(*) FROM pg_inherits WHERE inhparent = 'public.prices'::regclass)
         - (SELECT count(*) FROM candidates) AS partitions_after_apply;

-- apply reaches the DO block as a setting, since a $$ body takes no psql variable.
SELECT set_config('drop_future.apply', :'apply_on', true) \gset
DO $$
DECLARE
    r record;
BEGIN
    IF current_setting('drop_future.apply')::boolean THEN
        FOR r IN SELECT relname FROM candidates ORDER BY relname LOOP
            EXECUTE format('DROP TABLE public.%I', r.relname);
        END LOOP;
    END IF;
END $$;

\if :apply_on
COMMIT;
\echo committed
\else
ROLLBACK;
\echo dry run: rolled back, pass -v apply=1 to commit
\endif
