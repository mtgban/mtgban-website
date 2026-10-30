-- Copy the monthly partitions of prices into prices_v2 in the price archive
-- (the sql_config database), oldest month first. See README.md. Run from this
-- directory after 02_create.sql, with no backfill and no repair running
-- meanwhile (they write prices, and a month copied is not copied again):
--
--   psql -f 03_copy.sql
--
-- It runs outside a transaction block on purpose: each month is its own
-- statement and commits alone, so a killed run resumes at the next month
-- that has no done row in migration.progress (phase 'repartition', chunk_key
-- the source partition). It takes no apply: it only fills prices_v2, which
-- nothing reads yet. To start over, TRUNCATE public.prices_v2 and
-- DELETE FROM migration.progress WHERE phase = 'repartition' (the table
-- also holds the earlier backfill phases: never truncate it).
-- A month whose upper bound is on or before the census day (UTC) must copy
-- exactly the census count; the month still being written, at least that. A
-- shortfall raises and rolls that month back, progress row and all. So does
-- a surplus in a static month: rows dated inside it arrived after the
-- census, so re-run 01_census.sql, then this script.
-- Each month's copy holds an advisory lock on that month until it commits,
-- so a run resumed after an ssh session dropped waits on a month the dropped
-- session's backend is still copying, then skips it once done, rather than
-- copying it twice.
-- Raises when the census holds no month source.
-- prices_default is never a source (01_census.sql refuses it holding rows).
-- Re-running is safe: done months are skipped.

\set ON_ERROR_STOP on
-- Command tags stay out of the output; the report SELECTs still print.
\set QUIET on
SET client_min_messages = warning;
SET statement_timeout = 0;
SET synchronous_commit = off;
SET work_mem = '256MB';

CREATE OR REPLACE FUNCTION migration.copy_month(src text) RETURNS bigint
LANGUAGE plpgsql AS $fn$
DECLARE
    part     regclass := to_regclass('public.' || quote_ident(regexp_replace(src, '^public\.', '')));
    upper_d  date;
    census_d date;
    want     bigint;
    got      bigint;
    t0       timestamptz := now();
BEGIN
    -- One copier per month; the done row is read again once the lock is held.
    PERFORM pg_advisory_xact_lock(hashtext('repartition:' || src));
    IF EXISTS (SELECT 1 FROM migration.progress
               WHERE phase = 'repartition' AND chunk_key = src AND status = 'done') THEN
        RETURN 0;
    END IF;
    IF part IS NULL THEN
        RAISE EXCEPTION 'no partition %', src;
    END IF;
    SELECT (regexp_match(pg_get_expr(c.relpartbound, c.oid), 'TO \(''([0-9-]+)''\)'))[1]::date
      INTO upper_d FROM pg_class c WHERE c.oid = part;
    SELECT sum(rows), (max(run_at) AT TIME ZONE 'UTC')::date INTO want, census_d
      FROM migration.census WHERE source = src;
    IF want IS NULL OR upper_d IS NULL THEN
        RAISE EXCEPTION 'no census rows or no upper bound for %', src;
    END IF;

    EXECUTE format('INSERT INTO public.prices_v2 SELECT * FROM %s', part);
    GET DIAGNOSTICS got = ROW_COUNT;

    IF upper_d <= census_d AND got <> want THEN
        RAISE EXCEPTION '% copied % rows, census has %', src, got, want;
    ELSIF got < want THEN
        RAISE EXCEPTION '% copied % rows, census has at least %', src, got, want;
    END IF;

    INSERT INTO migration.progress (phase, chunk_key, status, rows_written, started_at, finished_at, error_msg)
    VALUES ('repartition', src, 'done', got, t0, clock_timestamp(), NULL)
    ON CONFLICT (phase, chunk_key) DO UPDATE
    SET status = 'done', rows_written = EXCLUDED.rows_written, started_at = EXCLUDED.started_at,
        finished_at = EXCLUDED.finished_at, error_msg = NULL;
    RETURN got;
END
$fn$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM migration.census
                   WHERE source ~ '^(public\.)?prices_[0-9]{4}_[0-9]{2}$') THEN
        RAISE EXCEPTION 'migration.census holds no month source, run 01_census.sql, nothing copied';
    END IF;
END $$;

-- Every month source of the census, copied or not (rows_written is NULL until done).
CREATE OR REPLACE TEMP VIEW copy_report AS
SELECT c.source AS month, c.rows AS census_rows,
       coalesce(p.status, 'todo') AS status, p.rows_written
FROM (SELECT source, sum(rows) AS rows FROM migration.census
      WHERE source ~ '^(public\.)?prices_[0-9]{4}_[0-9]{2}$' GROUP BY source) c
LEFT JOIN migration.progress p ON p.phase = 'repartition' AND p.chunk_key = c.source
ORDER BY c.source;
SELECT * FROM migration.status WHERE phase = 'repartition';
SELECT * FROM copy_report;

-- One statement per month not yet done; each commits on its own.
SELECT format('SELECT %L AS month, migration.copy_month(%L) AS rows_copied', source, source)
FROM (SELECT DISTINCT source FROM migration.census
      WHERE source ~ '^(public\.)?prices_[0-9]{4}_[0-9]{2}$') s
WHERE NOT EXISTS (SELECT 1 FROM migration.progress p
                  WHERE p.phase = 'repartition' AND p.chunk_key = s.source AND p.status = 'done')
ORDER BY source
\gexec

SELECT * FROM migration.status WHERE phase = 'repartition';
SELECT * FROM copy_report;
