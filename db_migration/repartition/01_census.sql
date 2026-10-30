-- Count the rows of prices in the price archive (the sql_config database) by
-- source partition and ban_id range, then cut the sequence block into the
-- partitions of prices_v2. See README.md. Run from this directory; it writes
-- only the migration schema, so there is no apply:
--
--   psql -f 01_census.sql
--   psql -v target_rows=1000 -f 01_census.sql    smaller cuts, for a rehearsal
--
-- It reads the whole table in one scan (hours): run it off-peak. A failure
-- leaves the previous census and bounds in place.
-- Raises when prices is already partitioned by ban_id, and when
-- prices_default holds a row (repair it first, ../partitions/README.md).
-- Re-running is safe: it replaces the census and rewrites the bounds.

\set ON_ERROR_STOP on
-- Command tags stay out of the output; the report SELECTs still print.
\set QUIET on
-- A second run would otherwise print a notice per existing table.
SET client_min_messages = warning;
\if :{?target_rows}
\else
\set target_rows 90000000
\endif

-- target_rows is checked once; anything but a positive integer is refused.
SELECT :'target_rows' ~ '^[1-9][0-9]{0,17}$' AS target_valid \gset
\if :target_valid
\else
\echo target_rows must be a positive integer, got :target_rows
DO $$ BEGIN RAISE EXCEPTION 'target_rows must be a positive integer, nothing changed'; END $$;
\endif

BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '12h';

CREATE TABLE IF NOT EXISTS migration.census (
    run_at   timestamptz NOT NULL DEFAULT now(),
    source   text NOT NULL,
    bucket   bigint,
    category int,
    rows     bigint NOT NULL
);
CREATE TABLE IF NOT EXISTS migration.repartition_bounds (
    ord      int PRIMARY KEY,
    name     text NOT NULL UNIQUE,
    lo       bigint NOT NULL,
    hi       bigint NOT NULL,
    est_rows bigint NOT NULL
);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_partitioned_table p
               JOIN pg_attribute a ON a.attrelid = p.partrelid AND a.attnum = p.partattrs[0]
               WHERE p.partrelid = 'public.prices'::regclass AND a.attname = 'ban_id') THEN
        RAISE EXCEPTION 'prices is already partitioned by ban_id, nothing changed';
    END IF;
    IF EXISTS (SELECT 1 FROM public.prices_default) THEN
        RAISE EXCEPTION 'prices_default holds rows, repair them first, nothing changed';
    END IF;
END $$;

TRUNCATE migration.census, migration.repartition_bounds;

-- Ids below 2^40 come from the sequence, above it are category<<40 | product<<8 | subtype.
INSERT INTO migration.census (source, bucket, category, rows)
SELECT tableoid::regclass::text,
       CASE WHEN ban_id < (1::bigint << 40) THEN ban_id >> 12 END,
       CASE WHEN ban_id >= (1::bigint << 40) THEN (ban_id >> 40)::int END,
       count(*)
FROM public.prices
GROUP BY 1, 2, 3;

-- A bucket joins the partition numbered by the rows before it over target_rows.
INSERT INTO migration.repartition_bounds (ord, name, lo, hi, est_rows)
WITH b AS (
    SELECT bucket, sum(rows) AS rows
    FROM migration.census WHERE bucket IS NOT NULL
    GROUP BY bucket
), g AS (
    SELECT bucket, rows,
           floor((sum(rows) OVER (ORDER BY bucket) - rows) / :'target_rows'::numeric) AS grp
    FROM b
), d AS (
    SELECT dense_rank() OVER (ORDER BY grp)::int AS ord,
           min(bucket) AS min_bucket, max(bucket) AS max_bucket, sum(rows)::bigint AS est_rows
    FROM g GROUP BY grp
), c AS (
    SELECT ord, est_rows, max_bucket,
           CASE WHEN ord = 1 THEN 1::bigint ELSE min_bucket << 12 END AS lo
    FROM d
), cuts AS (
    SELECT ord, est_rows, lo,
           coalesce(lead(lo) OVER (ORDER BY ord), (max_bucket + 1) << 12) AS hi
    FROM c
)
SELECT ord, 'prices_seq_' || to_char(ord, 'FM00'), lo, hi, est_rows FROM cuts
UNION ALL
SELECT (SELECT coalesce(max(ord), 0) FROM cuts) + 1, 'prices_seq_tail',
       coalesce((SELECT max(hi) FROM cuts), 1), 1::bigint << 40, 0;

COMMIT;

SELECT source, sum(rows) AS rows FROM migration.census GROUP BY source ORDER BY source;
SELECT category, sum(rows) AS rows FROM migration.census
WHERE category IS NOT NULL GROUP BY category ORDER BY category;
SELECT ord, name, lo, hi, est_rows FROM migration.repartition_bounds ORDER BY ord;
SELECT coalesce(sum(rows), 0) AS total_rows,
       coalesce(sum(rows) FILTER (WHERE bucket IS NOT NULL), 0) AS sequence_rows,
       coalesce(sum(rows) FILTER (WHERE category IS NOT NULL), 0) AS derived_rows,
       max(run_at) AS run_at
FROM migration.census;
