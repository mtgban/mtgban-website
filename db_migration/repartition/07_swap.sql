-- Swap prices_v2 in for prices in the price archive (the sql_config
-- database): prices becomes prices_old, prices_v2 becomes prices, and the
-- indexes and foreign keys take the names the monthly layout had. See
-- README.md. Run from this directory after 06_gate.sql passed and a volume
-- snapshot exists, outside every writer's window; nothing is kept unless
-- apply=1:
--
--   psql -f 07_swap.sql            check, list the renames, roll back
--   psql -v apply=1 -f 07_swap.sql
--
-- Raises when prices is not partitioned by date, when prices_v2 or one of
-- its parent indexes or foreign keys is missing, when an index is not
-- valid, when prices_v2 is not partitioned by ban_id, when prices has no
-- prices_provider_date, when prices_old or prices_uk already exists, when
-- the census holds no month source or one of them has no done row in
-- migration.progress (phase 'repartition') or one with fewer rows than the
-- census (run 03_copy.sql), when prices_v2 has another owner or other
-- grants than prices (both are shown: GRANT on prices_v2 until they
-- match), and when a provider's latest day differs between the two (run
-- 05_catchup.sql). The apply takes both tables ACCESS EXCLUSIVE with a 5s
-- lock_timeout, checks the latest days again under the lock, renames and
-- commits. Restart the sites on the Magic, Pokemon and Yu-Gi-Oh droplets
-- and cmd/tcgcsvd right after, the App Platform apps at their next deploy
-- or by hand.
-- A second run raises: prices is then partitioned by ban_id.

\set ON_ERROR_STOP on
-- Command tags stay out of the output; the report SELECTs still print.
\set QUIET on
SET client_min_messages = warning;
\if :{?apply}
\else
\set apply 0
\endif

-- apply is normalised once; any value but 0 or 1 is refused.
SELECT :'apply' IN ('0', '1') AS apply_valid, :'apply' = '1' AS apply_on \gset
\if :apply_valid
\else
\echo apply must be 0 or 1, got :apply
DO $$ BEGIN RAISE EXCEPTION 'apply must be 0 or 1, nothing renamed'; END $$;
\endif

BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '15min';

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_partitioned_table p
                   JOIN pg_attribute a ON a.attrelid = p.partrelid AND a.attnum = p.partattrs[0]
                   WHERE p.partrelid = 'public.prices'::regclass AND a.attname = 'date') THEN
        RAISE EXCEPTION 'prices is not partitioned by date, nothing renamed';
    END IF;
    IF to_regclass('public.prices_v2') IS NULL THEN
        RAISE EXCEPTION 'prices_v2 does not exist, nothing renamed';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_partitioned_table p
                   JOIN pg_attribute a ON a.attrelid = p.partrelid AND a.attnum = p.partattrs[0]
                   WHERE p.partrelid = 'public.prices_v2'::regclass AND a.attname = 'ban_id') THEN
        RAISE EXCEPTION 'prices_v2 is not partitioned by ban_id, nothing renamed';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_index
                   WHERE indexrelid = to_regclass('public.prices_provider_date')
                     AND indrelid = 'public.prices'::regclass) THEN
        RAISE EXCEPTION 'prices_provider_date is not an index of prices, nothing renamed';
    END IF;
    IF to_regclass('public.prices_uk') IS NOT NULL THEN
        RAISE EXCEPTION 'prices_uk already exists, nothing renamed';
    END IF;
    IF (SELECT count(*) FROM pg_index
        WHERE indexrelid IN (to_regclass('public.prices_v2_uk'), to_regclass('public.prices_v2_provider_date'))
          AND indrelid = 'public.prices_v2'::regclass AND indisvalid) <> 2 THEN
        RAISE EXCEPTION 'prices_v2_uk or prices_v2_provider_date is missing or not valid, run 04_indexes.sql, nothing renamed';
    END IF;
    IF (SELECT count(*) FROM pg_constraint
        WHERE conrelid = 'public.prices_v2'::regclass
          AND conname IN ('prices_v2_ban_id_fk', 'prices_v2_provider_fk')) <> 2 THEN
        RAISE EXCEPTION 'prices_v2_ban_id_fk or prices_v2_provider_fk is missing, run 04_indexes.sql, nothing renamed';
    END IF;
    IF to_regclass('public.prices_old') IS NOT NULL OR to_regclass('public.prices_old_provider_date') IS NOT NULL THEN
        RAISE EXCEPTION 'prices_old or prices_old_provider_date exists, nothing renamed';
    END IF;
END $$;

-- Every census month copied: a done row with at least its census rows.
DO $$
DECLARE
    bad text;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM migration.census
                   WHERE source ~ '^(public\.)?prices_[0-9]{4}_[0-9]{2}$') THEN
        RAISE EXCEPTION 'migration.census holds no month source, nothing renamed';
    END IF;
    SELECT format('%s (census %s, copied %s)', c.source, c.rows, coalesce(p.rows_written::text, 'nothing'))
      INTO bad
    FROM (SELECT source, sum(rows) AS rows FROM migration.census
          WHERE source ~ '^(public\.)?prices_[0-9]{4}_[0-9]{2}$' GROUP BY source) c
    LEFT JOIN migration.progress p
      ON p.phase = 'repartition' AND p.chunk_key = c.source AND p.status = 'done'
    WHERE p.rows_written IS NULL OR p.rows_written < c.rows
    ORDER BY c.source
    LIMIT 1;
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION 'a month of the census is not copied whole, run 03_copy.sql, nothing renamed: %', bad;
    END IF;
END $$;

-- LIKE copies no grants: the readers of prices must read prices_v2 too.
DO $$
DECLARE
    old_acl text;
    new_acl text;
BEGIN
    SELECT format('owner %s, grants %s', relowner::regrole, coalesce(relacl::text, 'default')) INTO old_acl
      FROM pg_class WHERE oid = 'public.prices'::regclass;
    SELECT format('owner %s, grants %s', relowner::regrole, coalesce(relacl::text, 'default')) INTO new_acl
      FROM pg_class WHERE oid = 'public.prices_v2'::regclass;
    IF old_acl <> new_acl THEN
        RAISE EXCEPTION 'prices_v2 has another owner or other grants than prices, nothing renamed'
            USING DETAIL = format('prices: %s; prices_v2: %s', old_acl, new_acl),
                  HINT = 'GRANT on prices_v2 (ALTER TABLE prices_v2 OWNER TO for the owner) until both match, then run this again';
    END IF;
END $$;

-- Each provider's latest day in both tables; the swap needs them equal.
CREATE TEMP TABLE swap_dates ON COMMIT DROP AS
SELECT p.id AS provider,
       (SELECT max(date) FROM public.prices WHERE provider = p.id) AS prices_last,
       (SELECT max(date) FROM public.prices_v2 WHERE provider = p.id) AS prices_v2_last
FROM public.providers p;
SELECT provider, prices_last, prices_v2_last,
       prices_last IS NOT DISTINCT FROM prices_v2_last AS same
FROM swap_dates ORDER BY provider;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM swap_dates WHERE prices_last IS DISTINCT FROM prices_v2_last) THEN
        RAISE EXCEPTION 'a provider''s latest day differs between prices and prices_v2, run the catch-up (05_catchup.sql), nothing renamed';
    END IF;
END $$;

SELECT * FROM (VALUES
    (1, 'index', 'prices_provider_date', 'prices_old_provider_date'),
    (2, 'table', 'prices', 'prices_old'),
    (3, 'table', 'prices_v2', 'prices'),
    (4, 'index', 'prices_v2_uk', 'prices_uk'),
    (5, 'index', 'prices_v2_provider_date', 'prices_provider_date'),
    (6, 'constraint', 'prices_v2_ban_id_fk', 'prices_ban_id_fk'),
    (7, 'constraint', 'prices_v2_provider_fk', 'prices_provider_fk')
) r(step, kind, old_name, new_name);

\if :apply_on
LOCK TABLE public.prices, public.prices_v2 IN ACCESS EXCLUSIVE MODE;
-- Under the lock no writer can move a latest day between the check and the renames.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM public.providers p
               WHERE (SELECT max(date) FROM public.prices WHERE provider = p.id)
                     IS DISTINCT FROM (SELECT max(date) FROM public.prices_v2 WHERE provider = p.id)) THEN
        RAISE EXCEPTION 'a provider''s latest day moved before the lock, run the catch-up (05_catchup.sql), nothing renamed';
    END IF;
END $$;
ALTER INDEX public.prices_provider_date RENAME TO prices_old_provider_date;
ALTER TABLE public.prices RENAME TO prices_old;
ALTER TABLE public.prices_v2 RENAME TO prices;
ALTER INDEX public.prices_v2_uk RENAME TO prices_uk;
ALTER INDEX public.prices_v2_provider_date RENAME TO prices_provider_date;
ALTER TABLE public.prices RENAME CONSTRAINT prices_v2_ban_id_fk TO prices_ban_id_fk;
ALTER TABLE public.prices RENAME CONSTRAINT prices_v2_provider_fk TO prices_provider_fk;
COMMIT;
SELECT c.relname AS name, c.relkind, pg_get_partkeydef(c.oid) AS partition_key
FROM pg_class c WHERE c.oid IN ('public.prices'::regclass, 'public.prices_old'::regclass)
ORDER BY c.relname;
\echo committed
\echo restart the sites on the Magic, Pokemon and Yu-Gi-Oh droplets and cmd/tcgcsvd now, so their prepared chart reads are planned afresh on the new prices
\else
ROLLBACK;
\echo dry run: rolled back, pass -v apply=1 to commit
\endif
