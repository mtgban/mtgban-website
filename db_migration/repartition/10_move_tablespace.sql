-- Move every relation of prices in the price archive (the sql_config
-- database) off a tablespace: the parent, its partitions and the indexes of
-- each, so the tablespace's volume can be deleted. See README.md. Run from
-- this directory; nothing moves unless apply=1:
--
--   psql -v from=fast -f 10_move_tablespace.sql            list the plan
--   psql -v from=fast -v apply=1 -f 10_move_tablespace.sql
--   psql -v from=fast -v apply=1 -v limit=6 -f 10_move_tablespace.sql
--   psql -v from=fast -v to=other -v apply=1 -f 10_move_tablespace.sql
--
-- to defaults to pg_default. It runs outside a transaction block on purpose:
-- each ALTER commits alone under a 5s lock_timeout, the parent first so new
-- partitions land on the target, then the partitions smallest first, so a
-- failed run keeps what moved and a rerun lists what is left. limit moves
-- the parent and that many partitions; a partly moved partition counts as
-- one. Each ALTER holds that relation ACCESS EXCLUSIVE for its whole copy;
-- the 5s lock_timeout bounds only the wait to acquire it.
-- Raises when from is missing or unknown, when to is unknown, equals from
-- or lacks the CREATE privilege, when limit is not a number of at most 9
-- digits, when prices is not partitioned by ban_id, when prices_old still
-- exists and when a parent index is not valid.

\set ON_ERROR_STOP on
-- Each ALTER commits alone: a .psqlrc with autocommit off would hold every
-- lock to the end and roll it all back at exit.
\set AUTOCOMMIT on
-- Command tags stay out of the output; the report SELECTs still print.
\set QUIET on
SET client_min_messages = warning;
\if :{?apply}
\else
\set apply 0
\endif
\if :{?to}
\else
\set to pg_default
\endif
\if :{?limit}
\else
\set limit 0
\endif
\if :{?from}
\else
\echo from is required, the tablespace to move prices off
DO $$ BEGIN RAISE EXCEPTION 'from is required, nothing moved'; END $$;
\endif

-- apply is normalised once; any value but 0 or 1 is refused.
SELECT :'apply' IN ('0', '1') AS apply_valid, :'apply' = '1' AS apply_on \gset
\if :apply_valid
\else
\echo apply must be 0 or 1, got :apply
DO $$ BEGIN RAISE EXCEPTION 'apply must be 0 or 1, nothing moved'; END $$;
\endif

-- Session level: the ALTERs run outside a transaction block.
SET lock_timeout = '5s';
SET statement_timeout = '30min';

-- The variables reach the DO block as settings, since a $$ body takes no psql variable.
SELECT set_config('move.from', :'from', false),
       set_config('move.to', :'to', false),
       set_config('move.limit', :'limit', false) \gset

DO $$
DECLARE
    src text := current_setting('move.from');
    dst text := current_setting('move.to');
    bad text;
BEGIN
    IF current_setting('move.limit') !~ '^[0-9]{1,9}$' THEN
        RAISE EXCEPTION 'limit must be a whole number of at most 9 digits, got %, nothing moved', current_setting('move.limit');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_tablespace WHERE spcname = src) THEN
        RAISE EXCEPTION 'tablespace % does not exist, nothing moved', src;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_tablespace WHERE spcname = dst) THEN
        RAISE EXCEPTION 'tablespace % does not exist, nothing moved', dst;
    END IF;
    IF src = dst THEN
        RAISE EXCEPTION 'from and to are both %, nothing moved', src;
    END IF;
    -- The database's default tablespace needs no grant; any other does.
    IF dst <> (SELECT t.spcname FROM pg_database d JOIN pg_tablespace t ON t.oid = d.dattablespace
               WHERE d.datname = current_database())
       AND NOT has_tablespace_privilege(current_user, dst, 'CREATE') THEN
        RAISE EXCEPTION '% has no CREATE privilege on tablespace %, nothing moved', current_user, dst;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_partitioned_table p
                   JOIN pg_attribute a ON a.attrelid = p.partrelid AND a.attnum = p.partattrs[0]
                   WHERE p.partrelid = 'public.prices'::regclass AND a.attname = 'ban_id') THEN
        RAISE EXCEPTION 'prices is not partitioned by ban_id, nothing moved';
    END IF;
    IF to_regclass('public.prices_old') IS NOT NULL THEN
        RAISE EXCEPTION 'prices_old still exists, run 09_drop_old.sql first: the target needs its room, nothing moved';
    END IF;
    SELECT string_agg(n, ' ' ORDER BY n) INTO bad
    FROM unnest(ARRAY['prices_uk', 'prices_provider_date']) n
    WHERE NOT EXISTS (SELECT 1 FROM pg_index
                      WHERE indexrelid = to_regclass('public.' || n) AND indisvalid);
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION 'a parent index of prices is missing or not valid, nothing moved: %', bad;
    END IF;
END $$;

-- The family: prices, its partitions and every index of either. A relation
-- stored with reltablespace 0 sits on the database's default tablespace.
CREATE TEMP VIEW move_family AS
WITH tabs AS (
    SELECT 'public.prices'::regclass::oid AS tbl, false AS part
    UNION ALL
    SELECT inhrelid, true FROM pg_inherits WHERE inhparent = 'public.prices'::regclass
)
SELECT t.tbl, t.part, c.oid, c.relname, 'table' AS kind, 1 AS seq,
       coalesce(nullif(c.reltablespace, 0), d.dattablespace) AS spc
FROM tabs t
JOIN pg_class c ON c.oid = t.tbl
CROSS JOIN (SELECT dattablespace FROM pg_database WHERE datname = current_database()) d
UNION ALL
SELECT t.tbl, t.part, c.oid, c.relname, 'index',
       1 + row_number() OVER (PARTITION BY t.tbl ORDER BY i.indisunique DESC, c.relname)::int,
       coalesce(nullif(c.reltablespace, 0), d.dattablespace)
FROM tabs t
JOIN pg_index i ON i.indrelid = t.tbl
JOIN pg_class c ON c.oid = i.indexrelid
CROSS JOIN (SELECT dattablespace FROM pg_database WHERE datname = current_database()) d;

-- Unit 0 is the parent and its indexes; partitions follow by bytes still on from.
-- pg_table_size counts every fork (main, fsm, vm, TOAST), for an index as for a table.
CREATE TEMP TABLE move_plan AS
WITH on_from AS (
    SELECT f.*, pg_table_size(f.oid) AS bytes
    FROM move_family f
    WHERE f.spc = (SELECT oid FROM pg_tablespace WHERE spcname = current_setting('move.from'))
), units AS (
    SELECT o.tbl, o.part, c.relname AS unit_name, sum(o.bytes) AS unit_bytes
    FROM on_from o JOIN pg_class c ON c.oid = o.tbl
    GROUP BY o.tbl, o.part, c.relname
), numbered AS (
    SELECT tbl, unit_name,
           CASE WHEN part THEN row_number() OVER (PARTITION BY part ORDER BY unit_bytes, unit_name)::int
                ELSE 0 END AS unit
    FROM units
)
SELECT n.unit, n.unit_name, o.seq, o.relname::text AS relname, o.kind, o.bytes
FROM on_from o JOIN numbered n ON n.tbl = o.tbl;

SELECT unit, unit_name, relname, kind, pg_size_pretty(bytes) AS size
FROM move_plan ORDER BY unit, seq;
SELECT count(*) AS relations, pg_size_pretty(coalesce(sum(bytes), 0)) AS total,
       count(DISTINCT unit) FILTER (WHERE unit > 0) AS partitions,
       CASE WHEN current_setting('move.limit')::int = 0 THEN count(DISTINCT unit) FILTER (WHERE unit > 0)
            ELSE least(current_setting('move.limit')::int, count(DISTINCT unit) FILTER (WHERE unit > 0)) END AS this_run
FROM move_plan;
-- Strays: relations placed on from that are not of prices, which keep it from being dropped.
-- It compares the stored reltablespace on purpose (0 on the default): empty for from=pg_default, exact for fast.
SELECT c.relname AS stray, c.relkind
FROM pg_class c
WHERE c.reltablespace = (SELECT oid FROM pg_tablespace WHERE spcname = current_setting('move.from'))
  AND c.oid NOT IN (SELECT oid FROM move_family)
ORDER BY c.relname;

\if :apply_on
\timing on
SELECT s FROM (
    SELECT unit, seq, 1 AS k, format('SELECT %L AS moving', relname || ' (' || pg_size_pretty(bytes) || ')') AS s FROM move_plan
    UNION ALL
    SELECT unit, seq, 2, format('ALTER %s public.%I SET TABLESPACE %I', CASE kind WHEN 'table' THEN 'TABLE' ELSE 'INDEX' END, relname, current_setting('move.to')) FROM move_plan
) q
WHERE current_setting('move.limit')::int = 0 OR unit <= current_setting('move.limit')::int
ORDER BY unit, seq, k
\gexec
\timing off
\endif

SELECT count(*) AS left_on_from, pg_size_pretty(coalesce(sum(pg_table_size(oid)), 0)) AS size
FROM move_family
WHERE spc = (SELECT oid FROM pg_tablespace WHERE spcname = current_setting('move.from'));
SELECT c.relname, coalesce(t.spcname, 'pg_default') AS tablespace
FROM pg_class c LEFT JOIN pg_tablespace t ON t.oid = c.reltablespace
WHERE c.oid IN ('public.prices'::regclass, 'public.prices_uk'::regclass, 'public.prices_provider_date'::regclass)
ORDER BY c.relname;
SELECT c.relname AS parent_index, i.indisvalid
FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
WHERE c.oid IN ('public.prices_uk'::regclass, 'public.prices_provider_date'::regclass)
ORDER BY c.relname;
SELECT c.relname AS stray, c.relkind
FROM pg_class c
WHERE c.reltablespace = (SELECT oid FROM pg_tablespace WHERE spcname = current_setting('move.from'))
  AND c.oid NOT IN (SELECT oid FROM move_family)
ORDER BY c.relname;
-- Lists this database too while its empty directory remains under from, until DROP TABLESPACE.
SELECT d.datname AS databases_using_from
FROM pg_tablespace_databases((SELECT oid FROM pg_tablespace WHERE spcname = current_setting('move.from'))) t(oid)
JOIN pg_database d ON d.oid = t.oid
ORDER BY d.datname;

\if :apply_on
\echo moved what the plan listed up to limit; rerun to see what is left
\else
\echo dry run: moved nothing, pass -v apply=1 to move
\endif
