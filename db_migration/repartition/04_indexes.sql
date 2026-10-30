-- Index prices_v2 in the price archive (the sql_config database) once
-- 03_copy.sql has copied every month. See README.md. Run from this directory,
-- with no backfill and no repair running meanwhile:
--
--   psql -f 04_indexes.sql
--   psql -v tablespace=fast -f 04_indexes.sql    the indexes on a tablespace
--
-- It runs outside a transaction block on purpose: every index build and
-- attach is its own statement and commits alone, so a killed run resumes at
-- the partitions still lacking an index or not yet attached to the parent
-- one. It takes no apply: it only indexes prices_v2, which nothing reads yet.
-- The parent indexes are created ON ONLY and stay invalid until every
-- partition is attached. The foreign keys are added NOT VALID, as on prices.
-- An index lands in the default tablespace, not its table's, so pass the
-- tablespace given to 02_create.sql again here. It ends with VACUUM
-- (FREEZE, ANALYZE): a fresh table has no visibility map, so without it
-- index-only scans read the heap and the gate measures that. FREEZE costs
-- nothing a reader sees, since nothing reads prices_v2 yet, and spares the
-- copied rows a later anti-wraparound vacuum of the whole table.
-- Raises before the vacuum when a parent index is not valid.
-- Re-running is safe: what exists is left alone, a second run lists nothing.

\set ON_ERROR_STOP on
-- Command tags stay out of the output; the report SELECTs still print.
\set QUIET on
SET client_min_messages = warning;
SET maintenance_work_mem = '768MB';
SET max_parallel_maintenance_workers = 2;
SET statement_timeout = 0;
\if :{?tablespace}
\else
\set tablespace ''
\endif
-- The tablespace clause is built once, quoted, empty when none is given.
SELECT CASE WHEN :'tablespace' <> '' THEN format(' TABLESPACE %I', :'tablespace') ELSE '' END AS ts_clause \gset

CREATE UNIQUE INDEX IF NOT EXISTS prices_v2_uk
    ON ONLY public.prices_v2 (ban_id, date, provider) INCLUDE (price) :ts_clause;
CREATE INDEX IF NOT EXISTS prices_v2_provider_date
    ON ONLY public.prices_v2 (provider, date) INCLUDE (ban_id, price) :ts_clause;

-- Per partition and index: build it if missing, attach it unless attached.
SELECT s.stmt
FROM pg_inherits i
JOIN pg_class c ON c.oid = i.inhrelid
CROSS JOIN LATERAL (VALUES
    ('uk', 'prices_v2_uk', 'UNIQUE ', '(ban_id, date, provider) INCLUDE (price)'),
    ('provider_date', 'prices_v2_provider_date', '', '(provider, date) INCLUDE (ban_id, price)')
) k(suffix, parent_idx, uniq, cols)
CROSS JOIN LATERAL (VALUES
    (1, format('CREATE %sINDEX IF NOT EXISTS %I ON public.%I %s%s',
               k.uniq, c.relname || '_' || k.suffix, c.relname, k.cols, :'ts_clause')),
    (2, format('ALTER INDEX public.%I ATTACH PARTITION public.%I',
               k.parent_idx, c.relname || '_' || k.suffix))
) s(step, stmt)
WHERE i.inhparent = 'public.prices_v2'::regclass
  -- Any index of this partition attached to the parent, whatever its name (a
  -- partition created after the attach gets one named by Postgres).
  AND NOT EXISTS (SELECT 1 FROM pg_inherits ai
                  JOIN pg_index pi ON pi.indexrelid = ai.inhrelid
                  WHERE pi.indrelid = c.oid
                    AND ai.inhparent = format('public.%I', k.parent_idx)::regclass)
ORDER BY c.relname, k.suffix, s.step
\gexec

-- The foreign keys lock variants and providers; give up rather than queue behind a long transaction.
SET lock_timeout = '5s';
SELECT NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid = 'public.prices_v2'::regclass AND conname = 'prices_v2_ban_id_fk') AS add_ban_id_fk,
       NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid = 'public.prices_v2'::regclass AND conname = 'prices_v2_provider_fk') AS add_provider_fk
\gset
\if :add_ban_id_fk
ALTER TABLE public.prices_v2 ADD CONSTRAINT prices_v2_ban_id_fk
    FOREIGN KEY (ban_id) REFERENCES public.variants(ban_id) NOT VALID;
\endif
\if :add_provider_fk
ALTER TABLE public.prices_v2 ADD CONSTRAINT prices_v2_provider_fk
    FOREIGN KEY (provider) REFERENCES public.providers(id) NOT VALID;
\endif

SELECT c.relname AS parent_index, i.indisvalid
FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
WHERE c.oid IN ('public.prices_v2_uk'::regclass, 'public.prices_v2_provider_date'::regclass)
ORDER BY c.relname;
SELECT conname, convalidated FROM pg_constraint
WHERE conrelid = 'public.prices_v2'::regclass AND contype = 'f' ORDER BY conname;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_index
               WHERE indexrelid IN ('public.prices_v2_uk'::regclass, 'public.prices_v2_provider_date'::regclass)
                 AND NOT indisvalid) THEN
        RAISE EXCEPTION 'a parent index of prices_v2 is not valid, a partition is not attached';
    END IF;
END $$;

-- Only a fully attached table is worth the vacuum, which takes hours on production.
VACUUM (FREEZE, ANALYZE) public.prices_v2;
\echo prices_v2 indexed, vacuumed, frozen and analyzed
