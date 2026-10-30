-- Drop prices_old in the price archive (the sql_config database) once the
-- swapped prices has served the week's soak and a volume snapshot exists.
-- See README.md. Run from this directory, outside every writer's window;
-- nothing is kept unless apply=1:
--
--   psql -f 09_drop_old.sql            check, roll back
--   psql -v apply=1 -f 09_drop_old.sql
--
-- The drop takes prices_old ACCESS EXCLUSIVE with a 5s lock_timeout, then
-- prices is analyzed. Removing its foreign keys' triggers takes variants
-- and providers ACCESS EXCLUSIVE too: it fails while a long variants reader
-- runs, and holds their readers up to the 5s while it waits.
-- Raises when prices is not partitioned by ban_id and when prices_old does
-- not exist, so a second run drops nothing.

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
DO $$ BEGIN RAISE EXCEPTION 'apply must be 0 or 1, nothing dropped'; END $$;
\endif

BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '15min';

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_partitioned_table p
                   JOIN pg_attribute a ON a.attrelid = p.partrelid AND a.attnum = p.partattrs[0]
                   WHERE p.partrelid = 'public.prices'::regclass AND a.attname = 'ban_id') THEN
        RAISE EXCEPTION 'prices is not partitioned by ban_id, run 07_swap.sql first, nothing dropped';
    END IF;
    IF to_regclass('public.prices_old') IS NULL THEN
        RAISE EXCEPTION 'prices_old does not exist, nothing to drop';
    END IF;
END $$;

SELECT count(*) AS prices_old_partitions,
       pg_size_pretty(sum(pg_total_relation_size(i.inhrelid))) AS prices_old_size
FROM pg_inherits i WHERE i.inhparent = 'public.prices_old'::regclass;

\if :apply_on
DROP TABLE public.prices_old;
COMMIT;
\echo dropped prices_old, analyzing prices
SET statement_timeout = '4h';
ANALYZE public.prices;
\echo committed
\else
ROLLBACK;
\echo dry run: rolled back, pass -v apply=1 to commit
\endif
