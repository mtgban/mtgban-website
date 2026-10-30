-- Copy the rows of one prices table into another since a date, in the price
-- archive (the sql_config database): the rows written to the old table
-- while 03_copy.sql ran, and again at the swap. See README.md. Run from this
-- directory after 04_indexes.sql, with no backfill and no repair running
-- meanwhile; nothing is kept unless apply=1:
--
--   psql -v src=prices -v dst=prices_v2 -v since=2026-10-29 -f 05_catchup.sql
--   psql -v src=prices -v dst=prices_v2 -v since=2026-10-29 -v apply=1 -f 05_catchup.sql
--
-- src, dst and since (YYYY-MM-DD) are all required. A row of src dated on or
-- after since is inserted into dst, or updates dst's price when the key
-- (ban_id, date, provider) is there with another one; an equal row is left
-- alone, so a second run changes 0 rows. The report gives that count and,
-- per provider, the latest date and the row count since that date in both
-- tables, and whether dst covers src (as many rows, as late a day); a dry
-- run shows them as the apply would leave them, then rolls back.
-- Raises when an argument is missing, when src or dst is not a table, and
-- when since is not a date.

\set ON_ERROR_STOP on
-- Command tags stay out of the output; the report SELECTs still print.
\set QUIET on
SET client_min_messages = warning;
\if :{?apply}
\else
\set apply 0
\endif
\if :{?src}
\else
\set src ''
\endif
\if :{?dst}
\else
\set dst ''
\endif
\if :{?since}
\else
\set since ''
\endif

-- apply is normalised once; any value but 0 or 1 is refused.
SELECT :'apply' IN ('0', '1') AS apply_valid, :'apply' = '1' AS apply_on \gset
\if :apply_valid
\else
\echo apply must be 0 or 1, got :apply
DO $$ BEGIN RAISE EXCEPTION 'apply must be 0 or 1, nothing changed'; END $$;
\endif

-- The arguments are checked once, before anything is read.
SELECT :'src' <> '' AND :'dst' <> '' AND :'since' <> '' AS args_given,
       coalesce(pg_input_is_valid(nullif(:'since', ''), 'date') AND :'since' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$', false) AS since_shaped,
       coalesce((SELECT relkind IN ('r', 'p') FROM pg_class WHERE oid = to_regclass(nullif(:'src', ''))), false) AS src_table,
       coalesce((SELECT relkind IN ('r', 'p') FROM pg_class WHERE oid = to_regclass(nullif(:'dst', ''))), false) AS dst_table \gset
\if :args_given
\else
\echo src, dst and since are all required
DO $$ BEGIN RAISE EXCEPTION 'src, dst and since are all required, nothing changed'; END $$;
\endif
\if :src_table
\else
\echo src is not a table: :src
DO $$ BEGIN RAISE EXCEPTION 'src is not a table, nothing changed'; END $$;
\endif
\if :dst_table
\else
\echo dst is not a table: :dst
DO $$ BEGIN RAISE EXCEPTION 'dst is not a table, nothing changed'; END $$;
\endif
\if :since_shaped
\else
\echo since must be a date, got :since
DO $$ BEGIN RAISE EXCEPTION 'since must be a date, nothing changed'; END $$;
\endif

BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '2h';

-- The names reach the DO block as settings, since a $$ body takes no psql variable.
SELECT set_config('catchup.src', to_regclass(:'src')::text, true),
       set_config('catchup.dst', to_regclass(:'dst')::text, true),
       set_config('catchup.since', (:'since')::date::text, true) \gset
DO $$
DECLARE
    s  text := current_setting('catchup.src');
    d  text := current_setting('catchup.dst');
    sd date := current_setting('catchup.since')::date;
    n  bigint;
BEGIN
    EXECUTE format(
        'WITH up AS (INSERT INTO %s AS d (ban_id, date, provider, price) '
        'SELECT ban_id, date, provider, price FROM %s WHERE date >= %L '
        'ON CONFLICT (ban_id, date, provider) DO UPDATE SET price = EXCLUDED.price '
        'WHERE d.price IS DISTINCT FROM EXCLUDED.price RETURNING 1) '
        'SELECT count(*) FROM up', d, s, sd) INTO n;
    PERFORM set_config('catchup.changed', n::text, true);
    EXECUTE format(
        'CREATE TEMP TABLE catchup_report ON COMMIT DROP AS '
        'SELECT coalesce(a.provider, b.provider) AS provider, '
        'a.last_date AS src_last, a.n AS src_rows, b.last_date AS dst_last, b.n AS dst_rows '
        'FROM (SELECT provider, max(date) AS last_date, count(*) AS n FROM %s WHERE date >= %L GROUP BY 1) a '
        'FULL JOIN (SELECT provider, max(date) AS last_date, count(*) AS n FROM %s WHERE date >= %L GROUP BY 1) b '
        'ON a.provider = b.provider', s, sd, d, sd);
END $$;

SELECT current_setting('catchup.changed')::bigint AS rows_inserted_or_changed;
-- Before the swap dst may hold more (prices_v2 rows src lost meanwhile); after it,
-- with the writers held, dst holds exactly src and the run changes 0 rows.
SELECT provider, src_last, src_rows, dst_last, dst_rows,
       coalesce(dst_rows >= src_rows AND dst_last >= src_last, src_rows IS NULL) AS dst_covers_src
FROM catchup_report ORDER BY provider;

\if :apply_on
COMMIT;
\echo committed
\else
ROLLBACK;
\echo dry run: rolled back, pass -v apply=1 to commit
\endif
