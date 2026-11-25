-- Give each two-sided token sheet's variants row the mtgban_id the
-- datastore's map files its alias under, where the row still holds a
-- "<face a>_tp_<face b>" id. Runs against the price archive (the sql_config
-- database) with variant_map.tsv beside it; see README.md. Nothing is kept
-- unless apply=1:
--
--   psql -f ids.sql              report and roll back
--   psql -v apply=1 -f ids.sql   commit
--
-- Re-running is safe: a row already holding its map id matches nothing.

\set ON_ERROR_STOP on
\set QUIET on
\if :{?apply}
\else
\set apply 0
\endif

SELECT :'apply' IN ('0', '1') AS apply_valid, :'apply' = '1' AS apply_on \gset
\if :apply_valid
\else
\echo apply must be 0 or 1, got :apply
DO $$ BEGIN RAISE EXCEPTION 'apply must be 0 or 1, nothing changed'; END $$;
\endif

BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

-- The admin export GET /admin?download=variantmap; language is empty for
-- English, which csv would read as NULL without FORCE_NOT_NULL.
CREATE TEMP TABLE variant_map (
    mtgjson_uuid uuid,
    is_foil      boolean,
    is_etched    boolean,
    is_alt       boolean,
    language     text,
    mtgban_id    text
) ON COMMIT DROP;
\copy variant_map FROM 'variant_map.tsv' WITH (FORMAT csv, DELIMITER E'\t', HEADER true, FORCE_NOT_NULL (language))

CREATE TEMP TABLE moves ON COMMIT DROP AS
SELECT v.ban_id, v.mtgban_id AS old_id, m.mtgban_id AS new_id
FROM variants v
JOIN variant_map m ON m.mtgjson_uuid = v.mtgjson_uuid AND m.is_foil = v.is_foil
    AND m.is_etched = v.is_etched AND m.is_alt = v.is_alt AND m.language = v.language
WHERE v.mtgban_id LIKE '%\_tp\_%' AND v.mtgban_id <> m.mtgban_id;

DO $$
DECLARE
    bad text;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM variant_map) THEN
        RAISE EXCEPTION 'variant_map.tsv holds no rows, nothing changed';
    END IF;
    IF EXISTS (SELECT 1 FROM variant_map WHERE mtgban_id LIKE '%\_tp\_%') THEN
        RAISE EXCEPTION 'variant_map.tsv still lists a _tp_ id, so it comes from an older build; nothing changed';
    END IF;

    -- Another row already holds the id a row would take.
    SELECT string_agg(mv.old_id || ' -> ' || mv.new_id || ' on ban_id ' || v.ban_id, '; ' ORDER BY mv.ban_id)
    INTO bad
    FROM moves mv
    JOIN variants v ON v.mtgban_id = mv.new_id
    WHERE v.ban_id <> mv.ban_id;
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION 'the map id is held by another row, nothing changed: %', bad;
    END IF;
END $$;

SELECT count(*) AS to_move,
       (SELECT count(*) FROM variants v
        WHERE v.mtgban_id LIKE '%\_tp\_%'
          AND NOT EXISTS (SELECT 1 FROM moves mv WHERE mv.ban_id = v.ban_id)) AS unmatched
FROM moves;

-- Sheets the map lacks keep their id and are still read by ban:<n>.
SELECT v.ban_id, v.mtgban_id, v.mtgjson_uuid
FROM variants v
WHERE v.mtgban_id LIKE '%\_tp\_%'
  AND NOT EXISTS (SELECT 1 FROM moves mv WHERE mv.ban_id = v.ban_id)
ORDER BY v.ban_id LIMIT 50;

UPDATE variants v SET mtgban_id = mv.new_id
FROM moves mv
WHERE v.ban_id = mv.ban_id;
\echo moved: :ROW_COUNT

SELECT count(*) AS still_tp FROM variants WHERE mtgban_id LIKE '%\_tp\_%';

\if :apply_on
COMMIT;
\echo committed
\else
ROLLBACK;
\echo dry run: rolled back, pass -v apply=1 to commit
\endif
