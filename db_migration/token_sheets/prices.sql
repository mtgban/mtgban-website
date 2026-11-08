-- Give each variants row the alias the datastore's map files its mtgban_id
-- under, where the map names another uuid: the two-sided token sheets that
-- took one face's alias. Runs against the price archive (the sql_config database)
-- with variant_map.tsv beside it; see README.md. Nothing is kept unless
-- apply=1:
--
--   psql -f prices.sql              report and roll back
--   psql -v apply=1 -f prices.sql   commit
--
-- Re-running is safe: a row already on its map alias matches nothing.

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
SELECT v.ban_id, v.mtgban_id,
       v.mtgjson_uuid AS old_uuid, m.mtgjson_uuid, m.is_foil, m.is_etched, m.is_alt, m.language
FROM variants v
JOIN variant_map m USING (mtgban_id)
WHERE v.mtgjson_uuid <> m.mtgjson_uuid;

DO $$
DECLARE
    bad text;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM variant_map WHERE mtgban_id LIKE '%\_tp\_%') THEN
        RAISE EXCEPTION 'variant_map.tsv lists no token sheet, so it predates them; nothing changed';
    END IF;

    -- Another row already holds the alias a row would move to.
    SELECT string_agg(mv.mtgban_id || ' -> ban_id ' || v.ban_id, '; ' ORDER BY mv.ban_id) INTO bad
    FROM moves mv
    JOIN variants v ON v.mtgjson_uuid = mv.mtgjson_uuid AND v.is_foil = mv.is_foil
        AND v.is_etched = mv.is_etched AND v.is_alt = mv.is_alt AND v.language = mv.language
    WHERE v.ban_id <> mv.ban_id;
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION 'the map alias is held by another row, nothing changed: %', bad;
    END IF;
END $$;

SELECT ban_id, mtgban_id, old_uuid, mtgjson_uuid AS new_uuid,
       (SELECT count(*) FROM prices p WHERE p.ban_id = mv.ban_id) AS prices
FROM moves mv ORDER BY ban_id;

UPDATE variants v
SET mtgjson_uuid = mv.mtgjson_uuid, is_foil = mv.is_foil, is_etched = mv.is_etched,
    is_alt = mv.is_alt, language = mv.language
FROM moves mv
WHERE v.ban_id = mv.ban_id;
\echo moved: :ROW_COUNT

\if :apply_on
COMMIT;
\echo committed
\else
ROLLBACK;
\echo dry run: rolled back, pass -v apply=1 to commit
\endif
