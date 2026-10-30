-- Fill variants.mtgban_id for the Magic rows of the price archive (the
-- sql_config database) from the datastore's map, variant_map.tsv. See
-- README.md. Run from this directory with the TSV beside the script; nothing
-- is kept unless apply=1:
--
--   psql -v apply=0 -f 02_backfill.sql    report and roll back
--   psql -v apply=1 -f 02_backfill.sql    commit
--
-- More than 5000 unmatched rows raises unless -v force=1 is given.
-- Not yet run on production.
-- Re-running is safe: a row already holding its id matches nothing to set.

\set ON_ERROR_STOP on
-- Command tags stay out of the output; the report SELECTs still print.
\set QUIET on
\if :{?apply}
\else
\set apply 0
\endif
\if :{?force}
\else
\set force 0
\endif

-- apply and force are normalised once; any value but 0 or 1 is refused.
SELECT :'apply' IN ('0', '1') AS apply_valid, :'apply' = '1' AS apply_on,
       :'force' IN ('0', '1') AS force_valid, :'force' = '1' AS force_on \gset
\if :apply_valid
\else
\echo apply must be 0 or 1, got :apply
DO $$ BEGIN RAISE EXCEPTION 'apply must be 0 or 1, nothing changed'; END $$;
\endif
\if :force_valid
\else
\echo force must be 0 or 1, got :force
DO $$ BEGIN RAISE EXCEPTION 'force must be 0 or 1, nothing changed'; END $$;
\endif

BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '15min';

-- The map is the admin export GET /admin?download=variantmap; language is
-- empty for English, which csv would read as NULL without FORCE_NOT_NULL.
CREATE TEMP TABLE variant_map (
    mtgjson_uuid uuid,
    is_foil      boolean,
    is_etched    boolean,
    is_alt       boolean,
    language     text,
    mtgban_id    text
) ON COMMIT DROP;
\copy variant_map FROM 'variant_map.tsv' WITH (FORMAT csv, DELIMITER E'\t', HEADER true, FORCE_NOT_NULL (language))

DO $$
DECLARE
    bad text;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM variant_map) THEN
        RAISE EXCEPTION 'variant_map.tsv holds no rows, nothing changed';
    END IF;
    IF EXISTS (SELECT 1 FROM variant_map
               WHERE mtgjson_uuid IS NULL OR is_foil IS NULL OR is_etched IS NULL
                  OR is_alt IS NULL OR language IS NULL OR mtgban_id IS NULL OR mtgban_id = '') THEN
        RAISE EXCEPTION 'variant_map.tsv holds a row with an empty column, nothing changed';
    END IF;

    SELECT string_agg(mtgban_id, ' ' ORDER BY mtgban_id) INTO bad
    FROM (SELECT mtgban_id FROM variant_map GROUP BY mtgban_id HAVING count(*) > 1 LIMIT 20) d;
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION 'mtgban_id appears twice in the map, nothing changed: %', bad;
    END IF;

    SELECT string_agg(mtgjson_uuid || '/' || is_foil || '/' || is_etched || '/' || is_alt || '/' || language,
                      ' ' ORDER BY mtgjson_uuid)
    INTO bad
    FROM (SELECT mtgjson_uuid, is_foil, is_etched, is_alt, language FROM variant_map
          GROUP BY mtgjson_uuid, is_foil, is_etched, is_alt, language HAVING count(*) > 1 LIMIT 20) d;
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION 'an alias key appears twice in the map, nothing changed: %', bad;
    END IF;

    -- A re-spelling: the id is on the table already, under another alias.
    SELECT string_agg(m.mtgban_id || ' stored as ' || v.mtgjson_uuid || '/' || v.is_foil || '/' || v.is_etched
                      || '/' || v.is_alt || '/' || v.language || ' but mapped to ' || m.mtgjson_uuid || '/'
                      || m.is_foil || '/' || m.is_etched || '/' || m.is_alt || '/' || m.language,
                      '; ' ORDER BY m.mtgban_id)
    INTO bad
    FROM variant_map m
    JOIN variants v ON v.mtgban_id = m.mtgban_id
    WHERE (v.mtgjson_uuid, v.is_foil, v.is_etched, v.is_alt, v.language)
          IS DISTINCT FROM (m.mtgjson_uuid, m.is_foil, m.is_etched, m.is_alt, m.language);
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION 'a mapped mtgban_id is stored on another alias, nothing changed: %', bad;
    END IF;

    -- The other way round: the alias holds a different id than the map's.
    SELECT string_agg(v.mtgjson_uuid || '/' || v.is_foil || '/' || v.is_etched || '/' || v.is_alt || '/'
                      || v.language || ' holds ' || v.mtgban_id || ' but the map says ' || m.mtgban_id,
                      '; ' ORDER BY v.ban_id)
    INTO bad
    FROM variant_map m
    JOIN variants v ON v.mtgjson_uuid = m.mtgjson_uuid AND v.is_foil = m.is_foil
        AND v.is_etched = m.is_etched AND v.is_alt = m.is_alt AND v.language = m.language
    WHERE v.mtgban_id IS NOT NULL AND v.mtgban_id <> m.mtgban_id;
    IF bad IS NOT NULL THEN
        RAISE EXCEPTION 'an alias holds another mtgban_id than the map, nothing changed: %', bad;
    END IF;
END $$;

-- Magic rows with no map row: retired printings, expected in the hundreds.
CREATE TEMP TABLE unmatched ON COMMIT DROP AS
SELECT v.ban_id, v.mtgjson_uuid, v.language
FROM variants v
WHERE v.mtgjson_uuid IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM variant_map m
                  WHERE m.mtgjson_uuid = v.mtgjson_uuid AND m.is_foil = v.is_foil
                    AND m.is_etched = v.is_etched AND m.is_alt = v.is_alt AND m.language = v.language);

SELECT count(*) FILTER (WHERE v.mtgban_id IS NULL) AS to_set,
       count(*) FILTER (WHERE v.mtgban_id = m.mtgban_id) AS already_set,
       (SELECT count(*) FROM unmatched) AS unmatched,
       (SELECT count(*) FROM variant_map m2
        WHERE NOT EXISTS (SELECT 1 FROM variants v2
                          WHERE v2.mtgjson_uuid = m2.mtgjson_uuid AND v2.is_foil = m2.is_foil
                            AND v2.is_etched = m2.is_etched AND v2.is_alt = m2.is_alt
                            AND v2.language = m2.language)) AS map_only
FROM variant_map m
JOIN variants v ON v.mtgjson_uuid = m.mtgjson_uuid AND v.is_foil = m.is_foil
    AND v.is_etched = m.is_etched AND v.is_alt = m.is_alt AND v.language = m.language;

SELECT mtgjson_uuid, language, count(*) OVER () AS unmatched_total
FROM unmatched ORDER BY mtgjson_uuid, language LIMIT 50;

-- Retirements are in the hundreds; thousands mean a map from another datastore.
\if :force_on
\else
DO $$
DECLARE
    n bigint;
BEGIN
    SELECT count(*) INTO n FROM unmatched;
    IF n > 5000 THEN
        RAISE EXCEPTION '% Magic rows are not in the map (over 5000), nothing changed; pass -v force=1 if that is right', n;
    END IF;
END $$;
\endif

UPDATE variants v SET mtgban_id = m.mtgban_id
FROM variant_map m
WHERE v.mtgban_id IS NULL
  AND v.mtgjson_uuid = m.mtgjson_uuid AND v.is_foil = m.is_foil
  AND v.is_etched = m.is_etched AND v.is_alt = m.is_alt AND v.language = m.language;
\echo set: :ROW_COUNT

SELECT count(*) AS still_null FROM variants WHERE mtgjson_uuid IS NOT NULL AND mtgban_id IS NULL;

\if :apply_on
COMMIT;
\echo committed
\else
ROLLBACK;
\echo dry run: rolled back, pass -v apply=1 to commit
\endif
