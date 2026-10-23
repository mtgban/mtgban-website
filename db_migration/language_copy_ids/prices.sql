-- Re-key the Japanese and Italian language copies in the price archive (the
-- sql_config database) to the uuids go-mtgban now gives them (mtgjson's
-- foreignData uuid). See README.md. Run from this directory; nothing is kept
-- unless apply=1:
--
--   psql -v apply=0 -f prices.sql    report and roll back
--   psql -v apply=1 -f prices.sql    commit
--
-- Re-running is safe: a row already on its new id matches nothing here.

\set ON_ERROR_STOP on
\if :{?apply}
\else
\set apply 0
\endif

BEGIN;

CREATE TEMP TABLE id_map (old_id text PRIMARY KEY, new_id text NOT NULL UNIQUE) ON COMMIT DROP;
-- The map is b2://mtgban-newspaper/db_migration/language_copy_ids.tsv.
\copy id_map FROM 'language_copy_ids.tsv'

-- variants stores the first 36 characters and the language apart.
CREATE TEMP TABLE uuid_map ON COMMIT DROP AS
SELECT DISTINCT left(old_id, 36)::uuid AS old_uuid,
       CASE WHEN old_id LIKE '%\_jpn%' THEN 'Japanese' ELSE 'Italian' END AS language,
       left(new_id, 36)::uuid AS new_uuid
FROM id_map;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM id_map WHERE old_id NOT LIKE '%\_jpn%' AND old_id NOT LIKE '%\_ita%') THEN
        RAISE EXCEPTION 'id_map holds an id that is not a language copy';
    END IF;
    IF (SELECT count(*) FROM uuid_map) <> (SELECT count(DISTINCT (old_uuid, language)) FROM uuid_map) THEN
        RAISE EXCEPTION 'an old uuid and language map to more than one new uuid';
    END IF;
END $$;

-- variants: a re-keyed identity keeps its ban_id, so its prices follow it.
-- Where the new identity already exists, prices written after the deploy,
-- those stay and the old identity's other days move under it.
CREATE TEMP TABLE variant_moves ON COMMIT DROP AS
SELECT o.ban_id AS old_ban, n.ban_id AS new_ban, m.new_uuid
FROM variants o
JOIN uuid_map m ON o.mtgjson_uuid = m.old_uuid AND o.language = m.language
LEFT JOIN variants n ON n.mtgjson_uuid = m.new_uuid AND n.is_foil = o.is_foil
    AND n.is_etched = o.is_etched AND n.is_alt = o.is_alt AND n.language = o.language;

UPDATE variants v SET mtgjson_uuid = mv.new_uuid
FROM variant_moves mv WHERE v.ban_id = mv.old_ban AND mv.new_ban IS NULL;

CREATE TEMP TABLE price_counts (moved bigint, dropped bigint) ON COMMIT DROP;
WITH moved AS (
    INSERT INTO prices (ban_id, date, provider, price)
    SELECT mv.new_ban, p.date, p.provider, p.price
    FROM prices p JOIN variant_moves mv ON p.ban_id = mv.old_ban
    WHERE mv.new_ban IS NOT NULL
      AND NOT EXISTS (SELECT 1 FROM prices q
                      WHERE q.ban_id = mv.new_ban AND q.date = p.date AND q.provider = p.provider)
    RETURNING 1
)
INSERT INTO price_counts (moved) SELECT count(*) FROM moved;
-- Every old row goes; the ones not moved are the days the new id already had.
WITH gone AS (
    DELETE FROM prices p USING variant_moves mv WHERE p.ban_id = mv.old_ban AND mv.new_ban IS NOT NULL
    RETURNING 1
)
UPDATE price_counts SET dropped = (SELECT count(*) FROM gone) - moved;
DELETE FROM variants v USING variant_moves mv WHERE v.ban_id = mv.old_ban AND mv.new_ban IS NOT NULL;

SELECT 'variants re-keyed' AS step, count(*) FILTER (WHERE new_ban IS NULL) AS count FROM variant_moves
UNION ALL SELECT 'variants merged into an existing id', count(*) FILTER (WHERE new_ban IS NOT NULL) FROM variant_moves
UNION ALL SELECT 'prices moved under the new id', moved FROM price_counts
UNION ALL SELECT 'prices dropped (day already on the new id)', dropped FROM price_counts;

\if :apply
COMMIT;
\echo committed
\else
ROLLBACK;
\echo dry run: rolled back, pass -v apply=1 to commit
\endif
