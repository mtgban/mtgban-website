-- Re-key the Japanese and Italian language copies to the uuids go-mtgban now
-- gives them (mtgjson's foreignData uuid). See README.md. Run from this
-- directory; nothing is kept unless apply=1:
--
--   psql -v apply=0 -f migrate.sql    report and roll back
--   psql -v apply=1 -f migrate.sql    commit
--
-- Re-running is safe: a row already on its new id matches nothing here.

\set ON_ERROR_STOP on
\if :{?apply}
\else
\set apply 0
\endif

BEGIN;

CREATE TEMP TABLE id_map (old_id text PRIMARY KEY, new_id text NOT NULL UNIQUE) ON COMMIT DROP;
\copy id_map FROM 'id_map.tsv'

-- The price tables store the first 36 characters and the language apart.
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

INSERT INTO prices (ban_id, date, provider, price)
SELECT mv.new_ban, p.date, p.provider, p.price
FROM prices p JOIN variant_moves mv ON p.ban_id = mv.old_ban
WHERE mv.new_ban IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM prices q
                  WHERE q.ban_id = mv.new_ban AND q.date = p.date AND q.provider = p.provider);
DELETE FROM prices p USING variant_moves mv WHERE p.ban_id = mv.old_ban AND mv.new_ban IS NOT NULL;
DELETE FROM variants v USING variant_moves mv WHERE v.ban_id = mv.old_ban AND mv.new_ban IS NOT NULL;

-- product_prices, the wide table: a day the new id already has keeps it.
CREATE TEMP TABLE wide_counts (moved bigint, dropped bigint) ON COMMIT DROP;
WITH moved AS (
    UPDATE product_prices p SET mtgjson_uuid = m.new_uuid
    FROM uuid_map m
    WHERE p.mtgjson_uuid = m.old_uuid AND p.language = m.language
      AND NOT EXISTS (SELECT 1 FROM product_prices q
                      WHERE q.date = p.date AND q.mtgjson_uuid = m.new_uuid AND q.is_foil = p.is_foil
                        AND q.is_etched = p.is_etched AND q.language = p.language AND q.is_alt = p.is_alt)
    RETURNING 1
)
INSERT INTO wide_counts (moved) SELECT count(*) FROM moved;
WITH dropped AS (
    DELETE FROM product_prices p USING uuid_map m
    WHERE p.mtgjson_uuid = m.old_uuid AND p.language = m.language
    RETURNING 1
)
UPDATE wide_counts SET dropped = (SELECT count(*) FROM dropped);

-- alerts: an alert the new build already found unresolvable is active again.
CREATE TEMP TABLE alert_moves ON COMMIT DROP AS
SELECT a.id, m.new_id FROM alerts a JOIN id_map m ON a.card_id = m.old_id;
UPDATE alerts a SET card_id = am.new_id, updated_at = now(),
    status = CASE WHEN a.status = 'unresolvable' AND a.last_error = 'card no longer in the datastore'
                  THEN 'active' ELSE a.status END,
    last_error = CASE WHEN a.status = 'unresolvable' AND a.last_error = 'card no longer in the datastore'
                      THEN '' ELSE a.last_error END
FROM alert_moves am WHERE a.id = am.id;

-- user_state and upload_shares hold ids inside text the server does not
-- parse; an id is replaced only whole, since one can prefix another.
CREATE FUNCTION pg_temp.rekey(t text) RETURNS text LANGUAGE plpgsql AS $$
DECLARE
    r record;
BEGIN
    FOR r IN SELECT old_id, new_id FROM id_map LOOP
        IF strpos(t, r.old_id) > 0 THEN
            t := regexp_replace(t, '(?<![-_0-9A-Za-z])' || r.old_id || '(?![-_0-9A-Za-z])', r.new_id, 'g');
        END IF;
    END LOOP;
    RETURN t;
END $$;

CREATE TEMP TABLE state_moves ON COMMIT DROP AS
SELECT email_hash,
       pg_temp.rekey(favorites::text) AS favorites,
       pg_temp.rekey(recents::text) AS recents,
       pg_temp.rekey(backpack::text) AS backpack
FROM user_state
WHERE favorites::text ~ '_(jpn|ita)' OR recents::text ~ '_(jpn|ita)' OR backpack::text ~ '_(jpn|ita)';
DELETE FROM state_moves s USING user_state u
WHERE s.email_hash = u.email_hash AND s.favorites = u.favorites::text
  AND s.recents = u.recents::text AND s.backpack = u.backpack::text;
-- A client holding the old version re-reads instead of writing old ids back.
UPDATE user_state u SET favorites = s.favorites::jsonb, recents = s.recents::jsonb,
    backpack = s.backpack::jsonb, version = u.version + 1, updated_at = now()
FROM state_moves s WHERE u.email_hash = s.email_hash;

CREATE TEMP TABLE share_moves ON COMMIT DROP AS
SELECT share_key, pg_temp.rekey(rows) AS rows FROM upload_shares WHERE rows ~ '_(jpn|ita)';
DELETE FROM share_moves s USING upload_shares u WHERE s.share_key = u.share_key AND s.rows = u.rows;
UPDATE upload_shares u SET rows = s.rows FROM share_moves s WHERE u.share_key = s.share_key;

SELECT 'variants re-keyed' AS step, count(*) FILTER (WHERE new_ban IS NULL) AS count FROM variant_moves
UNION ALL SELECT 'variants merged into an existing id', count(*) FILTER (WHERE new_ban IS NOT NULL) FROM variant_moves
UNION ALL SELECT 'product_prices rows moved', moved FROM wide_counts
UNION ALL SELECT 'product_prices rows dropped (day already on the new id)', dropped FROM wide_counts
UNION ALL SELECT 'alerts re-keyed', count(*) FROM alert_moves
UNION ALL SELECT 'user_state rows rewritten', count(*) FROM state_moves
UNION ALL SELECT 'upload_shares rows rewritten', count(*) FROM share_moves;

\if :apply
COMMIT;
\echo committed
\else
ROLLBACK;
\echo dry run: rolled back, pass -v apply=1 to commit
\endif
