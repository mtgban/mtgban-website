-- Re-key the Japanese and Italian language copies in the user_state_config
-- database (alerts, user_state, upload_shares) to the ids go-mtgban now gives
-- them (mtgjson's foreignData uuid). See README.md. Run from this directory;
-- nothing is kept unless apply=1:
--
--   psql -v apply=0 -f user_state.sql    report and roll back
--   psql -v apply=1 -f user_state.sql    commit
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

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM id_map WHERE old_id NOT LIKE '%\_jpn%' AND old_id NOT LIKE '%\_ita%') THEN
        RAISE EXCEPTION 'id_map holds an id that is not a language copy';
    END IF;
END $$;

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

SELECT 'alerts re-keyed' AS step, count(*) AS count FROM alert_moves
UNION ALL SELECT 'user_state rows rewritten', count(*) FROM state_moves
UNION ALL SELECT 'upload_shares rows rewritten', count(*) FROM share_moves;

\if :apply
COMMIT;
\echo committed
\else
ROLLBACK;
\echo dry run: rolled back, pass -v apply=1 to commit
\endif
