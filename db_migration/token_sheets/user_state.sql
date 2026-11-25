-- Re-key the two-sided token sheets in the user_state_config database
-- (alerts, user_state, upload_shares) from "<face a>_tp_<face b>" to the
-- uuid go-mtgban gives a sheet: the version 5 uuid of face b in face a's
-- namespace. See README.md. Nothing is kept unless apply=1:
--
--   psql -f user_state.sql              report and roll back
--   psql -v apply=1 -f user_state.sql   commit
--
-- Re-running is safe: an id already re-keyed matches nothing here.

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

-- uuid_generate_v5 comes from uuid-ossp, which is dropped again below
-- where this run is what installed it.
SELECT NOT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'uuid-ossp') AS own_extension \gset
\if :own_extension
CREATE EXTENSION "uuid-ossp";
\endif

-- Every sheet id stored anywhere, without its finish suffix, which stays
-- where it is: "<a>_tp_<b>_f" becomes "<uuid>_f".
CREATE TEMP TABLE id_map (old_id text PRIMARY KEY, new_id text NOT NULL) ON COMMIT DROP;
INSERT INTO id_map
SELECT DISTINCT m[1] || '_tp_' || m[2], uuid_generate_v5(m[1]::uuid, m[2])::text
FROM (SELECT card_id AS t FROM alerts WHERE card_id LIKE '%\_tp\_%'
      UNION ALL
      SELECT favorites::text || recents::text || backpack::text FROM user_state
      WHERE favorites::text LIKE '%\_tp\_%' OR recents::text LIKE '%\_tp\_%' OR backpack::text LIKE '%\_tp\_%'
      UNION ALL
      SELECT rows FROM upload_shares WHERE rows LIKE '%\_tp\_%') stored,
     regexp_matches(stored.t, '([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})_tp_([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})', 'g') m;

CREATE FUNCTION pg_temp.rekey(t text) RETURNS text LANGUAGE plpgsql AS $$
DECLARE
    r record;
BEGIN
    FOR r IN SELECT old_id, new_id FROM id_map LOOP
        t := replace(t, r.old_id, r.new_id);
    END LOOP;
    RETURN t;
END $$;

-- alerts: an alert the new build already found unresolvable is active again.
CREATE TEMP TABLE alert_moves ON COMMIT DROP AS
SELECT id, pg_temp.rekey(card_id) AS new_id FROM alerts WHERE card_id LIKE '%\_tp\_%';
DELETE FROM alert_moves am USING alerts a WHERE a.id = am.id AND a.card_id = am.new_id;
UPDATE alerts a SET card_id = am.new_id, updated_at = now(),
    status = CASE WHEN a.status = 'unresolvable' AND a.last_error = 'card no longer in the datastore'
                  THEN 'active' ELSE a.status END,
    last_error = CASE WHEN a.status = 'unresolvable' AND a.last_error = 'card no longer in the datastore'
                      THEN '' ELSE a.last_error END
FROM alert_moves am WHERE a.id = am.id;

-- user_state and upload_shares hold ids inside text the server does not
-- parse.
CREATE TEMP TABLE state_moves ON COMMIT DROP AS
SELECT email_hash,
       pg_temp.rekey(favorites::text) AS favorites,
       pg_temp.rekey(recents::text) AS recents,
       pg_temp.rekey(backpack::text) AS backpack
FROM user_state
WHERE favorites::text LIKE '%\_tp\_%' OR recents::text LIKE '%\_tp\_%' OR backpack::text LIKE '%\_tp\_%';
DELETE FROM state_moves s USING user_state u
WHERE s.email_hash = u.email_hash AND s.favorites = u.favorites::text
  AND s.recents = u.recents::text AND s.backpack = u.backpack::text;
-- A client holding the old version re-reads instead of writing old ids back.
UPDATE user_state u SET favorites = s.favorites::jsonb, recents = s.recents::jsonb,
    backpack = s.backpack::jsonb, version = u.version + 1, updated_at = now()
FROM state_moves s WHERE u.email_hash = s.email_hash;

CREATE TEMP TABLE share_moves ON COMMIT DROP AS
SELECT share_key, pg_temp.rekey(rows) AS rows FROM upload_shares WHERE rows LIKE '%\_tp\_%';
DELETE FROM share_moves s USING upload_shares u WHERE s.share_key = u.share_key AND s.rows = u.rows;
UPDATE upload_shares u SET rows = s.rows FROM share_moves s WHERE u.share_key = s.share_key;

SELECT 'sheets found' AS step, count(*) AS count FROM id_map
UNION ALL SELECT 'alerts re-keyed', count(*) FROM alert_moves
UNION ALL SELECT 'user_state rows rewritten', count(*) FROM state_moves
UNION ALL SELECT 'upload_shares rows rewritten', count(*) FROM share_moves;

\if :own_extension
DROP EXTENSION "uuid-ossp";
\endif

\if :apply_on
COMMIT;
\echo committed
\else
ROLLBACK;
\echo dry run: rolled back, pass -v apply=1 to commit
\endif
