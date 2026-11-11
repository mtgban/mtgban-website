package observability

import (
	"context"
	"database/sql"
	"log"
	"strconv"
	"time"
)

// schemaLockKey serialises schema setup across deployments starting together.
const schemaLockKey int64 = 0x6f62735f736368

// schemaTimeout bounds the wait for the schema lock at start-up; a variable so tests can shorten it.
var schemaTimeout = 60 * time.Second

// schemaLockTimeout bounds each statement's wait on another session's table lock; a variable so tests can shorten it.
var schemaLockTimeout = 5 * time.Second

// schemaLockSQL is a transaction lock; PgBouncer may move a session between server connections.
const schemaLockSQL = `SELECT pg_advisory_xact_lock($1)`

// schemaStatements create the events table and its indexes. Idempotent.
var schemaStatements = []string{
	`CREATE TABLE IF NOT EXISTS events (
    id       bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ts       timestamptz NOT NULL DEFAULT now(),
    path     text        NOT NULL,
    tier     text        NOT NULL,
    device   text        NOT NULL,
    visitor  text,
    is_bot   boolean     NOT NULL DEFAULT false,
    instance text
)`,
	// Checked first: the ALTER takes ACCESS EXCLUSIVE even when the column exists.
	`DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
        WHERE table_schema = current_schema() AND table_name = 'events' AND column_name = 'instance') THEN
        ALTER TABLE events ADD COLUMN instance text;
    END IF;
END $$`,
	`CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts)`,
	`CREATE INDEX IF NOT EXISTS idx_events_path_ts ON events (path, ts)`,
	`CREATE TABLE IF NOT EXISTS search_votes (
    instance  text        NOT NULL,
    key       text        NOT NULL,
    user_hash text        NOT NULL,
    day       date        NOT NULL,
    query     text        NOT NULL,
    ts        timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (instance, key, user_hash, day)
)`,
	`CREATE INDEX IF NOT EXISTS idx_search_votes_instance_day ON search_votes (instance, day)`,
	`CREATE INDEX IF NOT EXISTS idx_search_votes_user_day ON search_votes (instance, user_hash, day)`,
}

// featureStatements create the feature tables; a failure here leaves the base schema applied.
var featureStatements = []string{
	`CREATE TABLE IF NOT EXISTS feature_events (
    ts       timestamptz NOT NULL,            -- minute, UTC, bound by the writer
    instance text        NOT NULL,
    tier     text        NOT NULL,            -- '' where there is no reader
    device   text        NOT NULL,            -- desktop | mobile | api | discord | job
    signed   boolean     NOT NULL,
    is_bot   boolean     NOT NULL DEFAULT false,
    scope    text        NOT NULL DEFAULT '', -- one registry-bounded qualifier
    name     text        NOT NULL,
    value    text        NOT NULL DEFAULT '',
    n        bigint      NOT NULL DEFAULT 1,
    PRIMARY KEY (ts, instance, tier, device, signed, is_bot, scope, name, value)
)`,
	`CREATE INDEX IF NOT EXISTS idx_feature_events_name_ts ON feature_events (name, ts)`,
}

// ensureSchema applies both lists in one transaction under the schema lock. Idempotent (IF NOT EXISTS).
func ensureSchema(ctx context.Context, db *sql.DB) (featuresReady bool, err error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if _, err = tx.ExecContext(ctx, schemaLockSQL, schemaLockKey); err != nil {
		return false, err
	}
	if _, err = tx.ExecContext(ctx, `SELECT set_config('lock_timeout', $1, true)`, strconv.FormatInt(schemaLockTimeout.Milliseconds(), 10)); err != nil {
		return false, err
	}
	for _, stmt := range schemaStatements {
		if _, err = tx.ExecContext(ctx, stmt); err != nil {
			return false, err
		}
	}
	featuresReady, err = applyFeatureStatements(ctx, tx)
	if err != nil {
		return false, err
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return featuresReady, nil
}

// applyFeatureStatements runs featureStatements behind a savepoint, rolling back to it on failure.
func applyFeatureStatements(ctx context.Context, tx *sql.Tx) (bool, error) {
	if _, err := tx.ExecContext(ctx, `SAVEPOINT features`); err != nil {
		return false, err
	}
	for _, stmt := range featureStatements {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			log.Println("observability: feature schema:", err)
			if _, rerr := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT features`); rerr != nil {
				return false, rerr
			}
			return false, nil
		}
	}
	if _, err := tx.ExecContext(ctx, `RELEASE SAVEPOINT features`); err != nil {
		return false, err
	}
	return true, nil
}
