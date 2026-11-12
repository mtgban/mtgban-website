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
	// Indexes are checked first: CREATE INDEX takes SHARE even when the index exists, and waits behind the roll-up.
	`DO $$ BEGIN
    IF to_regclass(format('%I.idx_events_ts', current_schema())) IS NULL THEN
        CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts);
    END IF;
END $$`,
	`DO $$ BEGIN
    IF to_regclass(format('%I.idx_events_path_ts', current_schema())) IS NULL THEN
        CREATE INDEX IF NOT EXISTS idx_events_path_ts ON events (path, ts);
    END IF;
END $$`,
	`CREATE TABLE IF NOT EXISTS search_votes (
    instance  text        NOT NULL,
    key       text        NOT NULL,
    user_hash text        NOT NULL,
    day       date        NOT NULL,
    query     text        NOT NULL,
    ts        timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (instance, key, user_hash, day)
)`,
	`DO $$ BEGIN
    IF to_regclass(format('%I.idx_search_votes_instance_day', current_schema())) IS NULL THEN
        CREATE INDEX IF NOT EXISTS idx_search_votes_instance_day ON search_votes (instance, day);
    END IF;
END $$`,
	`DO $$ BEGIN
    IF to_regclass(format('%I.idx_search_votes_user_day', current_schema())) IS NULL THEN
        CREATE INDEX IF NOT EXISTS idx_search_votes_user_day ON search_votes (instance, user_hash, day);
    END IF;
END $$`,
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
	// Indexes are checked first: CREATE INDEX takes SHARE even when the index exists, and waits behind a fold or prune.
	`DO $$ BEGIN
    IF to_regclass(format('%I.idx_feature_events_name_ts', current_schema())) IS NULL THEN
        CREATE INDEX IF NOT EXISTS idx_feature_events_name_ts ON feature_events (name, ts);
    END IF;
END $$`,
	// A role that cannot create feature_days loses the feature counter and the jobs, as for feature_events.
	`CREATE TABLE IF NOT EXISTS feature_days (
    day      date    NOT NULL,
    instance text    NOT NULL,
    tier     text    NOT NULL,
    device   text    NOT NULL,
    signed   boolean NOT NULL,
    is_bot   boolean NOT NULL DEFAULT false,
    scope    text    NOT NULL DEFAULT '',
    name     text    NOT NULL,
    value    text    NOT NULL DEFAULT '',
    n        bigint  NOT NULL DEFAULT 0,
    PRIMARY KEY (day, instance, tier, device, signed, is_bot, scope, name, value)
)`,
	`DO $$ BEGIN
    IF to_regclass(format('%I.idx_feature_days_name_day', current_schema())) IS NULL THEN
        CREATE INDEX IF NOT EXISTS idx_feature_days_name_day ON feature_days (name, day);
    END IF;
END $$`,
	// A role that cannot create events_days loses the feature counter and every metrics job.
	// The gateway runs this DDL too until phase 3 gives it SkipSchema(); the site deploys first.
	`CREATE TABLE IF NOT EXISTS events_days (
    day      date    NOT NULL,
    instance text    NOT NULL DEFAULT '',
    path     text    NOT NULL,
    tier     text    NOT NULL,
    device   text    NOT NULL,
    is_bot   boolean NOT NULL DEFAULT false,
    hits     bigint  NOT NULL,
    uniques  bigint  NOT NULL,
    PRIMARY KEY (day, instance, path, tier, device, is_bot)
)`,
	// Review marks an admin sets on a metric; no author is stored.
	`CREATE TABLE IF NOT EXISTS feature_reviews (
    instance   text        NOT NULL,
    name       text        NOT NULL,
    value      text        NOT NULL DEFAULT '',
    scope      text        NOT NULL DEFAULT '',
    verdict    text        NOT NULL,   -- keep | remove | watch
    note       text        NOT NULL DEFAULT '',
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (instance, name, value, scope)
)`,
	// Script errors by place and class; at most errorRowsPerDay rows a day an instance, so no further index.
	`CREATE TABLE IF NOT EXISTS feature_errors (
    day      date    NOT NULL,
    instance text    NOT NULL,
    device   text    NOT NULL,
    build    text    NOT NULL,
    script   text    NOT NULL,
    line     integer NOT NULL,
    class    text    NOT NULL,
    n        bigint  NOT NULL DEFAULT 1,
    PRIMARY KEY (day, instance, device, build, script, line, class)
)`,
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
