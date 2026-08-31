package observability

import "database/sql"

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
	`ALTER TABLE events ADD COLUMN IF NOT EXISTS instance text`,
	`CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts)`,
	`CREATE INDEX IF NOT EXISTS idx_events_path_ts ON events (path, ts)`,
}

// ensureSchema applies each statement in order. Idempotent (IF NOT EXISTS).
func ensureSchema(db *sql.DB) error {
	for _, stmt := range schemaStatements {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}
