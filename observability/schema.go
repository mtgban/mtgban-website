// observability/schema.go
package observability

import "database/sql"

// schemaStatements create the events table, its indexes, and the daily rollup
// materialized view. Ordered: table, then indexes, then the view that reads it.
var schemaStatements = []string{
	`CREATE TABLE IF NOT EXISTS events (
    id       bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ts       timestamptz NOT NULL DEFAULT now(),
    path     text        NOT NULL,
    tier     text        NOT NULL,
    device   text        NOT NULL,
    visitor  text,
    is_bot   boolean     NOT NULL DEFAULT false
)`,
	`CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts)`,
	`CREATE INDEX IF NOT EXISTS idx_events_path_ts ON events (path, ts)`,
	`CREATE MATERIALIZED VIEW IF NOT EXISTS usage_daily AS
 SELECT date_trunc('day', ts)::date AS day, path, tier, device, is_bot,
        count(*) AS hits, count(DISTINCT visitor) AS uniques
 FROM events
 GROUP BY 1,2,3,4,5`,
	`CREATE UNIQUE INDEX IF NOT EXISTS usage_daily_pk
 ON usage_daily (day, path, tier, device, is_bot)`,
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
