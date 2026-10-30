package timeseries

import (
	"context"
	"fmt"
)

// ddlLockKey is the Postgres advisory-lock key that serializes concurrent
// creation of the tcg schema across processes. CREATE ... IF NOT EXISTS is not
// safe to run concurrently against the shared catalog (racing creators can
// raise "tuple concurrently updated" or a duplicate pg_type unique violation),
// which is reachable here because a manual backfill, the daily cron, and every
// server instance can all ensure the schema at once.
const ddlLockKey = 0x7463675f_64646c // "tcg_ddl"

// execDDL runs one or more idempotent DDL statements behind a
// transaction-scoped advisory lock so concurrent creators serialize instead of
// racing the catalog. Multiple statements in a single unparameterized Exec run
// as one implicit transaction (lib/pq simple protocol), so the lock taken by
// the leading statement is held through the DDL and released when it commits.
// lock_timeout makes the DDL fail behind a long reader rather than queue reads behind it.
func (c *Client) execDDL(ctx context.Context, ddl string) error {
	q := fmt.Sprintf("SET LOCAL lock_timeout = '5s';\nSELECT pg_advisory_xact_lock(%d);\n%s", ddlLockKey, ddl)
	_, err := c.db.ExecContext(ctx, q)
	return err
}
