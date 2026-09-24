package timeseries

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	// registers the postgres driver database/sql opens by name
	_ "github.com/lib/pq"
)

// SQLConfig names the database and how hard to lean on it, as the
// config file spells it.
type SQLConfig struct {
	Host                   string `json:"host"`
	Port                   int    `json:"port"`
	User                   string `json:"user"`
	Password               string `json:"password"`
	DBName                 string `json:"dbname"`
	SSLMode                string `json:"sslmode"`
	ReadOnly               bool   `json:"readonly"`
	MaxOpenConns           int    `json:"max_open_conns"`
	MaxIdleConns           int    `json:"max_idle_conns"`
	ConnMaxLifetimeSeconds int    `json:"conn_max_lifetime_seconds"`
}

// DSN renders the config as a lib/pq connection string.
func (c SQLConfig) DSN() string {
	sslMode := c.SSLMode
	if sslMode == "" {
		sslMode = "disable"
	}
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.Password, c.DBName, sslMode,
	)
}

// Client wraps a Postgres connection pool for the timeseries price table.
type Client struct {
	db       *sql.DB
	readOnly bool

	// variants caches variant identity -> ban_id for the long-form (variants +
	// prices) write path. Warm it once with WarmVariantCache; misses mint.
	variants variantCache

	// The chart reads are kept prepared, which is what stops their
	// hundred-partition plan from being rebuilt on every request. Set once by
	// NewClient, before the client is handed out, and never written again -
	// so reading them needs no synchronisation. Nil when preparing failed, or
	// on a client built without one, and the read falls back to Query.
	stmtHGetAllLong    *sql.Stmt
	stmtHGetAllByBanID *sql.Stmt

	// The screener's anchor walk asks for a provider's newest date up to
	// sixteen times a build, and the unbounded form spans every partition, so
	// its plan is the expensive part: 23ms of planning and 7,982 buffers
	// against 4ms of execution on the live archive. Kept prepared it plans in
	// 0.1ms. Indexed by the two shape flags the query takes - see
	// providerLatestDateStmt.
	stmtProviderLatestDate [3]*sql.Stmt
}

// providerLatestDateShape numbers the three forms of providerLatestDateQuery
// that moverAnchor actually asks for, so each can hold its own prepared
// statement. The fourth combination (unbounded and strict) is not a shape: with
// no bound there is nothing to be strict about.
func providerLatestDateShape(bounded, strict bool) int {
	switch {
	case !bounded:
		return 0
	case !strict:
		return 1
	default:
		return 2
	}
}

// providerLatestDateStmt returns the prepared statement for one shape of the
// newest-date query, or nil when preparing it failed.
func (c *Client) providerLatestDateStmt(bounded, strict bool) *sql.Stmt {
	return c.stmtProviderLatestDate[providerLatestDateShape(bounded, strict)]
}

// query runs a read through stmt when the client managed to prepare it, and as
// a plain query otherwise.
//
// What preparing buys is planning, not parsing. prices is partitioned by month,
// a hundred of them, so planning a statement against it costs far more than
// running it - measured on the live archive, a chart read plans in 24ms and
// executes in 4ms. lib/pq sends an unnamed statement per call and throws the
// plan away with it, so that 24ms was paid on every request; a statement that
// survives lets Postgres settle on a generic plan, which took the same read to
// 0.06ms of planning.
//
// The fallback covers a prepare that failed at NewClient time, and a client
// built without one. It does not cover a statement the server loses later - a
// pooler in transaction mode hands the prepare to one backend and the read to
// another, and the read comes back "prepared statement does not exist" with no
// second chance here. Nothing in front of this database pools that way today;
// if that changes, this is the path that has to learn to retry.
func (c *Client) query(ctx context.Context, stmt *sql.Stmt, text string, args ...any) (*sql.Rows, error) {
	if stmt != nil {
		return stmt.QueryContext(ctx, args...)
	}
	return c.db.QueryContext(ctx, text, args...)
}

// queryRow is query's single-row twin, with the same fallback.
func (c *Client) queryRow(ctx context.Context, stmt *sql.Stmt, text string, args ...any) *sql.Row {
	if stmt != nil {
		return stmt.QueryRowContext(ctx, args...)
	}
	return c.db.QueryRowContext(ctx, text, args...)
}

// OpenDB opens a raw Postgres pool for the database described by the config,
// with its pool settings applied.
//
// The pool is capped so concurrent traffic can't exhaust Postgres's
// max_connections. Idle matches open so bursts don't churn through fresh TCP
// handshakes, and connections recycle periodically so stale ones behind load
// balancers / failovers get dropped. Defaults apply when the corresponding
// config field is zero.
func (c SQLConfig) OpenDB() (*sql.DB, error) {
	db, err := sql.Open("postgres", c.DSN())
	if err != nil {
		return nil, err
	}

	maxOpen := c.MaxOpenConns
	if maxOpen <= 0 {
		maxOpen = 25
	}
	maxIdle := c.MaxIdleConns
	if maxIdle <= 0 {
		maxIdle = maxOpen
	}
	lifetime := time.Duration(c.ConnMaxLifetimeSeconds) * time.Second
	if lifetime <= 0 {
		lifetime = 30 * time.Minute
	}
	db.SetMaxOpenConns(maxOpen)
	db.SetMaxIdleConns(maxIdle)
	db.SetConnMaxLifetime(lifetime)

	return db, nil
}

// NewClient opens a connection pool to the Postgres database described by cfg.
func NewClient(cfg SQLConfig) (*Client, error) {
	db, err := cfg.OpenDB()
	if err != nil {
		return nil, fmt.Errorf("timeseries: open: %w", err)
	}

	if err := db.Ping(); err != nil {
		dbCloseErr := db.Close()
		if dbCloseErr != nil {
			return nil, fmt.Errorf("timeseries: ping: %w, close: %w", err, dbCloseErr)
		}
		return nil, fmt.Errorf("timeseries: ping: %w", err)
	}

	c := &Client{db: db, readOnly: cfg.ReadOnly}
	// Best effort: a read whose statement did not prepare still runs, it just
	// pays for its plan every time.
	c.stmtHGetAllLong, _ = db.Prepare(hgetAllLongQuery)
	c.stmtHGetAllByBanID, _ = db.Prepare(hgetAllByBanIDQuery)
	for _, shape := range []struct{ bounded, strict bool }{{false, false}, {true, false}, {true, true}} {
		stmt, _ := db.Prepare(providerLatestDateQuery(shape.bounded, shape.strict))
		c.stmtProviderLatestDate[providerLatestDateShape(shape.bounded, shape.strict)] = stmt
	}
	return c, nil
}

// ReadOnly reports whether the client was opened against a read-only database.
// Every write method is a silent no-op in that case, so callers that must
// persist data (e.g. a one-shot backfill) can check this up front and fail
// loudly instead of reporting success while writing nothing.
func (c *Client) ReadOnly() bool { return c.readOnly }

// TryAdvisoryLock attempts to acquire the session-level Postgres advisory lock
// for key without blocking. On success it pins a dedicated connection for the
// lock's lifetime and returns a release func that unlocks and returns the
// connection to the pool; the caller must invoke it. When another session
// already holds the lock, acquired is false and release is a no-op. Use it to
// make a job single-flight across processes (e.g. so N server instances don't
// all run the same crawl at once).
func (c *Client) TryAdvisoryLock(ctx context.Context, key int64) (acquired bool, release func(), err error) {
	conn, err := c.db.Conn(ctx)
	if err != nil {
		return false, nil, err
	}
	var ok bool
	if err := conn.QueryRowContext(ctx, "SELECT pg_try_advisory_lock($1)", key).Scan(&ok); err != nil {
		conn.Close()
		return false, nil, err
	}
	if !ok {
		conn.Close()
		return false, func() {}, nil
	}
	return true, func() {
		// Unlock on the same pinned connection (session locks are per-connection),
		// then return it to the pool. Closing the connection would release the
		// lock regardless, so the unlock is best-effort.
		_, _ = conn.ExecContext(context.Background(), "SELECT pg_advisory_unlock($1)", key)
		conn.Close()
	}, nil
}

// Close shuts down the connection pool.
func (c *Client) Close() error {
	stmts := []*sql.Stmt{c.stmtHGetAllLong, c.stmtHGetAllByBanID}
	stmts = append(stmts, c.stmtProviderLatestDate[:]...)
	for _, stmt := range stmts {
		if stmt != nil {
			stmt.Close()
		}
	}
	if c.db != nil {
		return c.db.Close()
	}
	return nil
}
