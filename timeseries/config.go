package timeseries

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq"
)

type SqlConfig struct {
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

func (c SqlConfig) DSN() string {
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
}

// OpenDB opens a raw Postgres pool for the database described by the config,
// with its pool settings applied.
//
// The pool is capped so concurrent traffic can't exhaust Postgres's
// max_connections. Idle matches open so bursts don't churn through fresh TCP
// handshakes, and connections recycle periodically so stale ones behind load
// balancers / failovers get dropped. Defaults apply when the corresponding
// config field is zero.
func (c SqlConfig) OpenDB() (*sql.DB, error) {
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
func NewClient(cfg SqlConfig) (*Client, error) {
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

	return &Client{db: db, readOnly: cfg.ReadOnly}, nil
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
	if c.db != nil {
		return c.db.Close()
	}
	return nil
}
