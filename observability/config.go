// observability/config.go
package observability

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/mtgban/mtgban-website/timeseries"

	_ "github.com/lib/pq"
)

// SqlConfig reuses the timeseries shape so observability_config matches sql_config.
type SqlConfig = timeseries.SqlConfig

// Client wraps a Postgres connection pool for the telemetry tables.
type Client struct {
	db *sql.DB
}

// NewClient opens a pool, applies small pool caps, pings, and ensures the schema.
func NewClient(cfg SqlConfig) (*Client, error) {
	db, err := sql.Open("postgres", cfg.DSN())
	if err != nil {
		return nil, fmt.Errorf("observability: open: %w", err)
	}

	maxOpen := cfg.MaxOpenConns
	if maxOpen <= 0 {
		maxOpen = 5
	}
	maxIdle := cfg.MaxIdleConns
	if maxIdle <= 0 {
		maxIdle = 2
	}
	lifetime := time.Duration(cfg.ConnMaxLifetimeSeconds) * time.Second
	if lifetime <= 0 {
		lifetime = 30 * time.Minute
	}
	db.SetMaxOpenConns(maxOpen)
	db.SetMaxIdleConns(maxIdle)
	db.SetConnMaxLifetime(lifetime)

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("observability: ping: %w", err)
	}
	if err := ensureSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("observability: ensure schema: %w", err)
	}
	return &Client{db: db}, nil
}

// Close shuts down the connection pool.
func (c *Client) Close() error {
	if c != nil && c.db != nil {
		return c.db.Close()
	}
	return nil
}
