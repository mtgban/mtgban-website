// observability/config.go
package observability

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/mtgban/mtgban-website/timeseries"

	// registers the postgres driver database/sql opens by name
	_ "github.com/lib/pq"
)

// SQLConfig reuses the timeseries shape so observability_config matches sql_config.
type SQLConfig = timeseries.SQLConfig

// Client wraps a Postgres connection pool for the telemetry tables.
type Client struct {
	db *sql.DB
}

// NewClient opens a pool, applies small pool caps, pings, and ensures the schema.
func NewClient(cfg SQLConfig) (*Client, error) {
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
	// Recycle idle conns before a NAT or firewall can silently drop them.
	db.SetConnMaxIdleTime(time.Minute)

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
