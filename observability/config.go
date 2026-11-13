package observability

import (
	"context"
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
	db            *sql.DB
	featuresReady bool
}

// Option changes how NewClient sets up a Client.
type Option func(*clientOptions)

type clientOptions struct {
	skipSchema bool
}

// SkipSchema makes NewClient apply no schema, for a process that does not own it.
func SkipSchema() Option {
	return func(o *clientOptions) { o.skipSchema = true }
}

// NewClient opens a pool, applies small pool caps, pings, and ensures the schema.
func NewClient(cfg SQLConfig, opts ...Option) (*Client, error) {
	var o clientOptions
	for _, opt := range opts {
		opt(&o)
	}

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
	if o.skipSchema {
		return &Client{db: db, featuresReady: true}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), schemaTimeout)
	defer cancel()
	featuresReady, err := ensureSchema(ctx, db)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("observability: ensure schema: %w", err)
	}
	return &Client{db: db, featuresReady: featuresReady}, nil
}

// FeaturesReady reports whether the feature tables exist for this client to write.
func (c *Client) FeaturesReady() bool {
	return c != nil && c.featuresReady
}

// Close shuts down the connection pool.
func (c *Client) Close() error {
	if c != nil && c.db != nil {
		return c.db.Close()
	}
	return nil
}
