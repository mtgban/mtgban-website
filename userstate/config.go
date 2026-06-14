package userstate

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/mtgban/mtgban-website/timeseries"

	_ "github.com/lib/pq"
)

// SqlConfig is the connection configuration. It reuses the timeseries shape so
// the user_state_config JSON block matches sql_config field-for-field.
type SqlConfig = timeseries.SqlConfig

// HashEmail returns the hex sha256 of the lowercased email. Plaintext email is
// never stored; this hash is the table primary key.
func HashEmail(email string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(email))))
	return hex.EncodeToString(sum[:])
}

// Client wraps a Postgres connection pool for the user_state table.
type Client struct {
	db *sql.DB
}

// NewClient opens a pool, applies pool caps, pings, and ensures the schema.
func NewClient(cfg SqlConfig) (*Client, error) {
	db, err := sql.Open("postgres", cfg.DSN())
	if err != nil {
		return nil, fmt.Errorf("userstate: open: %w", err)
	}

	// user_state sees near-zero write volume and only PK lookups, so a small
	// pool is plenty and keeps the total connection count (shared with the
	// timeseries pool) well under a managed Postgres connection cap.
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
		if closeErr := db.Close(); closeErr != nil {
			return nil, fmt.Errorf("userstate: ping: %w, close: %w", err, closeErr)
		}
		return nil, fmt.Errorf("userstate: ping: %w", err)
	}

	if _, err := db.Exec(createTableSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("userstate: ensure schema: %w", err)
	}

	return &Client{db: db}, nil
}

// Close shuts down the connection pool.
func (c *Client) Close() error {
	if c.db != nil {
		return c.db.Close()
	}
	return nil
}
