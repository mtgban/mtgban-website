package timeseries

import (
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
}

// NewClient opens a connection pool to the Postgres database described by cfg.
func NewClient(cfg SqlConfig) (*Client, error) {
	db, err := sql.Open("postgres", cfg.DSN())
	if err != nil {
		return nil, fmt.Errorf("timeseries: open: %w", err)
	}

	// Cap the pool so concurrent chart traffic can't exhaust Postgres's
	// max_connections. Match idle to open so bursts don't churn through
	// fresh TCP handshakes, and recycle periodically so stale conns
	// behind load balancers / failovers get dropped. Defaults apply when
	// the corresponding config field is zero.
	maxOpen := cfg.MaxOpenConns
	if maxOpen <= 0 {
		maxOpen = 25
	}
	maxIdle := cfg.MaxIdleConns
	if maxIdle <= 0 {
		maxIdle = maxOpen
	}
	lifetime := time.Duration(cfg.ConnMaxLifetimeSeconds) * time.Second
	if lifetime <= 0 {
		lifetime = 30 * time.Minute
	}
	db.SetMaxOpenConns(maxOpen)
	db.SetMaxIdleConns(maxIdle)
	db.SetConnMaxLifetime(lifetime)

	if err := db.Ping(); err != nil {
		dbCloseErr := db.Close()
		if dbCloseErr != nil {
			return nil, fmt.Errorf("timeseries: ping: %w, close: %w", err, dbCloseErr)
		}
		return nil, fmt.Errorf("timeseries: ping: %w", err)
	}

	return &Client{db: db, readOnly: cfg.ReadOnly}, nil
}

// Close shuts down the connection pool.
func (c *Client) Close() error {
	if c.db != nil {
		return c.db.Close()
	}
	return nil
}

// DB exposes the underlying connection pool so adjacent packages
// (e.g. joblog) can share it instead of opening a second pool to the same
// database.
func (c *Client) DB() *sql.DB { return c.db }

// ReadOnly reports whether the client was constructed against a read replica.
func (c *Client) ReadOnly() bool { return c.readOnly }
