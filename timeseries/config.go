package timeseries

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

type SqlConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	DBName   string `json:"dbname"`
	SSLMode  string `json:"sslmode"`
	ReadOnly bool   `json:"readonly"`
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
