package timeseries

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq"
)

type SqlConfig struct {
	Host     string `json:"sql_host"`
	Port     int    `json:"sql_port"`
	User     string `json:"sql_user"`
	Password string `json:"sql_password"`
	DBName   string `json:"sql_dbname"`
	SSLMode  string `json:"sql_sslmode"`
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
	db *sql.DB
}

// NewClient opens a connection pool to the Postgres database described by cfg.
func NewClient(cfg SqlConfig) (*Client, error) {
	db, err := sql.Open("postgres", cfg.DSN())
	if err != nil {
		return nil, fmt.Errorf("timeseries: open: %w", err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("timeseries: ping: %w", err)
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
