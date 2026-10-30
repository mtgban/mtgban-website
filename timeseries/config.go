package timeseries

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"

	// registers the postgres driver database/sql opens by name
	_ "github.com/lib/pq"
)

// SQLConfig names the database and how hard to lean on it, as the
// config file spells it.
type SQLConfig struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	// DirectPort is Postgres's own port where Port is a transaction-mode
	// pooler's: LISTEN and advisory locks need one session throughout, which
	// the pooler does not keep. Zero means Port.
	DirectPort             int    `json:"direct_port"`
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
//
// binary_parameters makes lib/pq send a query's Parse, Bind and Execute in one
// round trip. Without it the unnamed statement is parsed in one and bound in
// the next, and PgBouncer in transaction mode (port 6432 in production) can
// hand the second to another backend: "unnamed prepared statement does not
// exist".
func (c SQLConfig) DSN() string {
	return c.dsn(c.Port)
}

// SessionDSN is the connection string for what needs one Postgres session
// throughout (LISTEN, advisory locks): DirectPort's, or DSN's without one.
func (c SQLConfig) SessionDSN() string {
	if c.DirectPort == 0 {
		return c.DSN()
	}
	return c.dsn(c.DirectPort)
}

func (c SQLConfig) dsn(port int) string {
	sslMode := c.SSLMode
	if sslMode == "" {
		sslMode = "disable"
	}
	// lib/pq takes the token after "key=" as its value, so a key with an
	// empty value would swallow the one behind it: those stay out, and
	// dsnValue quotes a value the tokenizer would otherwise cut short.
	parts := make([]string, 0, 7)
	for _, kv := range [...][2]string{
		{"host", c.Host},
		{"port", strconv.Itoa(port)},
		{"user", c.User},
		{"password", c.Password},
		{"dbname", c.DBName},
		{"sslmode", sslMode},
		{"binary_parameters", "yes"},
	} {
		if kv[1] == "" {
			continue
		}
		parts = append(parts, kv[0]+"="+dsnValue(kv[1]))
	}
	return strings.Join(parts, " ")
}

// dsnEscaper writes a value the way lib/pq reads it back inside single
// quotes, where a backslash escapes the character after it.
var dsnEscaper = strings.NewReplacer(`\`, `\\`, `'`, `\'`)

// dsnValue is v as a lib/pq DSN value: bare when the tokenizer reads it
// whole, and single-quoted when a space, quote or backslash would end or
// escape part of it.
func dsnValue(v string) string {
	for _, r := range v {
		if unicode.IsSpace(r) || r == '\'' || r == '\\' {
			return "'" + dsnEscaper.Replace(v) + "'"
		}
	}
	return v
}

// Client wraps a Postgres connection pool for the timeseries price table.
type Client struct {
	db       *sql.DB
	readOnly bool
	// sessionDB reaches Postgres past the pooler db goes through, for the
	// advisory locks; nil without a direct_port. It keeps no idle connection,
	// so closing one always ends its session, and any lock left on it.
	sessionDB *sql.DB

	// variants caches variant identity -> ban_id for the long-form (variants +
	// prices) write path. Warm it once with WarmVariantCache; misses mint.
	variants variantCache

	// The chart reads are kept prepared, which is what stops their
	// hundred-partition plan from being rebuilt on every request. Set by
	// NewClient and PrepareStatements, before the client is handed out, and
	// never written again - so reading them needs no synchronisation. Nil when
	// preparing failed, or on a client built without one, and the read falls
	// back to Query.
	stmtHGetAllLong    *sql.Stmt
	stmtHGetAllByBanID *sql.Stmt
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
// second chance here. Production reaches this database through PgBouncer, so
// these statements survive only if it tracks them (max_prepared_statements).
func (c *Client) query(ctx context.Context, stmt *sql.Stmt, text string, args ...any) (*sql.Rows, error) {
	if stmt != nil {
		return stmt.QueryContext(ctx, args...)
	}
	return c.db.QueryContext(ctx, text, args...)
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
	if cfg.DirectPort != 0 {
		// sql.Open only validates the DSN; the first lock dials
		c.sessionDB, err = sql.Open("postgres", cfg.SessionDSN())
		if err != nil {
			db.Close()
			return nil, fmt.Errorf("timeseries: open session: %w", err)
		}
		c.sessionDB.SetMaxIdleConns(0)
	}
	// Best effort: a read whose statement did not prepare still runs, it just
	// pays for its plan every time.
	_ = c.PrepareStatements(context.Background())
	return c, nil
}

// PrepareStatements prepares each chart read not yet prepared, such as one
// whose column did not exist at NewClient. Call it only before the client is
// shared; a read left unprepared still runs, as a plain query.
func (c *Client) PrepareStatements(ctx context.Context) error {
	var errs []error
	for _, s := range []struct {
		stmt **sql.Stmt
		text string
	}{
		{&c.stmtHGetAllLong, hgetAllLongQuery},
		{&c.stmtHGetAllByBanID, hgetAllByBanIDQuery},
	} {
		if *s.stmt != nil {
			continue
		}
		stmt, err := c.db.PrepareContext(ctx, s.text)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		*s.stmt = stmt
	}
	return errors.Join(errs...)
}

// ReadOnly reports whether the client was opened against a read-only database.
// Every write method is a silent no-op in that case, so callers that must
// persist data (e.g. a one-shot backfill) can check this up front and fail
// loudly instead of reporting success while writing nothing.
func (c *Client) ReadOnly() bool { return c.readOnly }

// TryAdvisoryLock attempts to acquire the session-level Postgres advisory lock
// for key without blocking. On success it pins a dedicated connection for the
// lock's lifetime and returns a release func that unlocks and closes it: on
// the session pool (direct_port) that ends the session, elsewhere it goes back
// to the shared pool. The caller must invoke it. When another session already
// holds the lock, acquired is false and release is a no-op. Use it to make a
// job single-flight across processes (e.g. so N server instances don't all
// run the same crawl at once).
func (c *Client) TryAdvisoryLock(ctx context.Context, key int64) (acquired bool, release func(), err error) {
	db := c.db
	if c.sessionDB != nil {
		// Past the pooler, which would hand the unlock to another backend.
		db = c.sessionDB
	}
	conn, err := db.Conn(ctx)
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
		// Unlock on the same pinned connection (session locks are
		// per-connection), then close it. Ending the session releases the
		// lock regardless, so the unlock is best-effort.
		_, _ = conn.ExecContext(context.Background(), "SELECT pg_advisory_unlock($1)", key)
		conn.Close()
	}, nil
}

// Close shuts down the connection pool.
func (c *Client) Close() error {
	for _, stmt := range []*sql.Stmt{c.stmtHGetAllLong, c.stmtHGetAllByBanID} {
		if stmt != nil {
			stmt.Close()
		}
	}
	if c.sessionDB != nil {
		c.sessionDB.Close()
	}
	if c.db != nil {
		return c.db.Close()
	}
	return nil
}
