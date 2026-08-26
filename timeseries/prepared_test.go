package timeseries

import (
	"context"
	"database/sql"
	"testing"
)

// Keeping the chart reads prepared is an optimisation, not a dependency. A
// client that never prepared them - one built without NewClient, a server that
// refused, a pooler that cannot hold server-side statements - still has to run
// the read, from the same query text.
func TestQueryFallsBackWithoutAStatement(t *testing.T) {
	db, err := sql.Open("postgres", "postgres://127.0.0.1:1/nothing?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	c := &Client{db: db}
	if c.stmtHGetAllLong != nil {
		t.Fatal("a hand-built client should carry no prepared statement")
	}

	// Reaches the server (and fails there, since there is none) rather than
	// returning early on the nil statement.
	_, err = c.query(context.Background(), c.stmtHGetAllLong, hgetAllLongQuery,
		"7c3ea479-e463-58e7-b1b0-b217c77dae79", false, false, Lookback(365).Since())
	if err == nil {
		t.Error("query against a dead server did not error")
	}
}
