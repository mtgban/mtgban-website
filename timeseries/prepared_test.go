package timeseries

import (
	"context"
	"database/sql"
	"testing"
)

// Keeping the chart reads prepared is an optimisation, not a dependency. A
// client that never prepared them - one built without NewClient, a server or
// pooler that refused the prepare - still has to run the read, from the same
// query text.
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

// The prepared newest-date statements live in an array indexed by shape, so a
// slot that drifts from its query text would hand a bounded read the plan for
// `date <=` when it asked for `date <`, quietly moving the anchor by a day.
// Pin the mapping: the three shapes moverAnchor asks for get three distinct
// slots and three distinct texts, and the combination it never asks for
// (unbounded and strict) folds onto the unbounded slot rather than claiming a
// fourth.
func TestProviderLatestDateShapes(t *testing.T) {
	asked := []struct{ bounded, strict bool }{{false, false}, {true, false}, {true, true}}

	texts := map[int]string{}
	for _, shape := range asked {
		i := providerLatestDateShape(shape.bounded, shape.strict)
		q := providerLatestDateQuery(shape.bounded, shape.strict)
		if prev, seen := texts[i]; seen {
			t.Errorf("shapes share slot %d: %q and %q", i, prev, q)
		}
		texts[i] = q
	}
	if len(texts) != 3 {
		t.Errorf("three shapes landed in %d slots: %v", len(texts), texts)
	}
	for i := range texts {
		if i < 0 || i >= len(Client{}.stmtProviderLatestDate) {
			t.Errorf("slot %d is outside the prepared array", i)
		}
	}
	if got := providerLatestDateShape(false, true); got != providerLatestDateShape(false, false) {
		t.Errorf("unbounded-and-strict claims slot %d of its own", got)
	}
}
