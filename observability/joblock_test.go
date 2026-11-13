package observability

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

// Two callers ask for one key while the first still holds it: one runs.
func TestWithJobLockRunsOneHolder(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	key := "test-" + t.Name()
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		ran, err := c.WithJobLock(ctx, key, func(context.Context) error {
			close(entered)
			<-release
			return nil
		})
		if err == nil && !ran {
			err = errors.New("the first caller did not run")
		}
		done <- err
	}()
	select {
	case <-entered:
	case err := <-done:
		t.Fatalf("the first caller returned before running: %v", err)
	}

	called := false
	ran, err := c.WithJobLock(ctx, key, func(context.Context) error { called = true; return nil })
	if err != nil || ran || called {
		close(release)
		t.Fatalf("second caller: ran=%v called=%v err=%v, want it turned away", ran, called, err)
	}
	// Another key is another lock.
	if ran, err := c.WithJobLock(ctx, key+"-other", func(context.Context) error { return nil }); err != nil || !ran {
		close(release)
		t.Fatalf("other key: ran=%v err=%v", ran, err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// Released: the next caller runs.
	if ran, err := c.WithJobLock(ctx, key, func(context.Context) error { return nil }); err != nil || !ran {
		t.Fatalf("after release: ran=%v err=%v", ran, err)
	}
}

func TestWithJobLockReturnsTheJobsError(t *testing.T) {
	c := testClient(t)
	boom := errors.New("boom")
	ran, err := c.WithJobLock(context.Background(), "test-"+t.Name(), func(context.Context) error { return boom })
	if !ran || !errors.Is(err, boom) {
		t.Fatalf("ran=%v err=%v, want true and boom", ran, err)
	}
}

// A lock whose connection dies during the job is reported, not taken for a clean run.
func TestWithJobLockReportsALostLock(t *testing.T) {
	c := testClient(t)
	key := "test-" + t.Name()
	ran, err := c.WithJobLock(context.Background(), key, func(ctx context.Context) error {
		var pid int
		// Only this database: another one may hold the same key, and its holder is not ours to end.
		if err := c.db.QueryRowContext(ctx, `SELECT pid FROM pg_locks
			WHERE locktype = 'advisory' AND classid = $1 AND objid = hashtext($2::text)::oid AND objsubid = 2
			AND database = (SELECT oid FROM pg_database WHERE datname = current_database())`,
			jobLockClass, key).Scan(&pid); err != nil {
			return err
		}
		// The timeout makes the call wait until the holder is gone.
		var gone bool
		if err := c.db.QueryRowContext(ctx, `SELECT pg_terminate_backend($1, 5000)`, pid).Scan(&gone); err != nil || !gone {
			return errors.Join(err, errors.New("the lock holder was not terminated"))
		}
		return nil
	})
	if !ran || err == nil || !strings.Contains(err.Error(), "lost during the run") {
		t.Fatalf("ran=%v err=%v, want true and a lost lock", ran, err)
	}
}

// A deadline during the job is reported as the deadline, not as a lost lock.
func TestWithJobLockReportsTheDeadline(t *testing.T) {
	c := testClient(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ran, err := c.WithJobLock(ctx, "test-"+t.Name(), func(context.Context) error { cancel(); return nil })
	if !ran || !errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "lost") {
		t.Fatalf("ran=%v err=%v, want true and context.Canceled alone", ran, err)
	}
}

// stubLock is a database/sql driver that grants every advisory lock and fails "SELECT 1" when lost is set.
type stubLock struct{ lost bool }

func (s *stubLock) Connect(context.Context) (driver.Conn, error) { return &stubConn{s}, nil }
func (s *stubLock) Driver() driver.Driver                        { return nil }

type stubConn struct{ s *stubLock }

func (c *stubConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("stub: no prepare") }
func (c *stubConn) Close() error                        { return nil }
func (c *stubConn) Begin() (driver.Tx, error)           { return stubTx{}, nil }
func (c *stubConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	return &stubRows{}, nil
}
func (c *stubConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	if c.s.lost && query == "SELECT 1" {
		return nil, driver.ErrBadConn
	}
	return driver.RowsAffected(0), nil
}

type stubTx struct{}

func (stubTx) Commit() error   { return nil }
func (stubTx) Rollback() error { return nil }

// stubRows is one row holding true.
type stubRows struct{ done bool }

func (r *stubRows) Columns() []string { return []string{"held"} }
func (r *stubRows) Close() error      { return nil }
func (r *stubRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	dest[0] = true
	return nil
}

// stubClient is a Client over the stub driver, with a pool of maxOpen.
func stubClient(t *testing.T, s *stubLock, maxOpen int) *Client {
	t.Helper()
	db := sql.OpenDB(s)
	db.SetMaxOpenConns(maxOpen)
	t.Cleanup(func() { _ = db.Close() })
	return &Client{db: db}
}

// The outcomes of a run, with no database: a deadline, a lost lock, a clean run.
func TestWithJobLockOutcomes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ran, err := stubClient(t, &stubLock{}, 2).WithJobLock(ctx, "k", func(context.Context) error { cancel(); return nil })
	if !ran || !errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "lost") {
		t.Errorf("cancelled: ran=%v err=%v, want context.Canceled and no lost lock", ran, err)
	}

	boom := errors.New("boom")
	ran, err = stubClient(t, &stubLock{lost: true}, 2).WithJobLock(context.Background(), "k", func(context.Context) error { return boom })
	if !ran || !errors.Is(err, boom) || !strings.Contains(err.Error(), "lost during the run") {
		t.Errorf("lost: ran=%v err=%v, want boom and a lost lock", ran, err)
	}

	ran, err = stubClient(t, &stubLock{}, 0).WithJobLock(context.Background(), "k", func(context.Context) error { return nil })
	if !ran || err != nil {
		t.Errorf("clean: ran=%v err=%v", ran, err)
	}
}

// A pool of one would hold its only connection for the lock while the job waits for one.
func TestWithJobLockRefusesAPoolOfOne(t *testing.T) {
	called := false
	ran, err := stubClient(t, &stubLock{}, 1).WithJobLock(context.Background(), "k", func(context.Context) error { called = true; return nil })
	if ran || called || err == nil || !strings.Contains(err.Error(), "2 connections") {
		t.Fatalf("ran=%v called=%v err=%v, want a refusal before the job", ran, called, err)
	}
}

// PgBouncer can hand a session lock's unlock to another server connection.
func TestJobLockIsATransactionLock(t *testing.T) {
	src, err := os.ReadFile("joblock.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "pg_try_advisory_xact_lock(") {
		t.Error("joblock.go does not take pg_try_advisory_xact_lock")
	}
	for _, banned := range []string{"pg_advisory_lock(", "pg_try_advisory_lock(", "pg_advisory_unlock"} {
		if strings.Contains(string(src), banned) {
			t.Errorf("joblock.go uses the session lock call %s", banned)
		}
	}
}
