package observability

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"log"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lib/pq"
)

func TestFeatureStatementsCreateTheTable(t *testing.T) {
	joined := strings.Join(featureStatements, "\n")
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS feature_events",
		"PRIMARY KEY (ts, instance, tier, device, signed, is_bot, scope, name, value)",
		"CREATE INDEX IF NOT EXISTS idx_feature_events_name_ts",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("feature schema lacks %q", want)
		}
	}
	if strings.Contains(joined, "visitor") || strings.Contains(joined, "user_hash") {
		t.Error("the feature tables carry no reader column")
	}
}

func TestSkipSchemaOption(t *testing.T) {
	var o clientOptions
	SkipSchema()(&o)
	if !o.skipSchema {
		t.Fatal("SkipSchema sets the option")
	}
}

// PgBouncer can hand a session lock's unlock to another server connection.
func TestSchemaLockIsATransactionLock(t *testing.T) {
	if !strings.Contains(schemaLockSQL, "pg_advisory_xact_lock(") {
		t.Errorf("the schema lock is %q, want pg_advisory_xact_lock", schemaLockSQL)
	}
	src, err := os.ReadFile("schema.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{"pg_advisory_lock(", "pg_try_advisory_lock(", "pg_advisory_unlock"} {
		if strings.Contains(string(src), banned) {
			t.Errorf("schema.go uses the session lock call %s", banned)
		}
	}
}

// Concurrent start-up succeeds; TestSchemaLockSerialisesTheDDL proves the lock.
func TestConcurrentClientsEnsureTheSchema(t *testing.T) {
	cfg := testSQLConfig(t)
	clients := make([]*Client, 8)
	errs := make([]error, 8)
	var wg sync.WaitGroup
	for i := range clients {
		wg.Go(func() {
			clients[i], errs[i] = NewClient(cfg)
		})
	}
	wg.Wait()
	for _, c := range clients {
		if c != nil {
			t.Cleanup(func() { c.Close() })
		}
	}
	for i, c := range clients {
		if errs[i] != nil {
			t.Fatalf("client %d: %v", i, errs[i])
		}
		if !c.FeaturesReady() {
			t.Errorf("client %d: features not ready", i)
		}
	}
	var n int64
	if err := clients[0].db.QueryRow(`SELECT count(*) FROM feature_events`).Scan(&n); err != nil {
		t.Fatalf("feature_events: %v", err)
	}
}

func TestSchemaLockIsReleasedAtCommit(t *testing.T) {
	c := testClient(t)
	var held int
	err := c.db.QueryRow(`SELECT count(*) FROM pg_locks
		WHERE locktype = 'advisory' AND classid::bigint = $1 AND objid::bigint = $2 AND objsubid = 1`,
		int64(schemaLockKey>>32), int64(schemaLockKey&0xffffffff)).Scan(&held)
	if err != nil {
		t.Fatal(err)
	}
	if held != 0 {
		t.Errorf("%d holders of the schema lock after NewClient", held)
	}
}

// Holds the real schema lock: not safe beside another process starting on this database.
func TestSchemaLockSerialisesTheDDL(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	holder, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback() }()
	if _, err := holder.Exec(schemaLockSQL, schemaLockKey); err != nil {
		t.Fatal(err)
	}

	type result struct {
		ready bool
		err   error
	}
	done := make(chan result, 1)
	go func() {
		ready, err := ensureSchema(ctx, c.db)
		done <- result{ready, err}
	}()
	waitForSchemaBlocked(t, c.db, holder)
	if err := holder.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-done:
		if !r.ready || r.err != nil {
			t.Fatalf("ensureSchema = %v, %v; want true, nil", r.ready, r.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ensureSchema did not return after the holder committed")
	}
}

func TestAFeatureFailureKeepsTheBaseSchema(t *testing.T) {
	c := testClient(t)
	if _, err := c.db.Exec(`DROP TABLE IF EXISTS schema_test_marker`); err != nil {
		t.Fatal(err)
	}
	savedBase, savedFeatures := schemaStatements, featureStatements
	schemaStatements = append(slices.Clone(savedBase), `CREATE TABLE IF NOT EXISTS schema_test_marker (x int)`)
	featureStatements = []string{"CREATE TABLE feature_broken (x no_such_type)"}
	prevLog := log.Writer()
	log.SetOutput(io.Discard)
	t.Cleanup(func() {
		log.SetOutput(prevLog)
		schemaStatements, featureStatements = savedBase, savedFeatures
		_, _ = c.db.Exec(`DROP TABLE IF EXISTS schema_test_marker`)
	})

	ready, err := ensureSchema(context.Background(), c.db)
	if ready || err != nil {
		t.Fatalf("ensureSchema = %v, %v; want false, nil", ready, err)
	}
	fresh, err := NewClient(testSQLConfig(t), SkipSchema())
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	var marker bool
	if err := fresh.db.QueryRow(`SELECT to_regclass('schema_test_marker') IS NOT NULL`).Scan(&marker); err != nil {
		t.Fatal(err)
	}
	if !marker {
		t.Error("the base schema was rolled back with the feature failure")
	}
}

// Holds the real schema lock: not safe beside another process starting on this database.
func TestSchemaTimeoutFailsTheClient(t *testing.T) {
	c := testClient(t)
	holder, err := c.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback() }()
	if _, err := holder.Exec(schemaLockSQL, schemaLockKey); err != nil {
		t.Fatal(err)
	}
	saved := schemaTimeout
	schemaTimeout = 100 * time.Millisecond
	t.Cleanup(func() { schemaTimeout = saved })

	blocked, err := NewClient(testSQLConfig(t))
	if err == nil {
		blocked.Close()
		t.Fatal("NewClient succeeded while the schema lock was held")
	}
	// lib/pq reports a context deadline as the server's query_canceled error, or as the deadline itself.
	var pqErr *pq.Error
	canceled := errors.As(err, &pqErr) && pqErr.Code == "57014"
	if !canceled && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("NewClient error = %v, want pq query_canceled (57014) or the context deadline", err)
	}
}

// Holds a lock on events: not safe beside another process using this database.
func TestSchemaDoesNotWaitBehindAReader(t *testing.T) {
	c := testClient(t) // the instance column exists from here on
	reader, err := c.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Rollback() }()
	if _, err := reader.Exec(`LOCK TABLE events IN ACCESS SHARE MODE`); err != nil {
		t.Fatal(err)
	}
	var pid int
	if err := reader.QueryRow(`SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := ensureSchema(ctx, c.db)
		done <- err
	}()
	for {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("ensureSchema: %v", err)
			}
			return
		default:
		}
		var waiting int
		if err := c.db.QueryRow(`SELECT count(*) FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid))`, pid).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting > 0 {
			_ = reader.Rollback()
			<-done
			t.Fatal("ensureSchema waited behind a reader of events")
		}
		time.Sleep(time.Millisecond)
	}
}

// Holds a lock on events: not safe beside another process using this database.
func TestSchemaStatementFailsAtTheLockTimeout(t *testing.T) {
	c := testClient(t)
	holder, err := c.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback() }()
	if _, err := holder.Exec(`LOCK TABLE events IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	saved := schemaLockTimeout
	schemaLockTimeout = 100 * time.Millisecond
	t.Cleanup(func() { schemaLockTimeout = saved })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = ensureSchema(ctx, c.db)
	var pqErr *pq.Error
	if !errors.As(err, &pqErr) || pqErr.Code != "55P03" {
		t.Fatalf("ensureSchema error = %v, want pq lock_not_available (55P03)", err)
	}
}

// waitForSchemaBlocked waits until Postgres shows a query waiting on holder's
// locks, and fails the test when none does.
func waitForSchemaBlocked(t *testing.T, db *sql.DB, holder *sql.Tx) {
	t.Helper()
	var pid int
	if err := holder.QueryRow(`SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		var waiting int
		if err := db.QueryRow(`SELECT count(*) FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid))`, pid).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("ensureSchema never waited on the schema lock")
		}
		time.Sleep(time.Millisecond)
	}
}
