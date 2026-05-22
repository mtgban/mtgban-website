package joblog

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// JobRun is one durable record of a cron/background job execution or a
// periodic heartbeat. Pointer fields are nullable so a "still running" or
// "heartbeat" row can omit values it doesn't have.
type JobRun struct {
	Host        string
	BuildCommit string
	JobName     string
	Kind        string // "job" or "heartbeat"
	Status      string // "running", "success", "error", "panic", "tick"
	StartedAt   time.Time
	FinishedAt  *time.Time
	DurationMs  *int64
	ErrorMsg    *string
	PanicStack  *string

	HeapAllocBefore    *int64
	HeapAllocAfter     *int64
	HeapSysBefore      *int64
	HeapSysAfter       *int64
	GoroutinesBefore   *int
	GoroutinesAfter    *int
	NumGCBefore        *int64
	NumGCAfter         *int64
	PauseTotalNsBefore *int64
	PauseTotalNsAfter  *int64

	SysMemUsedBytes  *int64
	SysMemTotalBytes *int64
}

// LogLine is one captured line of stdout/stderr (or a synthetic source).
type LogLine struct {
	Timestamp time.Time
	Host      string
	Source    string // "stdout" | "stderr" | other
	Message   string
}

const jobRunsSchema = `
CREATE TABLE IF NOT EXISTS job_runs (
    id                       BIGSERIAL PRIMARY KEY,
    host                     TEXT NOT NULL,
    build_commit             TEXT,
    job_name                 TEXT NOT NULL,
    kind                     TEXT NOT NULL,
    status                   TEXT NOT NULL,
    started_at               TIMESTAMPTZ NOT NULL,
    finished_at              TIMESTAMPTZ,
    duration_ms              BIGINT,
    error_msg                TEXT,
    panic_stack              TEXT,
    heap_alloc_before        BIGINT,
    heap_alloc_after         BIGINT,
    heap_sys_before          BIGINT,
    heap_sys_after           BIGINT,
    goroutines_before        INT,
    goroutines_after         INT,
    num_gc_before            BIGINT,
    num_gc_after             BIGINT,
    pause_total_ns_before    BIGINT,
    pause_total_ns_after     BIGINT,
    sys_mem_used_bytes       BIGINT,
    sys_mem_total_bytes      BIGINT
);
CREATE INDEX IF NOT EXISTS idx_job_runs_started_at ON job_runs (started_at DESC);
CREATE INDEX IF NOT EXISTS idx_job_runs_job_name_started_at ON job_runs (job_name, started_at DESC);
`

const logLinesSchema = `
CREATE TABLE IF NOT EXISTS log_lines (
    id      BIGSERIAL PRIMARY KEY,
    ts      TIMESTAMPTZ NOT NULL DEFAULT now(),
    host    TEXT NOT NULL,
    source  TEXT NOT NULL,
    message TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_log_lines_ts ON log_lines (ts DESC);
CREATE INDEX IF NOT EXISTS idx_log_lines_host_ts ON log_lines (host, ts DESC);
`

// EnsureSchemas creates the job_runs and log_lines tables (and their indexes)
// if they don't already exist. No-op when the runner has no DB or is in
// read-only mode.
func (r *Runner) EnsureSchemas(ctx context.Context) error {
	if !r.canWrite() {
		return nil
	}
	if _, err := r.db.ExecContext(ctx, jobRunsSchema); err != nil {
		return fmt.Errorf("joblog: ensure job_runs schema: %w", err)
	}
	if _, err := r.db.ExecContext(ctx, logLinesSchema); err != nil {
		return fmt.Errorf("joblog: ensure log_lines schema: %w", err)
	}
	return nil
}

// insertJobRun writes a single job_runs row.
func (r *Runner) insertJobRun(ctx context.Context, run JobRun) error {
	if !r.canWrite() {
		return nil
	}
	_, err := r.db.ExecContext(ctx, insertJobRunSQL, jobRunArgs(run)...)
	return err
}

// insertJobRunReturningID writes a job_runs row and returns the new id, so a
// "running" row can later be updated in place by recordJobFinish.
func (r *Runner) insertJobRunReturningID(ctx context.Context, run JobRun) (int64, error) {
	if !r.canWrite() {
		return 0, nil
	}
	var id int64
	err := r.db.QueryRowContext(ctx, insertJobRunSQL+" RETURNING id", jobRunArgs(run)...).Scan(&id)
	return id, err
}

// updateJobRun rewrites the terminal-state fields on an existing job_runs row.
// Used to close out a row previously inserted with status="running".
func (r *Runner) updateJobRun(ctx context.Context, id int64, run JobRun) error {
	if !r.canWrite() {
		return nil
	}
	const q = `
		UPDATE job_runs SET
			status = $1,
			finished_at = $2,
			duration_ms = $3,
			error_msg = $4,
			panic_stack = $5,
			heap_alloc_after = $6,
			heap_sys_after = $7,
			goroutines_after = $8,
			num_gc_after = $9,
			pause_total_ns_after = $10,
			sys_mem_used_bytes = COALESCE($11, sys_mem_used_bytes),
			sys_mem_total_bytes = COALESCE($12, sys_mem_total_bytes)
		WHERE id = $13`
	_, err := r.db.ExecContext(ctx, q,
		run.Status,
		nullTime(run.FinishedAt), nullInt64Ptr(run.DurationMs),
		nullStrPtr(run.ErrorMsg), nullStrPtr(run.PanicStack),
		nullInt64Ptr(run.HeapAllocAfter), nullInt64Ptr(run.HeapSysAfter),
		nullIntPtr(run.GoroutinesAfter), nullInt64Ptr(run.NumGCAfter),
		nullInt64Ptr(run.PauseTotalNsAfter),
		nullInt64Ptr(run.SysMemUsedBytes), nullInt64Ptr(run.SysMemTotalBytes),
		id,
	)
	return err
}

const insertJobRunSQL = `
	INSERT INTO job_runs (
		host, build_commit, job_name, kind, status,
		started_at, finished_at, duration_ms,
		error_msg, panic_stack,
		heap_alloc_before, heap_alloc_after,
		heap_sys_before, heap_sys_after,
		goroutines_before, goroutines_after,
		num_gc_before, num_gc_after,
		pause_total_ns_before, pause_total_ns_after,
		sys_mem_used_bytes, sys_mem_total_bytes
	) VALUES (
		$1,$2,$3,$4,$5,
		$6,$7,$8,
		$9,$10,
		$11,$12,
		$13,$14,
		$15,$16,
		$17,$18,
		$19,$20,
		$21,$22
	)`

func jobRunArgs(run JobRun) []any {
	return []any{
		run.Host, nullStr(run.BuildCommit), run.JobName, run.Kind, run.Status,
		run.StartedAt, nullTime(run.FinishedAt), nullInt64Ptr(run.DurationMs),
		nullStrPtr(run.ErrorMsg), nullStrPtr(run.PanicStack),
		nullInt64Ptr(run.HeapAllocBefore), nullInt64Ptr(run.HeapAllocAfter),
		nullInt64Ptr(run.HeapSysBefore), nullInt64Ptr(run.HeapSysAfter),
		nullIntPtr(run.GoroutinesBefore), nullIntPtr(run.GoroutinesAfter),
		nullInt64Ptr(run.NumGCBefore), nullInt64Ptr(run.NumGCAfter),
		nullInt64Ptr(run.PauseTotalNsBefore), nullInt64Ptr(run.PauseTotalNsAfter),
		nullInt64Ptr(run.SysMemUsedBytes), nullInt64Ptr(run.SysMemTotalBytes),
	}
}

// insertLogLines writes a batch of log lines in a single multi-value INSERT.
// Recurses to keep parameter count under Postgres's 65535 cap.
func (r *Runner) insertLogLines(ctx context.Context, lines []LogLine) error {
	if !r.canWrite() || len(lines) == 0 {
		return nil
	}

	const colsPerLine = 4
	maxBatch := 65535 / colsPerLine
	if len(lines) > maxBatch {
		mid := len(lines) / 2
		if err := r.insertLogLines(ctx, lines[:mid]); err != nil {
			return err
		}
		return r.insertLogLines(ctx, lines[mid:])
	}

	var sb strings.Builder
	sb.WriteString(`INSERT INTO log_lines (ts, host, source, message) VALUES `)
	args := make([]any, 0, len(lines)*colsPerLine)
	for i, l := range lines {
		if i > 0 {
			sb.WriteByte(',')
		}
		offset := i * colsPerLine
		fmt.Fprintf(&sb, "($%d,$%d,$%d,$%d)", offset+1, offset+2, offset+3, offset+4)
		args = append(args, l.Timestamp, l.Host, l.Source, l.Message)
	}

	_, err := r.db.ExecContext(ctx, sb.String(), args...)
	return err
}

// pruneLogLines deletes log_lines older than the given cutoff.
func (r *Runner) pruneLogLines(ctx context.Context, olderThan time.Time) (int64, error) {
	if !r.canWrite() {
		return 0, nil
	}
	res, err := r.db.ExecContext(ctx, `DELETE FROM log_lines WHERE ts < $1`, olderThan)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// canWrite reports whether the runner has a writable DB. Sink-only operations
// (timing, local logging) still work when this is false.
func (r *Runner) canWrite() bool {
	return r != nil && r.db != nil && !r.readOnly
}

// Compile-time guard that we accept any *sql.DB-shaped handle.
var _ = (*sql.DB)(nil)

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}
func nullStrPtr(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}
func nullInt64Ptr(v *int64) any {
	if v == nil {
		return nil
	}
	return *v
}
func nullIntPtr(v *int) any {
	if v == nil {
		return nil
	}
	return *v
}
func nullTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return *t
}
