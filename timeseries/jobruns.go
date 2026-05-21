package timeseries

import (
	"context"
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
	Status      string // "success", "error", "panic", "tick"
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

// EnsureJobRunsSchema creates the job_runs table and its indexes if they do
// not already exist. No-op on read-only clients.
func (c *Client) EnsureJobRunsSchema(ctx context.Context) error {
	if c.readOnly {
		return nil
	}
	_, err := c.db.ExecContext(ctx, jobRunsSchema)
	return err
}

// InsertJobRun writes a single job_runs row. No-op on read-only clients.
func (c *Client) InsertJobRun(ctx context.Context, run JobRun) error {
	if c.readOnly {
		return nil
	}
	const q = `
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
	_, err := c.db.ExecContext(ctx, q,
		run.Host, nullStr(run.BuildCommit), run.JobName, run.Kind, run.Status,
		run.StartedAt, nullTime(run.FinishedAt), nullInt64Ptr(run.DurationMs),
		nullStrPtr(run.ErrorMsg), nullStrPtr(run.PanicStack),
		nullInt64Ptr(run.HeapAllocBefore), nullInt64Ptr(run.HeapAllocAfter),
		nullInt64Ptr(run.HeapSysBefore), nullInt64Ptr(run.HeapSysAfter),
		nullIntPtr(run.GoroutinesBefore), nullIntPtr(run.GoroutinesAfter),
		nullInt64Ptr(run.NumGCBefore), nullInt64Ptr(run.NumGCAfter),
		nullInt64Ptr(run.PauseTotalNsBefore), nullInt64Ptr(run.PauseTotalNsAfter),
		nullInt64Ptr(run.SysMemUsedBytes), nullInt64Ptr(run.SysMemTotalBytes),
	)
	return err
}

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
