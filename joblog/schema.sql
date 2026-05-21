-- Schema kept here for reference. The same DDL is executed at boot by
-- (*joblog.Runner).EnsureSchemas; this file exists so an operator can
-- inspect or recreate the tables without running the Go process.

-- Durable record of cron/background job executions and periodic heartbeats.
create table if not exists job_runs (
    id                       bigserial primary key,
    host                     text not null,
    build_commit             text,
    job_name                 text not null,
    kind                     text not null,            -- 'job' | 'heartbeat'
    status                   text not null,            -- 'success' | 'error' | 'panic' | 'tick'
    started_at               timestamptz not null,
    finished_at              timestamptz,
    duration_ms              bigint,
    error_msg                text,
    panic_stack              text,
    heap_alloc_before        bigint,
    heap_alloc_after         bigint,
    heap_sys_before          bigint,
    heap_sys_after           bigint,
    goroutines_before        int,
    goroutines_after         int,
    num_gc_before            bigint,
    num_gc_after             bigint,
    pause_total_ns_before    bigint,
    pause_total_ns_after     bigint,
    sys_mem_used_bytes       bigint,
    sys_mem_total_bytes      bigint
);

create index if not exists idx_job_runs_started_at on job_runs (started_at desc);
create index if not exists idx_job_runs_job_name_started_at on job_runs (job_name, started_at desc);

-- Captured stdout/stderr lines from the running process. Populated by the
-- pipe-based capture started in StartCapture; pruned to a rolling window by
-- StartLogPruner.
create table if not exists log_lines (
    id      bigserial primary key,
    ts      timestamptz not null default now(),
    host    text not null,
    source  text not null,                  -- 'stdout' | 'stderr' | 'page:Name' | ...
    message text not null
);

create index if not exists idx_log_lines_ts on log_lines (ts desc);
create index if not exists idx_log_lines_host_ts on log_lines (host, ts desc);
