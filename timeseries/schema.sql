create table public.product_prices (
    "date" date not null,
    mtgjson_uuid uuid not null,
    is_foil bool default false not null,
    is_etched bool default false not null,
    "language" text default ''::text not null,
    is_alt bool default false not null,
    cardkingdom_buylist_price numeric(10, 2) null,
    tcgplayer_market_price numeric(10, 2) null,
    tcgplayer_low_price numeric(10, 2) null,
    cardkingdom_retail_price numeric(10, 2) null,
    cardmarket_low_price numeric(10, 2) null,
    cardmarket_trend_price numeric(10, 2) null,
    starcitygames_buylist_price numeric(10, 2) null,
    abu_buylist_price numeric(10, 2) null,
    coolstuffinc_buylist_price numeric(10, 2) null,
    tcgplayer_low_sealed_expected_value numeric(10, 2) null
);

create unique index idx_unique_price_entry on
    public.product_prices
    using btree (date,
    mtgjson_uuid,
    is_foil,
    is_etched,
    language,
    is_alt);

create index idx_uuid_date on
    public.product_prices
    using btree (mtgjson_uuid,
    date);

-- Durable record of cron/background job executions and periodic heartbeats.
-- Created by Client.EnsureJobRunsSchema at boot; kept here for reference.
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
-- pipe-based capture started in main(); pruned to a rolling 14-day window.
create table if not exists log_lines (
    id      bigserial primary key,
    ts      timestamptz not null default now(),
    host    text not null,
    source  text not null,                  -- 'stdout' | 'stderr'
    message text not null
);

create index if not exists idx_log_lines_ts on log_lines (ts desc);
create index if not exists idx_log_lines_host_ts on log_lines (host, ts desc);