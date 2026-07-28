-- Run AFTER the prices backfill completes (task: build indexes + FK).
-- IDEMPOTENT: safe to re-run. If a build is interrupted mid-way, the incomplete
-- object rolls back and re-running skips already-built objects and resumes.
-- Safe to run while the old tables still serve all reads: nothing reads the new
-- prices table until code cutover, so the ACCESS EXCLUSIVE locks are harmless.
-- On a partitioned table each index/PK builds per-partition, so sort temp stays
-- small (one partition at a time), not one giant sort.
\timing on

-- Session tuning for the build (all USERSET, no superuser needed). Parallel
-- workers share maintenance_work_mem, so total memory stays ~1GB.
SET maintenance_work_mem = '1GB';
SET max_parallel_maintenance_workers = 2;
SET synchronous_commit = off;

-- Primary key (D6). Includes date because a range-partitioned unique constraint
-- must contain the partition key. Also the definitive duplicate check: fails if
-- any (ban_id, date, provider) is duplicated.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conname='prices_pkey' AND conrelid='public.prices'::regclass) THEN
        RAISE NOTICE 'building prices_pkey ...';
        ALTER TABLE public.prices ADD CONSTRAINT prices_pkey PRIMARY KEY (ban_id, date, provider);
    ELSE
        RAISE NOTICE 'prices_pkey exists, skipping';
    END IF;
END $$;

-- Per-provider analytics scans (D7): GetAggregatePriceStats / GetMovers scan one
-- provider across many cards since a date. INCLUDE keeps it index-only.
CREATE INDEX IF NOT EXISTS prices_provider_date ON public.prices (provider, date)
    INCLUDE (ban_id, price);

-- Provider FK: referenced table is 13 rows, validation is trivial — add validated.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conname='prices_provider_fk' AND conrelid='public.prices'::regclass) THEN
        ALTER TABLE public.prices ADD CONSTRAINT prices_provider_fk
            FOREIGN KEY (provider) REFERENCES public.providers(id);
    END IF;
END $$;

-- ban_id FK: NOT VALID now (new writes checked, backfill pays nothing); VALIDATE
-- off-peak via 06_validate_fk.sql (D8).
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conname='prices_ban_id_fk' AND conrelid='public.prices'::regclass) THEN
        ALTER TABLE public.prices ADD CONSTRAINT prices_ban_id_fk
            FOREIGN KEY (ban_id) REFERENCES public.variants(ban_id) NOT VALID;
    END IF;
END $$;

ANALYZE public.prices;
\echo === indexes/FKs done (remember to VALIDATE the ban_id FK off-peak) ===
