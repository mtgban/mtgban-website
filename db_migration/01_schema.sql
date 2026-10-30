-- card_prices redesign — schema (build alongside the existing tables).
-- Idempotent: safe to re-run. Creates providers, variants, prices (+partitions),
-- and the migration progress/checkpoint objects. Does NOT touch product_prices
-- or tcgplayer_nonmagic_product_prices.
--
-- Reference: ~/Desktop/card_prices_redesign_plan.md (consolidated DDL 17.9).
-- Load-speed note: prices is created WITHOUT its PK / secondary index / FKs so the
-- bulk backfill runs fast; those are added afterward by 05_indexes.sql.

-- ---------------------------------------------------------------------------
-- Checkpoint / progress tracking (its own schema so `public` stays clean).
-- ---------------------------------------------------------------------------
CREATE SCHEMA IF NOT EXISTS migration;

CREATE TABLE IF NOT EXISTS migration.progress (
    phase        text        NOT NULL,   -- 'variants_magic' | 'variants_nonmagic' | 'prices_magic' | 'prices_nonmagic'
    chunk_key    text        NOT NULL,   -- 'YYYY-MM' (magic) | 'cat<id>-YYYY-MM' (non-magic) | 'all'
    status       text        NOT NULL DEFAULT 'pending',   -- pending | running | done | error
    rows_written bigint,
    started_at   timestamptz,
    finished_at  timestamptz,
    error_msg    text,
    PRIMARY KEY (phase, chunk_key)
);

-- Human-readable rollup: one line per phase.
CREATE OR REPLACE VIEW migration.status AS
SELECT phase,
       count(*) FILTER (WHERE status = 'done')    AS chunks_done,
       count(*) FILTER (WHERE status = 'running') AS chunks_running,
       count(*) FILTER (WHERE status = 'error')   AS chunks_error,
       count(*)                                   AS chunks_total,
       round(100.0 * count(*) FILTER (WHERE status = 'done') / NULLIF(count(*), 0), 1) AS pct_done,
       coalesce(sum(rows_written) FILTER (WHERE status = 'done'), 0) AS rows_written,
       min(started_at)  AS first_started,
       max(finished_at) AS last_finished
FROM migration.progress
GROUP BY phase
ORDER BY phase;

-- ---------------------------------------------------------------------------
-- providers: 13-row lookup. kind is informational (plan 17.6).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.providers (
    id          smallint    PRIMARY KEY,
    shorthand   text        NOT NULL UNIQUE,
    public_name text        NOT NULL,
    kind        text        NOT NULL,               -- 'retail' | 'buylist' | 'derived'
    currency    char(3)     NOT NULL DEFAULT 'USD'
);

-- ---------------------------------------------------------------------------
-- variants: one row per identity. ban_id is bigint (plan 17.1). A variant is
-- either Magic (mtgjson_uuid set, tcgp_* null) or non-Magic (tcgp_* set,
-- mtgjson_uuid null); the CHECK enforces that split and guarantees a non-Magic
-- variant never has a NULL sub_type (so partial-index NULL-distinctness can't
-- admit duplicates — plan 17.2 / section 12 note).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.variants (
    ban_id           bigint  GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    mtgjson_uuid     uuid,                            -- NULL for non-Magic
    is_foil          boolean NOT NULL DEFAULT false,
    is_etched        boolean NOT NULL DEFAULT false,
    is_alt           boolean NOT NULL DEFAULT false,
    language         text    NOT NULL DEFAULT '',
    tcgp_category_id integer,                         -- NOT NULL for non-Magic
    tcgp_product_id  integer,                         -- NOT NULL for non-Magic
    tcgp_sub_type    text,                            -- NOT NULL ('' if none) for non-Magic
    mtgban_id        text,                            -- the matcher's id; NULL for non-Magic and for printings the datastore no longer knows
    CONSTRAINT variants_identity_ck CHECK (
        (mtgjson_uuid IS NOT NULL
             AND tcgp_category_id IS NULL AND tcgp_product_id IS NULL AND tcgp_sub_type IS NULL)
        OR
        (mtgjson_uuid IS NULL
             AND tcgp_category_id IS NOT NULL AND tcgp_product_id IS NOT NULL AND tcgp_sub_type IS NOT NULL)
    )
);

-- Magic identity (partial: excludes non-Magic rows). Also the backfill join key.
CREATE UNIQUE INDEX IF NOT EXISTS variants_mtg_uk ON public.variants
    (mtgjson_uuid, is_foil, is_etched, is_alt, language)
    WHERE mtgjson_uuid IS NOT NULL;

-- The matcher's id (partial: NULL until backfilled, and for non-Magic).
CREATE UNIQUE INDEX IF NOT EXISTS variants_mtgban_id_uk ON public.variants
    (mtgban_id)
    WHERE mtgban_id IS NOT NULL;

-- Non-Magic identity (partial). Also the backfill join key.
CREATE UNIQUE INDEX IF NOT EXISTS variants_tcg_uk ON public.variants
    (tcgp_category_id, tcgp_product_id, tcgp_sub_type)
    WHERE tcgp_product_id IS NOT NULL;

-- ---------------------------------------------------------------------------
-- prices: long fact table, RANGE partitions on ban_id. Zeros omitted (D3).
-- Created WITHOUT indexes / FKs: 05_indexes.sql adds them after the bulk load.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.prices (
    ban_id   bigint        NOT NULL,
    date     date          NOT NULL,
    provider smallint      NOT NULL,
    price    numeric(10,2) NOT NULL
) PARTITION BY RANGE (ban_id);

-- One block for the sequence ids. Production's block is cut by the census
-- (db_migration/repartition/); the writers create prices_cat_<n> for each
-- non-Magic category's block [n<<40, (n+1)<<40) on its first write. No default.
CREATE TABLE IF NOT EXISTS public.prices_seq PARTITION OF public.prices
    FOR VALUES FROM (1) TO (1099511627776);
