# card_prices redesign — migration workspace

Implements `~/Desktop/card_prices_redesign_plan.md`: collapses the two wide price
tables (`product_prices`, `tcgplayer_nonmagic_product_prices`) into a unified
identity space (`variants`) + a long, date-partitioned `prices(ban_id, date,
provider, price)` table, with a `providers` lookup.

**Build-alongside:** the old tables are never altered. Reads stay on them until
the Go rewrite (task #7) cuts over. Rollback = point code back at the old tables.

## Checkpointing / resume

All progress lives in the DB, in schema `migration`:
- `migration.progress` — one row per unit of work (`phase`, `chunk_key`, `status`).
- `migration.status` — per-phase rollup view.

Every price chunk runs as a **single atomic statement** (the INSERT and its
`status='done'` update commit together). So killing the driver — or a network
drop — mid-chunk rolls the whole chunk back; nothing is half-written. Re-running
the same command skips `done` chunks and resumes. Idempotent by construction.

### To resume after a disconnect
```bash
cd db_migration
python3 backfill.py status     # see where we are
python3 backfill.py prices     # resume; re-runs any pending/running/error chunks
```

## Order of operations

| # | Command | What it does | Cost |
|---|---------|--------------|------|
| 1 | `python3 backfill.py schema` | Apply `01_schema.sql` + `02_seed_providers.sql` (idempotent) | instant |
| 2 | `python3 backfill.py variants` | Build Magic + non-Magic `variants` (2 full scans) | ~10-40 min |
| 3 | `python3 backfill.py estimate` | Sample-based size/row estimate | seconds |
| 4 | `python3 backfill.py prices` | Backfill all price chunks (resumable) | hours |
| 5 | `psql -f 05_indexes.sql` | PK + `(provider,date)` index + FKs (ban_id FK NOT VALID) | long |
| 6 | `psql -f 06_validate_fk.sql` | VALIDATE ban_id FK (off-peak) | medium |
| 7 | `psql -f 07_verify.sql` | Per-provider parity: source cells == prices rows | heavy |

`psql` connection: driver reads `../config.json` `sql_config`. For raw psql, set
`PGHOST/PGPORT/PGUSER/PGPASSWORD/PGDATABASE/PGSSLMODE` from that block.

## Key facts (measured 2026-07-27)

- Magic `product_prices`: ~161M rows, 2020-09 → 2026-07 (~71 months), 35 GB.
- Non-Magic: **~145M rows** (NOT the 2.97M the plan's stale `reltuples` implied),
  2024-02 → 2026-07, LIST-partitioned by category across ~10 categories.
- Full backfill ≈ **1.23B price rows ≈ 157 GB** (heap ~59 + PK ~49 + 2nd idx ~49).
- `cat_1` partition is empty (droppable); `prices_default` catches strays.

## Decisions (from plan section 0)

Full backfill of **both** Magic and non-Magic. Zeros/nulls omitted (`price > 0`).
Providers 3/4 (TCGLow/TCGMarket) shared across Magic+non-Magic. `ban_id` bigint.
PK `(ban_id, date, provider)`; monthly range partitions. See the plan for D1-D10.

## Chunking

- Magic: one chunk per **month** (`product_prices` has an index on `date`).
- Non-Magic: one chunk per **(category, month)** — the table is partitioned by
  `category_id` with an index on `(category_id, date)`, so a date-only filter
  would scan every partition. `cat<id>-YYYY-MM`.

## Files

- `01_schema.sql` — providers, variants (+partial UKs, identity CHECK), prices
  (partitioned, no PK/indexes yet), `migration.progress` + `migration.status`.
- `02_seed_providers.sql` — 13-provider seed.
- `backfill.py` — the checkpointed driver (all commands above).
- `05_indexes.sql` / `06_validate_fk.sql` / `07_verify.sql` — post-load steps.
