# card_prices long tables

Implements `~/Desktop/card_prices_redesign_plan.md`: one identity space
(`variants`) and a long, date-partitioned `prices(ban_id, date, provider,
price)` table, with a `providers` lookup, in place of the two wide price tables
(`product_prices`, `tcgplayer_nonmagic_product_prices`).

The site reads only the long tables. The stash still writes `product_prices`
alongside them, and nothing reads it. The tools that backfilled the long tables
from the wide ones are in `retired/` and must not run again; its README says
why.

## A fresh database

| # | Command | What it does | Cost |
|---|---------|--------------|------|
| 1 | `psql -f 01_schema.sql` | providers, variants (+partial UKs, identity CHECK), prices (partitioned, no PK/indexes yet) | instant |
| 2 | `psql -f 02_seed_providers.sql` | 13-provider seed | instant |
| 3 | `psql -f 05_indexes.sql` | PK + `(provider,date)` index + FKs (ban_id FK NOT VALID) | long on a loaded table |
| 4 | `psql -f 06_validate_fk.sql` | VALIDATE ban_id FK (off-peak) | medium |

`PK (ban_id, date, provider)`, monthly range partitions, `ban_id` bigint. See
the plan for D1-D10.

For psql, set `PGHOST/PGPORT/PGUSER/PGPASSWORD/PGDATABASE/PGSSLMODE` from the
`sql_config` block of `../config.json` (the deployed configs keep it in
`infrastructure.json`).

## One-off repairs

- `09_alt_copies.sql`, then `10_alt_copy_prices.sql`: file `is_alt` only on the
  Alternate Fourth Edition copies, and put back the prices those copies and
  their 4ED originals filed on each other's variants. Both ran on 2026-10-25.
