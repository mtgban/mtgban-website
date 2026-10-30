# card_prices long tables

Implements `~/Desktop/card_prices_redesign_plan.md`: one identity space
(`variants`) and a long, date-partitioned `prices(ban_id, date, provider,
price)` table, with a `providers` lookup, in place of the two wide price tables
(`product_prices`, `tcgplayer_nonmagic_product_prices`).

Magic rows are filed under `variants.mtgban_id`, the matcher's id, with the
five alias columns kept for lookups; non-Magic rows have none (`mtgban_id/`
adds the column and backfills it).

The site reads and writes only the long tables for Magic; nothing touches
`product_prices` any more. The tcgcsv ingest writes only the long tables, and
takes its dates from `price_dates`. Everything that has already run against
production, the backfill tools and the one-off repairs alike, is in `retired/`
as text and must not run again; its README says why.

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
