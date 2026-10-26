# Retired scripts

Everything here has done its one job against production and is kept as the
record of it. Each is text that stops on its first line, so none runs by
accident. To run one on purpose, copy it back into `db_migration/` under its
old name, drop the stop line, and first read every step against the tables as
they are now.

## Backfill tools

These built the long tables (`variants`, `prices`) from the wide
`product_prices` and `tcgplayer_nonmagic_product_prices`, and checked the two
against each other. The site has read only the long tables since 2026-10-02, so
they have nothing left to do, and each would now do harm:

| File | What it did | Run today |
|---|---|---|
| `backfill.py.txt` | The checkpointed driver: schema, variants, price chunks | Re-mints the variants 09 folded and refills them |
| `08_catchup.sql.txt` | Re-mint variants and re-insert a recent window | The same, from `since` on |
| `07_verify.sql.txt` | Per-provider parity of the long tables against the wide ones | Reports the rows 09 and 10 moved as differences |

The wide rows written before 09 carry mtgjson's `isAlternative` in `is_alt`,
where the long tables now hold it only on the Alternate Fourth Edition copies,
so anything rebuilt from them brings the old split back.

## One-off repairs

| File | What it did | Ran |
|---|---|---|
| `09_alt_copies.sql.txt` | Kept `is_alt` only on the 378 Alternate Fourth Edition copies, folding every other `is_alt` variant into its plain twin | 2026-10-25 |
| `10_alt_copy_prices.sql.txt` | Put back the prices the copies and their 4ED originals filed on each other's variants | 2026-10-25 |
| `11_wide_only_prices.sql.txt` | Copied in the 385,857 Magic prices only `product_prices` held (2026-08-27 and six from September 2026) | with #1118 |
| `12_native_language.sql.txt` | Folded the empty-language variant of 1,668 printings native to another language into their language variant, the one the stash writes | 2026-10-26 |
| `13_foil_only_cards.sql.txt` | Moved the backfill's nonfoil prices of 13,376 foil-only and etched-only cards onto their foil or etched variant | 2026-10-26 |

## How the backfill worked

All progress lived in the DB, in schema `migration`: `migration.progress` held
one row per unit of work (`phase`, `chunk_key`, `status`), and
`migration.status` rolled it up per phase. Each price chunk ran as one atomic
statement, the INSERT and its `status='done'` update committing together, so a
killed driver or a dropped connection rolled the chunk back and a re-run
resumed from the last committed one.

Magic ran one chunk per month (`product_prices` has an index on `date`).
Non-Magic ran one per (category, month), `cat<id>-YYYY-MM`, since that table is
partitioned by `category_id` with an index on `(category_id, date)` and a
date-only filter would scan every partition.

Zeros and nulls were left out (`price > 0`). Providers 3 and 4 (TCGLow,
TCGMarket) are shared between Magic and non-Magic.

Measured 2026-07-27, before the backfill:

- Magic `product_prices`: about 161M rows, 2020-09 to 2026-07, 35 GB.
- Non-Magic: about 145M rows, 2024-02 to 2026-07, LIST-partitioned by category
  across about 10 categories.
- Full backfill: about 1.23B price rows, about 157 GB (heap 59, primary key 49,
  second index 49).
