# Non-Magic wide table

`tcgplayer_nonmagic_product_prices` held the tcgcsv ingest's prices, one wide
row per (date, category, product, sub-type), list-partitioned by category. The
ingest now writes only the long tables and takes its resume and freshness dates
from `price_dates`, and nothing reads the wide table, so it is dead weight on
disk. `drop_nonmagic.sql` removes it.

## What it does

In one transaction, with `lock_timeout` at 5 seconds and `statement_timeout`
at 15 minutes, it takes the table's ACCESS EXCLUSIVE lock first, so no write
lands between the checks and the drop. It then checks two things per category,
reading the category list and each category's days along the
`(category_id, date)` index rather than scanning the table:

- its newest wide date is at or below its newest `price_dates` day under
  providers 3 to 7, and it has `price_dates` rows at all;
- every distinct wide date from 13 months ago on, the window `price_dates`
  keeps, is a `price_dates` day for it under providers 3 to 7.

If either fails the script raises, names the categories (with the first few
missing days for the second), and drops nothing. Older days are not checked
here: they rest on the retired backfill's own cross-check of the long tables
against the wide ones (`db_migration/retired/README.md`). It then lists the 12
relations (the parent, the default partition and ten category partitions) with
their sizes and, with `apply=1`, drops the parent, which takes its partitions
with it. `apply` takes only 0 or 1; any other value is refused before anything
runs.

## Running it

Only after the build without the wide write path has served for two nights of
the daily ingest and the stash, with the long tables and `price_dates` fresh,
and after a snapshot of the database volume exists. The standalone ingest,
`/usr/local/bin/tcgcsvd`, must be reinstalled from this build before the drop:
an older copy recreates the table through `EnsureTCGSchema` at its next run and
writes to it again. Run it from this directory
on the direct port, with the connection in the usual `PG*` variables:

```sh
psql -f drop_nonmagic.sql             # check, report, roll back
psql -v apply=1 -f drop_nonmagic.sql  # drop it
```

It is safe to repeat: a second run reports the table absent and exits 0.

## Verifying

```sql
SELECT to_regclass('tcgplayer_nonmagic_product_prices') IS NULL;   -- true
```

The host has the table's size back free, which `df -h` shows.

## Rolling back

There is none in the database: the drop is permanent. The only way back is the
volume snapshot taken before it.
