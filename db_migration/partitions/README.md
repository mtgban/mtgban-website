# Future price partitions

`prices` was created with a partition for every month up to 2028-12, so the
archive carried a long tail of empty ones the planner had to consider.
On the monthly layout `UpsertLongPrices` creates the partitions for the
months it writes plus the next one. The monthly loop that pre-created them
was `01_schema.sql` before the repartition; a fresh database's schema is now
partitioned by `ban_id`.
`drop_future.sql` removes the empty ones already there.

All of this applies to the monthly layout only, so only until the
repartition's swap (`../repartition/README.md`): after it `prices` is
partitioned by `ban_id`, has no monthly partitions and no default one, and
the script has nothing to drop. It and this README are retired in the docs
pass after `prices_old` is dropped. Until then the stray-row repair below
is the one the census refuses on.

## What it does

In one transaction, with `lock_timeout` at 5 seconds and `statement_timeout`
at 15 minutes, it takes one ACCESS EXCLUSIVE lock on `prices` before anything
else, so no write reaches a partition between its check and its drop. It then
lists every `prices` partition whose lower bound is at or after the first day
of the month after next, checks each with `SELECT EXISTS (SELECT 1 FROM ...)`,
and drops them. The default partition and the current and next months are
never touched. If a candidate holds a row the script raises, naming it, and
drops nothing: a row there means a stash already ran past the pre-created
months.

The script decides by the current date, so run the dry run and the apply in
the same month. `apply` takes only 0 or 1; any other value is refused before
anything runs.

## Running it

Only after the build with the `UpsertLongPrices` change is serving everywhere
that writes prices (the Magic droplet, the non-Magic apps, `cmd/tcgcsvd`),
otherwise a write for a dropped month lands in `prices_default`. Run it from
this directory on the direct port, outside the write windows, with the
connection in the usual `PG*` variables:

```sh
psql -f drop_future.sql             # report the partitions, roll back
psql -v apply=1 -f drop_future.sql  # drop them
```

It is safe to repeat: a second run finds nothing to drop.

The report ends with three numbers, the same on a dry run and an apply:
`partitions_now` is how many partitions `prices` has when the script starts,
`candidates` how many it would drop (the ones listed), and
`partitions_after_apply` the difference.

## Verifying

```sql
SELECT count(*) FROM pg_inherits WHERE inhparent = 'prices'::regclass;
SELECT count(*) FROM prices_default;   -- 0
```

The first is the historical months, the current month, next month and the
default partition. The second stays 0 once the writers create their months.

## Repairing a stray row

A row in `prices_default` stops every later create of the partition it
belongs in, so the month's writes fail until it is moved out. Move it in one
transaction on the direct port, with the month's bounds in place of the dates
below:

```sql
BEGIN;
SET LOCAL lock_timeout = '5s';
CREATE TEMP TABLE stray (LIKE prices) ON COMMIT DROP;
WITH moved AS (
    DELETE FROM prices_default
    WHERE date >= '2027-01-01' AND date < '2027-02-01'
    RETURNING *
)
INSERT INTO stray SELECT * FROM moved;
CREATE TABLE prices_2027_01 PARTITION OF prices
    FOR VALUES FROM ('2027-01-01') TO ('2027-02-01');
INSERT INTO prices SELECT * FROM stray;
COMMIT;
```

The stray-row alarm clears at the next hourly staleness check.

## Rolling back

Nothing is lost, the partitions were empty. Create any month needed again:

```sql
CREATE TABLE prices_2027_01 PARTITION OF prices
    FOR VALUES FROM ('2027-01-01') TO ('2027-02-01');
```
