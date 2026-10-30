# Repartitioning prices by ban_id

`prices` is partitioned by month. A chart reads one variant across all of
history, so it opens every month's partition. The scripts here build
`prices_v2`, partitioned by `ban_id` range, so that read touches one
partition, and later swap it in for `prices`.

## The layout

Ids from the sequence are below `2^40` (`1099511627776`). Ids derived for the
other games are `category<<40 | product<<8 | subtype`, so a category's block
is `[n<<40, (n+1)<<40)`. `prices_v2` has:

- `prices_seq_01`, `prices_seq_02`, ...: the sequence block cut at bucket
  edges (a bucket is `ban_id >> 12`) so each holds about 90 million rows. The
  first starts at 1 and each ends where the next begins.
- `prices_seq_tail`: from the last cut to `2^40`, empty today, for the ids
  the sequence has yet to issue.
- `prices_cat_<n>`: one per category in `variants`, `n<<40` to `(n+1)<<40`.

The names never collide with the monthly ones. There are no indexes and no
constraints yet; they come after the copy.

## 01_census.sql

One scan of `prices` grouped by source partition, bucket and category into
`migration.census`, then the cuts into `migration.repartition_bounds` with
the rows each is expected to hold. It writes only the `migration` schema, so
it has no `apply`. It reads the whole table, which takes hours: run it
off-peak, from this directory, on the direct port.

```sh
psql -f 01_census.sql
psql -v target_rows=1000 -f 01_census.sql   # a rehearsal with small cuts
```

It runs in one transaction, so a failure leaves the previous census in
place. It raises, before the scan, when `prices` is already partitioned by
`ban_id` and when `prices_default` holds a row (repair it first,
`../partitions/README.md`). The report lists rows per source month, rows per
category, the bounds with `est_rows`, the totals and the time of the run. Run
it again to refresh the cuts; it replaces both tables.

## 02_create.sql

Creates `prices_v2` and one partition per bounds row and per category, with
`IF NOT EXISTS` throughout, so a second run creates nothing. The dry run
lists each partition with its bounds and whether it exists, then rolls back.

```sh
psql -f 02_create.sql                                      # list, roll back
psql -v apply=1 -f 02_create.sql                           # create
psql -v apply=1 -v tablespace=fast -f 02_create.sql        # on a tablespace
```

`apply` takes only 0 or 1. The tablespace is optional; the partitions take
it from the parent. The script raises when the bounds are empty (run the
census first), when `prices` is already partitioned by `ban_id`, when
`prices_v2` holds a row, and when a table under a planned name is not that
partition with those bounds.
