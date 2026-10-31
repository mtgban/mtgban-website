# Repartitioning prices by ban_id

`prices` is partitioned by month. A chart reads one variant across all of
history, so it opens every month's partition. The scripts here build
`prices_v2`, partitioned by `ban_id` range, so that read touches one
partition, and later swap it in for `prices`.

## The layout

Ids from the sequence are below `2^40` (`1099511627776`). Ids derived for
the other games are `category<<40 | product<<8 | subtype`, so a category's
block is `[n<<40, (n+1)<<40)`. `prices_v2` has:

- `prices_seq_01`, `prices_seq_02`, ...: the sequence block cut at bucket
  edges (a bucket is `ban_id >> 12`) so each holds about 90 million rows.
  The first starts at 1 and each ends where the next begins.
- `prices_seq_tail`: from the last cut to `2^40`, empty today, for the ids
  the sequence has yet to issue.
- `prices_cat_<n>`: one per category in `variants`, `n<<40` to `(n+1)<<40`.

The names never collide with the monthly ones. There are no indexes and no
constraints yet; they come after the copy.

The monthly partition script, `../partitions/drop_future.sql`, and its
README apply to `prices` only until the swap: after it there is no monthly
partition and no default one. They are retired in the docs pass after
`prices_old` is dropped.

## Before the census: the build, the disk and the WAL

The Phase C build serves every writer before the census starts: the
Magic, Pokemon and Yu-Gi-Oh droplets, the six App Platform apps (Lorcana,
One Piece, Flesh and Blood, Riftbound, Gundam and Palworld, of which
Gundam and Palworld have no app yet) and `cmd/tcgcsvd`. It reads which
column `prices` is partitioned on, so on the monthly layout it behaves as
before, and after the swap it creates `prices_cat_<n>` for a new category
itself. An old build left on any of them would try to create a monthly
partition after the swap, and its stash would fail.

The copy needs the heap (about 93 GB) plus the indexes (about 190 GB) free.
Either grow the volume to about 700 GB, for good, or attach a second
volume of about 350 GB, create a tablespace on it as the `postgres`
superuser over ssh (the archive role cannot), grant the archive role
`CREATE` on it, and pass its name to `02_create.sql` and
`04_indexes.sql`:

```sql
CREATE TABLESPACE fast LOCATION '/mnt/<second volume>/pg';
GRANT CREATE ON TABLESPACE fast TO <archive role>;
```

Without the grant those scripts, run as the archive role, fail with
"permission denied for tablespace", and after the swap so does every
writer's first write of a new category, whose partition takes the
tablespace of `prices`.

Re-read `df -h /mnt/postgres_database`, and the second volume's mount, the
day the copy starts.

Then the WAL, before the copy starts:

```sql
SELECT * FROM pg_replication_slots; -- none, or each actively consumed
SHOW archive_mode;                  -- when on, archive_command must work:
SELECT * FROM pg_stat_archiver;     -- failed_count still, recent archives
SHOW max_wal_size;
```

The copy and the index builds write roughly the heap plus the indexes in
WAL, on the main volume whichever route. Checkpoints recycle it, and
`max_wal_size` bounds what is kept between them, but a slot nobody consumes
or a failing `archive_command` keeps all of it: drop the slot or fix the
archiving first. The index builds' temp files go to `pg_default` (unless
`temp_tablespaces` names another), so the main volume needs room for a
partition's sort on the second-volume route too.

On the second-volume route, the volume snapshots of steps 7 and 14 cover
both volumes, and are taken with Postgres stopped or right after a
`CHECKPOINT` with the writers held: DigitalOcean's snapshots of two
volumes are not crash-consistent with each other, and the WAL lives on the
main volume only. A restore uses both. On the one-volume route a single
snapshot is enough.

## The writer hold

Steps 8 to 10 run inside the hold, a window in which nothing writes
`prices`. The writers are:

- the stash cron (`0 */12 * * *`, 00:00 and 12:00 UTC) on every game
  deployment: the Magic, Pokemon and Yu-Gi-Oh droplets and the App
  Platform apps (Lorcana, One Piece, Flesh and Blood, Riftbound, and
  Gundam and Palworld once they have one);
- the sealed analysis (`30 */12 * * *`), 30 minutes after each stash;
- `cmd/tcgcsvd`, daily at 21:00 UTC (prices) and Mondays at 22:00 UTC
  (products), and the same two crons inside the site itself on any
  deployment whose config sets `tcgcsv_config` (`startCrons` in
  `jobs.go`);
- the admin page's Take Snapshot and Ingest TCGCSV Prices buttons
  (`tool=snapshot` and `tool=tcgcsv` in `admin.go`), on any deployment;
- any `-tcgcsv-daily`, `-tcgcsv-products` or `-tcgcsv-backfill` run from
  a command line.

The hold is a schedule, not a switch: nothing is stopped. It is the window
from 02:00 to 10:00 UTC, which holds none of them, begun once the 00:00
stash and its sealed analysis show idle on the admin dashboard of every
deployment. Inside it, press no admin button and run no ingest by hand.
The buylist aggregates, the CK signals, the screener and the charts only
read, and run as usual. The times assume each server's clock is UTC:
confirm it before the day. Steps 8 to 10 take minutes; begin them by 03:00
so the window has hours to spare.

## The order

Each script runs from this directory on the direct port, dry first where it
has `apply` unless its step says otherwise. The times are the rehearsal's
on one month (54 M rows, `target_rows` at 10 M), locally; production holds
about 34 times as many.

| step | script | when | on one month, locally | before the next, look at |
|---|---|---|---|---|
| 1 | `01_census.sql` | off-peak, once the build and the disk are in place | 8.5 s | the bounds and `est_rows`; the user approves them |
| 2 | `02_create.sql` | after the census; again whenever a category appears before the swap | 0.3 s | every partition listed as `create`, then as `exists` |
| 3 | `03_copy.sql` | after the create, resumed as needed | 25 s | `migration.status`: every month `done`, its rows the census's |
| 4 | `04_indexes.sql` | after the copy, with the create's `tablespace` | 40 s, the vacuum included | both parent indexes `indisvalid` |
| 5 | `06_gate.sql` on `prices`, `prices_v2`, `prices`, `prices_v2` | in the same hour | 3 s each | the second pair: the aggregate and the movers no slower on `prices_v2` |
| 6 | `05_catchup.sql -v src=prices -v dst=prices_v2`, apply only | the day of the swap, after the 00:00 stash and its analysis, before the hold; `since` the census day minus 7 | 0.3 s | `dst_covers_src` on every provider |
| 7 | a volume snapshot, by the user | before the hold (on the second-volume route, at its start, as above) | | that it completed |
| 8 | `05_catchup.sql -v src=prices -v dst=prices_v2`, apply only | the hold starts; `since` two days back | 0.3 s | a small count, `dst_covers_src` on every provider |
| 9 | `07_swap.sql`, then the restart | inside the hold | 0.3 s | the partition keys it reports; the restart done |
| 10 | `05_catchup.sql -v src=prices_old -v dst=prices`, dry only | right after the restart, inside the hold; `since` the day before the swap | 0.3 s | `rows_inserted_or_changed` 0 and `dst_covers_src` on every provider; then the hold ends |
| 11 | `08_verify.sql` | after the hold, off-peak; `since` step 6's, `swap` the day of the swap | 1.7 s | `prices_covers` in every band and for the totals, both indexes valid |
| 12 | `VALIDATE CONSTRAINT prices_ban_id_fk` | off-peak, during the soak | | `convalidated` true |
| 13 | `VALIDATE CONSTRAINT prices_provider_fk` | off-peak, during the soak | | `convalidated` true |
| 14 | a volume snapshot, by the user | after the week's soak | | that it completed |
| 15 | `09_drop_old.sql` | after the snapshot, outside every writer's window | 2 s | then the cold-read measurement |

Steps 6 and 8 have no dry run: nothing reads `prices_v2` yet, so an apply
changes nothing anyone sees. Step 6 does the days since the census, so
step 8, inside the hold, does only two days and reports a small count.
`since` for step 6 is the census day minus 7, not the day before the copy
started: a stale store's stash files its own scrape date, which can be days
old, and the margin takes in those rows.

`04_indexes.sql` ends with `VACUUM (FREEZE, ANALYZE)`: a freshly filled
table has no visibility map, so its index-only scans read the heap until it
is vacuumed. In the first rehearsal, before the vacuum was part of it, that
made the movers three times slower on `prices_v2`, and no slower after.

The census (step 1) and `08_verify.sql` (step 11) each read whole tables
for hours, holding ACCESS SHARE on `prices` all the while. A writer's
partition create waits behind it and fails under its 5 s `lock_timeout`, so
run neither on the first day of a month nor across the 21:00 UTC ingest.

Start no new game's ingest between the census and the swap if it can be
avoided. If a category appears in `variants` meanwhile, the copy or the
catch-up fails on its rows with no partition of `prices_v2` for them: run
`02_create.sql` again, dry then apply, and it adds that category's
partition, rows copied or not.

## 01_census.sql

One scan of `prices` grouped by source partition, bucket and category into
`migration.census`, then the cuts into `migration.repartition_bounds` with
the rows each is expected to hold. It writes only the `migration` schema,
so it has no `apply`. It reads the whole table, which takes hours: run it
off-peak, from this directory, on the direct port.

```sh
psql -f 01_census.sql
psql -v target_rows=1000 -f 01_census.sql   # a rehearsal with small cuts
```

It runs in one transaction, so a failure leaves the previous census in
place. It raises, before the scan, when `prices` is already partitioned by
`ban_id` and when `prices_default` holds a row: move the row out first, as
"Repairing a stray row" in `../partitions/README.md` shows. The report
lists rows per source month, rows per category, the bounds with
`est_rows`, the totals and the time of the run. Run it again to refresh
the census, which it replaces. It replaces the bounds too until
`02_create.sql` has created `prices_v2`, and keeps them after: they are
what its partitions were cut by, and what a later run of `02_create.sql`
checks them against.

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
it from the parent. Their indexes do not: pass the same tablespace to
`04_indexes.sql`. The script raises when the bounds are empty (run the
census first), when `prices` is already partitioned by `ban_id`, when a
table under a planned name is not that partition with those bounds, and
when a partition still to create overlaps one `prices_v2` has. It runs on a
`prices_v2` that holds rows, to add a category that appeared after the
create; the dry run lists that one partition as `create`. A partition
created after `04_indexes.sql` gets the parent's indexes and foreign keys
with it, and a later run of that script leaves it alone.

## 03_copy.sql, 04_indexes.sql, 05_catchup.sql

`03_copy.sql` copies each monthly partition into `prices_v2`, oldest first,
one statement per month so each commits alone. It records a done row per
month in `migration.progress` (phase `repartition`), so a killed run
resumes at the next month. A month's count must equal the census, or be at
least it for the month still being written; a shortfall rolls that month
back. Each month's copy holds an advisory lock on that month until it
commits, so a run resumed after an ssh session dropped waits on the month
the dropped session's backend is still copying, then skips it, rather than
copying it twice. It and `04_indexes.sql` run outside a transaction block
and have no `apply`: they only fill and index `prices_v2`, which nothing
reads yet.

`04_indexes.sql` creates the parent indexes `ON ONLY`, then builds and
attaches each partition's index, only where one is missing or unattached,
adds the two foreign keys `NOT VALID` and runs `VACUUM (FREEZE, ANALYZE)`,
the freeze sparing the copied rows a later anti-wraparound vacuum. It ends
by reporting `indisvalid` of both parent indexes. An index goes to the
default tablespace whatever its table's, so with `-v tablespace=fast` the
parent and partition indexes (about twice the heap) are built there too;
give it the tablespace `02_create.sql` was given.

`05_catchup.sql` upserts the rows of `src` dated on or after `since` into
`dst`, run before the swap to pick up what was written meanwhile:

```sh
psql -v src=prices -v dst=prices_v2 -v since=2026-10-22 -v apply=1 -f 05_catchup.sql
psql -v src=prices -v dst=prices_v2 -v since=2026-10-31 -v apply=1 -f 05_catchup.sql
```

The first is step 6, the second step 8 inside the hold. It reports the rows
inserted or changed and, per provider, the latest date and the row count in
both tables and `dst_covers_src`: `dst` holds at least as many rows since
`since` as `src`, and as late a day. Before the swap nothing but the
catch-up writes `prices_v2`, so a false there means the catch-up missed
rows: run it again. After the swap (`src=prices_old`, `dst=prices`), step
10, see the restart below. Run no backfill or repair while any of them
runs.

To start the copy over, `TRUNCATE public.prices_v2` and
`DELETE FROM migration.progress WHERE phase = 'repartition'`; the table
also holds the earlier backfill phases, so never truncate it. A static
month that raises on a surplus received rows after the census: re-run
`01_census.sql`, which counts them and keeps the bounds, then
`03_copy.sql`.

## 06_gate.sql

`EXPLAIN (ANALYZE, BUFFERS, SUMMARY)` of the three reads the new layout
could slow, the table substituted: the 90-day buylist aggregate of
`GetAggregatePriceStatsLong`, the Magic movers rows of
`buildMoverRowsQuery` (provider 3, the latest day and the one a week before
it, taken from `price_dates` as `moverAnchor` takes them), and the chart
read `hgetAllByBanIDQuery` over ten years. Read-only, with a 10 minute
`statement_timeout` for the session.

```sh
psql -v table=prices -v ban=123456 -f 06_gate.sql
psql -v table=prices_v2 -v ban=123456 -f 06_gate.sql
psql -v table=prices -v ban=123456 -f 06_gate.sql
psql -v table=prices_v2 -v ban=123456 -f 06_gate.sql
```

Run it four times in the same hour, alternating the tables as above, keep
every output and judge the second pair: the first pair warms the caches
for the other table, as the rehearsal did. The chart read takes `ban` as a
literal, so the planner prunes partitions while planning and its planning
time is not the prepared statement's in production; compare the execution
times. `ban` is an id nothing has read lately, the same for all four;
`provider` (default 2) picks the aggregate's buylist. The swap goes ahead
only if the aggregate and the movers are no slower on `prices_v2`; if one
is, the swap waits and that query is rewritten first.

## 07_swap.sql

```sh
psql -f 07_swap.sql              # check, list the renames, roll back
psql -v apply=1 -f 07_swap.sql
```

It raises unless `prices` is partitioned by `date` and has its
`prices_provider_date`, `prices_v2` is partitioned by `ban_id` with both
parent indexes valid and both foreign keys, neither `prices_old` nor
`prices_uk` exists, every month source of the census has a done row in
`migration.progress` with at least the census's rows (it names the first
month that has not), `prices_v2` has the owner and the grants of `prices`,
and every provider's latest day is the same in both tables (else run the
catch-up). `CREATE TABLE ... LIKE` copies no grants: when that check
refuses, its DETAIL shows both owners and ACLs; run the `GRANT ... ON
prices_v2` (or `ALTER TABLE prices_v2 OWNER TO`) that makes them match,
then the swap again. The check compares the ACL text, so a NULL ACL and an
explicit owner-only one refuse although they grant the same; the HINT's
`GRANT`, or `REVOKE ALL ON prices_v2 ...; GRANT ...` to match exactly,
settles it.

The apply locks both tables ACCESS EXCLUSIVE with a 5 s `lock_timeout`,
checks the latest days again under the lock, and renames in one
transaction: `prices_provider_date` to `prices_old_provider_date`,
`prices` to `prices_old`, `prices_v2` to `prices`, `prices_v2_uk` to
`prices_uk`, `prices_v2_provider_date` to `prices_provider_date`, and the
two foreign keys to `prices_ban_id_fk` and `prices_provider_fk`. A second
run raises: `prices` is then partitioned by `ban_id`.

`RENAME CONSTRAINT` does not recurse, so the partitions there at the swap
keep child foreign keys named `prices_v2_*_fk` while later ones get
`prices_*_fk`. Only the names differ.

## The restart after the swap

Right after the commit, restart the sites on the Magic, Pokemon and
Yu-Gi-Oh droplets and `cmd/tcgcsvd`; the App Platform apps restart at
their next deploy or by hand. Their chart reads are prepared statements
(`stmtHGetAllLong`, `stmtHGetAllByBanID`), and the restart has them
planned afresh on the new table. In the rehearsal a statement prepared
before the swap re-planned onto the new `prices` by itself on its next
run, so the restart is a precaution rather than a repair. Then step 10, the catch-up from
`prices_old`, as a dry run:

```sh
psql -v src=prices_old -v dst=prices -v since=2026-11-01 -f 05_catchup.sql
```

The writers are held from step 8 to here, so nothing has written `prices`
since the swap and `prices_old` holds nothing `prices` lacks: the dry run
must report `rows_inserted_or_changed` 0 and `dst_covers_src` true on every
provider. Then skip the apply, which would change nothing and only open a
window in which it could: it overwrites a price in `prices` with
`prices_old`'s wherever the two differ, including one a writer set after
the swap (the rehearsal saw it revert 20 such rows). A count above 0 means
a writer ran inside the hold: stop and look, and apply nothing. Then the
hold ends and the writers resume. Never run this catch-up's apply once they
have.

## 08_verify.sql

```sh
psql -v since=2026-10-22 -v swap=2026-11-02 -f 08_verify.sql
```

`since` is step 6's, `swap` the day of the swap. Read-only, in one
REPEATABLE READ transaction so every section reads the same snapshot, with
a 4 h `statement_timeout` (it counts both tables whole, so off-peak, not
on the first day of a month and not across the 21:00 UTC ingest). After
the swap the writers reach only `prices`, so it reads in three bands:

- `since <= date < swap`: per provider, the rows and the latest day in
  `prices` and `prices_old`, and `missing`, the rows of `prices_old` whose
  key `prices` lacks. `prices_covers` must be true on every provider:
  none is missing. More rows in `prices` is normal: a writer resumed
  after the hold can still file a day before the swap (the 21:00 UTC
  ingest files the day of tcgcsv's last refresh, the day before when it
  is late; a stale store's stash its own scrape date), and the check goes
  by key so those rows cannot hide a missing one. A false means a row the
  catch-ups missed, so look before the drop, and consider the rollback.
- `date >= swap`: `prices_covers` must be true on every provider: `prices`
  holds at least the rows of `prices_old` and as late a day. More is
  normal: the writers resumed after step 10 and write `prices` only. A
  false means a writer ran inside the hold: investigate before anything
  else. Never apply the catch-up from `prices_old` after the writers
  resume; its `DO UPDATE` would revert the prices they wrote.
- `date < since`: per month and provider, `prices` must hold at least the
  rows of `prices_old`. Only the rows where it does not are listed, then
  one line for all, whose `prices_covers` is the pass. A false is a row
  dated before `since` but written after its month was copied (a stale
  store files its own scrape date) that no catch-up took in: look before
  the drop.

Then each whole table's count, `prices`'s at least `prices_old`'s, the
partitions of `prices` with their heap size, and whether its two parent
indexes are valid.

## The foreign keys during the soak

The swap brings both foreign keys over `NOT VALID`. Validate them off-peak
during the soak, one after the other; each takes SHARE UPDATE EXCLUSIVE,
which lets reads and writes through, and scans `prices` once:

```sql
ALTER TABLE prices VALIDATE CONSTRAINT prices_ban_id_fk;
ALTER TABLE prices VALIDATE CONSTRAINT prices_provider_fk;
```

## 09_drop_old.sql

```sh
psql -f 09_drop_old.sql              # check, roll back
psql -v apply=1 -f 09_drop_old.sql
```

After the week's soak and a volume snapshot, outside every writer's window.
It raises unless `prices` is partitioned by `ban_id` and `prices_old`
exists, so a second run drops nothing. The apply drops `prices_old` with a
5 s `lock_timeout`, commits, then analyzes `prices`. Dropping its foreign
keys' triggers takes `variants` and `providers` ACCESS EXCLUSIVE as well,
so the drop fails while a long `variants` reader runs, and holds the
readers of both up to those 5 s while it waits.

## Rollback

- Before the swap: `DROP TABLE prices_v2`. Nothing production reads has
  changed.
- After the swap, before the drop: hold the writers, the reverse renames
  in one transaction, the restart, then `05_catchup.sql -v src=prices_v2
  -v dst=prices` since the day of the swap minus 7, for what the writers
  put in the new table in between: they file days before the swap too, as
  `08_verify.sql` says, and the margin is step 6's. The writers stay held
  from the rename until that catch-up is done: apply it, then run it
  again, and the second run must report 0 rows inserted or changed
  (anything else is a writer inside the hold, whose prices the apply has
  just overwritten); then let them resume:

  ```sql
  BEGIN;
  SET LOCAL lock_timeout = '5s';
  LOCK TABLE prices, prices_old IN ACCESS EXCLUSIVE MODE;
  ALTER TABLE prices RENAME CONSTRAINT prices_ban_id_fk TO prices_v2_ban_id_fk;
  ALTER TABLE prices RENAME CONSTRAINT prices_provider_fk TO prices_v2_provider_fk;
  ALTER INDEX prices_provider_date RENAME TO prices_v2_provider_date;
  ALTER INDEX prices_uk RENAME TO prices_v2_uk;
  ALTER TABLE prices RENAME TO prices_v2;
  ALTER TABLE prices_old RENAME TO prices;
  ALTER INDEX prices_old_provider_date RENAME TO prices_provider_date;
  COMMIT;
  ```

- After the drop: the volume snapshot taken before it. On the
  second-volume route that is both volumes' snapshots, taken together as
  the disk section says, and restored together.

## Moving off a temporary tablespace

If `02_create.sql` and `04_indexes.sql` put `prices_v2` on the tablespace
of a temporary volume, move it back once `prices_old` is dropped and the
main volume has the room, one relation at a time, off-peak. Per
partition, its table and its two indexes:

```sql
SET lock_timeout = '5s';
ALTER TABLE prices_seq_01 SET TABLESPACE pg_default;
ALTER INDEX prices_seq_01_uk SET TABLESPACE pg_default;
ALTER INDEX prices_seq_01_provider_date SET TABLESPACE pg_default;
```

Each statement holds an ACCESS EXCLUSIVE lock on that partition for as
long as its copy takes, so the chart reads and the writes of the id range
it holds are blocked for the move's length. The `lock_timeout` only keeps a
statement from queuing behind a long reader. If the volume must go and that
wait cannot be afforded, pg_repack moves a table to another tablespace
without holding the lock for the copy. Then the parent and its two
indexes, which move no rows, only where new partitions and their indexes
go:

```sql
ALTER TABLE prices SET TABLESPACE pg_default;
ALTER INDEX prices_uk SET TABLESPACE pg_default;
ALTER INDEX prices_provider_date SET TABLESPACE pg_default;
```

`SELECT relname FROM pg_class WHERE reltablespace = (SELECT oid FROM
pg_tablespace WHERE spcname = 'fast')` lists what is left; when it is
empty, drop the tablespace and delete the volume.

## The cold-read measurement after the drop

Once `prices_old` is gone, take ids nothing has read since the last
restart and run `06_gate.sql -v table=prices -v ban=<id>` for a few of
them: its chart read is the one measured on the monthly layout before
Phase C. Record the planning and execution times and the buffers read
beside those numbers. A cold read is cold only once, so use fresh ids each
time.
