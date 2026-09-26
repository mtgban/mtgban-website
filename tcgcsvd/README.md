# tcgcsvd

Ingests TCGplayer prices and product catalogs for the non-Magic games from
[tcgcsv.com](https://tcgcsv.com) into the shared price database.

tcgcsv stopped serving its daily price archives in September 2026, so the live
per-group price files are the only source of prices right now and history is out
of reach. The archive reader stays here because the archives are still being
recorded upstream, just not published; `docs/tcgcsv-archive-withdrawal.md` has
the notice tcgcsv serves and what a backfill can still do.

This is a library plus a standalone binary. The website imports the library for
its crons and the admin "Ingest TCGCSV" button; `cmd/tcgcsvd` runs the same jobs
as its own process, with no web server, datastore, or template stack loaded.
The two scheduled jobs take the same cross-process Postgres advisory lock before
crawling, so a server with its crons on and a standalone run never hit
tcgcsv.com at once; a run that loses the lock says so and exits 0. The backfill's
archive walk stays outside the lock on purpose — it is operator-driven and can
run for hours, and holding the lock that long would starve the daily pull — but
its snapshot fallback takes it, being the same full crawl the daily job makes.

```
go install github.com/mtgban/mtgban-website/cmd/tcgcsvd@latest
```

## The chosen categories

TCGplayer calls a game a *category*: 2 is Yu-Gi-Oh!, 3 is Pokemon, 71 is Disney
Lorcana. The chosen categories are exactly the games listed under
`tcgcsv_config.games` in `config.json` — the games we support. Nothing is
inferred from tcgcsv.com's full category list: a game we don't list is never
fetched and never stored, so that config block is the only thing deciding what
we carry.

```json
"tcgcsv_config": {
  "user_agent": "mtgban-website (+https://mtgban.com)",
  "games": [
    {"name": "Yu-Gi-Oh!",           "category_id": 2},
    {"name": "Pokemon",             "category_id": 3},
    {"name": "Cardfight Vanguard",  "category_id": 16},
    {"name": "Dragon Ball Super CCG","category_id": 27},
    {"name": "Flesh & Blood",       "category_id": 62},
    {"name": "Digimon",             "category_id": 63},
    {"name": "One Piece",           "category_id": 68},
    {"name": "Disney Lorcana",      "category_id": 71},
    {"name": "Star Wars Unlimited", "category_id": 79},
    {"name": "Riftbound",           "category_id": 89}
  ]
}
```

Magic is deliberately absent: its prices are keyed by mtgjson uuid in
`product_prices` and come from a different pipeline. Categories 21, 69 and 70
are junk per the tcgcsv FAQ and should never be listed.

To see what is configured and how current each game is:

```
$ tcgcsvd -config config.json -games
GAME                     CATEGORY LATEST STORED
Yu-Gi-Oh!                2        2026-08-14
Pokemon                  3        2026-08-14
...
Riftbound                89       2026-08-14
```

`-categories` narrows a single backfill to a subset of those games, for when one
game has a hole and re-fetching the other nine would be wasted work. It can only
narrow: an id that isn't a configured game is an error listing the ones that
are, so a typo can't read as a clean backfill that quietly wrote nothing.

## Adding a game

Add one entry to `tcgcsv_config.games`, then run the daily job:

```
tcgcsvd -config config.json -daily
```

A game with no rows has an empty freshness cursor, so the daily pull ingests it
on its first run while the games already holding the snapshot date skip it. While
the archive is withdrawn that is all the history a new game gets: one day, plus
one a day from there.

Backfill is how the rest arrives once tcgcsv serves the archives again. It keeps
a per-category resume cursor — the newest date already stored for that category —
and skips any day at or below it, so a game added today pulls every day back to
the archive epoch (2024-02-08) while the games that are already current skip all
of them. Nothing already stored is re-ingested or disturbed.

The archives are per-day, not per-game: a day that any category still needs is
downloaded once and the wanted categories are extracted from it. Adding the
eleventh game costs one pass over ~900 archives, not eleven.

Catalog rows (names, collector numbers, rarities, images) are separate and have
no cursor — `-products` is a full refresh of the current catalog every time, so
run it once after adding a game and weekly thereafter.

## Jobs

| Job | What it does | Cadence |
|---|---|---|
| `-daily` | Pulls tcgcsv's current snapshot for every configured game, one request per group. Gates on tcgcsv's `last-updated`, so extra runs are cheap no-ops. | daily, after tcgcsv's ~20:00 UTC refresh |
| `-products` | Refreshes the `tcg_products` catalog for every configured game. | weekly |
| `-backfill` | Fills prices from the daily archives over a date range. With the archives withdrawn it stores the current snapshot instead, when the range covers it. | on demand |

```
tcgcsvd -config config.json -daily
tcgcsvd -config config.json -products
tcgcsvd -config config.json -backfill
tcgcsvd -config config.json -backfill -categories 71 -from 2026-07-08 -to 2026-07-14 -force
```

Each invocation runs one job and exits non-zero on failure, so cron or a systemd
timer can drive it.

Backfill flags:

- `-from` / `-to` bound the range, inclusive; defaults are the archive epoch and
  today. An explicit `-from` fetches the whole range, bypassing the resume
  cursor, which is what closing a gap below the high-water mark requires.
- `-force` does the same without naming a start date.
- The upsert is keyed on `(date, category, product, sub-type)`, so re-covering
  stored days overwrites them in place instead of duplicating them.

While the archives are withdrawn, a backfill gives up after one refused day and
stores the current snapshot in its place — the run above with no arguments still
leaves every game current, and posts a Discord notice saying which range stayed
missing. The last of the four examples, a range wholly in the past, fails instead
and names it: today's prices are not what it asked for, and what it asked for is
gone.

Backfill shells out to a `7z` binary (`p7zip` / `7zz`): the archives use solid
PPMd compression that pure-Go readers do not reliably decode. A missing binary
ends the run on its first day rather than failing 900 times, and it is looked for
only once an archive downloads, so a box without `p7zip` still reports the
archive as withdrawn rather than stopping on the extractor.

## Configuration

`-config` takes a local path or a `b2://` URL, the same two schemes the server
accepts, and falls back to `$BAN_CONFIG_PATH`. A b2 URL needs `BAN_CONFIG_KEY`
and `BAN_CONFIG_SECRET` in the environment. Only four sections are read; the rest
of the server's config is ignored, so the deployed file works unchanged:

- `sql_config` — the price database (a read-only client is refused, loudly,
  rather than reporting a clean run that wrote nothing)
- `tcgcsv_config` — the chosen categories and the User-Agent
- `timeseries_config.long_form_writes` — dual-write into the long `prices` table
- `discord.server_webhook_url` — optional, for job-level success and failure notices

## Running it as its own service

The website still registers the crons when `tcgcsv_config` and a price database
are both present. To move ingestion off the web servers, drop `tcgcsv_config`
from their config (the crons then stay unregistered and the admin button reports
ingestion as unconfigured) and give the box a unit and a timer:

```ini
# /etc/systemd/system/tcgcsvd@.service   —  %i is the job: daily, products
[Unit]
Description=tcgcsv ingest (%i)
After=network.target

[Service]
Type=oneshot
User=koda
EnvironmentFile=/etc/mtgban.env
ExecStart=/usr/local/bin/tcgcsvd -config b2://mtgban-config/magic/config.json -%i
```

```ini
# /etc/systemd/system/tcgcsvd@daily.timer
[Timer]
OnCalendar=*-*-* 21:00:00 UTC

[Install]
WantedBy=timers.target
```

Nothing enforces which process ingests: the crawl lock means several can be
armed at once and only one crawls. That makes the cutover safe in either
direction — stand up the timer first, confirm it wins the lock, then drop the
config from the servers.

## As a library

```go
svc, err := tcgcsvd.New(*cfg.TCGCSVConfig, db,
    tcgcsvd.WithLongFormWrites(cfg.TimeseriesConfig.LongFormWrites),
    tcgcsvd.WithNotifier(ServerNotify),
    tcgcsvd.WithProductReport(logMatchReport))
if err != nil {
    return err
}
go svc.StashPrices()   // single-flight + crawl lock; StashProducts is the same
```

`New` takes any `Store` — `*timeseries.Client` implements it — so the package
carries no assumption about how the caller built its connection pool.
`WithProductReport` exists because the server's match report needs the loaded
mtgmatcher datastore, which a standalone process doesn't have.
