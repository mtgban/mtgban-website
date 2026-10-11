# Price history on API v2

Design for a v2 endpoint that serves a card's price history from the
archive the site's charts read, in a shape that matches v2's prices.
Built on the site (`api_history.go`); the gateway's part is listed under
Rollout. The decisions are marked, and what stays open is at the end.

## What it serves

`GET /api/v2/history/{ids}.json` on a game host, and
`GET https://api.mtgban.com/v2/{game}/history/{ids}.json` through the
gateway, with `.csv` in place of `.json` for the same points as a table.
One route, `/api/v2/history/`, serves every form:

- `history/{id}.json` is one card or sealed product, resolved the way the
  v1 and v2 price APIs resolve a single card (`finishUUIDs`: the printing's
  uuid, then the rest of `FinishSiblings`, its finishes and the set-mates
  filed as its finish twins), so every finish of the printing comes back
  in one response.
- `history/{a},{b},{c}.json` is a batch: card ids separated by commas, no
  spaces, trimmed and deduplicated; an empty entry, as in `a,`, is
  dropped.
- `history/{set}.json` and `history/sealed/{set}.json` are a set's singles
  and sealed products, served in pages (`page=`, `meta.pages`). A single
  segment is tried as a set code first; a list with a comma is always a
  batch.
- `range=<days>` asks for the last N calendar days on the host's clock,
  today included, up to the plan's lookback (below). Without it, the
  whole lookback.
- `id=` takes the v2 id modes (`ban`, `tcg`, `scryfall`, `mtgjson`,
  `mkm`, `ck`, `name`) and refuses any other, as the v2 price API does. It
  defaults to `scryfall` for singles and `mtgjson` for sealed, as v2 search
  does, so a printing's finishes sit under one id. A card the mode has no
  id for is left out, as v2 prices leave it out.
- A request may cover 120 card-months, a card being one printing in one
  finish: the range in 30-day months (rounded, at least one) times the
  cards it names, so 120 at 30 days, 10 at a year. The budget counts the
  finishes the ids resolve to, so a printing sold in five finishes costs
  five. A batch naming more than three ids per card allowed is refused
  before any id resolves, a printing having usually one to three
  finishes: that cap bounds the ids, the budget bounds what is read. One
  id is always served whole, every finish and finish twin of its
  printing, so it is bounded by the printing rather than by any fixed
  multiple of the budget; five uuids, the most on a Magic card measured,
  is 610 card-months at a ten-year lookback.
  A batch whose ids resolve no card is a 404, like a single unknown id;
  unknown ids among known ones are skipped. See "What a read costs".
- **CSV.** `.csv` answers the same points as a flat table, header
  `id,finish,store,section,date,price`, `section` being `retail` or
  `buylist`, rows ordered by id, finish, store and date, retail before
  buylist for a store in both. `meta` travels as headers:
  `X-MTGBAN-Latest` (the newest day), `X-MTGBAN-Range` (the days) and, on
  a set, `X-MTGBAN-Page` and `X-MTGBAN-Pages`. Caching is the JSON form's
  (below), the `ETag` over the CSV bytes. Errors stay JSON, with their
  statuses.

`/api/chart/{id}` stays as it is. It serves the site's chart page, in
Chart.js's shape, and the two share the archive read.

## What the archive holds

From `timeseries/`, the long-form tables (`db_migration/01_schema.sql`),
and the deployed `config.json`:

- **One price per printing, per source, per day.** `prices(ban_id, date,
  provider, price)`. The snapshot runs every 12 hours and the day's last
  write wins. See "Days and timezones" below for what a date means.
- **No conditions.** `stashInTimeseries` scales a lower-condition price up
  to a Near Mint equivalent (`defaultGradeMap`: SP 1.25x, MP 1.67x, HP 2.5x,
  PO 4x) before it is stored. A history entry therefore has no `condition`.
- **Magic printings** are variants keyed by `(mtgjson_uuid, is_foil,
  is_etched)`, read through `HGetAllLong`, which picks the canonical
  language and non-alt variant. That is a uuid and a finish, which is what
  v2 keys prices by.
- **Other games' printings** are variants keyed by TCGplayer product and
  sub-type (`timeseries.TCGBanID`). Their history is TCGplayer's alone, and
  has holes; see below the source table.
- **USD (decided).** The providers table labels Cardmarket Low and Trend
  `EUR`, but the stored values are USD: the Cardmarket scrapers convert at
  scrape time, and the snapshot reads the converted price. Measured on
  2026-10-07: Sol Ring (CMR) nonfoil stored Cardmarket Low 3.91 for
  2026-10-06 against a live v2 `MKMLow` of 3.93 USD, and Sol Ring (C21)
  0.45 against 0.45; a EUR value would differ from these by the exchange
  rate. The endpoint keeps the stored USD values and the docs say so. The
  label in the providers table should be corrected separately.

### Sources and the store keys they get

A source is a provider in the archive. Each is keyed by the store tag v2
already uses for it and filed under the section below. This table is the
contract. `timeseries/providers.json` holds each provider's row and its
`history_key`, `historyDefaultKeys` in `api_history.go` is built from it,
and tests hold it to this table, to the SQL seed
(`db_migration/02_seed_providers.sql`) and to the `Provider` constants. A
`timeseries_config.datasets` entry with a
provider id may re-key its provider to the first non-sealed entry of its
`retail` or `buylist` list, under that list's section; a key another
provider already holds is refused and logged, so no two sources share a
key:

| Provider | Section | Key |
|---|---|---|
| CKRetail (1) | retail | `CK` |
| CKBuylist (2) | buylist | `CK` |
| TCGLow (3) | retail | `TCGLow` |
| TCGMarket (4) | retail | `TCGMarket` |
| TCGMid (5) | retail | `TCGMid` |
| TCGHigh (6) | retail | `TCGHigh` |
| TCGDirectLow (7) | retail | `TCGDirectLow` |
| MKMLow (8) | retail | `MKMLow` |
| MKMTrend (9) | retail | `MKMTrend` |
| SCGBuylist (10) | buylist | `SCG` |
| ABUBuylist (11) | buylist | `ABUGames` |
| CSIBuylist (12) | buylist | `CSI` |
| SealedEV (13) | retail | `TCGLowEV` |

TCGMid (5), TCGHigh (6) and TCGDirectLow (7) are in the table like every
other provider. No store carries them, so their key is the provider's
name; they carry data for the other games, from tcgcsv. A sealed
product's history is filed under the same providers (`CKSealed`,
`TCGSealed` and `MKMSealed` are listed with them), under the finish
`sealed`.

**Other games have only TCGplayer's history, with holes.** The Lorcana and
One Piece configs list no `timeseries_config.datasets`, so their history is
the TCGplayer series (Low, Market, Mid, High, Direct Low) the daily tcgcsv
ingest writes, from 2024-02-08 on. tcgcsv withdrew its archive in September
2026 (`docs/tcgcsv-archive-withdrawal.md`), so a day the ingest misses can
no longer be backfilled and stays a gap in the series. The endpoint's docs
say this beside the Magic sources, so a client reads a missing day as a
missing day and not as a bug.

### Days and timezones

A date is a calendar day, and the two writers name it differently:

- **The site's snapshot** (`stashInTimeseries`, cron `0 */12 * * *` on the
  host's clock) files a scrape under `snapshotDate`: today on the host's
  clock when the scrape is from today or tomorrow, so a scrape that
  straddles midnight lands on the run's day, and the scrape's own date
  otherwise, so a stale scrape keeps the day it was taken. Both are read
  in the host's local timezone.
- **The tcgcsv ingest** files TCGplayer's daily prices under the UTC day
  tcgcsv published them.

So every date is UTC as long as the hosts run in UTC. That has to be
confirmed on the droplets before the docs promise it, and if a host does
not, its cron and `snapshotDate` should be pinned to UTC rather than the
docs carrying a per-host timezone.

`range` counts calendar days on the host's clock: `range=1` is today,
`range=30` today and the 29 days before it, read from midnight.

## Response shape (decided: columns)

The same nesting as v2 prices, card id, then finish, then store tag. Only
the leaf differs: where a v2 price leaf is a list of `{condition, price,
qty, available}`, a history leaf holds its series as parallel arrays,
oldest first.

```json
{
  "meta": { "date": "2026-10-07T12:00:00Z", "version": "2", "base_url": "https://www.mtgban.com/go/", "latest": "2026-10-06", "range": 365 },
  "retail": {
    "aa21fc27-42d0-456a-9882-34d7f404270b": {
      "nonfoil": {
        "CK":     { "dates": ["2026-10-05", "2026-10-06"], "prices": [8.49, 8.49] },
        "TCGLow": { "dates": ["2026-10-05", "2026-10-06"], "prices": [4.89, 4.99] }
      },
      "foil": { "CK": { "dates": ["2026-10-06"], "prices": [16.99] } }
    }
  },
  "buylist": {
    "aa21fc27-42d0-456a-9882-34d7f404270b": {
      "nonfoil": { "CK": { "dates": ["2026-10-06"], "prices": [5.10] } }
    }
  }
}
```

- Every array in a leaf has the same length as its `dates`.
- A day a source has no price is left out of the leaf, date and price
  together, not sent as a null.
- **Today's point (decided):** the archive's as it stands; `meta.latest`
  names the newest day served, and `meta.range` the days covered.

A later series goes beside `prices` as another parallel array, not in an
object of its own, since it is read off the same snapshot and shares its
dates. Quantities, for one, would be a `qty` array, `null` on a day the
quantity is unknown, never 0, as an absent `qty` means unknown in v2, and
left out of a leaf whose store has none in the range. The archive stores no
quantities, so this is not planned, only the place it would go.

### What the shape costs

Measured on 2026-10-07 against the production archive, read-only, with a
throwaway probe that read each finish through `HGetAllLong` and encoded
the same points three ways, each with the nesting above. "Objects"
makes the leaf a list, `[{"date": "2026-10-06", "price": 8.49}, ...]`;
"columns" is the shape above; "pairs" makes it `[["2026-10-06", 8.49],
...]`. Bytes are raw / gzipped, the gateway serves gzip.

| Card | Range | Points | Objects | Columns | Pairs |
|---|---|---|---|---|---|
| Sol Ring (CMR), 2 finishes | 30 days | 462 | 16,198 / 1,524 | 8,701 / 645 | 9,268 / 1,365 |
| | 180 days | 2,815 | 97,313 / 8,879 | 49,815 / 2,631 | 55,088 / 8,032 |
| | 365 days | 5,892 | 203,234 / 18,954 | 103,448 / 5,177 | 114,854 / 16,938 |
| | all | 8,599 | 296,615 / 28,982 | 150,810 / 8,948 | 167,630 / 25,480 |
| Sol Ring (C21), 1 finish | all | 12,388 | 426,723 / 40,787 | 216,505 / 21,004 | 240,903 / 35,980 |
| CMR Collector Booster Pack | all | 2,843 | 101,471 / 10,856 | 53,245 / 5,429 | 58,826 / 9,413 |

Columns are about half the raw size and a third of the gzipped size of
objects. Pairs save raw bytes but little once gzipped. On the wire the
largest card measured is 21 KB as columns against 41 KB as objects, both
small next to the read that produces them (below); columns were chosen
for the bytes and for the room they leave for a parallel series.

### What a read costs

`timeseries.TestHistoryReadCostLive` times the read the endpoint makes,
`ban_id = ANY($1) AND date >= $2`, for a fresh id set ("cold") and the same
set again ("warm"), on the production archive; run it with
`CHARTLIVE_CONFIG` pointing at a site config to refresh the table. The
`ids` column is archive ids, each one printing in one finish, which is
what the budget counts. Measured before the budget was set; rerun the
live test to refresh the table:

| ids | days | cold ms | warm ms | rows |
|---|---|---|---|---|
| 10 | 30 | 393 | 120 | 1,971 |
| 10 | 180 | 2,321 | 255 | 12,928 |
| 10 | 365 | 3,229 | 187 | 23,073 |
| 50 | 30 | 1,286 | 73 | 10,133 |
| 50 | 180 | 9,435 | 302 | 60,641 |
| 50 | 365 | 13,148 | 310 | 119,417 |
| 100 | 30 | 2,428 | 99 | 21,092 |
| 100 | 180 | 12,233 | 249 | 118,242 |
| 100 | 365 | 20,393 | 323 | 241,880 |
| 300 | 30 | 3,442 | 132 | 63,709 |
| 300 | 180 | 39,842 | 684 | 370,539 |
| 300 | 365 | 59,443 | 25,266 | 715,764 |

The cost is cold I/O, about 20 ms per card per month of range: the plan
is one index scan per monthly partition on the primary key, and 300 ids
over a year read 90,274 blocks from disk. Batching saves round trips, not
I/O (ten single reads at 30 days took 1,002 ms against 393 ms in one
call), and warm reads stay cheap only while the result fits the cache.
So the cap is a budget of card-months, 120, about 3 s cold at any range,
and a set is paged by it.

The same test's second table times the handler's three shapes, cold then
warm, at 30, 90, 180, 365, 730, 1,825 and 3,650 days: one printing (every
archive id sharing one MTGJSON uuid), one set page (the ids the budget
allows at that range, `120 / months`), and a whole set of 300 ids. The
printing measured has two finish variants. Measured when the endpoint was
built; rerun the live test to refresh:

| shape | ids | days | cold ms | warm ms | rows |
|---|---|---|---|---|---|
| single printing | 2 | 30 | 100 | 62 | 150 |
| set page | 120 | 30 | 3521 | 301 | 24390 |
| whole set (300) | 300 | 30 | 2554 | 207 | 61297 |
| single printing | 2 | 90 | 183 | 61 | 510 |
| set page | 40 | 90 | 4634 | 88 | 25290 |
| whole set (300) | 300 | 90 | 12004 | 391 | 193887 |
| single printing | 2 | 180 | 313 | 66 | 1250 |
| set page | 20 | 180 | 3892 | 92 | 24795 |
| whole set (300) | 300 | 180 | 34514 | 1232 | 371452 |
| single printing | 2 | 365 | 460 | 66 | 2920 |
| set page | 10 | 365 | 2679 | 96 | 23812 |
| whole set (300) | 300 | 365 | 60758 | 8519 | 712653 |
| single printing | 2 | 730 | 602 | 65 | 4587 |
| set page | 5 | 730 | 2076 | 80 | 18637 |
| whole set (300) | 300 | 730 | 95085 | 77376 | 1087026 |
| single printing | 2 | 1825 | 2307 | 74 | 7022 |
| set page | 1 | 1825 | 328 | 65 | 2796 |
| whole set (300) | 300 | 1825 | 119461 | 109897 | 1335864 |
| single printing | 2 | 3650 | 2663 | 128 | 8240 |
| set page | 1 | 3650 | 1520 | 77 | 6624 |
| whole set (300) | 300 | 3650 | 113363 | 112022 | 1419831 |

The budgeted set page stays between 2 and 5 s cold up to two years, about
19,000 to 25,000 points each; past that the budget allows one card a page,
which reads in under 2 s. A single printing's finishes take 0.1 to 2.7 s.
An unpaged set of 300 printings grows from 2.5 s at 30 days to about two
minutes at five and ten years, and past a year its warm read is nearly as
slow, the result no longer fitting the cache. That is why a set is paged
by the budget.

## Plans (decided: a separate plan)

History is its own package in `apiproductlist/products.json`, not an
add-on to the price plans:

- a new mode, `history`, in the package's `modes`. The gateway's
  `NeedsModes` returns `["history"]` for the new route kind, so a price
  plan's key gets a 403 on history and a history plan's key gets a 403 on
  prices, from the check that exists today;
- a lookback in days on the package. The gateway mints it into the
  signature it forwards as `APIlookback`, the API key's own field beside
  `APImode` and `UserEmail` (`apisig.APIFields`); a key without it gets 30
  days. The site's `SearchChartLoopback`, which its own charts read, is
  unrelated and means nothing to the history endpoint.
  The package is `history` in `apiproductlist/products.json`, 365 days;
  its price is a placeholder until the maintainers set it.
- the sources are the archive's, not a store list, so the package has no
  `store_scope`. Every history plan reads every source; plans differ by
  lookback (decided).
- it takes the `extra_game` add-on like every package.

The gateway unions an account's entitlements across its packages, but its
billing allows one plan per account, so holding a price plan and a history
plan at once waits on the gateway (Rollout, step 3).

The plans page shows the package only where the config sets
`api_gateway.history_on_sale`, off until the gateway can check it out.

## Rate limit (advice)

The gateway throttles per account today, across every route
(`per_key_requests_per_sec`, `per_key_burst`, default burst 5). History
should get its own limiter, keyed the same way, so history traffic neither
spends nor is allowed the price allowance.

**1 request per second, burst 5, per account.** Why that number:

- The data changes once a day. One request a second is 86,400 cards a day
  per account, enough to walk any game's catalog daily, so it does not
  limit any use the data supports.
- Every request is one archive read, `HGetAllByBanIDs` over every id it
  covers. Read from a laptop over the internet, the probe's per-finish
  reads took 0.5 to 3.6 seconds a card; on the host,
  `fetchRosterPrices`'s note gives ten cards read one at a time as 848 ms,
  about 85 ms a card. A price request reads memory. At 10 a second per
  account, a few accounts walking a set would put a steady load of dozens
  of reads a second on the database the site's charts share.
- A burst of 5 lets a client fetch a handful of cards for one view without
  waiting.

Two things matter more than the exact number, and the site should do them
whatever the gateway's limit is:

- **One read per request** (built). `HGetAllByBanIDs` reads every id a
  request covers in one round trip.
- **A cap on concurrent history reads per host**, like
  `chartRosterConcurrency`, so the archive's load is bounded by the site
  and not by how many accounts are subscribed. Built: four at a time; a
  request waits at most 5 s for a slot, then gets a 503 with
  `Retry-After: 5`; a failed read is a 503 with `Retry-After: 30`.

### Caching

Latency is the cost a client feels, more than bytes: a catalog walk is one
archive read after another. Caching takes most of it away, because a
response changes only when a snapshot runs:

- The site sends `Cache-Control: public` with a `max-age` running to the
  next archive write (00:00 or 12:00 on the host's clock, and 21:00 on
  every game but Magic, where the tcgcsv ingest writes), and the same
  `ETag` for an unchanged response. For the half hour after each of those
  hours `max-age` is a minute: the standalone `cmd/tcgcsvd` and the other
  instance of a blue-green deploy write without this process seeing it.
- A response depends on the path, its extension, `range`, `id`, `page`
  and the plan's lookback, and on nothing else about the account, since
  every history plan reads the same sources (see Plans). So the gateway,
  or a CDN in front of it, can cache on those and answer a second
  account's request for the same card without reaching the archive. The
  gateway caches nothing today; this would be its first cache.
- Clients are told the data moves twice a day at most, so a client
  re-fetching a card more often gains nothing.
- Built: `Cache-Control: public, max-age=` to the next archive write, an
  `ETag` over the body (the JSON less `meta.date`, the CSV whole), 304
  on an `If-None-Match` that names it, weak or strong, alone or in a
  list, or `*`. An empty response, and any response served while this
  process's snapshot or tcgcsv ingest is writing, is `no-store` with no
  `ETag`.

## Open questions

1. **Lookback per plan.** How many days each tier grants.
2. **Host timezone.** Confirm the droplets run in UTC, or pin the snapshot
   to it (see "Days and timezones").

## Rollout

1. Site: the handler, the provider-to-store table, the single-query read,
   the concurrency cap, tests, and the guide and OpenAPI entries. (built)
2. `apiproductlist`: the package, its mode, its lookback, and `extra_game`
   applying to it. (built)
3. Gateway, in one PR:
   - the `history` route kind, with `NeedsModes` returning `["history"]`
     for it, and `history` in `ValidModes`;
   - the Patreon trial not granting history;
   - the store-scope guard and `Resolve` allowing a history-only plan,
     which has no store scope;
   - the history limiter (above);
   - `APIlookback` minted from the package's `lookback_days`;
   - the route: `history/` alone, with `.json`, `.csv` and comma lists
     passed through as they come; `history.json` and `history.csv` are
     gone, and on the site they fall to the price API;
   - a re-pin of this module and a `catalog seed`, so Stripe sells the
     package;
   - two subscriptions per account: holding a price plan and a history
     plan at once needs the gateway's billing to allow two subscriptions,
     which it does not today, a decision for the maintainers;
   - the `ETag` through gzip: nginx weakens a strong tag on a response it
     gzips; the site compares `If-None-Match` weakly, so a weakened tag
     still matches as long as the gateway forwards the header.
4. Deploy every game host, then the gateway, then set
   `api_gateway.history_on_sale` on the hosts and update the wiki.

A host with no stores loaded refuses history too, with the price API's
503, since the two share the API middleware (`enforceAPISigning`).
