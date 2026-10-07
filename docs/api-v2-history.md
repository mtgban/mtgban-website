# Price history on API v2

Design for a v2 endpoint that serves a card's price history from the
archive the site's charts read, in a shape that matches v2's prices. Not
built yet. The decisions taken so far are marked, and the open ones are at
the end.

## What it serves

`GET /api/v2/history/{id}.json` on a game host, and
`GET https://api.mtgban.com/v2/{game}/history/{id}.json` through the gateway.

- `{id}` is one card or sealed product, resolved the way the v2 price API
  resolves a single card (`b.MatchID` for each finish), so every finish of
  the printing comes back in one response.
- `range=<days>` asks for the most recent days, up to the plan's lookback
  (below). Without it, the whole lookback.
- `id=` takes the v2 id modes (`mtgban`, `tcg`, `scryfall`, `mtgjson`,
  `mkm`, `ck`, `name`) and refuses any other, as the v2 price API does. It
  defaults to `scryfall` for singles and `mtgjson` for sealed, as v2 search
  does, so a printing's finishes sit under one id.
- One card per request. A set-wide history would cost one archive read per
  printing, hundreds per request, where every other v2 endpoint reads the
  in-memory scrapes.
- JSON only to start with.

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
already uses for it, taken from `timeseries_config.datasets` (the first
non-sealed entry of its `retail` or `buylist` list), and filed under the
section that list names:

| Provider | Section | Key |
|---|---|---|
| CKRetail (1) | retail | `CK` |
| CKBuylist (2) | buylist | `CK` |
| TCGLow (3) | retail | `TCGLow` |
| TCGMarket (4) | retail | `TCGMarket` |
| MKMLow (8) | retail | `MKMLow` |
| MKMTrend (9) | retail | `MKMTrend` |
| SCGBuylist (10) | buylist | `SCG` |
| ABUBuylist (11) | buylist | `ABUGames` |
| CSIBuylist (12) | buylist | `CSI` |
| SealedEV (13) | retail | `TCGLowEV` |

TCGMid (5), TCGHigh (6) and TCGDirectLow (7) map to no store in any
config. They carry data for the other games, from tcgcsv, and are keyed by
the provider's own shorthand, under retail. A sealed product's history is
filed under the same providers (`CKSealed`, `TCGSealed` and `MKMSealed` are
listed with them), under the finish `sealed`.

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

## Response shape (decided: columns)

The same nesting as v2 prices, card id, then finish, then store tag. Only
the leaf differs: where a v2 price leaf is a list of `{condition, price,
qty, available}`, a history leaf holds its series as parallel arrays,
oldest first.

```json
{
  "meta": { "date": "2026-10-07T12:00:00Z", "version": "2", "base_url": "https://www.mtgban.com/go/" },
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

A later series goes beside `prices` as another parallel array, not in an
object of its own, since it is read off the same snapshot and shares its
dates. Quantities, for one, would be a `qty` array, `null` on a day the
quantity is unknown, never 0, as an absent `qty` means unknown in v2, and
left out of a leaf whose store has none in the range. The archive stores no
quantities, so this is not planned, only the place it would go.

### What the shape costs

Measured on 2026-10-07 against the production archive, read-only, with a
throwaway probe that read each finish through `HGetAllLong` and encoded the
same points three ways, each with the nesting above. "Objects" makes the
leaf a list, `[{"date": "2026-10-06", "price": 8.49}, ...]`; "columns" is
the shape above; "pairs" makes it `[["2026-10-06", 8.49], ...]`. Bytes are raw / gzipped, the
gateway serves gzip.

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

## Plans (decided: a separate plan)

History is its own package in `apiproductlist/products.json`, not an
add-on to the price plans:

- a new mode, `history`, in the package's `modes`. The gateway's
  `NeedsModes` returns `["history"]` for the new route kind, so a price
  plan's key gets a 403 on history and a history plan's key gets a 403 on
  prices, from the check that exists today;
- a lookback in days on the package. The gateway mints it into the
  signature it forwards, as `SearchChartLoopback`, which `chartLookback`
  already reads; a key without it falls back to that function's 30 days;
- the sources are the archive's, not a store list, so the package has no
  `store_scope`. Whether a history plan should narrow the sources to a
  price plan's stores is open (below).

The gateway already unions an account's entitlements across its packages,
so an account can hold a price plan and a history plan at once.

## Rate limit (advice)

The gateway throttles per account today, across every route
(`per_key_requests_per_sec`, `per_key_burst`, default burst 5). History
should get its own limiter, keyed the same way, so history traffic neither
spends nor is allowed the price allowance.

**1 request per second, burst 5, per account.** Why that number:

- The data changes once a day. One request a second is 86,400 cards a day
  per account, enough to walk any game's catalog daily, so it does not
  limit any use the data supports.
- Every request is archive reads, one per finish: today three
  (`HGetAllLong` for nonfoil, foil and etched). Read from a laptop over the
  internet, the probe took 0.5 to 3.6 seconds a card; on the host,
  `fetchRosterPrices`'s note gives ten cards read one at a time as 848 ms,
  about 85 ms a card. A price request reads memory. At 10 a second per
  account, a few accounts walking a set would put a steady load of dozens
  of reads a second on the database the site's charts share.
- A burst of 5 lets a client fetch a handful of cards for one view without
  waiting.

Two things matter more than the exact number, and the site should do them
whatever the gateway's limit is:

- **One read per card.** A query over the variants of one uuid, all
  finishes, instead of one `HGetAllLong` per finish, cuts a request to one
  round trip.
- **A cap on concurrent history reads per host**, like
  `chartRosterConcurrency`, so the archive's load is bounded by the site
  and not by how many accounts are subscribed.

### Caching

Latency is the cost a client feels, more than bytes: a catalog walk is one
archive read after another. Caching takes most of it away, because a
response changes only when a snapshot runs:

- The site sends `Cache-Control: public` with a `max-age` running to the
  next snapshot (00:00 or 12:00 on the host's clock), and the same
  `ETag` for an unchanged response.
- A response depends on the path, `range`, `id` and the plan's lookback,
  and on nothing else about the account, since every history plan reads
  the same sources (see the open questions). So the gateway, or a CDN in
  front of it, can cache on those and answer a second account's request
  for the same card without reaching the archive. The gateway caches
  nothing today; this would be its first cache.
- Clients are told the data moves twice a day at most, so a client
  re-fetching a card more often gains nothing.

## Open questions

1. **Sources per plan.** Provisional: every history plan gets every source
   the archive holds for the game, and plans differ by lookback. A plan
   naming its sources would make history a way to sell a wider price plan,
   and would split the cache by plan.
2. **Lookback per plan.** How many days each tier grants. Open.
3. **Today's point.** Provisional: serve what the archive holds, and say in
   the docs that the latest day is usually yesterday, since at midday on
   2026-10-07 the live chart had no point for that day for either Sol Ring.
   `meta` can carry the latest date in the response, `latest`, so a client
   tells a missing day from a day not yet written without a ticket.
4. **Host timezone.** Confirm the droplets run in UTC, or pin the snapshot
   to it (see "Days and timezones").

## Rollout

1. Site: the handler, the provider-to-store table, the single-query read,
   the concurrency cap, tests, and the guide and OpenAPI entries.
2. `apiproductlist`: the package, its mode and its lookback, and the gateway
   bump that picks it up.
3. Gateway: the `history` route kind, its limiter, the lookback in the
   minted signature, and the Stripe product.
4. Deploy every game host, then the gateway, then the wiki.
