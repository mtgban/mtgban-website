# Newspaper reports on API v2

The newspaper's reports (spike scores, vendor listing movers, Card
Kingdom buylist movers) as JSON and CSV on v2, built on the site
(`api_news.go`) and sold as an add-on to the price packages. The
gateway's part is listed under Rollout.

## What it serves

`GET /api/v2/newspaper/...` on a game host, and
`GET https://api.mtgban.com/v2/{game}/newspaper/...` through the
gateway. One route, `/api/v2/newspaper/`, behind `enforceAPISigning`
like the rest of v2, serves two forms:

- `newspaper/reports.json` lists the reports this game carries, in the
  page's order: those the newspaper declares with a query (not the
  settings entry) and shows on this game, loaded or not. A report is not
  shown off Magic when it needs Card Kingdom's buylist (`NeedsBuylist`,
  read by `shown()`): `combined_spike_score` and the two buylist reports
  are Magic's alone. Each names its columns, the filters it takes, the
  values `set`, `finish` and `bucket` accept, and its row count before
  filtering; a report not loaded yet lists with `rows: 0` and empty
  `sets` and `finishes`. It reads no options: `?page=2` or `?sort=x` on
  it is ignored and answers the same 200.
- `newspaper/{report}.json` is one report's live edition, filtered,
  sorted and paged at 1,000 rows (`newsPageSize`). `.csv` in place of
  `.json` is the same rows as a table.

Only the live edition is served; the page's three-day delayed edition
is not. The page's tiers (`NewsEnabled`, `NewsLarge`) do not apply: the
signature's `APImode` carrying `newspaper` (or `all`) is the whole grant,
through `canAccessMode`, checked before anything else, so without it
every path under `newspaper/` is a 403. A host in dev mode with signing
off answers as it does on every route.

The rows are the page's: each report's query runs on the refresh, every
three hours, and a row whose TCGplayer id does not match a card is
dropped then, as on the page, so every row served carries a card. The
live run under What a read costs, which prints the count, dropped
between 33 and 322 rows per report.

### Options

| Option | Values | Effect |
|---|---|---|
| `sort` | a sortable column's field, or `ranking`, `name`, `set`, `number`, `finish` | the sort key, `ranking` by default |
| `dir` | `asc`, `desc` | `asc` by default for `ranking`, `desc` for any other key |
| `page` | an integer from 1 to `meta.pages` | the page of the filtered, sorted rows, 1 by default |
| `set` | an edition from the report's `sets` | exact match |
| `rarity` | `M`, `R`, `U`, `C`, `S`, `M/R`, `U/C` | the first letter of the card's rarity, either of a pair |
| `finish` | a value from the report's `finishes` | exact match |
| `bucket` | a value from the report's `buckets` | exact match, reports that list `bucket` only |
| `min_price`, `max_price` | a number | inclusive bounds on the report's price column; a row with no price fails them |
| `min_change`, `max_change` | a number, in percent (20 is 20%) | inclusive bounds on the report's weekly change, in the unit its `percent` column is served in; a row with no change fails them |

The sort is the page's: numeric when either side is a nonzero number,
else by the text, ties kept in ranking order. Other query keys are
ignored, so a cache-busting parameter does no harm.

The page and the API filter through one function, `newsFilter`, which
answers a new slice and never reorders the cached one. Before it, no
report named its price or change column, so the page parsed the four
bounds and never applied them; each report now names them:

| Report | Price column | Change column |
|---|---|---|
| `combined_spike_score` | `tcg_market_price` | |
| `spike_score` | `current_price` | |
| `greatest_increase_listings` | | `pct_gain_7d` |
| `greatest_decrease_listings` | | `pct_drop_7d` |
| `greatest_increase_buylist` | `ck_buy_price` | `pct_increase_7d` |
| `greatest_decrease_buylist` | `ck_buy_price` | `pct_decrease_7d` |

The page's links send 0 for a bound the reader left blank, so the page
reads 0 as none; the API takes 0 as a bound. A bound filters on a
value: a row with none in the bound's column (served as `null`) fails
it, on the page and the API alike, and is kept when no bound is given.

The change columns are stored as fractions (0.065 for 6.5%), which the
page prints times 100. The page's "Min %" and "Max %" and the API's
`min_change` and `max_change` are percents, compared against the
stored value times 100 rounded to two decimals, the number a reader
sees. `pct_drop_7d` holds a fall as a negative number (-18.4).

### Paging

A report is filtered and sorted whole, then cut into pages of 1,000
rows. `page` picks one, 1 by default; `meta.rows` counts the rows the
filters matched, before paging, and `meta.pages` the pages they fill,
at least 1, so a filter that matches nothing is page 1 of 1 with
`"rows": []`. A `page` that is not an integer, below 1 or past
`meta.pages` is a 400, `page out of range`. The CSV carries the same in
`X-MTGBAN-Rows`, `X-MTGBAN-Page` and `X-MTGBAN-Pages`. In the run under
What a read costs, four reports fit one page; the combined spike score
fills two and the listings decrease seven.

### Errors

Real statuses with a JSON `{"error": ...}` body, `.csv` requests
included, and `Cache-Control: no-store`:

| Status | When |
|---|---|
| 400 | an unknown report (one not declared or not shown on this game, so not in `reports.json`: a report shown on Magic alone is unknown elsewhere), an option the report does not take, a value outside the report's lists, a bound that is not a finite number, `dir` other than `asc` or `desc`, a `sort` on a column that is not sortable, a `page` out of range |
| 403 | the signature's `APImode` lacks `newspaper` (and `all`) |
| 404 | a path under `newspaper/` that is neither `reports.json` nor `{report}.json` or `.csv`, `reports.csv` included |
| 503 | the cache is empty (startup, `-nonews`, or no newspaper database), with `Retry-After: 300`; and a report `reports.json` lists that is not loaded yet, `report not loaded yet`, with the same header |

`enforceAPISigning` answers its own 503 while a host's stores are still
loading, as on every v2 route.

## Response shape

`reports.json`:

```json
{
  "meta": {"latest": "2026-10-13", "refreshed": "2026-10-13T06:33:10Z", "stale": false},
  "reports": [
    {
      "key": "spike_score",
      "title": "Top Singles by Spike Score",
      "description": "Best cards to buy, using TCGplayer sales data",
      "columns": [
        {"field": "ranking", "title": "Ranking", "kind": "number", "sortable": true},
        {"field": "bucket_name", "title": "Bucket", "kind": "text", "sortable": true},
        {"field": "bucket_rank", "title": "Bucket Rank", "kind": "number", "sortable": true},
        {"field": "current_price", "title": "Current Price", "kind": "dollar", "sortable": true}
      ],
      "filters": ["set", "rarity", "finish", "bucket", "min_price", "max_price"],
      "sets": ["Bloomburrow", "Duskmourn: House of Horror"],
      "finishes": ["Foil", "Normal"],
      "buckets": ["$2+", "$5+", "$10+", "$20+", "$35+", "$50+", "$75+"],
      "rows": 412
    }
  ]
}
```

`columns` are the report's visible columns past the card fields, from
the page's headings: `kind` is `dollar`, `percent`, `number` or `text`
from the heading's flags, `sortable` whether the page sorts by it.
`filters` never lists `page`, which every report takes. `latest` is the
newest report date. The cache keeps a report's rows through a failed
refresh, so a report with none was never loaded: it lists with
`rows: 0`, and a request for it is a 503 to retry, not a 400.

`{report}.json`:

```json
{
  "meta": {
    "report": "spike_score",
    "title": "Top Singles by Spike Score",
    "date": "2026-10-13",
    "refreshed": "2026-10-13T06:33:10Z",
    "stale": false,
    "rows": 412,
    "page": 1,
    "pages": 1,
    "columns": [
      {"field": "ranking", "title": "Ranking", "kind": "number", "sortable": true},
      {"field": "bucket_name", "title": "Bucket", "kind": "text", "sortable": true},
      {"field": "bucket_rank", "title": "Bucket Rank", "kind": "number", "sortable": true},
      {"field": "current_price", "title": "Current Price", "kind": "dollar", "sortable": true}
    ]
  },
  "rows": [
    {"ranking": 1, "id": "7c3ea479-e463-58e7-b1b0-b217c77dae79", "name": "Ragavan, Nimble Pilferer",
     "set": "Modern Horizons 2", "number": "138", "finish": "Normal", "rarity": "mythic",
     "bucket_name": "$50+", "bucket_rank": 1, "current_price": 64.99}
  ]
}
```

- `id` is the card's MTGBAN id, the one `id=ban` keys the price
  endpoints by, so a client joins the two. `name`, `set`, `number` and
  `rarity` come from the matched card; `finish` is the newspaper's own
  (`Normal`, `Foil`).
- Report columns are keyed by their field exactly as the page sorts by
  them, `sellers_Today` included: renaming one is the newspaper
  pipeline's call. Dollar, percent and number columns are JSON numbers,
  `null` where the row has none or the value is NaN or infinite, which
  JSON cannot hold; text columns are strings. The newspaper stores an
  absent decimal and 0 alike, so a decimal column's 0 is `null` too.
  Hidden columns and the forecast-era fields never appear.
- A `percent` column is a percentage: 6.5 means 6.5%, the stored value
  times 100 to two decimals, in JSON and CSV alike.
- `date` is the report's `calc_date`. `refreshed` is when this host last
  took new rows from the newspaper, left out (and `X-MTGBAN-Refreshed`
  unset) before the first; `stale` is true once that is 12 hours old,
  the rule the page's notice uses. `rows` counts the rows the
  filters matched, before paging; `page` and `pages` are under Paging.
- A filter that matches nothing answers `"rows": []` with a 200.

The CSV is the same rows, header `ranking,id,name,set,number,finish,rarity`
then the report's column fields, with the meta in `X-MTGBAN-Date`,
`X-MTGBAN-Refreshed`, `X-MTGBAN-Stale`, `X-MTGBAN-Rows`, `X-MTGBAN-Page`
and `X-MTGBAN-Pages`. An absent, NaN or infinite value is an empty
cell:

```
ranking,id,name,set,number,finish,rarity,bucket_name,bucket_rank,current_price
1,7c3ea479-e463-58e7-b1b0-b217c77dae79,"Ragavan, Nimble Pilferer",Modern Horizons 2,138,Normal,mythic,$50+,1,64.99
```

## What a read costs

The handler reads the cached slice and encodes it, so a read costs its
response size and its encode time; the database is read only by the
refresh, every three hours. `TestNewspaperReadCostLive`
(`news_live_test.go`) reads each report's live edition from the
newspaper database, read-only, requests every page of each report
through the handler as JSON and CSV, and prints the table below. Rerun
it against a site config with `new_newspaper_sql_config`, with
`allprintings5.json` in the repo root (without it the test skips):

```
NEWSPAPER_LIVE=1 NEWSPAPER_LIVE_CONFIG=<config> go test -run TestNewspaperReadCostLive -v
```

The table sums every page of each report as the live test serves them,
raw and gzipped (the gateway and browsers compress), measured when the
endpoint was built against Magic's production newspaper database and
refreshed by rerunning the test. The ms columns are the whole handler's
time, not the encode alone. Rows dropped for a failed card match (33 to
322 per report in that run) are not counted.

| report | rows | JSON bytes | JSON gzip | CSV bytes | CSV gzip | JSON ms | CSV ms |
|---|---|---|---|---|---|---|---|
| combined_spike_score | 1328 | 358862 | 83517 | 157766 | 69869 | 3.7 | 1.6 |
| spike_score | 408 | 91423 | 23333 | 44229 | 20185 | 1.0 | 0.5 |
| greatest_increase_listings | 479 | 115001 | 27243 | 54323 | 22996 | 1.1 | 0.5 |
| greatest_decrease_listings | 6428 | 1518092 | 379050 | 706918 | 317571 | 18.5 | 46.1 |
| greatest_increase_buylist | 647 | 164409 | 38928 | 74190 | 32519 | 2.4 | 2.5 |
| greatest_decrease_buylist | 596 | 151472 | 35834 | 68254 | 30233 | 2.8 | 2.2 |

Five reports are under 400 KB of JSON. The listings-decrease report
alone is 6,428 rows and 1.5 MB (379 KB gzipped), which is why a report
is paged at 1,000 rows. The handler's own time is tens of milliseconds
at most, so the cost of a read is its bytes.

The rate limit is the gateway's default per-key limiter: a newspaper
read is cheaper than a price read, which walks every store's prices.

## Plans

The newspaper is an add-on to any price package, not a package of its
own: `newspaper` in `apiproductlist/products.json`, with
`grants_mode: newspaper`, applying to the three price packages,
`starter`, `all_stores` and `all_data`. An add-on with `grants_mode` is
bought once and grants that mode, unlike the counted `extra_store` and
`extra_game`; `Validate` refuses a `grants_mode` outside `Modes`. Its
price, $1 a month, is a placeholder for the maintainers to set.

The plans page shows a checkbox for it below the games picker, adding
its monthly to the total and submitting `addons=newspaper` to the
gateway's checkout, only where the config sets
`api_gateway.newspaper_on_sale`: the gateway cannot sell it until it
re-pins this module and seeds Stripe. Off, the add-on is left out of the
page and of the configurator's data.

## Caching

- `Cache-Control: public, max-age=` the seconds to the next newspaper
  refresh, `33 */3 * * *` on the host's clock (`newsCron`, which the
  cron itself reads), at least 60.
- While the cached data predates the last scheduled run, because that
  refresh has not landed yet or failed, `max-age=60`, so a client
  rechecks until the new rows arrive instead of holding the old ones to
  the next run.
- A stale cache (refreshed 12 hours or more ago) sends `max-age=300`.
- An `ETag` over the response body, so each page, sort and filter has
  its own. The body holds no clock-dependent field besides `refreshed`,
  which moves only when the data does, and `stale`, which turns true
  12 hours after it.
  `If-None-Match` is compared weakly, so a tag nginx weakened when it
  gzipped the response still matches; a match is a 304 with the same
  headers.
- `Last-Modified` from `refreshed`.

A response depends on the path, its extension and the options, and on
nothing about the account. The gateway forwards the site's
`Cache-Control` today; its newspaper PR is to set the final header for
a request made with an API key (step 3 of Rollout).

## Rollout

1. Site: the endpoint, the shared filter, the rarity field, the add-on
   in the catalog, the plans checkbox behind `newspaper_on_sale`, the
   OpenAPI and guide entries, and this doc. (built)
2. Deploy every game's site: the gateway's verifier needs nothing new,
   but the route must exist before the gateway forwards to it.
3. Gateway: the `newspaper` mode; the `newspaper/` route kind on v2,
   passing the site's 4xx and 503 through as the history route does;
   the opt-in add-on in the plan model, read from the `addons=newspaper`
   the configurator submits, into the checkout and its metadata; the
   portal checkbox; the trial not granting it; set
   `Cache-Control: private` on proxied newspaper responses. Then re-pin
   this module in the gateway's `go.mod` and seed Stripe from the
   catalog.
4. The maintainers set the price, then `api_gateway.newspaper_on_sale`
   on the sites.
