# Long-form cutover — operational runbook

The Go branch `card-prices-long-form` implements the long-form read/write paths
behind two config flags, so the cutover is a sequence of config flips with a
verify gate between each. The legacy wide path stays intact until the end, so
every step is reversible by flipping the flag back.

The cutover is complete: reads moved to the long tables on 2026-10-02. Steps 2 to
4 are kept as the record of how; the scripts they name are in `retired/` and must
not run again (see `retired/README.md`).

## 1. Config and datasets file additions (NOT in git)

Add a `provider` id to every entry of the datasets file the config names in
`datasets_path` (the admin page's Datasets tab edits it). Nothing is derived or defaulted in code: a dataset
without a `provider` is dropped from the chart registry, skipped by the long-form
dual-write, and unresolvable for buylist metrics and the screener (issue #282: a
config missing the field charted only TCGplayer Low and Market, because those
were the ids code still filled in). Startup logs one line per dataset it has to
skip — grep the boot log for `has no "provider" id` before flipping any flag.

The wide column each `provider` id stands for (plan 17.5):

| column | `provider` |
|---|---|
| cardkingdom_retail_price | 1 |
| cardkingdom_buylist_price | 2 |
| tcgplayer_low_price | 3 |
| tcgplayer_market_price | 4 |
| cardmarket_low_price | 8 |
| cardmarket_trend_price | 9 |
| starcitygames_buylist_price | 10 |
| abu_buylist_price | 11 |
| tcgplayer_low_sealed_expected_value | 13 |
| coolstuffinc_buylist_price | 12 |

```jsonc
// the datasets file
[
    { "public_name": "TCGplayer Low", "provider": 3, ... },
    { "public_name": "TCGplayer Market", "provider": 4, ... },
    // ... provider on every dataset ...
]
```

A deployment that ran dual-write with the field missing left gaps in `prices` for
every provider it skipped, which `retired/08_catchup.sql.txt` filled from
`product_prices` after the datasets file was fixed.

The tcgcsv (non-Magic) ingest writes providers 3/4/5/6/7 — columns low/market/
mid/high/direct_low — and the chart renders whichever of those the datasets file
names. Mid, High, and Direct Low have no Magic dataset behind them, so a
deployment that charts non-Magic products needs an entry for each, and
`provider`, `public_name`, and `color` are what the chart reads:

```jsonc
{ "public_name": "TCGplayer Mid",        "provider": 5, "color": "rgb(255, 206, 86)" },
{ "public_name": "TCGplayer High",       "provider": 6, "color": "rgb(75, 192, 192)" },
{ "public_name": "TCGplayer Direct Low", "provider": 7, "color": "rgb(153, 102, 255)" },
```

## 2. Deploy the dual-write

Done, and since superseded by step 5: the dual-write is over. Every 12h stash
and every daily tcgcsv ingest writes only the long tables (variants + prices)
and files the days it wrote in `price_dates`, in the same transaction. Each
write first ensures the partitions of the months it writes and the month after
(`UpsertLongPrices`); startup ensures the current and next month as a courtesy
and warms the variant to ban_id cache.

A write failure is reported through the job's notices and that run's rows are
not stored: there is no legacy write behind them any more.

## 3. Verify live-write parity

Done, before reads flipped: `retired/07_verify.sql.txt` compared the long
tables with the wide ones per provider, and `retired/08_catchup.sql.txt` closed
the drift the backfill left behind the live crons. Neither runs again; against
the tables as they are now both would do harm (`retired/README.md`).

## 4. Flip reads (`long_form_reads: true`), deploy

Done everywhere: charts (`HGetAllLong`), earliest-date, buylist metrics
(`GetAggregatePriceStatsLong`) and the screener (`GetMoversLong`) serve from the
long tables. The flag and the legacy read path are gone, and the site reads
only the long tables whatever the config says. A config may still carry
`long_form_reads`; it is ignored, and can be dropped once no deployment runs a
build that still reads it.

## 5. Drop the legacy write path

The snapshot writes only the long tables, so nothing writes `product_prices`
and it can be archived or dropped. The tcgcsv ingest writes only the long
tables and takes its dates from `price_dates`, and the `index` field of
datasets is gone: the screener and the buylist metrics key on `provider`.
The deployed datasets files may still carry `"index"` keys, which
`loadDatasets` ignores but the admin Datasets editor refuses when a file with
them is pasted (remove the key). During a rolling deploy an older build
reading a datasets file the new editor saved sees no index and charts nothing
until it is redeployed, so deploy all sites before editing datasets.
`tcgplayer_nonmagic_product_prices` is left to drop, which
`wide_tables/drop_nonmagic.sql` does after two nights of the ingest and with a
volume snapshot in hand (`wide_tables/README.md`).

## 6. Validate + finalize the FK

Off-peak, run `06_validate_fk.sql` to VALIDATE the `prices_ban_id_fk` constraint
that was added `NOT VALID`.
