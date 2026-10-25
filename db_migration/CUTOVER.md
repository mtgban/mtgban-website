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
`datasets_path` (the admin page's Datasets tab edits it), and the flag on
`timeseries_config`. Nothing is derived or defaulted in code: a dataset
without a `provider` is dropped from the chart registry, skipped by the long-form
dual-write, and unresolvable for buylist metrics and the screener (issue #282: a
config missing the field charted only TCGplayer Low and Market, because those
were the ids code still filled in). Startup logs one line per dataset it has to
skip — grep the boot log for `has no "provider" id` before flipping any flag.

The index→provider mapping (plan 17.5):

| dataset `index` | column | `provider` |
|---|---|---|
| 0 | cardkingdom_retail_price | 1 |
| 1 | cardkingdom_buylist_price | 2 |
| 2 | tcgplayer_low_price | 3 |
| 3 | tcgplayer_market_price | 4 |
| 4 | cardmarket_low_price | 8 |
| 5 | cardmarket_trend_price | 9 |
| 6 | starcitygames_buylist_price | 10 |
| 7 | abu_buylist_price | 11 |
| 8 | tcgplayer_low_sealed_expected_value | 13 |
| 9 | coolstuffinc_buylist_price | 12 |

```jsonc
// config.json
"timeseries_config": {
    "long_form_writes": false   // step 2 flips this on
}

// the datasets file
[
    { "public_name": "TCGplayer Low", "index": 2, "provider": 3, ... },
    { "public_name": "TCGplayer Market", "index": 3, "provider": 4, ... },
    // ... provider on every dataset ...
]
```

A deployment that ran dual-write with the field missing left gaps in `prices` for
every provider it skipped, which `retired/08_catchup.sql.txt` filled from
`product_prices` after the datasets file was fixed.

The tcgcsv (non-Magic) ingest writes providers 3/4/5/6/7 — columns low/market/
mid/high/direct_low — and the chart renders whichever of those the datasets file
names. Mid, High, and Direct Low have no Magic dataset behind them, so a
deployment that charts non-Magic products needs an entry for each; `index` goes
unused on that path (pick ids past the wide columns), while `provider`,
`public_name`, and `color` are what the chart reads:

```jsonc
{ "public_name": "TCGplayer Mid",        "index": 20, "provider": 5, "color": "rgb(255, 206, 86)" },
{ "public_name": "TCGplayer High",       "index": 21, "provider": 6, "color": "rgb(75, 192, 192)" },
{ "public_name": "TCGplayer Direct Low", "index": 22, "provider": 7, "color": "rgb(153, 102, 255)" },
```

## 2. Turn on dual-write (`long_form_writes: true`), deploy

Now every 12h stash and every daily tcgcsv ingest writes the legacy wide row AND
the long row (variants + prices). Reads are still legacy. Startup also ensures the
current+next month partitions exist and warms the variant→ban_id cache.

A long-form write failure is logged (ServerNotify / log), never fatal — the legacy
write already persisted the snapshot.

## 3. Verify live-write parity

After a stash and a tcgcsv run have both fired under dual-write, confirm the new
rows match the legacy ones for the latest date:

```sql
-- Magic: legacy non-null,>0 cells vs long rows for the latest date, per provider.
-- (Same shape as retired/07_verify.sql.txt, scoped to the newest date.)
```

Re-run `retired/07_verify.sql.txt` (full history) as the primary gate; it
already compares per-provider counts across the whole table. Spot-check a handful
of cards' charts.

**Closing backfill drift.** The initial backfill runs alongside the live crons, so
the long tables lag behind by the rows product_prices gained since the variants
snapshot (verification shows this as a small negative per-provider diff — e.g. new
printings minted on the backfill's start day). Once dual-write is on this stops
growing; to close the one-time gap, run `retired/08_catchup.sql.txt` (re-mints
new variants + re-inserts the recent window with ON CONFLICT DO NOTHING). Re-run
`retired/07_verify.sql.txt` after; the diffs should go to 0.

## 4. Flip reads (`long_form_reads: true`), deploy

Charts (`HGetAllLong`), earliest-date, buylist metrics (`GetAggregatePriceStatsLong`),
and the screener (`GetMoversLong`) now serve from the long tables. Legacy writes
continue (safety net). Watch charts / screener / buylist metrics for a day.

Done everywhere: the flag and the legacy read path are gone, and the site reads
only the long tables whatever the config says. A config may still carry
`long_form_reads`; it is ignored, and can be dropped once no deployment runs a
build that still reads it.

## 5. Drop the legacy write path

The snapshot writes only the long tables, so nothing writes `product_prices`
and it can be archived or dropped. Still to go:
`tcgplayer_nonmagic_product_prices`, which the tcgcsv ingest writes and takes
its dates from, and the `index` field of datasets, which the screener and the
buylist metrics still key on.

## 6. Validate + finalize the FK

Off-peak, run `06_validate_fk.sql` to VALIDATE the `prices_ban_id_fk` constraint
that was added `NOT VALID`.
