# Long-form cutover — operational runbook

The Go branch `card-prices-long-form` implements the long-form read/write paths
behind two config flags, so the cutover is a sequence of config flips with a
verify gate between each. The legacy wide path stays intact until the end, so
every step is reversible by flipping the flag back.

## 1. config.json additions (NOT in git — config.json is gitignored)

Add a `provider` id to every `timeseries_config.datasets` entry, and the two
flags on `timeseries_config`. The index→provider mapping (plan 17.5):

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
"timeseries_config": {
    "long_form_writes": false,   // step 2 flips this on
    "long_form_reads": false,    // step 4 flips this on
    "datasets": [
        { "public_name": "TCGplayer Low", "index": 2, "provider": 3, ... },
        { "public_name": "TCGplayer Market", "index": 3, "provider": 4, ... },
        // ... provider on every dataset ...
    ]
}
```

Non-Magic providers are wired in code, not config (tcgcsv columns low/market/mid/
high/direct_low → providers 3/4/5/6/7).

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
-- (Same shape as 07_verify.sql, scoped to the newest date.)
```

Re-run `07_verify.sql` (full history) as the primary gate; it already compares
per-provider counts across the whole table. Spot-check a handful of cards' charts.

**Closing backfill drift.** The initial backfill runs alongside the live crons, so
the long tables lag behind by the rows product_prices gained since the variants
snapshot (verification shows this as a small negative per-provider diff — e.g. new
printings minted on the backfill's start day). Once dual-write is on this stops
growing; to close the one-time gap, run `08_catchup.sql` (re-mints new variants +
re-inserts the recent window with ON CONFLICT DO NOTHING). Re-run `07_verify.sql`
after — the diffs should go to 0.

## 4. Flip reads (`long_form_reads: true`), deploy

Charts (`HGetAllLong`), earliest-date, buylist metrics (`GetAggregatePriceStatsLong`),
and the screener (`GetMoversLong`) now serve from the long tables. Legacy writes
continue (safety net). Watch charts / screener / buylist metrics for a day.

Rollback at any point before this is trusted: set `long_form_reads: false`.

## 5. Drop the legacy write path (follow-up PR, not this branch)

Once reads are trusted on long form: stop writing the wide `product_prices` /
`tcgplayer_nonmagic_product_prices`, delete `PriceForDataset` /
`SetPriceForDataset` / `columnForDataset` and the wide `PriceRow` read methods,
and drop the `index` field from datasets (provider fully replaces it). The old
tables can then be archived/dropped when you're ready.

## 6. Validate + finalize the FK

Off-peak, run `06_validate_fk.sql` to VALIDATE the `prices_ban_id_fk` constraint
that was added `NOT VALID`.
