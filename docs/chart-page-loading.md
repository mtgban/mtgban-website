# What a chart page costs, and where that cost went

Background for issue #328, "charts are slow to open". Measured against the
live archive on 2026-09-24, on `ban_id` 790 and on Black Lotus (`ban_id`
29954), from a client 69ms from the database — close to the app's own
50-70ms, so wire time reads the same way.

## The archive was not the problem

Timed through this repo's own client, warm, so the number includes the
prepared statement, the row scan and the pivot:

```
lookback   read     project   labels  points  gaps    inline-HTML
     30d   72ms     0s            31     224      24    2.2 KB
    180d   79ms     1ms          181    1242     206   13.2 KB
    730d   80ms     2ms          731    4252    1596   58.3 KB
   3650d   96ms     5ms         2208    7428   10236  207.3 KB
```

Six years instead of six months costs **11ms**. One round trip, ~5ms of
server execution. The read is not what makes the page slow.

## Two things were

**The payload, most of which was padding.** Every provider got an array as
long as the axis with `"Number.NaN"` in each day it did not quote — at max
lookback, 10,236 of 17,664 slots. The page then showed 180 days of it,
because `changeRange` only moved `scales.x.min` over series already sent.
Hence: slow to finish loading, fast once loaded.

**Cold reads, because a chart query fans out across every partition.**
`prices` is partitioned by month and keyed on `date`, but a chart read is
keyed on `ban_id`, so one card's history visits all of them:

```
window   partitions scanned        blocks read from disk   execution
 180d    35  (7 real + 28 empty)            101             108 ms
3650d   101  (73 real + 28 empty)           217             205 ms
```

Warm, that card reads in 85ms. Cold, a ten-card roster took 5.35s; the
same roster re-run warm took 840ms. The archive has 979MB of
`shared_buffers` against 233GB, and a 71% buffer cache hit rate, so "cold"
is the common case for anything not recently viewed.

## What changed

1. **The requested range reaches the query.** It used to read the tier's
   maximum and trim the axis afterwards, so `?range=30` read six years.
2. **The page renders the window it draws and widens through
   `/api/chart`**, which carries an hour of cache the per-viewer search
   page cannot. 207KB to 9.2KB on the measured card.
3. **A roster's cards are read together.** Ten cards: 848ms serial, 301ms
   concurrent, bounded so one roster cannot take the whole pool.
4. **A gap is `null`.** Four bytes rather than thirteen, and Chart.js's own
   gap value. Full-window payload 207KB to 113KB, and sparse history is now
   cheaper than dense rather than dearer.

A roster still renders its whole span inline: its select starts on "All",
so narrowing it would mean reading six months and then immediately
fetching the rest. Narrowing rosters belongs in their default range.

A window with no prices in it renders the whole span instead. A retired
printing, or a product no longer priced, has history only further back,
and hiding its chart would also hide the select that widens it.

## Still open

- 28 empty future partitions are scanned by every query against `prices`.
  Small at execution (~0.7ms), mostly a planning cost the prepared
  statement already covers.
- The legacy wide tables (`product_prices` 38GB, the non-Magic TCGplayer
  price tables ~20GB) are a quarter of the database and still dual-written
  while `long_form_reads` is on. They compete for that 979MB.
- The app is in NYC1 and the databases in SFO3: `deploy/REGION-MOVE.md`.
