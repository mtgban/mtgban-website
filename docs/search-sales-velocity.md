# Sales velocity on search

Search shows, in each result's header, how many copies of the card sell
on TCGplayer a day. The number comes from the newspaper's TCGplayer sales
scrape and is shown to the tiers that have the Newspaper page. Issue #220.

## The data

`tcgplayersalesdata` in the newspaper database holds one row per
TCGplayer product, day and printing (`variant`: `Normal`, `Foil`, and for
other games `1st Edition`, `Holofoil`, `Reverse Holofoil` and the like)
with `sales_count`, the copies sold, and `num_orders`, the orders they
came in. A row exists only for a day with a sale. There is no game
column: TCGplayer's product ids are global.

The newspaper keeps at most five orders per product a day. On a day with
five orders, both the orders and the copies are floors: the card may have
sold more. The badge and its tooltip say so.

## The metric

Per card uuid, a printing in one finish:

- copies and orders summed over the 30 days ending on the newest
  `sale_date` in the table, not today, since the scrape lags a day;
- the days in that window with a sale;
- capped, when any day in the window has five orders;
- the last sale over the 365 days ending on the same day.

The badge is the copies over 30, to one decimal.

## Three states

| State | When | Badge | Tooltip |
|---|---|---|---|
| No data | no sale in 365 days | none | none |
| Zero | sales in the year, none in the window | `0/day` | `no sale in the window; last sold` and the date |
| A rate | copies in the window | `2.3/day`, or `<0.1/day` under a tenth | copies, orders, days with a sale, last sale |

`velocityText` (salesvelocity.go) writes both. Each tooltip opens with
`Sold on TCGplayer, last 30 days`. A capped rate reads `>=2.3/day`, and
its tooltip marks the copies and orders `(at least)` and ends with `the
newspaper keeps five orders a day, so these are floors`. A capped rate
under a tenth would still print `<0.1/day`: the small-rate form takes
priority over the floor mark.

## Who sees it

`newspaperTier` (news.go) decides, by the rule the Newspaper page and the
screener use: a `NewsEnabled` of `0day`, `1day` or `3day`, or dev mode
with signing off. The search handler sets `SearchVars.CanVelocity` from
it, and both search templates render the badge only under it. Every
result card carries the text whoever reads the page, since it costs a
map read and two short strings; the oEmbed preview renders its own
markup and never shows it.
Nothing else is gated.

## The loader

`salesvelocity.go`, modeled on the listings loader (`tcglistings.go`).
An hourly job at `:55`, and a run after each datastore load, read the
newest sale day and stop if that day is already loaded, or if its last
load failed less than six hours ago. Two queries then run in one
read-only transaction, their date bounds computed in Go from that day:
the window grouped by product and printing, and the last sale per pair
over the year.

With no game column, all three queries keep to this deployment's game
through the listings loader's semi-join on `tcgplayerproductinfomodel`'s
`game_name`: the day query, and the window and lookback that follow it.
That keeps each deployment to its own game and makes the unmatched
count mean something. A product with sales but no info row is left out.

Each pair resolves to a card through `b.Match` with the product id and
the printing, as TCGplayer's own prices are filed. Two pairs on one card
add their copies and orders; their days with a sale keep the larger
count rather than the sum, since the window rows cannot say which days
overlap. A pair no card matches is counted and dropped: a finish the
printing lacks, or a product the datastore does not carry, such as a
sealed item. A load that matches no card fails and keeps the
previous one.

The newspaper looks to write a sale day in one batch: two probes nine
hours apart on the same day saw the same row count for the newest sale
day, and the day after it had no rows yet. So a day has not been seen
half written, and the loader reruns only when a new sale day appears.

## What it costs

`TestSalesVelocityLive` (`salesvelocity_live_test.go`) runs the queries
against the configured newspaper database, read-only, builds the snapshot
on the local datastore and prints the two tables below. They were
measured on the Magic datastore when the feature was built, the window
ending on the newest sale day; rerun the test to refresh them. It skips
unless `NEWSPAPER_LIVE` is set, and without the datastore:

    NEWSPAPER_LIVE=1 NEWSPAPER_LIVE_CONFIG=<config> go test -run TestSalesVelocityLive -v

The queries, timed apart rather than in one transaction, and the match
and build in Go:

| query | ms | rows |
|---|---:|---:|
| newest sale day | 93 | 1 |
| 30-day window | 26478 | 143939 |
| last sale over 365 days | 31417 | 162692 |
| match and build (cards) | 1163 | 148306 |

Entries are the cards with a sale in the year, capped share is of those,
and zero counts the cards with no sale in the window. Unmatched pairs
count the product and printing pairs no card matches. The last column
derives this game's pairs again from `tcgplayerproductinfomodel`, apart
from the queries, and counts those unmatched; matching the column before
it shows the semi-join kept to the game.

| entries | capped | capped share | zero | unmatched pairs | this game's pairs unmatched |
|---:|---:|---:|---:|---:|---:|
| 148306 | 11608 | 7.8% | 16410 | 14378 | 14378 of 162692 |

A card counts as capped if any day in its window was, so the capped
share of cards runs well above the share of capped days.

## Why not the most-searched cards first

The ticket suggested filling in the most-searched cards first. One pass
builds every card in about a minute, the first table's total, once a day
when the newspaper adds a sale day, so there is nothing to put first.
