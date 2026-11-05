# Sales velocity on search

Search shows, in a row at the top of each result's Buyers, how many copies
of the card sell on TCGplayer a day. The number comes from the newspaper's
TCGplayer sales scrape and is shown to the tiers that have the Newspaper
page; the others get a line offering it. Issue #220.

## The data

`tcgplayersalesdata` in the newspaper database holds one row per
TCGplayer product, day and printing (`variant`: `Normal`, `Foil`, and for
other games `1st Edition`, `Holofoil`, `Reverse Holofoil` and the like)
with `sales_count`, the copies sold, and `num_orders`, the orders they
came in. A row exists only for a day with a sale. There is no game
column: TCGplayer's product ids are global.

The newspaper pulls TCGplayer's `latestsales` for each product with a
signed-in cookie. Signed out, TCGplayer returns only the newest five sales, and
rows before 2026-10-13 were pulled that way, so they hold at most five orders
a day. A window ending before 2026-11-11 reaches back past that date and reads
low on the busiest cards.

## The metric

Per card uuid, a printing in one finish:

- copies and orders summed over the 30 days ending on the last complete
  sale day, the one before the newest `sale_date` in the table;
- the days in that window with a sale;
- the last sale over the 365 days ending on the same day.

The rate is the copies over 30, to one decimal.

## Three states

| State | When | Rate | Details |
|---|---|---|---|
| No data | no sale in 365 days | no row | none |
| Zero | sales in the year, none in the window | `0/day` | `no sale in the window; last sold` and the date |
| A rate | copies in the window | `2.3/day`, or `<0.1/day` under a tenth | copies, orders, days with a sale, last sale |

`velocityText` (salesvelocity.go) writes both. The details open with
`Sold on TCGplayer, last 30 days`.

The row is a `<details>` on both layouts, showing the rate and opening on a
click or tap to the details, so a phone reads what a desktop reads. A phone
card with sales and no buylist gets a Buyers panel to hold it, saying there
are no offers.

## Who sees it

`newspaperTier` (news.go) decides, by the rule the Newspaper page and the
screener use: a `NewsEnabled` of `0day`, `1day` or `3day`, or dev mode
with signing off. The search handler sets `SearchVars.CanVelocity` from
it, and both search templates render the row only under it. Every
result card carries the text whoever reads the page, since it costs a
map read and two short strings; the oEmbed preview renders its own
markup and never shows it.
Nothing else is gated.

Any other reader sees `Increase your tier to unlock sales velocity` in the
row's place, linking to Patreon, on the cards that have data and so would
show a row. The `noUpsell` search setting hides it, as it does the other
upsell lines.

## Searching by it

`v>1` or `velocity>1` finds the cards selling more than once a day, and `<`
those selling less, by the same copies over 30 the row shows. A card with no
data matches neither, and `-v>1` keeps
it. Each printing is judged on its own finish.

The filter parses locked, and a locked one matches nothing, negated or not,
because the parser has readers that check no tier: Discord, oEmbed, the API,
the popular searches and the search suggestions. Search and the site's export
unlock it for a `newspaperTier` reader, sharing the row's rule; anyone else
searching with it finds nothing and is told `Increase your tier to filter by sales velocity`.

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

The newspaper writes a sale day as it pulls each product, over hours, so the
newest `sale_date` holds only part of its sales while that runs. So the window
ends on the day before it, and the rates run a day behind the newest sales. A
pull keeps only sales dated the day before it runs, so that day takes no more
rows once the newest has its first. The loader reruns once a new sale day
appears, which is also when the one before it is complete.

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
| newest sale day | 12794 | 1 |
| 30-day window | 3897 | 144841 |
| last sale over 365 days | 21453 | 163985 |
| match and build (cards) | 583 | 157501 |

Entries are the cards with a sale in the year, and zero counts the cards with no sale in the window. Unmatched pairs
count the product and printing pairs no card matches. The last column
derives this game's pairs again from `tcgplayerproductinfomodel`, apart
from the queries, and counts those unmatched; matching the column before
it shows the semi-join kept to the game.

| entries | zero | unmatched pairs | this game's pairs unmatched |
|---:|---:|---:|---:|
| 157501 | 16959 | 6479 | 6479 of 163985 |

## Why not the most-searched cards first

The ticket suggested filling in the most-searched cards first. One pass
builds every card in about a minute, the first table's total, once a day
when the newspaper adds a sale day, so there is nothing to put first.
