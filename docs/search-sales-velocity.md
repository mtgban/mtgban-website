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

`text` (`internal/salesvelocity`) writes both. The details open with
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

## On the other pages

Arbitrage, Reverse, Global and upload's optimizer show the rate as a line of
text in the INFO column, beside Card Kingdom's signal where it shows, with the
row's details as its tooltip. Upload's results table has no such column and shows
no rate. A rate that prints as `0.1/day` or less is left out, being noise on these
tables. The rows already carry the text from `uuid2card`, so the line costs only
its own HTML. These pages check no tier: every tier with Arbitrage, Reverse or
Global also has the Newspaper, and on upload's optimizer, which Pioneer also
reaches without it, the rate is allowed through. These pages have no phone layout
of their own, so a phone gets the same line.

## On the Sleepers page

`?page=velocity` ranks cards by the same copies over 30: the S tier starts at about
25 a day, then 13, 6, 3 and 1, the E tier holds the rest, and the F tier the slowest
the page ranks, a card with two copies in the window. A single copy is left out. The
log and the cap at 50 a day (`velocityTierCap`) set those bands; without the cap one
card far ahead of the rest would have S to itself. Like every Sleepers tier, each shows its 34
priciest cards, so a tier is the most valuable of what sells that fast.

The order is as revealing as the sort, so a reader without the tier gets the index,
where the page's card is greyed out with a tooltip. With no sales loaded, the card is
not there at all.

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

`sort:velocity`, or the pill beside the other sorts, ranks any search fastest
first, with reverse for slowest first. Cards with no data sort last either way.
An order says which cards sell fastest as surely as a filter, so `readSearchSort` falls back to the default unless a
handler set `SearchConfig.VelocitySort`, which Search and the export do for a
`newspaperTier` reader. Others get the default order and, once sales are loaded,
the pill greyed out with no link and the tooltip `Increase your tier to sort by
sales velocity`, even after typing `sort:velocity`, which otherwise hides the pills.

## The loader

`internal/salesvelocity`, modeled on the listings loader (`tcglistings.go`).
`salesvelocity.go` wires it to the site and holds the filters and their locks.
It runs right after the Newspaper pages refresh, every three hours and
after each datastore load, because the newspaper writes one sale day a day.
It reads the newest sale day and stops if that day is already loaded, or
if its last load failed less than six hours ago. Two queries then run in one
read-only transaction, their date bounds computed in Go from that day:
the window grouped by product and printing, and the last sale per pair
over the year.

With no game column, all three queries keep to this deployment's game
through the listings loader's semi-join on `tcgplayerproductinfomodel`'s
`game_name`: the day query, and the window and lookback that follow it.
That keeps each deployment to its own game and makes the unmatched
count mean something. A product with sales but no info row is left out.

The day query walks the date index down from the newest sale and stops at
this game's first. A `max()` has to read every row the game has, which for
Magic is a scan of the whole table. It looks back over the window only, so a
game that stops selling costs a few seconds rather than a walk of the whole
index; such a game loads nothing and keeps its last load.

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

`TestSalesVelocityLive` (`internal/salesvelocity/live_test.go`) runs the queries
against the configured newspaper database, read-only, builds the snapshot
on the local datastore and prints the two tables below. They were
measured on the Magic datastore when the feature was built, the window
ending on the last complete sale day; rerun the test to refresh them. It skips
unless `NEWSPAPER_LIVE` is set, and without the datastore:

    NEWSPAPER_LIVE=1 NEWSPAPER_LIVE_CONFIG=<absolute path> go test ./internal/salesvelocity -run TestSalesVelocityLive -v

The test runs in its package directory, so a relative path would resolve there;
with none set it reads the repo's `config.json`.

The queries, timed apart rather than in one transaction, and the match
and build in Go:

| query | ms | rows |
|---|---:|---:|
| newest sale day | 185 | 1 |
| 30-day window | 18488 | 144841 |
| last sale over 365 days | 47987 | 163985 |
| match and build (cards) | 701 | 157501 |

Entries are the cards with a sale in the year, and zero counts the cards with no sale in the window. Unmatched pairs
count the product and printing pairs no card matches. The last column
derives this game's pairs again from `tcgplayerproductinfomodel`, apart
from the queries, and counts those unmatched; matching the column before
it shows the semi-join kept to the game.

| entries | zero | unmatched pairs | this game's pairs unmatched |
|---:|---:|---:|---:|
| 157501 | 16959 | 6479 | 6479 of 163985 |

## Watching the pull

The rates are only as good as the newspaper's TCGplayer logins. `CheckPull`
checks hourly, on the Magic site alone since every site reads the same table,
and reports on the `Newspaper sales` job's row, so the admin dashboard shows it
and `checkJobHealth` announces it and its recovery on Discord. It looks across
every game, at the newest sale day once it holds 10,000 rows, which takes about
an hour of the pull, and otherwise at the day before.

- **Signed out:** under 1% of the day's rows have over five orders. Signed in it
  has stayed between 5% and 19% on finished days through the signed-in stretches
  of the last year, 3.5% at 10,000 rows into a day, and signed out it is exactly
  none. So it fires within a couple of hours of a signed-out pull starting.
- **Stopped:** the newest sale day is over 72 hours old. Waiting on the next pull
  it reaches about 56, so `StaleAfter`'s 48 would fire every day. The newspaper
  stops its pull when no login works, so this is the likely shape of a full expiry.

A pull that stops partway through a day leaves it short but not signed out, which
neither check catches.

## Why not the most-searched cards first

The ticket suggested filling in the most-searched cards first. One pass
builds every card in about a minute, the first table's total, once a day
when the newspaper adds a sale day, so there is nothing to put first.
