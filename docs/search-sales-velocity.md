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
the table's oldest rows were pulled that way, so they hold at most five
orders a day; the window is past them.

`tcgplayerlastsalemodel` holds one row per product and printing: the newest
order through the end of the day before the pull, with its time, condition,
per-copy item price, shipping and quantity. The same pull writes it, from
pages it already fetches. Issue #1405.

## The metric

Per card uuid, a printing in one finish:

- copies and orders summed over the 30 days ending on the last complete
  sale day, the one before the newest `sale_date` of any game in the table;
- the price, each day's `median_price` over the window weighted by its
  orders (`total_revenue` is no price: it ignores each sale's quantity);
- the orders in the window's last 7 days, for its trend;
- the days in that window with a sale;
- the first and last sale over the 365 days ending on the same day;
- the last sale's price and condition, from the newest order of the card's
  pairs. It is used when it is not older than the last sale date above, which
  it then replaces. That date can fall a day past the window's end, since the
  order is written while that day's counts are still partial.

The rate is the copies over 30, to one decimal.

## Three states

| State | When | Rate | Details |
|---|---|---|---|
| No data | no sale in 365 days | no row | none |
| Zero | sales in the year, none in the window | `0/day` | `no sale in 30 days`, then the last sale with its price and condition when known |
| A rate | copies in the window | `2.3/day`, or `<0.1/day` under a tenth | copies, orders, days with a sale, then the trend and the last sale with its price, condition and date |

`text` (`internal/salesvelocity`) writes both. The counts sit two label and
value pairs a row, `copies 458 · days 30/30` over `orders 391 · vs. $30–100
top 1%`, and a rule sets the trend and the last sale off below them:
`last sale | $12.34 LP · Nov 17`. The date carries its year only when that
is not the year of the window's last day. The rule is a blank line in the
tooltip format, which ends a table (`tipBlocks`, templates.go). The row's
name says what the details count, so they have no heading; the other pages'
tooltip adds `Sold on TCGplayer, last 30 days` (`salesvelocity.Heading`).

The price is the item's, per copy, without shipping. Conditions print as NM,
LP, MP, HP and DMG, any other as TCGplayer sends it, and a sealed product's
Unopened not at all. With no order on record the lines show the date alone.

The row is a `<details>` on both layouts, showing the rate and opening on a
click or tap to the details, so a phone reads what a desktop reads. A phone
card with sales and no buylist gets a Buyers panel to hold it, saying there
are no offers.

## Its colour

The rate is coloured by how fast the card sells against cards of a like
price, since copies a day hold level to about $30 and fall above it: a $500
card selling every other day is a fast one, a $1 card doing the same is not.
`grade` (`internal/salesvelocity`) splits the cards with a sale in the window
into bands at $1, 3, 10, 30, 100 and 300, a band of under 200 cards joining
the one below it, and ranks each card by the share of its band it outsells:

| Pace | Share outsold | Shown |
|---|---|---|
| fastest | 90% or more | green, bold |
| fast | 60% or more | green |
| steady | 25% or more | orange |
| slow | less, or no sale in the window | red |

Shares rather than set rates keep the colours right for every game, each
grading its own cards. The search row, on both layouts, and the other pages'
rate take the colour as a `velocity-<pace>` class, and a tooltip on the rate
names the band it was judged in: `Slow for a $10–30 card`, `Among the fastest
$10–30 cards`. A phone, with no pointer to hover, shows the colour alone.

The rate each pace starts from, by band, from `TestSalesVelocityLive`:

| band | cards | fastest from | fast from | steady from |
|---|---:|---:|---:|---:|
| under $1 | 57985 | 3.20 | 0.63 | 0.17 |
| at $1–3 | 43673 | 2.30 | 0.57 | 0.17 |
| at $3–10 | 22783 | 2.90 | 0.60 | 0.17 |
| at $10–30 | 10286 | 2.17 | 0.50 | 0.13 |
| at $30–100 | 4977 | 1.47 | 0.33 | 0.13 |
| at $100–300 | 1319 | 1.00 | 0.27 | 0.10 |
| at $300+ | 659 | 0.70 | 0.17 | 0.07 |

## Its trend

An arrow, `↑`, leads the rate of a card selling at least twice as fast in the
window's last 7 days as in the 23 before them, and the details end their
orders row with `7-day trend | 2.4×`, against those 23 days. It counts orders rather than copies, so
one buyer taking a stack does not make a trend, and it needs 30 orders in the
window: with fewer, chance alone moves a card that far too often. A card first
sold in the window has no pace before it, so a new set's cards, all selling
more each day of their first weeks, are left out rather than all marked.
Past 5× the line reads `over 5×`: by then the days before hold an order or
two, and a figure like 95× measures them rather than the trend.

Only a rise is marked. A card slowing to half its pace is mostly chance at
these counts, and every set's cards slow as they age.

The cards with enough orders and a sale before the window, those marked, and
those chance alone would mark were each card's orders spread evenly over the
window, from `TestSalesVelocityLive`:

| cards with enough orders | rising | by chance |
|---:|---:|---:|
| 28877 | 984 (3.4%) | 321 (1.1%) |

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

Arbitrage, Reverse and Global show the rate as text beside the card's name, and
upload's optimizer in the INFO column beside Card Kingdom's signal where it shows,
each with the row's details as its tooltip. Upload's results table has no such column and shows
no rate. A rate that prints as `0.1/day` or less is left out, being noise on these
tables. Each page reads the loaded sales once and fills its rows' text from them
(`cardMetadata.fillSales`), so the line costs only its own HTML. These pages
check no tier: every tier with Arbitrage, Reverse or Global also has the
Newspaper, and on upload's optimizer, which Pioneer also reaches without it,
the rate is allowed through. These pages have no phone layout
of their own, so a phone gets the same line.

That rests on the ACL alone, and nothing in the code checks it: an
`acl.json` edit that gives a tier Arbitrage, Reverse, Global or Sleepers
has to give it the Newspaper too, or that tier reads the rates without it.

## On the Sleepers page

`?page=velocity` ranks cards by the same copies over 30: the S tier starts at about
25 a day, then 13, 6, 3 and 1, the E tier holds the rest, and the F tier the slowest
the page ranks, a card with two copies in the window. A single copy is left out. The
log and the cap at 50 a day (`velocityTierCap`) set those bands; without the cap one
card far ahead of the rest would have S to itself. Like every Sleepers tier, each shows its 34
priciest cards, so a tier is the most valuable of what sells that fast.

Every tier with Sleepers also has the Newspaper, so the page checks no tier. With no
sales loaded, its card is not on the index.

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

A search reads the loaded sales once, into `SearchConfig.Sales`, and
`unlockVelocity` hands the filters the same load, so a load published
mid-request cannot filter on one day and show or sort by another.

## The loader

`internal/salesvelocity`, modeled on the listings loader (`tcglistings.go`).
`salesvelocity.go` wires it to the site and holds the filters and their locks.
It runs right after the Newspaper pages refresh, every three hours and
after each datastore load, because the newspaper writes one sale day a day.
It reads whether this game has a sale in the window, then the newest sale day
of any game, and stops if the day before it is already loaded for the
current datastore, or if its last load failed less than six hours ago. Two queries then run in one
read-only transaction, their date bounds computed in Go from that day:
the window grouped by product and printing, and the last sale per pair
over the year. A third, `LastOrderQuery`, runs after the transaction ends:
`tcgplayerlastsalemodel` is overwritten in place, and a failed statement
would abort the transaction. It reads the newest order per pair, whatever
its date. A missing table or a denied read loads the rates and dates
without prices and says so on the job's dashboard row; that row also counts
the cards with a price. The count and the note are kept on the snapshot, so
the row keeps them on the loads that find the day already loaded.

With no game column, the game's day query and the window and lookback keep
to this deployment's game through the listings loader's semi-join on
`tcgplayerproductinfomodel`'s `game_name`. That keeps each deployment to
its own game and makes the unmatched count mean something. A product with
sales but no info row is left out. The other day query reads every game's
sales, since the day being written is the same for all of them.

Both day queries walk the date index down from the newest sale, the game's
stopping at this game's first and the other at the first row of any game. A
`max()` has to read every row it covers, which is a scan of the whole table.
They look back over the window only, so a game that stops selling costs a few
seconds rather than a walk of the whole index; such a game loads nothing and
keeps its last load.

Each pair resolves to a card through `b.Match` with the product id and
the printing, as TCGplayer's own prices are filed. Two pairs on one card
add their copies and orders; their days with a sale keep the larger
count rather than the sum, since the window rows cannot say which days
overlap. A pair no card matches is counted and dropped: a finish the
printing lacks, or a product the datastore does not carry, such as a
sealed item. A load that matches no card fails and keeps the
previous one.

The newspaper writes a sale day as it pulls each product of every game, over
hours, so the newest `sale_date` of any game holds only part of its sales
while that runs. So the window ends on the day before it, and the rates run a
day behind the newest sales. A game with no sale on that day or the ones
before has empty days at the end of its window, which are complete all the
same. A pull keeps only sales dated the day before it runs, so that day takes
no more rows once the newest has its first. The loader reruns once a new sale
day appears in any game, which is also when the one before it is complete, so
every game loads once a day.

## What it costs

`TestSalesVelocityLive` (`internal/salesvelocity/live_test.go`) runs the queries
against the configured newspaper database, read-only, builds the snapshot
on the local datastore and prints the two tables below and the ones under
"Its colour" and "Its trend". They were
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

The last-orders row of the first table and the count of priced cards appear
once the test is rerun against a filled table.

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

## Recent orders

Each card's newest TCGplayer orders per grade, for search's Sales
column, load beside the velocity from the newspaper's
`tcgplayerrecentsalemodel`. The `Recent sales` job runs every three hours
and reads only the orders stamped since its last load, and every order of
the game once a day. The pull writes them once a day, over a few hours, so most
runs find nothing new.
ADR-0009 has the design, and `TestRecentSalesLive` measures the load and its
heap, the same way the velocity's live test does:

    NEWSPAPER_LIVE=1 NEWSPAPER_LIVE_CONFIG=<absolute path> go test ./internal/salesvelocity -run TestRecentSalesLive -v

### The median sale on Arbitrage

Arbitrage, and neither Reverse nor Global, ends with a section selling at the
median sale, `TCG Median Sale`, for a reader with `SearchSales`. Each row
compares the store's price with the median of the card's order prices in the
row's condition, per copy, before shipping and fees. The choices below were
backtested on the stores' Magic prices, pricing each card without its newest
order and checking the rows against that order:

- **The median** over the average, which one stray sale moves though the two
  do about as well. A lower percentile lists fewer cards and loses less, and a
  higher one lists far more: at the 90th the rows lose money as a whole.
- **No ceiling at the cheapest TCGplayer listing.** Holding the price to it
  lists half as many cards and loses much less often, mostly by leaving out
  cards whose price has dropped since the sales. A row here can be one of
  those, so its newest sales are worth a look.
- **Five orders at least, from the last 90 days, all of the up to 20 kept.** A
  busy card's 20 can span a few days. The median moves little with any of
  these; a price from the newest five alone did worse.
- **Each order once**, so one bulk order does not set the price.

## Why not the most-searched cards first

The ticket suggested filling in the most-searched cards first. One pass
builds every card in about a minute, the first table's total, once a day
when the newspaper adds a sale day, so there is nothing to put first.
