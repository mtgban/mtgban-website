# ADR-0004: Card Kingdom buylist signals read CK's stock

**Status:** Accepted
**Date:** 2026-09-28
**Deciders:** Vittorio Giovara
**Change:** PR #682

## Context

The site flags Card Kingdom buylist prices with three signals, all built
from CK's own price history over 90 days:

- **Good** is CK's 90-day P90: `percentile_disc(0.9)` of the buying-day
  prices, shown once a card has 30 of them. An offer at or above it turns
  green (`price-best`), and `on:ckp90` finds cards where CK's offer meets it.
- **Highest** is the 90-day maximum, shown next to Good.
- **The hotlist** (`on:hotlist`, "Highest price in 3 months") marks a card
  whose current CK price ties or beats that maximum.

None of them looks at CK's retail stock, and CK's buylist moves with it: CK
raises what it pays for cards it has sold out of and trims cards it is
restocking. The newspaper database keeps a daily snapshot of CK's whole
price list (`cardkingdomproductmodel`: buy price, quantity wanted, retail
stock), which is enough to measure what each signal predicts.

### How it was measured

CK snapshots from 2025-12-28 to 2026-09-27: 255 of 274 days (a missing day
carries the previous snapshot). Every day from 2026-03-28 to 2026-08-28,
every card CK was buying at $1 or more with a P90 the site would show:
4,901,662 card-days over 50,057 cards. The P90 is recomputed from the
snapshots the way the site computes it from its own price archive.

The outcome is CK's buy price 14 days later:

- **up**: at least 5% higher, CK still buying;
- **down**: at least 5% lower, or CK no longer buying;
- **higher at some point**: at least 5% higher on any day of the 14;
- **avg**: mean log change over the 14 days while CK still buys.

Across all card-days: 33.0% up, 44.6% higher at some point, 35.1% down,
−0.4% avg.

### What the old signals say

An offer at or above P90 is 44.5% of all card-days. CK moves prices in steps
and holds them, so the top step often covers more than a tenth of the last
90 days and today's price *is* the P90. By CK's stock:

| CK's price vs P90 | CK's stock | Rows | Up | Higher at some point | Down | Avg |
|---|---|---|---|---|---|---|
| equals P90 | out of stock | 5.0% | 48.0% | 57.7% | 21.6% | +3.3% |
| equals P90 | halved since yesterday | 0.2% | 47.9% | 70.0% | 27.7% | +2.1% |
| equals P90 | in stock | 23.5% | 25.7% | 33.7% | 31.0% | −2.4% |
| above P90 | out of stock | 5.3% | 34.0% | 41.0% | 28.5% | 0.0% |
| above P90 | halved since yesterday | 0.2% | 39.2% | 60.7% | 33.8% | −2.3% |
| above P90 | in stock | 10.3% | 27.2% | 40.0% | 41.9% | −6.8% |

Only the last row behaves like "take this offer". The first is the opposite:
CK is about to pay more.

The hotlist fires on 32.9% of card-days, and 93% of those are ties with a
flat 90-day maximum. A strict new high is 2.34%, and it reads as a peak:
24.2% up, 33.1% higher at some point, 40.0% down, −6.1% avg. By stock:

| CK's price vs the previous 90 days' max | CK's stock | Rows | Up | Higher at some point | Down | Avg |
|---|---|---|---|---|---|---|
| new high | in stock | 1.5% | 24.8% | 35.1% | 44.7% | −8.4% |
| new high | out of stock | 0.9% | 23.2% | 29.6% | 31.6% | −2.2% |
| ties the high | in stock | 22.1% | 25.6% | 34.3% | 32.8% | −3.1% |
| ties the high | out of stock | 8.4% | 42.7% | 51.0% | 24.7% | +1.9% |

### What predicts a move

Evaluated in this order, each row excluding the ones above it:

| State | Rows | Up | Higher at some point | Down | Avg |
|---|---|---|---|---|---|
| stock halved since yesterday, from 3 or more | 1.0% | 51.4% | 73.1% | 27.0% | +3.7% |
| out of stock, price at or below P90 | 6.9% | 48.2% | 57.8% | 20.5% | +4.2% |
| buy price cut 20% or more in 7 days | 6.1% | 47.5% | 68.0% | 42.1% | +14.1% |

- **Stock at zero is the signal, not a falling count.** In stock, a week's
  10–25% drop is followed by more cuts than raises (34.1% up, 42.9% down).
  1–5 copies is not bullish (28.4% up); it is merely quiet.
- **Buyouts are fast.** In 50.6% of them CK has already raised its price in
  the same day's snapshot, and 49.2% see a further raise within 7 days. A
  buyout two or three days old has lost most of its edge (38.1% up against
  32.7% without one).
- **Cuts come back, but not overnight.** Of one-day cuts of 20% or more,
  13.7% are back within 5% the next day, 32.7% within 7 days, 36.7% within
  14. So they are not feed glitches. 19.7% of the cut cards stop being
  bought within 14 days, which is why the down column is high too.
- **Days out of stock change the downside, not the upside.** Out of stock at
  or below P90: 50.0% up / 23.2% down after 1–2 days, 50.1% up / 14.1% down
  after more than 30.
- **Foils and nonfoils differ in degree.** Out of stock at or below P90,
  nonfoils mostly stop falling (19.9% down against 41.3% for nonfoils
  generally) while foils also rise (50.2% up against 29.6%).

The same pattern shows in both halves of the period, with one sample per
week instead of every day, and within each price band from $1–3 to $30+.

### Other stores' offers

The site's own price archive keeps SCG's, ABU's and CSI's buylist prices
since February 2025, without stock. Every Wednesday from 2025-10-01 to
2026-09-09, every offer of $1 or more from those stores on a card with a CK
P90: 3.7M offers over 50,279 cards. The outcome is the store's own offer 14
days later, with "dropped" when the store no longer buys the card:

| Store's offer | Rows | Up | Down | Dropped |
|---|---|---|---|---|
| at or above CK's P90 | 9.8% | 3.6% | 16.1% | 6.6% |
| below CK's P90 | 90.2% | 9.9% | 9.2% | 4.3% |
| above CK's listed price that day | 20.5% | 3.8% | 15.8% | 6.4% |

These stores move far less than CK, but an offer at or above CK's P90 is one
they seldom raise and more often cut or drop. That holds for each store and
in both halves of the period, and by price band everywhere but nonfoils at
$30+, which are cut no more often (9.0% against 8.8%) though raised less
(2.2% against 8.1%). CK paid as much within 14 days for a quarter of these
offers. 85% of them are at or above CK's listed price that day, and "above
CK's listed price" predicts the same on twice the offers.

### When CK pauses a card

CK stops buying a card by setting its buy quantity to 0, and keeps listing
a price it does not pay; the site shows it as CK's last known offer
(CKBLLast). From 2025-12-29 to 2026-09-27 there were 150,313 such pauses on
cards CK had been paying $1 or more for. CK almost never drops a card for
good: 93% of pauses end within 30 days and 99% within 90, and 51 lasted
past 180 days. How long a pause has lasted is what predicts its end, over
1.1M paused card-days:

| Paused so far | CK buys again within 7 days | Within 30 days |
|---|---|---|
| 0–2 days | 62% | 92% |
| 3–6 days | 52% | 88% |
| 7–13 days | 45% | 83% |
| 14–29 days | 32% | 74% |
| 30+ days | 20% | 58% |

CK's stock adds little: 40–49% within a week at every stock level, 54% when
the stock fell over the last 7 days. CK does lower the price it lists while
paused, and after 14 days paused it came back 5%+ below what it last paid
75% of the time.

Whether waiting beats selling elsewhere was measured on the same Wednesdays
as other stores' offers, from 2026-01-07 to 2026-08-26: 168,945 paused
card-days, 81% of them with an SCG, ABU or CSI cash offer of $0.95 or more.
CK's product ids were tied to the archive's cards through the card each
product is filed under in CK's dumps (MTGJSON's Card Kingdom ids agree on
99.9% of products but cover fewer):

| Best other offer vs CK's listed price | Card-days | CK back within 30 days | CK back paying 5%+ more than that offer |
|---|---|---|---|
| under 80% | 15,177 | 74% | 73% |
| 80–95% | 20,385 | 82% | 62% |
| 95–100% | 3,597 | 80% | 26% |
| 100–110% | 18,316 | 83% | 20% |
| 110%+ | 78,864 | 85% | 4% |

With every offer below 95%, waiting paid 76% of the time in a pause's
first week, 66% in its second, 55% at 2–4 weeks and 41% after a month.

### By card category

The same card-days, each card in the first category that applies, by the
rules go-mtgban's `cmd/ckodds` applies (`category.go`):

| Category | A card is in it when |
|---|---|
| Reserved List | it is on the Reserved List |
| vintage | its set was released through 1995 (Alpha to Homelands) |
| Secret Lair | its set is `SLD`, or its set's name contains "Secret Lair" |
| Booster Fun | it is borderless, or has a showcase, extended-art, inverted, etched or shattered-glass frame, in a set released since Throne of Eldraine (2019-10-04) |
| promo | it is a promo printing, or its set's type is promo |
| Commander | its set's type is commander |
| Masters | its set's type is masters, masterpiece, from_the_vault, spellbook, premium_deck or duel_deck |
| recent | its set is two years old or less that day |
| older | none of the above |

CK paid 5% more / 5% less or nothing 14 days on, "–" where the rule met
fewer than 300 products:

| Category | Typical | Sell now | Buyout | Out of stock | Cut 20% | New high |
|---|---|---|---|---|---|---|
| all | 33 / 35 | 27 / 42 | 52 / 27 | 48 / 20 | 48 / 42 | 24 / 40 |
| Reserved List | 27 / 30 | 28 / 45 | – | 25 / 10 | 47 / 41 | – |
| vintage | 26 / 32 | 28 / 47 | – | 29 / 21 | 49 / 43 | – |
| Secret Lair | 38 / 36 | 28 / 39 | 46 / 23 | 45 / 23 | 52 / 38 | 24 / 38 |
| Booster Fun | 36 / 37 | 27 / 43 | 51 / 27 | 51 / 22 | 49 / 42 | 24 / 43 |
| promo | 30 / 33 | 30 / 33 | 62 / 17 | 56 / 20 | 36 / 48 | 26 / 28 |
| Commander | 35 / 39 | 27 / 47 | 52 / 31 | 54 / 22 | 52 / 40 | 27 / 46 |
| Masters | 34 / 40 | 24 / 50 | 52 / 29 | 50 / 22 | 50 / 42 | 22 / 48 |
| recent | 37 / 42 | 27 / 47 | – | 56 / 18 | 50 / 42 | – |
| older | 30 / 32 | 27 / 40 | 52 / 28 | 48 / 19 | 46 / 42 | 23 / 39 |

Most categories follow the whole, around typical rates of their own. Two
do not. On promos sell now shows no edge and a 20% cut is followed by more
cuts, not a raise. On the Reserved List and vintage, out of stock is
followed by a raise no more often than typical, only by far fewer cuts; so
is it on older nonfoils (36 / 17 against a typical 38 / 42), while newer
nonfoils rise (Booster Fun 56 / 27 against 41 / 42). Pauses end at their
own pace too: CK buys again within a week of a pause starting 68% of the
time on Booster Fun and 53–56% on promos and vintage, and after a month
paused 30% against 15–16%.

`cmd/ckodds` measures the same every day over the newspaper's last year of
CK snapshots. Its first run, on 2026-09-29, agreed with this table within
2 points on 50 of its 54 cells, filled 4 of the gaps, and gave the pause
chances above.

## Decision

1. **Good and Highest stay** as reference prices, the level other stores'
   offers are compared with. Good's tint in the optimizer and arbitrage
   details follows the signal (green for sell now, amber for wait) instead
   of the unmeasured 110% and 80% of P90 margins.
2. **The rules apply only where they were measured**: CK buying the card at
   $1 or more, and the card having a P90.
3. **Sell now (green)**: CK's buy price is strictly above its P90, CK has
   stock, and its stock did not halve since yesterday.
4. **Wait (↑)**: CK's stock halved since yesterday from 3 or more; or CK is
   out of stock and its price is at or below P90; or CK cut its buy price by
   20% or more in 7 days. Wait wins over sell now.
5. **Neutral** otherwise.
6. **Only CK's NM offer takes these states.** Other stores' offers keep the
   plain comparison with CK's P90: green at or above it, which for SCG, ABU
   and CSI is a time to sell to them as well.
7. **Facts** show whenever CK is buying: its stock now and a week ago, days
   out of stock, and a buy price change of 10% or more this week.
8. **The tooltips quote the chances measured every day** (17), not the
   tables above.
9. **Filters**: `on:cksell` finds sell now and `on:ckwait` finds wait.
   `on:ckp90`, which matched any price at or above P90, is dropped rather
   than redefined under the same name.
10. **Two pills mark CK's 90-day high**, one at a time: `90d high` when CK
    ties or beats it, the hotlist's meaning, which `on:hotlist` and the
    sleepers page's Hotlist keep; `New high` when CK strictly beats it
    (`on:newhigh`), with its odds.
11. **Stock is CK's total across conditions**, as measured. "Now" comes from
    the site's own CK scraper; yesterday and last week come from the
    newspaper's daily snapshots, reloaded when the day or the newest snapshot
    changes. A missed day or two carries the last snapshot, as in the
    backtest; history more than 3 days old is not used, and yesterday's
    stock only in a history loaded the same day.
12. **Without that history**, buyouts and cuts cannot be seen: wait fires
    only on out of stock, and sell now skips its buyout check (buyouts are
    0.2% of card-days, against 10.3% for sell now).
13. **Signals are computed when their inputs change**: CK's buylist or stock
    reloading, the P90s refreshing, and hourly, which also picks up a new day
    of history. Pages and filters read the result.
14. **A paused card** (CK's last known NM offer of $1 or more) gets a pill
    with the pause's length, from the last day the history saw CK buying:
    `Paused 11d`, or `Paused 30d+` past the history's month. Its tooltip has
    the chances of CK buying again within 7 and 30 days.
15. **Wait (↑) on a pause** when it is under 14 days old and every other cash
    buylist's NM offer is below 95% of CK's listed price, with at least one
    such offer. Cash buylists are every singles buylist but CK's own, ABU's
    credit list, TCGplayer Direct's net payout and lists of wants. Other
    stores' offers get no mark, and paused cards stay out of `on:ckwait`.
16. **CK's last known offer is never green**: CK does not pay it.
17. **Chances by category, measured every day**: go-mtgban's `cmd/ckodds`
    measures them the way this ADR does, over the newspaper's last year of
    CK snapshots, and publishes them with every CK product's category as
    `ck-odds.json.xz` beside the datastore. Every tooltip quotes its card's
    category next to that category's typical chances, and for out of stock
    those of its finish too; pauses and New high included. A cell under
    300 products or 3,000 card-days reads the category's chances over both
    finishes, then those over all cards. The site reads the file again once
    it is 20 hours old; until one loads, tooltips carry their verdicts
    alone.
18. **A rule holds where it has an edge**: on a category and finish, its
    chances beat the typical ones by 5 points or more, raises and cuts
    together (fewer raises and more cuts for sell now, the other way round
    for a wait). Where it does not, the card shows neutral and stays out
    of `on:cksell` and `on:ckwait`. On the first run that takes sell now
    and the cut's wait off promos.
19. **Out of stock that stops cuts without bringing raises** (5 points or
    less over typical) says CK seldom pays less after that, and stays a
    wait.

Windows: 1 day for buyouts, 7 days for stock and price changes, 90 days for
P90, predictions stated over 14 days, and over 7 and 30 days for pauses.

## Options considered

Each flag as a sell-now signal, over the same card-days (up and down as
above; a good flag has a low up and a high down):

| Flag | Rows | Up | Higher at some point | Down | Avg |
|---|---|---|---|---|---|
| A: price at or above P90 (before) | 44.5% | 29.7% | 39.0% | 32.2% | −2.4% |
| B: strictly above P90 | 15.8% | 29.6% | 40.6% | 37.3% | −4.4% |
| C: strictly above P90, in stock, no buyout (chosen) | 10.3% | 27.2% | 40.0% | 41.9% | −6.8% |
| D: C, or a 20% raise this week while in stock | 19.9% | 30.1% | 44.0% | 44.2% | −6.2% |
| E: at the 90-day high | 32.8% | 29.9% | 38.5% | 31.2% | −2.0% |
| F: at the 90-day high, in stock | 23.3% | 25.4% | 34.0% | 33.6% | −3.5% |
| G: 20% above the 90-day median, in stock | 19.0% | 31.7% | 45.7% | 42.1% | −6.6% |

C has the lowest chance of CK paying more later among the flags with a high
down rate. F has a lower up rate, but CK cuts less often after it than on a
typical day (33.6% against 35.1%). D and G fire twice as often at the cost
of more missed raises.

**Dropping P90 altogether** was considered too. It would lose the reference
price other stores' offers are compared with, and the stock rules still need
a level to call "high".

## Consequences

- Green fires on about a tenth of CK's rows instead of nearly half, and out
  of stock cards at their P90 show wait instead of green.
- The hotlist's 33% of CK's rows show a `90d high` pill, except the 2.3%
  that are strict new highs, which show `New high`. `on:hotlist` and the
  sleepers page's Hotlist are unchanged.
- The site reads the newspaper database's CK table: a `MAX(date)` every hour,
  and a one-month aggregate (about 30 seconds) when the day or the newest
  snapshot changes. If it is unreachable the history-based rules stop
  firing; P90 and the live stock still work.
- Every card CK is buying keeps its signal in memory: about 11 MB and 40 ms
  to rebuild per 60,000 cards.
- The tooltips' odds, and which rules hold, follow a year of CK's history
  as it moves; the tables above stay one period's (March to August 2026).
  The pause's wait (15) and its 95% are still that one measurement, as it
  needs the price archive of other stores' offers.
- If `cmd/ckodds` stops running the site keeps the last file it loaded; a
  site started without one shows verdicts without chances.
- Stock is total across conditions, as measured. NM-only stock, which the
  site's CK scraper has, is untested.
- Other stores' green is measured on SCG, ABU and CSI, the buylists the
  price archive keeps; the site's other buylists have no history to measure.
- A pause's wait is measured against those three stores too, but compared on
  the page with every cash buylist, which only makes it fire less.
- Pauses need CK's product id on its last known offers, which go-mtgban
  records since mtgban/go-mtgban#1040, and see other buylists' reloads at
  the next hourly rebuild.
- A card's category comes from the file, by CK's product id, not from the
  card data, which ADR-0003 keeps out of state the site holds; every
  tooltip is built once per load, so reading one is a lookup.
