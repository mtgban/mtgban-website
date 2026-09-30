# ADR-0004: Card Kingdom buylist signals follow CK's pricing rule

**Status:** Accepted
**Date:** 2026-10-01
**Deciders:** Vittorio Giovara

## Context

The site marks Card Kingdom's buylist offer on a card: **sell now** (green),
**wait** (↑), the `90d high`, `New high` and `Paused Nd` pills, the
`on:cksell` and `on:ckwait` filters, and tooltips with the chances behind
them. These are public; this ADR sets the rules and numbers behind them.

The rules come from recovering how CK sets its buy price, from the
newspaper's daily snapshots of CK's whole list (buy price, NM retail, copies
wanted, copies in stock), keyed by CK's product id.

### How it was measured

- **Cohort:** printings CK pays $3 or more for. The Reserved List and sets
  released through 1994 (Old School) are measured apart, as one group.
- **Window:** every newspaper snapshot. Rules are found on the snapshots up
  to the second-to-last main-set release before the measurement and checked
  on the ones after it (two release cycles). A missing day is unknown, not
  a copy of the day before.
- **Units:** printings, price changes, or stretches (one out-of-stock run or
  pause); each count sits beside its number.
- **Outcome:** what a seller sees: CK paying more, or less or nothing, a
  week and a month later.
- Prices over five years (CK retail, TCG Market) come from the site's price
  history, for seasons, release cycles and reprints.

The analysis, its scripts and every number below:
[mtgban/ck-buylist-analysis](https://github.com/mtgban/ck-buylist-analysis).

### How CK prices its buylist

1. **The buy price is a lookup, not a formula.** At each retail price CK
   pays one of a short list of buy prices, about five per retail price and
   finish, near retail × 0.40, 0.45, 0.50, 0.55, 0.60, 0.65:

   | Retail | Finish | Buy prices CK uses |
   |---|---|---|
   | $9.99 | both | 3.00, 4.00, 5.00, 5.50, 6.00, 6.50, 7.00 |
   | $13.99 | nonfoil | 5.75, 6.50, 7.00, 8.00, 8.50, 9.10, 9.80 |
   | $13.99 | foil | mostly 5.60, 7.00, 8.40 |
   | $39.99 | nonfoil | 18, 20, 22, 23, 25, 26, 28 |
   | $99.99 | both | 35, 40, 45, 50, 55, 60, 65 |

   A printing is on one of two lists at a retail price: the exact one
   (retail × the step, to the cent: most foils) or a rounded one (most
   nonfoils, Secret Lair foils). The lists learned before the holdout give
   the exact new buy price of 99.4% of its nonfoil price changes (185,594
   over 12,464 printings) and 99.8% of its foil ones (141,799 over
   18,387). The base is NM retail; CK's LP price is 0.80 of it.
2. **The step moves with need.** CK moves its step the day it changes the
   copies it wants: when it doubles them it steps up 52% of the time, when
   it halves them it steps down 55%; with the count unchanged 1.7% up and
   2.5% down. The count does not lead the step; both are CK's output. Need,
   (wanted − stock) / wanted, orders the steps of a printing 83–89% of the
   time. A step move is undone by the next one 35–47% of the time, within
   2–3 days.
3. **Retail carries the lasting moves.** CK moves retail one rung of its
   price ladder at a time, raising two to three times as often as cutting;
   a move with a retail change is undone 5–9% of the time. Stock leads it:
   after a sellout CK raises retail within a week on 79% of nonfoils and 44%
   of foils (28% and 12% typical). CK follows TCG Market up: after a 10%+
   week, retail up within a week 47% against 28% (nonfoil).
4. **A pause ends the step's walk down.** CK stops buying at its lowest
   step (foils at 0.40 of retail on 60% of pauses) and comes back at the
   price it lists that day (median 1.00 at every age). What falls with the
   pause's age is the chance it comes back within 30 days: 96% after a
   two-day pause, 74% after a month (nonfoil; 91% and 60% foil).
5. **Across the list:** a new release is raised in waves for about a month,
   then cut more than raised in weeks 4–7 (expansions: 114 raises against 43
   cuts per 1,000 printings a day in its first two weeks, 56 against 76 in
   weeks 4–7; 29 against 15 for older sets). A card moving with its set, or
   on CK's busiest days, means what a card moving alone means. CK raises
   most in March and cuts most in June–July. A Modern Horizons-type,
   Commander or Masters reprint takes 8–17% off CK's price of the older
   nonfoils within two months.

## Decision

1. **The signals apply where CK pays $3 or more**: sell now, wait, the
   `New high` and `Paused Nd` pills, and their filters.
2. **Good, Highest, `90d high`, `New high` and the hotlist keep their 90
   days**, as display references: none decides a verdict, and no
   measurement picks a display window. Good stays the level other stores'
   offers are compared with (green at or above it).
3. **Wait (↑)** when any of:
   - CK's stock halved since yesterday, from 3 or more;
   - CK sold out today;
   - TCG Market rose 10% or more over the last week.
4. **Sell now (green)** when any of, and no wait:
   - the card's set is 4 to 7 weeks past its release;
   - the card was reprinted in a Modern Horizons-type, Commander or Masters
     set released in the last 60 days;
   - CK's retail is twice TCG Market or more.
5. **Neutral** otherwise.
6. **A paused card** (CK's last known offer, on a printing CK bought in the
   past year) shows `Paused Nd`. Its ↑ shows when the chance CK buys again
   within 30 days, times the chance it comes back above the best other cash
   offer, is over one half, both for the pause's age and the card's finish.
   CK's last known offer is never green.
7. **The facts line** (display only): CK's stock now and a week ago, days
   out of stock, TCG Market's move over the week, CK's retail against TCG
   Market.
8. **Tooltips** quote, for the card's price bucket (CK's retail: $5–10,
   $10–20, $20–50, $50–100, $100–200, $200+) and finish, the chances CK pays
   more and less or nothing a week and a month later, for the verdict and
   for typical, with the printings behind them. A cell under 300 printings
   quotes the finish over all buckets. The Reserved List and Old School
   quote their own group; its foils, too few, quote the finish's.
9. **`ckodds` measures the chances every day**, in the analysis
   repository, and publishes them as `ck-odds-v2.json.xz` beside the
   datastore: the verdicts' and typical cells by bucket and finish, `New high`'s, and the pauses' (back within 30
   days and the return price against the listed one, by age and finish).
   The site reads only that file. The rules are this ADR's: the daily run
   refreshes the odds, not which rules exist.
10. **A rule the loaded file does not list does not hold.** Before a file
    loads there are no colors; the pills and the facts show.
11. **The rules are re-decided when a release cycle completes**, by hand,
    on the new cycle as the holdout; a change is logged here. If a side has
    no rule that holds, the site keeps the one it had.
12. **The guide explains the colors without numbers**; the tooltips carry
    them.

## Options considered

### Wait: strict (chosen) or broad

Broad adds every other wait signal that held on its own: out of stock
(1–7 days for nonfoils, 8+ for both), stock fell, retail under TCG Market
(nonfoils). On the holdout, CK paying more / less or nothing a week later
[typical]:

| Finish | Wait | Days it fires on | Printings | A week later | A month later |
|---|---|---|---|---|---|
| nonfoil | strict | 4.7% | 6,152 | 52 / 28 [36 / 38] | 53 / 41 [45 / 46] |
| nonfoil | broad | 31.2% | 10,438 | 44 / 31 [36 / 38] | 52 / 40 [45 / 46] |
| foil | strict | 3.9% | 11,406 | 34 / 19 [20 / 24] | 49 / 36 [39 / 40] |
| foil | broad | 17.9% | 17,908 | 32 / 19 [20 / 24] | 50 / 36 [39 / 40] |

Strict is the stronger signal and fires on a sixth of the days. On the
Reserved List and Old School, broad fires on half their nonfoil days with
little edge (23 / 22 against 19 / 24), strict on 3% with a clear one
(36 / 19). The broad signals go in the facts line.

### Sell now: without a new high (chosen) or with

On the holdout, CK paying more / less or nothing [typical]:

| Finish | Sell | Days it fires on | Printings | A week later | A month later |
|---|---|---|---|---|---|
| nonfoil | without | 6.3% | 1,781 | 27 / 45 [36 / 38] | 33 / 58 [45 / 46] |
| nonfoil | with a 90-day new high | 8.7% | 7,709 | 24 / 45 [36 / 38] | 34 / 58 [45 / 46] |
| foil | without | 9.6% | 3,169 | 14 / 24 [20 / 24] | 28 / 45 [39 / 40] |
| foil | with a 90-day new high | 11.1% | 11,747 | 13 / 24 [20 / 24] | 29 / 46 [39 / 40] |

The two look alike there, but nothing measured chose the 90 days.
The window was measured on every raise CK made over five years of its
prices (`results/newhigh_window.md` in the analysis): how far back CK last
paid as much, and what it paid a week and a month later, in two eras either
side of a gap in the price backup, the first training and the second
checking.

- The further back a raise reaches, the more often CK cuts afterwards. There
  is no turning point at 90 days or anywhere else.
- A week out, any window of 60 days or more holds.
- A month out, no window does. A high over the last two to twelve months was
  followed by further raises as often as by cuts in the checking era (foils
  a month later: 49 / 37, against 43 / 33 typical). For nonfoils the 90-day
  window keeps 14 of the 31 points of edge it had in the first era, under
  the half that holding asks.
- Only CK's highest price on record held a week and a month out, in both
  eras and both finishes (nonfoil a month later: 36 / 56, against 45 / 44).

Sell now goes without a new high. The highest price on record can join it
once `ckodds` measures it on CK's whole history; the newspaper's covers
under a year. The `New high` pill stays, with its own odds.

### Signals tested and left out

- **The step against the printing's usual one.** It predicts CK's next
  step, but not the price a week later: retail moves and pauses swamp it.
- **TCG Market up 3–10% in a week**: 40 / 37 against 36 / 38, too weak.
- **A set's first three weeks**: CK pays more a week later (53 / 35), less a
  month later (36 / 62): no single verdict.
- **A 20% cut in 7 days**: two different moves (a step and a retail cut),
  the step one undone.
- **CK's price against its P90**: a flat P90 made "at or above it" fire on
  45% of days.
- **Other stores' offers against CK's**: they measure the other stores, not
  CK.

### Floor and windows

The floor is $3 ($1 before; $4 was proposed; the analyst's own scripts
kept `todays_bl >= 3`). The 90 days of the display references are a display
choice; the rules are measured over release cycles, not calendar windows.

## Consequences

- On the newest snapshot CK buys 34,866 printings at $1 or more; the
  11,305 under $3 lose their marks and pills.
- Wait fires on about 4–5% of days and sell now on 6–10%; the rules they
  replace fired on about 14% (wait) and 10% (sell now).
- `ckodds` moves from go-mtgban to the analysis repository and changes its
  output and file name; the site reads the new file the day it ships, and
  the old one stops updating.
- The pause's wait no longer depends on other stores' measured odds; it
  compares CK's own return chances with the offers on the page.
- The tables above are one measurement; the tooltips follow the daily file.
- The newspaper's stock history covers under a year: seasons are measured on
  prices only until it covers a full one.
