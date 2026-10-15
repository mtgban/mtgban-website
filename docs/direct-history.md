# Direct price history for the SYP EV fallback

A precon SYP card with no TCG Direct price today is priced, for the TCG
Direct SYP (net) EV, from its trailing-window average of recorded Direct
prices (`directhistory.go`, served in the v2 price API's JSON answers as
`TCGDirectHist`, read by go-mtgban's sealedev; v2's `.csv` goes through
v1's writers and never carries it). The window and the sample floor below were
measured on real precons, so the choice is a number rather than a guess.

## Method

`scripts/direct-window` derives each precon SYP card's daily Direct price
from the newspaper's listings (the lowest Near Mint listing with Direct
inventory for the card's TCGplayer product and printing, which is how the
site's TCGDirect scraper prices) over the newspaper's rolling window, the
last seven days at the time of the run. It treats the newest day as today:
for cards priced today it predicts today's price from the trailing 3-day
and 7-day averages, excluding today, and reports the absolute percentage
error; for cards unpriced today it reports whether each window holds an
observation (coverage). Both are split by sample floor, 1 and 2.
Etched printings were measured under their base product, and listings of
every language were pooled.

The 30-day window could not be measured: the listings keep a week, and the
archive starts recording Direct prices only once the Magic datasets file
carries the entry (`{"retail": ["TCGDirect"], "provider": 7, "index": 10}`)
and this change ships, since the stash now files a dataset with no wide
column under its provider. Until the entry is deployed the job's dashboard
row reads `waiting for the Direct dataset` and raises no alarm; once the
datasets table names provider 7, an empty window is reported as a problem.
The job runs on the Magic site only: the archive's Direct rows are Magic
uuids, which another game's datastore folds to nothing.

## Numbers

```
precons with a decklist: 1812, SYP cards in them: 4093, skipped without a product id: 0
listings: 7 days ending on the newest day, today = the newest
```

| window | priced today, predicted | median APE | mean APE | within 10% | unpriced today | covered |
|---|---|---|---|---|---|---|
| 3d floor 1 | 2834 | 0.0% | 4.5% | 90% | 1011 | 283 |
| 3d floor 2 | 2689 | 0.0% | 3.5% | 90% | 1011 | 157 |
| 7d floor 1 | 3007 | 0.5% | 6.8% | 86% | 1011 | 576 |
| 7d floor 2 | 2904 | 0.5% | 6.8% | 86% | 1011 | 402 |

## Choice

The window is 7 days (today and the six before it) with a floor of 1
sample. The fallback exists to
price the cards Direct does not price today, so coverage comes first: the
window covering more of the unpriced cards wins unless its median error is
higher by more than two points. The 7-day window covers 576 of the 1011
unpriced cards against 283 for the 3-day window, at a median error of 0.5%
against 0.0%, well inside two points. The floor is 1 unless floor 2's
median error is lower by more than two points: at 7 days floor 2 leaves the
median at 0.5% and covers 402 cards against 576, so the floor stays at 1.

The error columns are measured on cards Direct prices today, while the
fallback prices cards Direct dropped, so the error is likely optimistic for
them. The datasets entry that makes the archive record Direct also adds a
"TCG Direct" line to the chart provider registry and the screener, a side
effect to know about.
