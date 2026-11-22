# ADR-0009: Recent TCGplayer sales in the Buyers column

**Status:** Proposed
**Date:** 2026-11-22
**Deciders:** Vittorio Giovara

## Context

Search's Buyers column lists each store's buylist offer, grouped by
condition, under the TCGplayer sales row: copies sold a day, from the
newspaper's daily totals, for the Newspaper tiers
(`docs/search-sales-velocity.md`). A reader pricing a card to sell often
wants what it actually sold for, not what stores offer. On Pokemon the
buylists are thin and the sales are the better guide.

What exists:

- **The newspaper keeps no individual sale.** Its nightly pull reads
  TCGplayer's `latestsales` for every product of each game: English only,
  newest first, 25 orders a page. It always reads the first page, then
  pages back to its cutoff (`today - days_back`, one day) or 5,000 orders.
  It keeps orders up to the end of yesterday (UTC) and stores two things.
  `tcgplayersalesdata` holds one row per product, sale day and printing
  (`variant`): copies, orders and price statistics, with no condition.
  `tcgplayerlastsalemodel` holds the single newest order per product and
  printing. Every other order is thrown away.
- **An order** carries `condition`, `variant`, `language`, `quantity`,
  `title`, `listingType`, `customListingId`, `purchasePrice` (one copy),
  `shippingPrice` (what it covers is not established) and `orderDate`.
  There is no order id. The repository has no raw signed-in record, so the
  date's precision is unknown.
- **Signed in, `latestsales` serves about 120 days** at any offset. Signed
  out it serves the 5 newest orders and ignores the offset
  (`docs/SPEC.md` §6.5 and the 2026-09 investigation in the newspaper).
- **The site reads the newspaper only in background jobs.** No request path
  touches its database. The velocity loads into an atomic snapshot that a
  search reads once (AGENTS.md invariant 1). It loads the day before the
  newest sale day, because the pull writes the newest day for hours.
  Sealed products do not match a card, so they have no velocity.

## Decision

1. **The newspaper keeps the newest 10 orders per product, printing and
   condition** in a new table, `tcgplayerrecentsalemodel`. Its columns are
   `product_id`, `variant`, `condition`, `order_date`, `purchase_price`,
   `shipping_price`, `quantity`, `custom_listing_id` and `pulled_at`
   (stamped by the database's clock on insert, indexed). The key is `(product_id, variant,
   condition, order_date, purchase_price, quantity, custom_listing_id)`, so
   reading one order on two nights stores it once. The key is checked
   against one raw signed-in record before the table is created.
2. **The pull writes only what changes the top 10.** The orders come from
   pages it already reads, with no extra call and the same limit of the
   end of yesterday. Because a page is newest first, a group's orders on it
   are that group's newest. So per group it takes the page's newest 10,
   inserts them with `ON CONFLICT DO NOTHING`, and trims only a product
   that gained a row. Every cut uses one order: date, price, quantity,
   listing id, newest first. A product with
   no new order writes nothing. A write failure is logged and never fails
   the product, as with the last sale. Nothing seeds the table: the first
   night's first pages fill it.
3. **A one-off backfill fills the busy products.** A product with at most
   25 orders in the 120 days is read whole by its first page on the first
   night. A busier product's first page holds its newest 25, mostly in the
   condition that sells most. So the backfill takes the game's products
   with over 25 orders in the last 120 days of `tcgplayersalesdata`,
   busiest first. For each condition still under 10, it reads with the
   request's `conditions` filter, empty in the pull today, until each
   printing has 10 or the feed ends. It is a newspaper flag beside
   `--backfill-from`. It runs signed in only, under the nightly's rate
   limits and with a progress file, and writes this table alone. A
   condition with fewer than 10 sales in 120 days cannot fill. The run
   logs, per game, how many groups reach 5 and 10. Before it runs, one
   signed-in read must settle the condition ids and show that the filter
   holds. An agent may not call TCGplayer, so the user makes that read.
4. **The site caches the orders in memory**, in `internal/salesvelocity`
   beside the velocity, with a store, snapshot and job row of their own.
   - A full load reads the game's orders from the last 365 days, matches
     each pair to a card id as the velocity does, and keeps 10 per card and
     grade, newest first.
   - A load every three hours reads only the rows stamped after the newest
     stamp it has seen, less ten minutes, because concurrent writers commit
     out of order. The merge drops the repeats. It builds a new snapshot
     that shares every card it did not touch, so orders appear within three
     hours of the pull writing them and not a day late. The pull runs once
     a day, over a few hours, so the other loads find nothing and read one
     indexed range.
   - A datastore reload and the first load of a day are full loads.
   - A failed load keeps the last snapshot and is retried three hours later.
   - The grades are the site's: TCGplayer's `Near Mint`, `Lightly Played`,
     `Moderately Played`, `Heavily Played` and `Damaged` become NM, SP, MP,
     HP and PO, the headers the Buyers column already uses. Any other
     condition is dropped and counted in the job's report. Sealed is out of
     scope, as for the velocity.
   - Nothing on a request path reads the newspaper.
5. **The Buyers column switches between Buylist and Sales.** Each card's
   column header holds a two-way switch, and a click sets every card on the
   page. The choice is kept in a cookie, `SearchBuyersMode` (`buylist`,
   `sales`), registered in the settings registry. Clicks are tracked as
   `ui.search.buyers_mode`. With no cookie, a logged-in reader gets the
   game config's `search_buyers_default` (Pokemon's sets `sales`), and
   everyone else gets `buylist`. Sealed search has no switch. The TCGplayer sales row stays above both modes,
   unchanged. Offline search, which has no orders, shows no switch.
6. **Only the pane on show is rendered.** The buylist renders as today. The
   sales pane is rendered only when the mode is Sales. The first switch to
   Sales fetches every card's pane for the page in one same-origin request,
   `/data/sales/?ids=…`, behind the same signing as the chart's data and
   rendered from the snapshot alone. The logged-out prompt is static and
   needs no fetch. A page in
   Buylist mode costs nothing more than today.
7. **Sales shows each condition's 5 newest orders**, under `Condition: NM`
   headers, newest first: the date, the price per copy and, above one copy,
   the quantity. A condition with more than 5 folds the rest under
   "N more". Shipping is not shown. A card with no order on record says
   so. Sales mode leaves out the buylist's index rows and ignores its
   condition filters. On phones the Buyers tab shows every condition's
   group in Sales mode rather than following the condition pills, and the
   tab appears whenever a card has orders.
8. **Every logged-in reader sees Sales**, any tier: a reader with a
   verified signature. A logged-out reader gets the switch too, and Sales
   shows a Join / Log in prompt in place of the orders. The velocity row
   keeps its Newspaper-tier gate.
9. **An API endpoint comes later**, reading the same snapshot. The snapshot
   is keyed by card id and made of plain values, so it needs no second
   cache. Nothing is built for it now.

## Options considered

- **Fetch from TCGplayer on demand**, as Discord's `$$` does: rejected. It
  puts TCGplayer on a request path, sees only 5 orders signed out, and
  each page view would cost calls the site's IP would answer for.
- **Read the newspaper per request**: rejected. It puts the newspaper
  database on a page's path for the first time.
- **Derive orders from `tcgplayersalesdata`**: impossible. It has no
  condition and no single order.
- **Keep N orders per printing rather than per condition**: rejected. NM
  crowds out the rest, and the reader asked for each condition's own five.
- **Render both panes**: rejected. Up to 100 cards × 5 conditions × 10
  orders, paid on every page for a pane most readers never open.
- **Reload the whole table on the velocity's day**: rejected. The day
  lands when the pull starts, so it would show orders a day old.
- **Seed from `tcgplayerlastsalemodel`**: rejected. It has no listing id,
  and it holds products no longer pulled, which would never trim.
- **Hard-code Pokemon's default**: rejected for a config field. The site
  has no per-game branch of that kind.

## Consequences

- **Gaps.** A product that fails every retry, a night the pull does not
  run, a read stopped by a 400 or the 5,000-order cap: past its first page,
  such a day's orders are never read, and its groups miss them. Signed-out
  nights give 5 orders a product. The newest orders still arrive on the
  next clean night.
- **An order TCGplayer later drops**, cancelled for instance, stays while it
  ranks in its group's 10. Nothing reconciles a group against the feed.
- **History starts at launch,** plus what the backfill recovers from 120
  days. A slow card's rarer conditions may stay under 5.
- **Memory and load time are measured, not estimated.** The live test
  reports, per game, the rows, the full load's time and the heap with old
  and new snapshots both alive, before the switch ships. Magic had 157,501
  cards with a sale in a year. The order's own fields fit in about 12
  bytes, but slice headers and the map add more per card than that.
- **The newspaper table** has at most 10 rows per product, printing and
  condition within the year. Its key is about as large as its rows. Its
  size is measured after the first nights. The sales run ends by deleting
  rows older than 400 days.
- **Search time.** In Buylist mode, one snapshot read per request and no
  rendering. In Sales mode, one lookup per card and the pane. Both are
  measured with `BenchmarkSearchPage`, on master against the branch with
  benchstat, before the site PR merges.
- **Free readers see each condition's recent prices and dates,** which
  hand them roughly what the velocity row's details gate. This was chosen:
  Sales is meant to bring readers in.
