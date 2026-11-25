# ADR-0009: Recent TCGplayer sales in search

**Status:** Accepted
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
  Only Magic's sealed products match an id there, so the other games'
  have no velocity.

## Decision

1. **The newspaper keeps the newest 20 orders per product, printing and
   condition, whatever their age,** in a new table, `tcgplayerrecentsalemodel`. Its columns are
   `product_id`, `variant`, `condition`, `order_date`, `purchase_price`,
   `shipping_price`, `quantity`, `custom_listing_id` and `pulled_at`
   (stamped by the database's clock on insert, indexed). The key is `(product_id, variant,
   condition, order_date, purchase_price, quantity, custom_listing_id)`, so
   reading one order on two nights stores it once. The key is checked
   against one raw signed-in record before the table is created.
2. **The pull writes only what changes the top 20.** The orders come from
   pages it already reads, with no extra call and the same limit of the
   end of yesterday. Because a page is newest first, a group's orders on it
   are that group's newest. So per group it takes the page's newest 20,
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
   busiest first. For each condition still under 20, it reads with the
   request's `conditions` filter, empty in the pull today, until each
   printing has 20 or the feed ends. It is a newspaper flag beside
   `--backfill-from`. It runs signed in only, under the nightly's rate
   limits and with a progress file, and writes this table alone. A
   condition with fewer than 20 sales in 120 days cannot fill. The run
   logs, per game, how many groups reach 5 and 20. Before it runs, one
   signed-in read must settle the condition ids and show that the filter
   holds. An agent may not call TCGplayer, so the user makes that read.
4. **The site caches the orders in memory**, in `internal/salesvelocity`
   beside the velocity, with a store, snapshot and job row of their own.
   - A full load reads every order of the game, matches each pair to a
     card id as the velocity does, and keeps 20 per card and grade, newest
     first.
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
     HP and PO, the headers the Buyers column already uses, and a sealed
     product's `Unopened` is a grade of its own. Any other condition is
     dropped and counted in the job's report.
   - A sealed order finds its product by TCGplayer id among the
     datastore's sealed products, because only Magic's datastore matches a
     sealed id as a card's. An id two products share answers for neither.
   - Nothing on a request path reads the newspaper.
5. **Sales is a third column, or a switch where it has no room.** A results
   area at least 800px wide shows Sellers, Buyers and Sales side by side.
   Up to 960px the sellers' and buyers' rows close up as in the tight band,
   so no store name is cut. Narrower, each card's Buyers header holds a
   two-way switch between Buylist and Sales, and a click sets every card on
   the page. Both show the one pane a card has. A page where no card has
   an order on record has neither, and keeps its two columns. The choice is kept in a cookie, `SearchBuyersMode` (`buylist`,
   `sales`), registered in the settings registry. Clicks are tracked as
   `ui.search.buyers_mode`. With no cookie, the mode is the game
   config's `search_buyers_default` (Pokemon's sets `sales`), else
   `buylist`; the three columns ignore it. Sealed search is the same and
   shares the choice. The TCGplayer sales row stays atop Buyers,
   unchanged. Offline search, which has no orders, shows no sales.
6. **The search draws no sales.** The buylist renders as today, and each
   card gets an empty Sales pane. When one is on show within a screen of the
   reader, or on the first switch, the page fetches every card's pane
   in one same-origin request, `/data/sales/{ids}`, behind the same signing
   as the chart's data and rendered from the snapshot alone. Neither mode
   costs a search anything measurable (Consequences).
7. **Sales shows each condition's 5 newest orders**, under `Condition: NM`
   headers, newest first.
   - Each header carries the condition's average price per copy over every
     order kept, weighted by copies. A sealed product's header is the
     average alone, since it only sells unopened.
   - A row is the source (TCGplayer's logo and name, linked to the card's
     product page in that condition and printing), the date
     (white, centred: `2026-11-19`, the minute in its tooltip), and the
     price per copy with the quantity
     beside it above one copy. Rows are half the height of a buyer's (21px),
     since a card can have 25 on show. The third column has room for
     neither the source's name nor the quantity, and leaves them out.
   - A condition with more than 5 folds the rest under "N more (show)", which
     becomes a "Hide" drawn after the last of them. In the page the fold
     comes first, so a keyboard or screen reader goes on from it to the
     orders it opened. Shipping
     is not shown. A card with no order on record says so.
   - Sales mode leaves out the buylist's index rows and ignores its
     condition filters.
   - Phones have no switch: a card with orders has a Sales list of its
     own, the same table, after its buyers or before them where the
     reader's mode is Sales (ADR-0010). It lays the orders out two to a line
     to keep the list short: each is the source's icon (the link), the full
     date and the price, with no quantity. The fold takes the empty place
     beside the fifth. A list under 360px wide goes back to one a line.
8. **Sales shows to the tiers with `SearchSales`**, a flag on the ACL's
   Search page, Admin's and Root's. A reader without it gets no switch, no
   list on a phone and a 403 from `/data/sales/`. The velocity row keeps
   its Newspaper-tier gate.
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
- **Render both panes**: rejected. Up to 100 cards × 5 conditions × 20
  orders, paid on every page for a pane most readers never open.
- **Render the Sales pane in the search when the reader is in Sales**:
  rejected. With 14 orders on every card it made the search 39% slower
  and its page 18% larger; the fetch after the page is on show costs the
  search nothing.
- **Fetch the folded orders when they are opened**: rejected. On a 100-card
  page with 2,485 orders, 1,167 of them folded, it saves 25KB of 52KB
  gzipped and 10ms of the 82ms the panes take to draw, against a wait each
  time a fold opens.
- **Keep the sales on screen as a card scrolls**, in a panel of their own
  beside it: rejected for a column of the card's table, which needs no
  wrapper around each card and leaves the pinned headers alone.
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
  ranks in its group's 20. Nothing reconciles a group against the feed.
- **History starts at launch,** plus what the backfill recovers from 120
  days. A slow card's rarer conditions may stay under 5.
- **Memory and load time are measured, not estimated.** The live test
  reports, per game, the rows, the full load's time and the heap with old
  and new snapshots both alive, before the switch ships. Magic had 157,501
  cards with a sale in a year. The order's own fields fit in about 12
  bytes, but slice headers and the map add more per card than that.
- **The newspaper table** has at most 20 rows per product, printing and
  condition. Nothing deletes a row for its age, so a card that sold
  years ago still shows its last orders. Its key is about as large as its
  rows. Its size is measured after the first nights.
- **Search time.** One snapshot read per request and one lookup per card,
  in either mode: measured with `BenchmarkSearchPage`, on master against
  the branch with benchstat. The panes cost their own request, after the
  page is on show, and show "Loading recent sales…" until it answers.
