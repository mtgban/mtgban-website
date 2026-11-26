# ADR-0012: Graded sales on the Graded page

**Status:** Accepted
**Date:** 2026-11-26
**Deciders:** Vittorio Giovara

## Context

No store buys slabs, so the Graded page's second column is Last Sold. The
newspaper pulls pokemonpricetracker's graded Pokemon sales nightly into
`pptgradedsalemodel`: eBay and Fanatics Collect sales, each filed by the
source under a TCGplayer product and printing, with the grader, grade and
slab tier read from the listing title. It holds 1.82M sales from 2020-10 on.
Its per-grade summary table is computed from the same sales.

The source's terms let the site show the data on its own pages, and forbid
passing it on through any API, feed, export or dataset.

An audit of the stored sales (2026-11-26) found the source's filing mostly
right and wrong in three repeatable ways on eBay; Fanatics was clean:

- About 11k listings sit under two or more products. At least one filing of
  each is wrong.
- A few cards, mostly Pikachu World Collection promos, are catch-alls: of
  Pikachu (Portuguese) PW 9's 3,663 sales, 45 titles say Portuguese.
- A title can spell a collector number that is not the card's: Base Set 2's
  Charizard 4/130 filed under Base Set's 4/102, Hidden Fates SV49 under 9/68.

## Decision

The site loads the sales into a snapshot every 6 hours and on every
datastore load, one that met a load running within 15 minutes
(`GradedStore`), and filters them before anything reads them:

1. Only sales from 2025-09-01 on are read, where the site's price history
   starts; eBay's coverage only gets dense in August 2025.
2. A listing filed under more than one product is dropped, in the query. A
   listing the source stopped returning is kept: it aged out of the
   source's window, which says nothing against it.
3. A title naming another language (Japanese, Japan, JPN, Korean, Chinese,
   German, French, Italian, Spanish, Portuguese) is dropped, unless the
   catalog carries the card as a non-English one: a datastore language other
   than English, or a Japanese promo's total (XY-P, SM-P, S-P, ADV-P), which
   the datastore gives no language. The source already keeps each card's
   sales to its language, so this drops nothing today; English catalog cards
   that are Japanese products (Hoopa 155/XY-P) keep their sales, and a
   European copy, which prints the English set's numbers, cannot reach an
   English card.
4. A lot is dropped: a title saying "lot" or "N pcs". Not "bundle", which
   names a card (Iron Bundle) and the products single promos came in, nor
   "set of", which names the V-Union cards printed in four pieces.
5. Where the source guessed the printing (`printing_source = 'default'`), a
   title naming another is dropped: 1st Edition guessed and not named, or
   named and not guessed, or a reverse holo named against any other guess.
   Sellers spell 1st Edition "1st", "1ED" or "first ed"; a bare "first"
   names promos ("First Partner").
6. A sale whose title spells a collector number as a fraction, none of which
   is the card's digits over its printed total, is dropped. A subgrade
   ("10/10/10") and a TAG rank are not read as numbers.
7. A card with 20 sales or more, under a fifth of whose titles carry its
   number outside the grade, is dropped whole.
8. A grader the Graded page has no group for (SGC, ACE) is left out.

Outliers stay: about 0.24% of sales are ten times off their median, and
dropping one would mean deciding a real sale is wrong.

Each card and grade keeps its 20 newest sales, as the recent TCGplayer
orders keep a condition's (ADR-0009), and Last Sold draws them with the same
Sales pane: the grade heads its rows with their average, the newest 5
follow and the rest fold away, each row linking to its listing. A best offer
is marked and left out of the average: eBay shows its ask, not the price
paid. Nothing reads the source's summary table.

Last Sold opens with the Sales Velocity row raw cards head Buyers with,
counted from these sales over the same 30 days: the rate is slabs sold a
day, and its drawer the sales and days with one, eBay's and Fanatics's
shares, and the last sale with its grade. Then it lists the grades a store
lists the card in, in the page's order. Both need a signature carrying
`SearchSales`; a reader without one gets an upsell.

## Consequences

- The data never leaves the page: not the price API, `/data/prices`,
  alerts, CSV exports nor the offline download. A new reader of
  `gradedSalesStore` has to keep to that.
- Of the 1.60M sales since September 2025, the filters drop about 2.5%
  (2026-11-26): 32,268 of other graders, 45 lots, 217 against a guessed
  printing, 1,887 naming another number, 3,562 on 16 catch-all cards and
  1,419 unmatched; none in another language. Fourteen Japanese products in
  the source's catalog (Red's Pikachu, the Ash vs Team Rocket Deck Kit) are
  not in the datastore, so their sales match no card. The number check costs some sound
  sales whose seller mistyped the total, the price of catching look-alikes;
  a look-alike whose title carries no number still gets through, as does a
  lot that only says "bundle".
- The snapshot holds about 67 MB on the Pokemon site, read in about 30 s.
  The listing titles are read for the filters and not kept: they would add
  62 MB.
- `TestGradedSalesLive` prints each filter's drops with samples, for
  rechecking the filters against the newspaper.
