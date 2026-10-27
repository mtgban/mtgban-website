# price_dates

The screener anchors each window on a game's newest day under a provider. It
reads that day from `price_dates (provider, category, date)`, which
`UpsertLongPrices` fills in the same transaction as the prices. `price_dates.sql`
fills it for the prices written before then: every month since 2020-09, about
40 s a month on the live archive.

## Running it

With `sql_config`'s connection in the usual `PG*` variables, from this
directory:

1. Before the build goes live: `psql -f price_dates.sql`.
2. Deploy the site, and reinstall `tcgcsvd` from the same commit. Both write
   prices, and a build without this change writes no days, which leaves its
   game's screener anchored on the day the old build last ran.
3. Once both are running the new build, repeat the days written in between:
   `psql -v from=<the day of step 1> -f price_dates.sql`.

The site at startup and `tcgcsvd` before each ingest create the table too, so
either one deployed ahead of step 1 still writes prices; the screener shows
nothing until the script has run.

A script that deletes a provider's prices for whole days leaves those days in
`price_dates`. Delete them there as well, or the screener anchors on a day with
nothing to compare.
