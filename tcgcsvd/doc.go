/*
Package tcgcsvd ingests TCGplayer prices and product catalogs for the non-Magic
games from tcgcsv.com into the shared price database. It is the ingestion half
of the tcgcsv work, split out of the web server: the server imports it for its
crons and admin button, and cmd/tcgcsvd runs the same jobs as a standalone
process with no web server, datastore, or template stack attached.

# The three jobs

Daily prices (Service.IngestLatest) pulls tcgcsv's current snapshot for every
configured game and upserts it under the snapshot's date. It gates on tcgcsv's
last-updated stamp, so running it more often than the upstream refresh is a
cheap no-op.

Backfill (Service.Backfill) fills the same table from tcgcsv's daily archives,
one day at a time, for any range back to the archive epoch (2024-02-08). It is
how a gap left by a missed daily run gets closed, and how a newly added game
gets its history.

Products (Service.SyncProducts) refreshes the tcg_products catalog — names,
collector numbers, rarities, images — which changes slowly and runs weekly.

The two scheduled jobs run under a shared Postgres advisory lock
(Service.WithCrawlLock, which Service.StashPrices and Service.StashProducts
apply for you), so several server instances — or a server and a standalone
tcgcsvd — never crawl tcgcsv.com at once. Per tcgcsv.com's FAQ a full sync
belongs at most once per 24h. Backfill deliberately stays outside the lock: it
is operator-driven and can run for hours, and holding the lock that long would
starve the daily pull, which is the one that must not be missed.

# Chosen categories

"Category" is TCGplayer's term for a game: 2 is Yu-Gi-Oh!, 3 is Pokemon, 71 is
Disney Lorcana, and so on. The chosen categories are exactly the games listed in
tcgcsv_config.games in config.json — the games we support. Nothing is inferred
from tcgcsv.com's full category list: a game we don't list is never fetched and
never stored, so the config file is the single place that decides what we carry.

	"tcgcsv_config": {
	  "user_agent": "mtgban-website (+https://mtgban.com)",
	  "games": [
	    {"name": "Pokemon", "category_id": 3},
	    {"name": "Disney Lorcana", "category_id": 71}
	  ]
	}

Magic is deliberately absent: its prices are keyed by mtgjson uuid in
product_prices and come from a different pipeline entirely. Categories 21, 69
and 70 are junk per the tcgcsv FAQ and should never be listed.

The -categories flag (Service.SelectGames) narrows a single backfill run to a
subset of the configured games, for when one game has a hole and re-fetching the
other nine would be wasted work. It cannot widen the set: an id that isn't a
configured game is an error listing the ones that are, so a typo can't read as a
clean backfill that quietly wrote nothing.

# Adding a game

Add one entry to tcgcsv_config.games and run a backfill:

	tcgcsvd -config config.json -backfill

The run needs no other argument. Backfill keeps a per-category resume cursor —
the newest date already stored for that category — and skips any day at or below
it. A game added today has no rows, so its cursor is empty and every day from the
archive epoch forward is fetched for it, while the games that are already current
skip every one of those days. The full history arrives without re-ingesting or
disturbing what is already stored.

Two consequences worth knowing. The daily archives are per-day, not per-game, so
a day any category still needs is downloaded once and the wanted categories are
extracted from it; the cost of adding the eleventh game is the download of every
archive since the epoch, roughly 900 days, not eleven times that. And the upsert
is keyed on (date, category, product, sub-type), so a re-run over days already
stored overwrites them in place rather than duplicating them — which is why
closing a gap with -force is safe.

The catalog is separate from prices and has no resume cursor; it is a full
refresh of the current catalog every time:

	tcgcsvd -config config.json -products

# Running it

As a library, from a process that already has a *timeseries.Client:

	svc, err := tcgcsvd.New(*cfg.TCGCSVConfig, db,
	    tcgcsvd.WithLongFormWrites(true),
	    tcgcsvd.WithNotifier(ServerNotify))
	go svc.StashPrices()

As a standalone process, one job per invocation, exiting when it finishes:

	go install github.com/mtgban/mtgban-website/cmd/tcgcsvd@latest
	tcgcsvd -config config.json -daily
	tcgcsvd -config config.json -backfill -categories 71 -from 2026-07-08 -to 2026-07-14 -force

Backfill shells out to a 7z binary: the archives use solid PPMd compression that
pure-Go readers do not reliably decode. CheckArchiveTooling reports a missing
binary up front rather than failing per-day.
*/
package tcgcsvd
