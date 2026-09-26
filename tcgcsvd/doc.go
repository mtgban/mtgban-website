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
gets its history — while tcgcsv serves the archives. It has not since September
2026: every date under /archive/ answers 403, so a backfill now stores the
current snapshot when the requested range covers it and fails naming the range
when it doesn't. docs/tcgcsv-archive-withdrawal.md has the notice tcgcsv serves
and what that leaves reachable.

Products (Service.SyncProducts) refreshes the tcg_products catalog — names,
collector numbers, rarities, images — which changes slowly and runs weekly.

The two scheduled jobs run under a shared Postgres advisory lock
(Service.WithCrawlLock, which Service.StashPrices and Service.StashProducts
apply for you), so several server instances — or a server and a standalone
tcgcsvd — never crawl tcgcsv.com at once. Per tcgcsv.com's FAQ a full sync
belongs at most once per 24h. The archive walk deliberately stays outside the
lock: it is operator-driven and can run for hours, and holding the lock that
long would starve the daily pull, which is the one that must not be missed. Its
snapshot fallback does take the lock, being the same full crawl the daily job
makes.

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

Add one entry to tcgcsv_config.games and run the daily job:

	tcgcsvd -config config.json -daily

A game with no rows has an empty freshness cursor, so the daily pull ingests it
on its first run while the games already holding the snapshot date skip it. That
is as much history as a new game gets while the archive is withdrawn: one day,
growing by one a day from there.

Backfill is what fills the rest in, once tcgcsv serves the archives again. It
keeps a per-category resume cursor — the newest date already stored for that
category — and skips any day at or below it, so a game added today pulls every
day from the archive epoch forward while the games that are already current skip
every one of them.

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
	    tcgcsvd.WithNotifier(func(kind, message string) { ServerNotify(kind, message) }))
	go svc.StashPrices(ctx)

The context is the caller's own shutdown one, not a request's: the run outlives
whatever started it, but a stop should reach it mid-crawl.

As a standalone process, one job per invocation, exiting when it finishes:

	go install github.com/mtgban/mtgban-website/cmd/tcgcsvd@latest
	tcgcsvd -config config.json -daily
	tcgcsvd -config config.json -backfill -categories 71 -from 2026-07-08 -to 2026-07-14 -force

Backfill shells out to a 7z binary: the archives use solid PPMd compression that
pure-Go readers do not reliably decode. A missing binary comes back as
tcgcsv.ErrArchiveTooling, which the day loop treats as terminal, so it is
reported once rather than per day — and it is looked up only after an archive
actually downloads, so a box without p7zip still learns the archive is withdrawn
rather than stopping on an extractor it has nothing to extract with.
*/
package tcgcsvd
