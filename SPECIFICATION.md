# MTGBAN Website — Architecture & Development Specification

> Generated from a full-codebase review (June 2026), then verified and
> corrected against the code on 2026-09-14 — three months of changes had
> accumulated by then: this is now a 9-game site rather than Magic+Lorcana,
> several subsystems described below (the long-form timeseries schema, the
> offline PWA mode, cross-device user-state sync, the observability/usage
> dashboard, tcgcsv ingestion) didn't exist in June, and a few that did
> (the MySQL-backed newspaper pages, the offline-API peer-loading mode, the
> `Config.ACL`/`Config.AffiliatesList` fields) have since been removed or
> restructured. Every section below was individually re-verified against the
> current tree on that date. Covers how the application is built, how data
> flows through it, and how it is developed and operated.

## 1. Overview

MTGBAN is a multi-game trading-card-game price-aggregation website written in
Go (`go 1.25`, module `github.com/mtgban/mtgban-website`). One codebase
deploys as a separate site per game, selected by `Config.Game` (`main.go`,
`DefaultGame = "magic"`): magic is the default, and lorcana, onepiece,
yugioh, riftbound, fleshandblood, pokemon, gundam, and palworld each have
their own `.github/workflows/<game>-deploy.yml`. gundam and palworld are the
newest and both already registered in go-mtgban's pinned version (games.go's
blank imports covered them before either had a deploy workflow) — but
neither has an actual DigitalOcean App Platform app or its secret
provisioned yet, which is infrastructure, not code; see AGENTS.md's
"Deploying a new game". It is a
single server binary (~25k lines in the root package, excluding tests) plus
small support packages, server-rendered Go HTML templates, and vanilla
JS/CSS with no frontend build step.

Core capabilities:

- **Search** — query retail (sellers) and buylist (vendors) prices across many
  stores with a rich query language.
- **Upload** — bulk collection valuation/optimization from CSV/XLS/XLSX,
  Google Sheets, Moxfield, TCGplayer collections.
- **Arbitrage / Global / Reverse** — cross-store price-gap detection.
- **Sleepers** — tiered (S–F) scoring of undervalued cards.
- **Newspaper** — daily market-mover reports backed by SQL databases.
- **Sealed EV** — expected-value analysis of sealed products.
- **BAN Price API** — signed JSON/CSV price API for external consumers.
- **Discord bot** — price lookups and affiliate-link rewriting in Discord.

Key dependency: `github.com/mtgban/go-mtgban` supplies the card database
(`mtgmatcher`: UUID canonicalization, fuzzy matching, sets, sealed contents)
and the scraper abstractions (`mtgban`: `Seller`/`Vendor` interfaces,
`InventoryRecord`/`BuylistRecord` maps of UUID → price entries, `Arbit()`
/`Mismatch()` comparison helpers) for every game the site deploys, not just
Magic.

## 2. Process lifecycle

### 2.1 Startup (`main.go`)

Flags (`main()`): `-cfg` (config path, default
`$BAN_CONFIG_PATH` or `config.json`), `-port`, `-ds` (datastore path,
default `AllPrintings.json.xz`), `-acl` (access-table path override),
`-grants` (Patreon grants path override), `-dumps` (a local directory to
read the scraper dumps from; see §2.3), `-dev` (hot-reload templates,
relaxed auth), `-sig` (force signature checks in dev), `-noload`,
`-stores` (comma-separated stores to load at startup; see §2.3), `-nonews`,
`-log` (default `logs/`), and a `tcgcsv-*` family — `-tcgcsv-backfill`,
`-tcgcsv-daily`, `-tcgcsv-products` each run one ingest job against
`tcg_prices`/`tcg_products` and exit without starting the web server (the
same jobs `cmd/tcgcsvd` runs as its own process); `-tcgcsv-from`/
`-tcgcsv-to`/`-tcgcsv-force`/`-tcgcsv-categories` tune the backfill, which
since tcgcsv withdrew its archives stores the current snapshot in their
place (`docs/tcgcsv-archive-withdrawal.md`). There is
no `-offline` flag any more — the old "run without B2, load prices from
another BAN instance's API" mode is gone (see §2.3).

Boot sequence (`main()`):

1. `preloadConfig()` → resolves `ConfigBucket` to a local file or `b2://`
   bucket only (an `http(s)://` config path is rejected). `loadVars()`
   parses the config and defaults `Config.Game`/`Config.Port`/
   `Config.DatastorePath`; `BAN_SECRET` seeds HMAC signing, falling back to
   `DefaultSecret` when unset in any mode (outside dev a defaulted secret
   only logs a warning). `loadCommonConfig()` loads the ACL/grants table and
   affiliates. `loadRarityBadges()` (no-op for the default game).
2. `s := newSite()` (site.go) — the site the routes and jobs are bound to,
   with its palette and offline services; pure, no I/O.
3. If any `-tcgcsv-*` job flag is set, `s.runTCGCSVMaintenance()`
   (tcgcsv_service.go): `openDBs()`, `initTCGCSVService(s)`, run the
   requested job, `os.Exit(0)` — the datastore and price data are never
   loaded and `ListenAndServe` never runs.
4. Otherwise: `loadKeyOverrides()`, create `LogDir`, load Google credentials,
   `openDBs()` → `PricesArchiveDB` (PostgreSQL, `timeseries` package, price
   history for charts, plus `tcg_prices`/`tcg_products` when TCGCSV
   ingestion is configured), `NewNewspaperDB` (PostgreSQL), `UserStateDB`
   (cross-device sync, only if `Config.UserStateConfig` is set), and
   `ObservabilityDB` (usage telemetry, only if `Config.ObservabilityConfig`
   + an instance name are set). `Newspaper1dayDB`/`Newspaper3dayDB` (MySQL)
   no longer exist. Then `startAccessReloadListener()` (picks up ACL/grant
   saves made by peer deployments sharing the price DB, recovering a reload
   that panics so it keeps listening), `initTCGCSVService(s)`
   (non-fatal if unconfigured), `reloadCheckpoints()`,
   `s.offline.LoadPersisted()`, then the production template cache
   build (`buildTemplateCache()`) — see §7.
5. `s.reloads.Start("startup", Config.DatastorePath, ...)` runs
   `s.loadDatastore(Config.DatastorePath)` in the background through the
   same single-flight tracker an admin/API reload uses (`internal/dsreload`):
   a reload requested before this finishes is queued to run once it ends
   instead of racing it (one waits at most, the latest request), and a panic
   building a snapshot is recovered instead of killing the process. `loadDatastore` opens the site's game via
   `mtgmatcher.Open(datastoreGame(), reader)` (not the old
   `mtgmatcher.LoadDatastore()`), builds the numbers/names/editions
   snapshots and the palette's sets/promos/finishes lists from it
   (`s.newDatastore()`, site.go), publishes backend and snapshots
   together in one `s.ds.Store()`, then itself spawns
   `s.cacheNewspaper()` and `s.loadTCGListings()` as further goroutines,
   which the tracker's recover does not reach: each defers `recoverJob()`
   (recover.go) of its own.
6. Unless `-noload` (`SkipPrices`): `s.startScraperLoad()` (load.go) opens
   the dumps bucket (`openDumpsBucket()`, or with `-dumps <dir>` a
   `simplecloud.FileBucket{Root: dir}` in its place; either is kept as
   `DataBucket` for reloads), then on a goroutine runs `loadScrapersNG()`
   on it with the stores to load (`-stores` when it names any, else
   `scraper_config.stores`), then `s.runSealedAnalysis()`,
   `warmVariantCacheIfEnabled()`, `s.offline.RefreshManifest()`.
7. `s.offline.StartRefresher(recovered)` — one debounced goroutine that
   every runtime manifest refresh funnels through, each run through
   `recovered()` (recover.go), so a refresh that panics is reported and the
   loop serves the next one.
8. Cron jobs (`gopkg.in/robfig/cron.v2`, non-dev only, `s.startCrons()` in
   jobs.go). The
   library runs each on a bare goroutine, so each is registered through
   `addJob`, which runs it under `tracked()` (recover.go): a panic is
   reported as a request's is (§2.2), the job runs again at its next time
   rather than taking the process down, and its runs and schedule go to
   the admin dashboard's Background Jobs ("Background jobs" in §5.9):
   - `0 */12 * * *` — `s.stashInTimeseries()` (snapshot prices to Postgres)
   - `30 */12 * * *` — `s.runSealedAnalysis()`
   - `33 */3 * * *` — `s.cacheNewspaper()`
   - `45 * * * *` — `s.refreshCKSignals()` (ckbuylist.go): reloads CK's
     stock history once the newspaper has a new day, rereads the odds its
     tooltips quote (`ck-odds-v2.json.xz` beside the datastore, ckodds.go)
     once the loaded ones are 20 hours old, and rebuilds every card's
     buylist signal. Only where the site serves CK's buylist
     (`ckAvailable()`), which the prices loading tells: the cron checks it
     each hour, its row appears with the first run that has CK, and the
     scraper goroutine `startScraperLoad()` starts also runs it once the
     prices are in, on a goroutine of its own under `tracked()`
   - `50 * * * *` — `s.loadTCGListings()` (tcglistings.go): reloads
     TCGplayer's sellers and copies per grade, for search's TCGplayer rows
     and the v2 price API's `available`, and TCGplayer Direct's own stock
     per grade (`direct_inventory`, the same on every listing of a grade),
     which the arbitrage, Global and reverse pages (with a tooltip dating
     it) quote as TCGDirect's quantity and the v2 price API as its
     `available`, but not search, until the day after its scrape ends,
     once the newspaper finishes a scrape, and retries a scrape day whose
     load failed every 6 hours; every datastore load also runs it, which
     queries only if no day is loaded yet
   - `20 */12 * * *` — `s.offline.RequestRefresh()` (backstop; normal
     refreshes are event-driven)
   - `15 */6 * * *` — `refreshCheckpoints()` (reads no datastore, so it stays
     a plain function rather than a site method)
   - `0 * * * *` - `checkStaleness()` (staleness.go): the Discord alarm below
   - `0 * * * *` - `checkJobHealth()` (jobs.go): the same alarm for the
     background jobs, below; under `recovered()`, not a job itself
   - when tcgcsv ingestion is configured: `0 21 * * *` —
     `stashTCGCSVPrices()`; `0 22 * * 1` — `stashTCGCSVProducts()`
   - the old per-scraper `force_reload_at` cron expressions no longer exist
9. `s.setupDiscord()`, then handlers are registered and `http.Server`
   `ListenAndServe`s on `Config.Port` (default `:8080`, no TLS — assumes
   reverse proxy); graceful shutdown on SIGINT/SIGTERM with a 5 s timeout,
   Discord notify, and `ObservabilityRecorder.Close()`. `/healthz` returns
   200 only when UUIDs + sellers + vendors are loaded.

### 2.2 Global state & concurrency model

The dominant pattern is **immutable snapshots behind atomic pointers**:

- `sellersPtr`/`vendorsPtr` (`atomic.Pointer[[]mtgban.Seller/Vendor]`,
  load.go). Readers call `GetSellers()`/`GetVendors()`; writers go
  through `updateSellers()`/`updateVendors()` which validate (timestamp must
  not regress; a new inventory/buylist under half the previous size is
  rejected once the previous one held over 100 entries) and `.Store()` a new
  slice under `scrapersWriteMu`. Zero-downtime reloads.
- Same pattern for newspaper page cache (`newspaperPagesPtr`), reprints
  (`reprintsPtr`), checkpoints (`checkpointsStore`, an
  `internal/bucketstore.Store[T]` — also an atomic-pointer swap, not a
  mutex), and last-update timestamps for the stash and newspaper crons
  (`lastStashUpdatePtr`/`lastNewspaperUpdatePtr`).
- The card datastore is the same pattern once more: backend plus its
  numbers/names/editions snapshots, the palette's sets/promos/finishes
  lists, and its own load time are one `datastore` value (datastore.go),
  built by `s.newDatastore()` (site.go) and published in a single
  `s.ds.Store()` by `s.loadDatastore()`, itself started by
  `s.startDatastoreReload()` (an admin or `/api/load/datastore` reload) or
  once at startup. `site` owns the pointer (`ds atomic.Pointer[datastore]`,
  pre-stored empty by `newSite()`); page handlers, crons and Discord
  callbacks are methods on `*site` (site.go) and read it through
  `s.datastore()` (never nil, even before the first load) or `s.backend()`
  for the backend alone; entry points read either once and pass `b`/`ds`
  down to what they call.
- The config lives behind `liveConfig` (`atomic.Pointer[ConfigType]`,
  main.go) and is read through `Config()`, never nil. A `?tool=config`
  reload (`reloadConfig`), a config-editor save (`saveConfig`, admin.go)
  and a new API key (`generateAPIKey`) each build a new value whole and
  publish it; nothing writes into the live one, so readers take no lock.
  Those three hold `configMu` across their file I/O, so none lands inside
  another. That I/O gives up after `configFileTimeout` (30 s), so a
  bucket that stops answering holds the lock that long at most. The
  reload reads the running port and paths it keeps under `configMu` too,
  so they are the ones a save it waited on set.
- Affiliate data sits behind `affiliatesMu`/`affiliatesPtr`.

**Panics.** A panic in a handler behind one of the three signing wrappers
is recovered by `recoverPanic` (auth.go): `reportPanic` (recover.go) logs
it with the panicking goroutine's whole stack and posts what `fmt.Sprint`
makes of the value, the first 1024 bytes of that stack and a
`source request:` line to the server webhook, and the request is answered
500 if the handler has not started its response. For 10 minutes after a
report posts (`panicQuietWindow`), later panics raised on the same line
(`panicSite`) are only logged, value, stack and source line alike, and
that line's next report says how many there were: a handler that panics
on every request pings the channel once a window, not once a request,
while a panic raised anywhere else still posts its own. net/http itself recovers a panic in any other handler,
logging it and dropping the connection. Off the serving goroutines, these
recover and report the same way under a `source job:` line: the cron jobs
and each debounced offline refresh through `recovered()`; the Discord
handlers and the `$$` lookup's fetch, the newspaper refresh and the
TCGplayer listings load a datastore load starts, the goroutines the admin page's `update`, `snapshot` and
`tcgcsv` actions start, the scraper reloads a key-overrides save starts,
the startup run of `s.refreshCKSignals()`, and each access-listener
reload through `recoverJob()`. A deploy through
`update` that fails, by an error or a recovered panic, leaves the old
process serving, with no restart to wait for; a panic is reported, an
error only logged. `dsreload` recovers its own panics without posting
them, logging one and recording it as the reload's error, and
`ObservabilityRecorder` recovers only a panic in its batch insert, which
it logs. A few goroutines are left bare, as none can realistically panic:
`listener.Ping` (access_notify.go), the event callback lib/pq runs for
that listener on a goroutine of its own, the `notify.Post` goroutines
(utils.go), the report's own three posts among them, the ratelimit
janitor, the goroutine `loadScraper` closes its reader on (load.go), and
the admin `server` action's, which only sleeps, logs and calls
`os.Exit(0)`, past which no deferred call would run anyway. Two startup
goroutines stay fatal on purpose, as their errors are: the scraper
goroutine `startScraperLoad()` starts, including the `runSealedAnalysis()`,
`warmVariantCacheIfEnabled()` and `RefreshManifest()` it runs after the
load, and the one running `ListenAndServe`. The workers
`searchParallelNG`, `fetchRosterPrices` and `runningWorkflows` fan out to
each defer `recoverJob()` too, so a panic in one costs only its share of
the answer: its side of the search, its roster card, counted as a failed
read, or its workflow state's names.

### 2.3 Data loading pipeline

- **Card datastore**: `Config.DatastorePath` (per-deployment; falls back to
  `AllPrintings.json.xz`) from local disk, B2, or HTTPS via
  `openBucketPath()`; opened through `mtgmatcher.Open(datastoreGame(), …)`
  and indexed per game — this is now a multi-game site (magic, lorcana,
  onepiece, yugioh, riftbound, fleshandblood, pokemon, gundam, palworld).
  Reloadable from the admin panel (`?tool=datastore`).
- **Scraper price data** (`loadScrapersNG()`, load.go): discovered, not
  configured. bantool publishes every game's dumps to the B2 bucket
  `mtgban-dumps` (`dumpsBucket`) as
  `<game>/<store>/<kind>/<shorthand>.json.xz` (kind `retail` or `buylist`),
  and `openDumpsBucket()` opens it through `newB2ClientFor` with the
  `bucket_keys["mtgban-dumps"]` key pair, like every other bucket. With
  `-dumps <dir>`, a `simplecloud.FileBucket{Root: dir}` stands in for it:
  a local directory laid out the same way, listed as the same keys,
  relative to dir, and read with no B2 credentials. `scraper_config` keeps
  `icons`, `name_override` and `stores`. At startup the bucket is listed
  under `<game>/` (`listDumps`, via `simplecloud.Lister`, with a timeout
  and retry per attempt); every key of that form becomes one load, and
  anything else is skipped with a log line. When `-stores`, else
  `scraper_config.stores`, names any store, `onlyStores` narrows the
  listing to those stores before the index is published, so only they
  load at startup and only they are indexed; the list is logged once, and
  a named store the listing lacks is logged and skipped. An empty list
  loads every store listed. Reloads aren't held to the list:
  `/api/load/<store>` loads and indexes whatever store it names, and admin
  `?reload=` loads whatever dump it names. Each load is fetched at that
  same key and
  deserialized via
  `mtgban.ReadSellerFromJSON`/`ReadVendorFromJSON`, 3 retries with backoff
  and a 2-minute timeout per scraper. The listing also builds a
  `scraperIndex`: store → kind → shorthands, and the reverse shorthand →
  store, published behind its own `atomic.Pointer` next to
  `sellersPtr`/`vendorsPtr` before any dump loads; the admin dashboard,
  `familyKeys()` and `isConfiguredScraper` all read it. A bucket that cannot
  be opened or listed is a startup error.

  **`/api/load/<store>`** (`LoadFromCloud`, api.go): store must match
  `^[a-z0-9_]+$` or this 404s before ever asking the bucket to list
  anything - a signature can carry other values in its API field (a stray
  `..`, an `ALL_ACCESS` minted for the price API), and none of them name a
  real store. The signature check itself is `GetParamFromSig(sig, "API") ==
  store`. It lists `<game>/<store>/` alone, 404s if that lists nothing,
  loads every dump found, and replaces that store's entries in the index: a
  shorthand another store also publishes moves to this one, and every other
  store's own entries are copied across untouched. The listing and the loads
  retry a timeout as startup does, each attempt on its own
  `context.Background()`, so a transient B2 timeout is not a 500 to the
  scraper that just published, and a reload finishes even if that caller
  hangs up. `?reload=` from the admin page names the store, kind and
  shorthand directly.
- **"Offline" now means the PWA offline experience**, not a data-loading
  mode — `api_load.go` and the old "run without B2, reconstruct
  sellers/vendors from another instance's `/api/mtgban/all.json` +
  `sealed.json` + `stores.json`" path are gone. `internal/offlineapi.Service`
  (wired as `s.offline`, built in `newSite()`, site.go) instead serves a manifest,
  catalog fragments, image metadata, and cached prices to the site's service
  worker for offline browsing: it loads persisted state at boot
  (`LoadPersisted()`), refreshes after scraper loads (`RefreshManifest()`),
  and recomputes on a debounced background goroutine
  (`RequestRefresh()`/`StartRefresher()`). Gated on `Config.Offline.ManifestPath`
  / `.ImagesPath` (`ManifestPathConfigured()`/`ImagesPathConfigured()`) — as of
  this writing none of the committed `config*.json` set either key, so on
  every environment those files describe, offline mode's manifest load and
  image bucket-auth are unconfigured no-ops until a deployment supplies the
  bucket paths out-of-band.
- **Checkpoints** (`checkpoints.go`): curated chart annotations (bans,
  releases, reprints) loaded from B2/file into `checkpointsStore`, editable
  as JSON in the admin panel, rendered as markers on price charts.

## 3. Authentication & authorization

### 3.1 Patreon OAuth (`Auth`, auth.go)

`/auth?code=…` exchanges the code via the `patreon` package, fetches user
identity, and checks the shared grant list (`PatreonGrants()`, loaded from
the file at `Config.PatreonGrantsPath` — not a `Config.Patreon` field) for a
hardcoded per-email tier override; failing that it fetches
`currently_entitled_tiers` and maps Patreon's tier labels onto four internal
tiers (`Pioneer`, `Modern`, `Legacy`, `Vintage` — Patreon's own "Standard"
tier folds into `Pioneer`), then issues a **signature**.

### 3.2 Signature mechanism (`sign`, `GetParamFromSig`, auth.go)

A signature is a base64-encoded query string carrying the user's identity,
tier, per-feature flags from the ACL, an `Expires` unix timestamp (11-day
default), and an HMAC-SHA1 `Signature` over
`METHOD + Expires + BaseURL + encoded-params` keyed by `BAN_SECRET`; API
signature checks (`enforceAPISigning`) look up a per-user secret in
`Config.APIUserSecrets` first, falling back to `BAN_SECRET` — page
signatures always use `BAN_SECRET` only. It is stored in the `MTGBAN`
cookie (31 days, shared across `*.mtgban.com`, **not** HttpOnly) and/or
passed as `?sig=`. `GetParamFromSig()` extracts individual grants, read off
`verifiedSignature()` (cookie first) or `verifiedRequestSignature()` (`?sig=`
first); `enforceSigning` hands the handler the `?sig=` it checked as the
cookie.

### 3.3 ACL / tiers

`ACL()` (common.go) returns `Access.Table()`, a `tier → page → {flag:
value}` map (`internal/access.Table`) loaded from the file at
`Config.ACLPath`; ACL, the Patreon grant list, and affiliate data each live
in their own shared file outside `ConfigType` proper (see `internal/access`),
not inline in `Config`. Tier `"Any"` defines public access. Page flags gate
nav visibility and handler access; feature flags (e.g. `SearchDownloadCSV`,
`UploadCustom`, `ArbitEnabled`, store blocklists, chart-lookback tier) ride
inside the signature. Tiers follow Magic format names, but only four exist
internally: Pioneer → Modern → Legacy → Vintage (longer chart lookback, more
stores, higher limits) — there is no separate `Standard` tier; Patreon's own
"Standard" membership is bucketed into `Pioneer` by `Auth()`.

### 3.4 Middleware tiers (auth.go)

| Wrapper | Used for | Behavior |
|---|---|---|
| `noSigning` | Home, Guide, Privacy, Offline page, suggest/chart/userstate/opensearch/palette APIs, `/api/load/datastore` | No checks; captures `?sig=` into cookie |
| `enforceSigning` | All feature pages, user APIs | Validates signature, expiry, per-page flag; 3 req/s per user email; POST only when `NavElem.CanPOST` |
| `enforceAPISigning` | `/api/mtgban/*`, `/api/v2/*`, `/api/load/*` (except `/api/load/datastore`) | JSON content-type; 10 req/s per IP (`ratelimit` token-bucket per IP via `x/time/rate`); HMAC-SHA1 validation via `apisig.Verify`, per-user secret from `Config.APIUserSecrets` falling back to `BAN_SECRET` |

Static assets (`/css/`, `/js/`, `/img/`, `/openapi/`) go through none of these three —
they're registered directly on `ServeFile` with no wrapper.

`/api/load/datastore` instead uses its own HMAC-SHA256 scheme (`verify()` in
api.go) over the request body with `X-Signature`/`X-Timestamp` headers,
rejecting any timestamp more than 60s old.

A fourth wrapper, `adminOnly`, composes behind `enforceSigning` on the
`/debug` pprof handler: it 404s (not 401s, so the endpoint's existence isn't
advertised) unless the signature carries the `Admin` grant.

## 4. Routing & page system

Routes are registered in `registerRoutes()` (routes.go) from the declarative
`NavElem` struct (pages.go) and the `ExtraNavs` map (declared and populated
by `init()` in pages.go): each entry declares its link, name, icon,
description, handler func, template, `CanPOST`, `AlwaysOnForDev`, optional
`ShouldHide` (a predicate that drops the entry - and, for a section like
Newspaper, its subpages with it - when e.g. no data is loaded yet for the
current game), `SubPages` (e.g. `/sets`, `/sealed` under Search) and
`SettingsTab` (the settings modal tab the page's gear opens on). Page
handlers are methods on `*site` (site.go); `NavElem.Handle` is
`func(*site, http.ResponseWriter, *http.Request)`, filled with method
expressions (`Handle: (*site).Search`) so `ExtraNavs` stays static data built
in `init()`, before any `*site` exists (`DefaultNav`'s entries, Home and
Changelog, carry no `Handle`). `ShouldHide` is
`func(*site) bool` for the same reason (it reads the site's current datastore
for visibility only, e.g. the Sealed sub-tab hides when the loaded backend has
no sealed product). `main()` builds `s := newSite()` and `s.registerRoutes()`
binds it at registration: `nav.Handle(s, w, r)` for declarative pages, plain
method values (`s.Search`, `s.palette.CardMeta`, `s.offline.Handle`, …) for
the rest.
`genPageNav(s, r, activeTab, sig)` builds the per-request navbar by filtering
`OrderNav` (Search, Newspaper, Screener, Sleepers, Upload, Global, Arbit,
Reverse, Admin) against the signature/ACL; the list itself is identical across
all 9 games, but per-entry `ShouldHide` (Newspaper hides itself whenever the
active game has no cached newspaper UUIDs yet) and per-deployment ACL config
narrow what actually renders for a non-Magic site. A mobile request runs the
result through `filterNavForMobile()` (mobile.go), called from every page
handler right after `genPageNav`, which keeps only the handful of pages that
ship a mobile template. Every page handler fills a `PageVars` (pages.go): the
nav, the messages and the fields several pages share, plus the one or two of
each small page (changelog, screener, API plans, alerts, upload handoff). The
six pages with many fields of their own keep them in a struct beside their
handler, embedded in `PageVars` so templates read them unchanged: `UploadVars`
(49 fields), `SearchVars` (48), `AdminVars` (23), `NewsVars` (17), `ArbitVars`
(6) and `SleepVars` (5).

Other routes: static `/css|/js|/img|/openapi` (plus `/favicon.ico`, `/robots.txt`)
served from disk via `ServeFile` with `Cache-Control: public, max-age=86400`
plus `?hash=<git commit>` cache-busting baked into template asset URLs;
`/go/{r|i|b}/{store}/{hash}` affiliate redirects, or the 2-segment
`/go/{store}/{hash}` short form defaulting to retail (redirect.go), resolved
via mtgjson UUID or an external id (scryfall/tcg product id); `/card/<set>/
<number>/<finish>` and `/sealed/<set>/<slug>` inbound-only redirects into
`/search`/`/sealed` (`CardRedirect`/`SealedRedirect`, redirect.go); `/random`
and `/randomsealed`; `/discord`; `/toggle-mobile` (cookie-based mobile
override; phone UA detection via `mileusna/useragent`).

## 5. Major subsystems

### 5.1 Search (`search.go`, `searchfilter.go`)

- **Query language**: `parseSearchOptionsNG()` (searchfilter.go) tokenizes
  `option:value` / `option>value` / `option<value` pairs, with `-`
  negation, against the `FilterOperations` table of **49 operators, not
  ~35**: search-engine
  modifiers (`sm:` mode override incl. `sm:scryfall`, `skip:`
  retail/buylist/empty/index, `sort:` chrono/hybrid/alpha/number/retail/
  buylist), identity (`s:`/`set:`/`edition:`/`e:`, `cn:`/`number:` with
  ranges and `cns:` strict, `r:`, `f:`, `t:`, `c:`/`color:`, `ci:`/
  `identity:`, `name:`, regex variants `se:`/`ee:`/`cne:`/`namee:`), format
  legality (`format:`/`legal:`, new), tags (`is:`/`not:` promo, reserved,
  showcase, borderless…), market presence (`on:`), dates (`date:`,
  `year:`), sealed relations (`unpack:`, `contents:`, `container:`,
  `decklist:`, `variable:`, new), UUID lookup (`id:`), store/region
  (`store:`, `seller:`, `vendor:`, `region:`), entry filters (`cond:`/
  `condr:`/`condb:`, `qty>`/`quantity>`, `ratio>`), and price comparisons
  (`price>`, `buy_price>`, `arb_price>`, `rev_price>`). Suffix sigils
  select finish (`*` foil, `~` etched, `&` nonfoil, `` ` `` alt-art foil).
  Bare hashes trigger UUID lookup mode; pipe syntax
  (`name|set|number|finish|cond`) supports the Scryfall-bot format.
- **Execution**: parse → `searchAndFilter()` resolves UUIDs through the
  backend's `Search*` methods (exact/any/prefix/regexp/sealed/hashing
  modes, plus `scryfall` and a sealed+card `mixed` mode) →
  `searchParallelNG()` runs seller and vendor scans in
  parallel goroutines, applying store/price/entry filter chains → optional
  custom-buylist injection → post-filters → sort (chrono/hybrid/alpha/
  number/retail/buylist, plus `odds` — a `variable:` search only, by each
  card's `dropOdds()` expected count, ascending) → `Paginate()`
  (utils.go) against the named constants `MaxSearchResults` (100/page)
  and `MaxSearchTotalResults` (10k max, search.go).
- **Results**: `map[cardUUID]map[condition][]SearchEntry`; INDEX
  pseudo-conditions merge TCG Low/Market and MKM Low/Trend pairs into
  single rows with a `Secondary` price. Without a signature, non-affiliate
  entries are `Locked` (link disabled), or left out under
  `search_hide_non_affiliates`, against `Affiliates().List` /
  `Affiliates().BuylistList` (common.go) — there is no longer a
  `Config.AffiliatesList` field; affiliates now live behind that accessor
  as a split retail/buylist list. `SearchEntry.PriceUnit` (search.go)
  says what a row's number means: an offer (the default, ranked and shown
  as currency), a store's own want-count, or — under a `variable:` search
  only — a synthetic "Avg Copies (est.)" row per card, `dropOdds()`'
  expected count of copies opening the named product once
  yields, summed across every slot that can draw it. Deliberately not a
  percentage: summed across more than one slot the same card can average
  past 1 (a common land can exceed 1 per booster box, several times that
  per case), which is exactly what a chance cannot mean. `IsOffer()` is
  what ranking, "best price" highlighting and the embed's price columns
  ask instead of assuming every row is a dollar amount.
- **Suggest** (`SuggestAPI` in `api_suggest.go`, matching in
  `internal/suggest`): no longer a live prefix scan of
  `mtgmatcher.AllNames()` per request. A `suggest.Names` is built once when
  the datastore (re)loads (`suggest.NewNames(singles, sealed)`, called from
  `s.newDatastore()`), folding every name
  (diacritics/case/punctuation stripped) and also "squashing" spaces out of
  the folded form, into separate sorted singles/sealed views searched by
  binary search — so a typed space or hyphen reaches either spelling
  ("blue eyed" finds "Blue-Eyed…", "fireice" finds "Fire // Ice"). Prefix
  ≥3 chars, capped at 30 results (`maxSuggestions`), 5-minute cache,
  OpenSearch-compatible array response — all unchanged from before.

### 5.2 Upload (`upload.go`)

Accepts CSV (delimiter auto-detect: comma → tab → `;`, plus a `sep=`
header-row override), XLS (`extrame/xls`), XLSX (`excelize`), Google
Sheets, Moxfield decks/collections (`moxfield` package), TCGplayer
collection scrapes (goquery), **Collectr showcase pages** (new `collectr`
package, `app.getcollectr.com`, Magic/Lorcana only), and plain decklists.
Header/row parsing has moved out of `upload.go` into the `internal/docparse`
package: a per-upload parser from `newUploadParser(b)` (a
`*docparse.Parser`) exposes `ParseHeader()`/`ParseRow()` — there is no
longer a standalone `parseHeader()`/`parseRow()` in `upload.go`.
Row resolution still goes through `Match` on the parser's backend
(preserving alias candidates and mismatch errors). Prices come from the same
`getSellerPrices()`/`getVendorPrices()` machinery as the API. The
**optimizer** picks the best store per card (highest buylist / lowest
retail within a percentage margin), with spread/absolute-value floors and a
profitability score
`((compare - price) / (price + 2)) * log10(1+factor) * sqrt(qty)`
— **the exponent on quantity is a square root, not
`qty^0.25`**, and the log is base 10 (`math.Log10`), not a bare `log`; the
`+2` is the named constant `ProfitabilityConstant`. Output: sub-tabbed
tables (singles/sealed/not-found, via `docparse.PartitionEntries()`), CSV
export, CardConduit estimate hand-off, sharable result URLs. Limits are now
named constants (upload.go): `MaxUploadEntries` 350,
`MaxUploadProEntries` 1,000 (granted by the `UploadOptimizer` signature
flag), `MaxUploadTotalEntries` **15,000, not 10,000** (granted by a
`UploadNoLimit` flag, or implied by dev mode, the CardConduit estimate
flow, Deckbox export, the TCGplayer CSV export, or a buylist CSV download),
and `MaxUploadFileSize` 5 MB (`5 << 20` bytes).

### 5.3 Arbitrage (`arbit.go`) and Sleepers (`sleep.go`)

- Three modes off one template/handler (`scraperCompare()`): **Arbit** (buy
  retail → sell to buylist), **Reverse** (same `mtgban.Arbit()` call with
  source/scraper roles swapped: pick a vendor buylist to sell into, compare
  against every seller's retail), and **Global** (`mtgban.Mismatch()`,
  seller vs seller mismatches, 200 %+ spread, capped at 300 results).
  19 toggleable filters (`FilterOptKeys`/`FilterOptConfig`: conditions,
  foil, rarity, reserved list, profitability ≥ 1.74 (`MinProfitable` —
  dropped from 4.0 when the profitability index switched to a log10 base),
  penny floors, quantity, SYP/stocks lists…) and 8 sort orders
  (`arbitLess()`: available, sell price, buy price, profitability, diff,
  spread, edition, alpha).
- **Sleepers** scores cards by how often they appear as opportunities across
  all seller×vendor pairs (`getTiers()`), plus variants: bulk repricing
  (`getBulks()`), long-unreprinted (`getReprints()` — the 2-year/$3 floors
  are not in sleep.go: they live in product.go's `getReprintsGlobal()`
  (`YearsBeforeReprint`/`MinimumReprintPrice`), which builds the snapshot
  `getReprints()` reads via `GetReprints()`, see §5.5), CK hotlist growth
  (`getHotlist()`), market-gap (`getGap()`). Scores are normalized onto S–F
  tiers (`SleeperLetters`), 34 cards per tier (`MaxSleepers`).

### 5.4 Newspaper (`news.go`)

Six report pages (spike score combined/plain, vendor-listing
increase/decrease, CK buylist increase/decrease), defined declaratively
with their SQL (`newspaperPagesInitial`), all query one PostgreSQL
`NewNewspaperDB` populated by external scripts into `scripts__*_cards`
tables. Each page's query filters on `game_name`, substituted per
deployment from `gameMap` (full game names for every game `mtgmatcher`
registers, gundam/palworld included — without an entry, every refresh
logs it, pages left empty — each TCGplayer's exact `productLineName`,
which is what the newspaper stores); the short form for the navbar wordmark
comes from the sibling `gameBadgeMap`. `cacheNewspaper()` refreshes every
3 h into an atomic pointer (`newspaperPagesPtr`), caching both a same-day
and a 3-day-delayed variant of every page's query (`Results`/
`Results3Day`), toggled per request by the `NewsEnabled` sig flag/cookie —
not by separate databases. The formerly separate MySQL-backed "old" pages
(`Newspaper1dayDB`/`Newspaper3dayDB`, `mtgjson_portable` joins, ensemble
forecast) are gone; only the PostgreSQL pages above remain. 25 rows/page
(`DefaultPageSize`), filterable by edition/rarity/price bucket/finish/%
change.

### 5.5 Sealed EV (`product.go`)

`runSealedAnalysis()` computes per-set values (TCGLow, TCGDirect,
low-minus-bulk, CK buylist, Direct-net; foil variants) by summing card
prices with bulk-price floors for cheap cards (`runRawSetValue()` →
`ProductKeys`/`ProductFoilKeys`). It also rebuilds the reprints snapshot
(`getReprintsGlobal()`, feeding Sleepers' `getReprints()`, §5.3), computes
three 90-day CK buylist metrics from `PricesArchiveDB`/`timeseries`
(hotlist, highest, P90 "good" price via `buylistMetrics()`), and indexes
every TCGplayer SKU (singles + sealed) to its card UUID plus the TCGplayer
catalog IDs CSV exports rely on. The editions snapshot (set lists,
categories, parent/child trees) published for the Sets/Sealed pages is
built separately, by `newEditionsSnapshot()` as part of a datastore load
(§2.1) — not by `runSealedAnalysis()`.

### 5.6 Charts (`chart.go`, `chart_resolve.go`, `api_chart.go`, `timeseries/`, `db_migration/`)

`timeseries` is a PostgreSQL client, currently spanning two schemas at once.
The legacy wide table `product_prices` is keyed `(date, mtgjson_uuid, is_foil,
is_etched, language, is_alt)` with ~10 nullable per-source price columns (CK
retail/buylist, TCG market/low, MKM low/trend, SCG/ABU/CSI buylist, TCG
sealed EV), COALESCE-merged in 500-row batch upserts. A "long form" redesign
(`db_migration/`, in-progress cutover) is being built alongside it without
touching the old tables: a 13-row `providers` lookup, a `variants` table (one
row per printing — Magic keyed by `mtgjson_uuid`, non-Magic by TCGplayer
product + sub-type), and a date-partitioned `prices(ban_id, date, provider,
price)` table with one row per provider instead of a COALESCE merge.
Charts, buylist metrics and the screener read only the long tables;
`Config.TimeseriesConfig.LongFormWrites` switches each deployment's writes
onto them (per the cutover plan).

`stashInTimeseries()` (cron `0 */12 * * *`, §2.1) snapshots current prices
twice daily, normalizing non-NM conditions up via grade multipliers
(`defaultGradeMap`: NM 1×, SP 1.25×, MP 1.67×, HP 2.5×, PO 4×), and — when
`LongFormWrites` is on — best-effort dual-writes the same snapshot into the
long tables via `stashLongForm()`. That path resolves every row through
`ResolveMagicBanID`. A non-Magic deployment skips the wide table, which
cannot hold its card ids, and writes the long tables whatever the flags say
(`stashNonMagicTimeseries`). Its ban_ids are not drawn from the identity
sequence: a new non-Magic variant is filed under `timeseries.TCGBanID`,
`category<<40 | product<<8 | sub-type code`, by the snapshot and the tcgcsv
ingest alike (`EnsureTCGVariants`). Variants filed before that keep their
sequence ids, so existing `ban:<n>` links and price rows stand; Magic still
mints from the sequence, since an mtgjson uuid does not fit in a bigint.
Reads are already game-agnostic: `resolveChartTarget()` (chart_resolve.go)
accepts `ban:<n>`, `tcg:<n>`, `scryfall:<uuid>`, `mtgjson:<uuid>`, or a bare
id, and non-Magic cards chart correctly. Lookback
is per-request, not a fixed per-tier table: `chartLookback()` reads days from
the signed `SearchChartLoopback` ACL param, defaulting to 30 days when
absent/invalid, and 3650 days in dev mode without `-sig`. `/api/chart/{id}`
(`ChartDataAPI`) returns Chart.js-ready datasets plus checkpoint annotations
for any id form above.

### 5.7 BAN Price API (`api_banprice.go`, `banprice/`)

`/api/mtgban/{retail|buylist|all|sealed}[/<set-code>|<uuid-or-hash>].json|
.csv`, plus flat `sets.json|.csv` and `stores.json|.csv` endpoints (version
"1"). Output: `{meta, retail: {id: {store: BanPrice}}, buylist: …}` where
`BanPrice` — its own `banprice` package now, importable by external
consumers — carries regular/foil/etched/sealed prices plus optional
per-condition (`Conditions`) and per-quantity (`Quantities`) breakdowns.
Query params: `id` mode (`tcg`, `scryfall`, `mtgjson`, `name`, `mkm`, `ck`;
unset or unrecognized falls back to the card's own internal uuid, not
scryfall), `qty`, `conds`, `finish`, `vendor` filter (must be a subset of the
enabled stores), `tag=names` (full store names instead of shorthands), and
`filter=singles|sealed` on the `/sets`/`/stores` endpoints. Access scoped by
sig params `API` (an explicit store list, or `ALL_ACCESS` — expanded from
live sellers/vendors minus blocklists at request time — or `DEV_ACCESS`) and
`APImode`; a request with neither `sig` nor `API` falls back to
`Config.APIDemoStores` and is refused the full `all`/`retail`/`buylist` dumps,
by those exact names; it keeps the sealed dump and per-set or per-card
requests. An unknown dump name answers "Not found". A `/sealed/` search
needs the `sealed` mode as the sealed dump does. Other user APIs: `/api/tcgplayer/{lastsold,directqty,decklist}`,
`/api/cardmarket/decklist` (CSV exports keyed to store SKUs), `/api/prices`
(`BatchPricesAPI`, batch best-retail/best-buylist for ≤50 ids),
`/api/palette/*` (public metadata for the command palette), and
`/api/mtgban/search/` (shares `SearchAPI` with `/api/search/`).

`/api/v2/` (version "2", `PriceAPIv2`, `api_banprice_v2.go`) serves the same
endpoints, options and access as v1, and v1's CSV. Its JSON prices are
`{id: {finish: {store: [{condition, price, qty, available}]}}}`
(`banprice.V2`): the finish is the card's `FinishSlug` (`sealed` for sealed
product), and a store's list has one entry per condition, best first
(`banprice.ConditionOrder`), holding its best price in that condition
(lowest retail, highest buylist), across every uuid the id covers, rounded
to the cent; a price that rounds to nothing is left out. `qty` is
the copies the store's own listings in the condition hold, summed (on a
buylist, the copies it buys); `available` is every copy in the condition
on sale there at any price, from the entry's `Available` where the scraper
counts them (Mana Pool does, keeping no quantities of its own), TCGplayer
Direct's stock, or TCGplayer's listed copies, the last two from the
newspaper scrape while it is a day old at most and TCGplayer's none for a
printing the scrape capped. An absent `qty` or `available` is unknown,
never zero, and an absent `qty` on a buylist is no limit. `condition` is
absent for an index store and for sealed. A printing's whole stock is the
sum of `available` over its conditions, where every condition has one.
`qty` and `conds` do not apply as options: the list always carries both.
v2's `stores.json` lists the caller's stores as objects, sellers and
vendors apart (`banprice.Stores`): shorthand, name, country, and whether a
store is sealed, an index (its prices carry no condition) or carries `qty`,
a vendor's credit multiplier, and when its prices were collected.
`finishes.json` (v2 only) lists the finish keys the game's prices use with
a label and a count, commonest first; `filter=singles|sealed` narrows both.
v2's JSON takes no `tag`: its prices are keyed by store shorthand, which
`stores.json` maps to each store's display name. Its `.csv` prices are
v1's CSV and still honor `tag=names`. An `id` outside `mtgban`, `tcg`,
`scryfall`, `mtgjson`, `mkm`, `ck` and `name` is refused with an error,
where v1 falls back to `mtgban`. With `id=mkm`, a card is keyed by the
product the Cardmarket shelves price it under, read off its first entry
(MKMLow, then MKMTrend, for singles, and MKMSealed for sealed product),
and by the datastore's `mcmId` only where they do not price it: the
datastore names a Cardmarket id for few non-Magic cards. A printing's
finishes can then sit under two ids, where the shelves price one finish
under a product the datastore's `mcmId` does not name and do not price
the other. A response takes the shelves once, so its cards all come from
one snapshot.

`/api/v2/search/` is v1's search (`SearchAPI`) answered in v2's shape: the
same query, scope, key store scope and sort pick the cards, and each store's
entries for them that the query's store, condition and price filters keep
(`sellerEntryFound`, `vendorEntryFound`, shared with the search page) are
filed as the v2 price API files them (`sellerSearchV2`, `vendorSearchV2`).
Its JSON keys cards as v1's search does, by `scryfall` and by `mtgjson`
for sealed, but takes the `id` a request asks for, sealed included, and
refuses one v2 does not know. Stores are keyed by shorthand, as in all of
v2. Its `.csv` is v1's search CSV.

### 5.8 Discord bot (`discord.go`, `embed.go`, `internal/embed/`)

`discordgo` session with Guilds + GuildMessages intents. Commands: `!card` /
`?card` (sealed) price embeds — an uncapped index section plus retail and
buylist sections capped at the 7 best prices each (`MaxCustomEntries`,
internal/embed/embed.go), with a 🔥 suffix above a 60% ratio and a 🚨 on a
buylist row priced above ~111% of some listed retail price; `$$card`
last-sold lookups (5 s fetch timeout, 30 s message-edit timeout);
`[[card]]`/`{{card}}` syntax, recognized only in three hardcoded channels
(dev/recap/chat); and Gatherer-link interception by multiverse id.
`discordgo` runs every handler on a bare goroutine, so `guildCreate` and
`messageCreate` each defer `recoverJob()` (recover.go), as does the
goroutine a `$$` lookup fetches on: a panic on one of them is reported
(§2.2) and costs that one event (a `$$` reply falls back to the timeout)
rather than the process. The scans the search of a
`!card`/`?card` lookup fans out to (`searchParallelNG`) recover their own
panics, so one that panics costs only its side of the reply's prices.
Automatic affiliate-link rewriting (`checkForLinks`: Card Kingdom, Cool
Stuff Inc, TCGplayer, Star City Games, Manapool, CardTrader, Amazon) is
gated to the configured Discord server *and* the default game, so a non-Magic
deployment's bot never rewrites links. Webhooks — a separate channel from
the bot session, via `internal/notify`, configured per
`Config.Discord.UserWebhookURL` / `Config.Discord.ServerWebhookURL` /
`Config.Discord.APIWebhookURL` — deliver server notifications:
reload/refresh, panics (with stack trace), shutdown, checkpoint/datastore
reload failures. A post longer than the 2000 characters Discord accepts is
cut to fit, and one Discord refuses is logged, as is one that fails before
Discord answers, without its URL.

### 5.9 Admin (`admin.go`)

One handler, `Admin`, which calls a function of its own for each action,
tool, editor and table, driving nine tabs —
Dashboard, Usage, People, Config, Checkpoints, Access, Affiliates, Key
Overrides, Tools — through query-command dispatch: scraper refresh via
GitHub Actions dispatch (`?refresh=`) or direct reload (`?reload=&table=&tag=`),
log download or redirect to the CI log (`?logs=`), and the `?tool=`
family (`adminTools`), the dashboard's server actions and admin tools:
`datastore` (`s.startDatastoreReload`), `config` (reload
config plus the ACL/grants/affiliates that ride beside it), `checkpoints`
(chart checkpoints), `snapshot` (stash into timeseries), `tcgcsv` (TCGCSV
price ingestion), `server` (process exit only), `newKey`/`demokey` (API-key
generation, `&user=&duration=`), and `invite` (a signed invite link for a
tier, `&tier=&duration=`). Five JSON editors — config,
checkpoints, ACL/access table, affiliates, key overrides — the last backed
by a per-store UUID-remap builder reached from a "Fix" link on search
results (`search.go`/`search.html`). A People tab adds/removes Patreon
grants in place. The dashboard lists retail/buylist scraper freshness with
live 🔶 status from a `?workflows=` GitHub Actions poll, registered pages,
uptime, memory via `go-osstat`, and disk via the platform-specific
`internal/diskusage.Stats` — a no-op returning zero on Windows. The Usage
tab aggregates 30 days of `ObservabilityDB` telemetry, cached 5 minutes.

Each row's store name comes from the scraper index's reverse lookup
(`scraperStoreOf`). Every place the dashboard talks to GitHub (the
`?refresh=` dispatch and the busy check in front of it, and the `?logs=`
redirect) names the target workflow through `newBantoolWorkflow(game,
store)`, one helper with no Magic special case: `EventType`
(`<game>-<store>`, also the `repository_dispatch` payload), `File`
(`bantool-<game>-<store>.yml`) it dispatches and polls by, and `RunName`
(`<game> / <store>`), which the `?workflows=` poll's running-indicator
script matches a row's `data-tag` against - the Actions API returns a run's
display name but not the `event_type` that started it.

**Staleness** (staleness.go): a row is stale when its
`InventoryTimestamp`/`BuylistTimestamp` is more than `StaleAfter` (48h) old,
or unset. The dashboard shows this three ways: a "stale Nd" badge in the
Status cell (alongside, not instead of, the 🔶 running indicator), the
Last Update cell in red, and a per-table "N stale" next to "N providers",
plus a page-top banner listing every stale store, each linking to
`?logs=<store>`. The badge is column 8 of each scraper-table row in
`PageVars.Tables`, and the template derives the rest from it rather than
reading `PageVars` fields: `stale_count` counts a table's stale rows, and
`stale_stores` lists their stores (column 2), sorted and deduplicated,
leaving out `UNKNOWN` and `session`. Separately, an hourly cron job
(`checkStaleness()`, registered in `startCrons()`) compares every served
seller's/vendor's staleness against an in-memory map and announces only
a transition (`classifyStaleTransition`, a pure function): once going
stale, once recovering, never on repeat. One check's transitions go out
together through `notifyStale` (`notify.Send` to the server webhook), in
as few messages as fit, and a transition is recorded only once its message
went through, so one Discord refuses is announced again at the next check.
A session store (an admin's upload) is skipped, the same as the banner.
The map is in memory only, so a restart's first check may announce every
already-stale row once.

**Background jobs** (jobs.go, `internal/jobs`): every cron job above, and
the goroutines that run the same jobs off schedule (the startup set
analysis and CK signals, the newspaper and TCG listings a datastore load
starts, the admin stash buttons, the offline refresher), goes through
`tracked()`, which records each run's start, length and panic under the
job's name in `backgroundJobs`; `addJob` also records its schedule. The
jobs whose output can be wrong while they succeed report what they found
and what is wrong with it: the set analysis (a run on the empty datastore,
and, where the site serves CK's buylist, no P90s), CK's signals (a missing or day-old stock history,
missing odds or odds past 36 hours, no sell now or wait), the price stash
(rows it failed to write), the newspaper cache and TCG listings (a failed
load). A row's problem is its latest run's panic, then a scheduled time it
missed or ran on past by more than 10 minutes, then its report. The
dashboard's first table lists every job with its last run, length, what it
found and its problem; mobile lists them in Status. The hourly
`checkJobHealth()` announces a row turning bad or recovering through the
staleness alarm's map and messages, from 15 minutes after startup.

## 6. Support packages

| Package | Purpose |
|---|---|
| `timeseries/` | PostgreSQL price-history client (see §5.6) |
| `apisig/`, `apihandoff/` | The API signature format and the signed Patreon handoff token; the API gateway imports both, so golden tests freeze their bytes |
| `apiproductlist/` | The API price list (`products.json`, embedded), which the pricing page renders and the gateway seeds Stripe from |
| `ratelimit/` | Per-IP token-bucket limiter wrapping `x/time/rate`; `IPAddress()` honors X-Forwarded-For |
| `patreon/` | Patreon OAuth2 token exchange + identity/membership tier lookup |
| `moxfield/` | Moxfield deck & paginated collection importer → `Item` list |
| `manabox/` | Reader for public decks from ManaBox's cloud API |
| `cardconduit/` | CardConduit bulk-estimate POST client |
| `banprice/` | Wire types for the price API — `Price`, `ConditionTags` — in the exact JSON shape `api_banprice.go` and the templates share |
| `collectr/` | Client for Collectr showcase pages (product listings, Magic + Lorcana categories) |
| `fuzzy/` | Levenshtein-distance string similarity powering "did you mean" suggestions |
| `observability/` | Postgres page-visit recorder backing the admin usage dashboard, plus the search-votes table behind the popular-searches ranking |
| `tcgcsv/` | Client for tcgcsv.com's category→group→product/price hierarchy, used to ingest non-Magic prices. The daily-archive reader stays here but every date answers 403 upstream; `ErrArchiveUnavailable` is how callers learn that |
| `tcgcsvd/` | tcgcsv ingest service: library + `cmd/tcgcsvd` binary. Daily/products/backfill jobs take a cross-process Postgres advisory lock so a standalone process and the website's own crons never crawl tcgcsv.com at once (`tcgcsvd/README.md`). With the archives withdrawn, the per-group daily price files are the only source and backfill falls back to the current snapshot (`docs/tcgcsv-archive-withdrawal.md`) |
| `userstate/` | Postgres-backed cross-device sync of per-user favorites/recents/prefs (`/api/userstate/`), keyed by a hash of the login email |
| `cmd/` | Just `cmd/tcgcsvd/main.go` — a thin CLI over the `tcgcsvd` package (`-daily`/`-products`/`-backfill`/`-games`) |
| `internal/` | Packages only this module imports: `alerts` (price alerts: the model, its Postgres store on the userstate pool, the debounced evaluator, the Discord DM and the `/api/alerts/` JSON API; `docs/adr/0005-price-alerts.md`), `jobs` (what each background job last did, for the admin dashboard and the staleness alarm), `dsreload` (single-flight datastore reload that queues one request behind a running one, remembers the outcome for late askers), `bucketstore` (atomic in-memory snapshot of a bucket JSON doc — key overrides, chart checkpoints), `access` (tier ACL table + Patreon grant list), `tmplparse` (indentation-stripping template parser used by all template loading, see §7), `docparse` (CSV/XLS/decklist row → matched card entry, used by `upload.go`), `offline` (offline-mode binary payload format, per-user watermarking, per-set fingerprints), `offlineapi` (serves the offline PWA data endpoints), `palette` (command-palette data endpoints + nav-target lists), `mkmidparser` (Cardmarket product id → the card it names, for uploads that carry one), `sessionstore` (an admin's upload published as a store for the running process), `embed` (oEmbed link-unfurl panels + Discord embed field lists), `suggest` (the names the browser's suggestion bar offers through OpenSearch, and "did you mean" hints for empty search results), `notify` (Discord webhook one-liners), `diskusage` (platform-specific disk stats, isolates build tags), `debounce` (shared burst-coalescing run loop for background refreshers), `tcgcatalog` (parses `tcgdumper`/go-tcgplayer catalog dumps) |

## 7. Frontend

- **Templates** (`templates/`): Go `html/template`, parsed via `internal/tmplparse.ParseFiles` (strips the authoring indentation before parsing — see §6). Desktop `base.html` / `base-landing.html` and `mobile/base-mobile.html`, with `templates/mobile/<page>.html` overrides for 7 of the 13 page templates (admin, home, news, offline, search, sets, sleep — the rest fall back to the desktop template on mobile). Partials (`templates/partials/`, included per-page by `renderTemplateFiles()`, not blanket-loaded): navbar, settings-modal + settings-stores-grouped, editions-picker, set-symbol, admin-usage, guide-overview/-palette/-syntax/-api (the guide's section descriptions) and guide-faq, search-landing, sussy-price, patreon-login, alert-modal, alerts-body. Custom template funcs live in `templates.go`'s `funcMap` (price formatting, affiliate links, a UUID→store-ID lookup, game/rarity-badge dispatch for the multi-game skin, palette-target JSON). None reads the card datastore: a page's set symbols, promo labels and TCG ids are in its data, filled by the handler from the one snapshot it read, and so is the admin page's reload status. Some still read package state as they render: the scraper snapshots (`scraper_name`, `is_sealed_scraper`, `uuid2ckid`, `invalid_direct`, `tcg_market_price`, `guide_stores`), the affiliate codes (`load_partner`) and `Config`. Production pre-parses every page×(mobile|desktop) combination at startup (`buildTemplateCache()`); dev mode re-parses per request. Base templates inject `__BAN_NAV` / `__BAN_PALETTE*` JSON globals for the client.
- **JS** (`js/`): all vanilla, no framework, no bundler — one vendored exception, `js/vendor/fflate.min.js` (gzip, used by the offline cache). Notable modules: `command-palette.js` (Cmd+K nav/search) plus its `palette-chips.js` (chip-based input) and `palette-providers.js` (prefix-driven candidate providers) helpers; `settings.js` (cookie-backed settings registry with dirty-state confirmation — the formerly separate `settings-modal.js`/`settings-search.js` are gone, folded in); `settings-shell.js` (the modal's tab rail and cross-tab search); `confirm-dialog.js` (in-page replacement for `window.confirm`); `autocomplete.js`, `favorites.js` and `recent-searches.js` (localStorage; also sends the popular-searches vote beacon for a typed search that found results); `user-state.js` (best-effort cross-device sync of favorites/recents/prefs for signed-in users, against `/api/userstate/`); `chartopts.js` (Chart.js v4 plugins: crosshair, gradients, HTML tooltips, checkpoint markers); `nightmode.js` theme toggle. `js/offline/` (17 files) plus a root `sw.js` service worker implement an installable offline mode (IndexedDB price cache, background sync, offline-first `/offline` shell). CDN libs: Chart.js v4 (+ date-fns adapter, annotation plugin), Lucide icons, Tablesort, Keyrune.
- **CSS** (`css/`): custom design system in `main.css` (+ a generic `mobile.css` override pass) via CSS variables (light/dark themes by body class, layered surfaces, type scale, tier colors); one stylesheet per feature page plus 5 `*-mobile.css` overrides, plus `command-palette.css`, `settings-modal.css`, `offline.css`, and two embedded webfonts (`phyrexian.woff2`, `quenya.woff2`).
- **State**: user preferences live in cookies (read server-side by handlers too — e.g. store blocklists, optimizer settings) and localStorage (favorites/recents/layout); signed-in users additionally get a best-effort Postgres sync of favorites/recents/prefs via `userstate/` + `js/user-state.js`.

## 8. Development & operations

- **Config variants**: one config file per deployment, selected via `Config.Game`
  (magic is the default; lorcana, onepiece, yugioh, riftbound, fleshandblood,
  and pokemon are already live; gundam and palworld have the code and the
  deploy workflow but no DigitalOcean app or secret provisioned yet — see
  AGENTS.md's "Deploying a new game"), each with its own
  `.github/workflows/<game>-deploy.yml`. All `*.json` files, including every
  `config*.json`, are gitignored — the copies in a local checkout are stripped
  dev config, not production; real per-deployment config is pulled from the
  config bucket, so don't infer live behavior from a local file.
- **Commit convention**: lowercase area prefix — `search:`, `upload:`,
  `api/banprice:`, `fix(mobile):` — small focused commits, no `Co-Authored-By`
  trailer.
- **Testing**: broad and per-feature, organized by subsystem rather than
  one-per-source-file: search/searchfilter (query parser, sort
  orders, sealed/collector-number edge cases), upload (parsers, unpack, magic
  export/CSV), arbit (blocklists, language handling, suspicious-spread
  heuristics), charts (axis, buttons, resolve/search-by-id), admin (ajax,
  datastore, table-sort, usage), games-coverage/game-badge/game-body (every
  game the matcher registers needs a badge and a template — checked in one
  place), set-symbol, mobile variants, redirects, news, common ACL/affiliates,
  plus `*_bench_test.go` benchmarks. `tests/` holds the Bun/JS tests, most of
  them (`tests/offline/`) for the offline/service-worker mode. Go tests that need card data skip
  without the local `allprintings5.json` datastore, and
  `MTGBAN_TEST_DATASTORE=off` skips loading it (AGENTS.md). CI (`.github/workflows/ci.yml`)
  runs on every PR and push to master: a `style` job (`gofmt -s -l .`,
  `go vet ./...`, `revive` (its config also rejects any import of
  `reflect`, per `docs/adr/0002-no-reflect.md`) and `staticcheck`, both
  pinned in the workflow) and a `build-and-test` job (`bun test tests/`, `go build ./...`,
  `go test ./...` against a downloaded `allprintings5.json`).
- **Deployment**: pushing a `v*` or `<game>-*` tag runs that game's
  `.github/workflows/<game>-deploy.yml`. App Platform games deploy with
  `doctl apps create-deployment`; `magic`, `pokemon` and `yugioh` run
  `deploy/deploy.sh <ref>` on their droplet, a blue-green swap between two
  systemd instances behind nginx, gated on `/healthz` (`deploy/README.md`).
  `update-mtgban.sh` is unrelated to this path: it's a local-dev
  helper that repoints the `go-mtgban` module dependency at a local checkout,
  the latest commit, or back to `go.mod`'s pinned version (`local`/`latest`/
  `remote` args) — not part of deploying the site. Logs rotate per page under
  `logs/` (500 KB × 3 via `leemcloughlin/logfile`), downloadable from admin
  via `?logs=`. Discord webhooks act as the alerting channel. `/healthz` for
  liveness.
- **Patch-based workflow**: work still being sequenced is sometimes staged as
  untracked `git format-patch` files in the repo root; `ls *.patch` lists them.

## 9. Architectural principles observed

1. **Immutable snapshot swapping** over locking for all hot data
   (scrapers, newspaper cache, editions) — readers never block.
2. **Stateless requests**: all user state is in the signed cookie or
   client-side storage; the server holds no sessions.
3. **Capability-based auth**: the HMAC signature *is* the permission set;
   handlers read flags from it rather than consulting a user database.
4. **Storage abstraction** via `simplecloud` URL schemes (file/B2/HTTP)
   for every external artifact (config, datastore, scraper dumps,
   checkpoints).
5. **Server-rendered, progressively enhanced UI** — no SPA, no build step;
   JS only enhances.
6. **Declarative page registry** (`NavElem`) ties routing, auth, nav,
   logging, and templates together in one place.
7. **An explicit card datastore**: the site owns the loaded datastore and
   publishes each load whole; an entry point reads it once and hands the
   backend (or the datastore) down, and templates read none of it
   (`docs/adr/0003-explicit-backend.md`).
