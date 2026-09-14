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
yugioh, riftbound, fleshandblood, and pokemon each have their own
`.github/workflows/<game>-deploy.yml`. gundam and palworld are wired into
the site's rarity/color/card-back handling (`utils.go`) and registered in
go-mtgban's `mtgmatcher/games`, but aren't deployed yet — go.mod pins
`go-mtgban v0.8.3`, which predates the commit adding their packages, and
neither has a deploy workflow. It is a single server binary (~25k lines in
the root package, excluding tests) plus small support packages,
server-rendered Go HTML templates, and vanilla JS/CSS with no frontend
build step.

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

Flags (`main()`, main.go:1300-1318): `-cfg` (config path, default
`$BAN_CONFIG_PATH` or `config.json`), `-port`, `-ds` (datastore path,
default `AllPrintings.json.xz`), `-acl` (access-table path override),
`-grants` (Patreon grants path override), `-dev` (hot-reload templates,
relaxed auth), `-sig` (force signature checks in dev), `-noload`, `-nonews`,
`-log` (default `logs/`), and a `tcgcsv-*` family — `-tcgcsv-backfill`,
`-tcgcsv-daily`, `-tcgcsv-products` each run one ingest job against
`tcg_prices`/`tcg_products` and exit without starting the web server (the
same jobs `cmd/tcgcsvd` runs as its own process); `-tcgcsv-from`/
`-tcgcsv-to`/`-tcgcsv-force`/`-tcgcsv-categories` tune the backfill. There is
no `-offline` flag any more — the old "run without B2, load prices from
another BAN instance's API" mode is gone (see §2.3).

Boot sequence (`main()`, main.go:1299-1674):

1. `preloadConfig()` → resolves `ConfigBucket` to a local file or `b2://`
   bucket only (an `http(s)://` config path is rejected). `loadVars()`
   parses the config and defaults `Config.Game`/`Config.Port`/
   `Config.DatastorePath`; `BAN_SECRET` seeds HMAC signing, falling back to
   `DefaultSecret` when unset in any mode (outside dev a defaulted secret
   only logs a warning). `loadCommonConfig()` loads the ACL/grants table and
   affiliates. `loadRarityBadges()` (no-op for the default game).
2. If any `-tcgcsv-*` job flag is set: `openDBs()`, `initTCGCSVService()`,
   run the requested job, `os.Exit(0)` — the datastore and price data are
   never loaded and `ListenAndServe` never runs.
3. Otherwise: `loadKeyOverrides()`, create `LogDir`, load Google credentials,
   `openDBs()` → `PricesArchiveDB` (PostgreSQL, `timeseries` package, price
   history for charts, plus `tcg_prices`/`tcg_products` when TCGCSV
   ingestion is configured), `NewNewspaperDB` (PostgreSQL), `UserStateDB`
   (cross-device sync, only if `Config.UserStateConfig` is set), and
   `ObservabilityDB` (usage telemetry, only if `Config.ObservabilityConfig`
   + an instance name are set). `Newspaper1dayDB`/`Newspaper3dayDB` (MySQL)
   no longer exist. Then `startAccessReloadListener()` (picks up ACL/grant
   saves made by peer deployments sharing the price DB), `initTCGCSVService()`
   (non-fatal if unconfigured), `reloadCheckpoints()`,
   `offlineService.LoadPersisted()`, then the production template cache
   build (`buildTemplateCache()`) — see §7.
4. Async goroutine: `loadDatastore(Config.DatastorePath)` — opens the site's
   game via `mtgmatcher.Open(datastoreGame(), reader)` (not the old
   `mtgmatcher.LoadDatastore()`) and publishes it, then itself spawns
   `rebuildSuggestIndex()`, `updateStaticData()`, `cacheNewspaper()`, and
   `paletteService.BuildSetsCache()`/`BuildPromosCache()`/`BuildFinishesCache()`
   as further goroutines.
5. Unless `-noload` (`SkipPrices`): async goroutine `loadScrapersNG()`, then
   `runSealedAnalysis()`, `warmVariantCacheIfEnabled()`,
   `offlineService.RefreshManifest()`.
6. `offlineService.StartRefresher()` — one debounced goroutine that every
   runtime manifest refresh funnels through.
7. Cron jobs (`gopkg.in/robfig/cron.v2`, non-dev only, main.go:1477-1513):
   - `0 */12 * * *` — `stashInTimeseries()` (snapshot prices to Postgres)
   - `30 */12 * * *` — `runSealedAnalysis()`
   - `33 */3 * * *` — `cacheNewspaper()`
   - `20 */12 * * *` — `offlineService.RequestRefresh()` (backstop; normal
     refreshes are event-driven)
   - `15 */6 * * *` — `refreshCheckpoints()`
   - when tcgcsv ingestion is configured: `0 21 * * *` —
     `stashTCGCSVPrices()`; `0 22 * * 1` — `stashTCGCSVProducts()`
   - the old per-scraper `force_reload_at` cron expressions no longer exist
8. `setupDiscord()`, then handlers are registered and `http.Server`
   `ListenAndServe`s on `Config.Port` (default `:8080`, no TLS — assumes
   reverse proxy); graceful shutdown on SIGINT/SIGTERM with a 5 s timeout,
   Discord notify, and `ObservabilityRecorder.Close()`. `/healthz` returns
   200 only when UUIDs + sellers + vendors are loaded.

### 2.2 Global state & concurrency model

The dominant pattern is **immutable snapshots behind atomic pointers**:

- `sellersPtr`/`vendorsPtr` (`atomic.Pointer[[]mtgban.Seller/Vendor]`,
  load.go:47-54). Readers call `GetSellers()`/`GetVendors()`; writers go
  through `updateSellers()`/`updateVendors()` which validate (timestamp must
  not regress; a new inventory/buylist under half the previous size is
  rejected once the previous one held over 100 entries) and `.Store()` a new
  slice under `scrapersWriteMu`. Zero-downtime reloads.
- Same pattern for newspaper page cache (`newspaperPagesPtr`), editions
  snapshot (`editionsPtr`), reprints (`reprintsPtr`), checkpoints
  (`checkpointsStore`, an `internal/bucketstore.Store[T]` — also an
  atomic-pointer swap, not a mutex), and last-update timestamps
  (`lastDatastoreUpdatePtr` and siblings).
- `Config` is loaded once and swapped whole on admin reload (`admin.go`);
  per-user API secrets read behind `apiUsersMutex`; affiliate data behind
  `affiliatesMu`/`affiliatesPtr`.

### 2.3 Data loading pipeline

- **Card datastore**: `Config.DatastorePath` (per-deployment; falls back to
  `AllPrintings.json.xz`) from local disk, B2, or HTTPS via
  `openBucketPath()`; opened through `mtgmatcher.Open(datastoreGame(), …)`
  and indexed per game — this is now a multi-game site (magic, lorcana,
  onepiece, yugioh, riftbound, fleshandblood, pokemon, gundam, palworld).
  Reloadable from the admin panel (`?reboot=datastore`/`datastore-backup`).
- **Scraper price data** (`loadScrapersNG()`, load.go:88-160): config maps
  scraper name → `{retail|buylist: [shorthands]}`; each is fetched from B2
  at `game/name/kind/shorthand.<format>` (format from `BucketFileFormat`),
  deserialized via `mtgban.ReadSellerFromJSON`/`ReadVendorFromJSON`. 3
  retries with backoff, 2-minute timeout per scraper.
- **"Offline" now means the PWA offline experience**, not a data-loading
  mode — `api_load.go` and the old "run without B2, reconstruct
  sellers/vendors from another instance's `/api/mtgban/all.json` +
  `sealed.json` + `stores.json`" path are gone. `internal/offlineapi.Service`
  (wired as `offlineService`, main.go:758) instead serves a manifest,
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

### 3.1 Patreon OAuth (auth.go:166-249)

`/auth?code=…` exchanges the code via the `patreon` package, fetches user
identity, and checks the shared grant list (`PatreonGrants()`, loaded from
the file at `Config.PatreonGrantsPath` — not a `Config.Patreon` field) for a
hardcoded per-email tier override; failing that it fetches
`currently_entitled_tiers` and maps Patreon's tier labels onto four internal
tiers (`Pioneer`, `Modern`, `Legacy`, `Vintage` — Patreon's own "Standard"
tier folds into `Pioneer`), then issues a **signature**.

### 3.2 Signature mechanism (auth.go:683-756)

A signature is a base64-encoded query string carrying the user's identity,
tier, per-feature flags from the ACL, an `Expires` unix timestamp (11-day
default), and an HMAC-SHA1 `Signature` over
`METHOD + Expires + BaseURL + encoded-params` keyed by `BAN_SECRET`; API
signature checks (`enforceAPISigning`) look up a per-user secret in
`Config.APIUserSecrets` first, falling back to `BAN_SECRET` — page
signatures always use `BAN_SECRET` only. It is stored in the `MTGBAN`
cookie (31 days, shared across `*.mtgban.com`, **not** HttpOnly) and/or
passed as `?sig=`. `GetParamFromSig()` extracts individual grants.

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
| `noSigning` | Home, Guide, Privacy, Offline page, suggest/chart/userstate/opensearch/palette APIs, `/api/load/datastore` | No checks; captures `?sig=` into cookie; lazily initializes `ServerURL` on the first trusted-host request |
| `enforceSigning` | All feature pages, user APIs | Validates signature, expiry, per-page flag; 3 req/s per user email; POST only when `NavElem.CanPOST` |
| `enforceAPISigning` | `/api/mtgban/*`, `/api/load/*` (except `/api/load/datastore`) | JSON content-type; 10 req/s per IP (`ratelimit` token-bucket per IP via `x/time/rate`); HMAC-SHA1 validation, per-user secret from `Config.APIUserSecrets` falling back to `BAN_SECRET` |

Static assets (`/css/`, `/js/`, `/img/`) go through none of these three —
they're registered directly on `ServeFile` with no wrapper.

`/api/load/datastore` instead uses its own HMAC-SHA256 scheme (`verify()` in
api.go) over the request body with `X-Signature`/`X-Timestamp` headers,
rejecting any timestamp more than 60s old.

A fourth wrapper, `adminOnly`, composes behind `enforceSigning` on the
`/debug` pprof handler: it 404s (not 401s, so the endpoint's existence isn't
advertised) unless the signature carries the `Admin` grant.

## 4. Routing & page system

Routes are registered in `main()` from the declarative `NavElem` struct
(main.go:318-360) and the `ExtraNavs` map (declared main.go:417, populated by
`init()` at main.go:420-544): each entry declares its link, name, icon,
description, handler func, template, `CanPOST`, `AlwaysOnForDev`, optional
`ShouldHide` (a predicate that drops the entry - and, for a section like
Newspaper, its subpages with it - when e.g. no data is loaded yet for the
current game), `SubPages` (e.g. `/sets`, `/sealed` under Search) and
`HasSettings`. `genPageNav(activeTab, sig)` builds the per-request navbar by
filtering `OrderNav` (Search, Newspaper, Screener, Sleepers, Upload, Global,
Arbit, Reverse, Admin) against the signature/ACL; the list itself is
identical across all 9 games, but per-entry `ShouldHide` (Newspaper hides
itself whenever the active game has no cached newspaper UUIDs yet) and
per-deployment ACL config narrow what actually renders for a non-Magic site.
A mobile request runs the result through `filterNavForMobile()` (mobile.go),
called from every page handler right after `genPageNav`, which keeps only
the handful of pages that ship a mobile template. Every page handler
receives a giant `PageVars` struct (main.go:64-316) that carries nav,
alerts, and all page-specific fields into the templates.

Other routes: static `/css|/js|/img` (plus `/favicon.ico`, `/robots.txt`)
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

- **Query language**: `parseSearchOptionsNG()` (searchfilter.go:593, moved
  from :514) tokenizes `option:value` / `option>value` / `option<value`
  pairs, with `-` negation, against the `FilterOperations` table
  (searchfilter.go:502) of **49 operators, not ~35**: search-engine
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
- **Execution**: parse → `searchAndFilter()` (search.go:1655) resolves
  UUIDs through `mtgmatcher.Search*` (exact/any/prefix/regexp/sealed/
  hashing modes, plus `scryfall` and a sealed+card `mixed` mode) →
  `searchParallelNG()` (search.go:1895) runs seller and vendor scans in
  parallel goroutines, applying store/price/entry filter chains → optional
  custom-buylist injection → post-filters → sort (chrono/hybrid/alpha/
  number/retail/buylist) → `Paginate()` (utils.go:1440) against the named
  constants `MaxSearchResults` (100/page) and `MaxSearchTotalResults`
  (10k max, search.go:32,39).
- **Results**: `map[cardUUID]map[condition][]SearchEntry`; INDEX
  pseudo-conditions merge TCG Low/Market and MKM Low/Trend pairs into
  single rows with a `Secondary` price. Without a signature, non-affiliate
  entries are `Locked` (link disabled) against `Affiliates().List` /
  `Affiliates().BuylistList` (common.go:70) — there is no longer a
  `Config.AffiliatesList` field; affiliates now live behind that accessor
  as a split retail/buylist list.
- **Suggest** (`api_suggest.go`): no longer a live prefix scan of
  `mtgmatcher.AllNames()` per request. A `suggestIndex` is built once when
  the datastore (re)loads (`rebuildSuggestIndex()`), folding every name
  (diacritics/case/punctuation stripped) and also "squashing" spaces out of
  the folded form, into separate sorted singles/sealed views searched by
  binary search — so a typed space or hyphen reaches either spelling
  ("blue eyed" finds "Blue-Eyed…", "fireice" finds "Fire // Ice"). Prefix
  ≥3 chars, capped at 30 results (`maxSuggestions`), 5-minute cache,
  OpenSearch-compatible array response — all unchanged from before.

### 5.2 Upload (`upload.go`, ~2,480 lines, not ~2,200)

Accepts CSV (delimiter auto-detect: comma → tab → `;`, plus a `sep=`
header-row override), XLS (`extrame/xls`), XLSX (`excelize`), Google
Sheets, Moxfield decks/collections (`moxfield` package), TCGplayer
collection scrapes (goquery), **Collectr showcase pages** (new `collectr`
package, `app.getcollectr.com`, Magic/Lorcana only), and plain decklists.
Header/row parsing has moved out of `upload.go` into the `internal/docparse`
package: a shared `uploadParser` (`*docparse.Parser`, upload.go:85) exposes
`ParseHeader()`/`ParseRow()` (internal/docparse/docparse.go:183,333) —
there is no longer a standalone `parseHeader()`/`parseRow()` in `upload.go`.
Row resolution still goes through `mtgmatcher.Match()` (preserving alias
candidates and mismatch errors). Prices come from the same
`getSellerPrices()`/`getVendorPrices()` machinery as the API. The
**optimizer** picks the best store per card (highest buylist / lowest
retail within a percentage margin), with spread/absolute-value floors and a
profitability score
`((compare - price) / (price + 2)) * log10(1+factor) * sqrt(qty)`
(upload.go:1438) — **the exponent on quantity is a square root, not
`qty^0.25`**, and the log is base 10 (`math.Log10`), not a bare `log`; the
`+2` is the named constant `ProfitabilityConstant`. Output: sub-tabbed
tables (singles/sealed/not-found, via `docparse.PartitionEntries()`), CSV
export, CardConduit estimate hand-off, sharable result URLs. Limits are now
named constants (upload.go:41-44): `MaxUploadEntries` 350,
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
registers, gundam/palworld included — a missing entry panics
`cacheNewspaper()` at startup); the short form for the navbar wordmark
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
built separately, by `updateStaticData()` (§2.1) — not by
`runSealedAnalysis()`.

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
`Config.TimeseriesConfig.LongFormWrites`/`LongFormReads` switch each
deployment onto it independently (writes first, then reads, per the cutover
plan).

`stashInTimeseries()` (cron `0 */12 * * *`, §2.1) snapshots current prices
twice daily, normalizing non-NM conditions up via grade multipliers
(`defaultGradeMap`: NM 1×, SP 1.25×, MP 1.67×, HP 2.5×, PO 4×), and — when
`LongFormWrites` is on — best-effort dual-writes the same snapshot into the
long tables via `stashLongForm()`. That path resolves every row through
`ResolveMagicBanID`, so today it only persists Magic printings correctly; a
matching non-Magic write path is written but not yet merged to master.
Reads are already game-agnostic: `resolveChartTarget()` (chart_resolve.go)
accepts `ban:<n>`, `tcg:<n>`, `scryfall:<uuid>`, `mtgjson:<uuid>`, or a bare
id, and non-Magic cards chart correctly once `LongFormReads` is on. Lookback
is per-request, not a fixed per-tier table: `chartLookback()` reads days from
the signed `SearchChartLoopback` ACL param, defaulting to 30 days when
absent/invalid, and 3650 days in dev mode without `-sig`. `/api/chart/{id}`
(`ChartDataAPI`) returns Chart.js-ready datasets plus checkpoint annotations,
routed to the long-form path (any id form above) or the legacy
mtgjson-uuid-only path depending on `LongFormReads`.

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
`Config.APIDemoStores` and is refused on `all`/`retail`/`buylist` (sealed-only
demo access). Other user APIs: `/api/tcgplayer/{lastsold,directqty,decklist}`,
`/api/cardmarket/decklist` (CSV exports keyed to store SKUs), `/api/prices`
(`BatchPricesAPI`, batch best-retail/best-buylist for ≤50 ids),
`/api/palette/*` (public metadata for the command palette), and
`/api/mtgban/search/` (shares `SearchAPI` with `/api/search/`).

### 5.8 Discord bot (`discord.go`, `embed.go`, `internal/embed/`)

`discordgo` session with Guilds + GuildMessages intents. Commands: `!card` /
`?card` (sealed) price embeds — an uncapped index section plus retail and
buylist sections capped at the 7 best prices each (`MaxCustomEntries`,
internal/embed/embed.go), with a 🔥 suffix above a 60% ratio and a 🚨 on a
buylist row priced above ~111% of some listed retail price; `$$card`
last-sold lookups (5 s fetch timeout, 30 s message-edit timeout);
`[[card]]`/`{{card}}` syntax, recognized only in three hardcoded channels
(dev/recap/chat); and Gatherer-link interception by multiverse id.
Automatic affiliate-link rewriting (`checkForLinks`: Card Kingdom, Cool
Stuff Inc, TCGplayer, Star City Games, Manapool, CardTrader, Amazon) is
gated to the main Discord server *and* the default game, so a non-Magic
deployment's bot never rewrites links. Webhooks — a separate channel from
the bot session, via `internal/notify`, configured per `Config.DiscordHook`
/ `DiscordNotifHook` / `DiscordAPINotifHook` — deliver server notifications:
reload/refresh, panics (with stack trace), shutdown, checkpoint/datastore
reload failures.

### 5.9 Admin (`admin.go`)

One ~710-line handler (`admin.go` is 1,184 lines total) driving nine tabs —
Dashboard, Usage, People, Config, Checkpoints, Access, Affiliates, Key
Overrides, Tools — through query-command dispatch: scraper refresh via
GitHub Actions dispatch (`?refresh=`) or direct reload (`?reload=&table=&tag=`),
log download or redirect to the CI log (`?logs=`), and a `?reboot=` family
that is really a generic run-then-redirect dispatch, not all of it a literal
reboot: `datastore`/`datastore-backup` (`StartDatastoreReload`), `update`
(git pull + `go build` + process exit), `build`/`code` (either step alone,
no restart), `config` (reload config plus the ACL/grants/affiliates that
ride beside it), `checkpoints` (chart checkpoints), `snapshot` (stash into
timeseries), `tcgcsv` (TCGCSV price ingestion), `server` (process exit
only), `newKey`/`demokey` (API-key generation, `&user=&duration=`), and
`spoof` (signed tier-spoof URL for testing). Five JSON editors — config,
checkpoints, ACL/access table, affiliates, key overrides — the last backed
by a per-store UUID-remap builder reached from a "Fix" link on search
results (`search.go`/`search.html`). A People tab adds/removes Patreon
grants in place. The dashboard lists retail/buylist scraper freshness with
live 🔶 status from a `?workflows=` GitHub Actions poll, registered pages,
uptime, memory via `go-osstat`, and disk via the platform-specific
`internal/diskusage.Stats` — a no-op returning zero on Windows. The Usage
tab aggregates 30 days of `ObservabilityDB` telemetry, cached 5 minutes.

## 6. Support packages

| Package | Purpose |
|---|---|
| `timeseries/` | PostgreSQL price-history client (see §5.6) |
| `ratelimit/` | Per-IP token-bucket limiter wrapping `x/time/rate`; `IPAddress()` honors X-Forwarded-For |
| `patreon/` | Patreon OAuth2 token exchange + identity/membership tier lookup |
| `moxfield/` | Moxfield deck & paginated collection importer → `Item` list |
| `cardconduit/` | CardConduit bulk-estimate POST client |
| `banprice/` | Wire types for the price API — `Price`, `ConditionTags` — in the exact JSON shape `api_banprice.go` and the templates share |
| `collectr/` | Client for Collectr showcase pages (product listings, Magic + Lorcana categories) |
| `fuzzy/` | Levenshtein-distance string similarity powering "did you mean" suggestions |
| `observability/` | Postgres page-visit recorder backing the admin usage dashboard |
| `tcgcsv/` | Client for tcgcsv.com's category→group→product/price hierarchy, used to ingest non-Magic prices |
| `tcgcsvd/` | tcgcsv ingest service: library + `cmd/tcgcsvd` binary. Daily/products/backfill jobs take a cross-process Postgres advisory lock so a standalone process and the website's own crons never crawl tcgcsv.com at once (`tcgcsvd/README.md`) |
| `userstate/` | Postgres-backed cross-device sync of per-user favorites/recents/prefs (`/api/userstate/`), keyed by a hash of the login email |
| `cmd/` | Just `cmd/tcgcsvd/main.go` — a thin CLI over the `tcgcsvd` package (`-daily`/`-products`/`-backfill`/`-games`) |
| `internal/` | No longer empty — 14 packages: `dsreload` (single-flight datastore reload, remembers the outcome for late askers), `bucketstore` (atomic in-memory snapshot of a bucket JSON doc — key overrides, chart checkpoints), `access` (tier ACL table + Patreon grant list), `tmplparse` (indentation-stripping template parser used by all template loading, see §7), `docparse` (CSV/XLS/decklist row → matched card entry, used by `upload.go`), `offline` (offline-mode binary payload format, per-user watermarking, per-set fingerprints), `offlineapi` (serves the offline PWA data endpoints), `palette` (command-palette data endpoints + nav-target lists), `embed` (oEmbed link-unfurl panels + Discord embed field lists), `suggest` ("did you mean" hints for empty search results), `notify` (Discord webhook one-liners), `diskusage` (platform-specific disk stats, isolates build tags), `debounce` (shared burst-coalescing run loop for background refreshers), `tcgcatalog` (parses `tcgdumper`/go-tcgplayer catalog dumps) |

## 7. Frontend

- **Templates** (`templates/`): Go `html/template`, parsed via `internal/tmplparse.ParseFiles` (strips the authoring indentation before parsing — see §6). Desktop `base.html` / `base-landing.html` and `mobile/base-mobile.html`, with `templates/mobile/<page>.html` overrides for 7 of the 13 page templates (admin, home, news, offline, search, sets, sleep — the rest fall back to the desktop template on mobile). Partials (`templates/partials/`, included per-page by `renderTemplateFiles()`, not blanket-loaded): navbar, settings-modal + settings-stores-grouped, editions-picker, set-symbol, admin-usage, guide-faq, search-landing, sussy-price. 47 custom template funcs in `templates.go`'s `funcMap` (price formatting, affiliate links, UUID→store-ID lookups, game/rarity-badge dispatch for the multi-game skin, palette-target JSON). Production pre-parses every page×(mobile|desktop) combination at startup (`buildTemplateCache()`); dev mode re-parses per request. Base templates inject `__BAN_NAV` / `__BAN_PALETTE*` JSON globals for the client.
- **JS** (`js/`): all vanilla, no framework, no bundler — one vendored exception, `js/vendor/fflate.min.js` (gzip, used by the offline cache). Notable modules: `command-palette.js` (Cmd+K nav/search) plus its `palette-chips.js` (chip-based input) and `palette-providers.js` (prefix-driven candidate providers) helpers; `settings.js` (cookie-backed settings registry with dirty-state confirmation — the formerly separate `settings-modal.js`/`settings-search.js` are gone, folded in); `confirm-dialog.js` (in-page replacement for `window.confirm`); `autocomplete.js`, `favorites.js` and `recent-searches.js` (localStorage); `user-state.js` (best-effort cross-device sync of favorites/recents/prefs for signed-in users, against `/api/userstate/`); `chartopts.js` (Chart.js v4 plugins: crosshair, gradients, HTML tooltips, checkpoint markers); `nightmode.js` theme toggle. `js/offline/` (16 files) plus a root `sw.js` service worker implement an installable offline mode (IndexedDB price cache, background sync, offline-first `/offline` shell). CDN libs: Chart.js v4 (+ date-fns adapter, annotation plugin), Lucide icons, Tablesort, Keyrune.
- **CSS** (`css/`): custom design system in `main.css` (+ a generic `mobile.css` override pass) via CSS variables (light/dark themes by body class, layered surfaces, type scale, tier colors); one stylesheet per feature page plus 5 `*-mobile.css` overrides, plus `command-palette.css`, `settings-modal.css`, `offline.css`, and two embedded webfonts (`phyrexian.woff2`, `quenya.woff2`).
- **State**: user preferences live in cookies (read server-side by handlers too — e.g. store blocklists, optimizer settings) and localStorage (favorites/recents/layout); signed-in users additionally get a best-effort Postgres sync of favorites/recents/prefs via `userstate/` + `js/user-state.js`.

## 8. Development & operations

- **Config variants**: one config file per deployment, selected via `Config.Game`
  (magic is the default; lorcana, onepiece, yugioh, riftbound, fleshandblood,
  and pokemon are also live, each with its own `.github/workflows/<game>-deploy.yml`;
  gundam and palworld have matcher/badge/card-back support but no deploy
  workflow yet — see AGENTS.md). All `*.json` files, including every
  `config*.json`, are gitignored — the copies in a local checkout are stripped
  dev config, not production; real per-deployment config is pulled from the
  config bucket, so don't infer live behavior from a local file.
- **Commit convention**: lowercase area prefix — `search:`, `upload:`,
  `api/banprice:`, `fix(mobile):` — small focused commits, no `Co-Authored-By`
  trailer.
- **Testing**: broad and per-feature, not thin — 82 `*_test.go` files in the
  root package as of this writing (`ls *_test.go`), organized by subsystem
  rather than one-per-source-file: search/searchfilter (query parser, sort
  orders, sealed/number-index edge cases), upload (parsers, unpack, magic
  export/CSV), arbit (best-of, language handling, suspicious-spread
  heuristics), charts (axis, buttons, resolve/search-by-id), admin (ajax,
  datastore, table-sort, usage), games-coverage/game-badge/game-body (every
  game the matcher registers needs a badge and a template — checked in one
  place), set-symbol, mobile variants, redirects, news, common ACL/affiliates,
  plus five dedicated `*_bench_test.go` files (auth, datastore, price-parity,
  searchfilter, sort). A separate `tests/offline/` tree holds ~14 Bun/JS tests
  for the offline/service-worker mode. All Go tests need the local
  `allprintings5.json` datastore (AGENTS.md). CI (`.github/workflows/ci.yml`)
  runs on every PR and push to master: a `style` job (`gofmt -s -l .`,
  `go vet ./...`, `revive` pinned to v1.13.0, `staticcheck` pinned to
  2025.1.1) and a `build-and-test` job (`bun test tests/`, `go build ./...`,
  `go test ./...` against a downloaded `allprintings5.json`).
- **Deployment**: single binary behind a reverse proxy; admin `?reboot=update`
  runs `git fetch` + `git reset --hard origin/master`, then `go build`, then
  `os.Exit(0)` (`pullCode()`/`build()` in admin.go — systemd restarts the
  process). `update-mtgban.sh` is unrelated to this path: it's a local-dev
  helper that repoints the `go-mtgban` module dependency at a local checkout,
  the latest commit, or back to `go.mod`'s pinned version (`local`/`latest`/
  `remote` args) — not part of deploying the site. Logs rotate per page under
  `logs/` (500 KB × 3 via `leemcloughlin/logfile`), downloadable from admin
  via `?logs=`. Discord webhooks act as the alerting channel. `/healthz` for
  liveness.
- **Patch-based workflow**: work still being sequenced is sometimes staged as
  `git format-patch` files in the repo root before merging rather than pushed
  straight to a branch. This list is point-in-time — run `ls *.patch` for
  what's actually pending rather than trusting an enumeration here; the set
  this doc listed a few weeks ago is gone entirely. As of this writing there
  are two: `0001-charts-stash-non-Magic-snapshots-through-the-long-fo.patch`
  ("charts: stash non-Magic snapshots through the long form" — makes the
  timeseries long-form dual-write game-aware, since non-Magic card ids like
  Lorcana's aren't Postgres `uuid`s and were silently failing the wide-table
  batch upsert) and `0001-upload-parse-rows-in-parallel.patch` ("upload: parse
  rows in parallel" — fans `ParseRow()` out across a `GOMAXPROCS`-bounded
  semaphore; ~4.7x measured on name-based rows, 37.7→176 rows/s). Otherwise
  the working tree is clean — no other uncommitted or in-flight change as of
  this writing.

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

