# AGENTS.md

Guidance for AI coding agents working in this repository. Humans may also find
it a useful quickstart. A fuller architecture doc, `SPECIFICATION.md`, is
committed alongside this file, in the same doc-refresh pass — read it for
detail this file only summarizes.

## What this is

MTGBAN is a card price-aggregation website — Magic first, and now also
Lorcana, One Piece, Yu-Gi-Oh, Riftbound, Flesh and Blood, Pokemon, Gundam and
Palworld, each its own deployment of the same binary switched by `Config.Game`
— a single Go server binary (most of it one flat root `package main`) plus
small support packages, server-rendered Go HTML templates, and
vanilla JS/CSS (no frontend build step). It loads card data and per-store
price dumps into memory and serves search, bulk-upload valuation, arbitrage,
newspaper reports, price charts, a signed price API, and a Discord bot.

The card database and scraper abstractions come from the sibling module
`github.com/mtgban/go-mtgban` (`mtgmatcher` = card identity/lookup; `mtgban` =
`Seller`/`Vendor` interfaces and `InventoryRecord`/`BuylistRecord` price maps).

## Build, run, test

```bash
go build ./...                 # compile everything
go vet ./...                   # vet before sending changes
go test ./...                  # run tests (needs allprintings5.json present)
go build -o mtgban-website .   # build the server binary (gitignored)

# Run locally in dev mode (hot-reload templates, relaxed auth):
./mtgban-website -dev -cfg config.json

# The same, loading one store's dumps from the bucket rather than every one:
./mtgban-website -dev -cfg config.json -stores cardkingdom

# Or from a local copy laid out like the bucket, with no B2 key; -stores
# narrows it the same way. A symlink os.Root won't follow (absolute, or
# leaving the directory) fails the listing at startup.
b2 sync b2://mtgban-dumps/magic/cardkingdom/ ~/mtgban-dumps/magic/cardkingdom/
./mtgban-website -dev -cfg config.json -dumps ~/mtgban-dumps

# Useful flags (defined in main(), main.go): -port, -ds <datastore.json.xz>,
# -acl / -grants (override those table paths), -dumps <dir> (read the dumps
# from a local directory), -noload (skip price load), -stores a,b (load
# only those stores' dumps at startup), -nonews, -sig (force signature
# checks in dev), -log <dir>.
# Also: -tcgcsv-daily / -tcgcsv-products / -tcgcsv-backfill (with
# -tcgcsv-from/-to/-force/-categories) run one ingest job and exit rather
# than serving; tcgcsvd/README.md covers the jobs and cmd/tcgcsvd, which
# runs them as a process of its own.
```

Switching the `go-mtgban` dependency during local work:

```bash
./update-mtgban.sh local    # go mod replace -> ../go-mtgban (local checkout)
./update-mtgban.sh remote   # drop the replace directive
./update-mtgban.sh latest   # bump to latest go-mtgban commit
```

There is no Makefile, but `.github/workflows/ci.yml` runs on every PR and on
push to `master`: a `style` job (`gofmt -s -l .`, `go vet ./...`, `revive`,
`staticcheck`), and alongside it `build-and-test` (`bun test tests/`, `go build ./...`,
`go test ./...` against a real downloaded `allprintings5.json`). Match those
same gates locally before pushing — `gofmt -s -l .` and the pinned `revive`/
`staticcheck` versions in particular are easy to miss running only `go vet`.

This file does not track current pass/fail status — that goes stale the
moment it's wrong. Run the build and test commands yourself and trust their
output, not a claim written here.

## Configuration & secrets

- Config files (`config.json`, `config-beta.json`, `config-lite.json`,
  `config-lorcana.json`) and all `*.json` are **gitignored** except the
  exemptions listed in `.gitignore` — do not commit them, and do not commit
  `client_secret.json` / `google_client_secret.json`. Verify with
  `git status` before any commit.
- `BAN_SECRET` (env var) keys the HMAC signing; `BAN_CONFIG_PATH` sets the
  default config path.
- Config schema is `ConfigType` in `main.go` (`grep -n "type ConfigType" main.go`
  for the current line, it moves): scraper config (`icons`, `name_override`
  and `stores`), Patreon OAuth, ACL (tier → page → flags), affiliates, DB
  addresses, B2 bucket credentials. The store list comes from listing
  bantool's dumps at startup (`load.go`'s `loadScrapersNG`/`listDumps`),
  which live in bucket `mtgban-dumps` (or a local copy, with `-dumps`) as
  `<game>/<store>/<kind>/<shorthand>.json.xz` and are read with the
  `bucket_keys["mtgban-dumps"]` key pair. `scraper_config.stores`, or
  `-stores` for one run, narrows what loads at startup to the stores
  named; empty loads every store listed. See SPECIFICATION.md §2.3.

## Repository conventions

- **Commit messages**: lowercase area prefix + imperative summary, e.g.
  `upload: scope CSV exports to the active result tab`, `search: add the
  custom buylist to search results`, `api/banprice: simplify function
  signature`, `fix(mobile): switch to full-screen edition picker`. Keep commits
  small and focused.
- **Keep the subject short, case by case, and the body to a few lines**,
  wrapped at 72: the why and the number that proves it. Longer write-ups
  go in `docs/`, committed with the change, and the body points at them.
  Comments stay two or three lines the same way.
- **A doc names a measurement's window relative to the run** ("the last 12
  months of CK snapshots"), not as calendar dates, and its tables of
  measured numbers come from the script that measured them rather than
  being copied into the prose. Written-in dates drift apart between
  sections, and they read as choices when nobody chose them.
- **Do NOT add a `Co-Authored-By` trailer** to commits.
- Match the surrounding code's style; this is plain idiomatic Go with a flat
  root package — most features live in one top-level file each.
- Don't commit binaries, datastores (`*.json.xz`, `allprintings5.json`),
  `dump.rdb`, `.orig`/`.rej` artifacts, or `logs/`.
- **No `reflect`**, tests included; CI's revive rejects the import. Compare
  with `slices`/`maps`, or a comparison written for the type:
  `docs/adr/0002-no-reflect.md` has why and how.
- **Page scripts go in `js/`, not inline in templates.** Load a page's
  script with a `src` tag where its code runs, and hand it template values
  through a small `window.BAN_*` object set by an inline script just
  before the tag (`BAN_SEARCH_RESULT`, `BAN_SEARCH_CHART` in
  `search.html`). A file in `js/` is cached between pages, bun can test it
  without regexing it out of a template, and CodeQL scans it, which it
  does not do for templates. Keep inline only what has to run before
  anything loads (the theme guard in `base.html`) or a few lines of glue.

## Where things live (root package)

| File | Responsibility |
|---|---|
| `main.go` | Startup, flags, config, `NavElem` page registry, cron jobs |
| `routes.go` | `registerRoutes`: static files, redirects, the `NavElem` pages and the APIs, each behind its signing middleware |
| `pages.go` | `PageVars`, the per-request nav (`genPageNav`), the template cache and `render` |
| `site.go` | The `site` value page handlers, crons and Discord callbacks hang off, as methods; owns the live datastore (`ds`), the palette and offline services, the datastore loader (`loadDatastore`, `newDatastore`) and the reload tracker (`reloads`, `startDatastoreReload`) |
| `datastore.go` | The `datastore` value: one load's backend and the snapshots built from it (numbers in `search_numbers.go`, editions in `product.go`, names in `internal/suggest`, palette lists in `internal/palette`), published together |
| `templates.go` | The template `FuncMap` — the helper funcs templates call by name |
| `load.go` | Scraper loading from B2; atomic seller/vendor snapshot swapping |
| `auth.go` | Patreon OAuth, HMAC signature sign/verify, the 3 middleware wrappers |
| `search.go`, `searchfilter.go` | Search execution and the query-language parser/filters |
| `upload.go` | Bulk-upload parsing (CSV/XLS/XLSX/Sheets/Moxfield/TCG) + optimizer |
| `arbit.go`, `sleep.go` | Arbitrage (arbit/global/reverse) and sleeper scoring |
| `news.go` | Newspaper reports (SQL-backed), plus `gameMap`/`gameBadgeMap` — every deployable game has to be named there, or its newspaper stays empty and each refresh logs an error |
| `product.go`, `chart.go`, `chart_resolve.go`, `checkpoints.go`, `banlist.go` | Sealed EV; price charts and the ids they accept; chart annotations, ban-list markers among them |
| `ckbuylist.go`, `ckodds.go` | Card Kingdom buylist signals on search and the odds their tooltips quote (`docs/adr/0004-ck-buylist-signals.md`) |
| `tcglistings.go` | TCGplayer seller and copy counts per grade, from the newspaper's nightly listings scrape |
| `alerts_*.go` | Price alerts: the Alerts page, the ACL values and login contact it reads, and the site's wiring of `internal/alerts` (`docs/adr/0005-price-alerts.md`) |
| `screener.go`, `popular.go`, `guide.go`, `changelog.go` | The price-movers screener; the landing page's featured searches; the guide; release notes read from Discord |
| `api*.go` | Price API, batch prices, chart/suggest/userstate APIs, CSV exports |
| `admin.go`, `discord.go` | Admin panel + commands; Discord bot |
| `common.go`, `access_notify.go`, `buckets.go` | The access table, grants and affiliates shared across deployments and the Postgres NOTIFY that reloads them; per-bucket B2 keys |
| `overrides.go`, `session_store.go` | Admin fixes: per-store uuid remaps, and stores published from an upload |
| `jobs.go`, `staleness.go`, `recover.go`, `telemetry.go` | Background-job registry and health, the stale-data alarm, panic recovery and reporting, page-visit recording |
| `upload_handoff.go`, `tcgcsv_service.go` | The page other sites hand a card list to; the tcgcsv ingest wired into the site |
| `api_plans.go`, `api_handoff.go` | The public API pricing page and configurator (`/api-plans`, renders `apiproductlist`), and the Patreon handoff redirects to the gateway (`/api-trial`, `/api-login`) |
| `utils.go`, `redirect.go`, `mobile.go` | Helpers (including the non-Magic rarity-badge `colorRarityMap` — see `img/setsymbol/README.md`), affiliate redirects, mobile toggle |
| `timeseries/` | PostgreSQL price-history client (charts) |
| `userstate/`, `observability/` | Postgres stores for per-user preferences and for page visits (the admin usage tab) |
| `banprice/` | The price API's wire types |
| `tcgcsv/` | tcgcsv.com client that `tcgcsvd/` ingests through |
| `tcgcsvd/` | Non-Magic price/catalog ingest from tcgcsv.com — see its own README |
| `apisig/` | Holds the API signature format (`Sign`, `Payload`, `Mint`, `Decode`, `Verify`); the API gateway repo imports it, so its payload bytes are frozen by golden tests |
| `apihandoff/` | The signed Patreon handoff token (`Mint`, `Verify`) the game sites hand to the API gateway for trials and sign-in; the gateway imports it, so the golden test freezes its bytes |
| `apiproductlist/` | The API price list (`products.json`, embedded; amounts in cents): packages, add-ons, intervals, store families. The API gateway repo pins this module by commit and seeds Stripe from it, so a price edit needs a gateway dependency bump; the pricing page renders from it |
| `ratelimit/`, `patreon/`, `moxfield/`, `manabox/`, `collectr/`, `cardconduit/`, `fuzzy/` | Support packages |
| `internal/` | Packages only this module imports: the palette and offline APIs, suggest, upload row parsing, the reload tracker and more; SPECIFICATION.md §6 lists them |

## Non-Magic games

One binary, switched by `Config.Game` in the config file: each of `lorcana`,
`onepiece`, `yugioh`, `riftbound`, `fleshandblood`, `pokemon`, `gundam` and
`palworld` (alongside the default, `magic`) is its own deployment — its own
`Seller`/`Vendor` set, its own card database, its own set of pages the ACL
allows. `gameMap`/`gameBadgeMap` (`news.go`) name every game a deployment can
be; a game the matcher registers that `gameMap` lacks still builds, but its
newspaper stays empty and each refresh logs an error. `gameMap`'s names
are TCGplayer's `productLineName`s, spelled exactly (Palworld's is `Palworld
OFFICIAL CARD GAME`), because the newspaper stores `game_name` that way and
the pages match it with `=`: keep them in step with MTGBan_Newspaper's
`games.py`.

Rarity badges (the colour and, for a few games, a drawn shape standing in for
Magic's keyrune glyph) are a separate system with its own recipe and its own
per-game history: `img/setsymbol/README.md`. Read it before touching
`colorRarityMap` or adding a ninth game.

`gundam` and `palworld` have their badges, card backs, and deploy workflow
all set up as of 2026-09-15 — see below — but neither has a DigitalOcean App
Platform app or its `DO_<GAME>_APP_ID`/`DO_API_TOKEN` secret provisioned
yet, which is not something committing code can do. Pushing a
`gundam-*`/`palworld-*` tag before that exists just fails the workflow's
`doctl apps create-deployment` step with an unknown-app error. (An earlier
version of this file also claimed `go.mod`'s go-mtgban pin predated the
commit that added their `mtgmatcher` packages — checked directly and that
was wrong: both were already registered at the pinned `v0.8.3`, games.go
blank-imports included, so no dependency bump was ever needed for this.)

### Deploying a new game

Two deploy patterns exist, chosen by how big the card pool is:

- **DigitalOcean App Platform** (`lorcana`, `onepiece`, `fleshandblood`,
  `riftbound`, `gundam`, `palworld`, plus `beta`) — a `.github/workflows/
  <game>-deploy.yml` that does nothing but `doctl apps create-deployment
  ${{ secrets.DO_<GAME>_APP_ID }} --wait` on a `v*`/`<game>-*` tag push
  (`beta-*` alone for beta), or `workflow_dispatch`. All the actual build/deploy config lives in that
  DigitalOcean App's own spec, not in this repo. This is the one to copy for
  a small non-Magic game's card pool.
- **Droplet over SSH** (`magic`, `pokemon`, `yugioh`) — the workflow SSHes
  into that game's own droplet and runs `deploy/deploy.sh <ref>`, a
  blue-green swap between two instances behind nginx, which does its own
  checkout and build. Reserved for the largest card pools; a new non-Magic
  game almost certainly wants the App Platform pattern instead.

Every deploy workflow first calls `.github/workflows/ci-passed.yml`, which
fails unless `ci.yml` passed on the commit being deployed (waiting for a run
still in progress), so a new game's workflow starts with the same `ci` job
and the same `skip_ci` input, which lets a manual run deploy regardless.

Either way, code alone doesn't finish the job: the App Platform app (or the
droplet slot) and its secret(s) have to be provisioned by someone with
DigitalOcean/infra access before the workflow's first real run — a step no
commit to this repo can complete on its own.

## Critical invariants — do not break these

1. **Atomic-pointer snapshots.** Sellers/vendors and other hot caches are held
   in `atomic.Pointer` and read via `GetSellers()`/`GetVendors()`. Never mutate
   a returned slice/map in place. To change data, build a new value and publish
   it through the existing `updateSellers()`/`updateVendors()` (which also
   validate that the dataset hasn't regressed) — keep that validation. The
   card datastore follows the same pattern one level up: `site` (site.go)
   owns it in `ds atomic.Pointer[datastore]`, pre-stored empty by `newSite()`
   so `s.datastore()`/`s.backend()` are never nil; code below an entry point
   reads the datastore only through the `b`/`ds` it was handed, never from
   the site (the nav's `ShouldHide` visibility check aside). The rules and
   why: `docs/adr/0003-explicit-backend.md`. The config is the same again:
   `Config()` returns the live one from `liveConfig`, read-only; a load, an
   editor save or a new API key builds a new value and publishes it whole
   (`finishConfig`, `generateAPIKey`). Never write into `Config()` outside
   tests.

2. **Stateless auth.** Permissions live entirely in the signed `MTGBAN`
   cookie / `?sig=` (an HMAC-signed query string). There is no session store
   or user DB. Read grants via `GetParamFromSig()`; don't introduce server-side
   session state. The Patreon email is an identity outside the site only once
   Patreon has confirmed it; where that is recorded, where it is enforced, and
   why a new signed field must not ride on every login:
   `docs/adr/0001-api-handoff-email-check.md`.

3. **Card identity goes through `mtgmatcher`.** Resolve cards through the
   `*mtgmatcher.Backend` a function was handed (`b.Match`, `b.GetUUID`,
   `b.MatchID`) — don't hand-roll UUID or set/number/finish parsing.

4. **Page registration is declarative.** Add a page by adding a `NavElem` (its
   route, handler, template, `CanPOST`, access flags) — this wires routing,
   auth, navbar, and logging together. Don't register routes ad hoc. Handlers
   are methods on `*site` (site.go); `Handle` takes a method expression
   (`Handle: (*site).NewPage`) and `ShouldHide func(*site) bool` reads the
   site's current datastore for visibility only — both are built once in
   `init()`, before any `*site` exists, and bound to one at registration.

5. **Templates**: production pre-parses every page in `buildTemplateCache()`;
   a new template/partial must be wired into the cache. Use `-dev` for
   per-request hot reload while iterating.

6. **Concurrency**: handlers run concurrently and read shared globals
   (`Config()`, DB handles, atomic snapshots). Don't add unsynchronized mutable
   package state.

7. **New background work recovers its own panics.** net/http recovers a
   panic only on the goroutine serving the request (`recoverPanic` reports
   it there, behind the three signing wrappers); on any other goroutine an
   unrecovered panic ends the process. So register a new cron job through
   `addJob` (main.go) and start a new background job's goroutine with
   `tracked(name, fn)`, both of which also list it on the admin dashboard
   (`jobs.go`); start any other goroutine or Discord handler with
   `defer recoverJob("<name>")` (recover.go), and have a loop that must
   keep serving recover each run in a function of its own, as
   `runAccessReload` does, not the loop around it. A request's fan-out
   workers defer it too, so a panic costs only that worker's share of the
   answer. Among the goroutines that do not recover: two startup ones,
   fatal on purpose (the scraper goroutine in `main()`, with the
   `runSealedAnalysis()`, `warmVariantCacheIfEnabled()` and
   `RefreshManifest()` it runs, and the one running `ListenAndServe`).

## Known issues / refactors pending

`todo/refactor.md` holds the measured, prioritized tech-debt list and the
plan for it. Read it there; this file does not copy it, since a copy goes
stale the moment an item lands.

## Gotchas

- `TestMain` loads `allprintings5.json` from the repo root; without it the
  tests that need card data skip (most through `skipWithoutDatastore`), so
  a green run proves less. `MTGBAN_TEST_DATASTORE=off` skips the load (7 s,
  3 GB) on purpose, for quick fixture runs, `-race` included.
- Static assets are served from disk (not embedded) with `?hash=<git commit>`
  cache-busting; bumping assets relies on a rebuild changing the hash.
- Mobile has separate templates under `templates/mobile/` and `*-mobile.css`;
  a UI change often needs both desktop and mobile variants.
- The search page's two columns (fixed sidebar + sticky result headers) have
  a set of offsets and degradation rules that read as arbitrary and are not:
  `docs/search-column-layout.md` has the reasoning, and
  `tests/offline/search-sticky-offsets.test.js` pins the parts a browserless
  test can reach.
- The API gateway (`mtgban/api-gatewahy`) imports six packages from this
  module: `apisig`, `apihandoff`, `apiproductlist`, `observability`,
  `ratelimit` and `timeseries`. A change to any of them is a change to the
  gateway too; `docs/api-gateway-dependency.md` has why the dependency points
  this way and which side deploys first.
- `embed.go` is Discord **embed** formatting, not Go `//go:embed` asset
  embedding — don't be misled by the name.
- **Template FuncMap risks:** `templates.go` adds about 60 template helpers
  via `template.FuncMap`. `templates_test.go` checks that every template
  parses and every reference resolves, not what each helper returns; only
  `csvWithout` has a table test of its own (`chart_test.go`). The rest
  (`firstCSV`, `slug`, ...) are pure functions that could be tested the
  same way.
