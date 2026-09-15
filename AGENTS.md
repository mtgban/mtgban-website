# AGENTS.md

Guidance for AI coding agents working in this repository. Humans may also find
it a useful quickstart. A fuller architecture doc, `SPECIFICATION.md`, is
committed alongside this file, in the same doc-refresh pass — read it for
detail this file only summarizes.

## What this is

MTGBAN is a card price-aggregation website — Magic first, and now also
Lorcana, One Piece, Yu-Gi-Oh, Riftbound, Flesh and Blood, Pokemon, Gundam and
Palworld, each its own deployment of the same binary switched by `Config.Game`
— a single Go server binary (~25k lines in the root `package main`, excluding
tests) plus small support packages, server-rendered Go HTML templates, and
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

# Useful flags (defined in main(), main.go): -port, -ds <datastore.json.xz>,
# -acl / -grants (override those table paths), -noload (skip price load),
# -nonews, -sig (force signature checks in dev), -log <dir>.
# Also: -tcgcsv-daily / -tcgcsv-products / -tcgcsv-backfill (see
# tcgcsvd/README.md) run one ingest job and exit rather than serving.
```

Switching the `go-mtgban` dependency during local work:

```bash
./update-mtgban.sh local    # go mod replace -> ../go-mtgban (local checkout)
./update-mtgban.sh remote   # drop the replace directive
./update-mtgban.sh latest   # bump to latest go-mtgban commit
```

There is no Makefile, but `.github/workflows/ci.yml` runs on every PR and on
push to `master`: a `style` job (`gofmt -s -l .`, `go vet ./...`, `revive`,
`staticcheck`), then `build-and-test` (`bun test tests/`, `go build ./...`,
`go test ./...` against a real downloaded `allprintings5.json`). Match those
same gates locally before pushing — `gofmt -s -l .` and the pinned `revive`/
`staticcheck` versions in particular are easy to miss running only `go vet`.

This file does not track current pass/fail status — that goes stale the
moment it's wrong. Run the build and test commands yourself and trust their
output, not a claim written here.

## Configuration & secrets

- Config files (`config.json`, `config-beta.json`, `config-lite.json`,
  `config-lorcana.json`) and all `*.json` are **gitignored** — do not commit
  them, and do not commit `client_secret.json` / `google_client_secret.json`.
  Verify with `git status` before any commit.
- `BAN_SECRET` (env var) keys the HMAC signing; `BAN_CONFIG_PATH` sets the
  default config path.
- Config schema is `ConfigType` in `main.go` (`grep -n "type ConfigType" main.go`
  for the current line — it moves): scraper config, Patreon OAuth, ACL (tier →
  page → flags), affiliates, DB addresses, B2 bucket credentials.

## Repository conventions

- **Commit messages**: lowercase area prefix + imperative summary, e.g.
  `upload: scope CSV exports to the active result tab`, `search: add the
  custom buylist to search results`, `api/banprice: simplify function
  signature`, `fix(mobile): switch to full-screen edition picker`. Keep commits
  small and focused.
- **Do NOT add a `Co-Authored-By` trailer** to commits.
- Match the surrounding code's style; this is plain idiomatic Go with a flat
  root package — most features live in one top-level file each.
- Don't commit binaries, datastores (`*.json.xz`, `allprintings5.json`),
  `dump.rdb`, `.orig`/`.rej` artifacts, or `logs/`.

## Where things live (root package)

| File | Responsibility |
|---|---|
| `main.go` | Startup, flags, config, routing, `NavElem` page registry, `PageVars`, template cache, cron jobs |
| `templates.go` | The template `FuncMap` — pure helper funcs templates call by name |
| `load.go` | Scraper loading from B2; atomic seller/vendor snapshot swapping |
| `auth.go` | Patreon OAuth, HMAC signature sign/verify, the 3 middleware wrappers |
| `search.go`, `searchfilter.go` | Search execution and the query-language parser/filters |
| `upload.go` | Bulk-upload parsing (CSV/XLS/XLSX/Sheets/Moxfield/TCG) + optimizer |
| `arbit.go`, `sleep.go` | Arbitrage (arbit/global/reverse) and sleeper scoring |
| `news.go` | Newspaper reports (SQL-backed), plus `gameMap`/`gameBadgeMap` — every deployable game has to be named there or the newspaper cache panics at startup |
| `product.go`, `chart.go`, `checkpoints.go` | Sealed EV, price charts, chart annotations |
| `api*.go` | Price API, batch prices, chart/suggest APIs, CSV exports, API-mode loading |
| `admin.go`, `discord.go` | Admin panel + commands; Discord bot |
| `utils.go`, `redirect.go`, `mobile.go`, `palette.go` | Helpers (including the non-Magic rarity-badge `colorRarityMap` — see `img/setsymbol/README.md`), affiliate redirects, mobile toggle, palette metadata APIs |
| `timeseries/` | PostgreSQL price-history client (charts) |
| `tcgcsvd/` | Non-Magic price/catalog ingest from tcgcsv.com — see its own README |
| `apisig/` | Holds the API signature format (`Sign`, `Payload`, `Mint`, `Decode`, `Verify`); imported by the API gateway repo, so its payload bytes are frozen by golden tests |
| `ratelimit/`, `patreon/`, `moxfield/`, `cardconduit/` | Support packages |

## Non-Magic games

One binary, switched by `Config.Game` in the config file: each of `lorcana`,
`onepiece`, `yugioh`, `riftbound`, `fleshandblood`, `pokemon`, `gundam` and
`palworld` (alongside the default, `magic`) is its own deployment — its own
`Seller`/`Vendor` set, its own card database, its own set of pages the ACL
allows. `gameMap`/`gameBadgeMap` (`news.go`) name every game a deployment can
be; a game the matcher registers but that isn't in those two maps panics the
newspaper cache at startup rather than failing to compile.

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
  ${{ secrets.DO_<GAME>_APP_ID }} --wait` on a `v*`/`<game>-*` tag push (or
  `workflow_dispatch`). All the actual build/deploy config lives in that
  DigitalOcean App's own spec, not in this repo. This is the one to copy for
  a small non-Magic game's card pool.
- **Droplet over SSH** (`magic`, `pokemon`, `yugioh`) — the workflow SSHes
  into a shared droplet and runs `deploy/deploy.sh <ref>`, which does its own
  checkout and build. Reserved for the largest card pools; a new non-Magic
  game almost certainly wants the App Platform pattern instead.

Either way, code alone doesn't finish the job: the App Platform app (or the
droplet slot) and its secret(s) have to be provisioned by someone with
DigitalOcean/infra access before the workflow's first real run — a step no
commit to this repo can complete on its own.

## Critical invariants — do not break these

1. **Atomic-pointer snapshots.** Sellers/vendors and other hot caches are held
   in `atomic.Pointer` and read via `GetSellers()`/`GetVendors()`. Never mutate
   a returned slice/map in place. To change data, build a new value and publish
   it through the existing `updateSellers()`/`updateVendors()` (which also
   validate that the dataset hasn't regressed) — keep that validation.

2. **Stateless auth.** Permissions live entirely in the signed `MTGBAN`
   cookie / `?sig=` (an HMAC-signed query string). There is no session store
   or user DB. Read grants via `GetParamFromSig()`; don't introduce server-side
   session state.

3. **Card identity goes through `mtgmatcher`.** Resolve cards via
   `mtgmatcher.Match()`/`GetUUID()`/`MatchId()` — don't hand-roll UUID or
   set/number/finish parsing.

4. **Page registration is declarative.** Add a page by adding a `NavElem` (its
   route, handler, template, `CanPOST`, access flags) — this wires routing,
   auth, navbar, and logging together. Don't register routes ad hoc.

5. **Templates**: production pre-parses every page in `buildTemplateCache()`;
   a new template/partial must be wired into the cache. Use `-dev` for
   per-request hot reload while iterating.

6. **Concurrency**: handlers run concurrently and read shared globals
   (`Config`, DB handles, atomic snapshots). Don't add unsynchronized mutable
   package state.

## Known issues / refactors pending

`todo/refactor.md` has the full prioritized plan, but it's a local, untracked
planning doc — not every clone of this repo will have it. Highlights, spot-
checked against the current tree rather than copied wholesale:

- **Phase 0** (done): tests compile, `filterEnabledStores` removed.
- **Phase 1** (high ROI, behavior-preserving): extract shared helpers. Done so
  far: `canAccessMode(modes, target)` is now one helper (`utils.go`), called
  from `api.go`/`api_banprice.go` rather than duplicated; `MaxUploadEntries`
  and `IQRThreshold` are already named constants; the FuncMap already moved
  to its own `templates.go`. Still open, last verified 2026-09-14:
  - `ParamParser` for cookie/sig/form reads (duplicated across upload.go, search.go)
  - `PartitionScrapersByMode` helper (4-way partition loop duplicated in upload.go, arbit.go, sleep.go)
  - Named constants for conditions & finish order (inline map repeated in upload.go + search.go)
  - Standardize JSON error responses (api*.go mix hand-built strings + json.NewEncoder)
  - Table-driven sort dispatch (58 inline `sort.Slice` blocks across the root package as of this check, not just arbit.go/search.go)
- **Phase 2** (decompose god-functions): split `Upload()`/`Search()`, consolidate CSV exporters, centralize external-ID resolution
- **Phase 3** (frontend consolidation): extract shared JS helpers, consolidate settings system, delete dead `js/nav.js`
- **Phase 4** (testing): add tests for auth logic, search parser, price aggregation, arbitrage math

Phases 2–4 above are copied from `todo/refactor.md` as of the same date and
were not independently re-verified — check that file directly if you have it,
rather than trusting this list indefinitely.

## Gotchas

- Tests load `allprintings5.json` from the repo root; without it,
  search/upload/product tests fail to set up. Keep that in mind before
  declaring tests "broken."
- Static assets are served from disk (not embedded) with `?hash=<git commit>`
  cache-busting; bumping assets relies on a rebuild changing the hash.
- Mobile has separate templates under `templates/mobile/` and `*-mobile.css`;
  a UI change often needs both desktop and mobile variants.
- `embed.go` is Discord **embed** formatting, not Go `//go:embed` asset
  embedding — don't be misled by the name.
- **Template FuncMap risks:** `templates.go` adds 30+ template helpers via
  `template.FuncMap`. `templates_test.go` exists but tests that every template
  parses and every reference resolves — it does not unit-test the individual
  helpers' logic (`csvWithout`, `firstCSV`, `slug`, ...). Those are pure
  functions that could be table-tested independently of page rendering; that
  gap is still open.
