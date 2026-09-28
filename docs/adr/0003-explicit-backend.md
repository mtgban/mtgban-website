# ADR-0003: Explicit backend

**Status:** Accepted
**Date:** 2026-09-28
**Deciders:** Vittorio Giovara
**Change:** PRs #655, #667, #674, #679 and #680

## Context

go-mtgban v0.9.0 dropped its package-level card datastore: `Match`,
`GetUUID` and the rest became methods on a `*mtgmatcher.Backend` that the
caller opens and holds. The site's port (4eeaae9a) put the global back on
this side, an `atomic.Pointer` read through `backend()`; when this work
started it had 240 calls in 25 files, reached by 195 functions. The numbers
index, editions lists, suggest names, palette lists and load time were each
published on their own, after the backend. That had three costs:

- **A unit of work could see two loads.** The Discord bot picked a uuid
  from one load and read its card from the next, so a reload in between
  would panic its goroutine. `searchAndFilter` read the global in 15
  places, and once per candidate card through `shouldSkipCardNG`.
- **A load arrived in pieces.** After a reload a reader could see the new
  backend with the previous load's indexes, or with none.
- **One site per process.** Every function reached the same global.

## Decision

The site owns the datastore, and code below an entry point is handed it.
Every change is reviewed against seven rules:

1. **One owner, one writer.** `site.ds` (site.go) is the only live
   datastore. `newSite` pre-stores an empty one; after that only
   `loadDatastore` stores, single-flight through `internal/dsreload`, the
   startup load included.
2. **Read once per unit of work, where it starts.** A handler, cron run,
   Discord message or background job reads `s.datastore()` or `s.backend()`
   once and passes the result down. Startup code (`main`, `init`, `newSite`,
   `setupDiscord`, `buildTemplateCache`) never reads: it runs before the
   load, so it would keep the empty datastore forever.
3. **Pass the narrowest thing.** A function that only matches cards takes
   `b *mtgmatcher.Backend` first, after a `ctx`; one that reads a derived
   snapshot takes `ds *datastore`. Neither goes into `SearchConfig`,
   `PageVars` or any other data struct.
4. **Read-only.** A published backend is shared by every goroutine, and
   accessors such as `GetUUIDs`, `GetAllSets` and `SearchEquals` return its
   own slices: never assign into one, sort it in place or `append` to it;
   `slices.Clone` first.
5. **Don't pin.** Only the owner keeps a `*datastore` or a
   `*mtgmatcher.Backend` past a unit of work. State derived from a backend
   lives in the `datastore`, or remembers its source through a
   `weak.Pointer`, as `internal/mkmidparser` does for its sellers.
6. **Never nil.** Before the first load the site serves the empty
   datastore, so a function handed `b` or `ds` may assume it is not nil.
7. **Templates read no datastore.** See below.

A load is one value, `datastore` (datastore.go): the backend, the numbers,
names, editions and palette snapshots built from it, and its load time.
`newDatastore` builds every snapshot from the `b` it is handed before
anything is published, and `loadDatastore` publishes them in one `Store`.
Until the first load, the empty datastore's nil numbers, names and palette
make an exact-number search scan, `/api/suggest` answer 204 and the palette
lists no-store.

Page handlers are methods on `*site`, and so are the crons that read the
datastore, the Discord message handler and the tcgcsv report.
`NavElem.Handle` holds a method expression (`(*site).Search`), so the page
registry stays static data built in `init()`, bound to the site by `main()`.

### The one sanctioned second read: `ShouldHide`

The Sealed sub-page hides itself when the loaded backend has no sealed
product. Its `ShouldHide` reads `s.backend()` in `enforceSigning`, before
the handler runs, to refuse the URL, and again whenever `genPageNav` builds
the nav, to hide the tab. Nothing the page computes depends on it: a reload
in between can show, hide or refuse the Sealed page one request early or
late.

### Templates

html/template cannot `Clone` a template after it has executed, so the
cached templates cannot take a FuncMap bound to one request's datastore.
What a page needs from the datastore rides in its data, filled by the
handler from the snapshot it read: `EditionEntry.Symbol`,
`GenericCard.SetSymbol`, `PromoLabels` and `TCGId`, and
`PageVars.DatastoreReload`.

### Tests

`backend_test.go` keeps `backend()` and `currentDatastore()` for tests,
reading `testSite`, which `TestMain` loads once and never republishes; a
production function of either name fails `go vet` and `go test` (not
`go build`) as a duplicate declaration. A test that needs a load of its own
builds a private site, usually over `fixtureBackend`.
`MTGBAN_TEST_DATASTORE=off` skips the real load (7.4 s, 3.0 GB): the tests
that need real data then skip, `skipWithoutDatastore` being the standard
guard, and the root package runs in 3 s, or 31 s under `-race`.

## Options considered

- **A: Keep the atomic package global.** No signature changes.
  **Rejected:** it let a unit of work see two loads, and it allows one site
  per process.
- **B: Carry the backend in `SearchConfig` or `PageVars`.** Fewer
  signatures change. **Rejected:** a struct hides the dependency, pins the
  datastore for as long as it is kept, and hands it to the templates (rules
  3, 5 and 7).
- **C: Let templates read the site at render.** Adopted on 2026-09-26 as a
  per-site exception, **reversed** on 2026-09-27 after the #667 review: a
  reload between the handler's read and the render could make one page
  disagree with itself on a promo label or a TCG id.
- **D: A transitional guard test**, failing on any read of the site below
  an entry point. **Dropped:** it caught 1 of 5 planted violations, and
  once `backend()` left production code the compiler enforced the rule.
- **E: Build the numbers index inside go-mtgban's `Backend`.** The numbers
  snapshot is the one real index (50-58 ms to build). Built in `Open`
  beside go-mtgban's sealed index, it would let `searchAndFilter`,
  `searchFallback`, `getPopularSearches` and `parseMessage` take `b`; with
  `editionsForSearch` moved too, only the chart's checkpoints would still
  take `ds` below an entry point. **Deferred to the next go-mtgban bump:**
  it needs a release, and any release now carries go-mtgban's 80 commits
  past v0.9.2. Type-checked against its master (a3149a87f), this module has
  80 errors in 22 files, tests included, most from the newly typed
  `mtgban.Condition`. Every function still taking `ds` reads a derived
  snapshot, as rule 3 prescribes, so nothing is wrong meanwhile.

## Consequences

- A reload publishes whole, after building every snapshot: 160-185 ms on
  the real datastore, after an open that takes seconds.
- The palette, offline API, suggest and embed take the backend as given.
  `internal/docparse` and `internal/sessionstore` still turn a nil one into
  an empty one, which only their own tests pass.
- Two sites could now share a process, but more than the datastore still
  assumes one. Moving the rest is Phase D:
  - `Config`: some `Config.Game` readers already hold a `b` whose `Game`
    would do;
  - the scrapers (`sellersPtr`/`vendorsPtr`, `scrapersWriteMu`, load.go)
    and the session stores;
  - the caches built from prices (newspaper, reprints, infos, TCG catalog,
    screener, popular searches): plain values that pin nothing, but can lag
    a reload by one refresh;
  - `LogPages`, the database handles, the Discord session, cron
    registration, `ServerContext` and the screener's test seams;
  - the FuncMap's reads of scraper state (`uuid2ckid`, `tcg_market_price`,
    `is_sealed_scraper`, `scraper_name`, `invalid_direct`, `guide_stores`),
    which go into page data or a per-site FuncMap.

## Action items

1. [ ] Move the numbers index into go-mtgban's `Backend` with the next
   go-mtgban bump (option E), with `editionsForSearch` taking `b`.
2. [ ] Phase D: move the state above onto the site, then have `main()`
   build one site per deployment and route by host.
