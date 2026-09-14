# MTGBAN Website — Refactor Plan & Checklist

Synthesized from a full-codebase review (June 2026). Findings are grouped into
phases so each phase is shippable on its own. Every refactor below is intended
to be **behavior-preserving** unless explicitly marked otherwise. Effort key:
**S** = <½ day, **M** = ½–2 days, **L** = multi-day.

**Ground rule:** do not start the structural refactors (Phase 2+) until the
test suite compiles and runs (Phase 0, item 1) — you need a green baseline to
refactor against.

> **2026-09-14 spot check:** three months of work have landed since the June
> review. Items below marked **[DONE]** were directly confirmed against the
> current tree this pass (grep/read, not assumed) and should be dropped on the
> next edit. Everything else — including every `file.go:NNN` line-number
> citation — was *not* re-verified this pass; treat those numbers as
> approximate at best and re-grep before trusting one. Two items turned out
> flatly wrong regardless of line numbers (the patch-file list, and the
> "in-flight `EntryRule`" framing) and are corrected in place below.

---

## Phase 0 — Unblock & clean (do first)

Repo hygiene and the broken build baseline. Low risk, high leverage.

- [x] **[DONE] P0 — Fix the broken test build.** `go test ./...` compiles
  cleanly now. (`go test .` currently has 3 unrelated pre-existing *runtime*
  failures — `TestCardRedirectFollowsScryfallsShape` and two `cn:`
  collector-number cases — not a compile error, and not this item's concern.)
- [x] **[DONE] Delete junk from the working tree.** `dump.rdb`, `pngout.png`,
  `main.go.orig`, `main.go.rej`, `main.go.rej.orig` are all gone from the
  working tree as of this check. (The gitignored `mtgban-website` build
  binary and `AllPrintings.json.xz` datastore still exist locally, as
  expected — those regenerate on every build/test run and were never the
  "junk" this item meant.)
- [x] **[DONE] Resolve the `main.go.{orig,rej}` conflict artifacts.** Gone —
  see above.
- [ ] **Decide the fate of the loose patch files in the repo root.** The
  specific 6-patch list this item originally named (standalone stash
  service, sealed-analysis debounce, upload external-ID resolution, Firefox
  drag-drop fix, B2 concurrency OOM fix, default MarketCredit sort) is stale
  — none of those files exist any more. As of 2026-09-14 there are two
  different loose patches instead:
  `0001-charts-stash-non-Magic-snapshots-through-the-long-fo.patch`
  ("charts: stash non-Magic snapshots through the long form") and
  `0001-upload-parse-rows-in-parallel.patch` ("upload: parse rows in
  parallel"). Same instruction as before, just a different current list:
  for each, `git am` it onto a branch or drop it — don't leave loose patches
  in the repo root. Check `ls *.patch` in the repo root for the live list
  rather than trusting either the old or this list indefinitely. **(M)**
- [ ] **Harden `.gitignore` for secrets.** Still open — `client_secret.json` /
  `google_client_secret.json` are still only covered by the broad `*.json`
  rule (confirmed: no explicit entry for either as of this check). Add
  explicit entries (and a comment) so they can't be force-added. Confirm they
  were never committed (`git log --all -- client_secret.json`). Best
  practice: move these to env/secret storage. **(S)**
- [ ] **Add a `Makefile`** with `build`, `run-dev`, `test`, `vet`, `lint`,
  `clean`, `help`. Still open — confirmed no `Makefile` exists as of this
  check. Use the *current* flags from `main()` in `main.go` (grep `flag\.` —
  the old `main.go:887` citation has drifted, and the flag set itself grew:
  `-cfg`, `-port`, `-ds`, `-acl`, `-grants`, `-dev`, `-sig`, `-noload`,
  `-nonews`, `-log`, plus a `-tcgcsv-*` family for the ingest jobs), e.g.
  `run-dev: go run . -dev -cfg config.json`. **(S)**
- [x] **[DONE] Add a test/build CI workflow.** `.github/workflows/ci.yml`
  exists and runs on every PR and push to `master`: a `style` job (`gofmt -s
  -l .`, `go vet ./...`, `revive`, `staticcheck`) and a `build-and-test` job
  (`bun test tests/`, `go build ./...`, `go test ./...` against a downloaded
  `allprintings5.json`). No deploy workflow currently *gates* on it passing
  first, if that's still wanted.

---

## Phase 1 — Shared helpers (high ROI, behavior-preserving)

Extract the duplicated patterns that recur 20–50× across the root package.
These are mechanical, low-risk, and shrink every later refactor. Do these
before the god-function splits — the extracted helpers are what the split
functions will call.

- [ ] **`ParamParser` for cookie/sig/form reads.** The
  `readCookie()` + `strconv.Parse{Float,Bool}`/`Atoi` + default-fallback dance
  appears ~24 times across the root package, concentrated in upload.go
  (10+ instances at 264-316 — customSpread/customSpreadMax/customMin/customMax/
  customMargin/customVisual/multiplier/maxQty) with smaller clusters in
  search.go (137-169) and a handful of one-offs elsewhere. Introduce
  `ParamParser{r, sig}` with `.Float(field, cookie, def)`, `.Bool(...)`,
  `.Int(...)`. Highest boilerplate concentration in upload.go. **(S)**
- [x] **[DONE] `canAccessMode(modes, target)` helper.** Now one function
  (`utils.go`), called from `api.go` and `api_banprice.go` rather than
  duplicated.
- [ ] **`PartitionScrapersByMode(scrapers, blocklist, sealed)` helper.** A
  similar "iterate GetSellers()/GetVendors(), apply allowlist/blocklist, split
  sealed vs singles" loop appears in upload.go:333-354 (4-way partition into
  singlesSellers/singlesVendors/sealedSellers/sealedVendors), arbit.go:338-360
  (allowlist for sellers, blocklist for vendors), and sleep.go:62-90 (adds
  CountryFlag/MetadataOnly filters). Filter conditions differ — the helper
  needs to take a predicate, not be a single boolean knob. ~40% overlap; the
  shared piece is the iteration + sealed/singles split. **(S)**
- [ ] **Named constants for conditions & finish order.** The inline condition
  normalization map `{"NM":"nm","SP":"lp","MP":"mp","HP":"hp","PO":"dmg"}` at
  upload.go:591-597 is repeated in spirit by the foil/etched/nonfoil
  precedence logic at search.go:1206-1228 (parallel `if isFoil … else if
  isEtched … else …` branches). Centralize as `ConditionNormalize` map +
  `FinishOrder` slice + `CondNM/CondSP/...` constants and a `pickFinish()`
  helper. **(S)**
- [x] **[DONE] Centralize magic numbers.** All five named examples this item
  gave now exist as named constants: `MaxUploadEntries` (upload.go),
  `MaxSearchResults` (search.go), `MaxArbitResults` (arbit.go), `MaxSleepers`
  (sleep.go), `IQRThreshold` (arbit.go). Spread/price floors and other
  smaller magic numbers weren't individually re-checked this pass.
- [x] **[DONE] `errorResponse(w, status, msg)` helper.** Exists (`utils.go`)
  and is adopted — 16 call sites across the API handlers as of this check.
- [ ] **Table-driven sort dispatch.** Replace the near-identical inline
  `sort.Slice` blocks — 9 in arbit.go:810-859 (available, sell_price,
  buy_price ×2, profitability, diff, spread, edition, alpha) and ~15
  `sort.Slice` + 2 `sort.SliceStable` in search.go (top-level dispatch at
  332-369: alpha/hybrid/number/retail/buylist/default, plus the nested
  vendor/seller result sorters around 404-432) — with a
  `map[string]func(...)` of comparators (or named comparator funcs). Cuts
  ~100 LOC and makes adding a sort mode a one-liner. **(M)**

---

## Phase 2 — Decompose the god-functions & shared price logic

Larger structural work. Each is behavior-preserving but touches a lot; land
them one at a time with the Phase-0 tests green.

- [ ] **Extract a reusable seller/vendor price-fetch abstraction.** The nested
  "iterate scrapers → check sealed mode → filter blocklist → resolve tag →
  read entries" logic is duplicated across `getSellerPrices`/`getVendorPrices`
  (api_banprice.go:408-463, 581-626), `BatchPricesAPI` (api_prices.go:20-128,
  109 lines), and the search/upload price loops. Define one iteration helper +
  a `getScraperTag(info, tagName)` + `buildEnabledStores(sig, opt)` so all
  callers share it. This is the backbone the upload/search splits depend on. **(M)**
- [ ] **Split `Upload()` (upload.go:168-1200, ~1033 lines).** Extract
  `parseUploadParams()` (~264-316), `loadAndPrepareInventory()` (~333-473),
  `computeOptimizedResults()` (~928-1142), `buildSortedTabView()`
  (~1144-1177). Remove the double-iteration over `uploadedData` (filtering
  twice, 698-719 & 935-1142) by partitioning once. **(L)**
- [ ] **Split `Search()` (search.go:79-723, ~644 lines).** Extract
  `parseSearchQueryAndOptions()`, `executeSortByMode()` (folds in the Phase-1
  sort dispatch), `normalizeIndexResults()` (the INDEX TCG/MKM merge,
  477-607), and `buildEmbed()` (438-681). **(L)**
- [ ] **Consolidate the 5 CSV exporters.** `UUID2CKCSV` (api.go:137-172),
  `UUID2SCGCSV` (174-209), `UUID2TCGCSV` (294-387), `UUID2MKMCSV` (471-591),
  and the deckbox converter (api_deckbox.go) share ~85% structure. Replace with
  one `ExportToCSV(w, config, ids, qtys, conds)` driven by a
  `CSVExportConfig{Header, FieldMapper, ConditionMap}`. ~400 LOC → ~200. **(M)**
- [ ] **Centralize external-ID resolution.** `getIdFunc()`'s 7 closures
  (api_banprice.go:362-406) plus `findTCGproductId`/`findInstanceId`/
  `findOriginalId`/`instanceId2UUID` (utils.go:270-330) and the upload-export
  ID logic all map BAN UUID ↔ scryfall/tcg/mtgjson/mkm/ck. Unify behind one
  `IDResolver`. The `EntryRule` custom-buylist-pricing work this item said to
  coordinate with is no longer in-flight — it's committed (`EntryRule` exists
  in both `api_banprice.go` and `upload.go` as of this check) — so there's
  nothing left to coordinate with, just this item itself, still open. **(M)**
- [ ] **Replace `scraperCompare(...flags ...bool)` with an options struct.**
  arbit.go:489 takes positional `flags ...bool` decoded as
  `flags[0]/flags[1]/flags[2]` — fragile and unreadable at call sites
  (`Arbit()`, `Global()`, `Reverse()`). Introduce `ScraperCompareOpts`. **(M)**
- [ ] **Table-drive the newspaper column projection.** news.go:243-385 maps ~30
  SQL columns to struct fields via parallel `strconv.Parse*` if-blocks. Replace
  with a `[]ColParser{Name, Apply}` table (or reflection/struct tags if the
  mapping is stable). **(S)**
- [ ] **Group `product.go` accumulators into a struct.** `runRawSetValue`
  (product.go:765-865) mutates ~10 parallel maps
  (`inv/invFoil/invDirect/...`) in one loop. Replace with a
  `SetValueAccumulator` struct (or `map[source]map[finish]float64`) to make the
  data flow auditable. **(M)**
- [x] **[DONE] Move the template FuncMap to its own file.** `templates.go`
  now holds `var funcMap = template.FuncMap{...}`, out of `main.go`.
- [ ] **(Optional, larger) Decompose the `PageVars` god-struct.** main.go:44-229
  has ~160 fields shared across every page. Composing it from per-feature
  sub-structs (`Search *SearchPageVars`, `Upload *UploadPageVars`, ...) reduces
  coupling but requires touching every handler and template. Do only if/when
  feature churn justifies it. **(L)**
- [ ] **(Optional) Unify the three auth middleware wrappers.** auth.go's
  `noSigning` (261-278, 18 lines), `enforceAPISigning` (279-374, 96 lines),
  and `enforceSigning` (375-539, 165 lines) each re-implement base64 decode +
  HMAC build/verify + expiry check. Extract a `SignatureValidator`
  (Decode/Verify/VerifyExpiry) shared by all three. `enforceSigning` is the
  heaviest of the three — most of the duplication-reduction win is there.
  Security-sensitive — do it with auth tests in place (see Phase 4). **(M)**

---

## Phase 3 — Frontend consolidation

Vanilla JS/CSS, no build step. (The "recently-added untracked files" this
section originally flagged — `js/settings-modal.js`, `js/settings-search.js`
— no longer exist as separate tracked files as of 2026-09-14; see the
settings item below. `js/nav.js` is also gone.)

- [x] **[DONE] Extract `js/utils.js` for shared HTML helpers.** `js/utils.js`
  exists and defines `escapeHtml`/`escapeAttr`/`thumbHtml`/`httpURL`/
  `sameSiteURL`; `favorites.js`, `recent-searches.js`, and `chartopts.js` no
  longer define `escapeHtml` locally — confirmed by grepping for a local
  `function escapeHtml` in each and finding none.
- [ ] **Extract a `ListStorage` helper.** localStorage get/set + try-catch +
  max-size + `pinnedFirst()` are reimplemented in `favorites.js`,
  `recent-searches.js`, and `navbar.js` (layout). One small class. **(M)**
- [ ] **Extract a `DragDropReorder` helper.** Drag-reorder state + event wiring
  + drop indicators exist in both `navbar.js` (drag setup ~161-172) and
  `favorites.js` (~363-405; handlers at 365 dragstart, 371 dragend, 378
  dragover, 384 dragleave, 387 drop). Generalize to `(container, getItems,
  setItems, selector)`. **(M)**
- [~] **[LIKELY DONE, not fully re-verified] Consolidate the settings
  system.** `settings-modal.js` and `settings-search.js` no longer exist as
  tracked files — only `settings.js` remains (confirmed via `git ls-files
  js/`) — which reads as this consolidation having happened, opposite the
  direction this item recommended (it suggested keeping `settings-modal.js`
  and deleting from `settings.js`; whichever way it went, only one file is
  left). Not independently re-checked: whether `settings.js` alone now
  covers every settings page (search, upload, sleep, news, arbit) without
  regressions — worth an actual click-through before crossing this off for
  good.
- [x] **[DONE] Delete `js/nav.js`.** Confirmed gone.
- [ ] **Namespace the global `window.*` callbacks.** 15+ functions
  (`toggleFavorite`, `deleteRecentSearch`, `openSettings`, ...) are global for
  inline `onclick`. Group under `window.MTGBAN.{Favorites,RecentSearches,Settings}`
  (or move to event delegation + data attributes). **(S–M)**
- [ ] **Move large inline `<script>` blocks out of templates.** e.g.
  search.html:145-297 (collapsePrintings/updateSidebar/getLastSold) →
  `js/search-sidebar.js`; similar in upload.html. Smaller diffs + JS
  cache-busting. **(S–M)**
- [ ] **Replace scattered inline `style="..."` with CSS classes** in
  search.html / arbit.html / upload.html. **(S)**
- [ ] **(Deferred) Consolidate `*-mobile.css`.** `search-mobile.css` is ~50 KB,
  largely duplicating `search.css`. Fold mobile overrides into each page's
  stylesheet under `@media` queries; extract a `mobile-common.css`. Needs
  visual-regression care. **(L)**
- [ ] **(Deferred) Reduce mobile/desktop template duplication.** `mobile/*.html`
  largely mirror desktop with different classes. Only worth unifying via
  responsive CSS if mobile churn is high — currently stable, low priority. **(L)**
- [ ] **(Optional) Add a light asset build step** (esbuild / Go `embed`).
  ~25 JS + ~20 CSS files (~800 KB pre-gzip). Only pursue if load metrics
  justify it; HTTP/2 multiplexing makes this low-urgency. **(L)**

---

## Phase 4 — Testing

After Phase 0 makes tests compile, grow coverage on the highest-risk,
currently-untested logic. Many Phase 1–2 extractions create naturally
unit-testable pure functions — add tests as you extract.

- [ ] **Reduce the `allprintings5.json` test dependency.** Tests need the full
  card DB symlinked in. Add a tiny fixture datastore or a loader seam so pure
  logic (parsing, aggregation, sorting) can be tested without the 30 MB file. **(M)**
- [ ] **Test the signature/auth logic** (auth.go, 627 lines, 0 tests): sign →
  verify round-trip, expiry rejection, tampered-sig rejection,
  `GetParamFromSig` parsing. Highest-risk untested area. **(M)**
- [x] **[DONE] Test the search query parser.** No longer benchmark-only:
  `searchfilter_test.go`, `searchfilter_number_test.go`,
  `searchfilter_pattern_test.go`, and `searchfilter_regexp_test.go` together
  carry 11 real test functions as of this check (plus
  `searchfilter_bench_test.go` for the benchmarks this item originally
  meant).
- [~] **[LIKELY SUBSTANTIALLY DONE, not fully re-verified] Test price
  aggregation / best-price selection.** `price_parity_test.go` (10 test
  functions) and `price_parity_bench_test.go` exist now — real coverage
  where in June there was none. Not independently confirmed: whether it
  specifically exercises `EntryRule.applies`'s first-match-wins rate-rule
  logic, or just cheapest-retail/highest-buylist selection.
- [~] **[LIKELY SUBSTANTIALLY DONE, not fully re-verified] Test arbitrage
  math.** `arbit_bestof_test.go`, `arbit_language_test.go`, and
  `arbit_sussy_test.go` together carry 9 test functions as of this check.
  Not independently confirmed against the specific asks (spread/difference/
  profitability math, the filter predicates) rather than other arbit
  behavior.

---

## Suggested order / dependency notes

1. **Phase 0** entirely first — green tests + clean tree are prerequisites.
2. **Phase 1** helpers next — they're used by Phase 2 and are individually
   trivial to review.
3. **Phase 2** one item at a time; do the **price-fetch abstraction before**
   the Upload/Search splits. (The **external-ID** item's original note to
   coordinate with in-flight `EntryRule` changes no longer applies —
   `EntryRule` is committed now.)
4. **Phase 3** is independent of the Go work and can proceed in parallel by a
   different contributor.
5. **Phase 4** ongoing — add tests alongside each extraction; prioritize auth
   and pricing.

## Out of scope (explicitly not doing now)

- Rewriting to a web framework / SPA — the server-rendered + progressive-
  enhancement approach is a deliberate, working choice.
- Replacing the atomic-pointer snapshot concurrency model — it is sound.
- Dependency-injecting global scraper state — current `atomic.Pointer` access
  is thread-safe; revisit only if testability demands it.
