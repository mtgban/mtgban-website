# Unify the search and price-API pipelines

> **2026-09-14 spot check:** most of this has already landed. `getIDFromMode`
> and `applyCardFilter` (`api_banprice.go`, `searchfilter.go`) exist and match
> the shapes this doc proposes in place of the old opaque `getIdFunc`
> closures/`checkFinish`; `storeEligible` exists, confirmed via its
> dependents; all six tests this doc's matrix names
> (`TestZeroPricedListings`, `TestSearchDownloadFilters`, `TestStoreEligible`,
> `TestApiEnabledStores`, `TestGetDefaultBlocklists`,
> `TestFinishPredicateParity`) exist in `price_parity_test.go` and pass. The
> "full dumps keep the direct `processEntry` scan" item further down is a
> settled design decision, not an open item. Re-grep before assuming anything
> below is still true — this file reads more like a changelog that already
> tracked its own completion than a live plan, and is a candidate to fold
> into `SPECIFICATION.md` as an architectural note and retire from here.

Goal: `search.go`/`searchfilter.go` (website results) and `api_banprice.go`
(price dumps) walk the same seller/vendor data but disagree on eligibility
rules and defaults. Unify the shared mechanics so, for the same card and
store, both surfaces report the same prices — while each keeps its own
output shape.

## How the two pipelines line up today

| Stage | Search (website) | Price API |
|---|---|---|
| Card set | query → uuids (`searchAndFilter`) | whole record, or `filterByHash` / edition |
| Store eligibility | `shouldSkipStoreNG` over `config.StoreFilters`; blocklists injected as negated seller/vendor filters by `parseSearchOptionsNG` | `enabledStores` membership (sig-derived); sealed/singles partition by `SealedMode`; blocklists applied **only** for `ALL_ACCESS` |
| Card eligibility | `FilterCardFuncs` (edition, `finish`, …) | `EntryRule{Edition, Finish}` inside `processEntry`, `checkFinish` |
| Entry eligibility | `shouldSkipEntryNG` (conditions), `shouldSkipPriceNG` (price ranges) | `EntryRule.MinPrice` |
| Extraction | one `SearchEntry` per entry, bucketed by condition, `INDEX` for MetadataOnly, PO suppression, dedup | `entries[0]` as base price per finish bucket, optional `Conditions`/`Quantities` maps, id remapping (`getIdFunc`) |

Both `processEntry` and the search extraction assume records are sorted
best-price-first per condition, so "search's top row per condition" and
"API's `Conditions[cond]`" should be the same number. That is the parity
invariant the tests pin.

## Known divergences (verified in code)

1. **Finish predicate.** Resolved 2026-07-14: `checkFinish` is deleted and
   the search predicate (`cardFilterFinish`) applies everywhere - filtered
   requests inherit it through the funnel, full dumps via `EntryRule.Finish`
   (now `[]string` from `fixupFinishNG`). Semantic changes: sealed counts
   as nonfoil (kept by `finish=nonfoil`, dropped by foil/etched; was kept
   under every value), foil-etched cards match both foil and etched, and
   unknown finish values drop everything instead of filtering nothing.
2. **Blocklists.** Documented and pinned 2026-07-14 (the behavior is
   intentional, not unified): an explicit store policy overrides blocklists,
   otherwise blocklists exclude. The precedence rule is encoded in
   `storeEligible`, used by `apiEnabledStores` (ALL_ACCESS generates from
   blocklists at runtime, DEV_ACCESS sees all, explicit lists bypass) and
   pinned together with the search-side `getDefaultBlocklists` (sig can
   replace or disable the config lists) by direct unit tests.
3. **PO suppression.** Resolved 2026-07-14: the sellers walk exports every
   condition like the API always did; hiding PO-when-NM+SP is now a website
   display policy in CSS (search.css `.cond-PO` rule via `:has()`, desktop
   only). Mobile shows a PO pill instead (conditions are opt-in there);
   Discord embeds may show a `(PO)`-tagged line for stores whose only stock
   is Poor.
4. **Vendor qty special case.** API: `qty && (!MetadataOnly || shorthand ==
   "SYP")`; search reports whatever the entry carries.
5. **Sealed partition plumbing.** Resolved 2026-07-14: filtered requests
   partition at the uuid level (`apiSearchConfig` keeps `co.Sealed ==
   sealed`), which the emergent record partition makes equivalent to the
   old store-level `SealedMode` skip; full dumps keep the store-level skip.

## Escape fixes (landed 2026-07-12)

Both pipelines paid a hidden allocation tax with the same shape: a freshly
copied 704-byte CardObject passed through an opaque func value (the
getIdFunc closure in processEntry; the FilterCardFuncs map in
shouldSkipCardNG) escapes to the heap on every card examined. Replacing both
with named-function switch dispatch (getIdFromMode, applyCardFilter):

| Benchmark | before | after |
|---|---|---|
| API edition dump | 203ms / 287MB / 378k allocs | 154ms / 0.6MB / 4.6k |
| API by-hash walk | 0.88ms / 1.5MB / 5.9k | 0.69ms / 0.6MB / 4.6k |
| Search s:CODE query | 99ms / 230MB / 304k | 52ms / 1.3MB / 6.1k |

Both sides now allocate only their output. The remaining costs were pure
iteration — addressed by the resolution front door (landed 2026-07-13,
go-mtgban#39 GetUUIDsInSet + seed selection): both surfaces now converge
on walk speed for the same set query:

| Benchmark | pre-work | after all three fixes |
|---|---|---|
| Search s:CODE query | 99ms / 230MB / 304k | 0.9ms / 1.3MB / 6.1k |
| API edition dump | 203ms / 287MB / 378k | 0.7ms / 0.6MB / 4.6k |

## Target architecture (funnel, decided 2026-07-12)

The API front-ends its narrow filter language into the same machinery the
website uses; output shapes stay frozen on both sides.

1. **Resolution front door (shared).** A query resolves to a uuid list
   before any store is touched: edition -> uuids via the mtgmatcher set
   index (O(set size), replacing both the API per-entry scan filter and
   searchAndFilter's full-pool scan for s:CODE), hash -> as-is, search text
   -> existing name index. Per the benchmarks this is the two-orders-of-
   magnitude fix for both surfaces.
2. **Filtered API endpoints go through the search gathering.** DONE
   2026-07-14: getSellerPrices/getVendorPrices route any edition/hash
   request through apiSearchConfig -> searchAndFilter -> the shared walk ->
   banPricesFromRows. entries[0] parity holds because records and buckets
   share the NM/SP/MP/HP/PO ordering; INDEX rows convert as grade NM
   (index prices are always NM). checkFinish and EntryRule.Edition are
   deleted. Conversion caveats all resolved along the way: PO suppression
   moved to CSS; isSame dedup replaced by upfront id dedup in the walks
   (it existed to absorb decklist/hashing per-copy uuid repeats; the
   residual rows it collapsed were distinct same-price listings that
   deserve to show); INDEX grade recovered by the NM rule above.
   Funnel cost accepted: edition dump 0.7ms/0.6MB direct scan ->
   1.1ms/1.9MB through rows (still ~200x below the pre-work baseline).
   Post-review addendum: zero-priced listings are now ignored on both
   paths (base = first nonzero entry, zero entries add no conds/qty),
   adopting the walk's semantic in processEntry - the old full-dump
   behavior dropped the whole store when a zero listing sorted first
   while counting its qty when it didn't (TestZeroPricedListings).
   Follow-up: SearchAPI (the search-page CSV/JSON download) now hands
   its fully parsed config to the walks and converts the rows, so the
   query's store/entry/price filters shape the output - the old path
   rebuilt a store list from blocklists alone and silently dropped
   every non-card filter (TestSearchDownloadFilters). The CSV branch
   also reuses the walked rows instead of re-fetching.
3. **Full dumps keep the direct processEntry scan.** A dump has no query to
   resolve and its BanPrice aggregation allocates ~500x less than row
   materialization would (0.6MB vs ~290MB per request at benchmark scale).
   This is the one place the pipelines legitimately differ.
4. **Store eligibility helper.** DONE 2026-07-14: storeEligible(shorthand,
   allowlist, blocklist) in utils.go encodes the precedence rule; the API's
   enabledStores construction lives in apiEnabledStores and goes through
   it, as does the vendor= narrowing. Unit tests pin both surfaces (see
   divergence #2).

## Test matrix (before + after)

| Test | Before | After |
|---|---|---|
| Retail parity NM/SP/foil per store | must pass | must pass |
| Buylist parity raw prices | must pass | must pass |
| Index (MetadataOnly) seller present on both | must pass | must pass |
| Qty sums (API) vs per-row qty (search) | pinned | pinned |
| PO suppression divergence | pinned divergent | parity (policy moved to CSS) |
| Finish predicate on sealed | pinned divergent | parity (TestFinishPredicateParity) |
| Blocklist application | documented (handler-level, untested) | pinned (TestStoreEligible, TestApiEnabledStores, TestGetDefaultBlocklists) |
