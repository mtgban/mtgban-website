# Search and the price API: one pipeline, two outputs

`search.go`/`searchfilter.go` (the website's results) and `api_banprice.go`
(the price API) walk the same seller and vendor data. They share the
mechanics, so for the same card and store both report the same prices; each
keeps its own output shape.

## How a request flows

| Stage | Search (website) | Price API |
|---|---|---|
| Card set | query -> uuids (`searchAndFilter`) | edition or hash -> uuids through the same resolution; a full dump has no query |
| Store eligibility | `shouldSkipStoreNG` over the query's store filters, blocklists injected as negated filters | `apiEnabledStores`, sig-derived; both sides go through `storeEligible` |
| Card eligibility | `applyCardFilter` (edition, finish, ...) | the same, through `apiSearchConfig`; full dumps through `EntryRule` |
| Extraction | one `SearchEntry` per entry, bucketed by condition | filtered requests convert the same rows (`banPricesFromRows`); full dumps scan entries directly (`processEntry`) |

Both assume records are sorted best-price-first per condition, so "search's
top row per condition" and "the API's `Conditions[cond]`" are the same
number. `price_parity_test.go` pins that.

## The rules both sides follow

- **Finish.** One predicate (`cardFilterFinish`) everywhere: sealed counts as
  nonfoil, a foil-etched card matches both foil and etched, and an unknown
  finish value matches nothing (`TestFinishPredicateParity`).
- **Blocklists.** An explicit store list overrides the blocklists; otherwise
  the blocklists exclude. `storeEligible` encodes it: ALL_ACCESS builds its
  list from the blocklists at runtime, DEV_ACCESS sees everything, an
  explicit list bypasses them (`TestStoreEligible`, `TestApiEnabledStores`,
  `TestGetDefaultBlocklists`).
- **Zero prices.** A zero-priced listing is ignored: the base price is the
  first nonzero entry, and zero entries add no condition or quantity
  (`TestZeroPricedListings`).
- **Poor condition.** Both export every condition. Hiding PO when NM and SP
  are listed is a display rule of the desktop page (`search.css`,
  `.cond-PO` under `:has()`); mobile shows a PO pill instead.
- **Vendor quantities.** The API sums a vendor row's quantity unless the
  store is an index, where only a want-count (`PriceUnitCount`) is summed.
- **Search downloads.** `SearchAPI` hands its parsed config to the same walks
  and converts the rows, so a query's store, entry and price filters shape
  the file (`TestSearchDownloadFilters`).

## The one place they differ

A full dump (no edition, no hash) keeps the direct `processEntry` scan. It
has no query to resolve, and aggregating straight into `BanPrice` allocates
about 500 times less than materializing rows would: 0.6 MB against roughly
290 MB per request at benchmark scale.

Both sides allocate only their output because the card filters and the id
remapping are named-function switches (`applyCardFilter`, `getIDFromMode`)
rather than func values a copied `CardObject` would escape through.
