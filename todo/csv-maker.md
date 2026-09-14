# CSV Maker

> **2026-09-14 spot check:** nothing below is built yet (`csvmaker.go`,
> `templates/csvmaker.html`, `js/csvmaker.js` — zero hits, and no `sheets`
> section in `userstate`'s `validSections`). The machinery this plans to
> reuse (`parseSearchOptionsNG`, `findSellerInventory`/`findVendorBuylist`,
> `priceRowToCSV`) still exists with compatible signatures, so the plan below
> is still buildable as written — this is a live, accurate, unstarted design
> doc, not a stale one.

A page for building custom price sheets: identify cards with the regular
search syntax, pick exactly one price source, preview the rows, then download
the CSV or save the sheet definition to the user's synced state to rebuild it
later with fresh prices.

Working name: **CSV Maker**, route `/csvmaker`. Everything below reuses
existing machinery; the only new persistence is one userstate section.

## User story

"I maintain a spreadsheet of my Legacy staples priced at CK buylist. Every
week I re-download it. Today I abuse the search page's CSV export, but that
gives me every store as columns and I only want one, and I have to re-type my
queries each time."

## UX

One full-width page (desktop template only at first; `filterNavForMobile`
hides the nav entry on mobile).

```
┌──────────────────────────────────────────────────────────────┐
│  Queries                              Source: [CK Buylist ▾] │
│  ┌────────────────────────────────────────────┐ [+ add row]  │
│  │ Force of Will                              │              │
│  │ Wasteland s:TMP                            │              │
│  │ t:legendary t:elf f:nonfoil                │              │
│  └────────────────────────────────────────────┘              │
│  Conditions: (•) NM only  ( ) all conditions                 │
├──────────────────────────────────────────────────────────────┤
│  Preview (first 50 of 312 rows)                 [refresh]    │
│  UUID | Name | Set | Number | Finish | Cond | Price          │
│  ...                                                         │
├──────────────────────────────────────────────────────────────┤
│  [Download CSV]   [Save sheet: name______] [▾ saved sheets]  │
└──────────────────────────────────────────────────────────────┘
```

- **Query rows**: each row is one full search-syntax query (same autocomplete
  assets as search: `autocomplete.js`, `fetchnames.js`). Rows resolve
  independently and results are concatenated, deduped by uuid, order
  preserved (first query first, `sortSets` within a query — same default as
  the search page).
- **Source picker**: a single dropdown listing every seller and vendor, one
  entry each, grouped "Retail" / "Buylist", labeled via `scraperName()`.
  Exactly one selection — this is the product's core simplification. Index
  sources (`MetadataOnly`) are included (TCGLow etc. are the most likely
  picks). The user's blocklists (`getDefaultBlocklists`) hide the same
  stores the search page hides.
- **Conditions**: `NM only` (default) emits one row per printing; `all`
  emits one row per (printing, condition) the source actually has.
- **Preview**: first 50 rows rendered client-side from the preview endpoint,
  with the total row count. Refresh re-resolves (prices move with the 12h
  stash, so a visible refresh beats silent staleness).
- **Saved sheets**: dropdown of the user's sheets; selecting one loads its
  queries/source/conds into the form. Save with an existing name overwrites
  after a confirm (`confirm-dialog.js`). Delete affordance per entry.

## What a saved sheet is

A sheet stores the **definition, not the rows**: queries, source, conds.
Rebuilding on load/download re-resolves through the live search pipeline, so
a sheet keeps up with new printings and price movement. (Freezing a snapshot
is explicitly out of scope; the download IS the snapshot.)

```json
{
  "id": "sh_8f3a...",            // random, server-side
  "name": "Legacy staples @ CK",
  "queries": ["Force of Will", "Wasteland s:TMP"],
  "source": { "kind": "vendor", "shorthand": "CK" },
  "conds": "NM",                  // "NM" | "ALL"
  "createdAt": "2026-08-04T12:00:00Z",
  "updatedAt": "2026-08-04T12:00:00Z"
}
```

Caps (server-enforced on save): ≤ 20 sheets, ≤ 50 queries per sheet,
≤ `MaxSearchQueryLen` (1000) per query, name ≤ 60 chars.

## Persistence: userstate section `sheets`

Extend the existing per-user JSONB row (`userstate/schema.go`):

- `sheets JSONB NOT NULL DEFAULT '[]'` column (+ `ALTER TABLE ... ADD COLUMN
  IF NOT EXISTS` in the ensure-schema path, same as the table create).
- Register in `validSections` and `defaultFor` (`userstate/store.go`),
  surface in `State`.
- Client reads/writes it through the existing `/api/userstate/` GET and
  `PATCH /api/userstate/sheets` with the optimistic `version` — no new
  persistence API at all. Identity is the signed-in email
  (`userStateIdentity`), already scoped per game.
- The PATCH payload cap for this section: reject > 64KB before the DB write
  (a full 20×50 sheet set is ~15KB).

## Endpoints

| Route | Gate | Purpose |
|---|---|---|
| `GET /csvmaker` | `enforceSigning` + nav ACL | the page |
| `GET /api/csvmaker/preview?q=<q1>&q=<q2>&source=CK&kind=vendor&conds=NM` | `enforceSigning` | JSON: `{total, rows: [first 50]}` |
| `GET /api/csvmaker/download?...same...&name=<sheet name>` | `enforceSigning` + CSV flag | `text/csv` attachment |

Both API handlers share one resolver:

1. For each `q`: `parseSearchOptionsNG(q, blocklistRetail, blocklistBuylist,
   miscOpts)` → `searchAndFilter(config)` → uuids (respecting
   `MaxSearchTotalResults`). Concatenate, dedupe, cap total at 10,000 rows.
2. Resolve the one source: `findSellerInventory(shorthand)` or
   `findVendorBuylist(shorthand)` — a single map, probed once per uuid.
   This is the cheap path: no `getSellerPrices` dump machinery, no
   per-store fan-out.
3. Row assembly mirrors `priceRowToCSV`'s identity columns (uuid → scryfall
   display id, name with `preferFlavor` preference, set code, edition,
   number, finish) with a single price column; `strconv.FormatFloat(_, 'f',
   2, 64)`. Sellers price from `entry.Price`, vendors from `entry.BuyPrice`;
   conds="ALL" walks the entries, conds="NM" filters `Conditions == "NM"`.
   Rows with no price at the source are kept with an empty price cell
   (spreadsheet-friendly), countable in the preview as "unpriced".

CSV shape:

```
UUID,Card Name,Set Code,Edition,Number,Finish,Condition,<scraperName> Price
```

Filename: `mtgban_<sheet-or-source>_<yyyymmdd>.csv`. Header comment row is
omitted (Excel-hostile); the source is in the price column header.

## Permissions

- Page + preview: any signed-in tier that passes the nav ACL (`ExtraNavs`
  entry `CSVMaker`, added to `OrderNav` and `sign()`'s field set —
  `SignedFields` picks it up automatically).
- Download: reuse the existing `SearchDownloadCSV` flag — it already means
  "may extract CSVs". No new tier knob unless marketing wants one; the spec
  reserves `CSVMaker` as the page-visibility flag only.
- Save/load: any signed-in user (userstate identity requires the email from
  the sig). Anonymous/demo (`sig == ""`): page hidden; nothing to gate.
- Sealed: allowed — `mode=sealed` toggles like the search page; the source
  dropdown then lists only `SealedMode` scrapers, and `conds` is forced NM
  (sealed has no conditions).

## Implementation map

| Piece | Where |
|---|---|
| Handler + resolver + CSV writer | new `csvmaker.go` |
| Page template | new `templates/csvmaker.html` (desktop; reuses search css vars + `sidebar-action` button styles) |
| Routes | `main.go` (`/csvmaker` via `enforceSigning`, `/api/csvmaker/` likewise) |
| Nav | `ExtraNavs["CSVMaker"]` + `OrderNav` + ACL config |
| Sign flag | `sign()` field `CSVMaker`; `SignedFields` const list |
| Userstate | `sheets` column + section (schema.go, store.go, api passthrough is free) |
| Frontend | small `js/csvmaker.js`: form state, preview fetch/render, userstate GET/PATCH with version retry (pattern already in `user-state.js`) |
| Tests | resolver unit tests (datastore-gated, synthetic seller/vendor via the `price_parity` seeding pattern); userstate section round-trip test; `TestTemplatesParse` covers the template |

## Deliberately out of scope (v1)

- Multiple sources / column-per-store (that's the search page's export).
- Price snapshots stored server-side.
- Scheduled emails / webhooks of a sheet.
- Mobile page (nav-hidden; API works regardless).
- Quantity column (belongs to the Upload optimizer's domain).

## Open questions

1. Reuse `SearchDownloadCSV` for the download gate (spec'd above) or mint a
   separate tier knob?
2. Should "all conditions" also expand sealed EV columns for EV-style
   sources (`CT Zero EV` etc.), or keep those flat?
3. Sheet sharing (a signed URL that rebuilds someone's sheet read-only) —
   cheap to add later since a sheet is just queries+source, but needs a
   privacy pass.
4. Should preview row 50 cap be a page (with next/prev) instead? V1 says no
   — the CSV is the real artifact.
