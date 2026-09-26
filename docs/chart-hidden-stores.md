# How a chart remembers hidden stores

Background for #665: why a chart saves the stores a viewer hides by
display name, rather than by scraper shorthand and side (retail or
buylist), and what moving off the name would take.

## A chart line is a provider, not a store

A single-card chart draws one line per *provider series* from the price
archive, not per scraper. On the long-form read, `chartDatasetsFrom`
(chart.go) emits one dataset per provider in `providerRegistry` with
prices in the requested window, in registry order, named by the
provider's `public_name` from `timeseries_config.datasets`
(`buildProviderRegistry`). So the list differs from card to card, and
between the window the page first renders (`chartInitialRange`: the
viewer's last range, else 180 days) and a wider one fetched later from
`/api/chart` (`ChartRangeLoader` in js/chart-range.js; the single-card
`installChartPayload` in templates/search.html rebuilds the datasets from
it). The legacy read lists every configured series, priced or not, so
positions held there.

Before #665, the desktop chart saved one boolean per dataset *position*.
Two symptoms followed. Hiding TCGplayer Market on a card whose datasets
were [TCGplayer Low, TCGplayer Market, Card Kingdom Buylist] saved
`[false,true,false]`; the next card, listing [TCGplayer Low, Card Kingdom
Retail, Card Kingdom Buylist], then opened with Card Kingdom Retail
hidden. And on a card listing [TCGplayer Low, Card Kingdom Buylist] with
Card Kingdom Buylist hidden (`[false,true]`), widening to a range that
inserted TCGplayer Market ahead of it hid TCGplayer Market on the rebuilt
chart and left Card Kingdom Buylist showing.

## What is remembered, and where

| Surface | Storage & key | Written by | Applied by |
|---|---|---|---|
| Desktop single-card chart | localStorage `BANChart`, or `BANChartSealed` for a sealed product | `saveLegendState` (js/chartopts.js), on every legend click | `applySavedLegendState` (js/chartopts.js), on first draw and after a wider-window rebuild |
| Mobile chart drawer | cookie `MobileChartHidden` (comma-joined names, URI-encoded, `path=/`, 5-year max-age, `SameSite=Lax`) | `saveHiddenVendors` (js/mobile-chart.js), on every legend tap and on drawer close | `chartDatasets` (js/mobile-chart.js), on first draw and in `installPrefetched` |

Both hold the hidden stores' display names, as a JSON array on desktop
and a comma-joined list on mobile:

```json
["Card Kingdom Buylist"]
```

A roster (multi-card) chart has no hidden-store state at all: its legend
lists cards, not stores, and `renderChartLegend` is called with no storage
key there, so nothing is read or written for it. Separately, a roster's
price-source picker remembers the chosen source by name, in localStorage
`chartMultiRef`.

Desktop and mobile do not share state, and mobile keeps one key for both
singles and sealed products, unlike desktop's two.

## The rules

A line is hidden if and only if its store's name is in the saved set.
Saving replaces the saved state of the stores the chart in hand draws, and
keeps the saved names of any store it does not draw: a click on a card
without some store must not unhide that store for the next card, or for a
wider window that brings it back. Desktop: #665 (`saveLegendState`).
Mobile: commit 3c2d984e (`saveHiddenVendors`).

The pre-#665 desktop format, one boolean per position, is ignored rather
than translated: `savedHiddenStores` keeps only string entries, so it
reads as nothing hidden until the next click overwrites it. Translating
it would mean guessing which card saved it, which is the bug itself, and
a wrong guess would then stick on every card. The cost: a viewer who had
stores hidden sees them once, and hides them again.

## Why the display name

**Position** fails outright: the store at a given position changes with
the card and with the window, as above.

**Scraper shorthand + side**, the convention of the search filters
(cookies `SearchSellersList` and `SearchVendorsList`; see utils.go,
js/settings.js), does not fit: a chart line is a provider series, not a
store. `DatasetConfig` (chart.go) lists the scrapers feeding a series as
`Retail []string` / `Buylist []string`, so one series can be fed by
several shorthands; a derived series has no scraper of its own (Sealed EV
is `kind = 'derived'` in db_migration/02_seed_providers.sql); and
non-Magic deployments write TCGplayer series straight under provider ids,
via the tcgcsv ingest (tcgcsvd/prices.go, `timeseries.ProviderTCGLow`
through `ProviderTCGDirectLow`, defined in timeseries/variants.go), with
no scraper at all. A series has exactly one name, but zero, one, or
several shorthands.

**Provider id** (`provider` in `timeseries_config.datasets`, which is
`providers.id` in the archive) is the sturdiest key: unique per series
(`buildProviderRegistry` drops a repeated id), shared across games, and
unaffected by editing a `public_name`. But the page is never sent it:
`Dataset` (chart.go) and `ChartAPIDataset` (api_chart.go) carry the name,
not the id, so adopting it is a change of its own (below).

**Display name** is what the page already has, what the viewer clicked,
and what the mobile drawer and `chartMultiRef` already key on.

## Known limits

- Editing a provider's `public_name` un-hides that store for every
  viewer who had hidden it, once: the saved name matches nothing. It
  can never hide another store: a name matching no line hides nothing.
- Two providers configured with the same `public_name` would hide and
  show together, since the registry dedups by provider id, not by name.
- The mobile cookie comma-joins names, so a name containing a comma would
  split into two entries; desktop's JSON has no such limit. None of the
  13 names in db_migration/02_seed_providers.sql has one, but a
  deployment's config can name its providers differently.
- The desktop key kept its pre-#665 name on purpose: the next legend click
  overwrites whatever the old format left behind, rather than leaving it
  unread under a new one. The cost is a rollback: a build from before
  #665 reads the saved names as per-position flags (every string is
  truthy), and hides the first N stores until clicked.

## Moving to provider ids

If names ever stop being good enough:

- Carry the id on `Dataset` (chart.go: `buildProviderDataset`, and
  `buildDataset` on the legacy read, from `config.Provider`), on
  `ChartAPIDataset` via `chartAPIDatasets` (api_chart.go), and in the
  template's inline datasets (templates/search.html). JS needs it too:
  `chartDatasetConfig` (js/chart-range.js) and the mobile `chartDatasets`.
- Expect a transition window: `/api/chart` answers are sent
  `Cache-Control: public, max-age=3600` (`writeChartAPIResponse`,
  api_chart.go), so for up to an hour after a deploy a page can still get
  a cached answer with no id, and needs to fall back to matching by name.
- Saved names translate to ids without guessing for every store the page
  shows, since it has both; the positions #665 dropped named nothing to
  translate from. A name for a store not on the page stays a name until
  that store shows up.
- Move desktop, mobile, and `chartMultiRef` together, so the three
  surfaces keep one rule rather than three.
