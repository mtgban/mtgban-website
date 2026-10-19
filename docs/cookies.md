# Cookies

Every cookie the site sets, what reads it, and where each could live
instead. The goal is a site that keeps only the signature in a cookie:
preferences go to the userstate database for signed-in readers and to
localStorage for everyone else.

The site sets **54 cookies**, all on its own origin:

| Group | Count | Server reads it | Proposed home |
|---|---|---|---|
| Auth | 2 | 2 | keep |
| Layout | 1 | 1 | keep |
| Search | 12 | 11 | userstate + localStorage, server-read ones via the route in [Server-read preferences](#server-read-preferences) |
| Charts | 3 | 2 | localStorage |
| Upload | 25 | 25 | localStorage + userstate, sent as form fields |
| Arbitrage, Global, Reverse | 6 | 6 | userstate, read by the server |
| Sleepers | 3 | 3 | userstate, read by the server |
| Newspaper | 2 | 2 | userstate, read by the server |

Theme, offline mode, favorites, recents, presets and the navbar layout
are already in localStorage, and userstate syncs them (`PREF_KEYS` in
`js/user-state.js`). There is no consent or analytics cookie.
`js/ban-to-cart.js` reads `XSRF-TOKEN` and `bga-buylist-cart-*`, but those
are the stores' own cookies, read on the store's page. This site does not
set them.

## How cookies are written

Each inventory row points at one of these writers.

| Key | Writer | Domain | Path | SameSite | Expiry | Other |
|---|---|---|---|---|---|---|
| **G** | `setCookie(..., global=true)`, utils.go | parent domain (`.mtgban.com`) on a trusted host, else host-only | `/` | none set (browser default) | given by the caller | Secure on HTTPS; not HttpOnly |
| **S** | `setCookie`/`setForeverCookie`, utils.go | host-only | `/` for `Search*`, `MobileSearch*` and `UploadCustom*`, else the request's first path segment (`cookiePath`) | Strict | 10 years | Secure on HTTPS; not HttpOnly; also expires a stray `Path=/` copy |
| **J** | `setCookie`, js/cookies.js | host-only | the same rule as S, applied to the **current page's** path (`routePath()`) | Strict | 1000 days unless noted | expires the copy at the other path |
| **W** | `writeCookie(..., '/')`, js/cookies.js | host-only | `/` | Strict | 1000 days | — |

## Inventory

"First render" means the server reads the cookie while building the HTML
of a page that a navigation reaches. These are the cookies that a Strict
attribute drops when the reader arrives from another site.

### Auth and layout

| Cookie | Written by | Read by | First render | Holds | Sensitivity | Attributes |
|---|---|---|---|---|---|---|
| `MTGBAN` | `putSignatureInCookies` (auth.go) at login; `Home` (home.go) expires it on `?errmsg=logout` | `unverifiedSignature` (auth.go), so every signed route, the nav and the ACL; `withSignatureCookie`. JS: `user-state.js` and `recent-searches.js` test that it exists; `offline/offline-mode.js` decodes it for `SearchOfflineMode` | yes, on every page | the HMAC-signed grants: tier, page flags, `UserEmail`, `Expires` | high: a bearer credential that carries the email, and JS can read it | G, 31 days |
| `MTGBAN_HANDOFF` | `apiHandoff` (api_handoff.go:83); expired by `spendHandoffCookie` (:233) | `finishAPIHandoff` (:143), `spendHandoffCookie` (:225), on the Patreon callback | callback only | a random nonce that ties the OAuth `state` to this browser | medium: CSRF binding, 10 minutes | `Path=/auth`, Max-Age 600, HttpOnly, Secure, Lax |
| `MobileView` | `toggleMobileView` (mobile.go), `/toggle-mobile` | `isMobileRequest` on every page; `toggleMobileView` | yes: it picks the desktop or the mobile template set | `true`/`false` | low | `Path=/`, 1 year, Lax, Secure on HTTPS |

### Search

Every row is written by J with `Path=/`. The desktop writer is the
settings modal (`js/settings.js`). The mobile writer is the settings
sheet inline in `templates/mobile/search.html`.

| Cookie | Written by | Read by (server) | Read by (JS) | First render | Holds |
|---|---|---|---|---|---|
| `SearchSellersList` | modal store grid, mobile sheet | `getSearchBlocklists` (Search, `/data/prices/`), `SearchAPI` | settings, mobile sheet, `offline.html` (both) | yes: hidden stores, which also changes which cards match | CSV of store shorthands |
| `SearchVendorsList` | same | same | same | same | same |
| `SearchMiscOpts` | modal, mobile sheet | `readSearchMiscOpts`: Search, `SearchAPI`, custom buylist, arbit, newspaper, screener, sleepers, upload | settings, mobile sheet | yes: `preferFlavor`, `noUpsell`, `hidePromos`, `hidePrelPack`, `skipEmpty`, `noSussy`, `hideBLconds` | CSV of flags |
| `SearchDefaultSort` | modal | `readSearchSort` (Search, `SearchAPI`), `fillSearchPrefs` (the alpha button's link) | `offline.html` | yes: result order | `chrono`, `hybrid`, ... |
| `SearchListingPriority` | modal, mobile sheet | Search (search.go:665), `sortOfferRows` | `offline.html` (both) | yes: offer order within a card | `stores` or empty |
| `SearchSellersPriority` | modal, mobile sheet | `sortSearchKeys` for `sort=retail` | mobile sheet | yes, when sorted by price | a store shorthand |
| `SearchVendorsPriority` | modal, mobile sheet | `sortSearchKeys` for `sort=buylist` | mobile sheet | yes, when sorted by price | a store shorthand |
| `SearchSealedContents` | modal, mobile sheet | Search and arbit, for the 🔎 links (`sealed_contents_filter`) | `command-palette.js` | yes, but only link targets | `contents`, `fixed`, ... |
| `SearchBuylistSecondary` | modal | — | `search.html:764`, `offline.html` | no | a mode name |
| `SearchDefaultTab` | mobile sheet | `fillSearchPrefs` → `mobile/search.html` | mobile sheet | yes, mobile only: which tab opens | `sellers`/`buyers` |
| `SearchDefaultView` | mobile sheet | `fillSearchPrefs` → `mobile/search.html` | mobile sheet | yes, mobile only: default condition | a condition |
| `MobileSearchLayout` | mobile sheet; copied from the synced `mtgban_search_layout` on load | `fillSearchPrefs` → `mobile/search.html` | mobile sheet | yes, mobile only: expanded or compact | `expanded`/`compact` |

Sensitivity: low for all of them.

### Charts

| Cookie | Written by | Read by | First render | Holds | Attributes |
|---|---|---|---|---|---|
| `SearchChartRange` | `rememberRange` (js/search-chart.js), mirroring the localStorage range | `chartInitialRange` via `fillLongFormChart` (chart page) | yes: the window rendered inline; without it the chart draws twice | days | J, `Path=/`, 365 days |
| `SearchChartMultiRange` | same, for the multi-card chart | same | same | days | same |
| `MobileChartHidden` | `writeHiddenVendors` (js/mobile-chart.js) | `mobile-chart.js` only | no | CSV of store names hidden on the chart | `Path=/`, 5 years, Lax |

### Upload

The server writes with S (`Path=/upload`). JS writes with J: `Path=/upload`
from `/upload`, but the current page's path from anywhere else (see
[Found while inventorying](#found-while-inventorying)). `UploadCustom*`
uses `Path=/`.

| Cookie | Written by | Read by | First render | Holds |
|---|---|---|---|---|
| `uploadMode` | `readSetFlag` for `?mode=` (upload.go:531) | the same | yes: retail or buylist page | `true`/`false` |
| `gdocURL` | `Upload` after a remote-link upload (upload.go:614) | `Upload` prefills the link field | yes: the field's value | the reader's last spreadsheet or deck URL. **Medium**: a private sheet's sharing link works as a capability |
| `enabledSellers`, `enabledVendors`, `enabledSealedSellers`, `enabledSealedVendors` | `Upload` after every upload (S); `persistStores` in `upload-presets.js` (J, 3650 days) | `tickedStores` (upload.go:1549); JS `retickFromCookie`, `upload-presets.js` | yes: which store boxes are ticked | `\|`-separated shorthands |
| `enabledIndexes`, `enabledSealedIndexes` | `Upload` when `index_pref` is posted (S); `persistStores` (J) | upload.go:1576 | yes: index boxes | `\|`-separated shorthands |
| `UploadOptimizerOpts` | modal, `upload-presets.js`, `upload-tabs.js` (a one-time copy from older localStorage keys) | `readUploadSettings` (upload.go:359); JS `upload-options.js`, `upload-tabs.js` | POST only, as a fallback | CSV of optimizer flags |
| `UploadSorting`, `UploadAltPrice`, `UploadPriceSource`, `UploadPercSpread`, `UploadPercSpreadMax`, `UploadMinVal`, `UploadMaxVal`, `UploadMargin`, `UploadCustomPercMax`, `UploadMultiplier`, `UploadMaxQty` | modal, `upload-presets.js`, `upload-tabs.js` | `getUploadSetting`, used when the form omits the field (upload.go:1427–1481); JS `upload-options.js` copies them into the form | POST only, as a fallback | one value each |
| `UploadCustomOpts`, `UploadCustomBuyer`, `UploadCustomSealedBuyer`, `UploadCustomMinPrice`, `UploadCustomRate` | modal, `upload-presets.js` | upload.go:1935–1956 (fallback); **`searchCustomBuylist` on every search**; JS `upload-options.js` | yes, on search: they add the custom buylist column | one value each |

Sensitivity: low except `gdocURL`.

### Arbitrage, Global, Reverse, Sleepers, Newspaper

| Cookie | Written by | Read by | First render | Holds | Attributes |
|---|---|---|---|---|---|
| `ArbitVendorsList`, `ReverseVendorsList` | modal vendor grid (`data-cookie`) | `arbit` for `Arbit`/`Reverse` (arbit.go:379) | yes: hidden vendors | CSV of shorthands | J |
| `GlobalVendorsList` | modal vendor grid | `Global` (arbit.go:441) | yes | CSV of shorthands | J |
| `ArbitFilters`, `GlobalFilters` | `arbit-filters.js`, mirroring the synced `mtgban_arbit_filters` | `scraperCompare` via `requestArbitState` (arbit.go:531) when the URL carries no filters | yes; the page reloads once if the mirror lagged | the filter query plus a stamp | W |
| `ArbitFiltersOpen` | `arbit-filters.js` | arbit.go:682 | yes: the filter panel open or closed | `1` or unset | W |
| `SleepersSellersList`, `SleepersVendorsList` | modal | `Sleepers` (sleep.go:83) | yes | CSV of shorthands | J |
| `SleepersEditionList` | modal editions picker | sleep.go:93 | yes | CSV of set codes | J |
| `NewspaperList` | modal editions picker | news.go:1305 | yes | CSV of set codes | J |
| `BanNewspaperPref` | `readSetFlag` for `?force3day=` (news.go:1149) | the same | yes: the 1-day or 3-day paper | `true`/`false` | S, `Path=/newspaper` |

Sensitivity: low for all of them.

## Found while inventorying

- **The modal saves other pages' settings at the wrong path.** The gear
  opens every tab on every page. J scopes each non-`Search*` cookie to the
  path of the page it was saved on, so the Arbitrage tab saved on
  `/search` writes `ArbitVendorsList; Path=/search`. `/arbit` never reads
  that copy. The tab also opens blank, because `/search` cannot see the
  `/arbit` copy. This affects the arbit, global, reverse, sleepers,
  newspaper and non-custom upload tabs. Checked in a browser with
  `js/cookies.js`: a value saved on `/arbit` stayed in effect after a
  different value was saved from `/search`.
- **`MTGBAN` is readable by JS** and carries `UserEmail`. Three scripts
  read it: two test that it exists, and `offline-mode.js` reads one flag.
  If the page rendered those two facts instead, the cookie could be
  HttpOnly.
- **Edition lists come close to the size limit.** All 869 Magic set codes
  in the current datastore, comma-joined, take 3,921 bytes. Browsers keep
  about 4,096 bytes per cookie, so an edition list can only just live in
  a cookie of its own, and cannot share one with anything else.
- `upload-tabs.js` copies old localStorage keys into cookies, the
  opposite of this plan. It goes when upload moves.

## Proposed home

| Cookie(s) | Home | Why |
|---|---|---|
| `MTGBAN` | keep (Lax) | The signature is the credential, and every page needs it on the first request. |
| `MTGBAN_HANDOFF` | keep | The server must check it on the Patreon callback, a cross-site redirect. It is HttpOnly and lives 10 minutes. |
| `MobileView` | keep (already Lax) | It picks the template set before anything else renders. Moving it would render the wrong layout and then reload. |
| `SearchBuylistSecondary`, `MobileChartHidden` | localStorage, synced | Only JS reads them. |
| `SearchDefaultTab`, `SearchDefaultView`, `MobileSearchLayout`, `ArbitFiltersOpen`, `SearchSealedContents` | localStorage, synced; applied by the page script | They change only display or link targets. `MobileSearchLayout` already has a synced copy (`mtgban_search_layout`). |
| `SearchChartRange`, `SearchChartMultiRange` | localStorage (already the source); drop the mirror | The cost is a second draw when the saved range differs from the default. Keep the mirror if that redraw matters more than the cookie. |
| Upload, except `UploadCustom*` (20) | localStorage, synced; sent as form fields | The upload POST already takes every setting as a field, and `upload-options.js` injects them. The GET page can tick the store grids and fill `gdocURL` from storage, as `retickFromCookie` already does. |
| `UploadCustom*` (5) | with the search group | `searchCustomBuylist` reads them on every search. |
| Search, result-changing (`SearchSellersList`, `SearchVendorsList`, `SearchMiscOpts`, `SearchDefaultSort`, `SearchListingPriority`, `SearchSellersPriority`, `SearchVendorsPriority`) | userstate, read by the server for signed-in readers; signed-out readers need a decision (below) | They change which cards match, their order and the columns shown, so the server must know them before it renders. |
| Arbitrage, Global, Reverse, Sleepers and Newspaper lists, `ArbitFilters`, `GlobalFilters`, `BanNewspaperPref` | userstate, read by the server | The same reason. These pages are normally behind a tier, so their readers are signed in and have a row. `ArbitFilters` is already synced. |

Nothing is dropped outright. Every cookie holds something a reader chose.

## Server-read preferences

Routes for a preference the server needs on the first render:

| Route | Touches | First render | Signed out | No JS | Cost |
|---|---|---|---|---|---|
| Lax cookie, one per preference (today, with Lax) | `setCookie`, `js/cookies.js` | works | works | works where the server writes the cookie | keeps all 52 server-read cookies |
| One Lax mirror cookie (`MTGBAN_PREFS`, `Path=/`) written from localStorage | every `readCookie` call above becomes `readPref`; `prefs.js` writes the mirror | works on the device that saved; one stale render after a change on another device (reload once, as arbit does) | works | no setter without JS today anyway | edition lists do not fit in it alongside anything else |
| userstate, read by the server | `Search`, `SearchAPI`, `BatchPricesAPI`, `Arbit`, `Reverse`, `Global`, `Sleepers`, `Newspaper`, `Upload`, `Screener`, chart page | works on every device | no row, so no preferences | works | one primary-key Postgres read per render (measure on search, the hot path); saving must wait for the PATCH before the reload; plain preference keys need per-key stamps, since `mergePrefs` lets local win; a database outage renders defaults |
| Query parameter or header added by the page script | fetches (`/api/search`, `/data/prices/`) and the site's own links and forms | fails for links from other sites, the case this is about | works | fails | puts preferences in shareable URLs; arbit's `f` marker guards against that |
| Filter on the client | search, arbit and sleepers templates and their scripts | flashes, then changes | works | fails | only works for display: hidden stores and flags change matches, pagination and best-price columns inside `parseSearchOptionsNG` |
| Render defaults, then reload | page scripts | double load | double load on **every** navigation unless combined with a cookie | defaults | arbit already does this once per saved state |

Recommendation: read userstate on the server for signed-in readers.
Search has an open mode for signed-out readers (`DisableChart`,
search.go:572). Other pages are open to them only where the bucket's ACL
says `Any`. On pages behind a tier, that covers every reader.

The one decision left for the owner is signed-out readers, who have no
row:

- **(a)** Keep one Lax `MTGBAN_PREFS` mirror for them, holding only the
  search group. It is small, with no edition lists.
- **(b)** Drop server-applied preferences for signed-out readers. They
  get the defaults, and the display-only preferences still apply from
  localStorage.

(a) keeps today's behaviour for them. (b) leaves only the signature,
the handoff nonce and `MobileView`.

## Migration

- **Seeding.** On load, `prefs.js` copies each cookie the page can see
  into its localStorage key if that key is unset. userstate's
  `PREF_KEYS` then syncs it. The copy is then expired at `/` and at the
  current path. Route-scoped cookies are visible only on their own route,
  so each page seeds its own. Stray copies left by the modal bug expire on
  whichever route the reader visits next.
- **Order of reads.** The server reads userstate first and the cookie
  second until seeding has run for a while. Then the cookie read goes.
- **Offline mode.** `offline.html` (desktop and mobile) reads
  `SearchDefaultSort`, `SearchSellersList`, `SearchVendorsList`,
  `SearchListingPriority` and `SearchBuylistSecondary` with `getCookie`.
  It switches to the same localStorage keys, which also work offline.
  `sw.js` precaches `js/cookies.js`, and needs `prefs.js` added.
- **Mobile.** The settings sheet in `templates/mobile/search.html` writes
  cookies itself. It moves together with `js/settings.js` in each PR, or
  that PR misses phones. `mobile-chart.js` has its own writer.
- **Settings modal.** The binders in `js/settings.js` and
  `EditionsPicker` call `getCookie`/`setCookie` in one place each, so a
  storage swap is local. `saveAll` already waits for promises, so a save
  can wait for the userstate PATCH before the reload.
- **Upload transfers.** The hash forms on search, arbit, newspaper and
  screener post to `/upload` without the optimizer fields. They need the
  same field injection as the upload form, or they price with defaults.
  A shared `/upload?gdocURL=` link from outside the site already gets
  defaults today.

### Tests to add

| Where | What |
|---|---|
| `tests/prefs.test.js` | get/set; seeding copies a cookie once, never over a set key, and expires both paths |
| `tests/settings-*.test.js` | each binder round-trips through prefs, not `document.cookie` |
| `tests/user-state-prefs.test.js` | new keys are in `PREF_KEYS`; per-key stamps decide the merge |
| `tests/offline/` | the offline page reads preferences from localStorage |
| Go, per handler | a request with the preference in userstate, or in the mirror, renders the same as one with the old cookie |
| Go, `setCookie` | `MTGBAN` carries `SameSite=Lax` |

## Order of PRs

| # | PR | Size | Risk |
|---|---|---|---|
| 1 | Fix the modal's path bug: write each tab's cookies at its own page's path | small | low |
| 2 | Make preference cookies Lax as well as `MTGBAN` (`setCookie`, `js/cookies.js`), and rewrite existing ones once on load | small | low; fixes the Discord case now |
| 3 | `prefs.js` with seeding, no callers yet | small | none |
| 4 | Move JS-only cookies (`SearchBuylistSecondary`, `MobileChartHidden`) | small | low |
| 5 | Move upload (20 cookies) to prefs and form fields; drop the `upload-tabs.js` copy | medium | medium: transfers and presets |
| 6 | Move display-only search, arbit and chart cookies; apply them in the page scripts | medium | low |
| 7 | Read userstate on the server; move Arbitrage, Global, Reverse, Sleepers and Newspaper | medium | medium: render-path read, save waits for sync |
| 8 | Move search and `UploadCustom*` for signed-in readers; signed-out per the decision above | medium | medium: hot path |

**#1008** can become PR 2: make `MTGBAN` and every preference cookie Lax
in one change. That fixes the link-from-Discord case today, and none of
these values is sensitive. `MTGBAN` on its own as Lax is enough only
after PR 8, once no first render reads a preference from a Strict cookie.
