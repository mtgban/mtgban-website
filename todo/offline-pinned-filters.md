# Pinned filters in offline mode

> **2026-09-16 state:** the pinned filter bar ships for online search only.
> `CanScope` is set in exactly one place, `Search()` at `search.go:423`, so
> `/offline` draws no chip and no row — verified on both the desktop and the
> mobile rendering (`nav-pin-btn`/`nav2-scope`/`has-scope`: zero hits). This
> is deliberate, not an oversight: a filter that cannot be seen is one that
> cannot be undone, and half-wiring it offline would be worse than leaving
> it out.

The online bar holds what does not change between searches — a set, a
finish, a rarity — in a field of its own, merged into the search at request
time. Offline search never sees it.

## Why it is not a flag

Offline search is a second engine, not the same code with the network
removed. `OfflineQuery.parse` (`js/offline/offline-query.js`) reads a query
into a flat shape:

    {names: [], set: '', number: '', finish: '', rarity: '', unsupported: []}

and `templates/offline.html` drives it from the url's `q` alone — see the
`URLSearchParams(location.search).get('q')` at both the initial run and the
`popstate` handler, and `buildUrl(q)`, which writes the next url back. A
`scope=` parameter is ignored on the way in and dropped on the way out.

## What wiring it would take

1. Set `CanScope` in the offline handler (`offline_page.go`) so the navbar
   draws the chip and the row. `js/scope.js` is already precached by the
   service worker (`sw.js` `SHELL_URLS`), and `/offline` already loads it
   through `base.html`, so the behaviour comes along for free.
2. Read `scope` beside `q` in `templates/offline.html`, at all three places
   the query is read, and carry it through `buildUrl`.
3. Merge the two parses. Online nothing arbitrates: every pinned filter
   applies on top of the typed ones, and two that cannot both hold answer
   nothing, which the empty page then explains. The flat offline shape
   cannot express that - one `set` field cannot hold two sets - so the
   honest equivalent is to let the pinned value fill a field the typed
   query left empty, and to answer nothing where both are set and differ,
   rather than quietly preferring one:

       if (!primary.set) primary.set = pinned.set;
       else if (pinned.set && pinned.set !== primary.set) return noResults;

   and the same for `number`, `finish`, `rarity`. Names never cross over,
   same as online.
4. Give the offline empty state the escape hatch the online one has: a link
   that reruns the search with `scope` cleared, set apart from whatever else
   the page suggests. Without it a pinned filter that matches nothing in the
   synced sets reads as a broken cache.

## The one real wrinkle

The two syntaxes overlap but are not the same. Checked against
`parseSearchOptionsNG`:

| written   | online             | offline            |
|-----------|--------------------|--------------------|
| `s:sos`   | `edition` filter   | `set`              |
| `f:foil`  | `finish` filter    | `finish`           |
| `r:mythic`| `rarity` filter    | `rarity`           |
| `cn:12`   | number filter      | `number`           |
| `is:foil` | `is` filter        | **unsupported**    |

`is:` is the one that parts, and it is the likeliest thing anybody pins,
since it is what the finish chips and most of the site's own links write.
Either translate the finish values of `is:` into offline's `finish` on the
way in, or steer the placeholder toward `f:` — but note the placeholder is
shared with the online bar, where `is:` is the idiomatic spelling, so the
translation is probably the honest fix.

Until one of those is done, a bar pinned online as `is:foil` would come back
"unsupported" offline, which is the sort of quiet difference that makes
offline mode feel unreliable rather than limited.
