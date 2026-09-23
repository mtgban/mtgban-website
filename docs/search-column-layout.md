# How the search page's two columns are laid out

The search page is a two-column grid: a fixed sidebar holding the card and
its boxes, and a scrolling results column. Almost every rule in
`css/search.css` that sets a height, a top or a padding on either column is
load-bearing for something non-obvious, and several of them have been
"simplified" into bugs more than once.

This is the design and, more importantly, the reasoning — the numbers are
easy to re-derive, the reasons are not. `tests/offline/search-sticky-offsets.test.js`
pins the parts that can be checked without a browser; this file covers the
rest.

## One line governs the top of the page

A result header is `position: sticky` under the navbar, and
`.result-header-cover` paints the band between the two so nothing shows
through as a header pins. Three separate things have to agree on where that
line is:

| what | rule | must be |
|---|---|---|
| where the results column starts | `.search-layout` `margin-top` | `--nav-height` (the negative margin removes `--content-padding-slack`) |
| where the fixed sidebar starts | `--search-sidebar-top` | `--nav-height`, *without* the slack |
| the column's top padding | `.search-results` `padding-top` | `--result-cover-height` |

**A sticky offset never moves anything else.** A header whose static
position sits *above* its own sticky `top` is painted lower than the space it
left behind, and covers whatever follows it — the variant row — by exactly
that difference, permanently, from load. That was an 11px fold: the column
padded 10px against a header offset of `nav + 21px`. The padding and the
cover's height are one token now so they cannot drift apart.

The tempting fix for the two columns not lining up is to add the slack to
`--search-sidebar-top`. That lines them up by pushing the results column down
into the drift instead, giving every header that much scroll to travel
through before it catches. **Bring the sidebar up to the line, never the
results column down to meet it.**

## The site footer runs under the results, not across them

The sidebar is `position: fixed` and reaches the viewport bottom, so a
full-bleed footer crosses it at the end of every page. That used to be paid
for by reserving a strip the sidebar stopped short of, plus a `z-index` to
win where they still met — 90px of column given up at every scroll position
to protect one.

The footer is indented past the sidebar column instead
(`margin-left: calc(var(--search-sidebar-left) + var(--search-sidebar-width))`),
so the two never meet and the sidebar takes its full height.

`--search-footer-reserve` still exists, doing its *other* job: the grid's
floor is what the document must reach, and the footer comes after it, so
flooring the grid at the whole viewport pushes the footer below the fold by
its own height on every page with room to spare. 64px covers the two-line
case at the narrow end of this layout, where the indented column wraps the
disclosure sooner. **If the footer ever goes full-bleed again, the sidebar's
height has to give the strip back.**

`--search-sidebar-left` / `--search-sidebar-width` are declared once on
`body:has(.search-layout)`, which the grid, the fixed sidebar and the footer
all inherit from. Three copies of the same centring arithmetic could drift
apart silently.

## The sidebar is a stack that degrades in a stated order

Three boxes on one 8px gap: the card and its edition icons, Available In,
then Export/Upload.

**The card never resizes.** It is the one thing here that cannot be made
smaller without making it worse, and because a replaced element's size is
content-driven, shrinking it happens in jumps rather than smoothly. It is
`flex: 0 0 auto`.

What gives, in order:

1. **Available In shrinks.** Its 8em list cap is gone, so it takes whatever
   room the column has and scrolls inside itself.
2. **Available In collapses to its title bar** below a threshold. It is not
   removed: `AVAILABLE IN 7` still answers how many products there are, and
   presses open over Export for as long as it is open.
3. **Export goes**, and only when its own two rows cannot both be drawn.
4. **The column scrolls**, with a visible scrollbar. A hidden scrollbar on a
   cut-off list is exactly what reads as a bug.

### Why the thresholds are each box's own requirement

What else is in this column varies with the card — one result has a single
"Show all versions" link above these, another has three, plus Switch
Foil/Etched and MTGStocks. A threshold set for the busy case hides a box that
would have fitted comfortably in the quiet one; erring the other way costs at
worst a short scroll, which is reachable. So each threshold is what *that
box* needs, not a guess at the whole stack.

The one exception is Available In's, which is set above its own requirement
on purpose: shown at exactly its floor, the column has to scroll to hold it,
which is worse than not showing it at all.

### The one literal

`.sidebar-products-card` has `min-height: 78px` — its title bar plus about two
rows. It cannot be derived: `auto` and `min-content` both floor a flex item at
its **whole** content (every product the card knows, which pinned the card at
221px and made the column scroll 200px), and `auto` is collapsed to zero
anyway by the box's own `overflow: hidden`. Without a floor the box shrank
past its content to the 2px of border left over — the same "clipped sliver"
the collapse exists to prevent, reached from the other side.

### `container-type: size` on `.sidebar-body`

The body is a size container so the boxes inside can be told how much room is
left under the card. `flex: 1 1 auto` with a basis that size containment fixes
at 0 means it is never anything but the leftover: it does not ask for room of
its own, and hiding something inside it cannot change its height, so there is
no loop between the queries and what they hide.

### Specificity

Every rule in the desktop stack is written from `.search-sidebar` rather than
on the class alone. The shared rules they override — the Available In card's
8em list cap among them — sit further down the file, so matching their
specificity would lose to them on source order.

## Floating panels are placed against the viewport

The editions overflow panel (`+52`) is `position: fixed`, placed by the script
that opens it.

**`overflow: hidden` makes a box a scroll container.** The panel used to hang
below the symbol row, absolutely positioned, which counted as
`.sidebar-pinned`'s scrollable overflow; focusing the panel's filter then made
the browser scroll that box to "reveal" it, carrying the card up out of the
column with no scrollbar to bring it back (`scrollHeight` 565 → 727,
`scrollTop` 18.5 on open). The panel's own lower half was clipped by the same
box.

Every box between such a panel and the viewport either is a scroll box or can
become one, so **the viewport is the only ancestor that cannot clip it** — and
placing it from script means it gets the room that is actually there rather
than a number guessed from the card's height. Focus is taken with
`preventScroll`, and `.sidebar-pinned` no longer clips what it has no need to
clip.

## Icon placeholders reserve the icon's box

The server renders `<i data-lucide="…">` and the bundle swaps it for an `<svg>`
a frame later. An unsized placeholder is a 0×0 box, so the row lays out at the
wrong size and jumps when the swap happens — the SORT row was 16px shorter and
its label 8px higher; the result star, whose row is right-aligned, slid the
whole strip 24px sideways.

**Every rule that sizes one of these icons must size its placeholder in the
same selector list**, which is the only way the two cannot disagree. The star
is the exception: its own selector out-specifies anything the narrow layout
could reasonably write, so the size travels as an inherited custom property
(`--qi-icon-size`) instead. A first attempt without that traded a 24px jump
for a 4px one in the other direction.

This reserves the room; it does not make the icons arrive sooner. The slots
are empty until the bundle lands, they just no longer shove anything.

## Measuring this

Eyeballing does not work here — several of these bugs are a handful of pixels,
and two of them were mis-diagnosed from screenshots before being measured.
Useful method:

- Read `getBoundingClientRect()` and `getComputedStyle()`, not the rendering.
- For "did I regress this?", load the previous stylesheet into the live page
  and re-measure the same points. That is how the padding under the results
  was shown to be identical to what it had always been.
- For jump-on-paint, swap the `<svg>` back to an `<i data-lucide>` and compare
  geometry; identical numbers either way means no jump.
- Sweep the sidebar's height (`.search-sidebar { height }`) rather than the
  window when checking the degradation order — it is the input the layout
  actually reads, and it can be stepped finely.
- The dev server serves `search.css?hash=` with an empty hash and
  `Cache-Control: max-age=86400`, and that URL never varies. A plain reload
  shows the old stylesheet. Hard-reload, or bust the query string.
