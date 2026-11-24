# ADR-0010: Cards, the swipeable search on phones

**Status:** Proposed
**Date:** 2026-11-22
**Deciders:** Vittorio Giovara
**Change:** PR #1538

## Context

On a phone a search result is a long list. Each card is a header row (set
symbol, name, set and number, badges, buttons) and under it the store rows,
behind a Sellers/Buyers tab in the compact layout or both lists one after
the other in the expanded one. Comparing two printings means scrolling past
every store row of the first, and the card's picture is behind a tap (the
image drawer).

What the phone page already has, and this decision builds on:

- **Mobile templates go to phones only.** `isMobileRequest` (mobile.go)
  gives tablets the desktop page unless the reader sets `MobileView`.
- **Every row is in the page.** The server renders both lists for every
  card (the sellers and buyers `m-tab-panel`s, every condition group), 25
  cards a page. A layout decides which of them shows where; nothing more is
  fetched. A card with no offers on one side renders no panel for it.
- **The layout was a setting.** `MobileSearchLayout` chose `expanded` (the
  default) or `compact`, with `SearchDefaultTab` and `SearchDefaultView`
  picking what the lists opened on. The settings drawer wrote the layout on
  every save, `expanded` when the reader never touched it, so a stored
  value said little about what anyone chose.
- **Landscape already shows everything.** Under `orientation: landscape`
  each card is image | sellers | buyers, with no tabs.
- **Main-thread work shows as lag on iOS.** #1522 traced typing lag to
  repaint work. Script on `touchmove` runs on the main thread; native
  scrolling does not.

## Decision

1. **Cards is the only phone layout.** The expanded and compact lists go,
   and with them the settings that chose among them: `MobileSearchLayout`,
   `SearchDefaultTab` and `SearchDefaultView`, their drawer controls, the
   synced `mtgban_search_layout`, and the tracking names of the tabs and
   condition pills. A cookie a reader still carries is ignored. One layout
   is one thing to keep working; a choice whose stored values mostly
   recorded no choice was not worth keeping beside it.
2. **One card fills the results area.** At the top the result count and
   the sort buttons share one line, the count giving way to the buttons on
   a narrow screen. Under them one card at a time: the card's header row
   (set symbol, name, set and number, badges, promo types, and the ⋮
   menu), which stays put above the picture and both lists, and the
   picture filling the rest, its corners rounded as the desktop's. The
   search bar is at the bottom of the screen, within reach of a thumb, and
   stays fixed while the cards move up and down; it slides down out of the
   way once a swipe has gone a little way toward a list, so the list has
   the whole height, and back up once one has gone a little way onto the
   picture, so a finger's small reversals don't flicker it; from the sales
   back to the buyers it stays down. The picture keeps room for it. Above it, the picture's best ask
   at the left edge and its best offer at the right, the favorite,
   backpack and chart buttons between them, each edge with an arrow toward
   its list and its price under its label: the first priced, unlocked row of
   the first condition that has one, NM when there is one, as the rows
   already rank it after the reader's store factors. Where a side has rows
   but none priced and unlocked, its edge names the list without a price.
   Both are buttons that open their list, so the lists are reached
   without a swipe as well (iOS takes a swipe from the left edge as Back,
   Android's gesture navigation both edges), and by keyboard and
   VoiceOver.
3. **Up and down move between cards; left and right open its lists.**
   Swiping right brings the card's sellers in from the left, swiping left
   brings its buyers in from the right, as the desktop table puts sellers
   before buyers; swiping back returns to the picture. A card with
   TCGplayer orders on record has its recent sales one swipe past the
   buyers, the desktop's Sales table (ADR-0009), or one swipe before them
   where the reader's Buyers column opens on Sales, as it does by default
   on Pokemon; the sales are fetched the first time any card is swiped
   24 px off its picture towards them, a list early where the buyers come
   first, so they are there when a swipe lands on them.
   A card with only one side has two panes. A list shows every condition
   group with its heading, is headed with its name under the card's
   header, centred between arrows to the list or picture on either side,
   and scrolls inside its pane when it is taller than the screen.
   While a list is open, up and down scroll that list and stop at
   its ends; moving to another card starts from the picture, and every card
   opens on its picture. A flick moves one card, not several; to go
   further at once, a thin scrubber on the right edge, as long as its cards
   allow and centred on the deck, jumps
   straight to the card at the point tapped or dragged to, without the
   scroll in between, naming its set and number ("TRC #499") while
   dragging. Under the last card one more swipe raises a drawer over the
   card's foot, the card staying where it is: "End of results" on the
   last page, then the pager and the notices, where there are any; a swipe
   down lowers it. There is no empty slide.
4. **Native scroll snapping, one gesture in code.** The results area is a
   vertical scroller, `scroll-snap-type: y mandatory` with
   `scroll-snap-stop: always`; each card is a horizontal scroller,
   `scroll-snap-type: x mandatory` over its panes, sellers | picture |
   buyers | sales, with the same stop on the picture, the tools under it and
   each list, so a sideways flick moves one column too and never passes the
   picture by, as a hard one otherwise does on Android. The results area
   contains its overscroll, which also keeps Android's pull-to-refresh off the
   deck; a list contains its own up and down only, since Chrome would
   otherwise drop the sideways swipe out of a list that scrolls. The search
   does not zoom: `touch-action: pan-x pan-y` stops it on Android, and iOS,
   which pinch-zooms regardless, has its gesture events cancelled. Script does
   only what CSS cannot: put each card on its picture, inline right after the
   cards so the sellers pane never paints first, and again after a rotation
   or resize; remember in the history entry which card the reader was on
   and return there; scroll to a list when its edge price is tapped; slide
   the search bar down or up by the way the card in view is moving, a
   class it sets when that changes; move the deck to the card the
   scrubber points at, and its thumb to the card in view; fetch the sales
   as a card first heads their way; close the ⋮ menu when the deck scrolls.
   The one gesture it reads is the pager's: a vertical swipe of 40 px on
   the last card raises the drawer and a swipe down lowers it, since the
   deck has no slide past that card to snap to; while it is up the deck
   does not scroll, so the script takes every swipe: a sideways one folds
   the drawer away with the search bar and moves the card one list over.
5. **The results area is the scroller, sized by flex.** In Cards the page
   below the fixed navbar is a column: sort row, the optional Contents
   row, then the results area taking the rest, with the search bar fixed
   over its foot, or under it when there are no cards. The chrome's height
   varies (the Contents row), so nothing is computed from it; the search
   bar's own height, which the picture keeps free, is that of its
   fixed-size controls, and the pinned-filter row floats above the bar like
   the pager's drawer, its fixed height kept free too and sliding away with
   the bar. The search landing on a phone has the same shape:
   as many recent searches as the screen holds, then the favorites, above,
   the search bar at the bottom.
6. **A list is the desktop table.** Each pane holds the desktop's Sellers
   or Buyers column, drawn from one partial
   (`templates/partials/search-columns.html`) and styled by one stylesheet
   (`css/search-rows.css`) that the desktop search, the shared favorites
   and the offline page load as well: condition headers, store links,
   price, quantity, the buylist ratio or credit column, locked rows,
   velocity, CK signals and their tooltips. Two copies of the rows would
   drift; one table is one thing to change. A pane is a results area of
   its own width, so at phone width it folds as a narrow desktop column
   does: the price columns close up to one and the store names keep their
   room. What follows a price stacks under it, a buyer's ratio, credit and
   quantity included, and the row grows to hold them; desktop's band hides
   those behind the row's tooltip, which a touch screen cannot open. The
   phone's own row markup and
   its tap-to-open details go from search. The card itself keeps the phone
   header (`m-card`, `m-layout-cards`); what is new is small: the edge
   prices, the list headings, a wrapper for the results area, the last
   slide. The image drawer the card's name opened goes, since the picture
   is on screen.
7. **Pictures.** The first two load eagerly, the rest lazily. A sealed
   product shows its product picture; a missing picture falls back as it
   does today (card-art-fallback.js); a content-warning picture keeps its
   tap to reveal.
8. **Portrait only.** In landscape a Cards page uses the landscape grid the
   phone page already had, picture and both lists side by side, with each
   list's label and condition headings; the edge buttons and the sales are
   hidden there.
9. **Desktop and tablets are unchanged.** A tablet gets the desktop page
    and keeps it: one card per screen wastes a wide display, and the
    desktop table compares more stores at a glance. A tablet reader who
    switches to the mobile view gets Cards too, which has to hold up at
    768px.
10. **Out of scope:** the offline phone page (`templates/mobile/offline.html`),
    which renders the phone's own rows in script and keeps their CSS in
    `search-mobile.css`, and the sealed landing page.

## Alternatives considered

- **A gesture library or touch handlers** (Swiper and the like).
  Rejected: a dependency or a few hundred lines of script on every
  `touchmove`, redoing the momentum and axis lock the browser does, on the
  platform where main-thread work shows as lag.
- **A template of its own, or rendering from JSON.** Rejected: a second
  copy of the store rows that would drift from the first.
- **The phone's own row style in the panes.** Rejected: a second look for
  the same table, with its own CSS and markup to keep in step with
  desktop's.
- **Swiping instead of the tabs in the list layouts.** Rejected: a sideways
  swipe inside a vertically scrolling list is easy to trigger by accident.
- **Cards beside the lists, as a third layout.** Rejected: it kept three
  layouts working and a setting most readers had stored without choosing,
  for readers who could no longer tell which one they had.
- **Cards on tablets and desktop.** Not now (decision 9).

## Consequences

- Every phone reader gets the new layout at once, with no way back to the
  list.
- A page can hold 25 full-size pictures. They load as the reader swipes.
- A page's lists hold thousands of elements, and laying all of them out cost
  a swipe its frames in Safari, so each skips its rows until it is near
  (`content-visibility`). The pane gives it its size, so nothing moves when
  they come in.
- Nested snapping (vertical outside, horizontal inside, a scrolling list
  inside that) is the risk, proven in iPhone Safari before it ships, along
  with the ⋮ menu, which is fixed-position
  inside the scrollers, and the overlays above the deck (filter sheet,
  settings, chart and alert modals).
- The centring runs inline right after the cards, not from a script file:
  page scripts are deferred (`tests/defer-scripts.test.js`), and a
  deferred one runs after the first card has painted on its sellers pane.
- Visual order (sellers, picture, buyers) differs from DOM order (header,
  picture, sellers, buyers). The panes carry labels, and the edge buttons
  are the route for assistive technology. Scrolling to a list is instant
  under `prefers-reduced-motion`.
- `ui.cards.pane` counts the lists a reader opens, by tap, swipe or a
  list heading's arrow, and the arrows back to the picture, in place of
  `ui.row.tab`, `ui.row.condition` and `ui.row.detail`, whose rows are
  gone; `search.view` keeps only the listing priority and the sealed
  contents.

## Open questions

1. **Page size.** 25 as now. Every slide carries a picture and both full
   lists; the pane counts will show whether readers reach the pager.
