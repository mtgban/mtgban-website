# Device check: phones, tablets and every width

How to check the site on the browsers readers use (iPhone and iPad Safari,
Android Chrome, desktop at every width), and how to tell what a reader hits
from what a tool merely reports. Expect both: a table that hides its last
columns on every tablet, and a "menu off-screen" that is a closed dropdown
nobody can see. Each finding gets a number or a screenshot behind it.

The tools and scripts named here are the ones on the maintainer's Mac. For
Claude Code, the browser is the built-in browser pane (`javascript_tool`,
`resize_window`, `tabs_create`) and the simulator is its iOS Simulator tool;
another agent uses its own equivalents. The scripts beside this file are
plain bash, Python 3 (stdlib) and JS.

Three tools, three jobs. None replaces the others:

| Tool | Answers | Can't |
|---|---|---|
| A desktop Chrome you can run JS in | Layout at any width, measured: overflow, clipping, scroll boxes, sizes, computed colours. Dozens of pages a minute. | Real touch at >= 768px, Safari's chrome, iOS zoom-on-focus, the keyboard |
| iOS Simulator (Safari) | What only Safari does: status-bar strip and toolbar colour, zoom on focus, keyboard, sideways panning, iPad's desktop UA, rotation | Run JS. No console, so no numbers: screenshots only |
| Android emulator (Chrome) | Real Android Chrome, **with JS** over DevTools: layout viewport, toolbar colour, keyboard, touch | Safari anything |

## 0. Before measuring

- **Sync first.** `git fetch origin` and fast-forward `master` before the
  first measurement. Work in your own worktree, never the main checkout.
- **Know what's deployed.** Live serves `?hash=<commit>` on every asset:
  `curl -s https://mtgban.com/ | grep -o 'hash=[a-f0-9]*' | head -1`, then
  compare with `git log origin/master`. A merged PR isn't live until it is
  deployed. Say which commit a finding was measured on. When checking a fix,
  `curl` the live CSS for the rule (`curl -s https://mtgban.com/css/news.css
  | grep -A5 '^.news-table-wrap {'`) rather than trusting a merge.
- **Sign in without exposing the signature.** Pages past the landing page
  need a signed reader (Newspaper, Arbitrage, Upload and so on). The admin
  link comes from the maintainer, or from `BAN_SIG` in go-mtgban's `.env`.
  Write it to a 0600 file in a scratch directory and pass it by
  `$(cat file)`. Never echo it or write it into a command by hand. Delete the file when done. The admin link
  carries **no tier**, so its bar is the untiered one; fake a tier where
  colour matters (section 4).
- **Ask before installing.** The Android emulator is ~2.3 GB of downloads
  plus accepting Google's SDK licence: both need the maintainer's yes. The
  iOS Simulator needs Xcode with an iOS runtime.
- **Leave devices as you found them.** Restore light mode, Safari's tab
  layout, rotation, the browser's viewport and its `MobileView` cookie.

## 1. Which devices, which widths

The site has two template sets (desktop, mobile), picked by the server from
the user agent unless the `MobileView` cookie says otherwise, and CSS
breakpoints inside each. A full pass covers:

| Device | CSS size | Gets | Why it matters |
|---|---|---|---|
| iPhone 16 | 393x852 | mobile view | the main phone |
| small iPhone | 375x667 | mobile view | tightest common phone |
| Pixel 8 | 412x784 | mobile view | Android Chrome |
| phone, desktop view | 393 | desktop view | readers who tap the desktop switch |
| iPad mini portrait | 744x1133 | **desktop view under the 768 breakpoint** | desktop templates with phone media queries on: unlike any other device |
| iPad portrait | 820x1180 | desktop view | iPad Safari sends a Mac UA |
| iPad mini / iPad landscape | 1133x744, 1180x820 | desktop view | search's sidebar appears |
| laptops | 1280, 1440, 1920 | desktop view | a fix scoped to phones can break these |

Sweep every one in the browser (section 2), then put the real devices on what
the sweep can't see (section 3).

## 2. The sweep: every page, every width, measured

`probe.js` turns a page into numbers:

- `sw` against `W`: document width against the viewport. `sw > W` means the
  page overflows sideways.
- `off`: visible elements past a viewport edge with no scrolling ancestor.
- `clipped`: leaf text cut by an `overflow: hidden|clip` box. This catches a
  control clipped inside a card, which a page-width check misses.
- `scrollers`: boxes with content to scroll sideways.
- `small`: text inputs under 16px.

It skips anything hidden by an ancestor (opacity 0, closed `<details>`).

In the browser, run `pane-bundle.sh` and paste its output into the JS
console (Claude Code: `javascript_tool`) on any page of the site. It
defines:

- `__sweep(w, h, paths)`: loads each path into a same-origin iframe of that
  size (media queries follow the iframe) and probes it.
- `__issues(results)`: keeps only the entries worth reading.
- `__run(plan, paths)`: the same over many sizes, in the background.

Claude Code's `javascript_tool` gives up after 45 s, so `__run` starts a
sweep in the background; read `window.__res` once `window.__done` is true.
A hidden pane throttles its timers, though, to minutes per size.

For more than a few sizes, use `chrome-sweep.sh` instead: it runs the
same bundle in a headless desktop Chrome over DevTools, with no 45 s limit
and no throttling (ten sizes of 18 pages in about six minutes, against an
hour in a hidden pane). Start Chrome with `--headless=new
--remote-debugging-port=9333 --user-data-dir=<scratch dir>`, sign it in
(recipe in [`pane.md`](pane.md)), then
`chrome-sweep.sh https://mtgban.com 'desktop:1180x820 mobile:393x852' / /user ...`.
It prints one JSON line per size. Recipes, page list and the full false-positive
list: [`pane.md`](pane.md).

On Android, `android-sweep.sh <origin> <paths...>` runs the same
probe inside real Chrome (section 3).

## 3. The devices

**iOS Simulator** (Claude Code: its iOS Simulator tool; otherwise
`xcrun simctl`). Attach or boot first, open URLs rather than typing them,
and take a screenshot after each step. Quirks that cost time:

- Opening a URL alternates between Safari's normal and Private tab groups,
  which keep separate cookies. A sign-in or view cookie set in one is
  missing in the other.
- Taps get eaten after a page load.
- In landscape, screenshots come back sideways; tap in that sideways frame
  as it is.
- Hiding the keyboard by setting refuses until one is stored.

All of it, with the fixes, plus the iPad settings that change what Safari
paints: [`ios.md`](ios.md).

**Android emulator**. Set up once ([`android.md`](android.md)), then for every
session:
`android-boot.sh` boots `mtgban_pixel8` and opens Chrome, closes
every tab but one, and forwards DevTools to `localhost:9222`.
`android-cdp.py '<js>'` evaluates in the page and
`android-sweep.sh` sweeps. It also skips Chrome's first-run terms
screen without accepting the terms on the maintainer's behalf.
Screenshots: `adb exec-out screencap -p > x.png`. To check colours, read
exact pixels with `png-pixel.py x.png 20,200`.

## 4. Reading results: real bugs and false alarms

Shapes to look for, each one this method has found on the site:

- **A box that clips instead of scrolling.** `overflow: hidden` on a table
  wrapper, with `overflow-x: auto` only inside a phone media query. The
  table loses its last columns at every width from the breakpoint up to its
  own width, laptops included.
  Check the wrapper's computed `overflow-x`; `scrollLeft` moves even on a
  hidden box.
- **Absolutely positioned content escaping a scroll box.** Screen-reader
  spans (`position: absolute`) inside an `overflow-x: auto` box that isn't
  positioned take the page as their containing block and widen the
  document. `html { overflow-x: clip }` hides that from desktop. It doesn't
  stop iOS (the page pans sideways) or Android, where Chrome widens the
  layout viewport (`innerWidth` 523 on a 412 phone) and pushes the navbar's
  menu off-screen. Fix: `position: relative` on the scroll box.
- **An ellipsis eating badges.** A name and its badges in one `nowrap` +
  ellipsis box: a long name takes the badges with it. The name needs an
  element of its own that is the only flex item allowed to shrink.
- **A menu hung from a control that wraps.** It anchors to wherever the
  control lands and runs off one side; hang it from the bar instead.
- **Inputs under 16px** zoom iOS on focus and stay zoomed: 16px under
  `@media (pointer: coarse)`.

False alarms to drop before reporting:

- The mobile menu `#m-menu` and favourites toast `#m-fav-toast`, parked
  off-canvas on purpose.
- Card-variant lines and store names ellipsizing on purpose.
- The landing page's popular-searches marquee.
- "Small input" anywhere a desktop Chrome measured it: the pane at >= 768px
  and headless Chrome at every width have no touch, so the `pointer: coarse`
  rules that fix it don't apply. Only a touch device (Android, or the pane
  resized below 768) can report it.
- The simulator raising the keyboard for autofocused fields on every load.
  Real iOS usually doesn't, so don't report it.

Colour (Safari's status strip and toolbar, Android Chrome's toolbar) comes
from `<meta name="theme-color">`, which `js/nightmode.js` sets to the
navbar's computed colour. To check a tier:

1. In the browser or over Android DevTools, set `data-tier="modern"` on
   `.navbar-v2` / `.m-nav`.
2. Call `BANTheme.set('light')`, then `BANTheme.set('dark')`.
3. Compare the meta's `content` with the bar's `backgroundColor`, for each
   tier and each theme.
4. On Android, screenshot and read the toolbar pixel.

## 5. Proving a fix before it deploys

Measure the fix on the live page, before and after, in the same call:

- **Browser:** append the new rules as a `<style>` in the sweep iframe's
  document. To test a whole stylesheet, fetch the live sheet, apply the diff
  as a text replace, and swap the `<link>` for a `<style>`.
- **Android:** inject the same `<style>` through `android-cdp.py`.
- **Markup changes:** mimic them in the DOM (wrap the text node, move the
  element) and measure.

Then make the PR the usual mtgban way:

- **Base:** branch off `origin/master`.
- **Fix:** CSS where layout is the problem, no JS measuring.
- **Test:** a bun test in `tests/` that pins the rule, revert-checked by
  restoring master's file and seeing it fail.
- **PR body:** the before/after numbers from the live page, plus desktop and
  phone screenshots.

[`pane.md`](pane.md) has the recipes.

## 6. Showing results

- Send screenshots as PNG, not HTML: an HTML sheet may not render where the
  reader is (Claude Code: `SendUserFile`).
- `sheet.sh out.png 'Caption' a.png 'Caption' b.png ...` lays
  screenshots side by side through headless Chrome. There's no PIL or
  ImageMagick on this Mac, and `sips` only crops from the centre.
- Findings go in an audit file kept outside the repo (the maintainer's live
  in `~/src/claude-scratchpad/plans/`): what, where, the number, the cause,
  the fix, and the commit it was measured on.
- Lead the report with what readers hit, give each finding its number, name
  the false alarms you dropped, and say what you couldn't check.
