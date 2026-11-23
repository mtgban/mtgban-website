# Measuring in a desktop browser

Written for Claude Code's browser pane (`javascript_tool`, `navigate`,
`resize_window`, `tabs_create`); any Chrome with a JS console works the
same way.

## Loading the sweep

The pane can't read local files, so:

1. Run `pane-bundle.sh <out.js>` and Read the output.
2. Paste the whole thing into `javascript_tool`.

The bundle defines `window.__probe` (probe.js as a string), `__sweep`,
`__issues` and `__run`. They live on `window`, so any navigation of the
pane's tab drops them: paste again after navigating.

Open the pane on a page of the target origin first (`navigate` to
`https://mtgban.com/`, or the local dev server), because the sweep's iframe
must be same-origin for `contentWindow.eval`.

## Short checks (under 45 s)

```js
__issues(await __sweep(393, 852, ['/', '/search?q=Sol+Ring', '/user']))
```

Set the view first with the cookie: `document.cookie = 'MobileView=true;
path=/; max-age=31536000'`. The pane itself is a desktop browser, so without
the cookie every width gets the desktop view.

## Long sweeps

```js
__run([
  ['desktop', 1920, 1080], ['desktop', 1440, 900], ['desktop', 1280, 800],
  ['desktop', 1180, 820], ['desktop', 1133, 744], ['desktop', 820, 1180],
  ['desktop', 744, 1133], ['mobile', 393, 852], ['mobile', 375, 667],
  ['desktop', 393, 852],
], PATHS)
```

- **Results:** `window.__res`, one entry per size, keyed
  `'desktop 1180x820'`. `window.__done` turns true at the end.
- **Waiting:** a hidden pane throttles timers, so ten sizes of 16 pages
  take about 15 minutes. Start a background `sleep 240` and read `__res`
  when it fires; don't poll in a loop.
- **The pane's tab:** `__run` holds it. Open a second tab (`tabs_create`)
  for anything else that needs a page meanwhile.

`PATHS` for a full pass:

```js
['/', '/search?q=Sol+Ring', '/search?q=Lightning+Bolt', '/sets', '/sealed',
 '/newspaper', '/newspaper?page=greatest_decrease_buylist', '/newspaper?page=syp',
 '/screener', '/upload', '/arbit?source=CK', '/global?source=CK',
 '/reverse?source=CK', '/sleepers', '/alerts', '/user', '/api-plans', '/guide']
```

The mobile view has no Arbitrage, Global or Reverse page of its own: those
serve the desktop page. The Screener and Upload have no mobile template
either, and render in the mobile layout.

## Headless Chrome: the fast way to sweep many sizes

A hidden pane throttles its timers to minutes per size. A headless desktop
Chrome over DevTools runs the same bundle unthrottled:

```bash
SC=<scratch dir>
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless=new \
  --remote-debugging-port=9333 --user-data-dir=$SC/hc --no-first-run about:blank &   # in the background
# sign in: the admin link sits in a 0600 file and goes in through a generated
# script, so it never appears in a command line or the transcript
LINK="$(cat $SC/adminlink)" python3 -I -c 'import json, os; print("location.href = " + json.dumps(os.environ["LINK"]) + "; 1")' > $SC/goto.js
CDP_PORT=9333 python3 -I docs/agents/device-check/android-cdp.py -f $SC/goto.js; rm $SC/goto.js
docs/agents/device-check/chrome-sweep.sh https://mtgban.com \
  'desktop:1920x1080 desktop:1440x900 desktop:1280x800 desktop:1180x820 desktop:1133x744 desktop:820x1180 desktop:744x1133 mobile:393x852 mobile:375x667 desktop:393x852' \
  / '/search?q=Sol+Ring' /user ...
```

- **Speed:** ten sizes of 18 pages take about six minutes.
- **Output:** each size prints one JSON line.
- **Small inputs:** dropped from the output, because desktop Chrome has no
  touch at any width. Check those on Android or the simulator.
- **Cleanup:** when done, close Chrome (`pkill -f 'remote-debugging-port=9333'`)
  and delete the profile directory and the link file.

## Interactive state the probe doesn't open

The probe measures the page as it loads. Menus and drawers need opening by
hand in the iframe before measuring:

```js
const d = document.getElementById('__f').contentDocument;
d.querySelector('.screener-editions').open = true;          // a <details>
d.getElementById('tools-btn').click();                       // a dropdown
const r = d.querySelector('.screener-editions-menu').getBoundingClientRect();
```

Check the control is reachable at that width first. At 393 in the desktop
view the Tools button is 0 wide, and the ☰ opens `#mobile-menu` instead: a
Tools dropdown that measures off-screen there is not a bug.

## Is a reported overflow real?

- **`sw > W`:** find the element. Hide candidates one at a time
  (`el.style.display = 'none'`) and re-read
  `document.documentElement.scrollWidth`. If none of the elements past the
  edge sits outside a scroll box, look for `position: absolute` descendants
  inside one (the `.user-hidden` case).
- **`html`/`body` with `overflow-x: clip`:** the pane won't let you scroll
  to the overflow, but iOS pans and Android widens its layout. Confirm with
  a sideways swipe in the simulator, or with `innerWidth` on Android.
- **A table that seems to fit:** check the wrapper's computed `overflow-x`.
  `hidden` means a reader can't reach the clipped columns even though
  `scrollLeft` moves in script.
- **A box 1-4px wider than its content (`769/773`):** a near-miss. Mention
  it, but it's rarely worth a PR.

## Proving a fix on the live page

```js
const d = document.getElementById('__f').contentDocument;
const before = d.documentElement.scrollWidth;
const s = d.createElement('style');
s.textContent = '.user-compare { position: relative; }';
d.head.append(s);
({before, after: d.documentElement.scrollWidth})
```

- **Markup changes:** mimic them in the DOM before adding the CSS. For
  example, wrap bare text nodes in the element the template will now emit.
- **Comparing many pages:** run the probe before and after on each, and
  compare the totals that should not move too (summed row heights, page
  width).
- **A whole stylesheet:** `fetch` the live sheet, apply the diff as a text
  replace, and swap its `<link>` for a `<style>` holding the result.

## Things the pane gets wrong

- **No touch at >= 768px.** `resize_window` below 768 emulates an Android
  phone (UA, touch, `pointer: coarse`); at 768 and up it doesn't. So
  `@media (pointer: coarse)` rules are off at tablet sizes, and "small
  input" reports there are false.
- **Stale pages.** A page loaded before a deploy keeps its old HTML and JS.
  Reload it or use a new tab before reading anything the deploy changed.
- **Screenshots are scaled.** A hidden pane can still be screenshotted, but
  `zoom` regions use the scaled frame the screenshot reports.
- **Leftover state.** Reset the viewport (`resize_window` preset `desktop`)
  and the `MobileView` cookie when done.
