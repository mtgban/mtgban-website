# iPhone and iPad Safari in the iOS Simulator

Claude Code drives the simulator with its iOS Simulator tool, whose actions
(`attach`, `open_url`, `tap`, `rotate` and so on) are named below;
`xcrun simctl` covers the rest. The maintainer's Mac has Xcode 16.4 with the
iOS 18.6 runtime. List the devices with `xcrun simctl list devices
available`.

| Device | Points | Screenshot scale |
|---|---|---|
| iPhone 16 | 393x852 | 3x |
| iPad (A16) | 820x1180 | 2x |
| iPad mini (A17 Pro) | 744x1133 | 2x |
| iPad Air 11/13, iPad Pro 11/13 | | 2x |

Taps are in points: a screenshot pixel divided by the scale. The tool
reports the frame of each screenshot, so read the factor from that.

## Getting started

- `attach` with `device: "<name>"` first. It boots the device and opens
  the panel. Pass `device` on every call when more than one is booted.
- Open a URL with `open_url`. To keep a signed link out of the transcript,
  use `xcrun simctl openurl <udid> "$(cat <file>)"`. On a freshly booted
  device the first open lands on Safari's start page; run it again.
- Sign in by opening the admin link once. It sticks for that tab group only.
- Simulator Safari reaches a local dev server at `http://localhost:<port>`.

## Quirks that cost time

- **Normal and Private tab groups alternate.** On this setup `open_url` and
  `simctl openurl` alternate between Safari's normal and Private groups,
  which have separate cookies and localStorage. You get signed in in one,
  signed out in the other, and in different views. Make each URL carry what
  it needs (the local harness below), or accept the alternation and check
  the screenshot. On iPad each `open_url` opens a new tab in the same group.
- **A page can change under a tap.** The page from one `openurl` can
  surface after you tap for another: one tap opened a store's site.
  Screenshot after every URL settles, then tap.
- **Taps get eaten.** The first tap after a load often does nothing. Tap,
  screenshot, then tap again if nothing happened.
- **The address bar is unreliable** (taps eaten, text cut). Use `open_url`.
- **Rotation turns screenshots sideways.** `rotate left|right` works, but on
  iOS 18.6 landscape screenshots come back portrait-shaped with the content
  turned 90°. Tap in that sideways frame as is: the point you read off the
  screenshot is the point to tap. Rotate back when done.
- **The keyboard.** `set_keyboard hide` refuses until the device has a
  stored setting. Tap the keyboard's own dismiss key instead (bottom right
  on iPad). The simulator raises the keyboard for autofocused fields on
  every load; real iOS usually doesn't.
- **Swipes.** A drag starting within 4pt of an edge is a system gesture.
  Start further in. A sideways swipe on page content is how to prove the
  page pans.
- **Theme.** `set_appearance dark|light` switches the device, and the site
  follows it when its theme is "system". Switch back afterwards.
- **Settings.** `open_url App-prefs:SAFARI` opens Safari's settings.

## What Safari paints, and how to check it

- **iPhone:** the status-bar strip and the bottom toolbar take
  `<meta name="theme-color">`. Without one they fall back to the manifest's
  `theme_color`, and with neither iOS 18 draws its own grey; it doesn't
  sample the page. `color(srgb …)` (what `getComputedStyle` returns for
  `color-mix`) is accepted. The toolbar changes as soon as the meta does,
  including on a live switch to dark.
- **iPad:** the whole toolbar (status bar, tabs, address bar) takes
  theme-color, but only with **Settings > Apps > Safari > Tabs > Compact
  Tab Bar** ("Show Color in Compact Tab Bar" is on by default). The default
  Separate Tab Bar ignores it. To check: open the settings, pick Compact,
  load the site, screenshot. Then put Separate back.
- **Tiers:** a tier can't be faked here, because there's no JS. Check
  theme-color per tier in the pane or on Android, then just confirm on
  Safari that the strip follows the meta.

## Views and numbers without a console

- **Switching view on the device:** `open_url` to
  `/toggle-mobile?redirect=%2Fsearch%3Fq%3D...` *flips* the `MobileView`
  cookie. An `open_url` that timed out during first boot can run later and
  flip it back, so check the screenshot. Cookies are per host, so every
  localhost port shares `MobileView`; localStorage (the theme) is per port.
- **The monitor icon** in the mobile navbar is the theme toggle, not the
  view switch.
- **Getting numbers out of Safari** on a local build: add a fixed readout
  `<div>` and a `setInterval` script to a throwaway tree's navbar partial
  (inside its `{{define}}`, before `{{end}}`). `-dev` reloads it. Static
  probe pages can be served from the scratchpad with
  `python3 -m http.server`.
- **Zoom skews heights.** A page zoomed by a small autofocused field has
  `visualViewport.scale` above 1. A 15.2px navbar box gave 1.05,
  `innerWidth` 374 and a `100dvh` panel 5% past the screen. Read the scale
  before trusting any height.

## Behaviour to test

- **Zoom on focus:** iOS zooms into a focused text field under 16px and
  stays zoomed. Tap the field and screenshot. Selects don't zoom on iOS 18.
- **iPad gets the desktop site** (Mac UA). The iPad mini at 744 is under
  the 768 breakpoint, so it gets desktop templates with phone CSS: sweep it
  on its own.
- **Search on iPad:** portrait (820) has no sidebar; landscape (1133/1180)
  has the card sidebar and a narrower results column. Check store names and
  badges there.
- **Hover-only UI:** tap a row that has a hover preview (Arbitrage, Upload,
  Newspaper). The preview should appear at the tap and go on the next tap.
- **Sideways pan:** swipe left on a page that the pane says overflows
  behind `overflow-x: clip`.

## Local mocks (never committed)

For comparing designs or testing an unmerged branch on a device:

- **Worktree:** a temporary one under
  `~/src/claude-scratchpad/worktrees/mtgban-website/<task>`.
- **Server:** run it from that worktree with `-dev -noload -nonews`, a
  minimal config, and its own port. Safari caches CSS by URL (`?hash=` is
  the commit), so after editing CSS serve on a new port or the old sheet is
  used.
- **Harness:** add a throwaway `js/zz-mock.js` before `</body>` in the base
  templates. URL parameters make every `open_url` self-sufficient:
  - `?view=desktop|mobile` sets the `MobileView` cookie and reloads if the
    page came up in the other view.
  - `?tier=Legacy` signs in a dev reader by setting
    `BAN_SIG = base64(UserEmail=..&UserTier=..&Expires=..)`; dev mode
    accepts any decodable signature. Guard the reload with sessionStorage
    so it happens once.
  - A variant parameter (`?tc=a|b|c`) for each design option, so one
    server shows them all.
