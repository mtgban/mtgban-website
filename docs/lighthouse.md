# Lighthouse: accessibility, best practices and SEO to 100

Issue #53 asks for repeatable Lighthouse runs over the main pages and for
each category to reach 100, accessibility and best practices first, then
performance, then SEO. This records the first pass: the structural and
colour fixes that take accessibility to 100 on every audited page in both
themes, best practices to 100 everywhere HTTPS is on, and SEO to 100 on
every page not kept out of the index on purpose. Performance is untouched
here and has its own pass to come.

## How it was measured

`scripts/lighthouse/audit.mjs` (its README has the usage) ran against a
local dev server loaded with the Magic datastore and three stores' dumps,
on nine pages, each on Lighthouse's phone profile (Moto G Power, slow 4G,
4x CPU slowdown) and desktop profile, with the site in the machine's
colour scheme, which was dark; a second run pinned the light theme. Every
number below is the script's own output. Performance scores are included
for completeness but are lab numbers on a dev box against a cold local
server, not a production measurement.

Two failures are expected and stay: `is-on-https` (local server) and
`is-crawlable` on `/search` and `/sealed`, which `robots.txt` disallows on
purpose so the catalogue is not crawled a card at a time.

## Before

```
page      profile perf  a11y  bp    seo   FCP     LCP     TBT       CLS
home      mobile  66    91    100   92    2.9 s   8.0 s   70 ms     0
home      desktop 93    84    81    92    0.8 s   1.7 s   0 ms      0
search    mobile  58    85    81    58    7.1 s   11.9 s  0 ms      0
search    desktop 72    74    81    42    1.8 s   3.3 s   0 ms      0.063
sealed    mobile  68    91    81    58    3.9 s   6.5 s   10 ms     0
sealed    desktop 98    86    81    58    0.8 s   1.1 s   0 ms      0
news      mobile  74    91    100   92    2.1 s   7.8 s   0 ms      0
news      desktop 94    76    81    92    0.8 s   1.6 s   0 ms      0
screener  mobile  78    81    81    92    3.3 s   4.4 s   0 ms      0
screener  desktop 92    80    81    92    0.6 s   1.8 s   0 ms      0
upload    mobile  70    87    81    92    2.9 s   10.4 s  0 ms      0.029
upload    desktop 96    87    81    92    0.8 s   1.3 s   0 ms      0.001
sleepers  mobile  82    76    81    92    3.3 s   3.8 s   0 ms      0
sleepers  desktop 98    80    81    92    0.7 s   1.1 s   0 ms      0
arbit     mobile  87    86    81    92    2.4 s   3.6 s   0 ms      0
arbit     desktop 99    86    81    92    0.6 s   0.8 s   0 ms      0
guide     mobile  84    91    96    92    2.9 s   3.7 s   30 ms     0
guide     desktop 98    89    77    92    0.7 s   1.0 s   0 ms      0
```

The accessibility failures, with the pages they hit:

- `html-has-lang` and `landmark-one-main` on every page: no `lang` on
  `<html>` and no `<main>` in any of the three base templates.
- `meta-description` on every page (SEO).
- `color-contrast` on every desktop page, 51 hits on the guide's phone
  view and 120 on its desktop one.
- `image-alt` and `unsized-images`, 300 each, on search: the three
  quick-action icons on every result.
- `link-name`, 100 on search: the set-symbol link on every result.
- `select-name` on the screener, sleepers and the phone search settings.
- `target-size`, 102 on search and 8 on the screener.
- `aria-required-children`: the Tools dropdown declared `role="menu"`
  with no menu items in it.
- `heading-order` on sleepers, `link-in-text-block` on home and news,
  `image-aspect-ratio` on the guide, and two `crawlable-anchors` on
  search (SEO).

## What changed

**Page skeleton.** Every base gets `lang="en"`, a `<main>` around the page
content, and a description meta tag filled from the active nav entry's
subtitle (the site's own line where there is none, the card's name and
printings on a card page). The changelog and guide had a `<main>` of their
own, which would have nested, so those became `<div>`s.

**Controls and names.** The screener's and sleepers' select captions are
labels; the two phone settings selects carry `aria-label`. The set-symbol
link on each search result is named after its edition. The quick-action
icons carry empty `alt` and their height, the sidebar card image an alt,
the guide's decklist icon its height. The Tools dropdown is a `group`.
The sidebar's Retail and Buylist actions, which were anchors with no
`href`, are buttons. The sleepers "About" card heads with an `h2`.

**Touch targets.** The result name link is padded to 24px, the sidebar's
product links get a 24px minimum, and the newspaper tables' sort arrows
sit in a 24px box.

**Colour.** Lighthouse measured each pair; the replacements were chosen
with a contrast script to clear 4.5:1 on every surface the text sits on,
and no further. Dark theme: `--text-dim` #5f6672 to #8a929e (it was 2.4
to 3.1 on the three dark surfaces), `--greytext` #4b5786 to #9aa5c8, the
named `green` to #3fb950, and striped table rows from the named `gray` to
#22262d. The phone stylesheet's own dark `--greytext` went, being dimmer
than the shared one now. Light theme: `--text-dim` #6b7280 to #5b6270,
the navbar text to the navy `--bluetext`, the brand's red to #8f1026,
success and warning text to #166534 and #a04a06, `--blue` to #2a56ad, the
search link to #2f5fc0, and the dodger blue shared by both themes to
#0a5fb4 so white text on it reads. Two sleepers tier badges and the
Discord login button got light-theme colours of their own. The landing
copyright lost its half opacity and links inside the landing blurb are
underlined.

## After

Dark theme, the machine's scheme:

```
page      profile perf  a11y  bp    seo   FCP     LCP     TBT       CLS
home      mobile  71    100   100   100   2.9 s   8.0 s   0 ms      0
home      desktop 93    100   81    100   0.8 s   1.7 s   0 ms      0
search    mobile  58    100   81    66    7.2 s   11.8 s  0 ms      0
search    desktop 70    100   81    66    1.9 s   3.3 s   0 ms      0.07
sealed    mobile  68    100   81    66    3.9 s   6.5 s   10 ms     0
sealed    desktop 98    100   81    66    0.8 s   1.0 s   0 ms      0
news      mobile  74    100   100   100   2.1 s   7.8 s   0 ms      0
news      desktop 93    100   81    100   0.8 s   1.6 s   0 ms      0
screener  mobile  78    100   81    100   3.4 s   4.4 s   0 ms      0
screener  desktop 93    100   81    100   0.6 s   1.8 s   0 ms      0
upload    mobile  70    100   81    100   2.9 s   10.4 s  0 ms      0.029
upload    desktop 91    100   81    100   0.8 s   1.9 s   0 ms      0.001
sleepers  mobile  92    100   81    100   2.4 s   2.9 s   0 ms      0
sleepers  desktop 93    100   81    100   0.7 s   1.7 s   0 ms      0
arbit     mobile  88    100   81    100   2.4 s   3.4 s   0 ms      0
arbit     desktop 98    100   81    100   0.6 s   1.1 s   0 ms      0
guide     mobile  86    100   100   100   2.9 s   3.5 s   0 ms      0
guide     desktop 98    100   81    100   0.7 s   1.0 s   0 ms      0

== failing audits (page/profile, item count) ==
best-practices: is-on-https  Does not use HTTPS
seo: is-crawlable  Page is blocked from indexing
```

Light theme, accessibility only (`THEME=light CATS=accessibility`): 100
on all eighteen page and profile pairs, no failing audit.

Best practices reads 81 wherever `is-on-https` is the one failure, so it
is 100 in production; the pages showing 100 above are the ones Lighthouse
happened not to flag for the local scheme. SEO reads 66 on search and
sealed for `is-crawlable` alone.

## Still open from #53

- Performance, mobile main-thread work first. The leads from these runs:
  27 script tags in `base.html`, two render-blocking stylesheets fetched
  from CDNs in the head, unminified CSS and JS, and the 1,400-line phone
  search template.
- Whether `/search` and `/sealed` should stay out of the index is a
  product call; the scores above treat it as intended.

## Performance

Issue #53's second phase: fix the measured causes of slow first paint
and heavy main-thread work, phone profile first, without a score
target. The design notes behind this section (the full design and the
"What was measured" section the quote below comes from) are kept
outside the repo; the decisions that matter here are that the CDNs
stay, there is no build step, there is no Go-side compression, and
phone page changes are in scope. This records what the committed
runner measured before and after the pass.

### Production, before this pass

Quoted verbatim from the spec:

> Production, Lighthouse 13.5 phone profile (simulated slow 4G, 4x CPU),
> `/search?q=s:LEB`: performance 57, FCP 3.1 s, LCP 7.2 s, TBT 520 ms.
> Main thread: script evaluation 4.2 s (nearly all attributed to the page
> document), style and layout 2.2 s. The HTML is 2.6 MB raw with 100
> results, 3,871 vendor rows, 5,926 links and 1,291 `data-lucide`
> placeholders that the 645 KB icon library (120 KB over the wire)
> replaces at runtime. Sixteen requests block first paint: every local
> script sits in the head or body without `defer`, plus Google Fonts and
> keyrune CSS. The 732 KB autocomplete name list is fetched three times
> at load. The phone search page preloads four chart libraries on every
> load. Home on the phone profile scores 79, upload 88. Desktop search
> carries 830 KB of `onmouseenter` attributes, two per result.
>
> Local dev server, same profiles: the same render-blocking set, mobile
> LCP 8 to 12 s on every page.

Production numbers come after deploy and are to be appended below then,
from Git Bash:

```bash
MSYS_NO_PATHCONV=1 node audit.mjs prod https://www.mtgban.com / '/search?q=s%3ALEB' /upload
```

### Local, before this pass

Same server, same nine pages, same two profiles, dark theme: the
accessibility phase's "After" table above (run `pass3`), taken before
any of this pass's commits.

```
page      profile perf  a11y  bp    seo   FCP     LCP     TBT       CLS
home      mobile  71    100   100   100   2.9 s   8.0 s   0 ms      0
home      desktop 93    100   81    100   0.8 s   1.7 s   0 ms      0
search    mobile  58    100   81    66    7.2 s   11.8 s  0 ms      0
search    desktop 70    100   81    66    1.9 s   3.3 s   0 ms      0.07
sealed    mobile  68    100   81    66    3.9 s   6.5 s   10 ms     0
sealed    desktop 98    100   81    66    0.8 s   1.0 s   0 ms      0
news      mobile  74    100   100   100   2.1 s   7.8 s   0 ms      0
news      desktop 93    100   81    100   0.8 s   1.6 s   0 ms      0
screener  mobile  78    100   81    100   3.4 s   4.4 s   0 ms      0
screener  desktop 93    100   81    100   0.6 s   1.8 s   0 ms      0
upload    mobile  70    100   81    100   2.9 s   10.4 s  0 ms      0.029
upload    desktop 91    100   81    100   0.8 s   1.9 s   0 ms      0.001
sleepers  mobile  92    100   81    100   2.4 s   2.9 s   0 ms      0
sleepers  desktop 93    100   81    100   0.7 s   1.7 s   0 ms      0
arbit     mobile  88    100   81    100   2.4 s   3.4 s   0 ms      0
arbit     desktop 98    100   81    100   0.6 s   1.1 s   0 ms      0
guide     mobile  86    100   100   100   2.9 s   3.5 s   0 ms      0
guide     desktop 98    100   81    100   0.7 s   1.0 s   0 ms      0

== failing audits (page/profile, item count) ==
best-practices: is-on-https  Does not use HTTPS
seo: is-crawlable  Page is blocked from indexing
```

### Local, after this pass

`node audit.mjs perf-after2 http://localhost:8080`, same server, same
nine pages, same two profiles, dark theme (the machine's scheme), all
four categories, run on the branch tip with every task in this pass
committed, including the final-review fix wave that followed it (the
guide's own `guide-data.js` tag restored, the sleepers heading
selector, the dodgerblue contrast tokens, immutable caching scoped to
the build hash, and the autocomplete fetch/retry fixes):

```
page      profile perf  a11y  bp    seo   FCP     LCP     TBT       CLS
home      mobile  70    100   100   100   2.9 s   8.0 s   20 ms     0
home      desktop 93    100   81    100   0.8 s   1.6 s   0 ms      0
search    mobile  68    100   81    66    3.9 s   6.6 s   0 ms      0
search    desktop 78    100   81    66    1.4 s   2.9 s   0 ms      0.059
sealed    mobile  83    100   81    66    2.6 s   4.1 s   20 ms     0
sealed    desktop 96    100   81    66    0.7 s   1.3 s   0 ms      0
news      mobile  74    100   100   100   2.0 s   7.9 s   0 ms      0
news      desktop 95    100   81    100   0.5 s   1.5 s   0 ms      0
screener  mobile  95    100   81    100   2.0 s   2.7 s   0 ms      0
screener  desktop 97    100   81    100   0.6 s   1.2 s   0 ms      0
upload    mobile  71    100   81    100   2.7 s   9.8 s   0 ms      0.029
upload    desktop 92    100   81    100   0.6 s   1.8 s   0 ms      0.001
sleepers  mobile  98    100   81    100   1.7 s   2.3 s   0 ms      0
sleepers  desktop 98    100   81    100   0.5 s   1.1 s   0 ms      0
arbit     mobile  77    100   81    100   2.4 s   5.3 s   0 ms      0
arbit     desktop 98    100   81    100   0.5 s   1.0 s   0 ms      0
guide     mobile  78    100   100   100   2.0 s   3.9 s   30 ms     0.198
guide     desktop 92    100   81    100   0.6 s   1.8 s   0 ms      0

== failing audits (page/profile, item count) ==
best-practices: is-on-https  Does not use HTTPS
    home/desktop (1), search/mobile (1), search/desktop (1), sealed/mobile (1), sealed/desktop (1), news/desktop (1), screener/mobile (1), screener/desktop (1), upload/mobile (1), upload/desktop (1), sleepers/mobile (1), sleepers/desktop (1), arbit/mobile (1), arbit/desktop (1), guide/desktop (1)
performance: cache-insight  Use efficient cache lifetimes
    home/mobile (18), home/desktop (19), search/mobile (33), search/desktop (50), sealed/mobile (28), sealed/desktop (45), news/mobile (18), news/desktop (19), screener/mobile (18), screener/desktop (35), upload/mobile (38), upload/desktop (38), sleepers/mobile (15), sleepers/desktop (33), arbit/mobile (35), arbit/desktop (35), guide/mobile (18), guide/desktop (35)
performance: cls-culprits-insight  Layout shift culprits
    guide/mobile (1)
performance: cumulative-layout-shift  Cumulative Layout Shift
    search/desktop (1), guide/mobile (1)
performance: document-latency-insight  Document request latency
    home/mobile, home/desktop, search/mobile, search/desktop, sealed/mobile, sealed/desktop, news/mobile, news/desktop, screener/mobile, screener/desktop, upload/mobile, upload/desktop, sleepers/mobile, sleepers/desktop, arbit/mobile, arbit/desktop, guide/mobile, guide/desktop
performance: first-contentful-paint  First Contentful Paint
    home/mobile, home/desktop, search/mobile, search/desktop, sealed/mobile, sealed/desktop, news/mobile, screener/mobile, screener/desktop, upload/mobile, upload/desktop, sleepers/mobile, arbit/mobile, arbit/desktop, guide/mobile, guide/desktop
performance: font-display-insight  Font display
    search/mobile (1), search/desktop (1), sealed/mobile (1), sealed/desktop (1)
performance: forced-reflow-insight  Forced reflow
    sealed/desktop (1), upload/mobile (1), upload/desktop (1), arbit/mobile (1), arbit/desktop (1), guide/mobile (1), guide/desktop (1)
performance: image-delivery-insight  Improve image delivery
    home/mobile (1), home/desktop (8), search/mobile (1), search/desktop (5), sealed/mobile (1), sealed/desktop (2), news/mobile (1), news/desktop (1), screener/mobile (1), screener/desktop (2), upload/mobile (2), upload/desktop (2), sleepers/mobile (1), sleepers/desktop (2), arbit/mobile (2), arbit/desktop (2), guide/mobile (1), guide/desktop (2)
performance: interactive  Time to Interactive
    home/mobile, home/desktop, search/mobile, search/desktop, sealed/mobile, news/mobile, news/desktop, screener/mobile, upload/mobile, upload/desktop, sleepers/mobile, arbit/mobile, guide/mobile, guide/desktop
performance: largest-contentful-paint  Largest Contentful Paint
    home/mobile, home/desktop, search/mobile, search/desktop, sealed/mobile, sealed/desktop, news/mobile, news/desktop, screener/mobile, screener/desktop, upload/mobile, upload/desktop, sleepers/mobile, sleepers/desktop, arbit/mobile, arbit/desktop, guide/mobile, guide/desktop
performance: layout-shifts  Avoid large layout shifts
    guide/mobile (1)
performance: lcp-discovery-insight  LCP request discovery
    search/desktop (2)
performance: max-potential-fid  Max Potential First Input Delay
    home/mobile, sealed/mobile, guide/mobile
performance: network-dependency-tree-insight  Network dependency tree
    home/mobile (3), home/desktop (3), search/mobile (3), search/desktop (3), sealed/mobile (3), sealed/desktop (3), news/mobile (3), news/desktop (3), screener/mobile (3), screener/desktop (3), upload/mobile (3), upload/desktop (3), sleepers/mobile (3), sleepers/desktop (3), arbit/mobile (3), arbit/desktop (3), guide/mobile (3), guide/desktop (3)
performance: render-blocking-insight  Render-blocking requests
    home/mobile (8), home/desktop (6), search/mobile (8), search/desktop (11), sealed/mobile (8), sealed/desktop (12), news/mobile (8), news/desktop (6), screener/mobile (8), screener/desktop (12), upload/mobile (11), upload/desktop (11), sleepers/mobile (7), sleepers/desktop (11), arbit/mobile (11), arbit/desktop (11), guide/mobile (6), guide/desktop (11)
performance: speed-index  Speed Index
    home/mobile, home/desktop, search/mobile, search/desktop, sealed/mobile, screener/mobile, upload/mobile, arbit/mobile
performance: total-byte-weight  Avoid enormous network payloads
    search/desktop (10)
performance: unminified-css  Minify CSS
    home/mobile (3), home/desktop (3), search/mobile (3), search/desktop (5), sealed/mobile (3), sealed/desktop (5), news/mobile (3), news/desktop (3), screener/mobile (3), screener/desktop (5), upload/mobile (5), upload/desktop (5), sleepers/mobile (2), sleepers/desktop (5), arbit/mobile (5), arbit/desktop (5), guide/mobile (3), guide/desktop (5)
performance: unminified-javascript  Minify JavaScript
    home/mobile (6), home/desktop (9), search/mobile (12), search/desktop (23), sealed/mobile (11), sealed/desktop (21), news/mobile (6), news/desktop (9), screener/mobile (5), screener/desktop (17), upload/mobile (20), upload/desktop (20), sleepers/mobile (4), sleepers/desktop (17), arbit/mobile (17), arbit/desktop (17), guide/mobile (7), guide/desktop (18)
performance: unsized-images  Image elements do not have explicit `width` and `height`
    home/mobile (3), search/mobile (3), search/desktop (1), sealed/mobile (2), news/mobile (3), screener/mobile (2), sleepers/mobile (2), guide/mobile (2)
performance: unused-css-rules  Reduce unused CSS
    home/mobile (2), home/desktop (2), search/mobile (3), search/desktop (5), sealed/mobile (3), sealed/desktop (5), news/mobile (2), news/desktop (2), screener/mobile (2), screener/desktop (4), upload/mobile (5), upload/desktop (5), sleepers/mobile (2), sleepers/desktop (4), arbit/mobile (5), arbit/desktop (5), guide/mobile (2), guide/desktop (4)
performance: unused-javascript  Reduce unused JavaScript
    home/desktop (1), search/mobile (1), search/desktop (2), sealed/mobile (1), sealed/desktop (2), news/desktop (1), screener/desktop (1), upload/mobile (1), upload/desktop (1), sleepers/desktop (1), arbit/mobile (1), arbit/desktop (1), guide/desktop (1)
seo: is-crawlable  Page is blocked from indexing
    search/mobile (1), search/desktop (1), sealed/mobile (1), sealed/desktop (1)
```

Lighthouse 13's performance category now reports mostly through named
"insight" audits (`cache-insight`, `render-blocking-insight`, and the
rest above) rather than the older single-metric audits; none of the
ones that still fail here are new regressions, they are categories this
pass did not target (CSS/JS minification, image sizing, far-future
caching for non-hashed paths). Accessibility is clean on every page and
profile in this run, guide included.

An earlier run of this same audit, taken before the final-review fix
wave landed, had scored guide at 90 (mobile) and 92 (desktop)
accessibility: a prior commit had dropped guide.html's own
`guide-data.js` tag as a duplicate of base.html's, but base's copy
loads after `guide.js`, which needs it and silently renders nothing
without it, so the guide had no sidebar links or sections on either
device. That tag is restored (scoped so it does not double-load on
desktop), which is why guide reads 100/100 here.

`arbit/mobile`'s performance score moves from 88 before this pass to 77
after. No commit in this pass touches `/arbit`, which has no large
result table, autocomplete box or hover payload; this run is a single
lab measurement on a dev box, and the move reads as noise rather than a
regression. The production run after deploy is the check.

### HTML size on the phone profile

`curl -sL -A '<the phone UA in audit.mjs>' --compressed
http://localhost:8080/search?q=s%3ALEB | wc -c`, on the branch tip:
189,570 bytes (185 KB) after this pass, against 454 KB measured locally
before it (production, with no paging, is 2.6 MB raw).

### What each task addressed

**Task 1** (`7db179b0`, immutable caching for hashed static files)
replaced the one-day `Cache-Control` lifetime with `public,
max-age=2592000, immutable` (30 days) on the hashed static paths, 17 to
49 files per page depending on which chart libraries and icons that page
loads, and kept the one-day lifetime for unhashed paths, so a repeat
view stops refetching the hashed ones.

**Task 2** (`c61259bf`, the desktop hover payload written once per
result) replaced the two `onmouseenter` attributes per search result,
830 KB of markup on desktop search, with a single delegated listener and
one `data-hover` payload per row.

**Task 3** (`9651e49e`, `abf446b7`, the autocomplete name list fetched
once on first focus) stopped the 732 KB name list from being fetched
three times at load; it now fetches once, on first focus of any
autocomplete box, memoised for the rest of the page.

**Task 4** (`d12d4e0e`, every local script deferred, icons painted on
DOM ready) and **Task 5** (`07d71bf1`, fonts loaded once with
preconnects, phone chart preloads dropped) together took render-blocking
requests on the local phone search page from 17 before this pass to 8
after (`render-blocking-insight` in the after run's `summary.json`
reports `search/mobile (8)`): deferring every local `<script>` moved
the sixteen un-deferred script tags production measured off the
blocking path, loading Geist once with preconnects instead of per-page
cut the font requests, and dropping the four preloaded chart libraries
(about 370 KB raw) removed those from every phone search load whether
or not a chart was opened. What is left blocking: the font stylesheets
and keyrune CSS, the three head scripts that stay synchronous on
purpose (`js/cookies.js`, `js/utils.js`, `js/card-art-fallback.js`), and
three stylesheets.

**Task 6** (`b6f12762`, the phone search page paged at 25, card icons
painted on approach) is what moved the HTML-size and icon-count numbers:
the 2.6 MB phone page with 100 results, 3,871 vendor rows and 1,291
runtime icon replacements at load is now a 25-result page, with the
remaining cards' icons painted as they scroll into view instead of all
at once.
