# Lighthouse runs

`audit.mjs` runs Lighthouse over the site's main pages, on a phone profile
and a desktop one, in the Chromium browser `CHROME_PATH` names, or the
Chrome chrome-launcher finds when it is unset. It prints the four category
scores and the Core Web Vitals per page, then every failing audit with the
pages it failed on, and writes each run's JSON under `out/<label>/`, below
the directory it runs from.

```bash
cd scripts/lighthouse
npm install
node audit.mjs baseline http://localhost:8080          # all four categories
THEME=light CATS=accessibility node audit.mjs light http://localhost:8080
CATS=performance node audit.mjs perf-after http://localhost:8080
node audit.mjs prod https://www.mtgban.com /search?q=s%3ALEB
CHROME_PATH='C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe' node audit.mjs edge http://localhost:8080
```

`THEME=light|dark` pins the site theme by seeding `localStorage` before
each navigation; without it the page follows the machine's colour scheme.
`CATS` narrows the categories, which makes a run several times faster.
Extra arguments replace the default page list.

Two failures are expected and not defects: `is-on-https` on a local
server, and `is-crawlable` on `/search` and `/sealed`, which `robots.txt`
keeps out of the index on purpose.

The script closes the browser connection before `chrome.kill()`, so a
headless run leaves no ghost window on the Windows task switcher.

`docs/lighthouse.md` records the runs behind issue #53.
