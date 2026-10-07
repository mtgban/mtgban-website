# Tech debt: the measured list and the plan

Measured 2026-09-30 against master `9876f6e61`; status updated 2026-10-01
against `6df64a85c`, re-measuring the numbers the merged work could move.
Each item scores (Impact + Risk) × (6 − Effort), all three on 1-5; effort
S is under half a day, M half a day to two, L longer. Numbers drift with
every merge: re-measure (commands at the end) before acting on one.

Where it stood: 1,042 Go tests passing and 10 skipping, 55% statement
coverage in the root package (56.5% on 2026-10-01), CI green on 59 of the
last 60 master runs, no dead code to speak of, three TODOs. The debt is
concentrated, and some of it grows fast: the root package went from 18.0k
to 30.8k lines between May 17 and Sep 30.

## Done

| PR | What landed |
|---|---|
| #732 | The admin actions that deployed in-process (`git reset --hard origin/master`, build, exit) are gone |
| #733 | `go 1.26.0` + `toolchain go1.26.8`: 0 reachable vulnerabilities, from 34 under 1.25.0. Direct modules and simplecloud v0.1.1 bumped, staticcheck 2026.2.1, weekly Dependabot; actions stay on version tags |
| #734 | autocomplete/fetchnames load once per page; the hover image moves on events, not a 10 ms timer |
| #735 | CK/SCG exporters share one loop, MKM CSV rows key on id and condition, the store-list loops collapse, the batch API names stores through `scraperName` |
| #737 | One `escapeHtml`, shared favorites/recents storage, one `getPatreonURL`, the offline renderers' common helpers |
| #739 | search.html's and upload.html's inline scripts moved into `js/` |
| #742 | `utils.js` loads in `<head>`, which fixed the add-to-chart modal's `sameSiteURL` error |
| #740, #745 | This file, the AGENTS.md and SPECIFICATION.md corrections, and the page-scripts-in-`js/` convention |
| #747 | `Config()` reads one atomic snapshot that a reload replaces whole, and `DataBucket` is set before serving starts: `-race` went from 118 reports to 0 |
| #748 | A deploy waits for CI on the deployed commit (a manual run can skip it), queues behind a running one, and shares a lock with the self-cycle timer; a rollback can start the old instance |
| #754 | `main()` from 499 lines to 174: routes, crons, the scraper load, the tcgcsv mode and serving are functions of their own, and the page registry, `PageVars`, nav and render live in pages.go |
| #756 | The 148 `PageVars` fields one of six pages owns sit in a struct beside its handler (`UploadVars`, `SearchVars`, `AdminVars`, `NewsVars`, `ArbitVars`, `SleepVars`), embedded in `PageVars`, which keeps the 49 that pages share or a small page has one or two of |
| #762, #763, #764 | `Admin` from 719 lines and 410 statements to 104 and 55: its actions, tools, five editors, dashboard tables and grant forms are each a function below it |
| #767, #770-#774, #777, #778 | `Upload` from 1,269 lines and 701 statements to 292 and 171: its settings, store selection, exports, input, loading, price lookups, row pricing and results page are each a function below it |
| #779, #782, #784-#787, #795, #815, #816 | `Search` from 1,046 lines and 550 statements to 157 and 82: its chart page, result shaping, chart roster, preferences, landing, search run and request prelude are each a function below it; #782 dropped the legacy chart reads first, #795 gave oEmbed its own handler, and #815 and #816 put its helpers in Upload's shape |

## Open

| Item | Type | I/R/E | Score | Effort | Evidence |
|---|---|---|---|---|---|
| Price API handlers thinly tested | Test | 2/4/2 | 24 | M | `PriceAPI` 25% covered, `BatchPricesAPI` 0% |
| Database code untested in CI | Test | 3/4/3 | 21 | M | No Postgres in CI; every DB test is env-gated. news.go 5%, `timeseries` 20% (the gateway imports it), `userstate` 1% |
| Monitoring gaps | Infra | 2/3/2 | 20 | S-M | `/healthz` checks no database; every alert goes to one Discord webhook (none set: logged only); stale-data alarms live in memory and repeat after a restart |
| Non-Magic games untested in CI | Test | 3/3/3 | 18 | M | 8 of 9 deployments; their tests skip without the `*_PATH` datastores |
| Giant functions keep growing | Code | 5/3/4 | 16 | L | Since May 17: `Upload` 793 -> 1,275 lines, `Search` 630 -> 1,040, `Admin` 447 -> 719; all three since split, to 292, 157 and 104 (Done above). `parseSearchOptionsNG` 646 -> 816, left whole. Plan below |

Lower down, measured but not scored: 45 request values parsed with the
error discarded (upload 13, search 7, news 7); 80 `window.X =` globals (8
of them `window.BAN_*` hand-offs, 5 added by #739) and 228 inline
`onclick`/`onchange` handlers; 107 inline `style=`; 1,919 lines of inline
script left in templates (4,683 before #739), most in mobile/search.html
(445), admin.html (305) and offline.html (182); 21 scripts (385 KB,
unminified) on every desktop page, `command-palette.js` (101 KB) and
`guide-data.js` (80 KB) among them; the 10 deploy workflows are
near-copies of each other.

## Plan for the giant functions

`Upload`, `Search` and `Admin` are split by moving each phase into a
function below its handler, in three streams. Every PR branches from master,
and a stream's next PR is cut once the one before it has merged.

- **Admin:** the tools switch (`?tool=`) and the `refresh`, `reload`,
  `removestore` and `logs` actions; the config, checkpoints, access-table,
  affiliates and key-override editors; the dashboard tables and the grant
  forms.
- **Search:** the chart page; INDEX rows, ordering, per-card offer sorts,
  the embed and the notify line; the chart roster and the cookie
  preferences; the empty-query landing and the search execution.
- **Upload:** the settings struct and store selection; the exports; input
  and loading; the fetches and the CSV download; the row loop; the results
  and page scaffolding.

A split is a move: the phase's lines go unchanged into a function below its
handler, one extraction per commit, using the handler's own names so the
moved lines are byte-identical. A move that writes cookies, files or shared
state, ends the request or changes a slice other phases hold is named as
such in its commit and keeps its order. The author proves each PR inert
before opening it, and says how: every template render in the package and a
handler-level probe compared between master and the branch, the effect of
each admin save asserted, and a focused case for each boundary that is not a
plain move.

Sizes are reported in each PR (lines and statements before and after), not
enforced, and nothing stops a handler from growing again. The largest
functions are listed by the command under "Re-measuring".

`parseSearchOptionsNG` stays as it is: a flat switch of independent cases is
long, not complex. If a new filter makes it unmanageable, split the switch
by filter family first.

## Not worth doing

- Consolidating `*-mobile.css` into the desktop sheets: `search-mobile.css`
  shares 4 of its 391 selectors with `search.css`; it is a separate class
  set, not a copy.
- An asset build step, until load measurements ask for one.
- Renaming the `*NG` functions: all 20 are live and none has an old twin.
- Replacing `gopkg.in/robfig/cron.v2`: its successor (v3) is itself
  unreleased since 2020, and the five-field specs parse the same in both.
- Pinning GitHub Actions to commit SHAs: a changed action should fail the
  workflow where it can be seen, so actions stay on version tags.

## Re-measuring

```bash
go test -count=1 -coverprofile=c.out ./... && go tool cover -func=c.out
govulncheck ./...                  # under the Go that go.mod names
go list -m -u -f '{{if and .Update (not .Indirect)}}{{.Path}} {{.Version}} -> {{.Update.Version}}{{end}}' all
git log --since=2026-09-30 --name-only --pretty=format: -- '*.go' ':!*_test.go' | sort | uniq -c | sort -rn | head

# the largest top-level functions of the root package, in lines
awk '/^func /{if ($0 ~ /}$/) next; name=$0; start=FNR; next}
     /^}/{if (name != "") {print FNR-start+1, FILENAME ":" start,
          substr(name,1,48); name=""}}' \
    $(ls *.go | grep -v _test.go) | sort -rn | head -15
```
