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

## Open

| Item | Type | I/R/E | Score | Effort | Evidence |
|---|---|---|---|---|---|
| Price API handlers thinly tested | Test | 2/4/2 | 24 | M | `PriceAPI` 25% covered, `BatchPricesAPI` 0% |
| Database code untested in CI | Test | 3/4/3 | 21 | M | No Postgres in CI; every DB test is env-gated. news.go 5%, `timeseries` 20% (the gateway imports it), `userstate` 1% |
| main.go and `PageVars` collide | Arch | 4/1/2 | 20 | M | main.go touched by 198 of 1,261 commits since June. `main()` is 174 lines, from 499, with routes, crons, the scraper load, the tcgcsv mode and serving in functions of their own; `PageVars` (pages.go) has 197 fields, most read by one page, and per-page structs are next |
| Monitoring gaps | Infra | 2/3/2 | 20 | S-M | `/healthz` checks no database; every alert goes to one Discord webhook (none set: logged only); stale-data alarms live in memory and repeat after a restart |
| Non-Magic games untested in CI | Test | 3/3/3 | 18 | M | 8 of 9 deployments; their tests skip without the `*_PATH` datastores |
| Giant functions keep growing | Code | 5/3/4 | 16 | L | Since May 17: `Upload` 793 -> 1,275 lines, `Search` 630 -> 1,040, `Admin` 447 -> 717 (#732 took its deploy actions), `parseSearchOptionsNG` 646 -> 816. Plan below |

Lower down, measured but not scored: 45 request values parsed with the
error discarded (upload 13, search 7, news 7); 80 `window.X =` globals (8
of them `window.BAN_*` hand-offs, 5 added by #739) and 228 inline
`onclick`/`onchange` handlers; 107 inline `style=`; 2,429 lines of inline
script left in templates (4,683 before #739), most in guide.html (499),
mobile/search.html (446) and admin.html (305); 18 scripts (379 KB,
unminified) on every desktop page, `guide-data.js` (125 KB) and
`command-palette.js` (101 KB) among them; the 10 deploy workflows are
near-copies of each other.

## Plan for the giant functions

1. **Stop the growth.** A test that walks the root package with `go/ast`
   and fails when a function passes its recorded length (the current
   offenders at today's size, 150 lines for everything else). A feature
   touching `Search` first moves the part it changes into a function of
   its own, in a commit before the feature.
2. **A safety net per handler.** Render each page shape (search: plain
   name, set filter, sealed, decklist, empty, error, oembed, chart;
   upload: retail, buylist, each export, unpack) on master and on the
   branch and diff the bytes: the throwaway probe that proves a template
   edit inert, pointed at the handler instead.
3. **Extract by phase, one function per PR,** biggest self-contained block
   first, each returning its own struct embedded in `PageVars` so templates
   keep reading `.ChartID` and the like unchanged:
   - `Search`: the chart block (~210 lines), the INDEX-row rebuild (~145),
     request and options parsing (~150), sorting (~90), embed/oembed (~75).
   - `Upload`: the per-row results loop (~265), the four exports (~230),
     input loading (~170), store selection (~160), settings (~105).
   - `Admin`: the `reboot` switch becomes a table of one function per
     action.
   - `main`: done; routes, cron jobs, the scraper load, the tcgcsv
     maintenance mode and serving are each a function.
   - `parseSearchOptionsNG` last, if at all: a flat switch whose cases
     don't interact is long, not complex.

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
```
