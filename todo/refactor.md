# Tech debt: the measured list and the plan

Measured 2026-09-30 against master `9876f6e61`. Each item scores
(Impact + Risk) × (6 − Effort), all three on 1-5; effort S is under half a
day, M half a day to two, L longer. Numbers drift with every merge:
re-measure (commands at the end) before acting on one.

Where it stood: 1,042 Go tests passing and 10 skipping, 55% statement
coverage in the root package, CI green on 59 of the last 60 master runs, no
dead code to speak of, three TODOs. The debt is concentrated, and some of
it grows fast: the root package went from 18.0k to 30.8k lines between
May 17 and Sep 30.

## In flight

| PR | Item |
|---|---|
| #732 | Drop the admin actions that deployed in-process (`git reset --hard origin/master`, build, exit) |
| #733 | Build with Go 1.26.8 (a 1.25.0 build carries 34 reachable stdlib vulnerabilities), bump modules and staticcheck, pin secret-holding actions, Dependabot |
| #734 | Load autocomplete/fetchnames once per page, stop the 10 ms hover-image timer |
| #735 | Go duplication: CK/SCG exporters, the MKM condition misalignment, store-list loops, `name_override` |
| #737 | Shared JS helpers: one `escapeHtml`, favorites/recents storage, `getPatreonURL`, the offline renderers' common code |
| #739 | Move search.html's and upload.html's inline scripts (1,371 and 1,047 lines) into `js/` |

## Open

| Item | Type | I/R/E | Score | Effort | Evidence |
|---|---|---|---|---|---|
| Price API handlers thinly tested | Test | 2/4/2 | 24 | M | `PriceAPI` 25% covered, `BatchPricesAPI` 0% |
| Deploys aren't safe to run | Infra | 2/4/2 | 24 | S-M | A tag push deploys without CI on that commit. Nothing serializes deploys, and the hourly self-cycle timer can collide with an Actions run. Rollback's `sudo systemctl start` isn't in `bootstrap.sh`'s sudoers, and `\|\| true` hides it. The 11 deploy workflows are near-copies |
| Database code untested in CI | Test | 3/4/3 | 21 | M | No Postgres in CI; every DB test is env-gated. news.go 5%, `timeseries` 20% (the gateway imports it), `userstate` 1% |
| main.go and `PageVars` collide | Arch | 4/1/2 | 20 | M | main.go touched by 197 of 1,221 commits since June; `main()` 238 -> 484 lines; `PageVars` has 194 fields, 140 read by one template |
| Monitoring gaps | Infra | 2/3/2 | 20 | S-M | `/healthz` checks no database; every alert goes to one Discord webhook (none set: logged only); stale-data alarms live in memory and repeat after a restart |
| Non-Magic games untested in CI | Test | 3/3/3 | 18 | M | 8 of 9 deployments; their tests skip without the `*_PATH` datastores |
| Giant functions keep growing | Code | 5/3/4 | 16 | L | Since May 17: `Upload` 793 -> 1,275 lines, `Search` 630 -> 1,046, `Admin` 447 -> 765, `parseSearchOptionsNG` 646 -> 816. Plan below |
| Config reload races handlers | Arch | 2/3/3 | 15 | M | `loadVars` swaps `Config` whole while 223 unlocked `Config.X` reads may run; `DataBucket` is set after serving starts |

Lower down, measured but not scored: 45 request values parsed with the error
discarded (upload 13, search 7, news 7); 76 `window.X =` globals and 234
inline `onclick`/`onchange` handlers; 110 inline `style=`; 18 scripts
(388 KB, unminified) on every desktop page, `guide-data.js` (125 KB) and
`command-palette.js` (101 KB) among them.

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
   - `main`: routes, cron jobs and the tcgcsv maintenance mode.
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

## Re-measuring

```bash
go test -count=1 -coverprofile=c.out ./... && go tool cover -func=c.out
govulncheck ./...                  # under the Go that go.mod names
go list -m -u -f '{{if and .Update (not .Indirect)}}{{.Path}} {{.Version}} -> {{.Update.Version}}{{end}}' all
git log --since=2026-09-30 --name-only --pretty=format: -- '*.go' ':!*_test.go' | sort | uniq -c | sort -rn | head
```
