# Feature usage metrics

The site counts how often its features and settings are used, so the admin
Metrics section can say what to keep, what to remove and where to invest.
Every count is a registered name with a bounded scope and value, summed by
minute and folded into days. Nothing in the feature tables names a reader.

## What is counted

A count is `(name, scope, value, n)` with five dimensions:
`observability.Dims` holds the instance, the tier read off the checked
signature (`Any` when there is none, `other` when the ACL does not name
it), the device class (`desktop`, `mobile`, or `job`, `discord` and `api`
for work with no browser), whether the request was signed in, and whether
its user agent is a bot. That is the whole key of `feature_events` and
`feature_days`.

The counts come from four places:

- **The server** counts what a request did: `page.view`, every route's
  `http.status` and `http.duration`, refusals, and each page's own facts
  (a search's mode and operators, an upload's source, an arbitrage view's
  options).
- **The page script**, `js/metrics.js`, counts marked controls, `ui.load`
  once per page shown, and the settings snapshot: once a UTC day per path
  scope, `state.reader` and a `state.set` for each registered setting off
  its default, its value only `on`, `off`, `set` or one of the setting's
  own enum words.
- **Script errors**: `ui.js.error` and `ui.js.rejection`, scoped by a
  script basename from a closed list (`inline` or `other` otherwise), with
  an error class from a closed list, a line and the build. No message,
  stack or URL is read into them. Each also adds a `feature_errors` row.
- **Page timings**: `ui.perf.ttfb`, `ui.perf.dom_ready` and `ui.perf.lcp`
  as buckets, scoped by page, on one load in ten, never on a prerendered
  page or one loaded in a hidden tab.

The nightly stock job adds `stock.` rows under the instance `shared`:
how much stored state readers keep (favorites, backpacks, presets,
alerts and the like), as counts and size buckets.

What is never counted: an email or its hash, a user or account id, an IP
address (the beacon's rate limit keys on it in memory only), query text,
a card, a URL or any text a reader typed. A string the registry does not
name for that slot is refused or folded to `other`, never stored as sent.

The script sends nothing, and removes both of its localStorage keys, when
the page has counting off or the browser sends Do Not Track or Global
Privacy Control. The server's own counts do not depend on either signal.
The privacy page (`templates/privacy.html`) says all of this to readers,
and `privacy_test.go` ties its retention and key names to the code.

## Where things live

| Where | What |
|---|---|
| `observability/names.go` | The registry: every name, its family, the values and scopes it takes, its area and how the reports treat it |
| `observability/settings.go` | The settings registry: every cookie and localStorage key a reader can set, its kind, default and class, and `notSettings`, the keys that hold data rather than a choice |
| `observability/counter.go`, `errors.go` | The minute counter and the script error buffer, each written to the database off the request path once a minute |
| `metrics.go`, `metrics_http.go` | The site's side: a request's dimensions, `count` (the one door to the counter), the `observe*` helpers, the route labels and the status and duration wrapper |
| `api_metrics.go` | `POST /api/metrics`, the beacon, and `GET /api/metrics/settings.json`, the preference settings the snapshot reads |
| `js/metrics.js` | The page script: marks, `BAN.track`, the offline queue, the snapshot, errors and timings |
| `metrics_jobs.go`, `metrics_stock.go` | The nightly jobs: the fold, the stored-state counts and the page-visit roll-up |
| `admin_metrics.go` | The admin Metrics section (`/admin?page=metrics`): Overview, Remove, Invest, Feature, Health and Explore |
| `internal/metricsreport` | The rules behind those views, the digest and the cache of their queries |

## Configuration

- **`instance_name`** in the config turns counting on, with
  `observability_config` in the infrastructure file. With no name, nothing
  is recorded; `shared` is refused, since the stock rows use it.
- **The observability database role must be able to create the feature
  tables** (`featureStatements` in `observability/schema.go`). They are
  created behind a savepoint at start-up: where that fails, page visits
  and search votes still work, but the counter, the error buffer and the
  jobs stay off, and the server channel is told.
- **`metrics_jobs: true` on exactly one instance.** The jobs work on tables
  every site shares. Each runs under an advisory lock, so a second flagged
  instance stands aside rather than doubling a run, but the jobs are meant
  to have one home. The crons read the flag once, when they are scheduled;
  the admin's fold-now tool reads it live. A flagged instance that cannot
  run them says why on the server channel.
- **Script errors need a version-stamped build.** `BuildCommit` comes from
  the binary's `vcs.revision`, which `go build` stamps in a git checkout.
  An unstamped binary renders no build, the script installs no error
  listeners, and the server keeps no error rows; Health says so. The
  server keeps a row only when its build is this binary's own, so pages
  served by the previous build during a deploy lose theirs.

## Adding a count

**A server count.** Add a `Name` to `names` in `observability/names.go`
(the zero `Family` is the server's), then emit it with `observe`,
`observeScoped`, `observeStore`, `observeJob` or `newFact`, its name a
string literal. `TestEveryObservedNameIsRegistered` fails on an emitter
the registry lacks, `TestEveryServerNameIsObserved` on an entry nothing
emits, and `TestFeatureCounterIsReachedThroughCount` on a call that skips
the registry's check. `TestRegistryIsWellFormed` holds the entry's shape,
and a new Signal name has to be classed in `internal/metricsreport`'s
`TestAreaNotUseMatchesTheRegistry`. A count the server makes on every
view of a page, which Health should call broken when it stops, also goes
in `everyViewCounts` (`internal/metricsreport/health.go`) by hand.

**A click.** Register a `ui.` name with `Family: FamilyUI` and a `Page`
naming the page labels where the control renders. Then mark the element
`data-track="ui.name"`, with `data-track-value` and `data-track-scope`
when it needs them, or call `BAN.track(name, value, scope)` where there is
no element to mark. Values and scopes are literals in the markup: a
templated one fails `TestTrackValuesAreLiterals` unless it is on that
test's allowlist with a reason it is bounded. `TestEveryTrackedNameIsRegistered`
and `TestEveryClientNameIsTracked` check both directions, and bun tests can
read the registry through `tests/track-registry.js`.

**A setting.** A new cookie, localStorage key or synced preference goes in
`observability/settings.go`, or in `notSettings` when it holds data rather
than a choice. `TestEveryServerCookieIsARegisteredSetting`,
`TestSettingPathsMatchTheCookiePaths`, `TestSettingDefaultsMatchTheCode` and
`tests/settings-registry.test.js` fail until it is there. A setting the
settings modal changes is also held by `TestSettingsCoverTheModal` and
`TestSettingsChangesTablesAreTheRegistry`. A cookie the server writes on
every run must not be preference class, or every reader who ran the page
would read as having changed it.

**A script file.** A new file under `js/` goes in `scripts`
(`observability/errors.go`) and `SCRIPTS` (`js/metrics.js`), or its
errors are placed as `other`. `TestScriptListMatchesTheJSDirectory` and
`TestMetricsScriptMatchesTheRegistry` fail until both have it.

## Bounds

- **The beacon** reads at most 8 KiB and 100 entries a post, takes a
  count of at least 1 an entry, adds at most 50 to a key a post, and takes
  strings of up to 40
  printable ASCII characters. Only `ui.` names and the snapshot's two
  `state.` names are taken from a browser. Past its method, origin and
  rate checks it always answers 204, and each refused entry is counted
  by reason under `metrics.client`.
- **The script** holds up to 500 keys, posts 50 entries at a time, and
  parks what it cannot send in one localStorage queue of up to 100
  entries, dropped once its oldest day is more than a week old.
- **Script errors**: 5 a page load, 20 error entries a post, 400 distinct
  rows in the buffer between writes, and 200 rows an instance a day. A
  full day is a Health problem; the counts by script and class are still
  kept.
- **The counter** holds up to 50,000 keys across its pending minutes and
  drops a minute it could not write within half an hour; both show on
  Health as `metrics.dropped` and `metrics.flush_fail`.
- **Retention**: minute rows go after 14 days, folded days are kept,
  error rows go after 90 days, and page visits older than 400 days are
  rolled up into `events_days`, daily hits and uniques with no visitor
  hash. Gateway rows under `/api/` are deleted at that age, not rolled.
  Search votes are pruned after 90 days by each site's popular-searches
  job, and the nightly fold prunes every instance's, so a renamed or
  retired site's votes go too.
