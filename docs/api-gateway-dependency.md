# Why the API gateway imports this module

The API gateway (`github.com/mtgban/api-gatewahy`, api.mtgban.com) requires
this module by commit and imports six of its packages. That looks backwards,
since the website is otherwise the top of the dependency tree, and moving the
shared packages into the gateway has come up. This file says why they stay
here and what changing one of them takes.

## What the gateway imports

| package | this repo | the gateway |
|---|---|---|
| `apisig` | verifies every `?sig=` (`enforceAPISigning`); the admin panel mints keys | mints a signature for each call it forwards |
| `apihandoff` | mints the token behind `/api-trial` and `/api-login` | verifies it and burns its nonce (`portal/trial.go`) |
| `apiproductlist` | renders `/api-plans` | seeds Stripe, runs checkout, reconciles entitlements |
| `observability` | owns the `events` table the admin Usage tab reads | records every API call into it |
| `ratelimit` | per-IP API limits, per-user page limits | per-key and per-IP limits |
| `timeseries` | the price-history client | `SQLConfig` and `OpenDB` for its own Postgres pools |

The first three are the contracts. They import only the standard library, and
golden tests freeze their bytes. The site is the server for the price API the
gateway calls, and `apiproductlist` sells that API's own scopes (`ALL_ACCESS`,
`BASE_ACCESS`) and modes, so the client importing them is the usual direction.
`apihandoff` runs the other way (the site signs, the gateway verifies), but
moving it alone would still create the two-way dependency below.

## Why they don't move to the gateway

The gateway would still import `observability`, `ratelimit` and `timeseries`,
which are site code. Moving the contracts would leave that dependency in place
and add the reverse one: each module would require the other, and each repo
would pin the other.

## Why they aren't split into their own module

It would save nothing. Rebuilding the gateway against a copy of this module
cut down to the six packages changed none of its dependency versions (checked
2026-09-24 at `987f4c3b`). The six need only `lib/pq`, `mileusna/useragent`
and `x/time`; the rest of this module's requirements enter the gateway's
module graph, but none of them are compiled. A split would also have to take
all six to remove the dependency, and a nested module falls outside the
`./...` that CI builds, vets, lints and tests here.

Revisit this if the gateway starts importing a package with heavy
dependencies, or a dependency bump here starts raising versions in the
gateway's `go.mod`.

## Changing one of them

- **Keep them light.** Whatever these packages import, the gateway compiles.
- **The verifier deploys first.** A failing golden test means the wire bytes
  changed, and every verifier still running will refuse the new ones. For
  `apisig` the verifiers are the game sites, which all deploy before the
  gateway signs anything new. For `apihandoff` it is the gateway, which
  deploys before the sites mint the new shape.
- **Check the gateway before merging.** In a gateway checkout,
  `go work init . <path to this repo>` builds it against your working tree
  (`go.work` is gitignored there); then run its `go test ./...`.
- **The gateway pins merged commits.** Pull requests here are rebase-merged,
  which gives every commit a new SHA, so the gateway re-pins to the `master`
  commit once a change lands. An edit to `apiproductlist/products.json`
  reaches customers only after that re-pin and an `api-gatewahy catalog seed`.
