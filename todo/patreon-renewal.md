# Transparent Patreon session renewal

> **2026-09-14 spot check:** nothing below is built yet — `patreon.RefreshAuthToken`
> doesn't exist (only `GetAuthToken`), and no `Renewal`/`FirstLogin` fields or
> `resolveTier()`/`renew_window_days` config knobs exist anywhere. The
> premise is still exactly accurate: `DefaultSignatureDuration` is still 11
> days (`main.go`) and the `MTGBAN` cookie is still set for 31 days
> (`auth.go`) — the 11-day-logout problem this plans to fix is still live.
> Live, accurate, unstarted design doc.

Stop logging paying users out every 11 days. Instead of letting the signed
cookie expire, renew it through Patreon's official refresh-token flow a few
days before expiry, invisibly, piggybacked on a request they were already
making. Every failure mode degrades to exactly today's behavior.

## How it works today (verified in code)

- `/auth` exchanges the OAuth code and gets back `access_token`,
  `refresh_token`, `expires_in` (`patreon.GetAuthToken`). **The refresh
  token is decoded and thrown away** — only the access token is used, once,
  to fetch identity + tier, and nothing is persisted server-side.
- `sign()` packs tier permissions + `UserName`/`UserEmail`/`UserTier` +
  `Expires` (now + `DefaultSignatureDuration` = **11 days**) into
  url.Values, HMAC-SHA1s them with `BAN_SECRET`, base64s the lot. The
  cookie `MTGBAN` carrying it lives **31 days**, `Domain=mtgban.com` (all
  subdomains → all deployments share one cookie).
- On sig expiry `enforceSigning` renders "You've been logged out" with the
  Patreon button; `getSignatureFromCookies` treats an expired sig as
  anonymous. Re-login is a full OAuth redirect (Patreon has no silent
  re-auth; the consent screen is user-visible).

## Patreon token facts (docs + developer forum)

- Access tokens: `expires_in` ≈ 2678400s ≈ **31 days**.
- Refresh: `grant_type=refresh_token&refresh_token=…&client_id=…&
  client_secret=…` against the same token URL; response is a fresh
  access+refresh pair. **Allowed at any time** — no need to wait for
  expiry.
- **Rotation**: using a refresh token invalidates the old pair. The
  refresh token is effectively single-use (multi-device consequences
  below).
- Refresh-token absolute lifetime is not documented; the guidance is
  "assume tokens can be invalidated at any time" (revocation, security
  events). Rotation makes the question moot as long as we refresh more
  often than the pair can age out: renewing every ~8 days keeps a
  perpetually fresh pair.

## Design

### 1. Capture the refresh token at login

`Auth()` keeps `tokens.RefreshToken` and `sign()` gains two values:

- `Renewal`: the refresh token. Encryption is OPTIONAL, not a security
  requirement: redeeming a refresh token needs the client_secret, which
  never leaves the config, so the token is inert to a cookie thief —
  who anyway already holds the sig, i.e. the session itself. The one
  real exposure is sigs that travel as `?sig=` query params (invite
  links, API) landing in access logs with a long-lived credential
  inside; invite sigs are minted without user data and would never
  carry Renewal, but if belt-and-braces is wanted, AES-256-GCM (key
  HKDF'd from `BAN_SECRET`, nonce prepended) is ~30 lines. Either way,
  version the field (e.g. `1:` prefix) so wrapping can change later via
  a routine renewal.
- `FirstLogin`: unix timestamp of the real OAuth login, carried forward
  verbatim through every renewal.

Both are appended to `OptionalFields` so the existing HMAC covers them.
Backwards compatible in both directions: old sigs lack the fields and
verify exactly as before (the verifier only encodes non-empty fields);
old binaries ignore the extra fields... but note old binaries would NOT
include them in the HMAC they verify → **a sig signed by the new binary
fails verification on an old binary**. Deploy everywhere before enabling
(see rollout).

### 2. Renewal middleware (pre-expiry, the common case)

In `enforceSigning`, after a sig validates, when
`Expires - now < renewWindow` (config, suggest 3 days) and the sig
carries `Renewal`:

1. **Single-flight + backoff** per email (small in-process map): one
   attempt at a time, and after a failure don't retry for an hour —
   renewal opportunities recur on every request for days, so patience
   is free.
2. POST the refresh grant (new `patreon.RefreshAuthToken`, mirror of
   `GetAuthToken`), context timeout ~5s. One slow request per user per
   ~8 days is the entire latency budget.
3. On success: `getUserIDs` with the new access token, resolve the tier
   through the same logic `Auth()` uses today — grants list first, then
   `getUserTier` + the title mapping (refactor that block into a shared
   `resolveTier()` so the two paths cannot drift). Re-`sign()` with a
   fresh 11-day expiry, the **new rotated** refresh token, and the old
   `FirstLogin`; `putSignatureInCookies` (which also pushes the cookie
   out another 31 days). Serve the current request with the old sig —
   the new one takes effect next request.
4. Tier changed? Sign whatever Patreon says now — up or down,
   transparently. That's a feature: today a downgraded patron keeps
   their old tier until expiry.
5. Any failure (network, invalid_grant, empty tier): log it, keep the
   old sig, change nothing. The sig is still valid for days; the user
   notices nothing. Only if failures persist until expiry does today's
   login screen appear — the status quo.

Grants-list users renew the same way: the refresh proves their identity
(the token round trip re-authenticates the email), then the grants file
supplies the tier as usual. No local-only shortcut — identity proof
stays fresh for everyone.

### 3. The expired case ("not sure what to do if the key is actually expired")

Two distinct situations:

- **Sig expired, cookie still present** (days 11–31): the sig is
  HMAC-authentic, just stale, and the encrypted refresh token inside is
  the same proof of Patreon authorization it was yesterday. Add a grace
  path: where `enforceSigning` today renders `ErrMsgExpired`, first try
  the exact renewal above (full Patreon round trip — never local-only
  from an expired sig). Success → set cookie, redirect to the same URL
  (self-redirect, so the request replays with the new sig). Failure →
  the login screen, as today. Bound the grace by cookie life and by
  `FirstLogin` (below). This makes expiry invisible to anyone who
  visits at least once a month.
- **Refresh token dead** (revoked, rotated away by another device,
  Patreon security purge): there is no smarter answer than the login
  screen — Patreon has no silent re-auth. The lever is making the
  window + grace generous so this is rare, not making the fallback
  cleverer.

**Hard cap**: renewals (pre- and post-expiry) allowed only while
`now - FirstLogin < maxSessionAge` (config, suggest 90 days). After
that, a real OAuth round trip is required. This bounds how long a
stolen cookie can self-perpetuate and how stale the original consent
can get.

### 4. Multi-device and cross-deploy rotation

The cookie is shared across subdomains, so magic and lorcana see the
same sig; two browsers do not.

- **Two deploys, same browser**: whichever deploy renews first sets the
  shared cookie with the rotated token. If the other deploy raced and
  lost, its attempt fails invalid_grant, it keeps the still-valid old
  sig, and the next request carries the winner's cookie. Self-healing;
  single-flight need only be per-process.
- **Two browsers/devices**: each holds its own copy of the refresh
  token. The first to renew rotates it; the second's copy is then dead
  → transparent renewal works only on the most recently renewed device,
  the others fall back to the login screen at expiry. That is exactly
  today's behavior, so nothing regresses — but it is the strongest
  argument for someday moving the token server-side (per-email row in
  the shared Postgres). Explicitly out of scope for v1; the cookie
  design requires no storage, no migration, and no new secret store.

### 5. Rollout (the delicate part)

1. **Phase 0** — refactor only: extract `resolveTier()` from `Auth()`,
   add `patreon.RefreshAuthToken` + the AES helpers, full test
   coverage. No behavior change.
2. **Phase 1** — capture: new logins carry `Renewal`/`FirstLogin`.
   Renewal code ships **disabled** (`renew_window_days: 0`). Deploy to
   every instance. Existing sigs unaffected; new sigs verify everywhere
   because every binary now covers the new fields.
3. **Phase 2** — enable pre-expiry renewal via config on one deploy,
   watch the logs (log every attempt: email, window, outcome, tier
   before/after; the admin log page already exists for this). Then
   everywhere.
4. **Phase 3** — enable the post-expiry grace path.

Rollback at any phase = config flag to 0; sigs already renewed stay
valid, everything else is the status quo.

### 6. Testing

- Unit: encrypt/decrypt round trip; the renewal decision function as a
  pure function of (sig values, now, config) → skip / renew / grace /
  deny — table-driven over the window boundaries, FirstLogin cap,
  missing-Renewal, expired-beyond-grace.
- Handler: `httptest` fake of the Patreon token + identity endpoints
  (the patreon package takes URLs from consts — make them variable for
  tests); full enforceSigning pass with `SigCheck` on and a test
  `BAN_SECRET`: renew on the Nth day, cookie updated, old sig still
  honored, invalid_grant leaves everything untouched, rotation race
  (second renewal with the stale token) degrades cleanly.
- Backwards compat: a sig produced by today's `sign()` (no new fields)
  must verify and never trigger renewal.

## Answered while reviewing

- **Does renewal ever show the user a Patreon page?** No. Renewal is
  server-to-server (refresh grant + identity fetch inside a request the
  user already made); the browser only sees a Set-Cookie. The visible
  OAuth redirect survives only as the fallback, in exactly the cases it
  fires today: token revoked/rotated away, absent past the 31-day
  cookie, or past the FirstLogin cap.

## Open questions

1. `renew_window_days` = 3 and `maxSessionAge` = 90d — right numbers?
   (Window must stay well under the 11-day sig life; cap is a product
   choice about how long consent stays fresh.)
2. Should a renewal that finds the user's pledge gone (valid identity,
   no tier, no grant) actively clear the cookie, or just let the sig
   run out? Clearing is cleaner; letting it ride is today's behavior.
3. Server-side token store (fixes multi-device) — revisit after v1
   proves the flow, possibly on the shared Postgres with a NOTIFY-style
   channel already in place.
4. While in there: `signHMACSHA1Base64` is HMAC-SHA1 everywhere — fine
   for now (HMAC-SHA1 is not broken), but if the sig format is being
   touched anyway, worth considering a versioned upgrade path to
   HMAC-SHA256 as a separate follow-up.
