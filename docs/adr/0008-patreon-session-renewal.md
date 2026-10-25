# ADR-0008: The site renews a Patreon session itself

**Status:** Accepted (the renewal ships off: it runs once `patreon_renewal.after_days` is set)
**Date:** 2026-10-23
**Deciders:** Vittorio Giovara
**Amends:** AGENTS.md invariant 2 ("stateless auth"); ADR-0005's "the site keeps no Patreon tokens"

## Context

A Patreon login mints a `BAN_SIG` signature good for 11 days
(`DefaultSignatureDuration`) in a cookie that lives 31 days. When the
signature runs out the reader is logged out and has to go through
Patreon again, whether or not their pledge still stands. `/auth`
receives a refresh token with every login and throws it away.

Patreon's refresh grant lets the site mint a new access token at any
time, server to server, and rotates the pair: using a refresh token
invalidates the old one. So the site can renew a signature without the
reader doing anything, if it keeps the refresh token somewhere.

The signature is the wrong place. It is verified field by field by each
build's own list (`SignedFields`), so a field added to every login
breaks every older build on the one `Domain=mtgban.com` cookie that
nine sites share, during every rollout and rollback (ADR-0001). Scripts
can read it, every subdomain gets it, and `?sig=` links, `/go/`
redirects and panic logs carry it (ADR-0006). A credential does not
belong in it.

The site has, since ADR-0005, a Postgres database (`user_state`) that
every deployment shares, with a create-only schema recipe and a
5-connection pool.

## Decision

Authorisation stays in the signed cookie, read with no database work.
The database holds only what lets the server mint the next cookie
without the reader.

1. **One `patreon_sessions` row per login**, keyed by the game-agnostic
   `HashEmail`, holding the Patreon user and client the refresh token was
   issued to, the token, the login time, and a renewal lease. Created by
   the login beside the signature, dated from its code exchange, replacing
   the row the browser's cookie already names; deleted by logout; pruned
   past `max_session_days`. Patreon keeps one refresh
   token per account and client (probed 2026-10-23: a second login
   returns the pair the first holds, and a refresh rotates it for both),
   so every row of an account under one client carries the same token and
   moves together.
2. **An HttpOnly `BAN_SESSION` cookie** names the row. Renewal needs
   both an HMAC-valid signature naming an email and this cookie whose
   row carries that email's hash. A signature on its own — leaked
   through a script, a link or a log, or planted by `?sig=` — cannot
   renew and runs out as it does today.
3. **The signature's shape does not change.** A renewed signature is
   what a login mints, with a later `Expires` and the tier Patreon
   reports now. Every build verifies it; an older build simply never
   renews.
4. **Renewal is lazy and leased.** Inside the signing middleware, once
   a signature is older than `after_days`, the request leases every row
   of the account under this client, its own among them, with one
   `UPDATE … RETURNING` (safe
   through a transaction pooler, holding no connection across Patreon),
   refreshes, re-resolves the tier through `Pledge.Resolve`, stores the
   rotated token on all of those rows *before* signing, and serves the
   same request on the new signature. Another request, tab, device, site
   or port that loses the lease serves on the old signature; its row has
   the new token all the same. A request of the same browser that
   reaches the site after the renewal answered, still carrying the
   signature it renewed, is served on the new one; one that arrives
   while the renewal runs is served as any request that lost the lease.
5. **Patreon's answer decides, three ways.** *Entitled*: re-sign, with
   whatever tier Patreon reports, up or down. *Not entitled* (identity
   OK, no membership, no entitled tier or only the free one, no grant):
   delete the row, clear both cookies, log the reader out now
   (`clear_on_negative`).
   *Unknown* (any transport, status, shape or title failure): keep
   everything, back off an hour, and store the token a refresh that went
   through already rotated to, since the old one is dead. Unknown never
   extends a session; it can only keep one until the signature runs out
   on its own. A refresh token Patreon refuses (`invalid_grant`) ends the
   rows holding it; a row another renewal left holding a live one stays.
6. **Refresh token at rest: plain text.** It redeems only with the
   client secret, which lives in the infrastructure config; a session
   id renews only beside its reader's signature, which the database
   never holds.

## Options considered

### Refresh token inside the signature

| Dimension | Assessment |
|---|---|
| Rollout | Two signed fields on every login: breaks every older build on the shared cookie; rollback logs readers out (ADR-0001's rejected pattern) |
| Exposure | The token travels wherever the signature does: scripts, URLs, logs |
| Multi-device | Each device holds a copy; rotation kills the others' |
| Storage | None |

### One row per email

| Dimension | Assessment |
|---|---|
| Binding | Renewal keyed by the signature's email alone: any leaked signature renews itself to the cap |
| Multi-device | One token, which fits Patreon's one pair per account, but one id too: logging out on one device logs out all |
| Storage | Simplest |

### One row per login + HttpOnly cookie, chosen

| Dimension | Assessment |
|---|---|
| Rollout | No signed field; deploy in any order |
| Exposure | A leaked signature dies at its own expiry; stealing the HttpOnly cookie needs device or TLS compromise |
| Multi-device | Independent rows for binding and logout; one lease and one commit per account and client keep them on the one pair Patreon issues |
| Storage | One small table, create-only, pruned |

## Consequences

- A paying reader who visits at least every `after_days` is never logged
  out. A reader absent longer than the signature plus `grace_days` logs
  in again.
- A cancelled pledge is noticed at the next renewal (~day 8 at the
  default) rather than at expiry; with the webhook (Phase 5) at the next
  page load.
- Patreon's webhook (`POST /webhook/patreon`) turns that into
  revocation within one page load. A delivery whose signature checks out
  *pokes* the member's email in memory on every site (a Postgres NOTIFY
  carries the hash), and a poked reader's next request renews whatever
  the signature's age. The body's own verdict is never read: the renewal
  asks Patreon who is entitled, so one path decides, and the portal's
  test deliveries, which call a deleted pledge active, could not mislead
  it. A poke a restarting site missed, or one that outlives `after_days`,
  falls back to the age window; a poke that meets Patreon's silence stays,
  and is tried again once the hour's backoff is up.
- A tier change, and an ACL or grant edit, reach an active reader at
  the next page load, not the next renewal. The webhook pokes the
  tier change; a grant edit pokes its grantee; an access table that
  differs from the one it replaces, saved here, reloaded after a peer's
  save or by the admin's config reload, stamps the poke set, and every
  signature issued before the stamp is re-signed on its next request,
  since its page flags were baked in from the old table. The edit
  changes nothing Patreon knows, so the re-sign asks it nothing: it
  keeps the reader, the tier and the `Expires` the signature had and
  takes the flags of the table now, so an ACL save costs no Patreon
  call and extends no session. A start or a deploy stamps nothing, and
  neither does a reload that finds the same table, as the listener's
  does after every reconnect. Pokes and the stamp are kept to the
  second and rounded up, so a signature minted under the old state in
  their own second is not missed; one minted after them in that second
  renews once more. **Refresh now** on the account page renews from
  Patreon on demand.
- A renewal on one device renews the token every device's row holds,
  under the account's lease, so no row is left with the token Patreon just
  rotated away. The renewal lease and commit are therefore per account,
  not per row.
- After a reader changes their Patreon email, the renewal files their
  sessions under the new one. Their other devices, whose signatures
  still name the old email, stop renewing and log in again when the
  signature runs out.
- **Log out everywhere** deletes every row for the email: no device can
  renew; signatures already issued run to their own `Expires`.
- `recordAlertContact` runs on every entitled renewal, so alerts no
  longer park for a reader who never re-logs in.
- A Patreon outage costs each near-expiry session one bounded wait per
  hour, and a session that rests costs the database nothing until its
  rest is over; nobody is logged out by it. A refresh whose answer is
  lost after Patreon rotated the token loses that token, so the refresh
  waits longer than the lookups do; a session left holding a dead token
  stops renewing, and its reader logs in again when the signature runs
  out.
- The API handoff is untouched: it still asks Patreon through a
  redirect and never reads the session row (decision recorded in the
  plan; a stolen `BAN_SESSION` must not become a gateway login).

## Action items

1. [ ] Deploy Phase 1 to all nine sites in any order; rows accrue as
   readers log in.
2. [ ] Enable `after_days` on one site (its own config overrides the
   infrastructure file); watch verdict rates; then everywhere.
3. [ ] `clear_on_negative` once the not-entitled rate looks like churn.
4. [ ] `grace_days`, if kept at 3.
5. [ ] Register the webhook at Patreon (Phase 5): the URL
   `https://mtg.ban.cards/webhook/patreon`, the triggers
   `members:pledge:create`, `members:pledge:update` and
   `members:pledge:delete`, and the secret it generates filed in
   `infrastructure.json` as `patreon_webhook_secret`. Register it once the
   magic droplet serves `mtg.ban.cards` itself: a host that redirects loses
   deliveries, since a webhook sender need not follow a redirect.
