# ADR-0001: Where the API handoff checks the Patreon email

**Status:** Accepted
**Date:** 2026-09-24
**Deciders:** Vittorio Giovara
**Change:** PR #560

## Context

The site has no session store. Who a reader is lives in the `MTGBAN` cookie
(or a `?sig=`): an HMAC over the fields listed in `SignedFields`
(`OrderNav` plus `OptionalFields` in `main.go`), written at Patreon login by
`Auth` through `sign()`. Two properties of that cookie shape this decision:

- **It is shared.** It is set for the parent domain, so every `*.mtgban.com`
  deployment (each game, and beta) reads the same signature.
- **A build verifies only the fields it knows.** Verification rebuilds the
  signed data from the build's own `SignedFields`, so a signature carrying a
  field an older build does not list fails that build's check, and the
  reader looks signed out there.

Inside the site the Patreon email is a label: the navbar shows it, logs and
the rate limiter key on it, and the grants list matches against it.

The API handoff turns it into an identity somewhere else. `/api-login` and
`/api-trial` mint an `apihandoff` token naming the email. It is signed with
this game's shared gateway secret: the `gateway@mtgban.com` entry in
`api_user_secrets`, which is also the secret the gateway uses to call the
site. The token names the game that minted it, and the gateway
([`portal/trial.go`](https://github.com/mtgban/api-gatewahy/blob/master/portal/trial.go))
verifies it with that game's secret. It then calls
`GetOrCreateAccount(claims.Email)` on `/session` and `/trial`, and signs in
whoever the token names, including their API keys and billing. Every game site
holds a secret the gateway accepts, so any of them can sign in any email.

Patreon lets an account carry an email its owner never confirmed, and says so
in the identity response's `is_email_verified`. Its [OAuth
guide](https://www.patreon.com/portal/start/oauth-explained) says that when
the email is unverified you should "avoid allowing the user to log in, to
register or to link that Patreon account with any local account". Discourse's
Patreon login shipped without this check
([GHSA-fvj9-f67v-qpr4](https://github.com/discourse/discourse-patreon/security/advisories/GHSA-fvj9-f67v-qpr4)).

Two more constraints:

- **The middleware does not run on the handoff.** For the pricing page to be
  public, the shared ACL gives `"Any"` the `API` section. `enforceSigning`
  then passes `/api-plans` and its sub-pages `/api-login` and `/api-trial`
  straight to the handler without checking anything. That is why
  `apiHandoff` reads the reader through `verifiedSignature` itself.
- **Grants must keep working without confirmation.** Grantees are invitees
  and testers, and are not to be sent off to confirm anything.

## Decision

Record at login; enforce at the one place the email becomes a login
elsewhere.

1. **Record.** `Auth` asks Patreon for `is_email_verified`
   (`patreon.PatreonIdentityURL`). When the email is not confirmed,
   `sign()` adds `UserEmailUnverified=true` to the signature. The field is
   in `OptionalFields`, so it is under the HMAC: removing it breaks the
   signature.
2. **Enforce.** `apiHandoff` refuses to mint a token for a signature that
   carries the flag. It offers the Patreon login instead, and the OAuth
   state brings the reader back to the handoff afterwards.
3. **Mark the exception, not the rule.** A confirmed login carries no new
   field.
4. **Grants are untouched.** They match the Patreon email whether or not it
   is confirmed.

## Options considered

### A: Refuse unconfirmed emails at login, in `Auth`

What Patreon's guide recommends.

| Dimension | Assessment |
|---|---|
| Protects the gateway | Yes |
| Effect on the site | Anyone with an unconfirmed Patreon email is locked out of every page, grantees and paying patrons included |
| Rollout | No new signed field |
| Code | Smallest: one check, no flag, nothing in the handoff |

**Rejected:** grants must keep working without confirmation, and the site
itself doesn't need a confirmed email.

### B: Check in the `enforceSigning` middleware

| Dimension | Assessment |
|---|---|
| Protects the gateway | No: the middleware is bypassed for `/api-login` and `/api-trial` whenever `API` is open to `"Any"`, which it has to be for a public pricing page |
| Effect on the site | Refuses unconfirmed readers on every gated page |

**Rejected:** it misses the one route that matters and blocks every other
page.

### C: Mark every confirmed login (`UserEmailVerified=true`)

| Dimension | Assessment |
|---|---|
| Protects the gateway | Yes, sessions from before the change included, since those would all be refused |
| Effect on the site | None |
| Rollout | Every new login carries a field older builds reject. During a staggered `v*` rollout, a `beta-*` deploy or a rollback, anyone who logs in on the newer build looks signed out on the older ones. Every existing session also has to log in again before the handoff works, and the mobile error page offers no button to do it |

**Rejected:** it breaks the shared cookie to guard a window that is at most
eleven days long.

### D: Mark only unconfirmed logins (`UserEmailUnverified=true`), chosen

| Dimension | Assessment |
|---|---|
| Protects the gateway | Yes, for every session signed after the deploy. Sessions from before carry no flag and are handed over for the eleven days at most they have left (`DefaultSignatureDuration`) |
| Effect on the site | None |
| Rollout | Only unconfirmed logins carry the field, and until every site runs this build only those few are refused by older ones |

### E: Ask Patreon again at handoff time

The site keeps no Patreon token, so it cannot re-ask with the one from
login. The handoff can make its own round trip instead: `/api-login` and
`/api-trial` always send the reader through Patreon's authorize page, and
`Auth` mints the token from the fresh identity response, never reading the
cookie.

| Dimension | Assessment |
|---|---|
| Protects the gateway | Yes, sessions from before the change included, since every handoff reads `is_email_verified` afresh |
| Effect on the site | Every API sign-in and trial goes through patreon.com first: one more redirect, or a click if Patreon asks to approve the app again |
| Rollout | No signed field |
| Code | `Auth` has to tell a handoff from a login by the OAuth state, and mint the token itself |

**Not chosen, for now:** D is the smaller change, and keeps the handoff one
click for a reader who is already signed in. E is the way to go if the token
ever needs the Patreon user id, for one trial per Patreon account: the
callback has the id without adding a field to every login.

## Trade-off analysis

Where to enforce was decided by the constraints, not by preference. The
middleware never sees the handoff, and the site does not need what the
handoff needs. So the check sits in the handler that turns the email into
someone else's login.

Where to record is the real choice. A and C each put the cost on people who
did nothing wrong: A on everyone whose Patreon email is unconfirmed, C on
every reader at every staggered deploy. D puts the cost on the unconfirmed
readers only, and only for the handoff. What it leaves open is sessions
signed before the change, for at most eleven days. That was accepted.

E sidesteps both questions by never reading the cookie: it closes the
eleven-day window and needs no signed field. Its price is paid on every API
sign-in, as a trip through Patreon, which is why D came first.

## Consequences

- **Any new consumer that turns the Patreon email into an identity outside
  the site must refuse `UserEmailUnverified`,** the way `apiHandoff` does:
  a new gateway route, a partner integration. The site's own uses of the
  email (navbar, logs, rate limit, grants) need not.
- **The check has to hold on every game site.** Each one can sign any email
  in, so the gateway is only as careful as the least careful site.
- **Avoid adding a field to every login on this cookie.** Mark the exception,
  or ship the verifier (the `OptionalFields` entry) one release before the
  signer.
- **Deploy every site in the same release when a signed field is added.** A
  rollback logs out the readers whose signature carries a field the older
  build does not know.
- **A grant on an unconfirmed email** can be claimed by whoever registers
  that address on Patreon first, provided nobody already has. Accepted,
  given who grantees are.
- **`-dev` without `-sig` believes any cookie here too,** as it does on every
  other page, so the handoff can be tried locally. That is only safe because
  `-dev` runs nowhere but on developer machines: an instance run that way with
  a configuration holding a real gateway secret would mint a token for any
  email.
- **The refusal offers the Patreon login on desktop only.** The mobile error
  page renders the message with no button.

## Action items

1. [ ] Merge #560 and ship it in a release that deploys every site together.
2. [ ] Before tagging, confirm that the shared ACL gives `"Any"` the `API`
   section and that every deployment's `api_user_secrets` has the
   `gateway@mtgban.com` entry.
