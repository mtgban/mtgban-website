# ADR-0006: The API handoff asks Patreon who the reader is

**Status:** Accepted
**Date:** 2026-10-08
**Deciders:** Vittorio Giovara
**Supersedes:** ADR-0001

## Context

`/api-login` and `/api-trial` mint an `apihandoff` token naming an email, and
the gateway signs in whoever it names: their API keys and their billing.
ADR-0001 took that email from the reader's `MTGBAN` signature, refusing one
Patreon had not confirmed.

That signature was built to say which pages a reader may see, and it is
handled the way that job allows:

- **It travels in URLs.** An invite link is a `?sig=`, and every page that
  receives one keeps it as the reader's cookie.
- **Scripts can read it.** The cookie is not HttpOnly and is shared by every
  `*.mtgban.com` site.

Reading it in the handoff made it a gateway credential without protecting
it like one. Anyone could send a reader a link carrying *their* signature and
have the next "Manage your API access" land the reader in their gateway
account. Anyone who obtained a subscriber's signature, from a shared link or
a script on any subdomain, could sign in to the gateway as them. #561 stopped
the handoff reading a `?sig=` on its own request, but any other page still
plants one.

## Decision

The handoff never reads the site's signature. `/api-login` and `/api-trial`
send the reader to Patreon's authorize page, and the callback (`Auth`, told
apart from a site login by its OAuth state) mints the token from Patreon's
answer, in `finishAPIHandoff`:

1. **Bound to the browser.** The state carries a random nonce, also kept in
   a ten-minute HttpOnly `MTGBAN_HANDOFF` cookie on `/auth`. The callback
   finishes only when the two match, so a code from somebody else's Patreon
   account, sent to a reader in a link, hands over nobody. The cookie is
   `SameSite=Lax`, which is what lets it ride the redirect back from
   patreon.com, and is cleared on the callback whatever the outcome.
2. **Confirmed email.** Patreon's `is_email_verified` is read fresh on every
   handoff.
3. **A supporter.** The tier is resolved as the site login resolves it, a
   grant or a pledge, and both handoffs need one, as they did when only a
   signed-in reader could reach them.
4. **Signs in nobody here.** The callback sets no `MTGBAN` cookie for a
   handoff.

## Options considered

### Keep ADR-0001 as #561 left it

| Dimension | Assessment |
|---|---|
| Fixation | Still open: any page plants a link's signature, and the next handoff reads it |
| Theft | Open: a subscriber's site signature is their gateway login |
| Cost | None |

### Same-origin POST from the pricing page

| Dimension | Assessment |
|---|---|
| Fixation | Closed for the handoff request itself; a planted cookie is still read |
| Theft | Open |
| Cost | A form instead of a link |

### The gateway runs its own Patreon login

| Dimension | Assessment |
|---|---|
| Fixation, theft | Closed |
| Cost | A Patreon client, callback and tier lookup in the gateway, which today knows nothing of tiers |

### Patreon round trip from the site, chosen

| Dimension | Assessment |
|---|---|
| Fixation, theft | Closed: the token comes from Patreon's answer for this browser's own flow |
| Cost | One redirect through patreon.com per API sign-in, or a click when Patreon asks to approve the app again |
| Gateway | Unchanged: same token, same routes |

## Consequences

- **The handoff works signed out.** A reader with a Patreon pledge can reach
  the gateway without signing in to the site first.
- **`UserEmailUnverified` no longer guards the gateway.** The pricing page
  still reads it to pick its button, and the alerts API to refuse an
  unconfirmed caller, so it stays signed. A new consumer that turns the email into an
  identity elsewhere should ask Patreon the same way rather than read the
  cookie.
- **The handoff needs the Patreon client configured** (`patreon.source` and
  its `client` entry), as the site login does, and the deployment's origin
  registered as a redirect URI. Without either it says the handoff is off.
- **`-dev` can no longer fake a handoff with a cookie.** Trying it locally
  needs a Patreon client whose redirect URI is the local origin.

## Action items

1. [ ] Deploy every site together, as with any handoff change: each one can
   sign any email in to the gateway.
2. [ ] Confirm each deployment's Patreon client lists its own `/auth` as a
   redirect URI, which the site login already needs.
