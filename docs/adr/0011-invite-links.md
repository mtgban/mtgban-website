# ADR-0011: Invite links with limited uses

**Status:** Accepted
**Date:** 2026-11-25
**Deciders:** Vittorio Giovara
**Change:** PR #1615

## Context

The admin dashboard's Admin Tools card has a Create Invite Link tool
(`adminTools`, admin.go; the form in `templates/admin.html` and
`templates/mobile/admin.html`). It takes a tier and a length of 1 to 30
days and answers with `/?sig=<signature>`: `sign(tier, nil, nil,
duration)`, a signature carrying the tier's ACL values and no name. Any
page that reads `?sig=` keeps it as the `BAN_SIG` cookie
(`noSigning`, `enforceSigning`).

What that tool cannot do:

- **Count uses.** The link is the credential. Everyone it is forwarded to
  gets the same access until it expires, and nothing records that it was
  opened.
- **Say who made it.** Nothing is stored; the only trace is the admin's
  request in the server log.
- **Grant other than a tier.** It signs the tier as the ACL has it. A
  grant (`access.Grant.Overrides`) can add pages and options on top of a
  tier for one email; an invite cannot.
- **Be withdrawn.** A link handed out by mistake works until it expires.

What the site already has that this builds on:

- **The userstate database** (`userstate/`) holds per-user state and
  short-lived shared links (`upload_shares`, `favorites_shares`), keyed by
  random ids, each table created additively at start-up.
  `UserStateDB` is nil when a deployment has none.
- **Authorisation stays in the signature** (AGENTS.md invariant 2). A
  request is never authorised from a database row.
- **Signatures cross sites.** The cookie is set on the apex domain and
  `signatureLink()` is the same on every site, so a signature minted on
  one game's site is read by all of them.
- **The signature lasts at most a month.** `signatureCookieDays` (31)
  caps an invite's access, because the browser drops the cookie after
  that whatever the signature says.
- **Overrides are not filtered.** `applyACL` copies any `OptionalFields`
  key it finds, identity fields (`UserName`, `UserEmail`, `UserTier`,
  `UserEmailUnverified`) included. A login overwrites those from Patreon;
  a nameless signature does not.
- **Nameless signatures are never renewed.** `renewSignature`,
  `resignStale` and `graceSignature` all need `UserEmail`, so a signature
  with none keeps the values it was minted with until it expires, ACL
  edits included, and is then simply gone.
- **Link unfurlers fetch URLs.** Discord, Slack, iMessage and mail
  clients open a pasted link to build its preview, before any person
  clicks it. `alerts/unsubscribe` already splits GET from POST for this.

## Decision

### 1. An Invites tab in the admin, minting from the database

The Create Invite Link tool is removed from both admin templates and from
`adminTools`, along with the `html=invite` label it fed. In its place is
an **Invites** tab in the admin (`/admin?page=invites`), beside People
and Metrics, and on phones an "Open invites" link like the one Metrics
has. It is guarded like the other tabs: the Admin page's ACL flag,
`CanPOST`, the cross-site POST check, and every write in a POST body.

The tab has a form to mint an invite and a table of invites. Each invite
is chosen from these controls:

| Control | Meaning | Bounds |
|---|---|---|
| Tier | The ACL tier the invite signs | Any tier in the ACL that does not open `Admin` |
| Features | Pages and options on top of the tier, stored as overrides | What a grant's overrides accept, less the refused keys below |
| Uses | How many times it can be accepted | 1 (default) to 25 |
| Open for | How long it can be accepted, from minting | 1 hour to 30 days, default 7 days |
| Access | How long each acceptance's signature lasts, from acceptance | 1 to 31 days, default 7 days |
| Note | Who it is for, free text, shown only to admins | 200 characters |

The Features control lists every page and option that any tier in the ACL
sets (no list kept in code), prefilled with the chosen tier's values.
What differs from the tier is saved as the invite's overrides, checked as
a grant's are (`emptyOption`). Overrides add pages and set options; they
cannot take a page away, so an invite that should grant less starts from
a lower tier.

The POST refuses, whatever the form offered: the `Admin` page, as tier or
override, and the identity keys `UserName`, `UserEmail`,
`UserEmailUnverified` and `UserTier` in any override. An invite is a
bearer token that can be forwarded; it must not sign anyone's identity or
the right to mint more invites.

Minting needs the admin's `UserEmail` on the verified signature. An admin
on a nameless signature (an old admin-tier `?sig=` link) is refused; a
`-dev` run without `-sig` records `dev`.

### 2. Codes are eight characters from a 31-letter alphabet

An invite is named by a code of 8 characters drawn with `crypto/rand`
from the lowercase letters and digits without `0 o 1 l i` (31 symbols,
about 40 bits). The URL is `https://<site>/invite/<code>` on whichever
site's admin tab copies it; any site accepts it, checking the tier
against its own ACL. The handler lowercases the code, so one read out or
retyped in capitals still works, and refuses any other shape before it
asks the database. A code that collides with an existing one is drawn
again.

### 3. Opening a link shows a page; accepting it spends a use

`/invite/` is an unsigned sub-page of Admin (`NoSigning: true`, hidden
from the nav), as `/alerts/confirm` is of Alerts, so it is registered with
the pages rather than by hand. It answers 404 when `UserStateDB` is nil.
Both methods are throttled per client address by a limiter of its own,
like `sharedPageLimiter` on the shared favorites page, since `noSigning`
has none. Both answer with `Cache-Control: no-store`, and the route's
metrics label is `/invite/`, never the code.

`GET /invite/<code>` renders a page saying what the invite grants (the
tier, the extra features by name, how long access lasts) and an **Accept
invite** button. It spends nothing and writes nothing, so an unfurler or
a prefetching mail client cannot use up a single-use link. An unknown,
used-up, expired or revoked code gets the same page with one line saying
the invite can no longer be accepted, and no button; which it was is not
said.

The form carries a random nonce. `POST /invite/<code>` (cross-site POSTs
refused) runs one transaction:

1. Spend a use, only while the invite's tier is still one an invite may
   sign (`$2`: the ACL's tiers that do not open `Admin`, read at the
   request):

   ```sql
   UPDATE invites SET uses = uses + 1
    WHERE code = $1 AND tier = ANY($2) AND revoked_at IS NULL
      AND open_until > now() AND uses < max_uses
   RETURNING tier, overrides, access_days
   ```

   A tier renamed, removed or given `Admin` since minting matches nothing:
   no use is spent, the visitor sees the can-no-longer-be-accepted line,
   and the table marks the invite broken.
2. Insert the redemption row (§4), with the nonce.

When the update matches nothing, or the insert hits the unique index, the
transaction rolls back and the nonce is looked up before the invite is
called closed. A second POST with the same nonce waits on the first's row
lock, and once the first commits it either finds the invite used up or
collides on the nonce; either way it is then answered as a repeat
(below), not as closed.

On commit the handler mints `sign(tier, nil, overrides,
time.Until(expires_at))`, `expires_at` being the redemption row's, sets
it with `putSignatureInCookies` and redirects to `/`. Two people pressing
on the last use cannot both get it.

A POST whose nonce is already on a redemption of the same code re-issues
that redemption's signature the same way, so to the same expiry, without
spending: a double click, or a browser that dropped the first response,
does not burn a single-use link. The nonce only ever reached the page
that redeemed. The re-issue checks the tier as a spend does, since it
signs under today's ACL: a tier given Admin since is refused.

**A signed-in visitor.** The invite's signature stays nameless and
replaces theirs, because a named one would be taken for a login:
`decideRenewal` ages a signature from its expiry, so a short named
invite would be renewed from Patreon at once or re-minted by
`resignStale`, dropping the invite's overrides. The GET page tells a
signed-in visitor plainly that accepting signs them out of their account
for the access length, and that they log in again when it ends. Nothing
of theirs is deleted: the userstate API refuses a nameless signature, so
favorites, recents and backpack stop syncing and live in the browser's
own copy, which merges back at the next login; alerts cannot be managed
meanwhile. It does not refuse them.

### 4. Every mint, acceptance and revocation is recorded

Two tables in the userstate database, created additively like the others:

```sql
CREATE TABLE IF NOT EXISTS invites (
    code          TEXT PRIMARY KEY,
    game          TEXT NOT NULL,
    tier          TEXT NOT NULL,
    overrides     JSONB NOT NULL DEFAULT '{}',
    max_uses      INTEGER NOT NULL,
    uses          INTEGER NOT NULL DEFAULT 0,
    access_days   INTEGER NOT NULL,
    open_until    TIMESTAMPTZ NOT NULL,
    note          TEXT NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by    TEXT NOT NULL,   -- the admin's UserEmail
    created_ip    TEXT NOT NULL,
    created_ua    TEXT NOT NULL,
    created_site  TEXT NOT NULL,   -- instance_name, else the request host
    revoked_at    TIMESTAMPTZ,
    revoked_by    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS invites_created ON invites (created_at DESC);

CREATE TABLE IF NOT EXISTS invite_redemptions (
    id            BIGSERIAL PRIMARY KEY,
    code          TEXT NOT NULL REFERENCES invites (code) ON DELETE CASCADE,
    nonce         TEXT NOT NULL,
    redeemed_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ NOT NULL,  -- the signature's own expiry
    ip            TEXT NOT NULL,
    ua            TEXT NOT NULL,
    site          TEXT NOT NULL,
    signed_in     BOOLEAN NOT NULL DEFAULT false
);
CREATE UNIQUE INDEX IF NOT EXISTS invite_redemptions_nonce ON invite_redemptions (code, nonce);
```

*Who* is the admin's `UserEmail`, stored as written since it names
staff. *When* is `created_at`. *Where* is the client's address, the
user agent, and the site that answered. The address comes from a new
helper, `clientAddress`, which applies `BAN_CLIENT_IP_HEADER` the way
`apiLimitAddress` does but does not mask IPv6 to its /64;
`apiLimitAddress` is rewritten on top of it.

Only acceptances that spend a use (or re-issue) are rows. A refused POST
on a code that exists is a line in the Admin log with the code's first
three characters and the address, so a forwarded single-use link shows
up. A POST on an unknown code is not logged, so a stranger cannot fill
the staff channel. Mint and revoke go to `LogPages["Admin"]` as grant
edits do, with the code's first three characters, never the full code
or the note: that log reaches a Discord channel wider than the Admin ACL.

### 5. The table shows every invite; revoking stops acceptances

The table lists every invite in the database, with the game it was minted
on as a column, since an invite minted on one site grants on all of
them. Each row shows the code (with a copy button for the full URL),
note, tier and features, uses as `n / max`, open until, access length,
**last access ends**, who minted it, when and from where, and its state
(open, used up, expired, revoked, broken). Expanding a row lists its
redemptions: when, address, user agent, site, and whether the visitor was
signed in. A **Revoke** button sets `revoked_at` and `revoked_by`.

Revoking stops further acceptances only. A signature already minted
carries no reference back to its invite and works until its own expiry.
"Last access ends" is that bound: the latest acceptance time possible
(`open_until`, or `revoked_at` once revoked) plus `access_days`.

### 6. Rows are pruned after 90 days

A daily job, registered through `addJob`, deletes invites whose
`open_until` (or `revoked_at`) is more than 90 days past, and their
redemptions with them. Every deployment runs it; the delete is
idempotent. The privacy page's usage-data paragraph says that accepting
an invite records the address and browser with the time, deleted about
90 days after the invite expires or is revoked.

### 7. Old links keep working

Signatures already handed out as `/?sig=` links are not touched: they
verify as before until their expiry, at most 31 days after the last one
was minted. Only the minting goes.

## Alternatives considered

**Keep consuming on GET.** One click and the visitor is in, as the
current link does. Every unfurler and prefetcher would spend a use before
the person it was sent to opens it, so a single-use link pasted in
Discord would be dead on arrival. Rejected.

**Sign an `Invite=<code>` field into the invite's signature.** It would
let the site refuse a revoked invite's signatures before they expire,
through an in-memory revoked set kept fresh by a Postgres NOTIFY, as
`patreon_poke` keeps `Pokes`. It adds a signed field and a per-request
check for a case the Access control already bounds. Left for later; it
needs nothing this ADR stores to change.

**Sign the invite with a signed-in visitor's name.** They would keep
favorites, backpack and alerts. Renewal reads a named signature as a
login (§3) and would replace it with their own tier within a request or
two, so the invite would grant nothing. Rejected.

**Turn an accepted invite into a grant.** A signed-in visitor could have
the invite written to the grants file under their Patreon email. That
makes every invite a permanent grant unless someone removes it, and needs
a Patreon login the invitee may not have. The People tab already does
this for people an admin names. Rejected.

**A page of its own in the nav.** It would need its own `NavElem`,
template and ACL flag, or an Admin sub-page whose handler branches on the
path, to get what the admin tabs already have: the guard, the POST
handling and the layout. Rejected.

**Six-character codes.** About 30 bits. Behind the per-address limiter
that would hold too, but eight costs nothing in a link and leaves the
margin to whatever the limiter allows.

## Consequences

- Single-use and few-use links exist. Who made each one, when and from
  where, and when and from where it was accepted, is on the admin page
  for 90 days after it expires or is revoked.
- An invite needs the userstate database. A deployment without one,
  local `-dev` runs without a scratch Postgres included, cannot mint; the
  tab says so.
- Accepting takes a click on a page of ours rather than landing straight
  on the site.
- A signature minted from an invite is a bearer token. Whoever accepts
  can copy the cookie to another browser; uses count acceptances, not
  people.
- An invite's access is fixed when accepted: ACL edits during its access
  length do not reach it, and it is not renewed.
- Options that act on a member's stored state (`AlertsMax`,
  `AlertChannels`, `SearchBackpackMax`, `SearchBackpackTabs`,
  `UploadPublish`) do nothing on a nameless signature. They stay in the
  Features list, which comes from the ACL with no list of its own; one
  line on the tab says that options acting on a member's saved state do
  nothing for an invite.
- A panic while serving `/invite/<code>` is reported with the request URL
  (`recoverPanic`), so that one report puts a full code in the staff
  channel. Panics there are rare and the code may already be spent; the
  report is left as it is.
- The site stores client addresses and user agents in a database, bounded
  by the 90-day prune and named on the privacy page.
- Each new control (Accept invite, the tab's mint, copy and revoke
  buttons) gets a `data-track` name registered in
  `observability/names.go`.

## Open questions

- Is recording the visitor's address and browser on acceptance wanted?
  The request asked who, when and where for the admin who makes a link.
  The acceptance rows are what make a forwarded link visible; a time
  alone would still count uses.
  Answered: yes, each acceptance row keeps the address and browser.
- Is an admin tab the page wanted, or a page of its own?
  Answered: an admin tab, Invites.
