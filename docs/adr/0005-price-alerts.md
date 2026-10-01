# ADR-0005: Price alerts

**Status:** Accepted
**Date:** 2026-10-01
**Deciders:** Vittorio Giovara
**Change:** PR #701

## Context

A user saves an alert on a card or sealed product: a side (retail or
buylist), a condition, a set of stores (none means every store they can
see), a reference price and an "above" and/or "below" line. Each game site
evaluates its own alerts after a store's dump installs and sends a Discord
DM through the bot when one fires.

Two facts shape everything below. The evaluator runs in the background, so
it has no cookie to read a user's grants from and cannot ask Patreon
either: the site keeps no Patreon tokens (AGENTS.md invariant 2). And every
game shares one login: the `MTGBAN` cookie sits on `mtgban.com`, every site
signs against the same link, and `acl.json` and the grants are one file
each for all of them.

## Decision

1. **An alert watches the best price in its stores**: the lowest ask on
   retail, the highest offer on buylist. A side fires when that price
   crosses its line, holds until the price comes back across, and waits at
   least six hours between sends. The DM lists every store past the line,
   best first. Counting every store instead fired almost every new alert at
   once, because some store always asks more than the cheapest or pays less
   than the best: a fresh ±20% alert around the best price fired "above" on
   retail (`CK 14.99`, `SCG 12.50` against a best ask of `10.00`) and
   "below" on buylist (`SCG 5.00`, `ABU 6.40` against `8.00`).
2. **A line the price is already past starts disarmed** on create and edit,
   and waits for the price to come back before it can fire. Resuming arms
   both sides: a user resuming an undeliverable alert wants the crossing
   they missed.
3. **The allowance and the store list come from the ACL.** `Alerts` grants
   the page and `AlertsMax` the number of alerts per game site; the
   allowance counts only when both are set. A request reads them off its
   signed values. The evaluator rebuilds the same values from the tier
   stored at the user's last login and their live grant, and on every run
   keeps the newest alerts within the allowance active and parks the rest.
4. **One tier per user, not per game.** The shared cookie already gives a
   user one tier on every site; a per-game tier would leave a user who only
   ever logs in on mtgban.com parked on every other game.
5. **Thirty-one days without a Patreon login parks a user's alerts.** Site
   access ends with the 11-day signature, but alerts are for users who do
   not visit; 31 days is one billing cycle, the time a cancelled patron
   keeps their benefits. Logging in again brings the alerts back at the
   next evaluation.
6. **Roll out before granting.** `Alerts` and `AlertsMax` enter a signature
   only for a tier whose `acl.json` entry carries them, and a build without
   them rejects a cookie that does (ADR-0001). Every site runs this build
   before `acl.json` grants either.

## Considered and not done

- **Making create atomic.** Create counts the user's alerts and scans them
  for a duplicate before inserting, so two creates at once can pass the
  allowance by one or save the same alert twice. The form disables Save
  while a request is in flight, so this takes two tabs; the evaluator parks
  an alert past the allowance on its next run, so what is left is one
  duplicate DM. A unique index over a `TEXT[]` of stores and nullable
  thresholds needs `NULLS NOT DISTINCT` and costs more than that DM.
- **Reading the page's allowance live.** The page and the API read the
  allowance from the signed cookie, as every page reads its grants, so a
  tier or grant change shows there after the next login. The evaluator
  applies the live grant and parks anything past it, so the two disagree
  only until its next run.
- **`SameSite` on the `MTGBAN` cookie, or refusing a missing
  `Sec-Fetch-Site`.** Every write needs an `application/json` body (POST,
  PATCH) or the DELETE method; both force a CORS preflight the API never
  answers, so another site's page cannot send one, whatever the cookie's
  SameSite. `Sec-Fetch-Site: cross-site` is refused on top. The cookie is
  shared by every page and every game, so its attributes are a site-wide
  change, not this feature's.
- **Shipping the verifier a release ahead.** Not needed: no signature
  carries the new fields until `acl.json` grants them (decision 6).

## Consequences

- An alert on a card with widely spread prices does not fire on the
  outliers. A user who wants one store's price watches that store alone.
- A parked alert shows Parked and comes back by itself once there is room;
  only a paused or undeliverable alert offers Resume.
- `AlertsMax` is a signed field name: renaming it after `acl.json` uses it
  takes another deploy of every site and an `acl.json` edit together.
