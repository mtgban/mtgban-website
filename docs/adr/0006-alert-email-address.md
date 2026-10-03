# ADR-0006: Storing an alert email address

**Status:** Accepted
**Date:** 2026-10-03
**Deciders:** Vittorio Giovara
**Change:** PR (email-alerts branch)

## Context

Before this, the site kept a user's email address only in the access
grants an admin writes by hand (`access.Grant.Email`); per-user state was
keyed by an unsalted sha256 of the Patreon-verified address
(`userstate.HashEmail`; ADR-0001 covers the verification), and nothing
read a real address back to send to it. Email alerts break that: a deliverer needs somewhere to send to, and a user who
wants alerts on an address Patreon does not have (or does not want tied to
their Patreon login) needs to enter one.

## Decision

`alert_channels` stores the address, one row per user per source:

- A `patreon` row is written at login, only when the user's tier allows
  the email channel (`AlertChannels`). It carries Patreon's verified
  address, confirmed by Patreon itself, so it needs no link of its own.
- A `user` row is written when the owner enters an address on the alerts
  page, and starts unverified: a signed confirmation link
  (`/alerts/confirm`) verifies it, the same shape as `/alerts/unsubscribe`.
  A verified `user` row wins over a `patreon` row.

Four things read it: the evaluator's mail deliverer, to address a digest;
the channels API, to show the owner their own address and to refuse a
confirm mail to an address any user's row marks as complained; and the
mail webhook, to resolve a bounce or complaint report back to a user by
address (`ChannelByAddress`).

It leaves in four ways: the owner's Remove deletes the `user` row outright;
the owner's unsubscribe link, a bounce, or a complaint disable the channel
in place (`disabled_at`, `disabled_reason`) rather than deleting it: a
bounced row can be re-verified, an unsubscribed `patreon` row is turned
back on with Enable, and an unsubscribed `user` row is removed and added
again; and
an unverified `user` row nobody ever confirmed is pruned 7 days after its
address was entered, alongside the alert-events prune. A bounce or
complaint parks the user's email alerts only when no working address is
left; Enable, or a confirm that turns a row back on, returns them.

No mail body or recipient-visible content is stored. A delivery event
records only Resend's message id, which counts a user's mails for the
daily ceiling and a run's mails for the jobs dashboard; the webhook
matches by recipient address. The event has no copy of what was sent.

## Considered and not done

- **A separate suppression table for complaints.** Resend already
  suppresses a complained recipient on its side, so a second list here
  would only duplicate what the provider enforces; left for later if that
  ever proves insufficient.
- **SMTP instead of the HTTP API.** The HTTP API gives a provider message
  id per send, which the daily ceiling counts; SMTP would need an id of
  its own for the same job, for no benefit here.
- **Storing nothing and sending through Patreon.** Patreon has no mail
  relay for third parties, and routing through it would hand it the alert
  content besides, which no other part of this feature does.

## Consequences

- A changed Patreon email is a different hash, so it signs in as a new
  contact with no alerts. The old contact, its rows and its alerts stay
  under the old hash and do not follow. A `user` row stays until the
  owner edits it.
- A tier can be moved off the email channel without touching stored rows
  at all: `AlertChannels` governs who the evaluator will send to, not
  whether a channel row exists. Writing `AlertChannels` to `none` (never
  an empty string, which signing keeps but verification drops, breaking
  every signed page for that tier) is how a tier is given no channels.
- A bounce or complaint is visible on the owner's channel state
  immediately, without waiting for the next login or alert evaluation.
