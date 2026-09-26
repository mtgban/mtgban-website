# When tcgcsv withdrew the price archive

Background for #577: the non-Magic price history came from tcgcsv's daily
archives, those archives stopped being served in September 2026, and
nothing noticed. This is what happened, what ingestion does about it, and
what would have to change if it comes back.

## What went away

`https://tcgcsv.com/archive/tcgplayer/prices-YYYY-MM-DD.ppmd.7z` was one
solid 7z per day holding every category's price files, from the epoch
(2024-02-08) forward. `Service.Backfill` walked it a day at a time: it is
how a game added to `tcgcsv_config.games` got its history, and how a hole
left by a missed daily run got closed.

Every date under `/archive/` now answers HTTP 403 with this body, and the
FAQ still documents the archive as if it were there:

> The price archive has been temporarily removed due to rising server
> costs and its growing moderation burden. Prices are still being archived
> behind-the-scenes. My goal is to share the price archive once I can get
> further clarification from TCGplayer, and standup a reliable way to
> cover my operating costs.
>
> If you were previously relying on the price archive to pull daily
> pricing, please instead process categories, groups, and prices by making
> multiple requests. [...] There are no workarounds or ways to appeal this
> decision at this time.

Confirmed with the maintainer directly: the archive is still being
recorded, just not published. So the archive reader stays in the tree and
starts working again the moment the 403 stops — this change is about not
depending on it in the meantime, not about removing it.

## What ingestion does now

The daily pull is unaffected, because it was already reading what tcgcsv
asks callers to read: one request for `/tcgplayer/<category>/groups`, then
`/tcgplayer/<category>/<group>/prices` per group. Across the ten
configured games that is about 1,630 requests a run, paced by the client's
150ms throttle.

What changed is the backfill. `tcgcsv.FetchPriceArchive` maps a 403 to
`tcgcsv.ErrArchiveUnavailable`, carrying the notice above so the reason
reaches the logs. The day loop treats that as terminal — it says nothing
about the date asked for, so every remaining day would refuse the same
way — and one refusal, not several hundred, ends the archive attempt.
`Service.backfill` then falls back to the only prices tcgcsv still
publishes:

- The current snapshot is stored when its own date falls inside the
  requested range, so a plain `tcgcsvd -backfill` still leaves every game
  current, and a Discord notice says which range stayed missing. A named
  range or `-force` also ignores the per-category freshness gate, which
  would otherwise make re-fetching the one reachable date a no-op; a plain
  resumed run keeps the gate, so repeating it costs one `last-updated`
  request rather than a whole catalog crawl.
- That crawl runs under the cross-process crawl lock, which the archive
  walk it replaces is exempt from. The exemption is about holding a lock
  for hours; this is the same ~1,630 requests the daily job makes, and
  running it beside that job is what the lock is for. A run that loses the
  lock leaves the crawl to whoever holds it and exits 0.
- A range entirely in the past fails and names it. Storing today's prices
  because someone asked for last July would be a surprise, and that range
  is genuinely unrecoverable.

Two silent-failure holes closed alongside it. A missing 7z binary is now
`tcgcsv.ErrArchiveTooling` and is also terminal in the day loop, which is
what the old up-front `CheckArchiveTooling` call was for; it is looked up
after the fetch rather than before, so a box without p7zip still learns
the archive is withdrawn instead of stopping on tooling it no longer
needs. And a range where *every* requested day answers 404 — how the
archive disappearing would look if it ever 404s instead of 403s — reports
`ErrArchiveUnavailable` rather than a clean run over zero days. A single
404 at the tail of a range stays ordinary: today's archive used to land
after tcgcsv's ~20:05 UTC refresh.

## The gap this leaves

Between the archive going away and this change, days that no daily run
covered are gone for good; tcgcsv has them but won't hand them over.
Going forward the daily pull is the only source, so a stretch of failed
daily runs is now permanent data loss rather than something a backfill
can repair. `tcgcsvd -games` prints each game's newest stored date, which
is the cheapest way to see a game falling behind.

If the archive returns, nothing needs undoing: the 403 stops, the day loop
stops seeing `ErrArchiveUnavailable`, and backfill goes back to reading
history. Getting the missed window back would then be a `-backfill -force`
over it.
