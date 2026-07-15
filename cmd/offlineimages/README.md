# offlineimages

Mirrors card images from upstream CDNs into the offline bucket so the
website can serve them without hitting external hosts.

## What it does

1. Reads the full card catalog from the mtgmatcher datastore.
2. Compares each card's image URL against the mirror state
   (`mirror-state.json`). Any URL that has changed or is absent is
   queued for a fresh fetch.
3. Downloads images with per-domain rate limiting (100 ms between
   requests per source domain) and exponential backoff on 429/5xx.
4. Optionally transcodes each JPEG to WebP with `cwebp -q 80`. If
   `cwebp` is not on PATH the original JPEG is stored instead.
5. Writes the image into `images/<uuid>.webp` (or `.jpg`).
6. Rebuilds per-set ZIP bundles and updates `images-manifest.json`
   with new hashes and byte counts.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-config` | `config.json` | Path to the website `config.json` |
| `-sets` | (all) | Comma-separated set codes to restrict the run |
| `-dry-run` | false | Print plan without writing anything |

## Incremental contract

A card's image is only re-fetched when its URL changes in the
datastore. The mirror state tracks the SHA-256 of the fetched source bytes and
the source URL; a URL change is the refetch trigger.

Bundle ZIPs are rebuilt only for sets whose per-image digest set has
changed. The manifest is merged: sets outside the current run scope
keep their existing manifest entries untouched.

## Backfill marker and website autosync

A full, successful run with no `-sets` and no `-dry-run` writes
`mirror-backfill-complete.json` next to `mirror-state.json`. Once that
marker exists, the website process auto-syncs small deltas (up to 2000
pending images) whenever the datastore reloads, with a daily backstop.
Larger deltas alert and wait for a manual run of this binary.

Deleting the marker from the bucket pauses autosync until the next full
successful run rewrites it.

Deployments that completed their backfill before the marker existed need
one more full run (cheap, incremental) to write it and turn autosync on.

## Exit code

The binary exits non-zero when any image fetch fails. Bundle and
manifest writes complete first so the tree remains consistent for
subsequent runs. Use the exit code in cron to detect partial runs.

## Politeness

Each source domain is served by a single goroutine with a 100 ms
minimum gap between requests. `Retry-After` headers are honored up to
a 5-minute cap.

## cwebp

If `cwebp` is available on PATH it is used to transcode each fetched
JPEG to WebP at quality 80. If it is absent or fails, the original
JPEG is stored. The website will serve whichever format is present,
falling back from `.webp` to `.jpg`.

## Suggested cadence

Run once for the initial backfill. After the marker is written the website
handles day-to-day deltas itself; keep an occasional manual or cron run as
a deep backstop and for cap-exceeded alerts.

## Windows path note

`offline_images_path` must be a relative path or a `b2://` URL.
Windows absolute paths (e.g. `C:/mirror`) are rejected at startup
because simplecloud v0.0.9 silently strips the drive letter. This
restriction will be lifted once the upstream fix lands.

## Deferred chore

Old bundle ZIPs (`bundles/<code>-<oldhash>.zip`) are not pruned
automatically. Periodic manual cleanup of stale bundles is a deferred
chore.
