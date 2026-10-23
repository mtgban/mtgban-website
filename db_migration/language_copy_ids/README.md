# Language copy ids

go-mtgban names its Japanese (SLD, PURL) and Italian (LEGITA, DRKITA) copies by
the uuid mtgjson gives that printing in `foreignData`, instead of
`{english uuid}_jpn` / `_ita` (mtgban/go-mtgban#1281). `migrate.sql` moves
everything stored under the old ids onto the new ones:

| table | keyed by | done |
|---|---|---|
| `variants` (and `prices` through `ban_id`) | uuid's first 36 chars + language | re-keyed; merged where the new id already has a row |
| `product_prices` | uuid's first 36 chars + language | re-keyed; a day the new id already has keeps it |
| `alerts.card_id` | full id | re-keyed; one marked unresolvable for the missing id is active again |
| `user_state` favorites, recents, backpack | full ids in JSON | each whole id replaced; `version` bumped where something changed |
| `upload_shares.rows` | full ids in text | each whole id replaced |

## Running it

Run it right after the build with the new go-mtgban is serving, from this
directory, with the `sql_config` connection in the usual `PG*` variables:

```sh
psql -v apply=0 -f migrate.sql   # dry run: prints what it would change, rolls back
psql -v apply=1 -f migrate.sql   # commit
```

It runs in one transaction and is safe to repeat: a second run finds nothing to
move. Repeat it if the old build wrote prices after a run. No restart is
needed, since a re-keyed variant keeps its `ban_id`.

## The map

`id_map.tsv` holds every id that changes, old then new: 536 ids (SLD 106,
PURL 1, LEGITA 310, DRKITA 119), built from the 2026-10-23 AllPrintings. It
was made by loading that file with go-mtgban before and after #1281 and
joining the non-English printings on set, number, side, name, language and
finish, which neither version changes; both mint the same 169,370 uuids.
Rebuild it the same way if go-mtgban gains a language copy before this runs.
