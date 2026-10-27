# Language copy ids

go-mtgban names its Japanese (SLD, PURL) and Italian (LEGITA, DRKITA) copies by
the uuid mtgjson gives that printing in `foreignData`, instead of
`{english uuid}_jpn` / `_ita` (mtgban/go-mtgban#1281). Two scripts move
everything stored under the old ids onto the new ones, one per database:

| script | database | table | keyed by | done |
|---|---|---|---|---|
| `prices.sql` | `sql_config` | `variants` (and `prices` through `ban_id`) | uuid's first 36 chars + language | re-keyed; merged where the new id already has a row |
| `user_state.sql` | `user_state_config` | `alerts.card_id` | full id | re-keyed; one marked unresolvable for the missing id is active again |
| | | `user_state` favorites, recents, backpack | full ids in JSON | each whole id replaced; `version` bumped where something changed |
| | | `upload_shares.rows` | full ids in text | each whole id replaced |

`product_prices` is left as it is: nothing writes or reads it.

## Running it

Download the map into this directory and check it first:

```sh
b2 file download b2://mtgban-newspaper/db_migration/language_copy_ids.tsv language_copy_ids.tsv
echo "ab2f6440dd0162bf3d524826d623867445cf066156a69099da038bd681e5b570  language_copy_ids.tsv" | shasum -a 256 -c
```

Run both right after the build with the new go-mtgban is serving, from this
directory, with that database's connection in the usual `PG*` variables:

```sh
psql -v apply=1 -f prices.sql       # sql_config
psql -v apply=1 -f user_state.sql   # user_state_config
```

Without `-v apply=1` a script reports what it would change and rolls back.
Each runs in one transaction and is safe to repeat: a second run finds nothing
to move. Repeat `prices.sql` if the old build wrote prices after a run. No
restart is needed, since a re-keyed variant keeps its `ban_id`, but each site
names it by its old id until its variant index is warmed again: after
`prices.sql`, run a snapshot from the admin page rather than wait for the
next one, up to 12 hours away.

## The map

`language_copy_ids.tsv` holds every id that changes, old then new: 536 ids
(SLD 106, PURL 1, LEGITA 310, DRKITA 119), built from the 2026-10-25
AllPrintings. It was made by loading that file with go-mtgban v0.12.0 and
v0.12.1 (#1281) and joining the non-English printings on set, number, side,
name, language and finish, which neither version changes; both mint the same
169,443 uuids. Rebuild it the same way if go-mtgban gains a language copy
before this runs, then replace it on B2 and its sha256 above.
