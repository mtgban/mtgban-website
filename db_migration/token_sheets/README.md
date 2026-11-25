# Two-sided token sheets

go-mtgban derives a card for each two-sided token sheet TCGplayer sells. It
has no mtgjson uuid, so its id is the version 5 uuid of face b in face a's
namespace, with the finish suffix any printing takes (`<uuid>_f`).
`magicAlias` (chart.go) files it under that uuid like any other printing.

Before go-mtgban v0.16.0 the id read `<face a uuid>_tp_<face b uuid>`.
Everything stored under that spelling moves with one script per database:

| script | database | table | done |
|---|---|---|---|
| `ids.sql` | `sql_config` | `variants.mtgban_id` | takes the map's id; alias, `ban_id` and prices stay |
| `user_state.sql` | `user_state_config` | `alerts.card_id` | re-keyed; one marked unresolvable for the missing id is active again |
| | | `user_state` favorites, recents, backpack | each id replaced; `version` bumped where something changed |
| | | `upload_shares.rows` | each id replaced |

Until `ids.sql` runs, the snapshot refuses each sheet as respelled and its
chart is empty. Until `user_state.sql` runs, a saved sheet resolves to
nothing and the evaluator marks its alerts unresolvable.

`prices.sql` is for a row filed under face a's uuid, before the sheets had
an alias of their own. It needs a map from a build before v0.16.0 and has
already run on production.

## Running ids.sql

Export `variant_map.tsv` from a build on go-mtgban v0.16.0 or later, against
the datastore production serves, as in `../mtgban_id/README.md`:

```sh
go build -o mtgban-website .
./mtgban-website -dev -cfg config.json -noload -ds <production datastore>
curl -o variant_map.tsv 'http://localhost:<port>/admin?download=variantmap'
```

Then, from this directory with the TSV beside the script and the
`sql_config` connection in the usual `PG*` variables, as the build deploys:

```sh
psql -f ids.sql              # report, rolls back
psql -v apply=1 -f ids.sql   # commit
```

The report gives `to_move`, the rows taking the map's id, and `unmatched`,
the sheets the map lacks, listed below it (the first 50). Those keep their
id and are still read by `ban:<n>`.

It raises, changing nothing, when the map still lists a `_tp_` id (an export
from an older build) or when another row already holds an id a row would
take. It is safe to repeat. Afterwards a snapshot's completion notice
reports `0 respelled`.

## Running user_state.sql

It needs no map: it finds every `_tp_` id stored and computes the uuid
from its two faces. With the `user_state_config` connection in the usual
`PG*` variables, as the build deploys:

```sh
psql -f user_state.sql              # report, rolls back
psql -v apply=1 -f user_state.sql   # commit
```

The report counts the sheets found, the alerts re-keyed and the
`user_state` and `upload_shares` rows rewritten. A finish suffix stays
where it is: `<a>_tp_<b>_f` becomes `<uuid>_f`.

It uses `uuid_generate_v5` from the `uuid-ossp` extension, installing it
for the run and dropping it again where the database did not have it, so
the role needs `CREATE` on the database. It is safe to repeat.
