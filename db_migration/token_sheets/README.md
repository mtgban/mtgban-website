# Two-sided token sheets

go-mtgban derives a card for each two-sided token sheet TCGplayer sells,
`<face a uuid>_tp_<face b uuid>`, which has no mtgjson uuid of its own.
`magicAlias` (chart.go) files it under the version 5 uuid of face b in face
a's namespace. A row the snapshot filed before that holds face a's uuid
instead, which keeps the next sheet sharing that face, finish and language
out of the table: the snapshot refuses it as respelled.

`prices.sql` moves each such row to the alias the map gives its
`mtgban_id`. It keeps its `ban_id`, its prices and its id, so nothing reads
it differently. It moves only a row whose map uuid differs from the stored
one; a finish or language the matcher now spells otherwise is left as it is.

## Running it

Export `variant_map.tsv` from a build that files the sheets this way, against
the datastore production serves, as in `../mtgban_id/README.md`:

```sh
go build -o mtgban-website .
./mtgban-website -dev -cfg config.json -noload -ds <production datastore>
curl -o variant_map.tsv 'http://localhost:<port>/admin?download=variantmap'
```

Then, from this directory with the TSV beside the script and the
`sql_config` connection in the usual `PG*` variables:

```sh
psql -f prices.sql              # report, rolls back
psql -v apply=1 -f prices.sql   # commit
```

It raises, changing nothing, when the map lists no sheet (an export from an
older build) or when another row already holds an alias a row would move to.
It is safe to repeat. Run it again once the build serves: until then a
snapshot can still file a sheet under its face's alias.
