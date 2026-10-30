# variants.mtgban_id

Phase B keys Magic price rows on the matcher's own id (`CardObject.UUID`:
`<uuid>`, `<uuid>_f`, `<uuid>_alt`) instead of rebuilding identity from the
alias columns of `variants`. `mtgban_id` is the nullable `text` column that
holds it, with a partial unique index `variants_mtgban_id_uk`. It stays NULL
for non-Magic rows and for printings the datastore no longer knows.

## Order

The Magic site's readers look charts up by `mtgban_id`, so a deploy before
the backfill would show empty charts. The export therefore comes from a local
build, and the backfill runs before the deploy.

1. Column (`01_column.sql`), on the direct port, before the deploy.
2. Export `variant_map.tsv` from a local dev build of the exact commit being
   deployed, with the same go-mtgban version in `go.mod`, against the
   production datastore file. The map is right only for the matcher that
   will serve, and the backfill cannot detect a mismatch.

   ```sh
   go build -o mtgban-website .
   ./mtgban-website -dev -cfg config.json -noload -ds <production datastore.json.xz>
   curl -o variant_map.tsv 'http://localhost:<port>/admin?download=variantmap'
   ```

   With `-dev` and without `-sig` the server checks no signature, so the
   plain curl needs no login; opening the URL in a browser works as well.
   `wc -l variant_map.tsv` is the datastore's printing count plus the
   header line.
3. Backfill (`02_backfill.sql`), from this directory with the TSV beside it:
   dry run first, then `-v apply=1`.
4. Deploy the Magic site. The other games' sites and `cmd/tcgcsvd` deploy
   from the same commit for the `timeseries` change, in any order, but only
   after step 1: a build started before the column exists relies on the
   startup ensure, whose failure is only logged and then breaks the variant
   cache's warm pass.
5. Trigger a snapshot from the admin page. It adopts every alias-only row
   minted between the backfill and the deploy. Its completion notice must
   report `0 respelled`; any other count means the map came from another
   matcher, and a separate notice lists the first respelled ids. The export
   and backfill are idempotent: repeat both after the deploy if the
   verifying count below stays above the dry run's `unmatched`.
6. Verify (below).

## Rollback

Redeploy the previous build. The column and the ids stay, nothing reads them,
and a repeat of the backfill is a no-op.

## Column

Run on the direct port, outside a transaction, with the connection in the
usual `PG*` variables:

```sh
psql -v ON_ERROR_STOP=1 -f 01_column.sql
```

It is safe to repeat: a second run changes nothing.

The startup ensure (`EnsureVariantsSchema`) is a fallback for a fresh or
scratch database, not a substitute for this script: on production it would
build the index without `CONCURRENTLY`, blocking writes to `variants`
meanwhile. It asks the catalog first and runs no DDL once the column and the
index both exist.

The index is built `CONCURRENTLY`, so writes continue meanwhile. If that
build fails it leaves an INVALID index under the same name, and re-running
skips it. Drop it, then run again:

```sql
DROP INDEX IF EXISTS variants_mtgban_id_uk;
```

## Verifying

```sql
SELECT count(*) FROM information_schema.columns
 WHERE table_name = 'variants' AND column_name = 'mtgban_id';   -- 1
SELECT indisvalid FROM pg_index
 WHERE indexrelid = 'variants_mtgban_id_uk'::regclass;          -- t
```

## Backfill

```sh
psql -v ON_ERROR_STOP=1 -f 02_backfill.sql              # report, rolls back
psql -v ON_ERROR_STOP=1 -v apply=1 -f 02_backfill.sql   # commit
```

It raises, changing nothing, when the map holds a `mtgban_id` or an alias
key twice, when a mapped id is already stored on another alias, or when an
alias already holds an id other than the map's. It also raises, after the
report, when `unmatched` exceeds 5000, which means a map from another
datastore rather than retirements; `-v force=1` goes on regardless. The
report gives:

- `to_set`: Magic rows with no id that the map names.
- `already_set`: rows already holding the map's id.
- `unmatched`: Magic rows the map lacks, listed by uuid and language (the
  first 50, with the total). Expect retired printings, in the hundreds; they
  keep `mtgban_id` NULL and are still read by `ban:<n>`.
- `map_only`: map rows with no variant yet, printings no store has priced.
- `set`: the rows the UPDATE gave an id, equal to `to_set`.
- `still_null`: Magic rows left without an id, equal to `unmatched` after an
  apply.

## Verifying after the deploy

```sql
SELECT count(*) FROM variants
 WHERE mtgjson_uuid IS NOT NULL AND mtgban_id IS NULL;
```

It is at or below the dry run's `unmatched`. Above it, the snapshot has not
run yet (or rows were minted since the export): trigger it, or repeat the
export and backfill. Then the four charts (a 4EDALT card, a Japanese Secret
Lair card, an etched card, a retired printing's `ban:<n>`) read the same as
before, and the snapshot's completion notice reports `0 respelled`.
