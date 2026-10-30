# variants.mtgban_id

Phase B keys Magic price rows on the matcher's own id (`CardObject.UUID`:
`<uuid>`, `<uuid>_f`, `<uuid>_alt`) instead of rebuilding identity from the
alias columns of `variants`. `mtgban_id` is the nullable `text` column that
holds it, with a partial unique index `variants_mtgban_id_uk`. It stays NULL
for non-Magic rows and for printings the datastore no longer knows.

## Order

1. Column (`01_column.sql`): run it before the deploy.
2. Deploy.
3. Export: to be written.
4. Backfill: to be written.

## Column

Run on the direct port, outside a transaction, with the connection in the
usual `PG*` variables:

```sh
psql -v ON_ERROR_STOP=1 -f 01_column.sql
```

It is safe to repeat: a second run changes nothing. The startup ensure
(`EnsureVariantsSchema`) is a no-op once this has run; it exists for the
scratch database and fresh installs, whose `01_schema.sql` already has the
column.

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
