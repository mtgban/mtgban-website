-- mtgban_id is the matcher's own id for a Magic printing (CardObject.UUID:
-- <uuid>, <uuid>_f, <uuid>_alt), the key price rows are filed under. NULL for
-- non-Magic and for printings the datastore no longer knows. Applied
-- idempotently at startup by (*Client).EnsureVariantsSchema; production gets
-- it from db_migration/mtgban_id/01_column.sql, which builds the index
-- concurrently.
ALTER TABLE public.variants ADD COLUMN IF NOT EXISTS mtgban_id text;
CREATE UNIQUE INDEX IF NOT EXISTS variants_mtgban_id_uk ON public.variants (mtgban_id) WHERE mtgban_id IS NOT NULL;
