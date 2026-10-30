-- Add variants.mtgban_id, the matcher's id for a Magic printing, and its
-- unique index. See README.md. Run on the direct port before the deploy,
-- outside a transaction (CREATE INDEX CONCURRENTLY cannot run inside one):
--
--   psql -v ON_ERROR_STOP=1 -f 01_column.sql
--
-- Re-running is safe: both statements skip what exists. A CONCURRENTLY build
-- that fails leaves an INVALID index of that name, which IF NOT EXISTS then
-- skips; drop it first with DROP INDEX IF EXISTS variants_mtgban_id_uk.

ALTER TABLE public.variants ADD COLUMN IF NOT EXISTS mtgban_id text;

CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS variants_mtgban_id_uk
    ON public.variants (mtgban_id)
    WHERE mtgban_id IS NOT NULL;
