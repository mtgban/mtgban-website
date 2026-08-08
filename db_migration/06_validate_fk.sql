-- Off-peak: validate the ban_id FK added NOT VALID by 05_indexes.sql (D8).
-- Takes a SHARE UPDATE EXCLUSIVE lock (allows reads/writes) and scans prices once.
\timing on
\echo === VALIDATE prices_ban_id_fk ===
ALTER TABLE public.prices VALIDATE CONSTRAINT prices_ban_id_fk;
\echo === DONE ===
