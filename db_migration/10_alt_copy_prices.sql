-- Puts back the prices that the Alternate Fourth Edition copies and their 4ED
-- originals filed on each other's variants, in two windows:
--   2025-07-01 to 2025-09-30: 4ED prices on the copies' variants;
--   2026-03-28 to :until, the deploy that keyed is_alt off the copy: the copies'
--   Cardmarket prices on the originals'.
--
-- Cardmarket is the one store that prices the copies, at a median 31x their
-- original, so each Cardmarket row goes to the card whose price level it sits
-- closer to, measured on each card's own history outside both windows. Any
-- other store's row on a copy's variant is the original's, except ABU's before
-- 2025-09: it bought the copies until then. A row whose right variant already
-- holds that day is dropped, and the rest move.
--
-- Run it after 09_alt_copies.sql, which leaves only the copies' variants with
-- is_alt, with until set to the day the fix deployed. It is safe to run again.
--
--   psql ... -v until=2026-10-27 -f 10_alt_copy_prices.sql
\if :{?until}
\else
  \echo 'Set until to the deploy date: -v until=YYYY-MM-DD'
  \quit
\endif

BEGIN;

CREATE TEMP TABLE alt_pairs ON COMMIT DROP AS
SELECT o.ban_id AS plain_id, a.ban_id AS alt_id
  FROM public.variants a
  JOIN public.variants o
    ON o.mtgjson_uuid = a.mtgjson_uuid AND NOT o.is_alt
   AND o.is_foil = a.is_foil AND o.is_etched = a.is_etched AND o.language = a.language
 WHERE a.is_alt AND a.mtgjson_uuid IS NOT NULL;

DO $$
BEGIN
    IF (SELECT count(*) FROM public.variants WHERE is_alt) > 378 THEN
        RAISE EXCEPTION 'is_alt is on more than the 378 copies: run 09_alt_copies.sql first';
    END IF;
END $$;

CREATE TEMP TABLE alt_levels ON COMMIT DROP AS
SELECT ap.plain_id, p.provider,
       percentile_cont(0.5) WITHIN GROUP (ORDER BY p.price) FILTER (WHERE p.ban_id = ap.plain_id) AS plain_mid,
       percentile_cont(0.5) WITHIN GROUP (ORDER BY p.price) FILTER (WHERE p.ban_id = ap.alt_id) AS alt_mid
  FROM alt_pairs ap
  JOIN public.prices p ON p.ban_id IN (ap.plain_id, ap.alt_id)
  JOIN public.providers pr ON pr.id = p.provider AND pr.shorthand IN ('MKMLow', 'MKMTrend')
 WHERE p.price > 0 AND p.date < '2026-03-28'
   AND p.date NOT BETWEEN '2025-07-01' AND '2025-09-30'
 GROUP BY 1, 2;

CREATE TEMP TABLE alt_misfiled ON COMMIT DROP AS
SELECT p.ban_id AS from_id,
       CASE WHEN p.ban_id = ap.plain_id THEN ap.alt_id ELSE ap.plain_id END AS to_id,
       p.date, p.provider, p.price
  FROM alt_pairs ap
  JOIN public.prices p ON p.ban_id IN (ap.plain_id, ap.alt_id)
  JOIN public.providers pr ON pr.id = p.provider
  LEFT JOIN alt_levels l ON l.plain_id = ap.plain_id AND l.provider = p.provider
 WHERE (p.date BETWEEN '2025-07-01' AND '2025-09-30'
        OR (p.date >= '2026-03-28' AND p.date < DATE :'until'))
   AND CASE WHEN pr.shorthand IN ('MKMLow', 'MKMTrend') THEN
            p.price > 0 AND l.plain_mid > 0 AND l.alt_mid > 0
            AND (abs(ln(p.price / l.alt_mid)) < abs(ln(p.price / l.plain_mid))) <> (p.ban_id = ap.alt_id)
       ELSE p.ban_id = ap.alt_id AND (pr.shorthand <> 'ABUBuylist' OR p.date >= '2025-09-01')
       END;

-- Deleting first frees the targets of two rows that swapped variants on a day.
DELETE FROM public.prices p
 USING alt_misfiled m
 WHERE p.ban_id = m.from_id AND p.date = m.date AND p.provider = m.provider;

WITH moved AS (
    INSERT INTO public.prices (ban_id, date, provider, price)
    SELECT to_id, date, provider, price FROM alt_misfiled
        ON CONFLICT (ban_id, date, provider) DO NOTHING
    RETURNING ban_id
)
SELECT count(*) FILTER (WHERE ban_id IN (SELECT plain_id FROM alt_pairs)) AS moved_to_originals,
       count(*) FILTER (WHERE ban_id IN (SELECT alt_id FROM alt_pairs)) AS moved_to_copies,
       (SELECT count(*) FROM alt_misfiled) - count(*) AS dropped
  FROM moved;

COMMIT;
