-- Fill price_dates from the prices already written: every day each game has
-- under each provider, as far back as the site keeps them (ExpirePriceDates).
-- Each month is its own statement and transaction, newest first, and inserts
-- only the days missing, so a run that stops can be repeated.
--
--   psql -f price_dates.sql                      the last 13 months
--   psql -v from=2026-10-27 -f price_dates.sql   from that day on
\set ON_ERROR_STOP on
\timing on
\if :{?from}
\else
\set from ''
\endif

\ir ../../timeseries/schema_price_dates.sql

-- The game and the rows filed are timeseries.priceDatesGame; a test keeps the
-- two the same.
SELECT format($q$
INSERT INTO price_dates (provider, category, date)
SELECT p.provider, coalesce(v.tcgp_category_id, 1), p.date
  FROM prices p
  JOIN variants v ON v.ban_id = p.ban_id
 WHERE p.date >= %L AND p.date < %L
   AND ((v.mtgjson_uuid IS NOT NULL AND v.language='' AND NOT v.is_alt) OR (v.mtgjson_uuid IS NULL AND v.tcgp_category_id <> 1))
 GROUP BY 1, 2, 3
ON CONFLICT DO NOTHING$q$, greatest(m::date, s.start), (m + interval '1 month')::date)
  FROM (SELECT coalesce(nullif(:'from', '')::date, (current_date - interval '13 months')::date) AS start) AS s,
       generate_series(date_trunc('month', s.start), date_trunc('month', current_date), interval '1 month') AS m
 ORDER BY m DESC
\gexec
