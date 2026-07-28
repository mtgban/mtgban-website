#!/usr/bin/env python3
"""Checkpointed driver for the card_prices redesign backfill.

Every unit of work is recorded in migration.progress. Each price chunk runs as a
SINGLE atomic statement (the INSERT and its 'done' marker commit together), so a
disconnect mid-chunk rolls the whole thing back and re-running resumes from the
last committed chunk. Safe to kill and restart at any time.

Usage:
    python3 backfill.py schema      # apply 01_schema.sql + 02_seed_providers.sql (idempotent)
    python3 backfill.py variants    # build Magic + non-Magic variants (skips if done)
    python3 backfill.py seed        # seed migration.progress rows for all price chunks
    python3 backfill.py prices      # run all pending/failed price chunks (resumable)
    python3 backfill.py prices --explain-first   # EXPLAIN one magic + one nonmagic chunk, then run
    python3 backfill.py status      # print migration.status + a per-phase chunk tally
    python3 backfill.py estimate    # sample-based size/row estimate for the full backfill
"""
import json
import os
import subprocess
import sys
from datetime import date

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG = os.path.join(os.path.dirname(HERE), "config.json")

# source column -> provider id (plan 17.5)
MAGIC_COLS = [
    (1,  "cardkingdom_retail_price"),
    (2,  "cardkingdom_buylist_price"),
    (3,  "tcgplayer_low_price"),
    (4,  "tcgplayer_market_price"),
    (8,  "cardmarket_low_price"),
    (9,  "cardmarket_trend_price"),
    (10, "starcitygames_buylist_price"),
    (11, "abu_buylist_price"),
    (12, "coolstuffinc_buylist_price"),
    (13, "tcgplayer_low_sealed_expected_value"),
]
NONMAGIC_COLS = [
    (3, "low_price"),
    (4, "market_price"),
    (5, "mid_price"),
    (6, "high_price"),
    (7, "direct_low_price"),
]

# Session tuning applied to every load connection (all USERSET, no superuser needed).
SESSION_SETUP = (
    "SET synchronous_commit=off; SET work_mem='256MB'; "
    "SET maintenance_work_mem='512MB'; SET statement_timeout=0;"
)


def pgenv():
    with open(CONFIG) as f:
        c = json.load(f)["sql_config"]
    env = dict(os.environ)
    env["PGHOST"] = str(c["host"])
    env["PGPORT"] = str(c["port"])
    env["PGUSER"] = str(c["user"])
    env["PGPASSWORD"] = str(c["password"])
    env["PGDATABASE"] = str(c["dbname"])
    env["PGSSLMODE"] = str(c.get("sslmode", "require"))
    return env


ENV = pgenv()


def psql(sql, capture=True, quiet=True):
    """Run one SQL batch via psql stdin. Returns (rc, stdout)."""
    args = ["psql", "-v", "ON_ERROR_STOP=1", "-X"]
    if quiet:
        args += ["-q"]
    args += ["-f", "-"]
    r = subprocess.run(args, input=sql, env=ENV, text=True,
                       capture_output=capture)
    if r.returncode != 0:
        sys.stderr.write(r.stderr or "")
    return r.returncode, (r.stdout or "")


def query(sql):
    """Run a query, return list of tab-split rows."""
    r = subprocess.run(["psql", "-v", "ON_ERROR_STOP=1", "-X", "-tAF", "\t",
                        "-c", sql], env=ENV, text=True, capture_output=True)
    if r.returncode != 0:
        raise RuntimeError(r.stderr)
    return [line.split("\t") for line in r.stdout.strip().splitlines() if line]


def run_file(fname):
    path = os.path.join(HERE, fname)
    with open(path) as f:
        sql = f.read()
    print(f"  applying {fname} ...", flush=True)
    rc, _ = psql(sql, capture=True)
    if rc != 0:
        raise SystemExit(f"FAILED applying {fname}")


def months(start_ym, end_ym):
    """Inclusive list of first-of-month dates from start_ym to end_ym ('YYYY-MM')."""
    sy, sm = map(int, start_ym.split("-"))
    ey, em = map(int, end_ym.split("-"))
    out = []
    y, m = sy, sm
    while (y, m) <= (ey, em):
        out.append(date(y, m, 1))
        m += 1
        if m > 12:
            m = 1
            y += 1
    return out


def next_month(d):
    return date(d.year + 1, 1, 1) if d.month == 12 else date(d.year, d.month + 1, 1)


def source_range(table):
    rows = query(f"SELECT to_char(min(date),'YYYY-MM'), to_char(max(date),'YYYY-MM') FROM {table}")
    return rows[0][0], rows[0][1]


def nonmagic_categories():
    """Category ids that have a dedicated partition, cheaply from the catalog."""
    rows = query(
        "SELECT regexp_replace(c.relname, '^tcgplayer_nonmagic_product_prices_cat_', '')::int "
        "FROM pg_inherits i JOIN pg_class c ON c.oid=i.inhrelid "
        "JOIN pg_class p ON p.oid=i.inhparent "
        "WHERE p.relname='tcgplayer_nonmagic_product_prices' "
        "AND c.relname ~ '_cat_[0-9]+$' ORDER BY 1")
    return [int(r[0]) for r in rows]


# ---------------------------------------------------------------------------

def cmd_schema():
    run_file("01_schema.sql")
    run_file("02_seed_providers.sql")
    print("schema + providers applied.")


def cmd_variants():
    for phase, sql in (("variants_magic", _variants_magic_sql()),
                       ("variants_nonmagic", _variants_nonmagic_sql())):
        done = query("SELECT status FROM migration.progress WHERE phase=%s AND chunk_key='all'"
                     % _q(phase))
        if done and done[0][0] == "done":
            print(f"  {phase}: already done, skipping.")
            continue
        print(f"  {phase}: building (full-table scan, one pass) ...", flush=True)
        rc, _ = psql(sql)
        if rc != 0:
            raise SystemExit(f"FAILED {phase}")
        n = query("SELECT rows_written FROM migration.progress WHERE phase=%s AND chunk_key='all'"
                  % _q(phase))
        print(f"  {phase}: done, {n[0][0]} new variants.")
    tot = query("SELECT count(*), count(*) FILTER (WHERE mtgjson_uuid IS NOT NULL), "
                "count(*) FILTER (WHERE tcgp_product_id IS NOT NULL) FROM public.variants")
    print(f"variants total={tot[0][0]}  magic={tot[0][1]}  nonmagic={tot[0][2]}")


def _q(s):
    return "'" + s.replace("'", "''") + "'"


def _variants_magic_sql():
    return f"""
WITH ins AS (
  INSERT INTO public.variants (mtgjson_uuid, is_foil, is_etched, is_alt, language)
  SELECT DISTINCT mtgjson_uuid, is_foil, is_etched, is_alt, language
  FROM public.product_prices
  ON CONFLICT (mtgjson_uuid, is_foil, is_etched, is_alt, language)
     WHERE mtgjson_uuid IS NOT NULL DO NOTHING
  RETURNING 1
)
INSERT INTO migration.progress (phase, chunk_key, status, rows_written, started_at, finished_at)
VALUES ('variants_magic','all','done',(SELECT count(*) FROM ins), now(), now())
ON CONFLICT (phase, chunk_key) DO UPDATE
  SET status='done', rows_written=EXCLUDED.rows_written, finished_at=now(), error_msg=NULL;
"""


def _variants_nonmagic_sql():
    return f"""
WITH ins AS (
  INSERT INTO public.variants (tcgp_category_id, tcgp_product_id, tcgp_sub_type)
  SELECT DISTINCT category_id, product_id, coalesce(sub_type_name,'')
  FROM public.tcgplayer_nonmagic_product_prices
  ON CONFLICT (tcgp_category_id, tcgp_product_id, tcgp_sub_type)
     WHERE tcgp_product_id IS NOT NULL DO NOTHING
  RETURNING 1
)
INSERT INTO migration.progress (phase, chunk_key, status, rows_written, started_at, finished_at)
VALUES ('variants_nonmagic','all','done',(SELECT count(*) FROM ins), now(), now())
ON CONFLICT (phase, chunk_key) DO UPDATE
  SET status='done', rows_written=EXCLUDED.rows_written, finished_at=now(), error_msg=NULL;
"""


def build_chunks():
    """Return ordered list of (phase, chunk_key, sql) for every price chunk."""
    chunks = []
    # Magic: one chunk per month.
    mmin, mmax = source_range("public.product_prices")
    for m in months(mmin, mmax):
        ck = m.strftime("%Y-%m")
        chunks.append(("prices_magic", ck, _magic_chunk_sql(m, next_month(m), ck)))
    # Non-Magic: one chunk per (category, month).
    nmin, nmax = source_range("public.tcgplayer_nonmagic_product_prices")
    cats = nonmagic_categories()
    for cat in cats:
        for m in months(nmin, nmax):
            ck = f"cat{cat}-{m.strftime('%Y-%m')}"
            chunks.append(("prices_nonmagic", ck,
                           _nonmagic_chunk_sql(cat, m, next_month(m), ck)))
    return chunks


def _values_list(cols):
    return ",\n       ".join(f"({pid}::smallint, src.{col})" for pid, col in cols)


def _magic_chunk_sql(start, end, ck):
    vals = _values_list(MAGIC_COLS)
    return f"""
WITH ins AS (
  INSERT INTO public.prices (ban_id, date, provider, price)
  SELECT v.ban_id, src.date, u.provider, u.price
  FROM public.product_prices src
  JOIN public.variants v
    ON v.mtgjson_uuid = src.mtgjson_uuid
   AND v.is_foil   = src.is_foil
   AND v.is_etched = src.is_etched
   AND v.is_alt    = src.is_alt
   AND v.language  = src.language
  CROSS JOIN LATERAL (VALUES
       {vals}
  ) AS u(provider, price)
  WHERE src.date >= DATE '{start}' AND src.date < DATE '{end}'
    AND u.price > 0
  RETURNING 1
)
UPDATE migration.progress
   SET status='done', rows_written=(SELECT count(*) FROM ins),
       started_at=now(), finished_at=now(), error_msg=NULL
 WHERE phase='prices_magic' AND chunk_key='{ck}';
"""


def _nonmagic_chunk_sql(cat, start, end, ck):
    vals = _values_list(NONMAGIC_COLS)
    return f"""
WITH ins AS (
  INSERT INTO public.prices (ban_id, date, provider, price)
  SELECT v.ban_id, src.date, u.provider, u.price
  FROM public.tcgplayer_nonmagic_product_prices src
  JOIN public.variants v
    ON v.tcgp_category_id = src.category_id
   AND v.tcgp_product_id  = src.product_id
   AND v.tcgp_sub_type    = src.sub_type_name
  CROSS JOIN LATERAL (VALUES
       {vals}
  ) AS u(provider, price)
  WHERE src.category_id = {cat}
    AND src.date >= DATE '{start}' AND src.date < DATE '{end}'
    AND u.price > 0
  RETURNING 1
)
UPDATE migration.progress
   SET status='done', rows_written=(SELECT count(*) FROM ins),
       started_at=now(), finished_at=now(), error_msg=NULL
 WHERE phase='prices_nonmagic' AND chunk_key='{ck}';
"""


def cmd_seed():
    chunks = build_chunks()
    # Bulk seed pending rows.
    values = ",".join(f"({_q(p)},{_q(c)})" for p, c, _ in chunks)
    sql = (f"INSERT INTO migration.progress (phase, chunk_key) "
           f"VALUES {values} ON CONFLICT (phase, chunk_key) DO NOTHING;")
    rc, _ = psql(sql)
    if rc != 0:
        raise SystemExit("FAILED seeding progress")
    print(f"seeded {len(chunks)} price chunks into migration.progress.")


def cmd_prices(explain_first=False):
    chunks = build_chunks()
    seed_needed = query("SELECT count(*) FROM migration.progress WHERE phase LIKE 'prices_%'")
    if int(seed_needed[0][0]) == 0:
        cmd_seed()
    if explain_first:
        _explain_samples(chunks)

    # Which chunks still need doing?
    done = set()
    for r in query("SELECT phase||'|'||chunk_key FROM migration.progress "
                   "WHERE phase LIKE 'prices_%' AND status='done'"):
        done.add(r[0])
    pending = [(p, c, s) for (p, c, s) in chunks if f"{p}|{c}" not in done]
    total = len(chunks)
    print(f"{total-len(pending)}/{total} chunks already done; running {len(pending)} "
          f"through ONE persistent connection.", flush=True)
    if not pending:
        print("nothing to do.")
        return

    # Stream every chunk through a single psql session. psql is autocommit, so each
    # atomic (insert + mark-done) statement commits on its own — a mid-stream failure
    # or dropped connection leaves the committed chunks done and stops the rest; a
    # re-run resumes from the first still-pending chunk. \echo markers stream to the
    # log; the live source of truth is `SELECT * FROM migration.status`.
    parts = [SESSION_SETUP]
    for i, (phase, ck, sql) in enumerate(pending, 1):
        parts.append(f"\\echo [{i}/{len(pending)}] {phase} {ck}")
        parts.append(sql)
    rc, _ = psql("\n".join(parts), capture=False)
    if rc != 0:
        raise SystemExit("backfill errored (see log). Re-run 'prices' to resume "
                         "from the first still-pending chunk.")
    print("prices backfill complete for all seeded chunks.")


def _explain_samples(chunks):
    for want in ("prices_magic", "prices_nonmagic"):
        for phase, ck, sql in chunks:
            if phase == want:
                inner = sql.split("RETURNING 1")[0]
                inner = inner.replace(
                    "INSERT INTO public.prices (ban_id, date, provider, price)\n  SELECT",
                    "SELECT", 1)
                print(f"\n=== EXPLAIN {phase} {ck} ===")
                rc, out = psql("EXPLAIN " + inner + ";", capture=True, quiet=False)
                print(out)
                break


def cmd_status():
    rc, out = psql(
        "\\echo === migration.status ===\n"
        "SELECT * FROM migration.status;\n"
        "\\echo\n\\echo === price chunk tally ===\n"
        "SELECT phase, status, count(*) FROM migration.progress "
        "WHERE phase LIKE 'prices_%' GROUP BY 1,2 ORDER BY 1,2;\n"
        "\\echo\n\\echo === errored chunks (if any) ===\n"
        "SELECT phase, chunk_key, error_msg FROM migration.progress "
        "WHERE status='error' ORDER BY 1,2;",
        capture=False, quiet=False)


def cmd_estimate():
    """Sample-based estimate of long-form row count + heap size for the full backfill."""
    print("Sampling non-null, >0 price density (this reads small samples) ...", flush=True)
    magic_expr = " + ".join(
        f"count(*) FILTER (WHERE {col} > 0)" for _, col in MAGIC_COLS)
    nm_expr = " + ".join(
        f"count(*) FILTER (WHERE {col} > 0)" for _, col in NONMAGIC_COLS)
    m = query(f"SELECT count(*), ({magic_expr}) FROM public.product_prices "
              f"TABLESAMPLE SYSTEM (0.5)")
    nm = query(f"SELECT count(*), ({nm_expr}) FROM public.tcgplayer_nonmagic_product_prices "
               f"TABLESAMPLE SYSTEM (0.5)")
    mrows_tot = int(query("SELECT reltuples::bigint FROM pg_class WHERE relname='product_prices'")[0][0])
    nm_rows = query("SELECT coalesce(sum(c.reltuples),0)::bigint FROM pg_inherits i "
                    "JOIN pg_class c ON c.oid=i.inhrelid JOIN pg_class p ON p.oid=i.inhparent "
                    "WHERE p.relname='tcgplayer_nonmagic_product_prices'")
    nm_tot = int(nm_rows[0][0])

    def project(sample, total):
        srows = int(sample[0][0]) or 1
        scells = int(sample[0][1])
        return int(scells / srows * total)

    m_cells = project(m, mrows_tot)
    nm_cells = project(nm, nm_tot)
    total = m_cells + nm_cells
    # heap ~ 24B header + 8(ban_id)+4(date)+2(provider)+ ~6(numeric) + padding ≈ ~48B/row
    heap_gb = total * 48 / 1e9
    print(f"  magic source rows   ~{mrows_tot:,} -> price rows ~{m_cells:,}")
    print(f"  nonmagic source rows ~{nm_tot:,} -> price rows ~{nm_cells:,}")
    print(f"  TOTAL price rows     ~{total:,}")
    print(f"  est heap ~{heap_gb:,.0f} GB; + PK idx ~{total*40/1e9:,.0f} GB; "
          f"+ (provider,date) idx ~{total*40/1e9:,.0f} GB")
    print(f"  est prices total on disk ~{heap_gb + total*80/1e9:,.0f} GB")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    cmd = sys.argv[1]
    if cmd == "schema":
        cmd_schema()
    elif cmd == "variants":
        cmd_variants()
    elif cmd == "seed":
        cmd_seed()
    elif cmd == "prices":
        cmd_prices(explain_first=("--explain-first" in sys.argv))
    elif cmd == "status":
        cmd_status()
    elif cmd == "estimate":
        cmd_estimate()
    else:
        print(__doc__)
        raise SystemExit(f"unknown command: {cmd}")


if __name__ == "__main__":
    main()
