#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Single entry: pull all Fingerprint feeds (network) + Maltrail (static files + dynamic fetch)
into one database **threat_intel_hub**, routed into **fp_*** tables by indicator type.

- Non-Maltrail: reuses logic from Fingerprint/urlhaus, threatfox, SSLBL, ja4_db (fetch/transform).
- Maltrail static: read trails (no HTTP).
- Maltrail dynamic: run each trails/feeds/*.py ``fetch()`` (network).

Prerequisite::

    mysql -h HOST -P PORT -u USER -p < Fingerprint/grouped_intel/schema.sql

Run from **repository root**::

    python Fingerprint/intel_hub_ingest.py
    python Fingerprint/intel_hub_ingest.py --port 3307 --password maltrail_root

By default all ``fp_*`` tables are **truncated** before ingest (full replace). Use ``--incremental`` to only upsert.

"""

from __future__ import print_function

import argparse
import importlib.util
import os
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GROUPED_DIR = os.path.join(REPO_ROOT, "Fingerprint", "grouped_intel")
if GROUPED_DIR not in sys.path:
    sys.path.insert(0, GROUPED_DIR)


def _load_module(abs_path, logical_name):
    spec = importlib.util.spec_from_file_location(logical_name, abs_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _check_hub_schema(conn):
    cur = conn.cursor()
    cur.execute("SHOW TABLES LIKE 'fp_domain'")
    ok = cur.fetchone()
    cur.close()
    if not ok:
        sys.stderr.write(
            "[!] Database %r has no fp_* tables. Create them first, e.g.:\n"
            "    mysql -h HOST -P PORT -u USER -p < Fingerprint/grouped_intel/schema.sql\n"
            % getattr(conn, "db", None)
        )
        sys.exit(1)


def _truncate_all_fp_tables(conn):
    """Empty every fp_* table (full refresh). Names from information_schema only."""
    cur = conn.cursor()
    cur.execute(
        """
        SELECT TABLE_NAME FROM information_schema.TABLES
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = 'BASE TABLE'
          AND TABLE_NAME LIKE 'fp/_%' ESCAPE '/'
        """
    )
    tables = [row[0] for row in cur.fetchall()]
    if not tables:
        cur.close()
        return
    cur.execute("SET FOREIGN_KEY_CHECKS=0")
    for name in tables:
        safe = name.replace("`", "")
        cur.execute("TRUNCATE TABLE `%s`" % safe)
    cur.execute("SET FOREIGN_KEY_CHECKS=1")
    conn.commit()
    cur.close()
    print("[+] Truncated %s fp_* tables (full refresh)" % len(tables))


def _ingest_urlhaus(conn):
    path = os.path.join(REPO_ROOT, "Fingerprint", "urlhaus", "urlhaus_ip_domain_port.py")
    m = _load_module(path, "urlhaus_ingest")
    from hub_db import ingest_flat_rows

    rec = m.fetch_recent_urls()
    data = m.deduplicate_records(m.transform(rec))
    print("[+] URLhaus → hub: %s rows" % len(data))
    ingest_flat_rows(conn, data)


def _ingest_threatfox(conn):
    path = os.path.join(REPO_ROOT, "Fingerprint", "threatfox", "treatfox_ip_domain_port.py")
    m = _load_module(path, "threatfox_ingest")
    from hub_db import ingest_flat_rows

    data = m.transform(m.fetch_threatfox_iocs())
    print("[+] ThreatFox → hub: %s rows" % len(data))
    ingest_flat_rows(conn, data)


def _ingest_sslbl_ja3(conn):
    path = os.path.join(REPO_ROOT, "Fingerprint", "SSLBL", "sslbl_ja3_md5.py")
    m = _load_module(path, "sslbl_ja3_ingest")
    from hub_db import ingest_flat_rows

    m.download_ja3()
    data = m.transform(m.load_csv())
    print("[+] SSLBL JA3 → hub: %s rows" % len(data))
    ingest_flat_rows(conn, data)


def _ingest_sslbl_sha1(conn):
    path = os.path.join(REPO_ROOT, "Fingerprint", "SSLBL", "sslbl_ssl_sha1.py")
    m = _load_module(path, "sslbl_sha1_ingest")
    from hub_db import ingest_flat_rows

    m.download_sslbl()
    data = m.transform(m.load_csv())
    print("[+] SSLBL SSL SHA1 → hub: %s rows" % len(data))
    ingest_flat_rows(conn, data)


def _ingest_ja4(conn):
    path = os.path.join(REPO_ROOT, "Fingerprint", "ja4_db", "ja4db_ja4.py")
    m = _load_module(path, "ja4db_ingest")
    from hub_db import ingest_flat_rows

    rec = m.fetch_ja4db()
    data = m.filter_too_long_records(m.deduplicate_records(m.transform(rec)))
    print("[+] JA4DB → hub: %s rows" % len(data))
    ingest_flat_rows(conn, data)


def _ingest_maltrail(conn, static=True, dynamic=True, maltrail_dedupe_static_over_feed=True):
    path = os.path.join(REPO_ROOT, "Fingerprint", "maltrail", "maltrail_intel.py")
    mt = _load_module(path, "maltrail_intel_ingest")
    from hub_db import ingest_row_stream

    if static and dynamic and maltrail_dedupe_static_over_feed:
        print("[+] Maltrail static (read trail files)...")
        srows = mt.collect_static_intel_rows()
        print("[+] Maltrail dynamic (fetch each feed module)...")
        drows = mt.collect_dynamic_intel_rows()
        rows = mt.merge_maltrail_prefer_static(srows, drows)
        print("[+] Maltrail → hub: %s rows (after static/feed dedupe)" % len(rows))
        ingest_row_stream(conn, rows, progress_every=200000)
        return

    if static:
        print("[+] Maltrail static (read trail files)...")
        rows = mt.collect_static_intel_rows()
        ingest_row_stream(conn, rows, progress_every=200000)
    if dynamic:
        print("[+] Maltrail dynamic (fetch each feed module)...")
        rows = mt.collect_dynamic_intel_rows()
        ingest_row_stream(conn, rows, progress_every=100000)


def main():
    ap = argparse.ArgumentParser(
        description="Fetch/read all configured sources into threat_intel_hub (fp_* tables)."
    )
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=3306)
    ap.add_argument("--user", default="root")
    ap.add_argument("--password", default="123456")
    ap.add_argument("--database", default="threat_intel_hub")
    ap.add_argument("--skip-urlhaus", action="store_true")
    ap.add_argument("--skip-threatfox", action="store_true")
    ap.add_argument("--skip-sslbl-ja3", action="store_true")
    ap.add_argument("--skip-sslbl-sha1", action="store_true")
    ap.add_argument("--skip-ja4", action="store_true")
    ap.add_argument("--skip-maltrail-static", action="store_true")
    ap.add_argument("--skip-maltrail-dynamic", action="store_true")
    ap.add_argument(
        "--no-maltrail-static-feed-dedupe",
        action="store_true",
        help="Allow the same IOC twice when it appears in both static trails and a feed (default: static wins).",
    )
    ap.add_argument(
        "--incremental",
        action="store_true",
        help="Do not truncate: merge into existing rows (ON DUPLICATE KEY UPDATE). Default is full replace.",
    )
    args = ap.parse_args()

    try:
        import pymysql
    except ImportError:
        print("[!] pip install pymysql")
        sys.exit(1)

    os.chdir(REPO_ROOT)

    conn = pymysql.connect(
        host=args.host,
        port=args.port,
        user=args.user,
        password=args.password,
        database=args.database,
        charset="utf8mb4",
    )
    try:
        _check_hub_schema(conn)

        if not args.incremental:
            _truncate_all_fp_tables(conn)

        if not args.skip_urlhaus:
            _ingest_urlhaus(conn)
        if not args.skip_threatfox:
            _ingest_threatfox(conn)
        if not args.skip_sslbl_ja3:
            _ingest_sslbl_ja3(conn)
        if not args.skip_sslbl_sha1:
            _ingest_sslbl_sha1(conn)
        if not args.skip_ja4:
            _ingest_ja4(conn)

        if not args.skip_maltrail_static or not args.skip_maltrail_dynamic:
            _ingest_maltrail(
                conn,
                static=not args.skip_maltrail_static,
                dynamic=not args.skip_maltrail_dynamic,
                maltrail_dedupe_static_over_feed=not args.no_maltrail_static_feed_dedupe,
            )

        print("[+] intel_hub_ingest finished.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
