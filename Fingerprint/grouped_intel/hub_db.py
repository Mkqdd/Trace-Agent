#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Shared helpers: route flat intel-shaped rows into threat_intel_hub.fp_* tables.
Used by ``../intel_hub_ingest.py``.
"""

from __future__ import print_function

import re

BATCH = 3000

TYPE_TO_TABLE = {
    "domain": "fp_domain",
    "ip": "fp_ip",
    "url": "fp_url",
    "cidr": "fp_cidr",
    "ip_port": "fp_ip_port",
    "md5": "fp_md5",
    "sha1": "fp_sha1",
    "sha256": "fp_sha256",
    "ssl_sha1": "fp_ssl_sha1",
    "ja3_md5": "fp_ja3_md5",
    "ja4": "fp_ja4",
    "ja4_string": "fp_ja4_string",
    "ja4s": "fp_ja4s",
    "ja4h": "fp_ja4h",
    "ja4x": "fp_ja4x",
    "ja4t": "fp_ja4t",
    "ja4ts": "fp_ja4ts",
    "ja4tscan": "fp_ja4tscan",
}

_SAFE_TABLE = re.compile(r"\Afp_[a-z0-9_]+\Z")


def table_for_type(indicator_type):
    if not indicator_type:
        return "fp_other"
    t = str(indicator_type).strip().lower()
    return TYPE_TO_TABLE.get(t, "fp_other")


def insert_batch_hub(conn, table, rows, use_other=False):
    if not rows:
        return
    if not _SAFE_TABLE.match(table):
        raise ValueError("bad table %r" % table)
    if use_other:
        sql = """
        INSERT INTO `%s` (legacy_type, indicator_value, malware_family, severity, confidence,
          source, last_updated, trail_info)
        VALUES (%%s, %%s, %%s, %%s, %%s, %%s, %%s, %%s)
        ON DUPLICATE KEY UPDATE
          malware_family = VALUES(malware_family),
          last_updated = VALUES(last_updated),
          trail_info = IFNULL(VALUES(trail_info), trail_info)
        """ % table
    else:
        sql = """
        INSERT INTO `%s` (indicator_value, malware_family, severity, confidence,
          source, last_updated, trail_info)
        VALUES (%%s, %%s, %%s, %%s, %%s, %%s, %%s)
        ON DUPLICATE KEY UPDATE
          malware_family = VALUES(malware_family),
          last_updated = VALUES(last_updated),
          trail_info = IFNULL(VALUES(trail_info), trail_info)
        """ % table
    cur = conn.cursor()
    cur.executemany(sql, rows)
    conn.commit()
    cur.close()


def flush_ready_batches(hub, batches, batch_other):
    for t in list(batches.keys()):
        rows = batches[t]
        while len(rows) >= BATCH:
            insert_batch_hub(hub, t, rows[:BATCH], use_other=False)
            del rows[:BATCH]
    while len(batch_other) >= BATCH:
        insert_batch_hub(hub, "fp_other", batch_other[:BATCH], use_other=True)
        del batch_other[:BATCH]


def finalize_batches(conn, batches, batch_other):
    for t in list(batches.keys()):
        rows = batches[t]
        if rows:
            insert_batch_hub(conn, t, rows, use_other=False)
            del rows[:]
    if batch_other:
        insert_batch_hub(conn, "fp_other", batch_other, use_other=True)
        del batch_other[:]


def route_intel_row(batches, batch_other, itype, val, mf, sev, conf, source, lu, tinfo=None):
    """Append one normalized row into batches (mutates lists)."""
    if not val:
        return
    val = str(val).strip()
    tbl = table_for_type(itype)
    if tbl == "fp_ja4_string":
        if len(val) > 65535:
            val = val[:65535]
    elif len(val) > 512:
        val = val[:512]
    if sev == "":
        sev = None
    src = (source or "")[:64]
    mf = mf if mf is not None else None
    if mf is not None and len(str(mf)) > 128:
        mf = str(mf)[:128]
    tup = (val, mf, sev, conf, src, lu, tinfo)
    if tbl == "fp_other":
        batch_other.append((str(itype or "unknown")[:32],) + tup)
    else:
        batches.setdefault(tbl, []).append(tup)


def ingest_flat_rows(conn, rows):
    """rows: iterable of 7-tuple or 8-tuple (..., trail_info)."""
    batches = {}
    batch_other = []
    n = 0
    for r in rows:
        if len(r) >= 8:
            itype, val, mf, sev, conf, source, lu, tinfo = r[:8]
        else:
            itype, val, mf, sev, conf, source, lu = r[:7]
            tinfo = None
        route_intel_row(batches, batch_other, itype, val, mf, sev, conf, source, lu, tinfo)
        n += 1
        if n % BATCH == 0:
            flush_ready_batches(conn, batches, batch_other)
    flush_ready_batches(conn, batches, batch_other)
    finalize_batches(conn, batches, batch_other)
    return n


def ingest_row_stream(conn, row_iter, progress_every=100000):
    batches = {}
    batch_other = []
    n = 0
    for r in row_iter:
        if len(r) >= 8:
            itype, val, mf, sev, conf, source, lu, tinfo = r[:8]
        else:
            itype, val, mf, sev, conf, source, lu = r[:7]
            tinfo = None
        route_intel_row(batches, batch_other, itype, val, mf, sev, conf, source, lu, tinfo)
        n += 1
        flush_ready_batches(conn, batches, batch_other)
        if progress_every and n % progress_every == 0:
            print("[+] streamed %s rows" % n)
    flush_ready_batches(conn, batches, batch_other)
    finalize_batches(conn, batches, batch_other)
    return n
