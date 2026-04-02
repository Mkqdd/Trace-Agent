#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Maltrail → flat intel rows for ``Fingerprint/intel_hub_ingest.py``.

- Static: read ``trails/static`` (or bundled ``Fingerprint/maltrail/trails/static``).
- Dynamic: each ``trails/feeds/*.py`` that defines ``fetch()`` (needs network + repo ``core/common.py``).

Row shape: (indicator_type, indicator_value, malware_family, severity, confidence, source, last_updated).

Paths: this file lives at ``<repo>/Fingerprint/maltrail/maltrail_intel.py`` (repo root = two levels up).
"""

from __future__ import print_function

import glob
import inspect
import os
import sys
from collections import OrderedDict

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
FEEDS_DIR = os.path.join(REPO_ROOT, "trails", "feeds")
LOCAL_TRAILS = os.path.join(HERE, "trails")

MAX_TYPE = 20
MAX_VALUE = 512
MAX_FAMILY = 100
MAX_SOURCE = 50

INFO_NULL_FAMILY = frozenset({"known attacker"})


def _clip(s, n):
    if s is None:
        return None
    s = str(s).strip()
    if len(s) <= n:
        return s
    return s[:n]


def resolve_static_root():
    """Prefer repo trails/static; fall back to Fingerprint/maltrail/trails/static."""
    r = os.path.join(REPO_ROOT, "trails", "static")
    if os.path.isdir(r):
        return r
    local = os.path.join(LOCAL_TRAILS, "static")
    if os.path.isdir(local):
        print("[i] using bundled static: %s" % local)
        return local
    return r


def resolve_feeds_dir():
    r = FEEDS_DIR
    if os.path.isdir(r):
        return r
    local = os.path.join(LOCAL_TRAILS, "feeds")
    if os.path.isdir(local):
        print("[i] using bundled feeds: %s" % local)
        return local
    return r


def _ensure_repo_path():
    if REPO_ROOT not in sys.path:
        sys.path.insert(0, REPO_ROOT)


def _ensure_maltrail_pkg_path():
    """So ``import static_trails`` works when this file is load_module()'d from intel_hub_ingest."""
    if HERE not in sys.path:
        sys.path.insert(0, HERE)


def _intel_source_static(category_dirname, malware_family):
    fam = _clip(malware_family, MAX_SOURCE - 4) or "unknown"
    if not category_dirname or category_dirname == "static":
        p = "Sr_"
    elif category_dirname == "malware":
        p = "Sm_"
    elif category_dirname == "suspicious":
        p = "Ss_"
    elif category_dirname == "malicious":
        p = "Smc_"
    else:
        short = _clip(category_dirname, 3) or "x"
        p = "Sx%s_" % short
    out = (p + fam).replace(" ", "_")
    return _clip(out, MAX_SOURCE)


def _intel_source_dynamic(feed_module):
    base = "f_%s" % (feed_module or "unknown").replace(" ", "_")
    return _clip(base, MAX_SOURCE)


def _dynamic_malware_family(info, feed_module):
    info = (info or "").strip()
    fm = (feed_module or "").strip() or "unknown"
    if info.lower() in INFO_NULL_FAMILY:
        return None
    if not info:
        return _clip(fm, MAX_FAMILY)
    return _clip(info, MAX_FAMILY)


def collect_static_intel_rows():
    _ensure_maltrail_pkg_path()
    _ensure_repo_path()
    import static_trails as _st  # noqa: WPS433 — same directory as this file

    _st.STATIC_ROOT = resolve_static_root()
    from static_trails import iter_trail_rows  # noqa: WPS433

    rows = []
    for itype, value, malware_family, src_tag, _trail_info in iter_trail_rows():
        if src_tag == "maltrail_static":
            cat = None
        elif src_tag.startswith("maltrail_static_"):
            cat = src_tag[len("maltrail_static_") :]
        else:
            cat = None
        source = _intel_source_static(cat, malware_family)
        mf = _clip(malware_family, MAX_FAMILY)
        rows.append(
            (
                _clip(itype, MAX_TYPE),
                _clip(value, MAX_VALUE),
                mf,
                None,
                None,
                source,
                None,
            )
        )
    return rows


def collect_dynamic_intel_rows():
    _ensure_maltrail_pkg_path()
    _ensure_repo_path()
    feeds_dir = resolve_feeds_dir()
    if feeds_dir not in sys.path:
        sys.path.insert(0, feeds_dir)

    from static_trails import classify_indicator  # noqa: WPS433

    rows = []
    feed_files = sorted(
        f
        for f in glob.glob(os.path.join(feeds_dir, "*.py"))
        if not f.endswith("__init__.py")
    )

    for filepath in feed_files:
        name = os.path.splitext(os.path.basename(filepath))[0]
        try:
            mod = __import__(name)
        except Exception as ex:
            print("[x] import %s: %s" % (name, ex))
            continue

        fetch_fn = None
        for fname, fn in inspect.getmembers(mod, inspect.isfunction):
            if fname == "fetch":
                fetch_fn = fn
                break
        if not fetch_fn:
            try:
                sys.modules.pop(name, None)
            except Exception:
                pass
            continue

        try:
            results = fetch_fn()
        except Exception as ex:
            print("[x] fetch %s: %s" % (name, ex))
            try:
                sys.modules.pop(name, None)
            except Exception:
                pass
            continue

        if not results:
            print("[!] empty: %s" % name)
            try:
                sys.modules.pop(name, None)
            except Exception:
                pass
            continue

        src = _intel_source_dynamic(name)
        n = 0
        for trail, pair in results.items():
            if not trail or str(trail).startswith("__"):
                continue
            if isinstance(pair, (tuple, list)) and len(pair) >= 2:
                info, _ref = pair[0], pair[1]
            else:
                info, _ref = repr(pair), ""
            itype = classify_indicator(str(trail).strip())
            mf = _dynamic_malware_family(str(info), name)
            rows.append(
                (
                    _clip(itype, MAX_TYPE),
                    _clip(str(trail).strip(), MAX_VALUE),
                    mf,
                    None,
                    None,
                    src,
                    None,
                )
            )
            n += 1
        print("[+] feed %s: %s rows" % (name, n))
        try:
            sys.modules.pop(name, None)
            del mod
        except Exception:
            pass

    return rows


def merge_maltrail_prefer_static(static_rows, dynamic_rows):
    """
    For each (indicator_type, indicator_value) present in static trails, drop matching
    dynamic feed rows. Static duplicates (same key in multiple files): last wins.

    Two different feeds with the same IOC (and not in static): both rows are kept.
    """
    static_by_key = OrderedDict()
    for r in static_rows:
        static_by_key[(r[0], r[1])] = r
    static_keys = frozenset(static_by_key.keys())
    out = list(static_by_key.values())
    skipped = 0
    for r in dynamic_rows:
        key = (r[0], r[1])
        if key in static_keys:
            skipped += 1
            continue
        out.append(r)
    if skipped:
        print("[i] Maltrail dedupe (static over feed): skipped %s dynamic rows already in static" % skipped)
    return out
