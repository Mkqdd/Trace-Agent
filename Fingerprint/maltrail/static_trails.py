#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Parse Maltrail trails/static (same rules as upstream trails/static/__init__.py).
Used by maltrail_intel; ``STATIC_ROOT`` is set before iteration to repo or bundled path.
"""

from __future__ import print_function

import glob
import os
import re

_HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))

# Overridden by maltrail_intel.resolve_static_root() before use.
STATIC_ROOT = os.path.join(REPO_ROOT, "trails", "static")

_RE_IPV4 = re.compile(r"\A\d+\.\d+\.\d+\.\d+\Z")
_RE_IPV4_PORT = re.compile(r"\A\d+\.\d+\.\d+\.\d+:\d+\Z")
_RE_IPV4_CIDR = re.compile(r"\A\d+\.\d+\.\d+\.\d+/\d+\Z")


def source_for_category(category_dirname):
    if not category_dirname or category_dirname == "static":
        return "maltrail_static"
    return "maltrail_static_%s" % category_dirname


def classify_indicator(value):
    v = value.strip()
    if _RE_IPV4.match(v):
        return "ip"
    if _RE_IPV4_PORT.match(v):
        return "ip_port"
    if _RE_IPV4_CIDR.match(v):
        return "cidr"
    if "/" in v:
        return "url"
    return "domain"


def _sorted_static_directories():
    base = STATIC_ROOT
    dirs = [base] + glob.glob(os.path.join(base, "*"))
    return sorted(
        dirs,
        key=lambda p: (
            -1 if any(x in p for x in ("suspicious", "malicious")) else int("custom" in p),
            p,
        ),
    )


def iter_trail_rows():
    """
    Yields: (indicator_type, indicator_value, malware_family, source, trail_info).
    """
    for directory in _sorted_static_directories():
        if not os.path.isdir(directory):
            continue

        category = os.path.basename(directory)
        if category == "static":
            category = None
        source = source_for_category(category)

        for filepath in glob.glob(os.path.join(directory, "*.csv")):
            malware_family = os.path.splitext(os.path.basename(filepath))[0]
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "," not in line:
                        continue
                    value, info = line.split(",", 1)
                    info = info.strip().strip('"')
                    value = value.strip()
                    if "://" in value:
                        value = re.search(r"://(.*)", value).group(1)
                    value = value.rstrip("/")
                    trail_info = info
                    if "/" in value:
                        v = value
                        yield (classify_indicator(v), v, malware_family, source, trail_info)
                        value = value.split("/")[0]
                    if _RE_IPV4.match(value):
                        yield (classify_indicator(value), value, malware_family, source, trail_info)
                    else:
                        yield (
                            classify_indicator(value.strip(".")),
                            value.strip("."),
                            malware_family,
                            source,
                            trail_info,
                        )

        txt_files = glob.glob(os.path.join(directory, "*.txt"))
        txt_files = sorted(txt_files, key=lambda p: "history" in p)

        for filepath in txt_files:
            malware_family = os.path.splitext(os.path.basename(filepath))[0]
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    line = re.sub(r"\s*#.*", "", line)
                    if "://" in line:
                        line = re.search(r"://(.*)", line).group(1)
                        if "/" not in line:
                            line = "%s/" % line
                    if "/" in line:
                        if line.count("/") > 1:
                            line = line.rstrip("/")
                        yield (classify_indicator(line), line, malware_family, source, None)
                        line = line.split("/")[0]
                    if _RE_IPV4.match(line):
                        yield (classify_indicator(line), line, malware_family, source, None)
                    else:
                        yield (
                            classify_indicator(line.strip(".")),
                            line.strip("."),
                            malware_family,
                            source,
                            None,
                        )
