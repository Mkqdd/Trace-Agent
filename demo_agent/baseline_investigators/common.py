from __future__ import annotations

import json
import time
from concurrent.futures import Future
from typing import Any, Dict, Optional

from ..tooling import abuse_ch_lookup, family_intel_lookup, local_intel_lookup, standard_web_search, vt_enrich_ioc
from ..tooling.common import merge_search_observations


def first_non_empty(*values: Any) -> str:
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return ""


def lookup_local(indicator_type: str, indicator_value: str) -> Dict[str, Any]:
    return json.loads(local_intel_lookup.invoke({"indicator_type": indicator_type, "indicator_value": indicator_value}))


def enrich_vt(indicator_type: str, indicator_value: str) -> Dict[str, Any]:
    return json.loads(vt_enrich_ioc.invoke({"indicator_type": indicator_type, "indicator_value": indicator_value}))


def search_standard(query: str, max_results: int = 5) -> Dict[str, Any]:
    return json.loads(standard_web_search.invoke({"query": query, "max_results": max_results}))


def search_abuse(indicator: str, indicator_type: str, max_results: int = 5) -> Dict[str, Any]:
    return json.loads(abuse_ch_lookup.invoke({"indicator": indicator, "indicator_type": indicator_type, "max_results": max_results}))


def lookup_family(family: str, context: str = "", max_results: int = 5) -> Optional[Dict[str, Any]]:
    if not first_non_empty(family):
        return None
    return json.loads(family_intel_lookup.invoke({"family": family, "context": context, "max_results": max_results}))


def merge_searches(*observations: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    return merge_search_observations(*observations)


def safe_future_result(future: Future[Any], default: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    try:
        return future.result()
    except Exception:
        return default


def timed_call(func: Any, *args: Any, **kwargs: Any) -> Dict[str, Any]:
    started = time.perf_counter()
    try:
        value = func(*args, **kwargs)
        return {"ok": True, "value": value, "duration_s": round(time.perf_counter() - started, 4)}
    except Exception as exc:
        return {"ok": False, "value": None, "duration_s": round(time.perf_counter() - started, 4), "error": str(exc)}


def fingerprint_query(fp_type: str, fp_value: str, family_seed: str) -> str:
    prefix = fp_type if fp_type else "indicator"
    return f"{prefix} {fp_value} {family_seed}".strip()


def context_query(fp_type: str, fp_value: str, family_seed: str) -> str:
    fp_type = str(fp_type or "").upper()
    if fp_type == "IP":
        return f"{fp_value} malware C2 {family_seed}".strip()
    if fp_type in {"JA3", "JA4", "SSL_SHA1", "CERT_SHA1"}:
        return f"{fp_type} {fp_value} malware family {family_seed}".strip()
    if fp_type in {"DOMAIN", "URL"}:
        return f"{fp_value} malware phishing payload {family_seed}".strip()
    return f"{fp_type} {fp_value} malware context {family_seed}".strip()
