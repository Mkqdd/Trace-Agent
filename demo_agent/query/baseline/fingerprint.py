from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict

from .common import context_query, first_non_empty, fingerprint_query, lookup_family, lookup_local, merge_searches, search_abuse, search_standard, safe_future_result, timed_call


def investigate_fingerprint(event: Dict[str, Any]) -> Dict[str, Any]:
    fp = event.get("trigger_fingerprint") or {}
    fp_type = str(fp.get("type") or "").upper()
    fp_value = str(fp.get("value") or "")
    hint_family = str((event.get("enrichment") or {}).get("info") or "").strip()

    with ThreadPoolExecutor(max_workers=5) as executor:
        future_local = executor.submit(timed_call, lookup_local, fp_type, fp_value)
        future_fp_standard = executor.submit(timed_call, search_standard, fingerprint_query(fp_type, fp_value, hint_family), 5)
        future_context_standard = executor.submit(timed_call, search_standard, context_query(fp_type, fp_value, hint_family), 5)
        future_abuse = executor.submit(timed_call, search_abuse, fp_value, fp_type, 5)
        future_family = (
            executor.submit(timed_call, lookup_family, hint_family, context=fp_value, max_results=5)
            if hint_family
            else None
        )

        local_timed = safe_future_result(future_local, default={}) or {}
        local_obs = (local_timed.get("value") if isinstance(local_timed, dict) else None) or {}
        local_best = (local_obs or {}).get("best_match") or {}
        family_seed = first_non_empty(local_best.get("malware_family"), hint_family)
        if family_seed and (future_family is None or family_seed != hint_family):
            future_family = executor.submit(timed_call, lookup_family, family_seed, context=fp_value, max_results=5)

        fp_standard_timed = safe_future_result(future_fp_standard, default={}) or {}
        context_standard_timed = safe_future_result(future_context_standard, default={}) or {}
        abuse_timed = safe_future_result(future_abuse, default={}) or {}
        family_timed = safe_future_result(future_family, default={}) if future_family is not None else {"ok": True, "value": None, "duration_s": 0.0}

    fp_standard_obs = (fp_standard_timed.get("value") if isinstance(fp_standard_timed, dict) else None) or {}
    context_standard_obs = (context_standard_timed.get("value") if isinstance(context_standard_timed, dict) else None) or {}
    abuse_obs = (abuse_timed.get("value") if isinstance(abuse_timed, dict) else None) or {}

    fingerprint_obs = merge_searches(
        fp_standard_obs,
        abuse_obs,
    )
    context_obs = merge_searches(
        context_standard_obs,
        abuse_obs,
    )
    family_obs = (family_timed.get("value") if isinstance(family_timed, dict) else None) or None

    return {
        "local_obs": local_obs,
        "obs_fp": fingerprint_obs,
        "obs_context": context_obs,
        "obs_family": family_obs,
        "timings": {
            "local_lookup_s": local_timed.get("duration_s", 0.0),
            "fingerprint_search_s": fp_standard_timed.get("duration_s", 0.0),
            "context_search_s": context_standard_timed.get("duration_s", 0.0),
            "abuse_lookup_s": abuse_timed.get("duration_s", 0.0),
            "family_lookup_s": family_timed.get("duration_s", 0.0),
        },
    }
