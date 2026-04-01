from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict

from .common import context_query, first_non_empty, lookup_family, lookup_local, merge_searches, search_abuse, search_standard, enrich_vt, safe_future_result


def investigate_domain_or_url(event: Dict[str, Any]) -> Dict[str, Any]:
    fp = event.get("trigger_fingerprint") or {}
    fp_type = str(fp.get("type") or "").upper()
    fp_value = str(fp.get("value") or "")
    hint_family = str((event.get("enrichment") or {}).get("info") or "").strip()
    query = context_query(fp_type, fp_value, hint_family)

    with ThreadPoolExecutor(max_workers=4) as executor:
        future_local = executor.submit(lookup_local, fp_type, fp_value)
        future_vt = executor.submit(enrich_vt, fp_type, fp_value)
        future_abuse = executor.submit(search_abuse, fp_value, fp_type, 5)
        future_standard = executor.submit(search_standard, query, 5)

        local_obs = safe_future_result(future_local, default={}) or {}
        vt_obs = safe_future_result(future_vt, default={}) or {}
        abuse_obs = safe_future_result(future_abuse, default={}) or {}
        standard_obs = safe_future_result(future_standard, default={}) or {}

    local_best = (local_obs or {}).get("best_match") or {}
    family_seed = first_non_empty(local_best.get("malware_family"), hint_family)
    context_obs = merge_searches(abuse_obs, standard_obs)
    family_obs = lookup_family(family_seed, context=fp_value, max_results=5)

    return {
        "local_obs": local_obs,
        "obs_fp": vt_obs,
        "obs_context": context_obs,
        "obs_family": family_obs,
    }
