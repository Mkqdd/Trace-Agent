from __future__ import annotations

import re
from typing import Any, Dict, List

from langchain_core.tools import tool

from ..clients.local_intel import LocalIntelClient
from ..clients.vt_client import VirusTotalClient
from .common import (
    _CACHE_LOCAL_INTEL,
    _CACHE_VT_IP,
    dumps_json,
    is_ip,
    merge_search_observations,
    search_web,
    strip_quotes,
    vt_stats_to_confidence,
)


def _infer_indicator_type(value: str) -> str:
    value = strip_quotes(value)
    if is_ip(value):
        return "IP"
    if value.startswith(("http://", "https://")):
        return "URL"
    if re.fullmatch(r"[a-fA-F0-9]{32}", value):
        return "MD5"
    if re.fullmatch(r"[a-fA-F0-9]{40}", value):
        return "SSL_SHA1"
    if re.fullmatch(r"[a-fA-F0-9]{64}", value):
        return "SHA256"
    if "." in value and " " not in value and "/" not in value:
        return "DOMAIN"
    return ""


@tool
def local_intel_lookup(indicator_value: str, indicator_type: str = "") -> str:
    """Lookup a fingerprint/IOC in the local MySQL threat_intel.intel table. indicator_type is optional."""
    inferred_type = strip_quotes(indicator_type).upper() or _infer_indicator_type(indicator_value)
    key = f"{inferred_type}::{strip_quotes(indicator_value)}"
    if key in _CACHE_LOCAL_INTEL:
        cached = dict(_CACHE_LOCAL_INTEL[key])
        cached["cache_hit"] = True
        return dumps_json(cached)

    client = LocalIntelClient()
    obs = client.lookup(indicator_type=inferred_type, indicator_value=strip_quotes(indicator_value))
    _CACHE_LOCAL_INTEL[key] = obs
    return dumps_json(obs)


@tool
def vt_enrich_ip(ip: str) -> str:
    """Use VirusTotal to enrich an IP address (IP only). Returns JSON string."""
    ip = strip_quotes(ip)
    if ip in _CACHE_VT_IP:
        cached = dict(_CACHE_VT_IP[ip])
        cached["cache_hit"] = True
        cached["note"] = cached.get("note") or "cached result; do not query again"
        return dumps_json(cached)
    if not is_ip(ip):
        return dumps_json({"enabled": False, "error": "invalid ip", "ip": ip})
    vt = VirusTotalClient()
    if not vt.enabled():
        obs = {"enabled": False, "note": "VT_API_KEY not set; skipped.", "ip": ip}
        _CACHE_VT_IP[ip] = obs
        return dumps_json(obs)
    enrichment = vt.enrich_ip(ip)
    obs = {
        "enabled": True,
        "ip": ip,
        "country": enrichment.country,
        "asn": enrichment.asn,
        "as_owner": enrichment.as_owner,
        "reputation": enrichment.reputation,
        "last_analysis_stats": enrichment.stats,
        "confidence": vt_stats_to_confidence(enrichment.stats),
    }
    _CACHE_VT_IP[ip] = obs
    return dumps_json(obs)


@tool
def vt_enrich_ioc(indicator_value: str, indicator_type: str = "") -> str:
    """Use VirusTotal to enrich an IOC. indicator_type is optional and will be inferred when possible."""
    indicator_type = strip_quotes(indicator_type).upper() or _infer_indicator_type(indicator_value)
    indicator_value = strip_quotes(indicator_value)
    if indicator_type == "IP":
        return vt_enrich_ip.invoke(indicator_value)
    return dumps_json(
        {
            "enabled": False,
            "indicator_type": indicator_type,
            "indicator_value": indicator_value,
            "note": f"VirusTotal enrichment for {indicator_type} is not implemented in baseline tool yet.",
        }
    )


@tool
def standard_web_search(query: str, max_results: int = 5) -> str:
    """Standard baseline web search using fixed templates. Returns JSON string."""
    return dumps_json(search_web(query=query, max_results=max_results))


@tool
def abuse_ch_lookup(indicator: str, indicator_type: str = "", max_results: int = 5) -> str:
    """Query abuse.ch related sources through constrained search. Returns JSON string."""
    indicator = strip_quotes(indicator)
    indicator_type = strip_quotes(indicator_type).upper()
    query = " ".join(part for part in [indicator_type, indicator] if part).strip() or indicator
    constraint = "site:abuse.ch OR site:sslbl.abuse.ch OR site:threatfox.abuse.ch OR site:urlhaus.abuse.ch OR site:bazaar.abuse.ch"
    obs = search_web(query=query, max_results=max_results, constraint=constraint)
    obs["source_family"] = "abuse_ch"
    return dumps_json(obs)


@tool
def family_intel_lookup(family: str, context: str = "", max_results: int = 5) -> str:
    """Search malware-family background pages and return highlights plus raw results."""
    family = strip_quotes(family)
    context = strip_quotes(context)
    query = " ".join(part for part in [family, context, "malware family C2"] if part).strip()
    primary = search_web(
        query=query,
        max_results=max_results,
        constraint="site:malpedia.caad.fkie.fraunhofer.de OR site:microsoft.com OR site:abuse.ch OR site:checkpoint.com OR site:trendmicro.com OR site:proofpoint.com",
    )
    secondary = search_web(query=query, max_results=max_results)
    merged = merge_search_observations(primary, secondary)
    highlights: List[str] = []
    for item in list(merged.get("results") or [])[:5]:
        title = item.get("title") or ""
        url = item.get("url") or ""
        if title and url:
            highlights.append(f"- {title}（{url}）")
        elif title:
            highlights.append(f"- {title}")
    return dumps_json({"ok": merged.get("ok", False), "family": family, "query": query, "highlights": highlights, "raw": merged})
