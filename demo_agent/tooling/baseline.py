from __future__ import annotations

import re
from typing import Any, Dict, List

from langchain_core.tools import tool

from ..clients.abuse_ch import ThreatFoxClient, URLhausClient
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

_CACHE_THREATFOX: Dict[str, Dict[str, Any]] = {}
_CACHE_URLHAUS: Dict[str, Dict[str, Any]] = {}
_CACHE_ABUSECH: Dict[str, Dict[str, Any]] = {}
_THREATFOX_SUPPORTED_TYPES = {"IP", "DOMAIN", "URL", "MD5", "SHA256"}
_URLHAUS_SUPPORTED_TYPES = {"IP", "DOMAIN", "URL", "SHA256"}


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


def _dedupe_result_rows(rows: List[Dict[str, Any]], *, limit: int = 8) -> List[Dict[str, Any]]:
    kept: List[Dict[str, Any]] = []
    seen = set()
    for row in rows:
        title = strip_quotes(row.get("title"))
        url = strip_quotes(row.get("url"))
        snippet = strip_quotes(row.get("snippet"))
        key = (title, url, snippet)
        if key in seen:
            continue
        seen.add(key)
        kept.append(row)
        if len(kept) >= limit:
            break
    return kept


def _supports_threatfox(indicator_type: str) -> bool:
    return strip_quotes(indicator_type).upper() in _THREATFOX_SUPPORTED_TYPES


def _supports_urlhaus(indicator_type: str) -> bool:
    return strip_quotes(indicator_type).upper() in _URLHAUS_SUPPORTED_TYPES


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
def threatfox_ioc_lookup(indicator_value: str, indicator_type: str = "") -> str:
    """Query ThreatFox Community API for an IOC/hash and return structured JSON."""
    indicator_value = strip_quotes(indicator_value)
    indicator_type = strip_quotes(indicator_type).upper() or _infer_indicator_type(indicator_value)
    cache_key = f"{indicator_type}::{indicator_value}"
    if cache_key in _CACHE_THREATFOX:
        cached = dict(_CACHE_THREATFOX[cache_key])
        cached["cache_hit"] = True
        return dumps_json(cached)
    if not _supports_threatfox(indicator_type):
        obs = {
            "enabled": True,
            "ok": False,
            "indicator_type": indicator_type,
            "indicator_value": indicator_value,
            "note": f"ThreatFox structured lookup does not support {indicator_type} directly.",
            "skipped": True,
            "source": "threatfox.abuse.ch",
        }
        _CACHE_THREATFOX[cache_key] = obs
        return dumps_json(obs)

    client = ThreatFoxClient()
    obs = client.search_indicator(indicator_value=indicator_value, indicator_type=indicator_type)
    _CACHE_THREATFOX[cache_key] = obs
    return dumps_json(obs)


@tool
def urlhaus_ioc_lookup(indicator_value: str, indicator_type: str = "") -> str:
    """Query URLhaus Community API for a host/url/hash and return structured JSON."""
    indicator_value = strip_quotes(indicator_value)
    indicator_type = strip_quotes(indicator_type).upper() or _infer_indicator_type(indicator_value)
    cache_key = f"{indicator_type}::{indicator_value}"
    if cache_key in _CACHE_URLHAUS:
        cached = dict(_CACHE_URLHAUS[cache_key])
        cached["cache_hit"] = True
        return dumps_json(cached)
    if not _supports_urlhaus(indicator_type):
        obs = {
            "enabled": True,
            "ok": False,
            "indicator_type": indicator_type,
            "indicator_value": indicator_value,
            "note": f"URLhaus structured lookup does not support {indicator_type} directly.",
            "skipped": True,
            "source": "urlhaus.abuse.ch",
        }
        _CACHE_URLHAUS[cache_key] = obs
        return dumps_json(obs)

    client = URLhausClient()
    obs = client.lookup_indicator(indicator_value=indicator_value, indicator_type=indicator_type)
    _CACHE_URLHAUS[cache_key] = obs
    return dumps_json(obs)


@tool
def abuse_ch_lookup(indicator: str, indicator_type: str = "", max_results: int = 5) -> str:
    """Query abuse.ch related sources through structured APIs first, then constrained search fallback."""
    indicator = strip_quotes(indicator)
    indicator_type = strip_quotes(indicator_type).upper() or _infer_indicator_type(indicator)
    cache_key = f"{indicator_type}::{indicator}::{max_results}"
    if cache_key in _CACHE_ABUSECH:
        cached = dict(_CACHE_ABUSECH[cache_key])
        cached["cache_hit"] = True
        return dumps_json(cached)

    query = " ".join(part for part in [indicator_type, indicator] if part).strip() or indicator
    structured_rows: List[Dict[str, Any]] = []

    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        future_threatfox = None
        future_urlhaus = None
        if _supports_threatfox(indicator_type):
            future_threatfox = executor.submit(
                ThreatFoxClient().search_indicator, indicator_value=indicator, indicator_type=indicator_type
            )
        if _supports_urlhaus(indicator_type):
            future_urlhaus = executor.submit(
                URLhausClient().lookup_indicator, indicator_value=indicator, indicator_type=indicator_type
            )

        if future_threatfox is not None:
            try:
                threatfox_obs = future_threatfox.result(timeout=25)
            except Exception as exc:
                threatfox_obs = {"ok": False, "error": str(exc)}
        else:
            threatfox_obs = {
                "enabled": True,
                "ok": False,
                "indicator_type": indicator_type,
                "indicator_value": indicator,
                "note": f"ThreatFox structured lookup skipped for unsupported type {indicator_type}.",
                "skipped": True,
                "source": "threatfox.abuse.ch",
            }

        if future_urlhaus is not None:
            try:
                urlhaus_obs = future_urlhaus.result(timeout=25)
            except Exception as exc:
                urlhaus_obs = {"ok": False, "error": str(exc)}
        else:
            urlhaus_obs = {
                "enabled": True,
                "ok": False,
                "indicator_type": indicator_type,
                "indicator_value": indicator,
                "note": f"URLhaus structured lookup skipped for unsupported type {indicator_type}.",
                "skipped": True,
                "source": "urlhaus.abuse.ch",
            }

    if threatfox_obs.get("ok"):
        structured_rows.extend(list(threatfox_obs.get("results") or []))

    if urlhaus_obs.get("ok"):
        structured_rows.extend(list(urlhaus_obs.get("results") or []))

    merged_structured = {
        "ok": bool(structured_rows),
        "query": query,
        "results": _dedupe_result_rows(structured_rows, limit=max_results),
        "mode": "abuse_ch_structured",
    }

    web_obs: Dict[str, Any] = {}
    if not merged_structured["results"]:
        constraint = "site:abuse.ch OR site:sslbl.abuse.ch OR site:threatfox.abuse.ch OR site:urlhaus.abuse.ch OR site:bazaar.abuse.ch"
        web_obs = search_web(query=query, max_results=max_results, constraint=constraint)

    merged = merge_search_observations(merged_structured, web_obs)
    merged["source_family"] = "abuse_ch"
    merged["threatfox"] = threatfox_obs
    merged["urlhaus"] = urlhaus_obs
    merged["structured_hits"] = len(list(merged_structured.get("results") or []))
    _CACHE_ABUSECH[cache_key] = merged
    return dumps_json(merged)


@tool
def family_intel_lookup(family: str, context: str = "", max_results: int = 5) -> str:
    """Search malware-family background pages and return highlights plus raw results."""
    family = strip_quotes(family)
    context = strip_quotes(context)
    query = " ".join(part for part in [family, context, "malware family C2"] if part).strip()
    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        future_primary = executor.submit(
            search_web,
            query,
            max_results,
            constraint="site:malpedia.caad.fkie.fraunhofer.de OR site:microsoft.com OR site:abuse.ch OR site:checkpoint.com OR site:trendmicro.com OR site:proofpoint.com",
        )
        future_secondary = executor.submit(search_web, query, max_results)
        try:
            primary = future_primary.result(timeout=20)
        except Exception as exc:
            primary = {"ok": False, "query": query, "error": str(exc)}
        try:
            secondary = future_secondary.result(timeout=20)
        except Exception as exc:
            secondary = {"ok": False, "query": query, "error": str(exc)}
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
