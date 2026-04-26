from __future__ import annotations

import re
from typing import Any, Dict, List

from langchain_core.tools import tool

from .sources.abuse_ch import ThreatFoxClient, URLhausClient
from .sources.local_intel import LocalIntelClient
from .sources.vt_client import VirusTotalClient
from .common import dumps_json, is_ip, merge_search_observations, search_web, strip_quotes, vt_stats_to_confidence

_CACHE_LOCAL_INTEL: Dict[str, Dict[str, Any]] = {}
_CACHE_VT_IP: Dict[str, Dict[str, Any]] = {}
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


def _supports_threatfox(indicator_type: str) -> bool:
    return strip_quotes(indicator_type).upper() in _THREATFOX_SUPPORTED_TYPES


def _supports_urlhaus(indicator_type: str) -> bool:
    return strip_quotes(indicator_type).upper() in _URLHAUS_SUPPORTED_TYPES


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


def _local_intel_structured_results(raw: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    query = dict(raw.get("query") or {})
    indicator_value = strip_quotes(query.get("indicator_value"))
    indicator_type = strip_quotes(query.get("indicator_type")).upper()
    for match in list(raw.get("matches") or []):
        family = strip_quotes(match.get("malware_family"))
        severity = strip_quotes(match.get("severity"))
        source = strip_quotes(match.get("source")) or "local_intel"
        confidence = int(match.get("confidence") or 60)
        parts = [f"本地情报库命中 {indicator_type or 'IOC'} `{indicator_value}`。"]
        if family:
            parts.append(f"关联家族 `{family}`。")
        if severity:
            parts.append(f"严重度 `{severity}`。")
        if source:
            parts.append(f"来源 `{source}`。")
        rows.append(
            {
                "source": source,
                "url": None,
                "title": f"Local Intel {indicator_type or 'IOC'} {indicator_value}".strip(),
                "snippet": " ".join(part for part in parts if part).strip(),
                "confidence": confidence,
                "family": family,
                "ioc": indicator_value,
                "indicator_type": indicator_type,
                "indicator_value": indicator_value,
                "raw": match,
            }
        )
    return rows


@tool
def local_intel_lookup(indicator_value: str, indicator_type: str = "") -> str:
    """Lookup an IOC/fingerprint in the local threat_intel database, including JA4DB-style fingerprint sources."""
    indicator_value = strip_quotes(indicator_value)
    indicator_type = strip_quotes(indicator_type).upper() or _infer_indicator_type(indicator_value)
    cache_key = f"{indicator_type}::{indicator_value}"
    if cache_key in _CACHE_LOCAL_INTEL:
        cached = dict(_CACHE_LOCAL_INTEL[cache_key])
        cached["cache_hit"] = True
        return dumps_json(cached)

    client = LocalIntelClient()
    obs = client.lookup(indicator_type=indicator_type, indicator_value=indicator_value)
    obs["ok"] = bool(obs.get("matched"))
    obs["indicator_type"] = indicator_type
    obs["indicator_value"] = indicator_value
    obs["source"] = "local_intel"
    obs["results"] = _local_intel_structured_results(obs)
    _CACHE_LOCAL_INTEL[cache_key] = obs
    return dumps_json(obs)


def _vt_ip_structured_result(obs: Dict[str, Any]) -> Dict[str, Any]:
    stats = dict(obs.get("last_analysis_stats") or {})
    ip = strip_quotes(obs.get("ip"))
    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    harmless = int(stats.get("harmless") or 0)
    undetected = int(stats.get("undetected") or 0)
    parts = [
        (
            f"VirusTotal 最近分析显示 IP `{ip}` 的检测统计为 "
            f"malicious={malicious}, suspicious={suspicious}, harmless={harmless}, undetected={undetected}。"
        )
    ]
    if strip_quotes(obs.get("as_owner")):
        parts.append(f"ASN 归属 `{strip_quotes(obs.get('as_owner'))}`。")
    if obs.get("country"):
        parts.append(f"国家 `{strip_quotes(obs.get('country'))}`。")
    if obs.get("reputation") not in (None, ""):
        parts.append(f"信誉分 `{obs.get('reputation')}`。")
    return {
        "source": "virustotal.com",
        "url": f"https://www.virustotal.com/gui/ip-address/{ip}" if ip else None,
        "title": f"VirusTotal IP {ip}" if ip else "VirusTotal IP",
        "snippet": " ".join(part for part in parts if part).strip(),
        "confidence": int(obs.get("confidence") or vt_stats_to_confidence(stats)),
        "ioc": ip,
        "indicator_type": "IP",
        "indicator_value": ip,
        "raw": {
            "stats": stats,
            "asn": obs.get("asn"),
            "as_owner": obs.get("as_owner"),
            "country": obs.get("country"),
            "reputation": obs.get("reputation"),
        },
    }


@tool
def vt_enrich_ip(ip: str) -> str:
    """Use VirusTotal to enrich an external IP and return structured reputation context."""
    ip = strip_quotes(ip)
    if ip in _CACHE_VT_IP:
        cached = dict(_CACHE_VT_IP[ip])
        cached["cache_hit"] = True
        cached["note"] = cached.get("note") or "cached result; do not query again"
        return dumps_json(cached)
    if not is_ip(ip):
        return dumps_json({"enabled": False, "ok": False, "error": "invalid ip", "ip": ip})

    vt = VirusTotalClient()
    if not vt.enabled():
        obs = {"enabled": False, "ok": False, "ip": ip, "indicator_type": "IP", "indicator_value": ip, "note": "VT_API_KEY not set; skipped."}
        _CACHE_VT_IP[ip] = obs
        return dumps_json(obs)

    try:
        enrichment = vt.enrich_ip(ip)
    except Exception as exc:
        obs = {"enabled": True, "ok": False, "ip": ip, "indicator_type": "IP", "indicator_value": ip, "error": str(exc)}
        _CACHE_VT_IP[ip] = obs
        return dumps_json(obs)

    stats = dict(enrichment.stats or {})
    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    reputation = enrichment.reputation if enrichment.reputation is not None else 0
    has_positive_signal = malicious > 0 or suspicious > 0 or reputation < 0
    obs = {
        "enabled": True,
        "ok": has_positive_signal,
        "ip": ip,
        "indicator_type": "IP",
        "indicator_value": ip,
        "mode": "virustotal_ip",
        "country": enrichment.country,
        "asn": enrichment.asn,
        "as_owner": enrichment.as_owner,
        "reputation": enrichment.reputation,
        "last_analysis_stats": stats,
        "confidence": vt_stats_to_confidence(stats),
        "results": [],
    }
    if has_positive_signal:
        obs["results"] = [_vt_ip_structured_result(obs)]
    else:
        obs["note"] = "VirusTotal 已完成查询，但未返回正向恶意检测。"
    _CACHE_VT_IP[ip] = obs
    return dumps_json(obs)


@tool
def vt_enrich_ioc(indicator_value: str, indicator_type: str = "") -> str:
    """Use VirusTotal to enrich an IOC. The current structured tool surface is primarily for external IPs."""
    indicator_value = strip_quotes(indicator_value)
    indicator_type = strip_quotes(indicator_type).upper() or _infer_indicator_type(indicator_value)
    if indicator_type == "IP":
        return vt_enrich_ip.invoke(indicator_value)
    return dumps_json(
        {
            "enabled": VirusTotalClient().enabled(),
            "ok": False,
            "indicator_type": indicator_type,
            "indicator_value": indicator_value,
            "note": f"VirusTotal structured enrichment is currently exposed for IP indicators in this tool surface, not {indicator_type or 'unknown'}.",
        }
    )


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
def abuse_ch_lookup(indicator_value: str, indicator_type: str = "", max_results: int = 5) -> str:
    """Aggregate abuse.ch structured sources first, then fall back to constrained abuse.ch search if needed."""
    indicator_value = strip_quotes(indicator_value)
    indicator_type = strip_quotes(indicator_type).upper() or _infer_indicator_type(indicator_value)
    cache_key = f"{indicator_type}::{indicator_value}::{int(max_results or 5)}"
    if cache_key in _CACHE_ABUSECH:
        cached = dict(_CACHE_ABUSECH[cache_key])
        cached["cache_hit"] = True
        return dumps_json(cached)

    structured_rows: List[Dict[str, Any]] = []
    if _supports_threatfox(indicator_type):
        threatfox_obs = ThreatFoxClient().search_indicator(
            indicator_value=indicator_value,
            indicator_type=indicator_type,
        )
        if threatfox_obs.get("ok"):
            structured_rows.extend(list(threatfox_obs.get("results") or []))
    else:
        threatfox_obs = {
            "enabled": True,
            "ok": False,
            "indicator_type": indicator_type,
            "indicator_value": indicator_value,
            "note": f"ThreatFox structured lookup skipped for unsupported type {indicator_type}.",
            "skipped": True,
            "source": "threatfox.abuse.ch",
        }

    if _supports_urlhaus(indicator_type):
        urlhaus_obs = URLhausClient().lookup_indicator(
            indicator_value=indicator_value,
            indicator_type=indicator_type,
        )
        if urlhaus_obs.get("ok"):
            structured_rows.extend(list(urlhaus_obs.get("results") or []))
    else:
        urlhaus_obs = {
            "enabled": True,
            "ok": False,
            "indicator_type": indicator_type,
            "indicator_value": indicator_value,
            "note": f"URLhaus structured lookup skipped for unsupported type {indicator_type}.",
            "skipped": True,
            "source": "urlhaus.abuse.ch",
        }

    merged_structured = {
        "ok": bool(structured_rows),
        "query": " ".join(part for part in [indicator_type, indicator_value] if part).strip() or indicator_value,
        "results": _dedupe_result_rows(structured_rows, limit=max_results),
        "mode": "abuse_ch_structured",
    }
    web_obs: Dict[str, Any] = {}
    if not merged_structured["results"]:
        web_obs = search_web(
            query=merged_structured["query"],
            max_results=max_results,
            constraint=(
                "site:abuse.ch OR site:sslbl.abuse.ch OR site:threatfox.abuse.ch "
                "OR site:urlhaus.abuse.ch OR site:bazaar.abuse.ch"
            ),
        )

    merged = merge_search_observations(merged_structured, web_obs)
    merged["indicator_type"] = indicator_type
    merged["indicator_value"] = indicator_value
    merged["source_family"] = "abuse_ch"
    merged["threatfox"] = threatfox_obs
    merged["urlhaus"] = urlhaus_obs
    merged["structured_hits"] = len(list(merged_structured.get("results") or []))
    _CACHE_ABUSECH[cache_key] = merged
    return dumps_json(merged)
