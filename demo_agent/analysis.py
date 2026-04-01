import re
from html import unescape
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse

from .renderers.artifacts import severity_from_confidence


_GENERIC_WEB_SOURCES = {"html_fallback", "ddgs", "serpapi", "web_search"}
_HIGH_AUTHORITY_DOMAINS = {
    "virustotal.com": 92,
    "sslbl.abuse.ch": 90,
    "threatfox.abuse.ch": 88,
    "bazaar.abuse.ch": 88,
    "abuse.ch": 86,
    "microsoft.com": 84,
    "malpedia.caad.fkie.fraunhofer.de": 84,
    "spamhaus.org": 82,
    "netskope.com": 80,
    "securityaffairs.com": 78,
    "csirt.cy": 76,
}
_LOW_AUTHORITY_DOMAINS = {
    "trustmyip.com": 35,
    "ja3.me": 35,
    "github.com": 25,
    "forums.malwarebytes.com": 25,
}
_LOW_SIGNAL_TITLE_PARTS = (
    "lookup tool",
    "browse iocs",
    "free ja3 database",
    "github topics",
    "resolved malware",
)
_LOW_SIGNAL_SNIPPET_PARTS = (
    "using the form below, you can search",
    "freely available database of ja3 data",
    "github topics",
)
_LOW_SIGNAL_DOMAIN_PARTS = ("forum", "forums.", "github.com", "trustmyip.com", "ja3.me")
_SEARCH_KIND_STRENGTH = {
    "event": 100,
    "local_intel": 92,
    "hint": 78,
    "enrichment": 82,
    "supplemental": 74,
    "family_intel": 66,
    "search_result": 58,
}


def _first_non_empty(*values: Any) -> Optional[str]:
    for value in values:
        if isinstance(value, str):
            text = value.strip()
            if text:
                return text
    return None


def _first_label(labels: Any) -> Optional[str]:
    if not isinstance(labels, list):
        return None
    for value in labels:
        if isinstance(value, str):
            text = value.strip()
            if text:
                return text
    return None


def _coerce_int(*values: Any, default: int) -> int:
    for value in values:
        if value is None or value == "":
            continue
        try:
            return int(value)
        except Exception:
            continue
    return default


def _clean_text(value: Any) -> str:
    text = unescape(str(value or ""))
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _normalize_url(url: Any) -> Optional[str]:
    text = _clean_text(url)
    if not text:
        return None
    if text.startswith("//"):
        text = f"https:{text}"
    parsed = urlparse(text)
    if "duckduckgo.com" in (parsed.netloc or ""):
        uddg = parse_qs(parsed.query).get("uddg")
        if uddg:
            target = _clean_text(unquote(uddg[0]))
            if target.startswith("//"):
                target = f"https:{target}"
            return target
    return text


def _extract_domain(url: Any) -> str:
    normalized = _normalize_url(url)
    if not normalized:
        return ""
    netloc = urlparse(normalized).netloc.lower().strip()
    if netloc.startswith("www."):
        netloc = netloc[4:]
    return netloc


def _domain_matches(domain: str, needle: str) -> bool:
    return domain == needle or domain.endswith(f".{needle}")


def _source_name(source: Any, url: Any) -> str:
    raw_source = _clean_text(source)
    domain = _extract_domain(url)
    if domain and raw_source.lower() in _GENERIC_WEB_SOURCES:
        return domain
    return raw_source or domain or "unknown"


def _source_authority(source: str, url: Any, kind: str) -> Tuple[int, str]:
    domain = _extract_domain(url)
    normalized = source.lower()
    if normalized == "alert":
        return 95, "原始告警事实"
    if kind == "local_intel":
        return 88, "本地结构化指纹情报"
    if normalized in {"virustotal", "vt"} or _domain_matches(domain, "virustotal.com"):
        return 92, "结构化信誉情报"
    if normalized == "maltrail-static":
        return 76, "本地静态情报命中"
    for known_domain, score in _HIGH_AUTHORITY_DOMAINS.items():
        if _domain_matches(domain, known_domain):
            return score, f"权威外部来源 {domain}"
    for known_domain, score in _LOW_AUTHORITY_DOMAINS.items():
        if _domain_matches(domain, known_domain):
            return score, f"低权重泛化来源 {domain}"
    if domain:
        return 60, f"一般网页来源 {domain}"
    if kind in {"event", "hint"}:
        return 72, "结构化本地信息"
    return 55, "未识别来源"


def _mentions_context(title: str, claim: str, family: str, fp_value: str) -> bool:
    haystack = f"{title} {claim}".lower()
    family_hit = bool(family and family != "Unknown" and family.lower() in haystack)
    fingerprint_hit = bool(fp_value and fp_value.lower() in haystack)
    return family_hit or fingerprint_hit


def _looks_low_signal(title: str, claim: str, url: Any) -> bool:
    lowered = f"{title} {claim}".lower()
    domain = _extract_domain(url)
    if any(part in lowered for part in _LOW_SIGNAL_TITLE_PARTS):
        return True
    if any(part in lowered for part in _LOW_SIGNAL_SNIPPET_PARTS):
        return True
    if any(part in domain for part in _LOW_SIGNAL_DOMAIN_PARTS):
        return True
    return False


def _weight_label(weight: int) -> str:
    if weight >= 85:
        return "高"
    if weight >= 65:
        return "中"
    return "低"


def _score_evidence(item: Dict[str, Any]) -> Tuple[int, str]:
    kind = str(item.get("kind") or "")
    source = _source_name(item.get("source"), item.get("url"))
    authority, authority_reason = _source_authority(source, item.get("url"), kind)
    confidence = _coerce_int(item.get("confidence"), default=50)
    kind_strength = _SEARCH_KIND_STRENGTH.get(kind, 55)
    score = int(round(authority * 0.45 + confidence * 0.35 + kind_strength * 0.20))
    if item.get("url"):
        score += 2
    return max(20, min(99, score)), authority_reason


def _best_local_match(local_intel: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not isinstance(local_intel, dict):
        return None
    best = local_intel.get("best_match")
    return best if isinstance(best, dict) else None


def _append_evidence(evidence: List[Dict[str, Any]], item: Dict[str, Any]) -> None:
    prepared = dict(item)
    prepared["title"] = _clean_text(prepared.get("title"))
    prepared["claim"] = _clean_text(prepared.get("claim"))
    prepared["query"] = _clean_text(prepared.get("query")) or None
    prepared["url"] = _normalize_url(prepared.get("url"))
    prepared["domain"] = _extract_domain(prepared.get("url")) or None
    prepared["source"] = _source_name(prepared.get("source"), prepared.get("url"))

    url = str(prepared.get("url") or "").strip()
    claim = str(prepared.get("claim") or "").strip()
    source = str(prepared.get("source") or "").strip()
    for existing in evidence:
        if url and str(existing.get("url") or "").strip() == url:
            return
        if not url and claim and source:
            if str(existing.get("source") or "").strip() == source and str(existing.get("claim") or "").strip() == claim:
                return
    evidence.append(prepared)


def _should_keep_evidence(item: Dict[str, Any], family: str, fp_value: str) -> bool:
    kind = str(item.get("kind") or "")
    if kind in {"event", "local_intel", "hint", "enrichment", "supplemental"}:
        return True

    title = _clean_text(item.get("title"))
    claim = _clean_text(item.get("claim"))
    url = item.get("url")
    source = _source_name(item.get("source"), url)
    authority, _ = _source_authority(source, url, kind)
    if not title and not claim:
        return False

    context_hit = _mentions_context(title, claim, family, fp_value)
    if _looks_low_signal(title, claim, url) and not context_hit:
        return False

    if kind in {"family_intel", "search_result"} and authority < 70 and not context_hit:
        return False

    return True


def _finalize_evidence(evidence: List[Dict[str, Any]], *, family: str, fp_value: str) -> List[Dict[str, Any]]:
    kept: List[Dict[str, Any]] = []
    for item in evidence:
        if not _should_keep_evidence(item, family=family, fp_value=fp_value):
            continue
        weight, reason = _score_evidence(item)
        finalized = dict(item)
        finalized["weight"] = weight
        finalized["weight_level"] = _weight_label(weight)
        finalized["weight_reason"] = reason
        kept.append(finalized)

    kept.sort(
        key=lambda item: (
            -_coerce_int(item.get("weight"), default=0),
            -_coerce_int(item.get("confidence"), default=0),
            str(item.get("title") or ""),
        )
    )
    for index, item in enumerate(kept, start=1):
        item["id"] = f"e{index:02d}"
    return kept


def _local_family(local_intel: Optional[Dict[str, Any]]) -> Optional[str]:
    best = _best_local_match(local_intel)
    return _first_non_empty((best or {}).get("malware_family"))


def _extract_external_family_candidates(
    *,
    event: Dict[str, Any],
    obs_family: Optional[Dict[str, Any]],
    supplemental: Optional[Dict[str, Any]],
) -> List[str]:
    candidates: List[str] = []
    for value in (
        (event.get("enrichment") or {}).get("info"),
        (obs_family or {}).get("family") if isinstance(obs_family, dict) else None,
        (supplemental or {}).get("candidate_family") if isinstance(supplemental, dict) else None,
    ):
        text = _first_non_empty(value)
        if text and text not in candidates:
            candidates.append(text)
    return candidates


def _select_family(
    *,
    event: Dict[str, Any],
    local_intel: Optional[Dict[str, Any]],
    obs_family: Optional[Dict[str, Any]],
    supplemental: Optional[Dict[str, Any]],
) -> str:
    local_family = _local_family(local_intel)
    external_candidates = _extract_external_family_candidates(event=event, obs_family=obs_family, supplemental=supplemental)
    if local_family:
        return local_family
    if external_candidates:
        return external_candidates[0]
    labels = (event.get("enrichment") or {}).get("labels")
    return _first_label(labels) or "Unknown"


def _build_local_intel_summary(local_intel: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not isinstance(local_intel, dict):
        return {"enabled": False, "matched": False}
    best = _best_local_match(local_intel)
    summary: Dict[str, Any] = {
        "enabled": bool(local_intel.get("enabled")),
        "matched": bool(local_intel.get("matched")),
        "query": local_intel.get("query"),
        "match_count": local_intel.get("match_count") or len(local_intel.get("matches") or []),
        "matches": list(local_intel.get("matches") or []),
    }
    if best:
        summary.update(
            {
                "indicator_type": best.get("indicator_type"),
                "indicator_value": best.get("indicator_value"),
                "malware_family": best.get("malware_family"),
                "severity": best.get("severity"),
                "confidence": best.get("confidence"),
                "source": best.get("source"),
                "last_updated": best.get("last_updated"),
                "best_match": best,
            }
        )
    if local_intel.get("error"):
        summary["error"] = local_intel.get("error")
    return summary


def _build_external_intel(
    *,
    obs_fp: Optional[Dict[str, Any]],
    obs_context: Optional[Dict[str, Any]],
    obs_family: Optional[Dict[str, Any]],
    supplemental: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    return {
        "fingerprint_enrichment": obs_fp,
        "context_search": obs_context,
        "family_intel": obs_family,
        "supplemental": supplemental,
    }


def _build_corroboration(
    *,
    event: Dict[str, Any],
    local_intel: Optional[Dict[str, Any]],
    obs_family: Optional[Dict[str, Any]],
    supplemental: Optional[Dict[str, Any]],
    family: str,
) -> Dict[str, Any]:
    local_family = _local_family(local_intel)
    external_candidates = _extract_external_family_candidates(event=event, obs_family=obs_family, supplemental=supplemental)
    supporting = bool(local_family and local_family in external_candidates)
    conflict = bool(local_family and external_candidates and any(item != local_family for item in external_candidates))

    if local_family and supporting:
        driver = "local_and_external"
        summary = f"本地情报命中的家族 {local_family} 获得外部情报佐证。"
    elif local_family and not external_candidates:
        driver = "local_only"
        summary = f"当前家族判断主要依赖本地指纹情报 {local_family}。"
    elif local_family and conflict:
        driver = "local_with_conflict"
        summary = f"本地情报指向 {local_family}，但外部情报出现不同家族线索。"
    elif external_candidates:
        driver = "external_only"
        summary = f"当前家族判断主要依赖外部情报线索 {external_candidates[0]}。"
    else:
        driver = "insufficient"
        summary = "目前缺少足够的本地命中与外部佐证来稳定归因。"

    return {
        "local_family": local_family,
        "external_family_candidates": external_candidates,
        "supported_by_external": supporting,
        "conflict": conflict,
        "confidence_driver": driver,
        "summary": summary,
        "selected_family": family,
    }


def _estimate_confidence(
    *,
    event: Dict[str, Any],
    local_intel: Optional[Dict[str, Any]],
    obs_fp: Optional[Dict[str, Any]],
    obs_context: Optional[Dict[str, Any]],
    obs_family: Optional[Dict[str, Any]],
    supplemental: Optional[Dict[str, Any]],
    family: str,
    corroboration: Dict[str, Any],
) -> int:
    score = 30
    local_best = _best_local_match(local_intel)

    if family != "Unknown":
        score += 10
    if local_best:
        score += 18
        score += min(10, max(0, _coerce_int(local_best.get("confidence"), default=70) // 10))
    if isinstance(obs_fp, dict):
        if obs_fp.get("enabled") is True:
            score += 8
        if obs_fp.get("ok") is True and (obs_fp.get("results") or []):
            score += 8
    if isinstance(obs_context, dict) and obs_context.get("ok") is True and (obs_context.get("results") or []):
        score += 7
    if isinstance(obs_family, dict) and obs_family.get("ok") is True and (obs_family.get("raw") or {}).get("results"):
        score += 10
    if isinstance(supplemental, dict) and (supplemental.get("supplemental_evidence") or []):
        score += 6
    if corroboration.get("supported_by_external"):
        score += 10
    if corroboration.get("conflict"):
        score -= 12
    if corroboration.get("confidence_driver") == "local_only":
        score -= 4
    if family == "Unknown":
        score = min(score, 45)

    hint_confidence = _coerce_int((event.get("enrichment") or {}).get("confidence"), default=-1)
    if hint_confidence >= 0 and family != "Unknown":
        score = max(score, hint_confidence)

    return max(20, min(95, score))


def _build_gaps(
    *,
    event: Dict[str, Any],
    local_intel: Optional[Dict[str, Any]],
    obs_fp: Optional[Dict[str, Any]],
    obs_context: Optional[Dict[str, Any]],
    obs_family: Optional[Dict[str, Any]],
    corroboration: Dict[str, Any],
    family: str,
    confidence: int,
) -> List[Dict[str, Any]]:
    gaps: List[Dict[str, Any]] = []

    if not (local_intel or {}).get("matched"):
        gaps.append(
            {
                "id": "g01",
                "type": "missing_local_match",
                "priority": "medium",
                "question": "本地情报库没有直接命中该指标，是否还能找到稳定的家族或来源线索？",
                "status": "open",
            }
        )

    if (local_intel or {}).get("matched") and not corroboration.get("supported_by_external"):
        gaps.append(
            {
                "id": "g02",
                "type": "no_secondary_confirmation",
                "priority": "high",
                "question": "本地库给出了家族，但外部情报尚未形成有效佐证，是否需要补查更多外部证据？",
                "status": "open",
            }
        )

    if corroboration.get("conflict"):
        gaps.append(
            {
                "id": "g03",
                "type": "conflicting_attribution",
                "priority": "high",
                "question": "本地命中与外部情报出现不同家族线索，哪一方更可信？",
                "status": "open",
            }
        )

    if isinstance(obs_fp, dict) and obs_fp.get("enabled") is True and family == "Unknown":
        gaps.append(
            {
                "id": "g04",
                "type": "vt_only_context",
                "priority": "medium",
                "question": "当前只有信誉类上下文，缺少家族或行为层面的归因信息。",
                "status": "open",
            }
        )

    if family != "Unknown":
        supporting_sources = 0
        if (local_intel or {}).get("matched"):
            supporting_sources += 1
        if isinstance(obs_family, dict) and obs_family.get("ok") is True and (obs_family.get("raw") or {}).get("results"):
            supporting_sources += 1
        if isinstance(obs_context, dict) and obs_context.get("ok") is True and (obs_context.get("results") or []):
            supporting_sources += 1
        if supporting_sources <= 1 or confidence < 60:
            gaps.append(
                {
                    "id": "g05",
                    "type": "single_source_attribution",
                    "priority": "medium",
                    "question": "当前家族判断支持源较少，是否需要补充第二来源或更具体的上下文？",
                    "status": "open",
                }
            )

        has_family_background = bool(
            isinstance(obs_family, dict) and obs_family.get("ok") is True and (obs_family.get("raw") or {}).get("results")
        )
        if not has_family_background:
            gaps.append(
                {
                    "id": "g07",
                    "type": "behavior_context_missing",
                    "priority": "medium",
                    "question": f"已识别到家族 {family}，但缺少更具体的行为、TTP 或攻击意图描述。",
                    "status": "open",
                }
            )

    if not isinstance(obs_context, dict) or not (obs_context.get("ok") is True and (obs_context.get("results") or [])):
        gaps.append(
            {
                "id": "g06",
                "type": "destination_context_missing",
                "priority": "low",
                "question": f"事件目标 {((event.get('dst') or {}).get('ip') or 'unknown')} 缺少额外上下文，是否需要补查角色和历史线索？",
                "status": "open",
            }
        )

    return gaps


def _needs_gap_fill(gaps: List[Dict[str, Any]]) -> bool:
    high_priority_types = {
        "no_secondary_confirmation",
        "conflicting_attribution",
        "vt_only_context",
        "single_source_attribution",
        "behavior_context_missing",
    }
    return any(str(item.get("type") or "") in high_priority_types for item in gaps)


def _build_evidence(
    *,
    event: Dict[str, Any],
    local_intel: Optional[Dict[str, Any]],
    obs_fp: Optional[Dict[str, Any]],
    obs_context: Optional[Dict[str, Any]],
    obs_family: Optional[Dict[str, Any]],
    supplemental: Optional[Dict[str, Any]],
    family: str,
    confidence: int,
) -> List[Dict[str, Any]]:
    evidence: List[Dict[str, Any]] = []
    fp = event.get("trigger_fingerprint") or {}
    fp_value = _clean_text(fp.get("value"))
    enrichment = event.get("enrichment") or {}
    src = event.get("src") or {}
    dst = event.get("dst") or {}

    _append_evidence(
        evidence,
        {
            "kind": "event",
            "source": "alert",
            "type": "matched_alert",
            "query": None,
            "url": None,
            "title": "命中后告警事件",
            "claim": (
                f"在 {event.get('event_time')} 观察到 {src.get('ip')} -> {dst.get('ip')} 的 "
                f"{event.get('protocol')} 流量，命中 {fp.get('type')} 指纹 {fp.get('value')}。"
            ),
            "confidence": 95,
            "raw_ref": "event.raw_alert",
        },
    )

    best_local = _best_local_match(local_intel)
    if best_local:
        _append_evidence(
            evidence,
            {
                "kind": "local_intel",
                "source": best_local.get("source") or "local_db",
                "type": "local_indicator_match",
                "query": fp_value,
                "url": None,
                "title": "本地指纹情报命中",
                "claim": (
                    f"本地情报库将 {best_local.get('indicator_type')} {best_local.get('indicator_value')} "
                    f"关联到家族/标签 {best_local.get('malware_family')}，来源 {best_local.get('source')}。"
                ),
                "confidence": _coerce_int(best_local.get("confidence"), default=85),
                "raw_ref": "local_intel.best_match",
            },
        )

    family_hint = _first_non_empty(enrichment.get("info"))
    if family_hint:
        _append_evidence(
            evidence,
            {
                "kind": "hint",
                "source": enrichment.get("reference") or "alert_enrichment",
                "type": "family_hint",
                "query": None,
                "url": None,
                "title": "告警附带家族提示",
                "claim": f"原始告警将该事件关联到家族/标签 {family_hint}。",
                "confidence": 70,
                "raw_ref": "event.enrichment",
            },
        )

    if isinstance(obs_fp, dict):
        if obs_fp.get("enabled") is True:
            stats = obs_fp.get("last_analysis_stats") or {}
            stat_text = f" VT 分析统计为 {stats}。" if isinstance(stats, dict) and stats else ""
            _append_evidence(
                evidence,
                {
                    "kind": "enrichment",
                    "source": "VirusTotal",
                    "type": "vt_ip",
                    "query": str(fp.get("value") or ""),
                    "url": None,
                    "title": "VirusTotal IP 富化",
                    "claim": f"VirusTotal 返回 IP {obs_fp.get('ip')} 的信誉/归属信息。{stat_text}".strip(),
                    "confidence": _coerce_int(obs_fp.get("confidence"), default=confidence),
                    "raw_ref": "external_intel.fingerprint_enrichment",
                },
            )
        elif obs_fp.get("ok") is True:
            for index, result in enumerate((obs_fp.get("results") or [])[:5]):
                _append_evidence(
                    evidence,
                    {
                        "kind": "search_result",
                        "source": result.get("source") or obs_fp.get("mode") or "web_search",
                        "type": "fingerprint_search",
                        "query": obs_fp.get("query"),
                        "url": result.get("url"),
                        "title": result.get("title") or f"指纹外部搜索 {index + 1}",
                        "claim": result.get("snippet") or result.get("title"),
                        "confidence": 60,
                        "raw_ref": f"external_intel.fingerprint_enrichment.results[{index}]",
                    },
                )

    if isinstance(obs_context, dict) and obs_context.get("ok") is True:
        for index, result in enumerate((obs_context.get("results") or [])[:5]):
            _append_evidence(
                evidence,
                {
                    "kind": "search_result",
                    "source": result.get("source") or obs_context.get("mode") or "web_search",
                    "type": "context_search",
                    "query": obs_context.get("query"),
                    "url": result.get("url"),
                    "title": result.get("title") or f"上下文搜索 {index + 1}",
                    "claim": result.get("snippet") or result.get("title"),
                    "confidence": 62,
                    "raw_ref": f"external_intel.context_search.results[{index}]",
                },
            )

    family_raw = (obs_family or {}).get("raw") if isinstance(obs_family, dict) else None
    family_results = (family_raw or {}).get("results") if isinstance(family_raw, dict) else []
    if isinstance(family_results, list):
        for index, result in enumerate(family_results[:5]):
            _append_evidence(
                evidence,
                {
                    "kind": "family_intel",
                    "source": result.get("source") or (family_raw or {}).get("mode") or "family_intel",
                    "type": "family_search",
                    "query": (obs_family or {}).get("query"),
                    "url": result.get("url"),
                    "title": result.get("title") or f"{family} 家族情报 {index + 1}",
                    "claim": result.get("snippet") or result.get("title"),
                    "confidence": 65,
                    "raw_ref": f"external_intel.family_intel.raw.results[{index}]",
                },
            )

    supplemental_evidence = (supplemental or {}).get("supplemental_evidence") if isinstance(supplemental, dict) else []
    if isinstance(supplemental_evidence, list):
        for index, item in enumerate(supplemental_evidence[:5]):
            _append_evidence(
                evidence,
                {
                    "kind": "supplemental",
                    "source": item.get("source") or "react_gap_fill",
                    "type": item.get("type") or "supplemental_search",
                    "query": item.get("query"),
                    "url": item.get("url"),
                    "title": item.get("title") or f"补查证据 {index + 1}",
                    "claim": item.get("claim") or item.get("title"),
                    "confidence": _coerce_int(item.get("confidence"), default=60),
                    "raw_ref": item.get("raw_ref") or "external_intel.supplemental",
                },
            )

    return _finalize_evidence(evidence, family=family, fp_value=fp_value)


def _build_findings(
    *,
    event: Dict[str, Any],
    local_intel: Optional[Dict[str, Any]],
    corroboration: Dict[str, Any],
    family: str,
    confidence: int,
    severity: str,
    evidence: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    fp = event.get("trigger_fingerprint") or {}
    src = event.get("src") or {}
    dst = event.get("dst") or {}
    event_evidence_id = evidence[0]["id"] if evidence else None
    local_evidence_ids = [item["id"] for item in evidence if item.get("kind") == "local_intel"]
    family_evidence_ids = [
        item["id"]
        for item in evidence
        if item.get("type") in {"family_hint", "family_search", "fingerprint_search", "context_search", "supplemental_search"}
    ]

    findings: List[Dict[str, Any]] = [
        {
            "id": "f01",
            "title": "命中后恶意流量告警",
            "statement": (
                f"源 {src.get('ip')} 与目的 {dst.get('ip')} 的 {event.get('protocol')} 流量命中 "
                f"{fp.get('type')} 指纹 {fp.get('value')}。"
            ),
            "confidence": 95,
            "severity": severity,
            "based_on": [event_evidence_id] if event_evidence_id else [],
        }
    ]

    if local_evidence_ids:
        findings.append(
            {
                "id": "f02",
                "title": "本地情报命中",
                "statement": "本地指纹情报库对该指标存在直接命中记录，可作为家族归因的强参考。",
                "confidence": min(90, confidence),
                "severity": severity,
                "based_on": local_evidence_ids,
            }
        )

    if family != "Unknown":
        findings.append(
            {
                "id": "f03",
                "title": "当前家族判断",
                "statement": f"综合本地命中与外部佐证后，该事件当前更可能与 {family} 相关。",
                "confidence": confidence,
                "severity": severity,
                "based_on": family_evidence_ids or local_evidence_ids,
            }
        )

    if corroboration.get("conflict"):
        findings.append(
            {
                "id": "f04",
                "title": "归因存在冲突",
                "statement": "本地情报与外部情报出现不同家族线索，当前结论仍需结合补查结果审慎解读。",
                "confidence": max(35, confidence - 15),
                "severity": severity,
                "based_on": family_evidence_ids + local_evidence_ids,
            }
        )

    return findings


def _build_uncertainties(
    *,
    local_intel: Optional[Dict[str, Any]],
    obs_fp: Optional[Dict[str, Any]],
    obs_context: Optional[Dict[str, Any]],
    obs_family: Optional[Dict[str, Any]],
    corroboration: Dict[str, Any],
    gaps: List[Dict[str, Any]],
    family: str,
) -> List[Dict[str, Any]]:
    uncertainties: List[Dict[str, Any]] = []

    if isinstance(local_intel, dict) and local_intel.get("error"):
        uncertainties.append(
            {
                "id": "u01",
                "statement": "本地指纹情报查询未成功返回结果。",
                "reason": local_intel.get("error"),
            }
        )

    if isinstance(obs_fp, dict) and obs_fp.get("enabled") is False:
        uncertainties.append(
            {
                "id": "u02",
                "statement": "未获取到 VirusTotal 的即时信誉结果。",
                "reason": obs_fp.get("note") or obs_fp.get("error") or "外部情报未启用",
            }
        )

    if isinstance(obs_context, dict) and not obs_context.get("ok") and obs_context.get("error"):
        uncertainties.append(
            {
                "id": "u03",
                "statement": "上下文搜索未成功返回结构化结果。",
                "reason": obs_context.get("error"),
            }
        )

    if isinstance(obs_family, dict) and not obs_family.get("ok") and obs_family.get("error"):
        uncertainties.append(
            {
                "id": "u04",
                "statement": "家族情报搜索未成功返回结构化结果。",
                "reason": obs_family.get("error"),
            }
        )

    if family == "Unknown":
        uncertainties.append(
            {
                "id": "u05",
                "statement": "当前无法稳定归因到明确的恶意软件家族。",
                "reason": "本地命中和外部佐证都不足以形成稳定家族判断。",
            }
        )

    if corroboration.get("conflict"):
        uncertainties.append(
            {
                "id": "u06",
                "statement": "本地命中与外部情报存在归因冲突。",
                "reason": corroboration.get("summary"),
            }
        )

    for index, gap in enumerate(gaps, start=1):
        uncertainties.append(
            {
                "id": f"u{index + 6:02d}",
                "statement": gap.get("question"),
                "reason": f"gap={gap.get('type')} priority={gap.get('priority')}",
            }
        )

    return uncertainties


def _build_actions(*, event: Dict[str, Any], family: str) -> List[Dict[str, Any]]:
    fp = event.get("trigger_fingerprint") or {}
    src = event.get("src") or {}
    dst = event.get("dst") or {}
    actions: List[Dict[str, Any]] = [
        {
            "id": "a01",
            "priority": "high",
            "action": f"排查并视情况隔离源主机 {src.get('ip')}。",
            "rationale": "源主机产生了命中后恶意流量，需要确认是否存在持续外联或二次投递行为。",
        },
        {
            "id": "a02",
            "priority": "high",
            "action": f"在边界侧监控或阻断与 {dst.get('ip')} 相关的后续通信。",
            "rationale": "当前告警中的网络目的地址是最直接的外联对象，应优先纳入监测范围。",
        },
        {
            "id": "a03",
            "priority": "medium",
            "action": f"基于 {fp.get('type')} 指纹 {fp.get('value')} 在历史流量中做横向检索。",
            "rationale": "可以快速判断是否存在相同指纹的历史通信或更多受影响资产。",
        },
    ]
    if family != "Unknown":
        actions.append(
            {
                "id": "a04",
                "priority": "medium",
                "action": f"结合 {family} 相关 TTP 做主机侧排查与 IOC 扩线。",
                "rationale": "已有家族线索时，可以更有针对性地检查样本行为、持久化方式和额外外联特征。",
            }
        )
    return actions


def _build_assessment(*, family: str, confidence: int, severity: str, corroboration: Dict[str, Any]) -> Dict[str, Any]:
    rationale_parts = [corroboration.get("summary") or "当前缺少完整的交叉验证信息。"]
    if corroboration.get("conflict"):
        rationale_parts.append("存在归因冲突，因此当前结论应视为暂定判断。")
    verdict = "suspicious_match" if family == "Unknown" else "suspected_malware_activity"
    return {
        "family": family,
        "verdict": verdict,
        "confidence": confidence,
        "severity": severity,
        "rationale": " ".join(part for part in rationale_parts if part),
    }


def _build_facts(event: Dict[str, Any]) -> Dict[str, Any]:
    fp = event.get("trigger_fingerprint") or {}
    return {
        "event_time": event.get("event_time"),
        "src": event.get("src"),
        "dst": event.get("dst"),
        "protocol": event.get("protocol"),
        "fingerprint": {
            "type": fp.get("type"),
            "value": fp.get("value"),
            "matched": fp.get("matched"),
        },
    }


def build_analysis(
    *,
    event: Dict[str, Any],
    mode: str,
    local_intel: Optional[Dict[str, Any]] = None,
    obs_fp: Optional[Dict[str, Any]] = None,
    obs_context: Optional[Dict[str, Any]] = None,
    obs_family: Optional[Dict[str, Any]] = None,
    supplemental: Optional[Dict[str, Any]] = None,
    report_markdown: Optional[str] = None,
    report_path: Optional[str] = None,
) -> Dict[str, Any]:
    enrichment = dict(event.get("enrichment") or {})
    local_summary = _build_local_intel_summary(local_intel)
    family = _select_family(event=event, local_intel=local_summary, obs_family=obs_family, supplemental=supplemental)
    corroboration = _build_corroboration(
        event=event,
        local_intel=local_summary,
        obs_family=obs_family,
        supplemental=supplemental,
        family=family,
    )
    confidence = _estimate_confidence(
        event=event,
        local_intel=local_summary,
        obs_fp=obs_fp,
        obs_context=obs_context,
        obs_family=obs_family,
        supplemental=supplemental,
        family=family,
        corroboration=corroboration,
    )
    severity = severity_from_confidence(confidence)

    labels: List[str] = []
    for value in (
        local_summary.get("malware_family"),
        enrichment.get("info"),
        (obs_family or {}).get("family") if isinstance(obs_family, dict) else None,
        family if family != "Unknown" else None,
    ):
        text = _first_non_empty(value)
        if text and text not in labels:
            labels.append(text)

    gaps = _build_gaps(
        event=event,
        local_intel=local_summary,
        obs_fp=obs_fp,
        obs_context=obs_context,
        obs_family=obs_family,
        corroboration=corroboration,
        family=family,
        confidence=confidence,
    )
    external_intel = _build_external_intel(obs_fp=obs_fp, obs_context=obs_context, obs_family=obs_family, supplemental=supplemental)
    evidence = _build_evidence(
        event=event,
        local_intel=local_summary,
        obs_fp=obs_fp,
        obs_context=obs_context,
        obs_family=obs_family,
        supplemental=supplemental,
        family=family,
        confidence=confidence,
    )
    findings = _build_findings(
        event=event,
        local_intel=local_summary,
        corroboration=corroboration,
        family=family,
        confidence=confidence,
        severity=severity,
        evidence=evidence,
    )
    uncertainties = _build_uncertainties(
        local_intel=local_summary,
        obs_fp=obs_fp,
        obs_context=obs_context,
        obs_family=obs_family,
        corroboration=corroboration,
        gaps=gaps,
        family=family,
    )
    recommended_actions = _build_actions(event=event, family=family)
    assessment = _build_assessment(family=family, confidence=confidence, severity=severity, corroboration=corroboration)

    destination_enrichment: Dict[str, Any] = {}
    if isinstance(enrichment.get("dst_ip"), dict):
        destination_enrichment.update(enrichment.get("dst_ip") or {})

    analysis: Dict[str, Any] = {
        "mode": mode,
        "event": event,
        "facts": _build_facts(event),
        "entities": {
            "src_ip": (event.get("src") or {}).get("ip"),
            "dst_ip": (event.get("dst") or {}).get("ip"),
            "protocol": event.get("protocol"),
            "fingerprint": {
                "type": (event.get("trigger_fingerprint") or {}).get("type"),
                "value": (event.get("trigger_fingerprint") or {}).get("value"),
                "matched": (event.get("trigger_fingerprint") or {}).get("matched"),
            },
            "family_hint": enrichment.get("info"),
            "reference": enrichment.get("reference"),
            "update_time": enrichment.get("update_time"),
        },
        "local_intel": local_summary,
        "external_intel": external_intel,
        "observations": {
            "local_intel": local_summary,
            "fingerprint_enrichment": obs_fp,
            "context_search": obs_context,
            "family_intel": obs_family,
            "supplemental": supplemental,
        },
        "corroboration": corroboration,
        "gaps": gaps,
        "gap_fill_needed": _needs_gap_fill(gaps),
        "supplemental": supplemental or {},
        "evidence": evidence,
        "findings": findings,
        "uncertainties": uncertainties,
        "recommended_actions": recommended_actions,
        "assessment": assessment,
        "derived": {
            "family": family,
            "labels": labels,
            "confidence": confidence,
            "severity": severity,
            "destination_enrichment": destination_enrichment,
        },
    }

    if report_markdown is not None or report_path is not None:
        analysis["report"] = {"path": report_path, "content": report_markdown or ""}

    return analysis
