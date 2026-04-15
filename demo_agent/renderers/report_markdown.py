from __future__ import annotations

import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set
from urllib.parse import urlsplit, urlunsplit

from langchain_core.prompts import ChatPromptTemplate
from pydantic import BaseModel, Field


LOGGER = logging.getLogger(__name__)
_RENDERER_LLM_EXECUTOR = ThreadPoolExecutor(max_workers=4, thread_name_prefix="report-llm")
_TRUSTED_MULTI_DOC_DOMAINS = {
    "any.run",
    "malpedia.caad.fkie.fraunhofer.de",
    "microsoft.com",
    "checkpoint.com",
    "trendmicro.com",
    "proofpoint.com",
}
_LOW_SIGNAL_REPORT_PARTS = (
    "get a demo",
    "start for free",
    "support documentation",
    "portal login",
    "strategic partnership",
    "gain a hightouch",
    "optimize your security",
    "contact us",
    "free trial",
    "meet the team",
    "threat detection report",
)


@dataclass
class EvidenceView:
    evidence_id: str
    title: str
    source: str
    url: Optional[str]
    level: str
    kind: str
    body: str
    claim: str = ""


@dataclass
class ReportViewModel:
    conclusion_lines: List[str] = field(default_factory=list)
    attribution_summary: str = ""
    analyst_summary: str = ""
    event_evidence: List[EvidenceView] = field(default_factory=list)
    background_references: List[EvidenceView] = field(default_factory=list)
    base_actions: List[str] = field(default_factory=list)
    threat_hunt_actions: List[str] = field(default_factory=list)
    uncertainties: List[str] = field(default_factory=list)


class EvidenceSummaryItemModel(BaseModel):
    id: str
    summary: str = Field(default="")


class EvidenceSummaryBatchModel(BaseModel):
    analyst_summary: str = Field(default="")
    items: List[EvidenceSummaryItemModel] = Field(default_factory=list)


class EvidenceSummarySingleModel(BaseModel):
    summary: str = Field(default="")


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _text(value: Any) -> str:
    return str(value or "").strip()


def _confidence_phrase(confidence: int) -> str:
    if confidence >= 80:
        return "较高"
    if confidence >= 60:
        return "中等"
    return "有限"


def _synthesized_url(item: Dict[str, Any], analysis: Dict[str, Any]) -> Optional[str]:
    url = _text(item.get("url"))
    if url:
        return url

    event = analysis.get("event") or {}
    local_intel = analysis.get("local_intel") or {}
    best = local_intel.get("best_match") or {}
    fp = event.get("trigger_fingerprint") or {}

    source = _text(item.get("source")).lower()
    kind = _text(item.get("kind"))

    if kind == "local_intel" and source == "sslbl":
        indicator_type = _text(best.get("indicator_type")).lower()
        indicator_value = _text(best.get("indicator_value"))
        if indicator_type in {"ja3", "ja3_md5"} and indicator_value:
            return f"https://sslbl.abuse.ch/ja3-fingerprints/{indicator_value}/"
        if indicator_type in {"ssl_sha1", "ssl_sha1_fingerprint"} and indicator_value:
            return f"https://sslbl.abuse.ch/ssl-certificates/sha1/{indicator_value}/"

    if source == "virustotal" and _text(fp.get("type")).upper() == "IP":
        ip_value = _text(item.get("query")) or _text(fp.get("value"))
        if ip_value:
            return f"https://www.virustotal.com/gui/ip-address/{ip_value}"

    return None


def _format_reference(label: str, url: Optional[str]) -> str:
    if not url:
        return label
    return f"[{label}]({url})"


def _looks_mostly_ascii(text: str) -> bool:
    text = _text(text)
    if not text:
        return False
    ascii_chars = sum(1 for ch in text if ord(ch) < 128)
    return ascii_chars / max(len(text), 1) > 0.85


def _short_text(text: str, limit: int = 220) -> str:
    text = _text(text)
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def _family_name(analysis: Dict[str, Any]) -> str:
    assessment = analysis.get("assessment") or {}
    return _text(assessment.get("family")) or "该家族"


def _source_label(value: Any) -> str:
    source = _text(value)
    if not source:
        return "相关来源"
    lowered = source.lower()
    mapping = {
        "threatfox.abuse.ch": "ThreatFox",
        "urlhaus.abuse.ch": "URLhaus",
        "sslbl": "SSLBL",
        "ja4db": "JA4DB",
        "virustotal": "VirusTotal",
        "family_intel": "家族背景情报",
        "alert_enrichment": "告警附带标签",
    }
    return mapping.get(lowered, source)


def _normalized_text(text: str) -> str:
    return re.sub(r"\s+", " ", _text(text))


def _evidence_key(item: Dict[str, Any], analysis: Dict[str, Any]) -> str:
    url = _synthesized_url(item, analysis) or _text(item.get("url"))
    title = _text(item.get("title")).lower()
    source = _text(item.get("source")).lower()
    if url:
        try:
            parts = urlsplit(url)
            url = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
        except Exception:
            pass
        return f"url::{url}"
    if title or source:
        return f"meta::{source}::{title}"
    return json.dumps(item, ensure_ascii=False, sort_keys=True)


def _invoke_structured_llm_with_timeout(
    llm: Any,
    schema: Any,
    messages: Sequence[Any],
    *,
    timeout_s: float,
    label: str,
) -> Any:
    if llm is None:
        return None
    future = _RENDERER_LLM_EXECUTOR.submit(llm.invoke, list(messages))
    try:
        response = future.result(timeout=timeout_s)
    except FutureTimeoutError:
        future.cancel()
        LOGGER.warning("Renderer LLM synthesis timed out for %s after %.1fs", label, timeout_s)
        return None
    except Exception as exc:
        LOGGER.warning("Renderer LLM synthesis failed for %s: %s", label, exc)
        return None

    raw = _text(getattr(response, "content", response))
    if not raw:
        LOGGER.warning("Renderer LLM synthesis returned empty content for %s", label)
        return None

    decoder = json.JSONDecoder()
    for idx, ch in enumerate(raw):
        if ch not in "{[":
            continue
        try:
            payload, _ = decoder.raw_decode(raw[idx:])
        except json.JSONDecodeError:
            continue
        try:
            return schema.model_validate(payload)
        except Exception as exc:
            LOGGER.warning("Renderer JSON validation failed for %s: %s", label, exc)
            return None

    LOGGER.warning("Renderer did not receive parseable JSON for %s", label)
    return None


def _material_uncertainties(analysis: Dict[str, Any]) -> List[str]:
    assessment = analysis.get("assessment") or {}
    corroboration = analysis.get("corroboration") or {}
    local_intel = analysis.get("local_intel") or {}
    uncertainties: List[str] = []

    if local_intel.get("error"):
        uncertainties.append("本地指纹情报查询未成功返回完整结果，部分结论未能获得本地库补充。")

    if assessment.get("family") == "Unknown":
        uncertainties.append("当前自动化情报不足以稳定归因到明确恶意软件家族。")

    if corroboration.get("conflict"):
        uncertainties.append("本地情报与外部情报出现不同家族线索，当前归因应结合人工复核审慎使用。")

    return uncertainties


def _conclusion_lines(analysis: Dict[str, Any]) -> List[str]:
    event = analysis.get("event") or {}
    assessment = analysis.get("assessment") or {}
    corroboration = analysis.get("corroboration") or {}
    local_intel = analysis.get("local_intel") or {}
    supplemental = analysis.get("supplemental") or {}
    confidence = _coerce_int(assessment.get("confidence"), 0)
    family = _text(assessment.get("family")) or "Unknown"
    fp = event.get("trigger_fingerprint") or {}
    src = event.get("src") or {}
    dst = event.get("dst") or {}

    lines = [
        (
            f"在 {event.get('event_time')}，检测到 {src.get('ip')} 与 {dst.get('ip')} 之间存在 "
            f"{event.get('protocol')} 流量，该流量命中 {fp.get('type')} 指标 `{fp.get('value')}`。"
        )
    ]

    if family != "Unknown":
        if local_intel.get("matched") and corroboration.get("supported_by_external"):
            lines.append(
                f"结合本地指纹情报与外部公开情报，当前将该事件关联到 `{family}` 的把握为{_confidence_phrase(confidence)}。"
            )
        elif local_intel.get("matched"):
            lines.append(
                f"本地指纹情报将该指标关联到 `{family}`，当前未发现明显冲突信息，建议将其作为优先研判方向。"
            )
        else:
            lines.append(
                f"当前家族线索主要来自告警附带标签和外部情报，现阶段更倾向于将该事件关联到 `{family}`。"
            )
    else:
        lines.append("当前已确认该事件具备可疑恶意流量特征，但自动化情报尚不足以稳定归因到明确家族。")
        if list(supplemental.get("supplemental_evidence") or []):
            lines.append("补查阶段已获取额外页面证据和二跳线索，可作为人工复核和后续扩线的补充依据。")

    return lines


def _attribution_summary(analysis: Dict[str, Any]) -> str:
    assessment = analysis.get("assessment") or {}
    corroboration = analysis.get("corroboration") or {}
    family = _text(assessment.get("family"))
    confidence = _coerce_int(assessment.get("confidence"), 0)
    primary = corroboration.get("primary_source") or {}
    primary_label = _source_label(primary.get("source"))
    supporting = list(corroboration.get("supporting_sources") or [])
    conflicts = list(corroboration.get("conflicting_sources") or [])
    if family and family != "Unknown":
        base = f"当前归因结果为 `{family}`，置信度为 {confidence}。"
        if primary_label:
            base += f" 主依据来自 `{primary_label}`。"
        if supporting:
            labels = "、".join(_source_label(item.get("source")) for item in supporting[:3] if _source_label(item.get("source")))
            if labels:
                base += f" 另有 `{labels}` 提供补充支持。"
        if conflicts:
            conflict_labels = "、".join(_source_label(item.get("source")) for item in conflicts[:2] if _source_label(item.get("source")))
            if conflict_labels:
                base += f" 但 `{conflict_labels}` 提供了不同家族线索，建议结合人工复核审慎使用。"
        elif corroboration.get("summary"):
            base += f" {corroboration.get('summary')}"
        return base
    return "当前尚未获得足够证据完成稳定家族归因，现阶段更适合将其视为待进一步复核的可疑恶意流量。"


def _evidence_sort_key(item: Dict[str, Any]) -> tuple:
    priority = {
        "local_intel": 0,
        "enrichment": 1,
        "supplemental": 2,
        "search_result": 3,
        "family_intel": 4,
        "hint": 5,
        "event": 9,
    }
    penalty = 0
    domain = _text(item.get("domain")).lower()
    title = _text(item.get("title")).lower()
    url = _text(item.get("url")).lower()
    if domain == "sslbl.abuse.ch" and (
        title in {"malicious ssl certificates", "download ja3 ids ruleset (suricata 4.1.0 or newer)"}
        or url.endswith("/ssl-certificates/")
        or url.endswith("/blacklist/sslblacklist.csv")
        or url.endswith("/blacklist/ja3_fingerprints.rules")
    ):
        # 这类索引/黑名单页面有参考价值，但在已有本地命中时不应压过更有信息量的研究性正文。
        penalty = 8
    return (
        priority.get(_text(item.get("kind")), 9),
        -_coerce_int(item.get("weight"), 0) + penalty,
        -_coerce_int(item.get("confidence"), 0),
        _text(item.get("title")),
    )


def _per_domain_limit(item: Dict[str, Any]) -> int:
    domain = _text(item.get("domain")).lower()
    if not domain:
        return 1
    tier = _text(item.get("evidence_tier")).lower()
    if tier == "strong":
        for trusted in _TRUSTED_MULTI_DOC_DOMAINS:
            if domain == trusted or domain.endswith("." + trusted):
                return 2
    return 1


def _event_evidence_candidates(analysis: Dict[str, Any], limit: int = 4) -> List[Dict[str, Any]]:
    evidence: List[Dict[str, Any]] = list(analysis.get("evidence") or [])
    result: List[Dict[str, Any]] = []
    used: Set[str] = set()
    per_kind: Dict[str, int] = {}
    per_domain: Dict[str, int] = {}

    for item in sorted(evidence, key=_evidence_sort_key):
        kind = _text(item.get("kind"))
        tier = _text(item.get("evidence_tier"))
        if kind in {"event", "hint"}:
            continue
        if not bool(item.get("is_reportable")) or tier == "noisy":
            continue
        if _skip_report_item(item):
            continue
        signals = _substantive_signal_count(item)
        claim_origin = _text(item.get("claim_origin")).lower()
        title = _text(item.get("title"))
        if kind == "search_result" and claim_origin == "snippet" and signals < 2:
            continue
        if kind in {"family_intel", "search_result"} and _looks_indicatorish_title(title) and signals < 3:
            continue
        key = _evidence_key(item, analysis)
        if key in used:
            continue
        domain = _text(item.get("domain"))
        if domain and per_domain.get(domain, 0) >= _per_domain_limit(item):
            continue
        if kind == "family_intel" and per_kind.get(kind, 0) >= 2:
            continue
        if kind == "search_result" and per_kind.get(kind, 0) >= 2:
            continue
        if kind == "local_intel" and per_kind.get(kind, 0) >= 1:
            continue
        result.append(item)
        used.add(key)
        per_kind[kind] = per_kind.get(kind, 0) + 1
        if domain:
            per_domain[domain] = per_domain.get(domain, 0) + 1
        if len(result) >= limit:
            break
    return result


def _background_evidence_candidates(
    analysis: Dict[str, Any],
    *,
    used_keys: Set[str],
    used_domains: Optional[Set[str]] = None,
    limit: int = 2,
) -> List[Dict[str, Any]]:
    evidence: List[Dict[str, Any]] = list(analysis.get("evidence") or [])
    result: List[Dict[str, Any]] = []
    per_domain: Dict[str, int] = {}
    used_domains = set(used_domains or set())
    for item in sorted(evidence, key=_evidence_sort_key):
        kind = _text(item.get("kind"))
        if kind not in {"family_intel", "search_result"}:
            continue
        if not bool(item.get("is_reportable")) or _text(item.get("evidence_tier")) == "noisy":
            continue
        if _skip_report_item(item):
            continue
        key = _evidence_key(item, analysis)
        if key in used_keys:
            continue
        domain = _text(item.get("domain"))
        if domain and domain.lower() in used_domains:
            continue
        if domain and per_domain.get(domain, 0) >= _per_domain_limit(item):
            continue
        if not _text(item.get("claim")) and not _text(item.get("title")):
            continue
        signals = _substantive_signal_count(item)
        claim_origin = _text(item.get("claim_origin")).lower()
        title = _text(item.get("title"))
        if signals < 2:
            continue
        if claim_origin == "snippet" and signals < 3:
            continue
        if _looks_indicatorish_title(title):
            continue
        if not _mentions_family_content(item, analysis) and signals < 3:
            continue
        if _coerce_int(item.get("weight"), 0) < 65 and _coerce_int(item.get("confidence"), 0) < 60:
            continue
        result.append(item)
        used_keys.add(key)
        if domain:
            per_domain[domain] = per_domain.get(domain, 0) + 1
        if len(result) >= limit:
            break
    return result


def _skip_report_item(item: Dict[str, Any]) -> bool:
    kind = _text(item.get("kind"))
    if kind in {"local_intel", "enrichment"}:
        return False
    title = _text(item.get("title")).lower()
    url = _text(item.get("url")).lower()
    page_type = _text(item.get("page_type")).lower()
    claim_origin = _text(item.get("claim_origin")).lower()
    if title in {"download ja3 ids ruleset (suricata 4.1.0 or newer)", "malicious ssl certificates"}:
        return True
    if url.endswith("/blacklist/ja3_fingerprints.rules") or url.endswith("/blacklist/sslblacklist.csv"):
        return True
    if page_type == "list" and claim_origin != "page_enrichment":
        return True
    return False


def _page_claims(item: Dict[str, Any], *, limit: int = 4, per_item_limit: int = 200) -> List[str]:
    claims: List[str] = []
    seen: Set[str] = set()
    for raw in list(item.get("page_claims") or []):
        text = _normalized_text(_text(raw))
        if not text:
            continue
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        claims.append(_short_text(text, per_item_limit))
        if len(claims) >= limit:
            break
    return claims


def _page_iocs(item: Dict[str, Any], *, limit: int = 4, per_item_limit: int = 120) -> List[str]:
    result: List[str] = []
    seen: Set[str] = set()
    for raw in list(item.get("page_iocs") or []):
        text = _text(raw)
        if not text:
            continue
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        result.append(_short_text(text, per_item_limit))
        if len(result) >= limit:
            break
    return result


def _looks_indicatorish_title(title: str) -> bool:
    normalized = _text(title).lower()
    if not normalized:
        return False
    if re.fullmatch(r"[a-f0-9]{24,}", normalized):
        return True
    if re.fullmatch(r"t\d+[a-z0-9_]{18,}", normalized):
        return True
    if normalized.endswith("...") and ("_" in normalized or any(ch.isdigit() for ch in normalized[:6])):
        return True
    if normalized.startswith(("ja3 fingerprint ", "ja4 fingerprint ", "ssl fingerprint ", "ssl certificate ")):
        return True
    return False


def _substantive_signal_count(item: Dict[str, Any]) -> int:
    signals = 0
    summary = _normalized_text(_text(item.get("page_summary")))
    if summary and len(summary) >= 80 and not any(part in summary.lower() for part in _LOW_SIGNAL_REPORT_PARTS):
        signals += 2
    for claim in _page_claims(item, limit=5, per_item_limit=320):
        lowered = claim.lower()
        if len(claim) < 50:
            continue
        if any(part in lowered for part in _LOW_SIGNAL_REPORT_PARTS):
            continue
        signals += 1
    if _text(item.get("page_relevance")):
        signals += 1
    if list(item.get("page_iocs") or []):
        signals += 1
    return signals


def _mentions_family_content(item: Dict[str, Any], analysis: Dict[str, Any]) -> bool:
    family = _family_name(analysis).lower()
    if not family or family in {"unknown", "该家族"}:
        return False
    haystack = " ".join(
        [
            _text(item.get("title")),
            _text(item.get("claim")),
            _text(item.get("page_summary")),
            " ".join(_text(value) for value in list(item.get("page_claims") or [])),
            _text(item.get("page_relevance")),
        ]
    ).lower()
    return family in haystack


def _sentence_count(text: str) -> int:
    normalized = _normalized_text(_text(text))
    if not normalized:
        return 0
    parts = [part for part in re.split(r"[。！？!?]+", normalized) if part.strip()]
    return len(parts) if parts else 1


def _needs_detail_expansion(text: str, detail_mode: str) -> bool:
    normalized = _normalized_text(_text(text))
    if not normalized:
        return True
    length = len(normalized)
    sentences = _sentence_count(normalized)
    if detail_mode == "primary":
        return length < 150 or sentences < 4
    if detail_mode == "secondary":
        return length < 85 or sentences < 2
    return length < 40


def _supports_primary_detail(item: Dict[str, Any]) -> bool:
    if _text(item.get("kind")) == "local_intel":
        return True
    return _substantive_signal_count(item) >= 5


def _event_focus_score(item: Dict[str, Any], analysis: Dict[str, Any]) -> int:
    kind = _text(item.get("kind"))
    title = _text(item.get("title")).lower()
    url = _text(item.get("url")).lower()
    page_type = _text(item.get("page_type")).lower()
    claim_origin = _text(item.get("claim_origin")).lower()
    family = _family_name(analysis).lower()

    score = _coerce_int(item.get("weight"), 0)
    if kind == "local_intel":
        score += 120
    if claim_origin == "page_enrichment":
        score += 18
    if claim_origin == "snippet":
        score -= 12
    if kind == "family_intel":
        score += 8
    if page_type in {"profile", "detail"}:
        score += 8
    score += _substantive_signal_count(item) * 6
    if _looks_indicatorish_title(title):
        score -= 18
    if family and family != "该家族" and family in title:
        score += 5
    if title in {"ja3 fingerprint " + _text((analysis.get("event") or {}).get("trigger_fingerprint", {}).get("value")).lower()}:
        score -= 12
    if "fingerprint" in title:
        score -= 8
    if "sslbl.abuse.ch" in url and any(token in url for token in ("/ja3-fingerprints/", "/ssl-certificates/")):
        score -= 18
    if any(part in title for part in ("linked to", "latest alerts", "threat detection report")):
        score -= 10
    if any(part in (_normalized_text(_text(item.get("page_summary"))) + " " + " ".join(_page_claims(item, limit=3, per_item_limit=240))).lower() for part in _LOW_SIGNAL_REPORT_PARTS):
        score -= 12
    return score


def _background_focus_score(item: Dict[str, Any], analysis: Dict[str, Any]) -> int:
    score = _event_focus_score(item, analysis)
    title = _text(item.get("title")).lower()
    claim_origin = _text(item.get("claim_origin")).lower()
    signals = _substantive_signal_count(item)
    family = _family_name(analysis).lower()
    if family and family in title:
        score += 4
    if claim_origin == "snippet":
        score -= 18
    if signals < 2:
        score -= 18
    if _looks_indicatorish_title(title):
        score -= 20
    if any(part in title for part in ("linked to", "new malware family")):
        score -= 8
    return score


def _evidence_payload(
    item: Dict[str, Any],
    analysis: Dict[str, Any],
    *,
    evidence_id: str = "",
    detail_mode: str = "secondary",
) -> Dict[str, Any]:
    claim_limit = 320
    page_summary_limit = 360
    page_relevance_limit = 220
    claim_count = 4
    claim_item_limit = 200
    ioc_count = 4
    if detail_mode == "primary":
        claim_limit = 820
        page_summary_limit = 1200
        page_relevance_limit = 520
        claim_count = 6
        claim_item_limit = 360
        ioc_count = 8
    elif detail_mode == "background":
        claim_limit = 220
        page_summary_limit = 240
        page_relevance_limit = 140
        claim_count = 2
        claim_item_limit = 160
        ioc_count = 2
    payload: Dict[str, Any] = {
        "title": _text(item.get("title")),
        "source": _source_label(item.get("source")),
        "kind": _text(item.get("kind")),
        "type": _text(item.get("type")),
        "claim": _short_text(_text(item.get("claim")), claim_limit),
        "page_summary": _short_text(_text(item.get("page_summary")), page_summary_limit),
        "page_claims": _page_claims(item, limit=claim_count, per_item_limit=claim_item_limit),
        "page_relevance": _short_text(_text(item.get("page_relevance")), page_relevance_limit),
        "page_iocs": _page_iocs(item, limit=ioc_count),
        "url": _synthesized_url(item, analysis),
        "family": _family_name(analysis),
        "claim_origin": _text(item.get("claim_origin")),
        "detail_mode": detail_mode,
    }
    if evidence_id:
        payload["id"] = evidence_id
    return payload


def _fallback_item_paragraph(
    item: Dict[str, Any],
    analysis: Dict[str, Any],
    *,
    detail_mode: str = "secondary",
    section: str = "event",
) -> str:
    kind = _text(item.get("kind"))
    family = _family_name(analysis)
    title = _text(item.get("title")) or "相关来源"
    source = _source_label(item.get("source"))
    claim = _normalized_text(_text(item.get("claim")))
    page_summary = _normalized_text(_text(item.get("page_summary")))
    page_claims = _page_claims(item, limit=5 if detail_mode == "primary" else 3, per_item_limit=320 if detail_mode == "primary" else 220)
    page_relevance = _normalized_text(_text(item.get("page_relevance")))
    page_iocs = _page_iocs(item, limit=6 if detail_mode == "primary" else 3)
    local_intel = analysis.get("local_intel") or {}
    fp = (analysis.get("event") or {}).get("trigger_fingerprint") or {}
    fp_type = _text(fp.get("type"))
    fp_value = _text(fp.get("value"))

    if kind == "local_intel":
        parts = [
            f"本地情报库 `{source}` 直接将当前命中的 {fp_type} 指标 `{fp_value}` 关联到 `{family}`，这不是泛化的家族背景描述，而是直接落在本次告警触发项上的结构化命中，因此应视为本轮归因的核心证据。"
        ]
        last_updated = _text(local_intel.get("last_updated"))
        if last_updated:
            parts.append(f"该记录最近更新时间为 {last_updated}，说明这条映射并非孤立的历史残留，仍可以作为当前事件研判的高权重依据。")
        else:
            parts.append("相较于泛化的家族背景介绍，这类直接落在触发指标上的本地情报，更能解释本次告警为什么会被判定为该家族相关活动。")
        if detail_mode == "primary":
            parts.append(
                f"这意味着当前告警并不是仅凭标题或模糊标签做出的猜测，而是已经拿到了可以与历史情报库稳定对应的指纹线索，因此后续外部页面证据的主要作用是补充 `{family}` 的能力画像和行为细节，而不是替代这条直接映射。"
            )
            parts.append(
                f"从落地排查角度看，可以优先围绕 `{fp_value}` 做历史流量横向检索，确认是否存在同指纹复用、持续外联或多资产同时命中的情况。"
            )
        return " ".join(parts)

    if page_summary or page_claims:
        parts: List[str] = []
        if detail_mode == "primary":
            if page_summary:
                parts.append(f"`{title}` 的正文对 `{family}` 给出了更完整的能力画像：{_short_text(page_summary, 560)}")
            elif claim:
                parts.append(f"`{title}` 提供了与当前家族判断直接相关的页面证据：{_short_text(claim, 460)}")
            if page_claims:
                points = "；".join(page_claims[:3])
                parts.append(f"从页面正文能直接抽出的关键技术点包括：{points}。")
            if page_relevance:
                parts.append(f"就当前告警而言，{_short_text(page_relevance, 300)}")
            elif section == "event":
                parts.append(
                    f"放回当前告警语境里看，这些信息的价值不只是补充背景，而是说明 `{family}` 已知的传播、持久化、模块加载或窃密特征，与当前流量命中后的家族判断能够互相支撑。"
                )
            else:
                parts.append(f"这也说明当前报告里的 `{family}` 不是一个空泛标签，而是能够从公开研究中还原出相对清晰的行为画像和风险轮廓。")
            if page_iocs:
                parts.append(f"页面中还出现了 {', '.join(page_iocs[:4])} 等可继续用于扩线或交叉验证的技术线索。")
            else:
                parts.append("从研判与处置角度看，这类正文型来源能够帮助我们把“命中某个家族”进一步展开为“该家族通常如何传播、落地后会做什么、后续还该排查哪些痕迹”，因此比单纯标签更有分析价值。")
        elif detail_mode == "background":
            if page_summary:
                parts.append(f"`{title}` 补充说明了 `{family}` 的已知背景：{_short_text(page_summary, 220)}")
            elif claim:
                parts.append(f"`{title}` 还补充了一条家族背景线索：{_short_text(claim, 180)}")
            if page_claims:
                parts.append(f"其中值得保留的一点是：{page_claims[0]}。")
        else:
            if page_summary:
                parts.append(f"`{title}` 的页面正文提到了更具体的家族行为：{_short_text(page_summary, 320)}")
            elif claim:
                parts.append(f"`{title}` 的页面正文给出了与当前事件相关的线索：{_short_text(claim, 240)}")
            if page_claims:
                points = "；".join(page_claims[:2])
                parts.append(f"其中较直接的技术点包括：{points}。")
            if page_relevance:
                parts.append(_short_text(page_relevance, 180))
            elif kind in {"search_result", "supplemental", "enrichment"}:
                parts.append("这些信息更贴近当前指标或其关联家族，可为本次外联流量和归因判断提供更具体的背景支撑。")
            else:
                parts.append(f"这类研究性来源有助于解释 `{family}` 的已知能力与传播方式，从而补强本次归因。")
            if page_iocs:
                parts.append(f"正文还出现了 {', '.join(page_iocs[:3])} 等可供继续扩线的技术线索。")
        return " ".join(parts)

    if claim:
        snippet = _short_text(claim, 320 if detail_mode == "primary" else 260)
        if kind in {"search_result", "supplemental", "enrichment"}:
            if detail_mode == "primary":
                return (
                    f"`{title}` 的页面或搜索内容直接提到了与当前指标或其关联家族相关的线索：{snippet} "
                    f"虽然这条证据还不足以单独确认事件细节，但它至少说明当前命中的指标与 `{family}` 之间并非孤立关联，而是能在公开来源中得到进一步呼应。"
                )
            return (
                f"`{title}` 的页面或搜索内容直接提到了与当前指标或其关联家族相关的线索：{snippet} "
                f"这类来源更贴近本次事件本身，能够为当前流量、证书、指纹或基础设施的判断提供直接补充。"
            )
        if detail_mode == "background":
            return (
                f"`{title}` 提到了 `{family}` 的一条背景事实：{snippet} "
                f"这条信息更适合作为家族画像补充，而不是当前告警的直接证据。"
            )
        return (
            f"`{title}` 的正文内容指出：{snippet} "
            f"这类研究性来源更多用于解释 `{family}` 的家族背景、常见行为或传播方式，可作为归因补充支撑。"
        )

    return (
        f"`{title}` 提供了与 `{family}` 相关的公开情报。"
        f" 当前虽然缺少更完整的正文摘录，但该来源仍可作为本次事件归因和背景研判的辅助参考。"
    )


def _synthesize_evidence_paragraphs(
    analysis: Dict[str, Any],
    items: Sequence[Dict[str, Any]],
    *,
    detail_modes: Optional[Dict[str, str]] = None,
    section: str = "event",
    llm: Any = None,
) -> Dict[str, str]:
    if llm is None or not items:
        return {}

    detail_modes = detail_modes or {}
    payload_items = []
    for idx, item in enumerate(items):
        evidence_id = f"ev{idx}"
        payload_items.append(
            _evidence_payload(
                item,
                analysis,
                evidence_id=evidence_id,
                detail_mode=detail_modes.get(evidence_id, "secondary"),
            )
        )

    prompt = ChatPromptTemplate.from_messages(
        [
            (
                "system",
                "你是一位高级网络安全分析师。请只根据给定结构化证据，为每条证据生成中文段落。"
                "要求：1）优先使用 page_summary、page_claims、page_relevance、page_iocs 里的内容，提炼页面或情报里的具体事实，不要只写“概述了某家族”；"
                "2）detail_mode=primary 的条目必须写成至少 4 句、约 120-220 字的长段，并按“来源核心结论 -> 2-3 个关键技术细节 -> 与当前告警的关系 -> 对研判或排查的意义”组织；"
                "3）detail_mode=secondary 的条目写成至少 2 句、约 70-140 字；detail_mode=background 的条目写成 1-2 句、约 40-90 字；"
                "4）一条证据只保留最重要的 2-3 个事实，不要把所有 claim 机械平铺，也不要泛泛复述‘这是某家族恶意软件’；"
                "5）说明该来源如何支持当前事件或归因判断，并注意区分“直接支撑当前告警”和“只提供家族背景补充”；"
                "6）不要编造证据中没有的新事实；"
                "7）不同条目的摘要不要写成几乎相同的套话；"
                "8）不要重复标题，不要输出链接，不要使用项目符号。"
                "同时再输出 1 段总体分析摘要。"
                "必须只返回一个 JSON 对象，不要输出 markdown 代码块，不要输出解释性文字。"
                ' JSON 结构为 {{"analyst_summary":"...","items":[{{"id":"ev0","summary":"..."}},{{"id":"ev1","summary":"..."}}]}}。',
            ),
            (
                "user",
                "当前事件概览：\n{event_brief}\n\n当前报告区段：{section_name}\n\n证据列表：\n{evidence_json}",
            ),
        ]
    )
    event = analysis.get("event") or {}
    fp = event.get("trigger_fingerprint") or {}
    event_brief = (
        f"时间：{event.get('event_time')}；"
        f"通信：{(event.get('src') or {}).get('ip')} -> {(event.get('dst') or {}).get('ip')}；"
        f"协议：{event.get('protocol')}；"
        f"命中指标：{fp.get('type')} {fp.get('value')}；"
        f"当前家族：{_family_name(analysis)}。"
    )
    messages = prompt.format_messages(
        event_brief=event_brief,
        section_name="事件直接证据" if section == "event" else "家族背景与补充参考",
        evidence_json=json.dumps(payload_items, ensure_ascii=False, indent=2),
    )
    summaries: Dict[str, str] = {}
    result = _invoke_structured_llm_with_timeout(
        llm,
        EvidenceSummaryBatchModel,
        messages,
        timeout_s=18.0,
        label="event_evidence_batch",
    )
    if result is None:
        return summaries

    parsed = result.model_dump() if hasattr(result, "model_dump") else dict(result)
    analyst_summary = _text(parsed.get("analyst_summary"))
    if analyst_summary and not _looks_mostly_ascii(analyst_summary):
        summaries["__analyst_summary__"] = analyst_summary
    for item in parsed.get("items") or []:
        item_id = _text((item or {}).get("id"))
        summary = _text((item or {}).get("summary"))
        if item_id and summary and not _looks_mostly_ascii(summary):
            summaries[item_id] = summary
    return summaries


def _synthesize_single_evidence_paragraph(
    analysis: Dict[str, Any],
    item: Dict[str, Any],
    *,
    detail_mode: str = "secondary",
    section: str = "event",
    llm: Any = None,
) -> str:
    if llm is None:
        return ""

    prompt = ChatPromptTemplate.from_messages(
        [
            (
                "system",
                "你是一位高级网络安全分析师。请只根据给定单条结构化证据输出中文摘要。"
                "要求：1）优先使用 page_summary、page_claims、page_relevance、page_iocs 里的内容，提炼该来源中真正有信息量的内容；"
                "2）detail_mode=primary 时必须写成至少 4 句、约 120-220 字，并按“来源核心结论 -> 2-3 个关键细节 -> 与当前告警关系 -> 排查或研判含义”的顺序组织；"
                "3）detail_mode=secondary 时写成至少 2 句、约 70-140 字；detail_mode=background 时写成 1-2 句、约 40-90 字；"
                "4）说明它如何支持当前事件或归因判断，并注意区分当前告警直接证据和家族背景补充；"
                "5）不要编造 claim/snippet/page_summary 之外的新事实，也不要泛泛重复标题；"
                "6）不要输出链接，不要使用项目符号。"
                ' 必须只返回一个 JSON 对象，格式为 {{"summary":"..."}}，不要输出 markdown 代码块，不要输出其他解释。',
            ),
            (
                "user",
                "事件概览：{event_brief}\n\n当前报告区段：{section_name}\n\n单条证据：{evidence_json}",
            ),
        ]
    )
    event = analysis.get("event") or {}
    fp = event.get("trigger_fingerprint") or {}
    event_brief = (
        f"时间：{event.get('event_time')}；"
        f"通信：{(event.get('src') or {}).get('ip')} -> {(event.get('dst') or {}).get('ip')}；"
        f"协议：{event.get('protocol')}；"
        f"命中指标：{fp.get('type')} {fp.get('value')}；"
        f"当前家族：{_family_name(analysis)}。"
    )
    payload = _evidence_payload(item, analysis, detail_mode=detail_mode)
    messages = prompt.format_messages(
        event_brief=event_brief,
        section_name="事件直接证据" if section == "event" else "家族背景与补充参考",
        evidence_json=json.dumps(payload, ensure_ascii=False, indent=2),
    )
    result = _invoke_structured_llm_with_timeout(
        llm,
        EvidenceSummarySingleModel,
        messages,
        timeout_s=10.0,
        label=f"single_evidence:{payload.get('source') or payload.get('title') or 'unknown'}",
    )
    if result is None:
        return ""
    parsed = result.model_dump() if hasattr(result, "model_dump") else dict(result)
    summary = _text(parsed.get("summary"))
    if _looks_mostly_ascii(summary):
        return ""
    return summary


def _build_evidence_views(
    analysis: Dict[str, Any],
    items: Sequence[Dict[str, Any]],
    *,
    synthesized: Optional[Dict[str, str]] = None,
    detail_modes: Optional[Dict[str, str]] = None,
    section: str = "event",
    llm: Any = None,
) -> List[EvidenceView]:
    synthesized = synthesized or {}
    detail_modes = detail_modes or {}
    views: List[EvidenceView] = []
    for idx, item in enumerate(items):
        evidence_id = f"ev{idx}"
        claim = _text(item.get("claim"))
        body = _text(synthesized.get(evidence_id))
        detail_mode = detail_modes.get(evidence_id, "secondary")
        if _text(item.get("kind")) == "local_intel":
            body = _fallback_item_paragraph(item, analysis, detail_mode=detail_mode, section=section)
        elif not body or _needs_detail_expansion(body, detail_mode):
            body = _synthesize_single_evidence_paragraph(
                analysis,
                item,
                detail_mode=detail_mode,
                section=section,
                llm=llm,
            )
        if not body or _needs_detail_expansion(body, detail_mode):
            body = _fallback_item_paragraph(item, analysis, detail_mode=detail_mode, section=section)
        views.append(
            EvidenceView(
                evidence_id=evidence_id,
                title=_text(item.get("title")) or _source_label(item.get("source")) or "相关证据",
                source=_source_label(item.get("source")),
                url=_synthesized_url(item, analysis),
                level=_text(item.get("weight_level")),
                kind=_text(item.get("kind")),
                body=body,
                claim=claim,
            )
        )
    return views


def _overall_analyst_summary(
    analysis: Dict[str, Any],
    event_views: Sequence[EvidenceView],
    llm_summary: str = "",
) -> str:
    if _text(llm_summary):
        return _text(llm_summary)
    if not event_views:
        return _attribution_summary(analysis)
    family = _family_name(analysis)
    first = event_views[0].title
    count = len(event_views)
    return (
        f"当前结论并非仅来自单一标签，而是由结构化命中和外部公开情报共同支撑。"
        f" 其中 `{first}` 等 {count} 条高优证据从本地指纹、公开研究和基础设施线索多个角度支持该事件与 `{family}` 的关联。"
    )


def _event_detail_modes(items: Sequence[Dict[str, Any]]) -> Dict[str, str]:
    modes: Dict[str, str] = {}
    primary_budget = 2
    for idx, item in enumerate(items):
        evidence_id = f"ev{idx}"
        if primary_budget > 0 and _supports_primary_detail(item):
            modes[evidence_id] = "primary"
            primary_budget -= 1
        else:
            modes[evidence_id] = "secondary"
    return modes


def _base_action_lines(analysis: Dict[str, Any]) -> List[str]:
    actions: List[Dict[str, Any]] = list(analysis.get("recommended_actions") or [])
    rendered: List[str] = []
    for item in actions:
        rendered.append(
            f"[{_text(item.get('priority')).upper()}] {_text(item.get('action'))} 理由：{_text(item.get('rationale'))}"
        )
    return rendered


def _threat_hunt_actions(analysis: Dict[str, Any]) -> List[str]:
    claims = " ".join(
        " ".join(
            [
                _text(item.get("claim")),
                _text(item.get("page_summary")),
                " ".join(_text(value) for value in list(item.get("page_claims") or [])),
                _text(item.get("page_relevance")),
            ]
        )
        for item in (analysis.get("evidence") or [])
    )
    lowered = claims.lower()
    event = analysis.get("event") or {}
    fp = event.get("trigger_fingerprint") or {}
    actions: List[str] = []

    if any(token in lowered for token in ["infostealer", "stealer", "credential", "browser", "cookie", "wallet"]):
        actions.append("围绕浏览器凭据、Cookie、钱包插件和本地敏感配置文件开展主机侧排查，确认是否存在信息窃取后的残留痕迹。")
    if any(token in lowered for token in ["malvertising", "fake captcha", "compromised site", "hacked sites", "github"]):
        actions.append("回溯受害主机近期 Web 访问、下载链和跳转链路，重点排查恶意广告、伪造 CAPTCHA 页面、被入侵站点或第三方托管下载源。")
    if any(token in lowered for token in ["c2", "command and control", "backdoor", "rat", "beacon"]):
        actions.append("基于当前外联目标、同证书指纹或同类 TLS 特征继续扩线，排查是否存在持续 C2 通信或其他受影响资产。")
    if _text(fp.get("type")).upper() in {"JA3", "JA4", "SSL_SHA1"}:
        actions.append(f"在历史流量中进一步检索相同 {fp.get('type')} 指标 `{fp.get('value')}`，确认是否存在横向复用、批量投递或多资产命中。")

    deduped: List[str] = []
    seen: Set[str] = set()
    for action in actions:
        if action in seen:
            continue
        seen.add(action)
        deduped.append(action)
    return deduped[:3]


def _build_report_view_model(analysis: Dict[str, Any], *, llm: Any = None) -> ReportViewModel:
    model = ReportViewModel()
    model.conclusion_lines = _conclusion_lines(analysis)
    model.attribution_summary = _attribution_summary(analysis)
    model.uncertainties = _material_uncertainties(analysis)
    model.base_actions = _base_action_lines(analysis)
    model.threat_hunt_actions = _threat_hunt_actions(analysis)

    event_pool = sorted(
        _event_evidence_candidates(analysis, limit=8),
        key=lambda item: (
            0 if _text(item.get("kind")) == "local_intel" else 1,
            -_event_focus_score(item, analysis),
            -_coerce_int(item.get("weight"), 0),
        ),
    )
    event_items = event_pool[:2]
    if len(event_pool) > 2:
        third = event_pool[2]
        if _event_focus_score(third, analysis) >= 92:
            event_items.append(third)
    used_keys = {_evidence_key(item, analysis) for item in event_items}
    used_domains = {_text(item.get("domain")).lower() for item in event_items if _text(item.get("domain"))}
    background_pool = sorted(
        _background_evidence_candidates(analysis, used_keys=used_keys, used_domains=used_domains, limit=6),
        key=lambda item: (-_background_focus_score(item, analysis), -_coerce_int(item.get("weight"), 0)),
    )
    background_items = [item for item in background_pool if _background_focus_score(item, analysis) >= 78][:1]
    event_detail_modes = _event_detail_modes(event_items)
    background_detail_modes = {f"ev{idx}": "background" for idx, _ in enumerate(background_items)}

    llm_summary = ""
    event_payload: Dict[str, str] = {}
    background_payload: Dict[str, str] = {}
    if event_items:
        event_payload = _synthesize_evidence_paragraphs(
            analysis,
            event_items,
            detail_modes=event_detail_modes,
            section="event",
            llm=llm,
        )
        if llm is not None and not event_payload:
            LOGGER.warning(
                "Renderer event evidence synthesis returned empty; falling back to deterministic paragraphs for %d items",
                len(event_items),
            )
    if background_items:
        background_payload = _synthesize_evidence_paragraphs(
            analysis,
            background_items,
            detail_modes=background_detail_modes,
            section="background",
            llm=llm,
        )
        if llm is not None and not background_payload:
            LOGGER.warning(
                "Renderer background evidence synthesis returned empty; falling back to deterministic paragraphs for %d items",
                len(background_items),
            )

    model.event_evidence = _build_evidence_views(
        analysis,
        event_items,
        synthesized=event_payload,
        detail_modes=event_detail_modes,
        section="event",
        llm=llm,
    )
    model.background_references = _build_evidence_views(
        analysis,
        background_items,
        synthesized=background_payload,
        detail_modes=background_detail_modes,
        section="background",
        llm=llm,
    )
    llm_summary = _text(event_payload.get("__analyst_summary__"))

    model.analyst_summary = _overall_analyst_summary(analysis, model.event_evidence, llm_summary=llm_summary)
    return model


def render_report_from_analysis(analysis: Dict[str, Any], llm: Any = None) -> str:
    event = analysis.get("event") or {}
    assessment = analysis.get("assessment") or {}
    family = _text(assessment.get("family")) or "Unknown"
    confidence = _coerce_int(assessment.get("confidence"), 0)
    severity = _text(assessment.get("severity"))
    fp = event.get("trigger_fingerprint") or {}
    view = _build_report_view_model(analysis, llm=llm)

    lines: List[str] = ["# 网络安全事件分析报告", ""]

    lines.append("## 事件概述")
    lines.append(f"- 事件时间：{event.get('event_time')}")
    lines.append(f"- 通信关系：`{(event.get('src') or {}).get('ip')}` -> `{(event.get('dst') or {}).get('ip')}`")
    lines.append(f"- 协议：{event.get('protocol')}")
    lines.append(f"- 命中指标：{fp.get('type')} `{fp.get('value')}`")
    lines.append(f"- 当前研判：{family if family != 'Unknown' else '可疑恶意流量'}")
    lines.append(f"- 置信度：{confidence}")
    lines.append(f"- 严重度：{severity}")
    lines.append("")

    lines.append("## 研判结论")
    for line in view.conclusion_lines:
        lines.append(line)
        lines.append("")

    lines.append("## 归因依据")
    lines.append(view.attribution_summary)
    lines.append("")
    if view.analyst_summary:
        lines.append(view.analyst_summary)
        lines.append("")

    lines.append("## 事件直接证据")
    if view.event_evidence:
        for item in view.event_evidence:
            lines.append(f"### {item.title}")
            if item.source:
                lines.append(f"来源：{item.source}")
            if item.level:
                lines.append(f"证据等级：{item.level}")
            lines.append(item.body)
            if item.url:
                lines.append(f"参考：{_format_reference(item.url, item.url)}")
            lines.append("")
    else:
        lines.append("当前未提取到足以支撑正文展示的直接证据。")
        lines.append("")

    if view.background_references:
        lines.append("## 家族背景与补充参考")
        for item in view.background_references:
            lines.append(f"### {item.title}")
            if item.source:
                lines.append(f"来源：{item.source}")
            if item.level:
                lines.append(f"证据等级：{item.level}")
            lines.append(item.body)
            if item.url:
                lines.append(f"参考：{_format_reference(item.url, item.url)}")
            lines.append("")

    lines.append("## 处置建议")
    if view.base_actions:
        lines.append("### 基础响应")
        for action in view.base_actions:
            lines.append(f"- {action}")
        lines.append("")
    if view.threat_hunt_actions:
        lines.append("### 建议追加的威胁猎捕动作")
        for action in view.threat_hunt_actions:
            lines.append(f"- {action}")
        lines.append("")
    if not view.base_actions and not view.threat_hunt_actions:
        lines.append("- 当前未生成结构化处置建议。")
        lines.append("")

    if view.uncertainties:
        lines.append("## 说明")
        for item in view.uncertainties:
            lines.append(f"- {item}")
        lines.append("")

    return "\n".join(lines).strip() + "\n"
