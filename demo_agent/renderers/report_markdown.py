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
    limit: int = 2,
) -> List[Dict[str, Any]]:
    evidence: List[Dict[str, Any]] = list(analysis.get("evidence") or [])
    result: List[Dict[str, Any]] = []
    per_domain: Dict[str, int] = {}
    for item in sorted(evidence, key=_evidence_sort_key):
        kind = _text(item.get("kind"))
        if kind not in {"family_intel", "search_result"}:
            continue
        if not bool(item.get("is_reportable")) or _text(item.get("evidence_tier")) == "noisy":
            continue
        key = _evidence_key(item, analysis)
        if key in used_keys:
            continue
        domain = _text(item.get("domain"))
        if domain and per_domain.get(domain, 0) >= _per_domain_limit(item):
            continue
        if not _text(item.get("claim")) and not _text(item.get("title")):
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


def _fallback_item_paragraph(item: Dict[str, Any], analysis: Dict[str, Any]) -> str:
    kind = _text(item.get("kind"))
    family = _family_name(analysis)
    title = _text(item.get("title")) or "相关来源"
    source = _source_label(item.get("source"))
    claim = _normalized_text(_text(item.get("claim")))
    local_intel = analysis.get("local_intel") or {}
    fp = (analysis.get("event") or {}).get("trigger_fingerprint") or {}
    fp_type = _text(fp.get("type"))
    fp_value = _text(fp.get("value"))

    if kind == "local_intel":
        parts = [
            f"本地情报库 `{source}` 直接将当前命中的 {fp_type} 指标 `{fp_value}` 关联到 `{family}`，这类结构化指纹命中与当前告警直接对应，属于本次归因的主证据。"
        ]
        last_updated = _text(local_intel.get("last_updated"))
        if last_updated:
            parts.append(f"该记录最近更新时间为 {last_updated}，说明这条映射并非孤立的历史残留，仍可作为当前事件研判的高权重依据。")
        else:
            parts.append("相较于泛化的家族背景介绍，这类直接落在触发指标上的本地情报更能解释本次告警为何成立。")
        return " ".join(parts)

    if claim:
        snippet = _short_text(claim, 260)
        if kind in {"search_result", "supplemental", "enrichment"}:
            return (
                f"`{title}` 的页面或搜索内容直接提到了与当前指标或其关联家族相关的线索：{snippet} "
                f"这类来源更贴近本次事件本身，能够为当前流量、证书、指纹或基础设施的判断提供直接补充。"
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
    llm: Any = None,
) -> Dict[str, str]:
    if llm is None or not items:
        return {}

    payload_items = []
    for idx, item in enumerate(items):
        payload_items.append(
            {
                "id": f"ev{idx}",
                "title": _text(item.get("title")),
                "source": _source_label(item.get("source")),
                "kind": _text(item.get("kind")),
                "type": _text(item.get("type")),
                "claim": _short_text(_text(item.get("claim")), 320),
                "url": _synthesized_url(item, analysis),
                "family": _family_name(analysis),
            }
        )

    prompt = ChatPromptTemplate.from_messages(
        [
            (
                "system",
                "你是一位高级网络安全分析师。请只根据给定结构化证据，为每条证据生成 2-3 句中文段落。"
                "要求：1）提炼页面或情报里的具体内容，不要只写“概述了某家族”；"
                "2）说明该来源如何支持当前事件或归因判断；"
                "3）每条摘要必须体现该条 claim/snippet 中至少一个具体信息点，例如传播方式、功能、受害对象、IOC、TTP、基础设施线索之一；"
                "4）不要编造证据中没有的新事实；"
                "5）不同条目的摘要不要写成几乎相同的套话；"
                "6）不要重复标题，不要输出链接，不要使用项目符号。"
                "同时再输出 1 段 2-3 句的总体分析摘要。"
                "必须只返回一个 JSON 对象，不要输出 markdown 代码块，不要输出解释性文字。"
                ' JSON 结构为 {{"analyst_summary":"...","items":[{{"id":"ev0","summary":"..."}},{{"id":"ev1","summary":"..."}}]}}。',
            ),
            (
                "user",
                "当前事件概览：\n{event_brief}\n\n证据列表：\n{evidence_json}",
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
    if analyst_summary:
        summaries["__analyst_summary__"] = analyst_summary
    for item in parsed.get("items") or []:
        item_id = _text((item or {}).get("id"))
        summary = _text((item or {}).get("summary"))
        if item_id and summary:
            summaries[item_id] = summary
    return summaries


def _synthesize_single_evidence_paragraph(
    analysis: Dict[str, Any],
    item: Dict[str, Any],
    *,
    llm: Any = None,
) -> str:
    if llm is None:
        return ""

    prompt = ChatPromptTemplate.from_messages(
        [
            (
                "system",
                "你是一位高级网络安全分析师。请只根据给定单条结构化证据，输出 2 句中文摘要。"
                "要求：1）提炼该来源中真正有信息量的内容；"
                "2）说明它如何支持当前事件或归因判断；"
                "3）不要编造 claim/snippet 之外的新事实；"
                "4）不要重复标题，不要输出链接，不要使用项目符号。"
                ' 必须只返回一个 JSON 对象，格式为 {{"summary":"..."}}，不要输出 markdown 代码块，不要输出其他解释。',
            ),
            (
                "user",
                "事件概览：{event_brief}\n\n单条证据：{evidence_json}",
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
    payload = {
        "title": _text(item.get("title")),
        "source": _source_label(item.get("source")),
        "kind": _text(item.get("kind")),
        "type": _text(item.get("type")),
        "claim": _short_text(_text(item.get("claim")), 320),
        "url": _synthesized_url(item, analysis),
    }
    messages = prompt.format_messages(
        event_brief=event_brief,
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
    return _text(parsed.get("summary"))


def _build_evidence_views(
    analysis: Dict[str, Any],
    items: Sequence[Dict[str, Any]],
    *,
    synthesized: Optional[Dict[str, str]] = None,
    llm: Any = None,
) -> List[EvidenceView]:
    synthesized = synthesized or {}
    views: List[EvidenceView] = []
    for idx, item in enumerate(items):
        evidence_id = f"ev{idx}"
        claim = _text(item.get("claim"))
        body = _text(synthesized.get(evidence_id))
        if not body:
            body = _synthesize_single_evidence_paragraph(analysis, item, llm=llm)
        if not body:
            body = _fallback_item_paragraph(item, analysis)
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


def _base_action_lines(analysis: Dict[str, Any]) -> List[str]:
    actions: List[Dict[str, Any]] = list(analysis.get("recommended_actions") or [])
    rendered: List[str] = []
    for item in actions:
        rendered.append(
            f"[{_text(item.get('priority')).upper()}] {_text(item.get('action'))} 理由：{_text(item.get('rationale'))}"
        )
    return rendered


def _threat_hunt_actions(analysis: Dict[str, Any]) -> List[str]:
    claims = " ".join(_text(item.get("claim")) for item in (analysis.get("evidence") or []))
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

    event_items = _event_evidence_candidates(analysis)
    used_keys = {_evidence_key(item, analysis) for item in event_items}
    background_items = _background_evidence_candidates(analysis, used_keys=used_keys, limit=2)

    llm_summary = ""
    event_payload: Dict[str, str] = {}
    background_payload: Dict[str, str] = {}
    if event_items:
        event_payload = _synthesize_evidence_paragraphs(analysis, event_items, llm=llm)
        if llm is not None and not event_payload:
            LOGGER.warning(
                "Renderer event evidence synthesis returned empty; falling back to deterministic paragraphs for %d items",
                len(event_items),
            )
    if background_items:
        background_payload = _synthesize_evidence_paragraphs(analysis, background_items, llm=llm)
        if llm is not None and not background_payload:
            LOGGER.warning(
                "Renderer background evidence synthesis returned empty; falling back to deterministic paragraphs for %d items",
                len(background_items),
            )

    model.event_evidence = _build_evidence_views(analysis, event_items, synthesized=event_payload, llm=llm)
    model.background_references = _build_evidence_views(analysis, background_items, synthesized=background_payload, llm=llm)
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
