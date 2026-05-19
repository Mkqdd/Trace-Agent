from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Tuple

from .report_text_quality import (
    is_low_information_evidence_label as _is_low_information_evidence_claim,
    is_meta_material_text as _is_meta_material_text,
)


SOURCE_NAMESPACES = {"obs", "event", "claim", "object", "gap", "action", "verdict"}
REPORT_SECTION_TYPES = {
    "investigation_entry",
    "scope_hypothesis",
    "entity_roles",
    "evidence_judgment",
    "conclusion_actions",
    "timeline_process",
    "relationship_scope",
    "impact_assessment",
    "counterevidence_limits",
    "external_context_intel",
    "topology_path_analysis",
}
REPORT_SECTION_MODES = {"full", "compact", "boundary_only"}
REPORT_CORE_COVERAGE = {
    "entry": {"investigation_entry"},
    "scope": {"scope_hypothesis", "entity_roles", "relationship_scope", "impact_assessment"},
    "evidence": {"evidence_judgment"},
    "conclusion": {"conclusion_actions"},
}
SECTION_BRIEF_WRITING_FIELDS = {"fact_role", "reader_fact_text", "why_it_matters", "limitation"}
SECTION_BRIEF_ROUTE_FIELDS = {"fact_role", "why_it_matters", "limitation", "use_for"}
PARAGRAPH_GROUP_REQUIRED_FIELDS = {
    "group_id",
    "paragraph_role",
    "paragraph_claim",
    "write_focus",
    "contrast_or_boundary",
    "must_not_repeat",
}
BLAND_ROUTE_TEXTS = {
    "事件时间线事实",
    "主支撑事件",
    "行动建议",
    "归纳判断或观察",
    "未闭合缺口",
    "背景或替代解释事件",
    "该事实需要结合其他证据使用，不能单独推出更强结论。",
    "该原子事实用于支撑本节判断或边界。",
}
BLAND_ROUTE_MARKERS = {
    "这些事实说明本节为什么需要展开",
    "这些节点说明异常链条出现扩线线索",
    "这些节点提供维护、更新或共享基础设施背景",
    "这些对象或事件需要保留在候选范围",
    "这些对象可以写入已确认调查范围",
    "这些基础设施是外联和封禁排查对象",
    "这些建议对应当前证据边界",
    "这些未闭合问题限制更强结论",
    "背景事件提供替代解释或共享基础设施边界",
    "本段只承担当前章节",
}
COMPLEX_DENSE_SECTION_TYPES = {
    "timeline_process",
    "evidence_judgment",
    "relationship_scope",
    "counterevidence_limits",
}


def _text(value: Any) -> str:
    return str(value or "").strip()


def _list(value: Any) -> List[Any]:
    return list(value or []) if isinstance(value, list) else []


def _dict(value: Any) -> Dict[str, Any]:
    return dict(value or {}) if isinstance(value, dict) else {}


def _dedupe(values: Iterable[Any]) -> List[str]:
    seen: set[str] = set()
    out: List[str] = []
    for value in values:
        text = _text(value)
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def _slug(value: Any) -> str:
    text = re.sub(r"[^a-zA-Z0-9]+", "-", _text(value)).strip("-").lower()
    return text or "fact"


def _source_ids_from_item(item: Dict[str, Any]) -> List[str]:
    source_ids = _list(item.get("source_ids"))
    source_id = _text(item.get("source_id"))
    if source_id:
        source_ids.append(source_id)
    return _dedupe(_text(source_id).replace(" ", "") for source_id in source_ids if _text(source_id))


def _fact_ids_from_item(item: Dict[str, Any]) -> List[str]:
    fact_ids = _list(item.get("fact_ids"))
    fact_id = _text(item.get("fact_id"))
    if fact_id:
        fact_ids.append(fact_id)
    return _dedupe(_text(value).replace(" ", "") for value in fact_ids if _text(value))


def _has_section_brief_writing_field(item: Dict[str, Any]) -> bool:
    return any(_text(item.get(field)) for field in SECTION_BRIEF_WRITING_FIELDS)


def _has_section_brief_route_field(item: Dict[str, Any]) -> bool:
    return any(_text(item.get(field)) for field in SECTION_BRIEF_ROUTE_FIELDS)


def _is_bland_route_text(value: Any) -> bool:
    text = _text(value)
    if not text:
        return True
    if text in BLAND_ROUTE_TEXTS:
        return True
    if any(marker in text for marker in BLAND_ROUTE_MARKERS):
        return True
    return len(text) < 4


def _contains_placeholder(value: Any) -> bool:
    if isinstance(value, str):
        return _text(value) in {"...", "……", "<...>", "TODO", "TBD"}
    if isinstance(value, dict):
        return any(_contains_placeholder(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_placeholder(item) for item in value)
    return False


def _fake_reportable_limit(value: Any) -> bool:
    text = _text(value)
    if not text:
        return False
    generic_markers = [
        "报告中包含",
        "报告包含",
        "包含了事件过程",
        "包含了已确认",
        "包含了事件的结论",
        "详细信息",
    ]
    return sum(1 for marker in generic_markers if marker in text) >= 2


def _feedback(
    code: str,
    message_for_agent: str,
    *,
    severity: str = "blocking",
    suggested_next_action: str = "submit_repaired_materials",
) -> Dict[str, str]:
    return {
        "code": code,
        "severity": severity,
        "message_for_agent": message_for_agent,
        "suggested_next_action": suggested_next_action,
    }


def _append_feedback_once(feedback: List[Dict[str, str]], item: Dict[str, str]) -> None:
    code = item.get("code")
    if code and any(existing.get("code") == code for existing in feedback):
        return
    feedback.append(item)


def _source_id_examples(index: Dict[str, Dict[str, Any]], source_ids: List[str], *, limit: int = 20) -> List[str]:
    namespaces = []
    for source_id in source_ids:
        if ":" not in source_id:
            continue
        namespace = source_id.split(":", 1)[0]
        if namespace and namespace not in namespaces:
            namespaces.append(namespace)
    examples: List[str] = []
    for namespace in namespaces:
        prefix = f"{namespace}:"
        for valid_source_id in sorted(index):
            if valid_source_id.startswith(prefix) and valid_source_id not in examples:
                examples.append(valid_source_id)
                if len(examples) >= limit:
                    return examples
    return examples


def _source_ids_with_prefix(source_ids: Iterable[str], prefix: str) -> List[str]:
    return [source_id for source_id in _dedupe(source_ids) if source_id.startswith(prefix)]


def _bundle_complexity_profile(bundle: Dict[str, Any]) -> Dict[str, Any]:
    scope = _dict(bundle.get("scope"))
    confirmed_assets = [_text(item) for item in _list(scope.get("confirmed_assets")) if _text(item)]
    candidate_assets = [_text(item) for item in _list(scope.get("candidate_assets")) if _text(item)]
    external_infrastructure = [_text(item) for item in _list(scope.get("external_infrastructure")) if _text(item)]
    events = [item for item in _list(bundle.get("events")) if isinstance(item, dict)]
    claims = [item for item in _list(bundle.get("claims")) if isinstance(item, dict)]
    objects = [item for item in _list(bundle.get("objects")) if isinstance(item, dict)]
    gaps = [item for item in _list(bundle.get("gaps")) if isinstance(item, dict)]
    recommendations = [item for item in _list(bundle.get("recommendations")) if isinstance(item, dict)]
    candidate_events = [item for item in events if _text(item.get("status")) == "candidate"]
    background_events = [item for item in events if _text(item.get("status")) == "background"]
    confirmed_events = [item for item in events if _text(item.get("status")) == "confirmed"]
    candidate_claims = [item for item in claims if _text(item.get("status")) == "candidate"]
    candidate_objects = [
        item
        for item in objects
        if "candidate" in _text(item.get("report_scope_role") or item.get("status") or item.get("relation"))
        or _text(item.get("report_scope_role")) in {"candidate_asset", "candidate_object"}
    ]
    external_objects = [item for item in objects if _text(item.get("report_scope_role")) == "external_infrastructure"]
    open_gaps = [
        item
        for item in gaps
        if _text(item.get("status") or item.get("legacy_status")) not in {"", "closed"}
    ]
    has_relationship_complexity = bool(
        candidate_assets
        or candidate_events
        or candidate_claims
        or candidate_objects
        or (external_infrastructure and (len(confirmed_assets) >= 2 or candidate_assets))
    )
    has_timeline_complexity = len(confirmed_events) >= 4 or bool(candidate_events) or len(confirmed_assets) >= 2
    has_counterevidence_complexity = bool(open_gaps or background_events)
    return {
        "is_complex": bool(has_relationship_complexity or has_timeline_complexity or has_counterevidence_complexity),
        "has_relationship_complexity": has_relationship_complexity,
        "has_timeline_complexity": has_timeline_complexity,
        "has_counterevidence_complexity": has_counterevidence_complexity,
        "confirmed_asset_count": len(confirmed_assets),
        "candidate_asset_count": len(candidate_assets),
        "external_infrastructure_count": len(external_infrastructure),
        "candidate_event_count": len(candidate_events),
        "candidate_claim_count": len(candidate_claims),
        "background_event_count": len(background_events),
        "open_gap_count": len(open_gaps),
        "recommendation_count": len(recommendations),
        "relationship_source_ids": _dedupe(
            [_text(item.get("source_id")) for item in candidate_events + candidate_claims + candidate_objects + external_objects]
        ),
        "external_source_ids": _dedupe(_text(item.get("source_id")) for item in external_objects),
        "candidate_source_ids": _dedupe(
            [_text(item.get("source_id")) for item in candidate_events + candidate_claims + candidate_objects]
        ),
        "background_source_ids": _dedupe(_text(item.get("source_id")) for item in background_events),
        "gap_source_ids": _dedupe(_text(item.get("source_id")) for item in open_gaps),
        "action_source_ids": _dedupe(_text(item.get("source_id")) for item in recommendations),
    }


def _catalog_fact_id(source_id: Any) -> str:
    text = _text(source_id)
    if not text:
        return "fact-unknown"
    namespace, _, raw = text.partition(":")
    return f"fact-{_slug(namespace)}-{_slug(raw)}"


def _fact_objects(item: Dict[str, Any]) -> List[str]:
    values = [
        item.get("domain"),
        item.get("dst_ip"),
        item.get("destination_ip"),
        item.get("src_ip"),
        item.get("source_ip"),
        item.get("asset_id"),
        item.get("asset"),
        item.get("host"),
        item.get("value"),
        item.get("object"),
    ]
    return _dedupe(values)


def _fact_time(item: Dict[str, Any]) -> str:
    return _text(item.get("ts") or item.get("time") or item.get("event_time"))


def _fact_asset(item: Dict[str, Any]) -> str:
    return _text(item.get("asset_id") or item.get("asset") or item.get("host"))


def _fact_summary(item: Dict[str, Any], source_id: str) -> str:
    return (
        _text(item.get("exact_fact_text"))
        or _text(item.get("summary"))
        or _text(item.get("text"))
        or _text(item.get("question"))
        or _text(item.get("status_reason"))
        or _text(item.get("value"))
        or _text(item.get("object"))
        or source_id
    )


def _fact_reporting_focus(item: Dict[str, Any], namespace: str) -> str:
    status = _text(item.get("status") or item.get("relation") or item.get("report_scope_role"))
    classification = _text(item.get("classification"))
    role = _text(item.get("report_scope_role") or item.get("current_role") or item.get("investigation_role"))
    if namespace == "event":
        if status == "candidate":
            return "候选扩线事件"
        if status == "background" or classification == "benign":
            return "背景或替代解释事件"
        if classification == "malicious":
            return "主支撑事件"
        return "事件时间线事实"
    if namespace == "object":
        if role == "confirmed_affected_asset":
            return "已确认受影响对象"
        if "candidate" in role:
            return "待确认对象"
        if role == "external_infrastructure":
            return "核心外部基础设施"
        if role == "background_object":
            return "背景对象"
        return "对象角色事实"
    if namespace == "gap":
        return "未闭合缺口" if status != "closed" else "已关闭缺口"
    if namespace == "action":
        return "行动建议"
    if namespace == "claim":
        return "归纳判断或观察"
    if namespace == "verdict":
        return "交付结论"
    return namespace or "事实"


def _fact_boundary_note(item: Dict[str, Any], namespace: str) -> str:
    status = _text(item.get("status") or item.get("relation") or item.get("report_scope_role"))
    role = _text(item.get("report_scope_role") or item.get("current_role"))
    summary = _fact_summary(item, _text(item.get("source_id")))
    if namespace == "event" and status == "candidate":
        return "候选事件尚未独立验证，只能写成待确认扩线或边界线索。"
    if namespace == "event" and (status == "background" or "背景/替代解释事件" in summary):
        return "背景或替代解释只能用于收窄边界，不能单独推翻主链。"
    if namespace == "object" and "candidate" in role:
        return "待确认对象不能写成已确认受影响范围。"
    if namespace == "object" and role == "external_infrastructure":
        return "外部基础设施只能写成外联对象、关联基础设施或排查封禁对象。"
    if namespace == "gap":
        return "该缺口限制更强结论或范围扩展，但不等于否定当前已支撑事实。"
    if namespace == "action":
        return "行动建议不是已观测事实，正文应写成后续处置或核查动作。"
    return ""


def _is_catalog_candidate_or_boundary(item: Dict[str, Any], namespace: str) -> bool:
    status = _text(item.get("status") or item.get("relation") or item.get("report_scope_role"))
    role = _text(item.get("report_scope_role") or item.get("current_role"))
    summary = _fact_summary(item, _text(item.get("source_id")))
    return bool(
        namespace in {"gap", "counterevidence"}
        or status in {"candidate", "open", "reportable_unresolved", "partially_closed"}
        or "candidate" in role
        or "候选事件（尚未独立验证）" in summary
        or "背景/替代解释事件" in summary
    )


def build_source_fact_catalog(bundle: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Build a deterministic, source-bound catalog for writer routing.

    The catalog is intentionally lossless for report writing: every entry keeps
    the source id and exact fact text. It normalizes fields but does not create
    new incident facts or conclusions.
    """

    index = _source_index(bundle)
    ordered_source_ids: List[str] = []
    for key in ["events", "objects", "claims", "gaps", "counterevidence", "recommendations", "observations"]:
        for item in _list(bundle.get(key)):
            if not isinstance(item, dict):
                continue
            source_id = _text(item.get("source_id"))
            if source_id:
                ordered_source_ids.append(source_id)
    if "verdict:delivery" in index:
        ordered_source_ids.insert(0, "verdict:delivery")

    catalog: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for source_id in _dedupe(ordered_source_ids):
        if source_id in seen:
            continue
        seen.add(source_id)
        item = _dict(index.get(source_id))
        if not item:
            continue
        namespace = source_id.split(":", 1)[0] if ":" in source_id else _text(item.get("source_type"))
        summary = _fact_summary(item, source_id)
        catalog.append(
            {
                "fact_id": _catalog_fact_id(source_id),
                "source_id": source_id,
                "fact_type": _text(item.get("source_type") or namespace),
                "status": _text(item.get("status") or item.get("relation") or item.get("report_scope_role")),
                "classification": _text(item.get("classification")),
                "kind": _text(item.get("kind")),
                "stages": _list(item.get("stages")),
                "tags": _list(item.get("tags")),
                "time": _fact_time(item),
                "asset": _fact_asset(item),
                "objects": _fact_objects(item),
                "summary_line": summary,
                "exact_fact_text": summary,
                "reporting_focus": _fact_reporting_focus(item, namespace),
                "boundary_note": _fact_boundary_note(item, namespace),
                "candidate_or_boundary": _is_catalog_candidate_or_boundary(item, namespace),
            }
        )
    return catalog


def source_fact_indexes(catalog: List[Dict[str, Any]]) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    by_fact_id: Dict[str, Dict[str, Any]] = {}
    by_source_id: Dict[str, Dict[str, Any]] = {}
    for raw in _list(catalog):
        fact = _dict(raw)
        fact_id = _text(fact.get("fact_id"))
        source_id = _text(fact.get("source_id"))
        if fact_id:
            by_fact_id[fact_id] = fact
        if source_id:
            by_source_id[source_id] = fact
    return by_fact_id, by_source_id


def _covered_report_section_types(report_plan: Dict[str, Any]) -> set[str]:
    covered: set[str] = set()
    for raw_section in _list(report_plan.get("sections")):
        section = _dict(raw_section)
        section_type = _text(section.get("section_type"))
        if section_type:
            covered.add(section_type)
        for secondary_type in _list(section.get("secondary_section_types")):
            secondary_text = _text(secondary_type)
            if secondary_text:
                covered.add(secondary_text)
    return covered


def _primary_section_types_covering(report_plan: Dict[str, Any], target_type: str) -> List[str]:
    section_types: List[str] = []
    for raw_section in _list(report_plan.get("sections")):
        section = _dict(raw_section)
        section_type = _text(section.get("section_type"))
        secondary_types = {_text(item) for item in _list(section.get("secondary_section_types"))}
        if section_type == target_type or target_type in secondary_types:
            section_types.append(section_type)
    return _dedupe(section_types)


def _section_source_ids_covering(report_plan: Dict[str, Any], target_type: str) -> List[str]:
    source_ids: List[str] = []
    for raw_section in _list(report_plan.get("sections")):
        section = _dict(raw_section)
        section_type = _text(section.get("section_type"))
        secondary_types = {_text(item) for item in _list(section.get("secondary_section_types"))}
        if section_type == target_type or target_type in secondary_types:
            source_ids.extend(_source_ids_from_item(section))
    return _dedupe(source_ids)


def _brief_source_ids_for_section_types(materials: Dict[str, Any], section_types: Iterable[str]) -> List[str]:
    wanted = {_text(item) for item in section_types if _text(item)}
    source_ids: List[str] = []
    if not wanted:
        return []
    for raw_brief in _list(materials.get("section_briefs")):
        brief = _dict(raw_brief)
        if _text(brief.get("section_type")) not in wanted:
            continue
        source_ids.extend(_source_ids_from_item(brief))
        for raw_fact in _list(brief.get("key_facts")):
            source_ids.extend(_source_ids_from_item(_dict(raw_fact)))
    return _dedupe(source_ids)


def _normalize_severity(value: Any) -> str:
    text = _text(value)
    mapping = {
        "critical": "高",
        "high": "高",
        "medium": "中",
        "low": "低",
        "info": "低",
        "紧急": "高",
        "高危": "高",
        "中危": "中",
        "低危": "低",
        "高": "高",
        "中": "中",
        "低": "低",
    }
    return mapping.get(text.lower(), mapping.get(text, text or "未评估"))


def _normalize_confidence(value: Any) -> str:
    text = _text(value)
    if not text:
        return "未评估"
    mapping = {
        "high": "高",
        "medium": "中",
        "low": "低",
        "高": "高",
        "中": "中",
        "低": "低",
    }
    if text.lower() in mapping:
        return mapping[text.lower()]
    if text in mapping:
        return mapping[text]
    try:
        score = float(text)
    except ValueError:
        return text
    if score <= 1:
        score *= 100
    if score >= 70:
        return "高"
    if score >= 50:
        return "中"
    return "低"


def _valid_source_id(source_id: Any) -> bool:
    text = _text(source_id)
    if ":" not in text:
        return False
    namespace, raw = text.split(":", 1)
    return namespace in SOURCE_NAMESPACES and bool(raw.strip())


def _source_index(bundle: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    index: Dict[str, Dict[str, Any]] = {}
    for key in ["observations", "events", "claims", "objects", "gaps", "recommendations"]:
        for item in _list(bundle.get(key)):
            if not isinstance(item, dict):
                continue
            source_id = _text(item.get("source_id"))
            if source_id:
                index[source_id] = dict(item)
    for item in _list(bundle.get("counterevidence")):
        if isinstance(item, dict) and _text(item.get("source_id")):
            index[_text(item.get("source_id"))] = dict(item)
    case_header = _dict(bundle.get("case_header"))
    if case_header:
        verdict_summary = _verdict_summary(_dict(case_header.get("final_verdict")))
        index["verdict:delivery"] = {
            "source_id": "verdict:delivery",
            "source_type": "verdict",
            "exact_fact_text": _text(verdict_summary.get("exact_fact_text"))
            or _text(case_header.get("delivery_status_label") or case_header.get("delivery_status")),
            "data": case_header,
        }
    return index


def source_index_for_materials(bundle: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return _source_index(bundle)


def _item_summary(item: Dict[str, Any]) -> str:
    return (
        _text(item.get("exact_fact_text"))
        or _text(item.get("summary"))
        or _text(item.get("text"))
        or _text(item.get("question"))
        or _text(item.get("value"))
        or _text(item.get("object"))
    )


def _seed_alert_summary(seed: Dict[str, Any]) -> Dict[str, Any]:
    trigger = _dict(seed.get("trigger_fingerprint"))
    enrichment = _dict(seed.get("enrichment"))
    src = _dict(seed.get("src"))
    dst = _dict(seed.get("dst"))
    raw = _dict(seed.get("raw_alert"))
    return {
        "event_time": _text(seed.get("event_time") or raw.get("timestamp")),
        "src_ip": _text(src.get("ip") or raw.get("src_ip")),
        "dst_ip": _text(dst.get("ip") or raw.get("dst_ip")),
        "protocol": _text(seed.get("protocol") or raw.get("protocol")),
        "fingerprint_type": _text(trigger.get("type") or _dict(raw.get("trigger_fingerprint")).get("type")),
        "fingerprint_value": _text(trigger.get("value") or _dict(raw.get("trigger_fingerprint")).get("value")),
        "info": _text(enrichment.get("info") or raw.get("info")),
    }


def _verdict_summary(value: Dict[str, Any]) -> Dict[str, Any]:
    rationale = _list(value.get("rationale"))
    rationale_text = "；".join(_text(item) for item in rationale if _text(item))
    status_label = _text(value.get("status_label"))
    exact_parts = [part for part in [status_label, rationale_text] if part]
    return {
        "source_id": "verdict:delivery",
        "status": _text(value.get("status")),
        "status_label": status_label,
        "severity": _normalize_severity(value.get("severity")),
        "confidence": _normalize_confidence(value.get("confidence")),
        "delivery_ready": bool(value.get("delivery_ready")),
        "provisional_status_label": _text(value.get("provisional_status_label")),
        "rationale": [_text(item) for item in rationale[:4] if _text(item)],
        "exact_fact_text": "；".join(exact_parts),
    }


def get_case_overview(bundle: Dict[str, Any]) -> Dict[str, Any]:
    header = _dict(bundle.get("case_header"))
    header_for_report = dict(header)
    header_for_report["severity_normalized"] = _normalize_severity(header.get("severity"))
    header_for_report["confidence_normalized"] = _normalize_confidence(header.get("confidence"))
    header_for_report["seed_alert_summary"] = _seed_alert_summary(_dict(header.get("seed_alert")))
    header_for_report["final_verdict_summary"] = _verdict_summary(_dict(header.get("final_verdict")))
    header_for_report.pop("seed_alert", None)
    header_for_report.pop("final_verdict", None)
    scope = _dict(bundle.get("scope"))
    return {
        "case_header": header_for_report,
        "confirmed_scope": _list(scope.get("confirmed_assets")),
        "candidate_scope": _list(scope.get("candidate_assets")),
        "external_infrastructure": _list(scope.get("external_infrastructure")),
        "source_counts": _dict(bundle.get("source_counts")),
    }


def list_source_items(
    bundle: Dict[str, Any],
    *,
    item_type: str = "event",
    status: str = "any",
    limit: int = 20,
) -> Dict[str, Any]:
    item_type = _text(item_type) or "event"
    status = _text(status).lower() or "any"
    key_map = {
        "event": "events",
        "claim": "claims",
        "object": "objects",
        "gap": "gaps",
        "counterevidence": "counterevidence",
        "recommendation": "recommendations",
        "observation": "observations",
    }
    key = key_map.get(item_type, "events")
    rows: List[Dict[str, Any]] = []
    for item in _list(bundle.get(key)):
        if not isinstance(item, dict):
            continue
        item_status = _text(item.get("status") or item.get("role") or item.get("relation")).lower()
        if status != "any" and status and item_status != status:
            continue
        rows.append(
            {
                "source_id": _text(item.get("source_id")),
                "id": _text(item.get("id") or item.get("value") or item.get("claim_id") or item.get("gap_id")),
                "status": item_status,
                "time": _text(item.get("ts") or item.get("time")),
                "object": _text(item.get("asset_id") or item.get("value") or item.get("object")),
                "summary": _item_summary(item),
                "exact_fact_text": _item_summary(item),
                "relation": _text(item.get("relation")),
                "observation_ref_count": len(_list(item.get("observation_ids"))),
            }
        )
    return {"item_type": item_type, "status": status, "items": rows[: max(1, int(limit or 20))]}


def get_source_details(bundle: Dict[str, Any], *, ids: List[Any]) -> Dict[str, Any]:
    index = _source_index(bundle)
    details: List[Dict[str, Any]] = []
    missing: List[str] = []
    for raw in _dedupe(ids):
        source_id = _text(raw)
        item = index.get(source_id)
        if not item:
            missing.append(source_id)
            continue
        details.append(item)
    return {"details": details, "missing_source_ids": missing}


def get_scope_roles(bundle: Dict[str, Any]) -> Dict[str, Any]:
    return get_scope_roles_for_report(bundle, mode="full")


def get_scope_roles_for_report(bundle: Dict[str, Any], *, mode: str = "full") -> Dict[str, Any]:
    mode = _text(mode).lower() or "full"
    rows: List[Dict[str, Any]] = []
    key_roles = {
        "confirmed_affected_asset",
        "candidate_asset",
        "external_infrastructure",
    }
    for item in _list(bundle.get("objects")):
        if not isinstance(item, dict):
            continue
        report_scope_role = _text(item.get("report_scope_role"))
        if mode == "key" and report_scope_role not in key_roles:
            continue
        row = {
            "source_id": _text(item.get("source_id")),
            "object": _text(item.get("value") or item.get("object")),
            "object_type": _text(item.get("object_type") or item.get("type")),
            "investigation_role": _text(item.get("investigation_role")),
            "report_scope_role": report_scope_role,
            "may_be_written_as_affected": report_scope_role == "confirmed_affected_asset",
        }
        if mode == "key":
            row["exact_fact_text"] = (
                f"对象 `{row['object']}` 的调查角色为 {row['investigation_role']}，"
                f"报告范围角色为 {row['report_scope_role']}。"
            )
        else:
            row["all_observed_roles"] = _list(item.get("all_observed_roles") or item.get("roles"))
            row["exact_fact_text"] = _text(item.get("exact_fact_text"))
        rows.append(row)
    return {"scope": _dict(bundle.get("scope")), "objects": rows, "source_conflicts": _list(bundle.get("source_conflicts"))}


def get_timeline(bundle: Dict[str, Any], *, mode: str = "core") -> Dict[str, Any]:
    mode = _text(mode) or "core"
    events = []
    for item in _list(bundle.get("timeline") or bundle.get("events")):
        if not isinstance(item, dict):
            continue
        status = _text(item.get("status"))
        if mode == "core" and status not in {"confirmed", "background"}:
            continue
        if mode == "with_candidates" and status not in {"confirmed", "background", "candidate"}:
            continue
        row = {
            "source_id": _text(item.get("source_id")),
            "time": _text(item.get("ts") or item.get("time")),
            "status": status,
            "classification": _text(item.get("classification")),
            "stages": _list(item.get("stages")),
            "asset": _text(item.get("asset_id")),
            "exact_fact_text": _text(item.get("exact_fact_text")),
        }
        if mode == "full":
            row["observation_ids"] = _list(item.get("observation_ids"))
        events.append(row)
    return {"mode": mode, "events": events}


def get_gaps_and_boundaries(bundle: Dict[str, Any], *, include_closed: bool = True) -> Dict[str, Any]:
    gaps = [
        {
            "source_id": _text(item.get("source_id")),
            "question": _text(item.get("question") or item.get("exact_fact_text")),
            "status": _text(item.get("status") or item.get("legacy_status")),
            "status_reason": _text(item.get("status_reason")),
            "delivery_blocking": bool(item.get("delivery_blocking")),
            "actionable_now": bool(item.get("actionable_now")),
            "exact_fact_text": _text(item.get("exact_fact_text")),
        }
        for item in _list(bundle.get("gaps"))
        if isinstance(item, dict) and (include_closed or _text(item.get("status") or item.get("legacy_status")) != "closed")
    ]
    counterevidence = [
        {
            "source_id": _text(item.get("source_id")),
            "text": _text(item.get("text") or item.get("exact_fact_text")),
            "observation_ids": _list(item.get("observation_ids")),
            "event_source_ids": _list(item.get("event_source_ids")),
        }
        for item in _list(bundle.get("counterevidence"))
        if isinstance(item, dict)
    ]
    return {"gaps": gaps, "counterevidence": counterevidence, "source_conflicts": _list(bundle.get("source_conflicts"))}


def collect_material_source_ids(value: Any) -> List[str]:
    ids: List[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key in {"source_fact_catalog", "fact_catalog", "source_inventory", "used_source_inventory"}:
                continue
            if key in {"fact_id", "fact_ids", "allowed_fact_ids"}:
                continue
            if key.endswith("_ids") or key == "source_ids":
                ids.extend(_text(v) for v in _list(item))
            elif key == "source_id":
                ids.append(_text(item))
            else:
                ids.extend(collect_material_source_ids(item))
    elif isinstance(value, list):
        for item in value:
            ids.extend(collect_material_source_ids(item))
    return _dedupe(ids)


def validate_report_writer_materials(bundle: Dict[str, Any], materials: Dict[str, Any]) -> Dict[str, Any]:
    index = _source_index(bundle)
    source_fact_catalog = _list(materials.get("source_fact_catalog")) or build_source_fact_catalog(bundle)
    fact_by_id, fact_by_source_id = source_fact_indexes(source_fact_catalog)
    source_ids = collect_material_source_ids(materials)
    invalid_namespace = [source_id for source_id in source_ids if not _valid_source_id(source_id)]
    missing = [source_id for source_id in source_ids if _valid_source_id(source_id) and source_id not in index]
    invalid_fact_ids: List[str] = []
    missing_exact_fact_text: List[str] = []
    empty_required_sections: List[str] = []
    missing_case_thesis_fields: List[str] = []
    report_plan_errors: List[str] = []
    section_brief_errors: List[str] = []
    section_fact_errors: List[str] = []
    paragraph_group_errors: List[str] = []
    thin_paragraph_groups: List[str] = []
    bland_paragraph_groups: List[str] = []
    duplicate_paragraph_claims: List[str] = []
    duplicate_fact_route_errors: List[str] = []
    thin_section_briefs: List[str] = []
    placeholder_fields: List[str] = []
    fake_reportable_limits: List[str] = []
    coverage_errors: List[str] = []
    blocking_thin_section_briefs: List[str] = []
    generated_fact_text_fields: List[str] = []
    meta_case_thesis_fields: List[str] = []
    low_information_evidence_claims: List[str] = []
    agent_feedback: List[Dict[str, str]] = []
    plan_section_types: List[str] = []
    plan_section_modes: Dict[str, str] = {}
    section_refs_by_type: Dict[str, List[str]] = {}
    paragraph_group_refs_by_type: Dict[str, List[str]] = {}
    fact_routes_by_fact_id: Dict[str, List[Tuple[str, str, str]]] = {}
    complexity_profile = _bundle_complexity_profile(bundle)
    if not _dict(materials.get("case_thesis")):
        empty_required_sections.append("case_thesis")
    else:
        case_thesis = _dict(materials.get("case_thesis"))
        for field in ["conclusion", "severity", "confidence", "why_this_judgment_holds", "why_not_stronger_or_broader", "exact_fact_text"]:
            if not _text(case_thesis.get(field)):
                missing_case_thesis_fields.append(field)
            elif field in {"why_this_judgment_holds", "why_not_stronger_or_broader"} and _is_meta_material_text(case_thesis.get(field)):
                meta_case_thesis_fields.append(field)
        if not _list(case_thesis.get("source_ids")):
            missing_case_thesis_fields.append("source_ids")
    for idx, item in enumerate(_list(materials.get("evidence_argument_map")), start=1):
        if isinstance(item, dict) and _is_low_information_evidence_claim(item.get("claim")):
            low_information_evidence_claims.append(f"evidence_argument_map[{idx}].claim")
    for section_key in ["narrative_spine", "evidence_argument_map", "scope_role_matrix"]:
        if not _list(materials.get(section_key)):
            empty_required_sections.append(section_key)
    report_plan = _dict(materials.get("report_plan"))
    if not report_plan:
        empty_required_sections.append("report_plan")
    else:
        if _text(report_plan.get("schema_version")) != "report-plan-v1":
            report_plan_errors.append("report_plan.schema_version must be report-plan-v1")
        sections = _list(report_plan.get("sections"))
        if not sections:
            report_plan_errors.append("report_plan.sections is empty")
        if len(sections) > 9:
            report_plan_errors.append("report_plan.sections has more than 9 sections")
        primary_types: List[str] = []
        covered_types: set[str] = set()
        for idx, raw_section in enumerate(sections, start=1):
            section = _dict(raw_section)
            section_type = _text(section.get("section_type"))
            if section_type not in REPORT_SECTION_TYPES:
                report_plan_errors.append(f"sections[{idx}].section_type is not allowed: {section_type or '<empty>'}")
            else:
                primary_types.append(section_type)
                plan_section_types.append(section_type)
                covered_types.add(section_type)
                plan_section_modes[section_type] = _text(section.get("mode")) or "full"
            if _text(section.get("mode")) and _text(section.get("mode")) not in REPORT_SECTION_MODES:
                report_plan_errors.append(f"sections[{idx}].mode is not allowed: {_text(section.get('mode'))}")
            for field in ["title", "question_to_answer"]:
                if not _text(section.get(field)):
                    report_plan_errors.append(f"sections[{idx}].{field} is required")
            section_source_ids = _list(section.get("source_ids"))
            if not section_source_ids:
                report_plan_errors.append(f"sections[{idx}].source_ids is required")
            for secondary_type in _list(section.get("secondary_section_types")):
                secondary_text = _text(secondary_type)
                if secondary_text not in REPORT_SECTION_TYPES:
                    report_plan_errors.append(f"sections[{idx}].secondary_section_types contains invalid type: {secondary_text or '<empty>'}")
                    continue
                if secondary_text == section_type:
                    report_plan_errors.append(f"sections[{idx}].secondary_section_types repeats primary section_type")
                    continue
                covered_types.add(secondary_text)
        duplicates = sorted({section_type for section_type in primary_types if primary_types.count(section_type) > 1})
        for section_type in duplicates:
            report_plan_errors.append(f"duplicate primary section_type: {section_type}")
        for coverage_name, allowed_types in REPORT_CORE_COVERAGE.items():
            if not covered_types.intersection(allowed_types):
                report_plan_errors.append(f"core coverage missing: {coverage_name}")
        covered_report_types = _covered_report_section_types(report_plan)
        relationship_source_ids = _list(complexity_profile.get("relationship_source_ids"))
        gap_source_ids = _list(complexity_profile.get("gap_source_ids"))
        if complexity_profile.get("has_relationship_complexity") and "relationship_scope" not in covered_report_types:
            coverage_errors.append("relationship_scope coverage missing for candidate/external relationship material")
            _append_feedback_once(
                agent_feedback,
                _feedback(
                    "missing_relationship_scope",
                    "source bundle 明确存在候选资产、候选事件、扩线 claim 或核心外部基础设施。下一轮必须让 report_plan 承接 relationship_scope：优先新增独立 relationship_scope；如果合并到相邻章节，必须把 relationship_scope 放入 secondary_section_types，并在 must_include、boundary_notes 和对应 section_briefs 中写清确认对象、候选对象、外部基础设施和不能并入已确认范围的边界。",
                ),
            )
        elif complexity_profile.get("has_relationship_complexity") and relationship_source_ids:
            relationship_carrier_types = _primary_section_types_covering(report_plan, "relationship_scope")
            relationship_section_source_ids = _section_source_ids_covering(report_plan, "relationship_scope")
            relationship_brief_source_ids = _brief_source_ids_for_section_types(materials, relationship_carrier_types)
            if not set(relationship_section_source_ids + relationship_brief_source_ids).intersection(relationship_source_ids):
                coverage_errors.append("relationship_scope lacks relationship source ids")
                _append_feedback_once(
                    agent_feedback,
                    _feedback(
                        "insufficient_relationship_scope_support",
                        "report_plan 已承接 relationship_scope，但承接该职责的章节没有引用候选资产、候选事件、扩线 claim 或核心外部基础设施的 source_id。下一轮不要重写整份材料，优先补强对应 section 的 source_ids 和 section_briefs.key_facts，并逐字复制这些可用 source_id："
                        + "、".join(relationship_source_ids[:8]),
                    ),
                )
        if complexity_profile.get("has_counterevidence_complexity") and "counterevidence_limits" not in covered_report_types:
            coverage_errors.append("counterevidence_limits coverage missing for gap/background material")
            _append_feedback_once(
                agent_feedback,
                _feedback(
                    "missing_counterevidence_limits",
                    "source bundle 明确存在未闭合 gap 或背景/替代解释事件。下一轮必须让 report_plan 承接 counterevidence_limits：优先新增独立 counterevidence_limits；如果合并到相邻章节，必须放入 secondary_section_types，并在 section_briefs 中说明这些缺口限制哪些更强结论。",
                ),
            )
        elif complexity_profile.get("has_counterevidence_complexity") and gap_source_ids:
            counter_carrier_types = _primary_section_types_covering(report_plan, "counterevidence_limits")
            counter_section_source_ids = _section_source_ids_covering(report_plan, "counterevidence_limits")
            counter_brief_source_ids = _brief_source_ids_for_section_types(materials, counter_carrier_types)
            if not set(counter_section_source_ids + counter_brief_source_ids).intersection(gap_source_ids):
                coverage_errors.append("counterevidence_limits lacks gap source ids")
                _append_feedback_once(
                    agent_feedback,
                    _feedback(
                        "insufficient_counterevidence_support",
                        "report_plan 已承接 counterevidence_limits，但承接该职责的章节没有引用未闭合 gap source_id。下一轮不要重写整份材料，优先补强对应 section 的 source_ids 和 section_briefs.key_facts，说明这些 gap 限制哪些更强结论。可用 gap source_id："
                        + "、".join(gap_source_ids[:8]),
                    ),
                )
    section_briefs = _list(materials.get("section_briefs"))
    if not section_briefs:
        empty_required_sections.append("section_briefs")
        _append_feedback_once(
            agent_feedback,
            _feedback(
                "missing_section_briefs",
                "你提交的 materials 缺少 section_briefs。下一轮不要调用工具；请基于已有 report_plan.sections 为每个 section_type 补齐 section_briefs，每节给出 2 到 5 个 source-bound key_facts，并为每个 key_fact 写清 source_ids/fact_ids、fact_role、why_it_matters、limitation 或 use_for；不要输出 reader_fact_text 或 exact_fact_text。",
            ),
        )
    else:
        brief_section_types: List[str] = []
        for idx, raw_brief in enumerate(section_briefs, start=1):
            brief = _dict(raw_brief)
            section_type = _text(brief.get("section_type"))
            brief_section_types.append(section_type)
            section_refs = _source_ids_from_item(brief)
            if section_type not in REPORT_SECTION_TYPES:
                section_brief_errors.append(f"section_briefs[{idx}].section_type is not allowed: {section_type or '<empty>'}")
            key_facts = _list(brief.get("key_facts"))
            if not key_facts:
                section_fact_errors.append(f"section_briefs[{idx}].key_facts is required")
            else:
                if (
                    complexity_profile.get("is_complex")
                    and section_type in COMPLEX_DENSE_SECTION_TYPES
                    and plan_section_modes.get(section_type) != "boundary_only"
                    and len(key_facts) < 3
                ):
                    blocking_thin_section_briefs.append(section_type or f"section_briefs[{idx}]")
                elif plan_section_modes.get(section_type) != "boundary_only" and len(key_facts) < 2:
                    thin_section_briefs.append(section_type or f"section_briefs[{idx}]")
            for fact_idx, raw_fact in enumerate(key_facts, start=1):
                fact = _dict(raw_fact)
                fact_source_ids = _source_ids_from_item(fact)
                fact_ids = _fact_ids_from_item(fact)
                for fact_id in fact_ids:
                    if fact_id not in fact_by_id:
                        invalid_fact_ids.append(fact_id)
                    else:
                        source_id = _text(fact_by_id[fact_id].get("source_id"))
                        if source_id:
                            fact_source_ids.append(source_id)
                if not fact_source_ids and not fact_ids:
                    section_fact_errors.append(f"section_briefs[{idx}].key_facts[{fact_idx}].source_ids or fact_ids is required")
                if not _has_section_brief_route_field(fact):
                    section_fact_errors.append(
                        f"section_briefs[{idx}].key_facts[{fact_idx}] needs one of fact_role/why_it_matters/limitation/use_for"
                    )
                if _text(fact.get("reader_fact_text")) or _text(fact.get("exact_fact_text")):
                    generated_fact_text_fields.append(f"section_briefs[{idx}].key_facts[{fact_idx}]")
                section_refs.extend(fact_source_ids)
            paragraph_groups = _list(brief.get("paragraph_groups"))
            if not paragraph_groups:
                paragraph_group_errors.append(f"section_briefs[{idx}].paragraph_groups is required")
            else:
                if (
                    complexity_profile.get("is_complex")
                    and section_type in COMPLEX_DENSE_SECTION_TYPES
                    and plan_section_modes.get(section_type) != "boundary_only"
                    and len(paragraph_groups) < 3
                ):
                    thin_paragraph_groups.append(section_type or f"section_briefs[{idx}]")
                elif plan_section_modes.get(section_type) != "boundary_only" and len(paragraph_groups) < 1:
                    thin_paragraph_groups.append(section_type or f"section_briefs[{idx}]")
            for group_idx, raw_group in enumerate(paragraph_groups, start=1):
                group = _dict(raw_group)
                for field in PARAGRAPH_GROUP_REQUIRED_FIELDS:
                    if not _text(group.get(field)):
                        paragraph_group_errors.append(
                            f"section_briefs[{idx}].paragraph_groups[{group_idx}].{field} is required"
                        )
                if _is_bland_route_text(group.get("paragraph_claim")) or _is_bland_route_text(group.get("write_focus")):
                    bland_paragraph_groups.append(f"{section_type or idx}:{group_idx}")
                group_source_ids = _source_ids_from_item(group)
                group_fact_ids = _fact_ids_from_item(group)
                for fact_id in group_fact_ids:
                    if fact_id not in fact_by_id:
                        invalid_fact_ids.append(fact_id)
                    else:
                        source_id = _text(fact_by_id[fact_id].get("source_id"))
                        if source_id:
                            group_source_ids.append(source_id)
                        fact_routes_by_fact_id.setdefault(fact_id, []).append(
                            (
                                section_type,
                                _text(group.get("paragraph_role")),
                                _text(group.get("paragraph_claim")),
                            )
                        )
                for source_id in list(group_source_ids):
                    fact = fact_by_source_id.get(source_id)
                    fact_id = _text(_dict(fact).get("fact_id"))
                    if fact_id:
                        fact_routes_by_fact_id.setdefault(fact_id, []).append(
                            (
                                section_type,
                                _text(group.get("paragraph_role")),
                                _text(group.get("paragraph_claim")),
                            )
                        )
                if not group_source_ids and not group_fact_ids:
                    paragraph_group_errors.append(
                        f"section_briefs[{idx}].paragraph_groups[{group_idx}].source_ids or fact_ids is required"
                    )
                section_refs.extend(group_source_ids)
                if section_type:
                    paragraph_group_refs_by_type[section_type] = _dedupe(
                        paragraph_group_refs_by_type.get(section_type, []) + group_source_ids
                    )
            claim_counts: Dict[str, int] = {}
            for raw_group in paragraph_groups:
                claim = _text(_dict(raw_group).get("paragraph_claim"))
                if not claim:
                    continue
                claim_counts[claim] = claim_counts.get(claim, 0) + 1
            for claim, count in claim_counts.items():
                if count > 1 and section_type in COMPLEX_DENSE_SECTION_TYPES:
                    duplicate_paragraph_claims.append(f"{section_type}:{claim[:40]}")
            if section_type:
                section_refs_by_type[section_type] = _dedupe(
                    section_refs_by_type.get(section_type, []) + section_refs
                )
        if plan_section_types:
            missing_brief_types = [section_type for section_type in plan_section_types if section_type not in brief_section_types]
            extra_brief_types = [section_type for section_type in brief_section_types if section_type not in plan_section_types]
            if missing_brief_types or extra_brief_types or len(brief_section_types) != len(plan_section_types):
                section_brief_errors.append(
                    "section_briefs section_type set must match report_plan.sections section_type set"
                )
                _append_feedback_once(
                    agent_feedback,
                    _feedback(
                        "section_brief_mismatch",
                        "section_briefs 必须覆盖 report_plan.sections 的每个 section_type，且不能多出无对应章节的 brief。下一轮请不要调用工具，优先补齐或删除 section_briefs。缺失："
                        + "、".join(missing_brief_types[:8])
                        + ("；多余：" + "、".join(extra_brief_types[:8]) if extra_brief_types else ""),
                    ),
                )
            elif brief_section_types != plan_section_types:
                _append_feedback_once(
                    agent_feedback,
                    _feedback(
                        "section_brief_order_mismatch",
                        "section_briefs 的顺序与 report_plan.sections 不一致；系统会按 section_type 映射，但下一轮可按 report_plan 顺序输出以便排查。",
                        severity="advisory",
                    ),
                )
        if thin_section_briefs:
            _append_feedback_once(
                agent_feedback,
                _feedback(
                    "thin_key_facts",
                    "部分 section_briefs 的 key_facts 仍偏薄。下一轮不要重写整份材料，优先补强这些章节："
                    + "、".join(thin_section_briefs[:8])
                    + "。每节补 2 到 5 个 source-bound key_facts，并说明事实角色、判断作用和边界。",
                    severity="advisory",
                ),
            )
        if blocking_thin_section_briefs:
            _append_feedback_once(
                agent_feedback,
                _feedback(
                    "thin_complex_section_briefs",
                    "当前 source bundle 属于复杂 case，复杂章节的 section_briefs 不能只给 1 到 2 条 key_facts。下一轮请补强这些章节："
                    + "、".join(blocking_thin_section_briefs[:8])
                    + "。timeline_process、evidence_judgment、relationship_scope、counterevidence_limits 应优先给 3 到 5 条 source-bound key_facts，并写清 fact_role、why_it_matters 和 limitation。",
                    severity="advisory",
                ),
            )
        if section_fact_errors:
            _append_feedback_once(
                agent_feedback,
                _feedback(
                "insufficient_section_support",
                "section_briefs 中存在缺 source_ids/fact_ids 或缺路由角色的 key_fact。请优先修正对应 key_facts：每条都要复制已见 source_id 或 source_fact_catalog 中的 fact_id，并至少提供 fact_role、why_it_matters、limitation 或 use_for 之一；不要输出 reader_fact_text 或 exact_fact_text。",
                ),
            )
        if paragraph_group_errors:
            _append_feedback_once(
                agent_feedback,
                _feedback(
                    "invalid_or_missing_paragraph_groups",
                    "section_briefs 必须为每个章节提交 paragraph_groups。每个 group 必须包含 group_id、paragraph_role、paragraph_claim、fact_ids/source_ids、write_focus、contrast_or_boundary、must_not_repeat；不要输出事实文本，只引用已有 fact_id/source_id。",
                ),
            )
        if thin_paragraph_groups:
            _append_feedback_once(
                agent_feedback,
                _feedback(
                    "thin_paragraph_groups",
                    "复杂章节缺少足够的 paragraph_groups。下一轮请补强这些章节："
                    + "、".join(thin_paragraph_groups[:8])
                    + "。timeline_process、evidence_judgment、relationship_scope、counterevidence_limits 每节至少 3 组，按阶段/判断链/范围边界/缺口边界分组。",
                    severity="advisory",
                ),
            )
        if bland_paragraph_groups:
            _append_feedback_once(
                agent_feedback,
                _feedback(
                    "bland_paragraph_group_claims",
                    "部分 paragraph_groups 的 paragraph_claim 或 write_focus 太模板化。下一轮请把这些段落改成具体论证意图："
                    + "、".join(bland_paragraph_groups[:10])
                    + "。不要只写“执行推进/候选扩线/通信连续性/背景解释/事件时间线事实/主支撑事件/行动建议/不能单独推出更强结论”。",
                    severity="advisory",
                ),
            )
        if duplicate_paragraph_claims:
            _append_feedback_once(
                agent_feedback,
                _feedback(
                    "duplicate_paragraph_group_claims",
                    "同一复杂章节内存在重复 paragraph_claim。下一轮请把这些段落拆成不同论证目的，例如维护窗口替代解释、共享基础设施边界、候选事件未验证，而不是重复同一句："
                    + "、".join(_dedupe(duplicate_paragraph_claims)[:10]),
                    severity="advisory",
                ),
            )
    for fact_id, routes in fact_routes_by_fact_id.items():
        section_names = {_text(route[0]) for route in routes if _text(route[0])}
        route_pairs = {(_text(route[1]), _text(route[2])) for route in routes}
        if len(section_names) > 1 and len(route_pairs) <= 1:
            duplicate_fact_route_errors.append(fact_id)
    if duplicate_fact_route_errors:
        _append_feedback_once(
            agent_feedback,
            _feedback(
                "duplicate_cross_section_fact_routes",
                "同一 fact 被多个章节复用时，paragraph_role 或 paragraph_claim 必须体现不同论证目的。下一轮请调整这些 fact 的 paragraph_groups，不要让 timeline/evidence/scope/limits 复述同一种用法："
                + "、".join(_dedupe(duplicate_fact_route_errors)[:10]),
                severity="advisory",
            ),
        )
    for section_key in [
        "narrative_spine",
        "evidence_argument_map",
        "scope_role_matrix",
        "counterarguments_and_boundaries",
        "action_rationale",
    ]:
        for idx, item in enumerate(_list(materials.get(section_key)), start=1):
            if isinstance(item, dict) and not _text(item.get("exact_fact_text")):
                missing_exact_fact_text.append(f"{section_key}[{idx}]")
    for idx, item in enumerate(_list(materials.get("reportable_limits")), start=1):
        if _fake_reportable_limit(item):
            fake_reportable_limits.append(f"reportable_limits[{idx}]")
    if _contains_placeholder(materials):
        placeholder_fields.append("materials")
    if invalid_namespace or missing:
        bad_ids = invalid_namespace + missing
        examples = _source_id_examples(index, bad_ids)
        _append_feedback_once(
            agent_feedback,
            _feedback(
                "invalid_or_missing_source_id",
                "materials 中存在非法或不存在的 source_id："
                + "、".join(bad_ids[:12])
                + ("。同类型可用 source_id 示例：" + "、".join(examples) if examples else "")
                + "。下一轮必须逐项替换或删除这些 id，只能逐字复制工具结果中已经出现过的 source_id；不要拼接、改写、推断或生成新 id。",
            ),
        )
    if invalid_fact_ids:
        _append_feedback_once(
            agent_feedback,
            _feedback(
                "invalid_or_missing_fact_id",
                "section_briefs 中存在不存在的 fact_id："
                + "、".join(_dedupe(invalid_fact_ids)[:12])
                + "。下一轮只能复制 source_fact_catalog 中已经出现的 fact_id；也可以直接改用对应 source_id。",
            ),
        )
    if generated_fact_text_fields:
        _append_feedback_once(
            agent_feedback,
            _feedback(
                "generated_section_fact_text",
                "section_briefs.key_facts 不应输出 reader_fact_text 或 exact_fact_text。下一轮请只保留 source_ids/fact_ids、fact_role、why_it_matters、limitation、use_for；事实文本由 deterministic source_fact_catalog 回填。",
            ),
        )
    if meta_case_thesis_fields:
        _append_feedback_once(
            agent_feedback,
            _feedback(
                "meta_case_thesis_text",
                "case_thesis 中出现了材料生成流程式表述，而不是面向读者的 source-bound 判断依据。下一轮请基于 verdict:delivery 或已引用 source_id 改写这些字段："
                + "、".join(meta_case_thesis_fields[:4])
                + "；不要写“生成报告材料”“只能依据已整理证据包”这类内部流程话术。",
                severity="advisory",
            ),
        )
    if low_information_evidence_claims:
        _append_feedback_once(
            agent_feedback,
            _feedback(
                "low_information_evidence_claims",
                "evidence_argument_map.claim 不能只写 suspicious/malicious/benign/confirmed/candidate 等分类标签。下一轮请引用具体 source_id/fact_id，并用 source-bound 事实角色或判断作用表达这些字段："
                + "、".join(low_information_evidence_claims[:8]),
                severity="advisory",
            ),
        )
    if fake_reportable_limits:
        _append_feedback_once(
            agent_feedback,
            _feedback(
                "fake_reportable_limits",
                "reportable_limits 只能写真实剩余限制，例如候选事件未验证、反证检查未完成、主机侧日志缺失。请删除“报告中包含了……”这类报告内容概述式 limit。",
            ),
        )
    if complexity_profile.get("has_relationship_complexity"):
        material_source_ids = set(source_ids)
        if not material_source_ids.intersection(complexity_profile.get("relationship_source_ids") or []):
            coverage_errors.append("relationship source ids not referenced")
            _append_feedback_once(
                agent_feedback,
                _feedback(
                    "missing_relationship_sources",
                    "source bundle 中存在候选/外部关系材料，但 materials 没有引用对应 source_id。下一轮请在 relationship_scope 或承接该职责的章节中引用候选资产、候选事件、扩线 claim 或核心外部基础设施的 source_id；不要只写已确认主链事件。",
                ),
            )
    if complexity_profile.get("gap_source_ids"):
        material_source_ids = set(source_ids)
        if not material_source_ids.intersection(complexity_profile.get("gap_source_ids") or []):
            coverage_errors.append("gap source ids not referenced")
            _append_feedback_once(
                agent_feedback,
                _feedback(
                    "missing_gap_sources",
                    "source bundle 中存在未闭合 gap，但 materials 没有引用 gap source_id。下一轮请在 counterevidence_limits 或 reportable_limits 中引用关键 gap，并说明它限制哪些更强结论。",
                ),
            )
    if complexity_profile.get("action_source_ids"):
        material_source_ids = set(source_ids)
        if not material_source_ids.intersection(complexity_profile.get("action_source_ids") or []):
            coverage_errors.append("action source ids not referenced")
            _append_feedback_once(
                agent_feedback,
                _feedback(
                    "missing_action_sources",
                    "source bundle 中存在 recommendation/action source，但 materials 没有引用 action source_id。下一轮请优先在 conclusion_actions 或 action_rationale 中引用至少一个 action source，并说明为什么这些动作对应当前证据边界。",
                ),
            )
    def refs_for_report_type(target_type: str) -> List[str]:
        refs: List[str] = []
        for section_type in _primary_section_types_covering(report_plan, target_type):
            refs.extend(paragraph_group_refs_by_type.get(section_type, []))
        if not refs:
            for section_type in _primary_section_types_covering(report_plan, target_type):
                refs.extend(section_refs_by_type.get(section_type, []))
        if not refs:
            refs.extend(_section_source_ids_covering(report_plan, target_type))
        return _dedupe(refs)

    confirmed_event_sources = [
        _text(fact.get("source_id"))
        for fact in source_fact_catalog
        if _text(fact.get("fact_type")) == "event" and _text(fact.get("status")) == "confirmed"
    ]
    if complexity_profile.get("has_timeline_complexity") and "timeline_process" in _covered_report_section_types(report_plan):
        timeline_refs = set(refs_for_report_type("timeline_process"))
        required = min(4, len(confirmed_event_sources))
        if required and len(timeline_refs.intersection(confirmed_event_sources)) < required:
            coverage_errors.append("timeline_process lacks enough atomic event facts")
            _append_feedback_once(
                agent_feedback,
                _feedback(
                    "insufficient_timeline_atomic_facts",
                    "source bundle 中存在多步时序推进。下一轮请补强 timeline_process 的 section_briefs.key_facts，至少引用 "
                    + str(required)
                    + " 条 confirmed event source_id/fact_id，不要把多条事件合并成一句泛化摘要。可用事件："
                    + "、".join(confirmed_event_sources[:8]),
                ),
            )

    if "evidence_judgment" in _covered_report_section_types(report_plan):
        evidence_refs = set(refs_for_report_type("evidence_judgment"))
        required = min(3, len(confirmed_event_sources))
        if complexity_profile.get("is_complex") and required and len(evidence_refs.intersection(confirmed_event_sources)) < required:
            coverage_errors.append("evidence_judgment lacks enough atomic event facts")
            _append_feedback_once(
                agent_feedback,
                _feedback(
                    "insufficient_evidence_atomic_facts",
                    "复杂 case 的 evidence_judgment 需要引用足够的原子事件事实来解释判断作用。下一轮请至少引用 "
                    + str(required)
                    + " 条 confirmed event source_id/fact_id，并分别说明 fact_role、why_it_matters 和 limitation。",
                ),
            )

    if complexity_profile.get("has_relationship_complexity") and "relationship_scope" in _covered_report_section_types(report_plan):
        relationship_refs = set(refs_for_report_type("relationship_scope"))
        external_sources = set(_list(complexity_profile.get("external_source_ids")))
        candidate_sources = set(_list(complexity_profile.get("candidate_source_ids")))
        if external_sources and not relationship_refs.intersection(external_sources):
            coverage_errors.append("relationship_scope lacks external infrastructure facts")
            _append_feedback_once(
                agent_feedback,
                _feedback(
                    "missing_external_infrastructure_route",
                    "relationship_scope 必须承接核心外部基础设施。下一轮请在该节 key_facts 中引用外部基础设施 source_id/fact_id："
                    + "、".join(sorted(external_sources)[:8]),
                ),
            )
        if candidate_sources and not relationship_refs.intersection(candidate_sources):
            coverage_errors.append("relationship_scope lacks candidate boundary facts")
            _append_feedback_once(
                agent_feedback,
                _feedback(
                    "missing_candidate_boundary_route",
                    "relationship_scope 必须承接候选资产、候选事件或扩线 claim 的边界。下一轮请在该节 key_facts 中引用候选 source_id/fact_id："
                    + "、".join(sorted(candidate_sources)[:8]),
                ),
            )

    if complexity_profile.get("has_counterevidence_complexity") and "counterevidence_limits" in _covered_report_section_types(report_plan):
        counter_refs = set(refs_for_report_type("counterevidence_limits"))
        background_sources = set(_list(complexity_profile.get("background_source_ids")))
        gap_sources = set(_list(complexity_profile.get("gap_source_ids")))
        if gap_sources and not counter_refs.intersection(gap_sources):
            coverage_errors.append("counterevidence_limits lacks gap facts")
            _append_feedback_once(
                agent_feedback,
                _feedback(
                    "missing_gap_counterevidence_route",
                    "counterevidence_limits 必须承接未闭合 gap。下一轮请在该节 key_facts 中引用关键 gap source_id/fact_id，并说明它们限制哪些更强结论："
                    + "、".join(sorted(gap_sources)[:8]),
                ),
            )
        if background_sources and not counter_refs.intersection(background_sources):
            coverage_errors.append("counterevidence_limits lacks background facts")
            _append_feedback_once(
                agent_feedback,
                _feedback(
                    "missing_background_counterevidence_route",
                    "source bundle 中存在背景/替代解释事件。下一轮请在 counterevidence_limits 中引用这些 background event source_id/fact_id，说明它们如何限制更强结论但不直接推翻主链："
                    + "、".join(sorted(background_sources)[:8]),
                ),
            )
    if missing_exact_fact_text:
        _append_feedback_once(
            agent_feedback,
            _feedback(
                "missing_exact_fact_text",
                "部分核心材料缺少 exact_fact_text。通常系统会按 source_ids 回填；如果仍缺失，请确认对应条目带有正确 source_ids，不要新增事实文本。",
            ),
        )
    if empty_required_sections or missing_case_thesis_fields or report_plan_errors:
        _append_feedback_once(
            agent_feedback,
            _feedback(
                "schema_or_core_coverage",
                "materials 存在 schema 或核心覆盖问题。下一轮优先修正已有 draft materials 的缺失字段、report_plan 或核心列表；除非确实缺 source_id，否则不要调用工具。",
            ),
        )
    ok = (
        not invalid_namespace
        and not missing
        and not invalid_fact_ids
        and not missing_exact_fact_text
        and not empty_required_sections
        and not missing_case_thesis_fields
        and not report_plan_errors
        and not section_brief_errors
        and not section_fact_errors
        and not paragraph_group_errors
        and not placeholder_fields
        and not fake_reportable_limits
        and not generated_fact_text_fields
        and not coverage_errors
    )
    return {
        "schema_version": "report-writer-materials-validation-v1",
        "ok": ok,
        "source_id_count": len(source_ids),
        "invalid_namespace": invalid_namespace,
        "missing_source_ids": missing,
        "invalid_fact_ids": _dedupe(invalid_fact_ids),
        "missing_exact_fact_text": missing_exact_fact_text,
        "empty_required_sections": empty_required_sections,
        "missing_case_thesis_fields": missing_case_thesis_fields,
        "report_plan_errors": report_plan_errors,
        "section_brief_errors": section_brief_errors,
        "section_fact_errors": section_fact_errors,
        "paragraph_group_errors": paragraph_group_errors,
        "thin_paragraph_groups": thin_paragraph_groups,
        "bland_paragraph_groups": bland_paragraph_groups,
        "duplicate_paragraph_claims": _dedupe(duplicate_paragraph_claims),
        "duplicate_fact_route_errors": _dedupe(duplicate_fact_route_errors),
        "thin_section_briefs": thin_section_briefs,
        "blocking_thin_section_briefs": blocking_thin_section_briefs,
        "placeholder_fields": placeholder_fields,
        "fake_reportable_limits": fake_reportable_limits,
        "generated_fact_text_fields": generated_fact_text_fields,
        "meta_case_thesis_fields": meta_case_thesis_fields,
        "low_information_evidence_claims": low_information_evidence_claims,
        "coverage_errors": coverage_errors,
        "complexity_profile": complexity_profile,
        "agent_feedback": agent_feedback,
    }


def execute_report_agent_tool(bundle: Dict[str, Any], tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
    params = _dict(params)
    if tool_name == "get_case_overview":
        return get_case_overview(bundle)
    if tool_name == "list_source_items":
        return list_source_items(
            bundle,
            item_type=_text(params.get("item_type") or "event"),
            status=_text(params.get("status") or "any"),
            limit=int(params.get("limit") or 20),
        )
    if tool_name == "get_source_details":
        return get_source_details(bundle, ids=_list(params.get("ids")))
    if tool_name == "get_scope_roles":
        return get_scope_roles_for_report(bundle, mode=_text(params.get("mode") or "full"))
    if tool_name == "get_timeline":
        return get_timeline(bundle, mode=_text(params.get("mode") or "core"))
    if tool_name == "get_gaps_and_boundaries":
        return get_gaps_and_boundaries(bundle, include_closed=bool(params.get("include_closed", True)))
    raise ValueError(f"unknown report agent tool: {tool_name}")
