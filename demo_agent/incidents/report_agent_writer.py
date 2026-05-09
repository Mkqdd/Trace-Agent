from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Tuple

from ..services.api.llm_observability import invoke_llm_with_trace
from .report_agent_tools import source_fact_indexes


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True, default=str)


def _as_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def _text(value: Any) -> str:
    return str(value or "").strip()


def _dedupe(values: Iterable[Any]) -> List[str]:
    seen: set[str] = set()
    result: List[str] = []
    for value in values:
        text = _text(value)
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def _source_ids(value: Any) -> List[str]:
    return _dedupe(str(item) for item in _as_list(value))


def _fact_ids_from_item(item: Dict[str, Any]) -> List[str]:
    fact_ids = _as_list(item.get("fact_ids"))
    fact_id = _text(item.get("fact_id"))
    if fact_id:
        fact_ids.append(fact_id)
    return _dedupe(str(value) for value in fact_ids)


def _slug(value: Any) -> str:
    text = re.sub(r"[^a-zA-Z0-9]+", "-", _text(value)).strip("-").lower()
    return text or "section"


def _normalize_level(value: Any) -> str:
    text = _text(value)
    if not text:
        return "未评估"
    mapping = {
        "critical": "高",
        "high": "高",
        "medium": "中",
        "low": "低",
        "info": "低",
        "高危": "高",
        "中危": "中",
        "低危": "低",
        "高": "高",
        "中": "中",
        "低": "低",
        "未评估": "未评估",
    }
    return mapping.get(text.lower(), mapping.get(text, text if text in {"高", "中", "低", "未评估"} else "未评估"))


def _split_semicolon_text(value: Any, *, limit: int = 6) -> List[str]:
    text = _text(value)
    if not text:
        return []
    parts = re.split(r"[；;\n]+", text)
    return _dedupe(part.strip(" 。") for part in parts if _text(part))[:limit]


def _reader_clean_text(value: Any) -> str:
    text = _text(value)
    if not text:
        return ""
    replacements = {
        "同域名 / 同 dst_ip / 同 JA4": "相同域名、目标 IP 和 JA4 通信指纹",
        "同域名 / 同目标 IP / 同 JA4": "相同域名、目标 IP 和 JA4 通信指纹",
        "同域名/同 dst_ip/同 JA4": "相同域名、目标 IP 和 JA4 通信指纹",
        "同域名/同目标 IP/同 JA4": "相同域名、目标 IP 和 JA4 通信指纹",
        "dst_ip": "目标 IP",
        "seed alert": "种子告警",
        "Seed alert": "种子告警",
        "material loop": "材料整理流程",
        "rare domain": "罕见域名",
        "suspicious TLS": "可疑 TLS",
        "remote service creation": "远程服务创建",
        "user-writable path": "用户可写路径",
        "candidate window": "候选窗口",
        "maintenance window": "维护窗口",
        "shared infrastructure": "共享基础设施",
        "workstation": "工作站",
        "beacon": "信标",
        "这可能是恶意软件执行的一部分": "这可能是可疑执行链的一部分",
        "恶意软件执行": "可疑执行活动",
        "实际的恶意活动": "实际异常活动",
        "实际恶意活动": "实际异常活动",
        "这些基础设施是否为真实受影响对象": "这些基础设施是否属于共享基础设施或当前事件相关基础设施",
    }
    for source, target in replacements.items():
        text = text.replace(source, target)
    text = re.sub(r"\bpivot\b", "关键关联指标", text, flags=re.IGNORECASE)
    text = text.replace("当前 关键关联指标", "当前关键关联指标")
    text = text.replace("通信指纹 搜索", "通信指纹搜索")
    text = re.sub(r"\s+", " ", text).strip()
    return text


LOW_INFORMATION_EVIDENCE_LABELS = {
    "suspicious",
    "malicious",
    "benign",
    "confirmed",
    "candidate",
    "needs_review",
    "unknown",
    "主支撑证据",
    "范围证据",
    "边界证据",
    "章节事实",
    "关键事件事实",
    "可疑",
    "恶意",
}

META_CONCLUSION_MARKERS = {
    "生成报告材料",
    "证据包保守生成",
    "只能依据已整理",
}


def _is_low_information_evidence_text(value: Any) -> bool:
    text = _reader_clean_text(value)
    if not text:
        return True
    lowered = text.lower()
    if lowered in LOW_INFORMATION_EVIDENCE_LABELS or text in LOW_INFORMATION_EVIDENCE_LABELS:
        return True
    return len(text) <= 3


def _is_meta_conclusion_text(value: Any) -> bool:
    text = _reader_clean_text(value)
    return bool(text and any(marker in text for marker in META_CONCLUSION_MARKERS))


def _first_useful_evidence_text(item: Dict[str, Any]) -> str:
    for key in ["claim", "reader_fact_text", "exact_fact_text", "why_it_matters"]:
        text = _reader_clean_text(item.get(key))
        if text and not _is_low_information_evidence_text(text):
            return text
    return ""


def _catalog_event_evidence(catalog_facts: List[Dict[str, Any]]) -> List[str]:
    scored: List[Tuple[int, int, str]] = []
    for index, fact in enumerate(catalog_facts):
        if _text(fact.get("fact_type")) != "event":
            continue
        text = _reader_clean_text(fact.get("summary_line") or fact.get("exact_fact_text"))
        if not text or _is_low_information_evidence_text(text):
            continue
        status = _text(fact.get("status"))
        focus = _text(fact.get("reporting_focus"))
        classification = _text(fact.get("classification"))
        score = 0
        if status == "confirmed":
            score += 30
        if "主支撑" in focus:
            score += 40
        if classification == "malicious":
            score += 30
        if bool(fact.get("candidate_or_boundary")):
            score -= 30
        if status == "background":
            score -= 40
        scored.append((score, -index, text))
    return _dedupe(text for _score, _index, text in sorted(scored, reverse=True))


def _catalog_verdict_text(catalog_facts: List[Dict[str, Any]]) -> str:
    for fact in catalog_facts:
        if _text(fact.get("fact_type")) != "verdict" and _text(fact.get("source_id")) != "verdict:delivery":
            continue
        text = _reader_clean_text(fact.get("summary_line") or fact.get("exact_fact_text"))
        if text and not _is_meta_conclusion_text(text):
            return text
    return ""


def _header_conclusion_sentence(
    thesis: Dict[str, Any],
    strongest_evidence: List[str],
    *,
    verdict_text: str = "",
) -> str:
    raw = _reader_clean_text(thesis.get("why_this_judgment_holds"))
    if raw and not _is_meta_conclusion_text(raw):
        return raw
    if verdict_text:
        return verdict_text
    conclusion = _reader_clean_text(thesis.get("conclusion")) or "当前结论"
    confirmed_scope = "、".join(_dedupe(_as_list(thesis.get("confirmed_scope")))[:4])
    evidence_text = "；".join(strongest_evidence[:2])
    pieces = [f"当前结论为{conclusion}"]
    if confirmed_scope:
        pieces.append(f"已确认范围包括{confirmed_scope}")
    if evidence_text:
        pieces.append(f"主要依据包括{evidence_text}")
    return "；".join(pieces) + "。"


def _source_index(materials: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    index: Dict[str, Dict[str, Any]] = {}
    for item in _as_list(materials.get("source_fact_catalog")):
        entry = _as_dict(item)
        source_id = _text(entry.get("source_id"))
        if source_id:
            index[source_id] = {
                "source_id": source_id,
                "source_type": _text(entry.get("fact_type")),
                "status": _text(entry.get("status")),
                "summary": _text(entry.get("summary_line")),
                "exact_fact_text": _text(entry.get("exact_fact_text")),
            }
    for item in _as_list(materials.get("source_inventory")):
        entry = _as_dict(item)
        source_id = _text(entry.get("source_id"))
        if source_id:
            index[source_id] = entry
    return index


def _source_summaries(source_ids: List[str], source_by_id: Dict[str, Dict[str, Any]]) -> List[Dict[str, str]]:
    summaries: List[Dict[str, str]] = []
    for source_id in source_ids:
        source = source_by_id.get(source_id) or {}
        status = _text(source.get("status"))
        source_type = _text(source.get("source_type"))
        item = {"source_id": source_id}
        if source_type:
            item["source_type"] = source_type
        if status:
            item["status"] = status
        summaries.append(item)
    return summaries


def _is_candidate_or_boundary(fact_role: Any, texts: Iterable[Any], sources: List[Dict[str, str]]) -> bool:
    role_text = _text(fact_role)
    if any(marker in role_text for marker in ["候选", "待确认", "未闭合", "缺口", "反证", "边界"]):
        return True
    haystack = "；".join(_text(text) for text in texts)
    if "候选事件（尚未独立验证）" in haystack:
        return True
    for source in sources:
        source_id = _text(source.get("source_id"))
        source_type = _text(source.get("source_type")).lower()
        status = _text(source.get("status")).lower()
        if source_id.startswith("gap:") or source_id.startswith("counterevidence:"):
            return True
        if source_type in {"gap", "counterevidence"}:
            return True
        if status in {"candidate", "待确认", "open", "partially_closed"}:
            return True
    return False


def _first_text(items: Iterable[Dict[str, Any]], *keys: str) -> str:
    for item in items:
        for key in keys:
            text = _text(item.get(key))
            if text:
                return text
    return ""


def _brief_by_section(materials: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    result: Dict[str, Dict[str, Any]] = {}
    for brief in _as_list(materials.get("section_briefs")):
        entry = _as_dict(brief)
        section_type = _text(entry.get("section_type"))
        if section_type and section_type not in result:
            result[section_type] = entry
    return result


def _build_header_packet(materials: Dict[str, Any]) -> Dict[str, Any]:
    plan = _as_dict(materials.get("report_plan"))
    thesis = _as_dict(materials.get("case_thesis"))
    evidence_items = [_as_dict(item) for item in _as_list(materials.get("evidence_argument_map"))]
    action_items = [_as_dict(item) for item in _as_list(materials.get("action_rationale"))]
    scope_items = [_as_dict(item) for item in _as_list(materials.get("scope_role_matrix"))]
    catalog_facts = [_as_dict(item) for item in _as_list(materials.get("source_fact_catalog"))]

    action_texts: List[str] = []
    for item in action_items:
        action_texts.extend(
            _reader_clean_text(part)
            for part in _split_semicolon_text(item.get("reader_action") or item.get("action") or item.get("reader_fact_text"), limit=8)
        )

    key_gaps = _dedupe(_reader_clean_text(item) for item in _as_list(materials.get("reportable_limits")))
    if not key_gaps:
        for item in _as_list(materials.get("counterarguments_and_boundaries")):
            counter = _as_dict(item)
            key_gaps.extend(_reader_clean_text(part) for part in _split_semicolon_text(counter.get("reader_fact_text") or counter.get("limitation"), limit=4))

    evidence_map_texts = _dedupe(_first_useful_evidence_text(item) for item in evidence_items)
    catalog_event_texts = _catalog_event_evidence(catalog_facts)
    strongest_evidence = _dedupe(catalog_event_texts + evidence_map_texts)[:4]
    one_sentence_conclusion = _header_conclusion_sentence(
        thesis,
        strongest_evidence,
        verdict_text=_catalog_verdict_text(catalog_facts),
    )
    why_this_judgment_holds = _reader_clean_text(thesis.get("why_this_judgment_holds"))
    if not why_this_judgment_holds or _is_meta_conclusion_text(why_this_judgment_holds):
        why_this_judgment_holds = one_sentence_conclusion

    return {
        "report_title": _text(plan.get("title")),
        "conclusion": _text(thesis.get("conclusion")),
        "severity": _normalize_level(thesis.get("severity")),
        "confidence": _normalize_level(thesis.get("confidence")),
        "confirmed_scope": _dedupe(_as_list(thesis.get("confirmed_scope"))),
        "candidate_scope": _dedupe(_as_list(thesis.get("candidate_scope"))),
        "why_this_judgment_holds": why_this_judgment_holds,
        "why_not_stronger_or_broader": _text(thesis.get("why_not_stronger_or_broader")),
        "strongest_evidence": strongest_evidence,
        "key_gaps": key_gaps[:6],
        "immediate_actions": _dedupe(action_texts)[:6],
        "scope_roles": [
            {
                "role": _text(item.get("role") or item.get("how_to_write")),
                "how_to_write": _text(item.get("how_to_write")),
                "reader_fact_text": _reader_clean_text(item.get("reader_fact_text")),
                "limitation": _reader_clean_text(item.get("limitation")),
                "source_ids": _source_ids(item.get("source_ids")),
            }
            for item in scope_items
            if _text(item.get("reader_fact_text")) or _source_ids(item.get("source_ids"))
        ],
        "one_sentence_conclusion": one_sentence_conclusion,
    }


def _catalog_entry_from_source_fact(
    source_fact: Dict[str, Any],
    source_by_id: Dict[str, Dict[str, Any]],
    *,
    route_role: Any = "",
    route_texts: Iterable[Any] = (),
) -> Dict[str, Any]:
    source_id = _text(source_fact.get("source_id"))
    source_fact_id = _text(source_fact.get("fact_id")) or f"source-{_slug(source_id)}"
    source_summaries = _source_summaries([source_id], source_by_id) if source_id else []
    reader_fact_text = _reader_clean_text(
        source_fact.get("summary_line")
        or source_fact.get("exact_fact_text")
        or _as_dict(source_by_id.get(source_id)).get("summary")
    )
    exact_fact_text = _reader_clean_text(
        source_fact.get("exact_fact_text")
        or _as_dict(source_by_id.get(source_id)).get("exact_fact_text")
    )
    reporting_focus = _reader_clean_text(source_fact.get("reporting_focus"))
    boundary_note = _reader_clean_text(source_fact.get("boundary_note"))
    candidate_or_boundary = bool(source_fact.get("candidate_or_boundary")) or _is_candidate_or_boundary(
        route_role,
        [reader_fact_text, exact_fact_text, reporting_focus, boundary_note, *list(route_texts)],
        source_summaries,
    )
    entry = {
        "fact_id": source_fact_id,
        "source_id": source_id,
        "fact_type": _text(source_fact.get("fact_type")),
        "status": _text(source_fact.get("status")),
        "classification": _text(source_fact.get("classification")),
        "time": _text(source_fact.get("time")),
        "asset": _text(source_fact.get("asset")),
        "objects": _as_list(source_fact.get("objects")),
        "reader_fact_text": reader_fact_text,
        "reporting_focus": reporting_focus,
        "source_boundary_note": boundary_note,
        "source_ids": [source_id] if source_id else [],
        "candidate_or_boundary": candidate_or_boundary,
    }
    if exact_fact_text and exact_fact_text != reader_fact_text:
        entry["exact_fact_text"] = exact_fact_text
    return entry


def _fact_snapshot(entry: Dict[str, Any]) -> Dict[str, Any]:
    # Keep paragraph snapshots compact: fact_catalog remains the full fact
    # archive, while snapshots only carry the fields the writer needs in-place.
    snapshot = {
        "fact_id": _text(entry.get("fact_id")),
        "source_id": _text(entry.get("source_id")),
        "fact_type": _text(entry.get("fact_type")),
        "status": _text(entry.get("status")),
        "classification": _text(entry.get("classification")),
        "time": _text(entry.get("time")),
        "asset": _text(entry.get("asset")),
        "objects": _as_list(entry.get("objects")),
        "fact_text": _reader_clean_text(entry.get("reader_fact_text")),
        "reporting_focus": _reader_clean_text(entry.get("reporting_focus")),
        "source_boundary_note": _reader_clean_text(entry.get("source_boundary_note")),
        "candidate_or_boundary": bool(entry.get("candidate_or_boundary")),
    }
    exact_fact_text = _reader_clean_text(entry.get("exact_fact_text"))
    if exact_fact_text:
        snapshot["exact_fact_text"] = exact_fact_text
    return {
        key: value
        for key, value in snapshot.items()
        if value is not None and value != "" and value != []
    }


def _resolve_fact_refs(
    item: Dict[str, Any],
    fact_by_id: Dict[str, Dict[str, Any]],
    fact_by_source_id: Dict[str, Dict[str, Any]],
    *,
    fallback_source_ids: Iterable[Any] = (),
) -> Tuple[List[str], List[str]]:
    fact_ids = _fact_ids_from_item(item)
    source_ids = _source_ids(item.get("source_ids"))
    if not fact_ids and not source_ids:
        source_ids = _dedupe(fallback_source_ids)
    for fact_id in list(fact_ids):
        source_id = _text(_as_dict(fact_by_id.get(fact_id)).get("source_id"))
        if source_id:
            source_ids.append(source_id)
    for source_id in list(source_ids):
        fact_id = _text(_as_dict(fact_by_source_id.get(source_id)).get("fact_id"))
        if fact_id:
            fact_ids.append(fact_id)
    fact_ids = [fact_id for fact_id in _dedupe(fact_ids) if fact_id in fact_by_id]
    source_ids = [source_id for source_id in _dedupe(source_ids) if source_id in fact_by_source_id]
    return fact_ids, source_ids


def _route_fact_snapshots(
    fact_ids: List[str],
    fact_catalog_by_id: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    snapshots: List[Dict[str, Any]] = []
    for fact_id in fact_ids:
        entry = _as_dict(fact_catalog_by_id.get(fact_id))
        if not entry:
            continue
        snapshots.append(_fact_snapshot(entry))
    return snapshots


def _paragraph_plan_from_group(
    group: Dict[str, Any],
    *,
    section_type: str,
    index: int,
    fact_ids: List[str],
    source_ids: List[str],
    fact_snapshots: List[Dict[str, Any]],
) -> Dict[str, Any]:
    paragraph_role = _reader_clean_text(group.get("paragraph_role") or group.get("fact_role") or f"段落组 {index}")
    paragraph_claim = _reader_clean_text(group.get("paragraph_claim") or group.get("claim") or paragraph_role)
    return {
        "group_id": _text(group.get("group_id")) or f"{section_type or 'section'}-g{index}",
        "paragraph_role": paragraph_role,
        "paragraph_claim": paragraph_claim,
        "fact_ids": fact_ids,
        "source_ids": source_ids,
        "write_focus": _reader_clean_text(group.get("write_focus") or group.get("use_for") or paragraph_claim),
        "contrast_or_boundary": _reader_clean_text(
            group.get("contrast_or_boundary")
            or group.get("limitation")
            or "本段只承担当前章节的论证目的，不重复其他章节。"
        ),
        "must_not_repeat": _reader_clean_text(
            group.get("must_not_repeat")
            or "不要把本段事实改写成其他章节的结论，也不要新增 brief 之外的事实。"
        ),
        "fact_snapshots": fact_snapshots,
    }


def build_report_writer_brief(materials: Dict[str, Any]) -> Dict[str, Any]:
    """Compile source-bound report materials into a paragraph-group writer brief.

    The compiler only maps deterministic catalog facts into section routes. It
    does not create new incident facts, entities, IOCs, timestamps, stages, or
    judgments.
    """

    materials = _as_dict(materials)
    plan = _as_dict(materials.get("report_plan"))
    sections = [_as_dict(section) for section in _as_list(plan.get("sections"))]
    brief_by_type = _brief_by_section(materials)
    source_by_id = _source_index(materials)
    source_fact_catalog = [_as_dict(item) for item in _as_list(materials.get("source_fact_catalog"))]
    fact_by_id, fact_by_source_id = source_fact_indexes(source_fact_catalog)

    fact_catalog_by_id: Dict[str, Dict[str, Any]] = {}
    for source_fact in source_fact_catalog:
        entry = _catalog_entry_from_source_fact(source_fact, source_by_id)
        fact_id = _text(entry.get("fact_id"))
        if fact_id:
            fact_catalog_by_id[fact_id] = entry

    fact_ids_by_section: Dict[str, List[str]] = {}
    routes_by_section: Dict[str, List[Dict[str, Any]]] = {}
    used_source_ids: List[str] = []

    for section in sections:
        section_type = _text(section.get("section_type"))
        if not section_type:
            continue
        section_brief = brief_by_type.get(section_type) or {}
        fallback_source_ids = (
            _source_ids(section_brief.get("source_ids"))
            or _source_ids(section.get("source_ids"))
        )
        paragraph_plan: List[Dict[str, Any]] = []
        section_fact_ids: List[str] = []

        paragraph_groups = [_as_dict(item) for item in _as_list(section_brief.get("paragraph_groups"))]
        for idx, group in enumerate(paragraph_groups, start=1):
            fact_ids, source_ids = _resolve_fact_refs(group, fact_by_id, fact_by_source_id)
            fact_snapshots = _route_fact_snapshots(fact_ids, fact_catalog_by_id)
            if not fact_snapshots:
                continue
            paragraph_plan.append(
                _paragraph_plan_from_group(
                    group,
                    section_type=section_type,
                    index=idx,
                    fact_ids=fact_ids,
                    source_ids=source_ids,
                    fact_snapshots=fact_snapshots,
                )
            )
            section_fact_ids.extend(fact_ids)
            used_source_ids.extend(source_ids)

        if not paragraph_plan:
            key_facts = [_as_dict(item) for item in _as_list(section_brief.get("key_facts"))]
            for idx, fact in enumerate(key_facts, start=1):
                fact_ids, source_ids = _resolve_fact_refs(
                    fact,
                    fact_by_id,
                    fact_by_source_id,
                    fallback_source_ids=fallback_source_ids,
                )
                fact_snapshots = _route_fact_snapshots(fact_ids, fact_catalog_by_id)
                if not fact_snapshots:
                    continue
                paragraph_plan.append(
                    _paragraph_plan_from_group(
                        {
                            "group_id": f"{section_type}-fact-{idx}",
                            "paragraph_role": fact.get("fact_role") or fact.get("role") or "章节事实",
                            "paragraph_claim": fact.get("why_it_matters") or fact.get("use_for") or fact.get("fact_role"),
                            "write_focus": fact.get("use_for") or "使用 deterministic fact snapshot 展开该事实的判断作用。",
                            "contrast_or_boundary": fact.get("limitation"),
                            "must_not_repeat": "这是 key_facts 兼容回退生成的段落计划；不要扩展到 brief 外的事实。",
                        },
                        section_type=section_type,
                        index=idx,
                        fact_ids=fact_ids,
                        source_ids=source_ids,
                        fact_snapshots=fact_snapshots,
                    )
                )
                section_fact_ids.extend(fact_ids)
                used_source_ids.extend(source_ids)

        fact_ids_by_section[section_type] = _dedupe(section_fact_ids)
        routes_by_section[section_type] = paragraph_plan

    fact_catalog = list(fact_catalog_by_id.values())

    section_fact_map: List[Dict[str, Any]] = []
    complex_section_types = {
        "timeline_process",
        "evidence_judgment",
        "relationship_scope",
        "counterevidence_limits",
        "impact_assessment",
        "topology_path_analysis",
    }
    for section in sections:
        section_type = _text(section.get("section_type"))
        allowed_fact_ids = fact_ids_by_section.get(section_type, [])
        paragraph_plan = routes_by_section.get(section_type, [])
        roles = _dedupe(
            route.get("paragraph_role")
            for route in paragraph_plan
            if _text(route.get("paragraph_role"))
        )
        is_complex = section_type in complex_section_types
        paragraph_target = len(paragraph_plan) if paragraph_plan else (
            3 if is_complex and len(allowed_fact_ids) >= 3 else (2 if len(allowed_fact_ids) >= 2 else 1)
        )
        section_fact_map.append(
            {
                "section_type": section_type,
                "title": _text(section.get("title")),
                "question_to_answer": _reader_clean_text(section.get("question_to_answer")),
                "mode": _text(section.get("mode")),
                "must_include": _dedupe(_reader_clean_text(item) for item in _as_list(section.get("must_include"))),
                "must_not_repeat": _dedupe(_reader_clean_text(item) for item in _as_list(section.get("must_not_repeat"))),
                "boundary_notes": _dedupe(_reader_clean_text(item) for item in _as_list(section.get("boundary_notes"))),
                "source_ids": _source_ids(section.get("source_ids")),
                "allowed_fact_ids": allowed_fact_ids,
                "fact_roles_to_cover": roles,
                "minimum_fact_count_to_cover": min(3 if is_complex else 2, len(allowed_fact_ids)),
                "minimum_distinct_fact_roles": min(3 if is_complex else 2, len(roles)),
                "paragraph_target": paragraph_target,
                "complex_section": is_complex,
                "paragraph_plan": paragraph_plan,
            }
        )
        used_source_ids.extend(_source_ids(section.get("source_ids")))

    candidate_fact_ids = [fact["fact_id"] for fact in fact_catalog if fact.get("candidate_or_boundary")]
    external_fact_ids = [
        fact["fact_id"]
        for fact in fact_catalog
        if "核心外部基础设施" in _text(fact.get("reader_fact_text"))
        or "外部基础设施" in _text(fact.get("reporting_focus"))
    ]
    action_fact_ids = [
        fact["fact_id"]
        for fact in fact_catalog
        if fact.get("fact_type") == "action"
    ]

    writing_constraints = {
        "global_rules": [
            "每节只能使用 section_fact_map.allowed_fact_ids 指定的事实；不要从其他章节借事实来填充。",
            "候选事件、待确认对象和 candidate_or_boundary=true 的事实只能写入候选范围、扩线线索或边界说明，不能写成已确认传播或已确认受影响。",
            "外部基础设施只能写成外联判断、关联基础设施或封禁排查对象，不能写成受影响资产。",
            "action fact 只代表建议动作，不能改写成已经观测到的事实。",
            "如果 exact_fact_text 出现 rundll32.exe、loader DLL、PsExec、WMI，只能保守写成可疑执行线索、DLL 加载线索或潜在横向推进；不要写成已确认恶意软件加载器执行或攻击者已控制。",
        ],
        "candidate_or_boundary_fact_ids": candidate_fact_ids,
        "external_infrastructure_fact_ids": external_fact_ids,
        "action_fact_ids": action_fact_ids,
    }

    compact_sources = []
    for source_id in _dedupe(used_source_ids):
        source = source_by_id.get(source_id) or {}
        compact_sources.append(
            {
                "source_id": source_id,
                "source_type": _text(source.get("source_type")),
                "status": _text(source.get("status")),
            }
        )

    return {
        "schema_version": "report-writer-brief-v1",
        "source_material_schema_version": _text(materials.get("schema_version")),
        "header_packet": _build_header_packet(materials),
        "fact_catalog": fact_catalog,
        "section_fact_map": section_fact_map,
        "writing_constraints": writing_constraints,
        "used_source_inventory": compact_sources,
        "appendix_note": _reader_clean_text(plan.get("appendix_note")),
    }


def _strip_disallowed_subheadings(markdown: str) -> str:
    lines: List[str] = []
    previous_blank = False
    for line in str(markdown or "").splitlines():
        if re.match(r"^#{3,}\s+", line.strip()):
            if lines and not previous_blank:
                lines.append("")
                previous_blank = True
            continue
        is_blank = not line.strip()
        if is_blank and previous_blank:
            continue
        lines.append(line)
        previous_blank = is_blank
    return "\n".join(lines).strip()


def _paragraphs(markdown: str) -> List[str]:
    return [part.strip() for part in re.split(r"\n\s*\n", str(markdown or "").strip()) if part.strip()]


def _split_sentences(text: str) -> List[str]:
    cleaned = re.sub(r"\s*\n+\s*", " ", str(text or "").strip())
    if not cleaned:
        return []
    parts = re.findall(r"[^。！？!?]+[。！？!?]?", cleaned)
    return [part.strip() for part in parts if part.strip()]


def _expand_dense_sections(markdown: str, writer_brief: Dict[str, Any]) -> str:
    target_by_title: Dict[str, int] = {}
    for section in _as_list(_as_dict(writer_brief).get("section_fact_map")):
        entry = _as_dict(section)
        section_type = _text(entry.get("section_type"))
        title = _text(entry.get("title"))
        target = int(entry.get("paragraph_target") or 0)
        if title and section_type in {"evidence_judgment", "relationship_scope", "counterevidence_limits"} and target >= 3:
            target_by_title[title] = target
    if not target_by_title:
        return markdown

    result: List[str] = []
    current_title = ""
    current_lines: List[str] = []

    def flush_section() -> None:
        nonlocal current_title, current_lines
        if not current_title:
            result.extend(current_lines)
            current_lines = []
            return
        body = "\n".join(current_lines).strip()
        target = target_by_title.get(current_title, 0)
        if target and len(_paragraphs(body)) < target:
            sentences = _split_sentences(body)
            if len(sentences) >= target:
                grouped = sentences[: target - 1] + [" ".join(sentences[target - 1 :]).strip()]
                body = "\n\n".join(part for part in grouped if part)
        if result and result[-1].strip():
            result.append("")
        result.append(f"## {current_title}")
        if body:
            result.append("")
            result.extend(body.splitlines())
        current_title = ""
        current_lines = []

    for line in str(markdown or "").splitlines():
        if line.startswith("## "):
            flush_section()
            current_title = line[3:].strip()
            current_lines = []
        else:
            current_lines.append(line)
    flush_section()
    return "\n".join(result).strip()


def _edit_distance_leq_one(left: str, right: str) -> bool:
    if left == right:
        return True
    if abs(len(left) - len(right)) > 1:
        return False
    if len(left) == len(right):
        return sum(1 for a, b in zip(left, right) if a != b) <= 1
    if len(left) < len(right):
        left, right = right, left
    i = 0
    j = 0
    skipped = False
    while i < len(left) and j < len(right):
        if left[i] == right[j]:
            i += 1
            j += 1
            continue
        if skipped:
            return False
        skipped = True
        i += 1
    return True


def _guard_generated_iocs(markdown: str, writer_brief: Dict[str, Any]) -> str:
    """Correct one-character IP slips against the deterministic brief.

    The writer is allowed to paraphrase prose, but it must not invent new IOCs.
    When a generated IP is not present in the brief and is a unique edit-distance
    one typo of a known IP, normalize it back to the known value.
    """

    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    allowed_ips = set(re.findall(ip_pattern, _json(writer_brief)))
    if not allowed_ips:
        return markdown
    generated_ips = set(re.findall(ip_pattern, markdown))
    normalized = markdown
    for ip in sorted(generated_ips - allowed_ips, key=len, reverse=True):
        candidates = [candidate for candidate in allowed_ips if _edit_distance_leq_one(ip, candidate)]
        if len(candidates) == 1:
            normalized = normalized.replace(ip, candidates[0])
    return normalized


def _normalize_writer_markdown(markdown: str, writer_brief: Dict[str, Any]) -> str:
    stripped = _strip_disallowed_subheadings(markdown)
    expanded = stripped
    replacements = {
        "这可能是恶意软件执行的一部分": "这可能是可疑执行链的一部分",
        "恶意 JA4": "可疑 JA4",
        "恶意 JA4 通信指纹": "可疑 JA4 通信指纹",
        "可能存在恶意活动": "可能存在可疑活动",
        "恶意软件执行": "可疑执行活动",
        "实际的恶意活动": "实际异常活动",
        "实际恶意活动": "实际异常活动",
        "背景事件包括：": "背景或候选边界事件包括：",
        "这些背景事件": "这些背景或候选边界事件",
        "这些基础设施是否为真实受影响对象": "这些基础设施是否属于共享基础设施或当前事件相关基础设施",
    }
    for source, target in replacements.items():
        expanded = expanded.replace(source, target)
    expanded = re.sub(r"\bpivot\b", "关键关联指标", expanded, flags=re.IGNORECASE)
    expanded = expanded.replace("dst_ip", "目标 IP")
    expanded = _guard_generated_iocs(expanded, writer_brief)
    return expanded.strip()


REPORT_AGENT_WRITER_SYSTEM_PROMPT = """你是 Trace-Agent 的安全事件报告 writer。你只基于 report_writer_brief 写中文 Markdown 正文，读者是运维人员和安全运营协同对象。

输入契约：
- report_writer_brief 是确定性编译产物，没有新增事实。你只能使用 header_packet、fact_catalog、section_fact_map、writing_constraints、appendix_note、used_source_inventory。
- Fact Catalog 是事实库；Section Fact Map 是章节取材权限表。每节只能使用本节 allowed_fact_ids 对应的 fact，不能从其他章节借事实。
- fact_catalog 保存完整原子事实；section_fact_map.paragraph_plan 是段落组计划。每个 plan item 包含 group_id、paragraph_role、paragraph_claim、write_focus、contrast_or_boundary、must_not_repeat 和 fact_snapshots。
- fact_snapshots 是从 fact_catalog 确定性复制的事实快照；它可以包含 fact_text、exact_fact_text、time、asset、objects、status、candidate_or_boundary。它不是新增事实。
- 不得新增 brief 中没有的新 IOC、新资产、新时间、新动作、新阶段或新结论。

写作流程：
1. 先写 `# 首页摘要`，只使用 header_packet，固定输出 8 行：结论、严重度、研判把握、已确认范围、最强证据、关键缺口、立即动作、一句话结论。其中严重度必须等于 header_packet.severity，研判把握必须等于 header_packet.confidence。
2. 然后严格按 section_fact_map 顺序输出 `## {{title}}`，标题必须逐字使用 title，不得增删、改名或重排。
3. 对每个章节，按 paragraph_plan 顺序写。每个 paragraph_plan item 对应一个自然段，段落必须覆盖该 item 的全部 fact_snapshots。
4. 每个自然段围绕 paragraph_claim 的意图组织，但不要逐字复制 paragraph_claim、write_focus 或 contrast_or_boundary；正文要直接从 fact_snapshots 展开事实、判断作用和边界。
5. 同一 fact 可以在不同章节出现，但只能服务不同论证目的：timeline_process 写推进，evidence_judgment 写判断作用，relationship_scope 写范围边界，counterevidence_limits 写不能写强结论的原因。
6. 如果 fact_snapshots 有 time、asset、objects、exact_fact_text，优先点名其中的具体资产、域名/IP、时间或缺口，避免泛泛写“主要证据包括”。question_to_answer 只用于理解任务，禁止把问句原文写进正文。

段落硬约束：
- 正文目标 2400 到 4200 中文字。复杂章节宁可写厚，不要压缩成摘要。
- complex_section=true 的章节必须至少写 paragraph_target 个自然段，段落之间用空行分开。
- evidence_judgment、relationship_scope、counterevidence_limits 如果 paragraph_plan 有 3 条，必须一条 paragraph_plan 写一个自然段，不能把三个 paragraph group 合并成一段总括。
- evidence_judgment、relationship_scope、counterevidence_limits 禁止使用项目符号或编号清单，必须写成连续中文段落。
- timeline_process 必须按 paragraph_plan 全量覆盖组内每个时间节点，包括 candidate_or_boundary=true 的候选节点；可以写成连续时间线或项目符号，但不能只概括前几条 confirmed 事实。凡 fact_snapshots 中出现的时间戳必须在本节正文出现。
- relationship_scope 如果 paragraph_plan 包含候选事件、候选对象或外部基础设施，必须逐类点名确认范围、候选范围、外部基础设施和不能并入确认范围的原因。
- conclusion_actions 可以按“立即处置、短期核查、持续复核”组织，但 action fact 只能写成建议，不能写成已观测事实。

保守边界：
- writing_constraints.candidate_or_boundary_fact_ids 对应的事实只能写成候选范围、待验证线索、反证或缺口边界，不能写成已确认传播或已确认受影响。
- 外部基础设施只能写成外联判断、关联基础设施或封禁排查对象，不能写成受影响资产。
- PsExec、WMI、remote service creation 默认写成“横向移动线索”或“潜在横向推进”，不要写成“已证实横向移动”，除非 exact_fact_text 明确给出强结论。
- rundll32.exe、loader DLL 只能保守写成“可疑执行线索”或“DLL 加载线索”，不要写成“恶意软件已存在”“恶意软件加载器已确认”“攻击者已控制”。
- “持久化”只能出现在后续核查建议中，除非 fact_catalog 明确给出已观测持久化事实。
- 如果 header_packet.conclusion 包含“复核”，正文不要写成已经完成定性的“确认事件成立”；可以写成“足以支撑事件级复核”。

语言与格式：
- 最终报告必须是中文；英文 source summary 要转述为中文，但域名、IP、资产名、进程名、文件名、时间、JA3/JA4 值必须逐字保留。
- 时间戳必须保留 brief 原格式，例如 `2026-07-14 01:04:00 UTC`，不要改成中文日期。
- 不要暴露 source_ids、section_type、fact_id、observation_id、工具名、workflow、reviewer、selector、readiness、material loop 等内部术语。
- 不要原样输出 pivot、dst_ip、seed alert；应写成“关键关联指标”“目标 IP”“种子告警”。
- 不要用“这些事实说明……”“这些节点说明……”“主要证据包括……”“可疑活动”“横向移动到某资产”“当前结论被一些缺口限制……”这类低分辨率总括替代 source_fact_catalog 中的原子事实展开。
- 正文末尾如果 appendix_note 存在，可自然提示附录；不要新增 report_plan 以外的章节。
- 最终只返回 Markdown 正文，不要返回 JSON 或解释。"""


def render_polished_body_from_writer_brief(llm: Any, writer_brief: Dict[str, Any]) -> str:
    from langchain_core.prompts import ChatPromptTemplate

    prompt = ChatPromptTemplate.from_messages(
        [
            ("system", REPORT_AGENT_WRITER_SYSTEM_PROMPT),
            (
                "user",
                "请仅基于以下 report_writer_brief 生成完整 Markdown 正文。\n"
                "硬性要求：正文必须按 section_fact_map 全部展开；每节只能使用 allowed_fact_ids；禁止输出 question_to_answer 原句；complex_section=true 的章节按 paragraph_target 写够段落；timeline_process 必须覆盖该节全部 paragraph_plan.fact_snapshots 中的时间戳，不能省略候选节点；evidence_judgment、relationship_scope、counterevidence_limits 至少覆盖该节 3 条 allowed facts；如果 fact_roles_to_cover 足够多，还要覆盖不同事实角色；总长度目标 2400 到 4200 中文字。\n"
                "段落硬约束：每个 paragraph_plan item 写成一个自然段，段落之间用空行分开；段落要覆盖该 item 的全部 fact_snapshots，并围绕 paragraph_claim / write_focus / contrast_or_boundary 组织，不要退回一条 fact 一段，也不要把多个 paragraph group 合并成摘要。\n"
                "{writer_brief_json}",
            ),
        ]
    )
    writer = llm.bind(max_tokens=2800, temperature=0) if hasattr(llm, "bind") else llm
    response = invoke_llm_with_trace(
        writer,
        prompt.format_messages(writer_brief_json=_json(writer_brief)),
        role="report_agent_writer",
    )
    return _normalize_writer_markdown(str(getattr(response, "content", "") or "").strip(), writer_brief)


def render_polished_body_from_materials(llm: Any, materials: Dict[str, Any]) -> str:
    writer_brief = build_report_writer_brief(materials)
    return render_polished_body_from_writer_brief(llm, writer_brief)
