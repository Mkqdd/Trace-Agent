from __future__ import annotations

import json
import os
import re
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Tuple

from ..services.api.llm_observability import invoke_llm_with_trace
from .evidence_graph import build_graph_writer_brief
from .report_agent_tools import build_source_fact_catalog, source_fact_indexes
from .report_text_quality import (
    is_low_information_evidence_label,
    is_meta_material_text as _is_meta_conclusion_text,
)


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


def _is_low_information_evidence_text(value: Any) -> bool:
    text = _reader_clean_text(value)
    if not text:
        return True
    if is_low_information_evidence_label(text):
        return True
    return len(text) <= 3


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
            "如果 exact_fact_text 只提供执行、远程操作、工具调用或载荷加载线索，只能按证据强度保守写成可疑执行线索、潜在远程操作或范围推进线索；不要升级成已确认恶意软件存在、已确认横向移动或攻击者已控制，除非事实文本本身明确支持。",
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


def _compact_prompt_fact_snapshot(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    entry = _as_dict(snapshot)
    compact = {
        "fact_id": _text(entry.get("fact_id")),
        "fact_type": _text(entry.get("fact_type")),
        "status": _text(entry.get("status")),
        "classification": _text(entry.get("classification")),
        "time": _text(entry.get("time")),
        "asset": _text(entry.get("asset")),
        "objects": _as_list(entry.get("objects"))[:6],
        "fact_text": _reader_clean_text(entry.get("fact_text") or entry.get("reader_fact_text") or entry.get("exact_fact_text")),
        "reporting_focus": _reader_clean_text(entry.get("reporting_focus")),
        "candidate_or_boundary": bool(entry.get("candidate_or_boundary")),
    }
    return {key: value for key, value in compact.items() if value not in ["", [], {}]}


def build_report_writer_prompt_brief(writer_brief: Dict[str, Any]) -> Dict[str, Any]:
    """Build the compact brief sent to the LLM writer.

    The full writer brief remains the debug artifact. The prompt brief keeps
    only section-routed fact snapshots so the writer sees the facts it is
    allowed to expand without paying for a duplicate full catalog.
    """

    source = _as_dict(writer_brief)
    used_fact_ids: List[str] = []
    section_fact_map: List[Dict[str, Any]] = []
    for raw_section in _as_list(source.get("section_fact_map")):
        section = _as_dict(raw_section)
        paragraph_plan: List[Dict[str, Any]] = []
        section_fact_ids: List[str] = []
        for raw_plan in _as_list(section.get("paragraph_plan")):
            plan = _as_dict(raw_plan)
            snapshots = [
                _compact_prompt_fact_snapshot(_as_dict(snapshot))
                for snapshot in _as_list(plan.get("fact_snapshots"))
            ]
            snapshots = [snapshot for snapshot in snapshots if _text(snapshot.get("fact_id"))]
            if not snapshots:
                continue
            fact_ids = _dedupe(
                _text(snapshot.get("fact_id"))
                for snapshot in snapshots
                if _text(snapshot.get("fact_id"))
            )
            section_fact_ids.extend(fact_ids)
            used_fact_ids.extend(fact_ids)
            paragraph_plan.append(
                {
                    "group_id": _text(plan.get("group_id")),
                    "paragraph_role": _reader_clean_text(plan.get("paragraph_role")),
                    "paragraph_claim": _reader_clean_text(plan.get("paragraph_claim")),
                    "fact_ids": fact_ids,
                    "write_focus": _reader_clean_text(plan.get("write_focus")),
                    "contrast_or_boundary": _reader_clean_text(plan.get("contrast_or_boundary")),
                    "must_not_repeat": _reader_clean_text(plan.get("must_not_repeat")),
                    "fact_snapshots": snapshots,
                }
            )
        section_fact_map.append(
            {
                "section_type": _text(section.get("section_type")),
                "title": _text(section.get("title")),
                "question_to_answer": _reader_clean_text(section.get("question_to_answer")),
                "mode": _text(section.get("mode")),
                "must_include": _as_list(section.get("must_include"))[:4],
                "must_not_repeat": _as_list(section.get("must_not_repeat"))[:4],
                "boundary_notes": _as_list(section.get("boundary_notes"))[:4],
                "allowed_fact_ids": _dedupe(section_fact_ids),
                "fact_roles_to_cover": _as_list(section.get("fact_roles_to_cover"))[:6],
                "minimum_fact_count_to_cover": section.get("minimum_fact_count_to_cover"),
                "minimum_distinct_fact_roles": section.get("minimum_distinct_fact_roles"),
                "paragraph_target": section.get("paragraph_target"),
                "complex_section": bool(section.get("complex_section")),
                "paragraph_plan": paragraph_plan,
            }
        )

    used_fact_id_set = set(_dedupe(used_fact_ids))
    constraints = _as_dict(source.get("writing_constraints"))
    compact_constraints = {
        "global_rules": _as_list(constraints.get("global_rules")),
        "candidate_or_boundary_fact_ids": [
            fact_id
            for fact_id in _as_list(constraints.get("candidate_or_boundary_fact_ids"))
            if _text(fact_id) in used_fact_id_set
        ],
        "external_infrastructure_fact_ids": [
            fact_id
            for fact_id in _as_list(constraints.get("external_infrastructure_fact_ids"))
            if _text(fact_id) in used_fact_id_set
        ],
        "action_fact_ids": [
            fact_id
            for fact_id in _as_list(constraints.get("action_fact_ids"))
            if _text(fact_id) in used_fact_id_set
        ],
    }

    return {
        "schema_version": "report-writer-prompt-brief-v1",
        "source_brief_schema_version": _text(source.get("schema_version")),
        "source_material_schema_version": _text(source.get("source_material_schema_version")),
        "header_packet": _as_dict(source.get("header_packet")),
        "section_fact_map": section_fact_map,
        "writing_constraints": compact_constraints,
        "appendix_note": _reader_clean_text(source.get("appendix_note")),
    }


def build_report_writer_section_prompt_brief(writer_brief: Dict[str, Any], section_type: str) -> Dict[str, Any]:
    """Build a single-section writer input from the deterministic writer brief."""

    prompt_brief = build_report_writer_prompt_brief(writer_brief)
    sections = [_as_dict(item) for item in _as_list(prompt_brief.get("section_fact_map"))]
    selected_type = _text(section_type)
    selected_index = -1
    selected_section: Dict[str, Any] = {}
    for index, section in enumerate(sections):
        if _text(section.get("section_type")) == selected_type:
            selected_index = index
            selected_section = section
            break
    if not selected_section:
        selected_section = {
            "section_type": selected_type,
            "title": selected_type or "未命名章节",
            "paragraph_plan": [],
            "allowed_fact_ids": [],
        }
    return {
        "schema_version": "report-writer-section-prompt-brief-v1",
        "source_brief_schema_version": _text(prompt_brief.get("source_brief_schema_version")),
        "source_material_schema_version": _text(prompt_brief.get("source_material_schema_version")),
        "header_packet": _as_dict(prompt_brief.get("header_packet")),
        "all_section_titles": [_text(section.get("title")) for section in sections if _text(section.get("title"))],
        "section_index": selected_index,
        "section_count": len(sections),
        "section": selected_section,
        "writing_constraints": _as_dict(prompt_brief.get("writing_constraints")),
        "appendix_note": _reader_clean_text(prompt_brief.get("appendix_note")),
    }


def _writer_section_mode_enabled() -> bool:
    value = str(os.getenv("INCIDENT_AGENT_WRITER_SECTION_MODE") or "").strip().lower()
    return value in {"1", "true", "yes", "on", "section", "sections", "per_section", "per-section"}


def _ensure_header_markdown(markdown: str) -> str:
    text = str(markdown or "").strip()
    if not text:
        return "# 首页摘要\n\n**结论**：未评估"
    if "\n## " in text:
        text = text.split("\n## ", 1)[0].strip()
    if text.startswith("# 首页摘要"):
        return text
    text = re.sub(r"^#+\s*首页摘要\s*", "", text).strip()
    return f"# 首页摘要\n\n{text}".strip()


def _extract_single_section_markdown(markdown: str, title: str) -> str:
    text = str(markdown or "").strip()
    section_title = _text(title) or "未命名章节"
    if not text:
        return f"## {section_title}\n\n当前材料不足，无法进一步展开该章节。"

    lines = text.splitlines()
    start_index = -1
    for index, line in enumerate(lines):
        if line.strip() == f"## {section_title}":
            start_index = index
            break
    if start_index >= 0:
        selected = [lines[start_index]]
        for line in lines[start_index + 1 :]:
            stripped = line.strip()
            if stripped.startswith("# ") or stripped.startswith("## "):
                break
            selected.append(line)
        return "\n".join(selected).strip()

    body_lines = [line for line in lines if not re.match(r"^#{1,6}\s+", line.strip())]
    body = "\n".join(body_lines).strip() or text
    return f"## {section_title}\n\n{body}".strip()


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


def _restore_exact_timestamps(markdown: str, writer_brief: Dict[str, Any]) -> str:
    """Restore minute-only timestamps when the brief has a unique exact time.

    Writers often compress `YYYY-MM-DD HH:MM:SS UTC` to minute precision. That
    is readable, but it creates avoidable fact-card drift. The repair is safe
    only when the deterministic brief contains exactly one timestamp for that
    minute.
    """

    exact_times = set(re.findall(r"\b\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC\b", _json(writer_brief)))
    if not exact_times:
        return markdown
    minute_to_exact: Dict[str, set[str]] = {}
    bare_times = {exact[11:19] for exact in exact_times}
    minute_second_to_bare: Dict[str, set[str]] = {}
    for exact in exact_times:
        minute = f"{exact[:16]} UTC"
        minute_to_exact.setdefault(minute, set()).add(exact)
        bare = exact[11:19]
        minute_second_to_bare.setdefault(bare[3:], set()).add(bare)
    normalized = markdown
    for minute, exact_values in sorted(minute_to_exact.items(), key=lambda item: len(item[0]), reverse=True):
        if len(exact_values) != 1:
            continue
        exact = next(iter(exact_values))
        normalized = normalized.replace(minute, exact)
    for match in sorted(set(re.findall(r"(?<!\d)(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?!\d)", normalized))):
        if match in bare_times:
            continue
        candidates = minute_second_to_bare.get(match[3:]) or set()
        if len(candidates) == 1:
            normalized = normalized.replace(match, next(iter(candidates)))
    return normalized


def _remove_unsupported_lookback_windows(markdown: str, writer_brief: Dict[str, Any]) -> str:
    """Avoid invented exact start times in action-oriented lookback guidance."""

    exact_times = {
        _restore_exact_timestamps(_normalize_time, writer_brief)
        for _normalize_time in re.findall(r"\b\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?: UTC)?\b", _json(writer_brief))
    }
    exact_times = {time if time.endswith(" UTC") else f"{time} UTC" for time in exact_times}

    def normalize_token(time_text: str, *, reference_date: str = "") -> str:
        cleaned = time_text.strip().strip("`").strip()
        if not cleaned:
            return ""
        if re.match(r"^\d{2}:\d{2}:\d{2}(?: UTC)?$", cleaned) and reference_date:
            cleaned = f"{reference_date} {cleaned}"
        if not cleaned.endswith(" UTC"):
            cleaned = f"{cleaned} UTC"
        return cleaned

    def replace_range(match: re.Match[str]) -> str:
        start = normalize_token(match.group("start"))
        reference_date = start[:10] if re.match(r"^\d{4}-\d{2}-\d{2}", start) else ""
        end = normalize_token(match.group("end"), reference_date=reference_date)
        if start in exact_times and end in exact_times:
            return match.group(0)
        suffix = match.group("suffix") or ""
        return "当前调查窗口内" if suffix in {"间", "窗口内", "时段", "范围内"} else "当前调查窗口"

    time_range = re.compile(
        r"`?(?P<start>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?: UTC)?)`?"
        r"\s*至\s*"
        r"`?(?P<end>(?:\d{4}-\d{2}-\d{2} )?\d{2}:\d{2}:\d{2}(?: UTC)?)`?"
        r"\s*(?P<suffix>间|窗口内|时段|范围内)?"
    )

    def replace_parenthetical(match: re.Match[str]) -> str:
        time_text = match.group("time")
        normalized_time = time_text if time_text.endswith(" UTC") else f"{time_text} UTC"
        if normalized_time in exact_times:
            return match.group(0)
        return "当前调查窗口"

    normalized = re.sub(
        r"分析窗口（(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?: UTC)?)\s*至当前）",
        replace_parenthetical,
        markdown,
    )
    normalized = re.sub(
        r"回溯\s+(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?: UTC)?)\s*至当前(?:时段)?",
        lambda match: "回溯" + (
            f" {match.group('time')} 至当前"
            if (match.group("time") if match.group("time").endswith(" UTC") else f"{match.group('time')} UTC") in exact_times
            else "当前调查窗口"
        ),
        normalized,
    )
    normalized = time_range.sub(replace_range, normalized)
    return normalized


def _restore_beijing_times_to_source_utc(markdown: str, writer_brief: Dict[str, Any]) -> str:
    """Undo writer-side Beijing-time conversions when the UTC source is unique."""

    exact_times = set(re.findall(r"\b\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC\b", _json(writer_brief)))
    if not exact_times or "北京时间" not in markdown:
        return markdown

    def replace_zh(match: re.Match[str]) -> str:
        try:
            second = int(match.group("second") or "0")
            local_time = datetime(
                int(match.group("year")),
                int(match.group("month")),
                int(match.group("day")),
                int(match.group("hour")),
                int(match.group("minute")),
                second,
            )
        except ValueError:
            return match.group(0)
        utc_time = local_time - timedelta(hours=8)
        candidate = utc_time.strftime("%Y-%m-%d %H:%M:%S UTC")
        return candidate if candidate in exact_times else match.group(0)

    normalized = re.sub(
        r"北京时间\s*(?P<year>\d{4})\s*年\s*(?P<month>\d{1,2})\s*月\s*(?P<day>\d{1,2})\s*日"
        r"(?:凌晨|早上|上午|中午|下午|傍晚|晚上)?\s*(?P<hour>\d{1,2}):(?P<minute>\d{2})(?::(?P<second>\d{2}))?",
        replace_zh,
        markdown,
    )
    normalized = re.sub(
        r"北京时间\s*(?P<year>\d{4})-(?P<month>\d{1,2})-(?P<day>\d{1,2})\s+"
        r"(?P<hour>\d{1,2}):(?P<minute>\d{2})(?::(?P<second>\d{2}))?",
        replace_zh,
        normalized,
    )
    return normalized


def _normalize_markdown_spacing(markdown: str) -> str:
    normalized = markdown
    for char in ("\u2010", "\u2011", "\u2012", "\u2013", "\u2014", "\u2212"):
        normalized = normalized.replace(char, "-")
    # Keep inline code readable when the model attaches Chinese text directly
    # to the backtick span.
    normalized = re.sub(r"([\u4e00-\u9fff])(`[^`\n]+`)", r"\1 \2", normalized)
    normalized = re.sub(r"(`[^`\n]+`)([\u4e00-\u9fff])", r"\1 \2", normalized)
    normalized = re.sub(r"[ \t]+([，。；：！？、])", r"\1", normalized)
    normalized = re.sub(r"([（【])\s+", r"\1", normalized)
    normalized = re.sub(r"\s+([）】])", r"\1", normalized)
    return normalized


def _normalize_writer_markdown(markdown: str, writer_brief: Dict[str, Any]) -> str:
    stripped = _strip_disallowed_subheadings(markdown)
    expanded = stripped
    replacements = {
        "这可能是恶意软件执行的一部分": "这可能是可疑执行链的一部分",
        "暴露于恶意活动之中": "出现可疑外联活动",
        "恶意活动已经扩散到了多个资产": "异常线索已经扩展到多个资产",
        "恶意活动已经扩散": "异常线索已经扩展",
        "恶意活动的持续性": "可疑活动的连续性",
        "恶意活动": "可疑活动",
        "证实了横向移动的存在": "提示存在横向移动线索",
        "证实横向移动的存在": "提示存在横向移动线索",
        "证实了横向移动": "提示存在横向移动线索",
        "证实横向移动": "提示存在横向移动线索",
        "已证实横向移动": "提示存在横向移动线索",
        "恶意 JA4": "可疑 JA4",
        "恶意 JA4 通信指纹": "可疑 JA4 通信指纹",
        "可能存在恶意活动": "可能存在可疑活动",
        "恶意软件执行": "可疑执行活动",
        "恶意软件加载器": "可疑加载器",
        "恶意特征明确": "可疑特征明确",
        "已确认恶意的网络行为": "已确认可疑的网络行为",
        "攻击者控制域": "可疑控制域",
        "实际的恶意活动": "实际异常活动",
        "实际恶意活动": "实际异常活动",
        "被成功入侵": "被纳入确认受影响范围",
        "成功入侵": "纳入确认受影响范围",
        "攻击者控制链上的新节点": "需要隔离和取证的受影响节点",
        "攻击者控制链上的节点": "需要隔离和取证的受影响节点",
        "攻击者已在最少": "已观察到至少",
        "已观察到最少": "已观察到至少",
        "上建立对": "出现对",
        "恶意 TLS": "可疑 TLS",
        "恶意 TLS 信标": "可疑 TLS 信标",
        "确认第二台主机受控": "确认第二台主机受影响",
        "第二台主机受控": "第二台主机受影响",
        "已确认受控": "已确认受影响",
        "受控主机": "受影响主机",
        "受控节点": "受影响节点",
        "受控范围": "受影响范围",
        "受控回连": "可疑回连",
        "受控的怀疑": "受影响的怀疑",
        "攻击者已经": "现有证据显示",
        "攻击者已在": "已观察到",
        "攻击者已": "已观察到",
        "攻击者控制的存储": "可疑存储",
        "受控外传": "可疑外传",
        "确认横向移动": "确认存在横向推进线索",
        "已确认横向移动": "已确认存在横向推进线索",
        "成功将活动范围扩展至": "使调查确认范围扩展至",
        "成功将活动范围扩展到": "使调查确认范围扩展到",
        "横向移动（PsExec）": "PsExec 远程服务创建线索",
        "横向移动（WMI）": "WMI 远程进程创建线索",
        "loader DLL": "DLL 加载线索",
        "Loader DLL": "DLL 加载线索",
        "rundll32 加载器执行": "rundll32 可疑 DLL 加载线索",
        "加载器执行": "可疑加载线索",
        "可疑 `rundll32.exe` 可疑加载线索": "`rundll32.exe` 可疑 DLL 加载线索",
        "可疑 rundll32 可疑 DLL 加载线索": "rundll32 可疑 DLL 加载线索",
        "恶意基础设施": "关联外部基础设施",
        "恶意 C2": "可疑 C2",
        "背景事件包括：": "背景或候选边界事件包括：",
        "这些背景事件": "这些背景或候选边界事件",
        "这些基础设施是否为真实受影响对象": "这些基础设施是否属于共享基础设施或当前事件相关基础设施",
    }
    for source, target in replacements.items():
        expanded = expanded.replace(source, target)
    expanded = re.sub(r"\bpivot\b", "关键关联指标", expanded, flags=re.IGNORECASE)
    expanded = expanded.replace("dst_ip", "目标 IP")
    expanded = re.sub(
        r"决定是否将\s*(`[^`]+`|[A-Za-z0-9_.-]+)\s*(?:提升|升级)为已确认受影响范围",
        r"判断 \1 是否仍应保留为待确认边界，或是否具备并入确认范围所需证据",
        expanded,
    )
    expanded = re.sub(
        r"确认是否将\s*(`[^`]+`|[A-Za-z0-9_.-]+)\s*(?:提升|升级)为已确认受影响范围",
        r"确认 \1 是否仍应保留为待确认边界，或是否具备并入确认范围所需证据",
        expanded,
    )
    expanded = re.sub(
        r"没有足够证据将\s*(`[^`]+`|[A-Za-z0-9_.-]+)\s*(?:提升|升级)到[“\"]?已确认受影响[”\"]?状态",
        r"\1 仍缺少并入确认范围所需的独立证据",
        expanded,
    )
    expanded = _guard_generated_iocs(expanded, writer_brief)
    expanded = _remove_unsupported_lookback_windows(expanded, writer_brief)
    expanded = _restore_beijing_times_to_source_utc(expanded, writer_brief)
    expanded = _restore_exact_timestamps(expanded, writer_brief)
    expanded = _normalize_markdown_spacing(expanded)
    return expanded.strip()


REPORT_AGENT_WRITER_SYSTEM_PROMPT = """你是 Trace-Agent 的安全事件报告 writer。你只基于 report_writer_prompt_brief 写中文 Markdown 正文，读者是运维人员和安全运营协同对象。

输入契约：
- report_writer_prompt_brief 是从完整 report_writer_brief 确定性压缩出的写作输入，没有新增事实。你只能使用 header_packet、section_fact_map、writing_constraints、appendix_note。
- 完整 fact_catalog 已保存为调试 artifact，不会在 prompt 里重复展开；section_fact_map.paragraph_plan[*].fact_snapshots 是本次写作的事实库。
- Section Fact Map 是章节取材权限表。每节只能使用本节 allowed_fact_ids 和 paragraph_plan.fact_snapshots 对应的 fact，不能从其他章节借事实。
- section_fact_map.paragraph_plan 是段落组计划。每个 plan item 包含 group_id、paragraph_role、paragraph_claim、write_focus、contrast_or_boundary、must_not_repeat 和 fact_snapshots。
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
- 远程执行、远程服务、远程进程、脚本执行、载荷加载等行为默认写成“可疑执行线索”“潜在远程操作”或“范围推进线索”，不要写成“已证实横向移动”“恶意软件已存在”或“攻击者已控制”，除非 exact_fact_text 明确给出强结论。
- “持久化”只能出现在后续核查建议中，除非 fact_catalog 明确给出已观测持久化事实。
- 如果 header_packet.conclusion 包含“复核”，正文不要写成已经完成定性的“确认事件成立”；可以写成“足以支撑事件级复核”。

语言与格式：
- 最终报告必须是中文；英文 source summary 要转述为中文，但域名、IP、资产名、进程名、文件名、时间、JA3/JA4 值必须逐字保留。
- 时间戳必须保留 brief 原格式，例如 `<YYYY-MM-DD HH:MM:SS UTC>`，不要改成中文日期。
- 不要暴露 source_ids、section_type、fact_id、observation_id、工具名、workflow、reviewer、selector、readiness、material loop 等内部术语。
- 不要原样输出 pivot、dst_ip、seed alert；应写成“关键关联指标”“目标 IP”“种子告警”。
- 不要用“这些事实说明……”“这些节点说明……”“主要证据包括……”“可疑活动”“横向移动到某资产”“当前结论被一些缺口限制……”这类低分辨率总括替代 source_fact_catalog 中的原子事实展开。
- 正文末尾如果 appendix_note 存在，可自然提示附录；不要新增 report_plan 以外的章节。
- 最终只返回 Markdown 正文，不要返回 JSON 或解释。"""


REPORT_AGENT_WRITER_HEADER_PROMPT = """你是 Trace-Agent 的安全事件报告 writer。你只生成报告首页摘要，不写任何正文章节。

输入只有 header_packet 和 appendix_note。你不得新增事实、资产、IOC、时间、动作或判断。

输出要求：
- 只输出 `# 首页摘要`。
- 固定 8 行：结论、严重度、研判把握、已确认范围、最强证据、关键缺口、立即动作、一句话结论。
- 严重度必须等于 header_packet.severity；研判把握必须等于 header_packet.confidence。
- 如果某项为空，写“未评估”或“暂无明确材料”，不要编造。
- 最终只返回 Markdown，不要返回 JSON 或解释。"""


REPORT_AGENT_WRITER_SECTION_PROMPT = """你是 Trace-Agent 的安全事件报告 writer。你这次只生成一个正文章节，不写首页摘要，也不写其他章节。

输入契约：
- report_writer_section_prompt_brief 是从完整 writer brief 确定性裁剪出的单章节写作输入。
- 你只能使用 section.paragraph_plan[*].fact_snapshots 中的事实，以及 section 自身的标题、问题、边界和约束。
- header_packet 只用于理解全局结论边界，不能从 header_packet 补写本节没有路由到的事实。
- 不得新增 brief 中没有的新 IOC、新资产、新时间、新动作、新阶段或新结论。

写作要求：
1. 只输出一个二级标题：`## {section_title}`，标题必须逐字匹配 section.title。
2. 按 section.paragraph_plan 顺序写，每个 paragraph_plan item 对应一个自然段；段落之间空一行。
3. 每段必须覆盖该 paragraph group 的全部 fact_snapshots，并围绕 paragraph_claim、write_focus、contrast_or_boundary 组织。
4. 同一事实在不同章节可以复用，但本节必须服务当前 section_type 的论证目的：timeline_process 写事件推进，evidence_judgment 写判断作用，relationship_scope 写范围边界，counterevidence_limits 写不能写强结论的原因。
5. 时间、资产名、域名、IP、进程名、文件名、JA3/JA4 值必须保持原样；英文事实要转述为中文。
6. candidate_or_boundary=true 的事实只能写成候选范围、待验证线索或边界说明，不能写成已确认传播或已确认受影响。
7. 外部基础设施只能写成外联判断、关联基础设施或封禁排查对象，不能写成受影响资产。
8. 远程执行、进程创建、脚本执行、载荷加载等行为只能按 fact_snapshots 的证据强度保守表述，不得升级成已确认控制、已确认横向移动或已确认恶意软件存在。

格式要求：
- 不要输出 JSON、解释、source_ids、fact_id、section_type、工具名或内部流程术语。
- 不要输出三级及以下标题。
- 如果 paragraph_plan 存在，不要压缩成一句总括；复杂章节按 paragraph groups 展开。
- 最终只返回该章节 Markdown。"""


def _header_prompt_brief(writer_brief: Dict[str, Any]) -> Dict[str, Any]:
    source = _as_dict(writer_brief)
    return {
        "schema_version": "report-writer-header-prompt-brief-v1",
        "source_brief_schema_version": _text(source.get("schema_version")),
        "source_material_schema_version": _text(source.get("source_material_schema_version")),
        "header_packet": _as_dict(source.get("header_packet")),
        "appendix_note": _reader_clean_text(source.get("appendix_note")),
    }


def _section_max_tokens(section: Dict[str, Any]) -> int:
    paragraph_count = len(_as_list(_as_dict(section).get("paragraph_plan")))
    if bool(_as_dict(section).get("complex_section")):
        return max(1400, min(2600, 700 + paragraph_count * 450))
    return max(900, min(1800, 600 + paragraph_count * 350))


def _render_polished_body_by_section(llm: Any, writer_brief: Dict[str, Any]) -> str:
    from langchain_core.prompts import ChatPromptTemplate

    header_prompt = ChatPromptTemplate.from_messages(
        [
            ("system", REPORT_AGENT_WRITER_HEADER_PROMPT),
            (
                "user",
                "请只生成首页摘要，不要生成任何 `##` 正文章节。\n"
                "只生成首页摘要。\n"
                "{header_prompt_brief_json}",
            ),
        ]
    )
    header_writer = llm.bind(max_tokens=900, temperature=0) if hasattr(llm, "bind") else llm
    header_response = invoke_llm_with_trace(
        header_writer,
        header_prompt.format_messages(header_prompt_brief_json=_json(_header_prompt_brief(writer_brief))),
        role="report_agent_writer",
        extra={"writer_mode": "section", "writer_step": "header"},
    )
    parts = [_ensure_header_markdown(str(getattr(header_response, "content", "") or ""))]

    section_prompt = ChatPromptTemplate.from_messages(
        [
            ("system", REPORT_AGENT_WRITER_SECTION_PROMPT),
            (
                "user",
                "请只生成一个章节，禁止输出首页摘要或其他章节。\n"
                "section_type={section_type}\n"
                "section_title={section_title}\n"
                "{section_prompt_brief_json}",
            ),
        ]
    )
    prompt_brief = build_report_writer_prompt_brief(writer_brief)
    sections = [_as_dict(section) for section in _as_list(prompt_brief.get("section_fact_map"))]
    for index, section in enumerate(sections):
        section_type = _text(section.get("section_type"))
        section_title = _text(section.get("title")) or section_type or "未命名章节"
        section_prompt_brief = build_report_writer_section_prompt_brief(writer_brief, section_type)
        section_writer = (
            llm.bind(max_tokens=_section_max_tokens(section), temperature=0)
            if hasattr(llm, "bind")
            else llm
        )
        section_response = invoke_llm_with_trace(
            section_writer,
            section_prompt.format_messages(
                section_type=section_type,
                section_title=section_title,
                section_prompt_brief_json=_json(section_prompt_brief),
            ),
            role="report_agent_writer",
            step_index=index,
            extra={
                "writer_mode": "section",
                "writer_step": "section",
                "section_type": section_type,
                "section_title": section_title,
                "section_index": index,
            },
        )
        parts.append(_extract_single_section_markdown(str(getattr(section_response, "content", "") or ""), section_title))

    assembled = "\n\n".join(part.strip() for part in parts if part and part.strip())
    return _normalize_writer_markdown(assembled, writer_brief)


def render_polished_body_from_writer_brief(llm: Any, writer_brief: Dict[str, Any]) -> str:
    from langchain_core.prompts import ChatPromptTemplate

    if _writer_section_mode_enabled():
        return _render_polished_body_by_section(llm, writer_brief)

    prompt_brief = build_report_writer_prompt_brief(writer_brief)

    prompt = ChatPromptTemplate.from_messages(
        [
            ("system", REPORT_AGENT_WRITER_SYSTEM_PROMPT),
            (
                "user",
                "请仅基于以下 report_writer_prompt_brief 生成完整 Markdown 正文。\n"
                "硬性要求：正文必须按 section_fact_map 全部展开；每节只能使用 allowed_fact_ids；禁止输出 question_to_answer 原句；complex_section=true 的章节按 paragraph_target 写够段落；timeline_process 必须覆盖该节全部 paragraph_plan.fact_snapshots 中的时间戳，不能省略候选节点；evidence_judgment、relationship_scope、counterevidence_limits 至少覆盖该节 3 条 allowed facts；如果 fact_roles_to_cover 足够多，还要覆盖不同事实角色；总长度目标 2400 到 4200 中文字。\n"
                "段落硬约束：每个 paragraph_plan item 写成一个自然段，段落之间用空行分开；段落要覆盖该 item 的全部 fact_snapshots，并围绕 paragraph_claim / write_focus / contrast_or_boundary 组织，不要退回一条 fact 一段，也不要把多个 paragraph group 合并成摘要。\n"
                "{writer_prompt_brief_json}",
            ),
        ]
    )
    writer = llm.bind(max_tokens=2800, temperature=0) if hasattr(llm, "bind") else llm
    response = invoke_llm_with_trace(
        writer,
        prompt.format_messages(writer_prompt_brief_json=_json(prompt_brief)),
        role="report_agent_writer",
    )
    return _normalize_writer_markdown(str(getattr(response, "content", "") or "").strip(), writer_brief)


def render_polished_body_from_materials(llm: Any, materials: Dict[str, Any]) -> str:
    writer_brief = build_report_writer_brief(materials)
    return render_polished_body_from_writer_brief(llm, writer_brief)


def _direct_source_fact_snapshot(fact: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "fact_id": _text(fact.get("fact_id")),
        "source_id": _text(fact.get("source_id")),
        "fact_type": _text(fact.get("fact_type")),
        "status": _text(fact.get("status")),
        "classification": _text(fact.get("classification")),
        "reporting_focus": _text(fact.get("reporting_focus")),
        "candidate_or_boundary": bool(fact.get("candidate_or_boundary")),
        "summary_line": _text(fact.get("summary_line")),
        "boundary_note": _text(fact.get("boundary_note")),
    }


def _direct_source_fact_blob(fact: Dict[str, Any]) -> str:
    parts = [
        fact.get("fact_type"),
        fact.get("status"),
        fact.get("classification"),
        fact.get("reporting_focus"),
        fact.get("summary_line"),
        fact.get("boundary_note"),
    ]
    return " ".join(_text(part).lower() for part in parts if _text(part))


def _fact_has_any(text: str, needles: Iterable[str]) -> bool:
    return any(needle.lower() in text for needle in needles if needle)


def _build_direct_source_fact_lanes(fact_catalog: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Create generic navigation lanes without authoring semantic material.

    The lanes are derived only from fact metadata already present in the
    deterministic catalog. They help a direct-source writer avoid mixing
    confirmed, candidate, background, gap, and action facts while keeping the
    LLM responsible for final argument organization.
    """

    lanes: Dict[str, List[Dict[str, Any]]] = {
        "confirmed_timeline": [],
        "confirmed_scope": [],
        "external_infrastructure": [],
        "candidate_or_boundary": [],
        "background_or_alternative": [],
        "open_gaps": [],
        "actions": [],
        "context_claims": [],
    }
    boundary_statuses = ("candidate", "open", "reportable_unresolved", "partially_closed", "待确认", "已验证待确认")
    confirmed_statuses = ("confirmed", "supporting", "已确认")
    background_markers = ("background", "context", "benign", "背景", "替代解释", "上下文", "已关闭缺口")

    for raw_fact in fact_catalog:
        fact = _as_dict(raw_fact)
        fact_id = _text(fact.get("fact_id"))
        if not fact_id:
            continue
        snapshot = _direct_source_fact_snapshot(fact)
        fact_type = _text(fact.get("fact_type"))
        blob = _direct_source_fact_blob(fact)
        is_boundary = bool(fact.get("candidate_or_boundary")) or _fact_has_any(blob, boundary_statuses)
        is_background = _fact_has_any(blob, background_markers)

        if fact_type == "action":
            lanes["actions"].append(snapshot)
            continue
        if fact_type == "gap":
            if not _fact_has_any(blob, ("closed", "已关闭")):
                lanes["open_gaps"].append(snapshot)
            else:
                lanes["background_or_alternative"].append(snapshot)
            continue
        if is_boundary:
            lanes["candidate_or_boundary"].append(snapshot)
        if is_background and fact_type != "verdict":
            lanes["background_or_alternative"].append(snapshot)
        if "外部基础设施" in blob:
            lanes["external_infrastructure"].append(snapshot)
        if fact_type == "event" and _fact_has_any(blob, confirmed_statuses) and not is_boundary:
            lanes["confirmed_timeline"].append(snapshot)
        if _fact_has_any(blob, ("已确认受影响对象", "核心外部基础设施", "主支撑事件", "交付结论")) and not is_boundary:
            lanes["confirmed_scope"].append(snapshot)
        if fact_type in {"claim", "verdict", "intel_tool", "trace_store.seed_context"} and not is_boundary:
            lanes["context_claims"].append(snapshot)

    return {key: value for key, value in lanes.items() if value}


def build_direct_source_writer_brief(source_bundle: Dict[str, Any]) -> Dict[str, Any]:
    """Build the no-material-agent writer input from deterministic sources.

    This experiment deliberately skips LLM-authored section routing. The only
    semantic input is the report source bundle plus its deterministic fact
    catalog; the writer must organize the argument itself without inventing
    facts.
    """

    bundle = _as_dict(source_bundle)
    fact_catalog = [_as_dict(item) for item in build_source_fact_catalog(bundle)]
    case_header = _as_dict(bundle.get("case_header"))
    source_counts = _as_dict(bundle.get("source_counts"))

    facts_by_type: Dict[str, int] = {}
    for fact in fact_catalog:
        fact_type = _text(fact.get("fact_type")) or "unknown"
        facts_by_type[fact_type] = facts_by_type.get(fact_type, 0) + 1

    boundary_fact_ids = [
        _text(fact.get("fact_id"))
        for fact in fact_catalog
        if _text(fact.get("fact_id")) and bool(fact.get("candidate_or_boundary"))
    ]
    external_fact_ids = [
        _text(fact.get("fact_id"))
        for fact in fact_catalog
        if _text(fact.get("fact_id"))
        and (
            "外部基础设施" in _text(fact.get("reporting_focus"))
            or "external_infrastructure" in _text(fact.get("status"))
        )
    ]
    action_fact_ids = [
        _text(fact.get("fact_id"))
        for fact in fact_catalog
        if _text(fact.get("fact_id")) and _text(fact.get("fact_type")) == "action"
    ]

    return {
        "schema_version": "report-direct-source-writer-brief-v1",
        "writer_mode": "direct_source",
        "case_header": case_header,
        "source_counts": source_counts,
        "fact_counts_by_type": facts_by_type,
        "fact_lanes": _build_direct_source_fact_lanes(fact_catalog),
        "source_fact_catalog": fact_catalog,
        "writing_contract": {
            "purpose": "测试强 writer 是否能在不依赖 LLM material agent 的情况下，直接从事实目录组织报告。",
            "required_shape": [
                "# 首页摘要",
                "## 1. 事件结论与当前判断",
                "## 2. 事件过程与关键时间线",
                "## 3. 关键证据判断",
                "## 4. 影响范围、候选对象与外部基础设施",
                "## 5. 反证、替代解释与未闭合缺口",
                "## 6. 处置建议与后续核查",
            ],
            "boundary_fact_ids": boundary_fact_ids,
            "external_infrastructure_fact_ids": external_fact_ids,
            "action_fact_ids": action_fact_ids,
            "global_rules": [
                "只能使用 source_fact_catalog 中的事实，不得新增 IOC、资产、时间、动作、阶段或结论。",
                "fact_lanes 只是由 fact 元数据生成的导航索引，不是额外事实；若 fact_lanes 与 source_fact_catalog 有冲突，以 source_fact_catalog 的原始字段为准。",
                "candidate_or_boundary=true 的事实只能写成候选、待确认、边界、反证或缺口，不能写成已确认传播或已确认受影响。",
                "外部基础设施只能写成外联对象、关联基础设施或排查封禁对象，不能写成受影响资产。",
                "action fact 只代表建议动作，不能改写成已经观测到的事实。",
                "如果事实只显示 rundll32、脚本、远程服务、远程进程或载荷加载线索，只能写成可疑执行或潜在远程操作；除非事实明确支持，不要升级为已确认恶意软件执行、已确认横向移动或攻击者已控制。",
                "处置建议要尽量具体到对象、字段和验证目标；避免只写“补充主机侧日志”这类无法执行的泛句。",
            ],
        },
    }


DIRECT_SOURCE_WRITER_SYSTEM_PROMPT = """你是 Trace-Agent 的资深安全事件报告 writer。本次实验跳过 LLM material agent，你需要直接基于 report_direct_source_writer_brief 组织报告。

输入说明：
- source_fact_catalog 是唯一事实来源，由代码从 report_source_bundle 确定性编译而来。
- 每条 fact 都可能包含 fact_id、source_id、fact_type、status、classification、time、asset、objects、summary_line、exact_fact_text、reporting_focus、boundary_note、candidate_or_boundary。
- fact_lanes 是按 fact 元数据生成的导航索引，用来提醒你哪些事实适合放入确认时间线、范围说明、候选边界、背景/替代解释、未闭合缺口和处置建议；它不新增事实，也不能覆盖原始 fact 字段。
- 你可以自行决定哪些事实进入哪个章节，但不得使用 source_fact_catalog 之外的事实。

写作目标：
- 写给运维人员和安全运营协同对象，不写给内部 agent 开发者。
- 报告要体现分析判断：事件为何成立、证据如何改变判断、哪些对象已确认、哪些只是候选、哪些反证或缺口限制更强结论。
- 不要机械逐条朗读 fact catalog，也不要压缩成泛泛摘要。
- 写作时先用 fact_lanes 找出本节相关事实，再回到 source_fact_catalog 核对 exact_fact_text、summary_line 和 boundary_note，避免把候选、背景或 action 写成已发生事实。

固定结构：
- 严格按 writing_contract.required_shape 输出标题，不得增删章节或改名。
- 首页摘要必须固定输出 6 行项目符号，且每行都带粗体标签：结论、严重度、研判把握、已确认范围、一句话结论、立即动作。不要把首页摘要写成散句。
- 第 2 节写事件推进和时间线；第 3 节解释证据判断作用；第 4 节解释确认范围、候选对象和外部基础设施边界；第 5 节解释反证、替代解释、未闭合 gap 和判断上限；第 6 节写具体可执行动作。
- 第 2 节优先使用 confirmed_timeline，并可补充 candidate_or_boundary 中必须说明的后续候选节点；第 3 节优先使用 confirmed_timeline、confirmed_scope 和 context_claims；第 4 节优先使用 confirmed_scope、external_infrastructure、candidate_or_boundary；第 5 节优先使用 background_or_alternative、open_gaps、candidate_or_boundary；第 6 节优先使用 actions 和 open_gaps。
- 第 3、4、5 节必须写成连续分析段落，禁止使用项目符号或编号清单；每节至少 2 个自然段。
- 第 2 节可以按时间线列点，但每个节点必须说明它对事件推进意味着什么，不能只复制时间和事实。
- 第 6 节可以使用项目符号，但每条建议都必须包含排查对象、日志源或字段、验证目标，避免只有泛泛动作。

保守边界：
- “确认安全事件”只表示证据足以交付事件级结论，不等于已经确认攻击者控制、恶意软件完整执行、横向移动闭环、持久化或长期驻留。
- candidate_or_boundary=true 的事实只能写成候选范围、待验证线索、反证或缺口边界，不能写成已确认传播或已确认受影响。
- status 为 candidate/open/partially_closed/reportable_unresolved，或 boundary_note 明确提示边界的事实，必须保守落文。
- 外部基础设施只能写成外联判断、关联基础设施、出口侧排查或封禁对象，不能写成受影响资产。
- action fact 只能写成建议动作，不能写成已发生事实。
- 主机执行、rundll32、脚本、远程服务、远程进程、载荷加载等线索，如果缺少命令行、落地文件、DLL、父子进程、持久化或内存证据，只能写成可疑执行线索或待核查执行链，不能写成已确认恶意软件加载器执行。
- PsExec、WMI、远程服务创建、远程进程创建可以支撑“横向推进线索”或“疑似横向活动”，但除非事实明确给出成功执行结果、载荷落地、目标主机后续独立命中或主机取证闭环，不要写成“已确认横向移动到某资产”。
- 不要把“已确认受影响资产”写成“已确认受控主机”。可以写“已纳入确认受影响范围”“需要隔离和取证”，但不要暗示攻击者已完全控制。
- 如果同一事实同时有维护窗口、补丁、备份、SCCM、Windows Update、共享基础设施或其他背景解释，必须说明它限制了哪类更强结论，不能只把它当作无关背景。

行动建议要求：
- 动作必须尽量落到可执行检查项：对象、日志源、字段、验证目标。
- 如果事实中出现 rundll32.exe 但缺少完整参数，应建议排查完整命令行、加载 DLL、父进程、落地路径和相关哈希。
- 如果存在外部基础设施，应建议在边界/代理/DNS/EDR 中围绕具体域名或 IP 做封禁、回溯和复现搜索。
- 如果存在候选资产或候选事件，应建议用明确证据标准验证是否并入确认范围。
- 对候选资产的行动建议不要写“提升/升级为已确认受影响范围”；应写“核查其是否仍保留为候选边界，或是否具备并入确认范围所需证据”。

语言与格式：
- 最终只返回中文 Markdown 正文。
- 不要暴露 source_ids、fact_id、observation_id、工具名、workflow、reviewer、selector、readiness、material loop 等内部术语。
- 域名、IP、资产名、进程名、文件名、时间、JA3/JA4 值必须逐字保留。
- 时间必须尽量保留秒级精度；如果原始 fact 是 `YYYY-MM-DD HH:MM:SS UTC`，不要压成 `YYYY-MM-DD HH:MM UTC`。
- 不要把时间、资产、JA3/JA4、IP、域名硬塞进同一句形成 source_fact_catalog 中不存在的“时间-主体-对象”事件组合；如果 JA3/JA4 只是告警识别特征，应单独写成“该告警关联的识别特征/回溯指标”。
- 不要使用“这些证据表明”“主要证据包括”“这些事实说明”作为段落主体；必须直接说明具体事实如何支撑或限制判断。
- 不要在正文末尾写“以上是本次事件的详细报告”这类客服式收尾。
- 不要输出 JSON 或解释你的写作过程。
"""


EVIDENCE_GRAPH_WRITER_SYSTEM_PROMPT = """你是 Trace-Agent 的资深安全事件报告 writer。本次输入是 report_graph_writer_brief。

事实边界：
- source_fact_catalog 是唯一事实来源。
- evidence_graph 和 graph_lenses 只组织事实关系，不新增事实。
- hypothesis_board 是写作论证视角，不是额外证据。
- 任何候选、边界、反证、open gap、action fact 都不能被写成当前已确认事实。

写作策略：
- 写给运维人员和安全运营协同对象，不写给内部 agent 开发者。
- 不要机械逐条朗读证据图；先用 graph_lenses 找本节证据，再回到 source_fact_catalog 核对 exact_fact_text、summary_line 和 boundary_note。
- 第 2 节按 graph_lenses.main_chain 写主线推进，可补充 candidate_expansion，但必须标明待验证。
- 第 3 节结合 graph_lenses.main_chain 与 hypothesis_board.confirmed_main_chain，写当前结论为什么成立；同时用 insufficient_evidence_limits 说明哪些更强结论仍不成立。
- 第 4 节写确认资产、候选资产、核心外部基础设施、共享或背景基础设施，不能把外部 IP 写成受影响资产。
- 第 5 节结合 graph_lenses.counterevidence、graph_lenses.open_gaps 与 hypothesis_board.benign_or_shared_infra_alternative，写反证、替代解释和缺口如何限制结论上限。
- 第 6 节写行动建议，每条包含对象、日志源或字段、验证目标。

保守边界：
- “确认安全事件”只表示证据足以交付事件级结论，不等于已经确认攻击者控制、恶意软件完整执行、横向移动闭环、持久化或长期驻留。
- candidate_or_boundary=true 的事实只能写成候选范围、待验证线索、反证或缺口边界，不能写成已确认传播或已确认受影响。
- 外部基础设施只能写成外联对象、关联基础设施或排查封禁对象，不能写成受影响资产。
- action fact 只代表建议动作，不能改写成已经观测到的事实。
- 主机执行、脚本、远程服务、远程进程、载荷加载等线索，如果缺少命令行、落地文件、父子进程、持久化或内存证据，只能写成可疑执行线索或待核查执行链。

输出格式：
- 只输出中文 Markdown 正文。
- 严格使用 writing_contract.required_shape 的标题。
- 首页摘要必须固定输出 6 行项目符号，且每行都带粗体标签：结论、严重度、研判把握、已确认范围、一句话结论、立即动作。
- 第 3、4、5 节必须写成连续分析段落，禁止使用项目符号或编号清单；每节至少 2 个自然段。
- 第 6 节可以使用项目符号，但每条建议都必须包含排查对象、日志源或字段、验证目标。
- 时间必须保留 source_fact_catalog 中的 UTC 原格式，不要转换成北京时间、当地时间或中文日期。
- 已确认受影响资产只能写成“纳入确认受影响范围”“需要隔离和取证”；不要写成“成功入侵”“攻击者控制链节点”“已被攻击者控制”。
- 不输出 JSON、fact_id、source_id、工具名、内部状态或解释过程。
- 不发明事实卡之外的精确时间、IP、域名、资产、进程、文件或 IOC。
"""


def render_polished_body_from_direct_source_brief(llm: Any, writer_brief: Dict[str, Any]) -> str:
    from langchain_core.prompts import ChatPromptTemplate

    prompt = ChatPromptTemplate.from_messages(
        [
            ("system", DIRECT_SOURCE_WRITER_SYSTEM_PROMPT),
            (
                "user",
                "请仅基于以下 report_direct_source_writer_brief 生成完整 Markdown 正文：\n"
                "{writer_brief_json}",
            ),
        ]
    )
    writer = llm.bind(max_tokens=6000, temperature=0) if hasattr(llm, "bind") else llm
    response = invoke_llm_with_trace(
        writer,
        prompt.format_messages(writer_brief_json=_json(writer_brief)),
        role="report_agent_writer",
        extra={"writer_mode": "direct_source"},
    )
    return _normalize_writer_markdown(str(getattr(response, "content", "") or "").strip(), writer_brief)


def render_polished_body_from_source_bundle(llm: Any, source_bundle: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    writer_brief = build_direct_source_writer_brief(source_bundle)
    return render_polished_body_from_direct_source_brief(llm, writer_brief), writer_brief


def render_polished_body_from_graph_writer_brief(llm: Any, writer_brief: Dict[str, Any]) -> str:
    from langchain_core.prompts import ChatPromptTemplate

    prompt = ChatPromptTemplate.from_messages(
        [
            ("system", EVIDENCE_GRAPH_WRITER_SYSTEM_PROMPT),
            (
                "user",
                "请仅基于以下 report_graph_writer_brief 生成完整 Markdown 正文：\n"
                "{writer_brief_json}",
            ),
        ]
    )
    writer = llm.bind(max_tokens=7000, temperature=0) if hasattr(llm, "bind") else llm
    response = invoke_llm_with_trace(
        writer,
        prompt.format_messages(writer_brief_json=_json(writer_brief)),
        role="report_agent_writer",
        extra={"writer_mode": "evidence_graph"},
    )
    return _normalize_writer_markdown(str(getattr(response, "content", "") or "").strip(), writer_brief)


def render_polished_body_from_evidence_graph(llm: Any, source_bundle: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    fact_catalog = [_as_dict(item) for item in build_source_fact_catalog(source_bundle)]
    writer_brief = build_graph_writer_brief(source_bundle, fact_catalog)
    return render_polished_body_from_graph_writer_brief(llm, writer_brief), writer_brief
