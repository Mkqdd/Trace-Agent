from __future__ import annotations

from typing import Any, Dict, Iterable, List, Tuple


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
    source_ids = collect_material_source_ids(materials)
    invalid_namespace = [source_id for source_id in source_ids if not _valid_source_id(source_id)]
    missing = [source_id for source_id in source_ids if _valid_source_id(source_id) and source_id not in index]
    missing_exact_fact_text: List[str] = []
    empty_required_sections: List[str] = []
    missing_case_thesis_fields: List[str] = []
    report_plan_errors: List[str] = []
    if not _dict(materials.get("case_thesis")):
        empty_required_sections.append("case_thesis")
    else:
        case_thesis = _dict(materials.get("case_thesis"))
        for field in ["conclusion", "severity", "confidence", "why_this_judgment_holds", "why_not_stronger_or_broader", "exact_fact_text"]:
            if not _text(case_thesis.get(field)):
                missing_case_thesis_fields.append(field)
        if not _list(case_thesis.get("source_ids")):
            missing_case_thesis_fields.append("source_ids")
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
                covered_types.add(section_type)
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
    ok = (
        not invalid_namespace
        and not missing
        and not missing_exact_fact_text
        and not empty_required_sections
        and not missing_case_thesis_fields
        and not report_plan_errors
    )
    return {
        "schema_version": "report-writer-materials-validation-v1",
        "ok": ok,
        "source_id_count": len(source_ids),
        "invalid_namespace": invalid_namespace,
        "missing_source_ids": missing,
        "missing_exact_fact_text": missing_exact_fact_text,
        "empty_required_sections": empty_required_sections,
        "missing_case_thesis_fields": missing_case_thesis_fields,
        "report_plan_errors": report_plan_errors,
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
