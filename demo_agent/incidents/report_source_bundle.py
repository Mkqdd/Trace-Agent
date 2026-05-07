from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, Iterable, List


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


def _stable_hash(value: Any) -> str:
    try:
        payload = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    except Exception:
        payload = str(value)
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()[:12]


def _ns_id(namespace: str, raw: Any) -> str:
    text = _text(raw)
    if not text:
        text = _stable_hash(raw)
    if text.startswith(f"{namespace}:"):
        return text
    return f"{namespace}:{text}"


def _format_time(value: Any) -> str:
    text = _text(value)
    if not text:
        return ""
    return text.replace("T", " ").replace("Z", " UTC")


def _event_raw_id(event: Dict[str, Any]) -> str:
    return _text(event.get("id") or event.get("event_id"))


def _event_source_id(event: Dict[str, Any]) -> str:
    raw_id = _event_raw_id(event)
    if raw_id:
        return _ns_id("event", raw_id)
    return _ns_id("event", _stable_hash(event))


def _object_source_id(value: Any, object_id: Any = "") -> str:
    raw = _text(object_id) or _text(value)
    if not raw:
        raw = _stable_hash({"value": value, "object_id": object_id})
    safe = re.sub(r"\s+", "_", raw)
    return _ns_id("object", safe)


def _merge_dict_preserve_detail(base: Dict[str, Any], incoming: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(base or {})
    for key, value in dict(incoming or {}).items():
        if value in (None, "", [], {}):
            continue
        current = merged.get(key)
        if current in (None, "", [], {}):
            merged[key] = value
            continue
        if key == "summary":
            # Prefer the more detailed raw event summary over compressed derived summaries.
            if len(_text(value)) > len(_text(current)):
                merged[key] = value
        elif key in {"roles", "stages", "tags", "event_ids", "observation_ids", "source_refs"}:
            merged[key] = _dedupe(_list(current) + _list(value))
    return merged


def _event_exact_fact_text(event: Dict[str, Any]) -> str:
    ts = _format_time(event.get("ts") or event.get("event_time") or event.get("time"))
    asset = _text(event.get("asset_id") or event.get("asset") or event.get("host"))
    summary = _text(event.get("summary") or event.get("description") or event.get("message"))
    domain = _text(event.get("domain"))
    dst_ip = _text(event.get("dst_ip") or event.get("destination_ip"))
    src_ip = _text(event.get("src_ip") or event.get("source_ip"))
    process = _text(event.get("process") or event.get("process_name") or event.get("image"))
    command = _text(event.get("command") or event.get("command_line"))
    obj = " / ".join(_dedupe([domain, dst_ip]))
    parts: List[str] = []
    if ts:
        parts.append(ts)
    if asset:
        parts.append(f"资产 `{asset}`")
    if obj:
        parts.append(f"关联对象 `{obj}`")
    if process:
        parts.append(f"进程 `{process}`")
    if command:
        parts.append(f"命令 `{command}`")
    if summary:
        parts.append(summary)
    if src_ip and src_ip != asset:
        parts.append(f"源地址 `{src_ip}`")
    fact_text = "，".join(parts)
    status = _text(event.get("status"))
    classification = _text(event.get("classification"))
    if status == "candidate":
        return f"候选事件（尚未独立验证）：{fact_text}"
    if status == "background" or classification == "benign":
        return f"背景/替代解释事件：{fact_text}"
    return fact_text


def _object_report_scope_role(item: Dict[str, Any], delivery_decision: Dict[str, Any]) -> str:
    value = _text(item.get("value") or item.get("object"))
    current_role = _text(item.get("current_role"))
    roles = set(_text(role) for role in _list(item.get("roles")) if _text(role))
    confirmed = set(_text(v) for v in _list(delivery_decision.get("confirmed_scope")) if _text(v))
    candidates = set(_text(v) for v in _list(delivery_decision.get("candidate_scope")) if _text(v))
    if value in confirmed or "affected_asset" in roles:
        return "confirmed_affected_asset"
    if current_role == "core_external_indicator" or "core_external_indicator" in roles:
        return "external_infrastructure"
    if value in candidates or current_role in {"related_asset", "expansion_candidate"}:
        return "candidate_asset" if _text(item.get("object_type")) == "asset" or current_role == "related_asset" else "candidate_object"
    if current_role == "seed_asset" or "seed_asset" in roles:
        return "seed_asset"
    if current_role == "contextual_indicator" or "contextual_indicator" in roles:
        return "background_object"
    if current_role == "related_internal_address" or "related_internal_address" in roles:
        return "related_internal_address"
    return current_role or "background_object"


def _object_exact_fact_text(item: Dict[str, Any]) -> str:
    value = _text(item.get("value") or item.get("object"))
    object_type = _text(item.get("type_label") or item.get("object_type") or item.get("type"))
    role = _text(item.get("role_label") or item.get("current_role"))
    notes = _dedupe(_list(item.get("notes")))[:4]
    pieces = []
    if value:
        pieces.append(f"对象 `{value}`")
    if object_type:
        pieces.append(f"类型为{object_type}")
    if role:
        pieces.append(f"当前角色为{role}")
    if notes:
        pieces.append("；".join(notes))
    return "，".join(pieces)


def _source_ref_ids(values: Iterable[Any], namespace: str) -> List[str]:
    return [_ns_id(namespace, value) for value in _dedupe(values)]


def _build_observations(incident_state: Dict[str, Any], evidence_store: Dict[str, Any]) -> List[Dict[str, Any]]:
    by_id: Dict[str, Dict[str, Any]] = {}
    for source_layer, rows in [
        ("incident_state.observations", _list(incident_state.get("observations"))),
        ("evidence_store.observations", _list(evidence_store.get("observations"))),
    ]:
        for row in rows:
            if not isinstance(row, dict):
                continue
            obs_id = _text(row.get("observation_id") or row.get("id")) or _stable_hash(row)
            source_id = _ns_id("obs", obs_id)
            item = _merge_dict_preserve_detail(by_id.get(source_id, {}), dict(row))
            item["id"] = obs_id
            item["source_id"] = source_id
            item["source_layers"] = _dedupe(_list(item.get("source_layers")) + [source_layer])
            item["event_source_ids"] = _source_ref_ids(_list(item.get("event_ids")), "event")
            by_id[source_id] = item
    return list(by_id.values())


def _build_events(incident: Dict[str, Any], evidence_store: Dict[str, Any]) -> List[Dict[str, Any]]:
    by_id: Dict[str, Dict[str, Any]] = {}
    event_observations: Dict[str, List[str]] = {}
    for obs in _list(evidence_store.get("observations")):
        if not isinstance(obs, dict):
            continue
        obs_source = _ns_id("obs", obs.get("observation_id") or obs.get("id"))
        for event_id in _list(obs.get("event_ids")) + _list(obs.get("checked_event_ids")) + _list(obs.get("boundary_event_ids")):
            event_observations.setdefault(_ns_id("event", event_id), []).append(obs_source)

    source_rows = [
        ("incident.cluster.events", _list(_dict(incident.get("cluster")).get("events"))),
        ("incident.timeline", _list(incident.get("timeline"))),
        ("incident_state.timeline", _list(_dict(incident.get("incident_state")).get("timeline"))),
        ("evidence_store.confirmed_events", _list(evidence_store.get("confirmed_events"))),
        ("evidence_store.candidate_events", _list(evidence_store.get("candidate_events"))),
    ]
    for source_layer, rows in source_rows:
        for row in rows:
            if not isinstance(row, dict):
                continue
            source_id = _event_source_id(row)
            item = _merge_dict_preserve_detail(by_id.get(source_id, {}), dict(row))
            item["id"] = _event_raw_id(item) or source_id.removeprefix("event:")
            item["source_id"] = source_id
            item["source_layers"] = _dedupe(_list(item.get("source_layers")) + [source_layer])
            if source_layer == "evidence_store.candidate_events":
                item.setdefault("status", "candidate")
            elif source_layer == "evidence_store.confirmed_events":
                item.setdefault("status", "confirmed")
            role = _text(item.get("role"))
            classification = _text(item.get("classification"))
            if not item.get("status"):
                if role == "candidate":
                    item["status"] = "candidate"
                elif role in {"counterevidence", "context"} or classification == "benign":
                    item["status"] = "background"
                else:
                    item["status"] = "confirmed"
            item["observation_ids"] = _dedupe(_list(item.get("observation_ids")) + event_observations.get(source_id, []))
            item["exact_fact_text"] = _event_exact_fact_text(item)
            by_id[source_id] = item
    return sorted(by_id.values(), key=lambda item: (_text(item.get("ts")), _text(item.get("id"))))


def _build_claims(evidence_store: Dict[str, Any]) -> List[Dict[str, Any]]:
    claims: List[Dict[str, Any]] = []
    for index, row in enumerate(_list(evidence_store.get("claims")), start=1):
        if not isinstance(row, dict):
            continue
        claim_id = _text(row.get("claim_id")) or f"claim-{index:03d}"
        item = dict(row)
        item["id"] = claim_id
        item["source_id"] = _ns_id("claim", claim_id)
        item["observation_ids"] = _source_ref_ids(_list(item.get("observation_ids")), "obs")
        item["event_source_ids"] = _source_ref_ids(_list(item.get("event_ids")), "event")
        item["exact_fact_text"] = _text(item.get("text"))
        item["source_layer"] = "evidence_store.claims"
        claims.append(item)
    return claims


def _build_objects(evidence_store: Dict[str, Any], delivery_decision: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for row in _list(evidence_store.get("objects") or evidence_store.get("object_registry")):
        if not isinstance(row, dict):
            continue
        item = dict(row)
        value = _text(item.get("value") or item.get("object"))
        item["source_id"] = _object_source_id(value, item.get("object_id"))
        item["all_observed_roles"] = _dedupe(_list(item.get("roles")) + [item.get("current_role")])
        item["investigation_role"] = _text(item.get("current_role")) or (item["all_observed_roles"][0] if item["all_observed_roles"] else "")
        item["report_scope_role"] = _object_report_scope_role(item, delivery_decision)
        item["role_sources"] = _dedupe([item["source_id"], "verdict:delivery"])
        item["exact_fact_text"] = _object_exact_fact_text(item)
        item["source_layer"] = "evidence_store.objects"
        out.append(item)
    return out


def _build_gaps(incident_state: Dict[str, Any], evidence_store: Dict[str, Any], delivery_decision: Dict[str, Any]) -> List[Dict[str, Any]]:
    by_id: Dict[str, Dict[str, Any]] = {}
    for source_layer, rows in [
        ("incident_state.gap_ledger", _list(incident_state.get("gap_ledger"))),
        ("evidence_store.gaps", _list(evidence_store.get("gaps") or evidence_store.get("evidence_gaps"))),
        ("delivery_decision.blocking_gaps", _list(delivery_decision.get("blocking_gaps"))),
        ("delivery_decision.non_blocking_gaps", _list(delivery_decision.get("non_blocking_gaps"))),
    ]:
        for row in rows:
            if not isinstance(row, dict):
                continue
            gap_id = _text(row.get("gap_id") or row.get("id")) or _stable_hash(row)
            source_id = _ns_id("gap", gap_id)
            item = _merge_dict_preserve_detail(by_id.get(source_id, {}), dict(row))
            item["id"] = gap_id
            item["source_id"] = source_id
            item["source_layers"] = _dedupe(_list(item.get("source_layers")) + [source_layer])
            item["exact_fact_text"] = _text(item.get("question") or item.get("status_reason") or item.get("next_best_query"))
            by_id[source_id] = item
    return list(by_id.values())


def _scope_from_objects(objects: List[Dict[str, Any]], delivery_decision: Dict[str, Any]) -> Dict[str, Any]:
    confirmed = _dedupe(_list(delivery_decision.get("confirmed_scope")))
    candidates = _dedupe(_list(delivery_decision.get("candidate_scope")))
    return {
        "confirmed_assets": confirmed
        or _dedupe(item.get("value") for item in objects if item.get("report_scope_role") == "confirmed_affected_asset"),
        "candidate_assets": candidates
        or _dedupe(item.get("value") for item in objects if item.get("report_scope_role") in {"candidate_asset", "candidate_object"}),
        "seed_assets": _dedupe(item.get("value") for item in objects if item.get("investigation_role") == "seed_asset"),
        "external_infrastructure": _dedupe(item.get("value") for item in objects if item.get("report_scope_role") == "external_infrastructure"),
        "background_objects": _dedupe(item.get("value") for item in objects if item.get("report_scope_role") == "background_object"),
        "related_internal_addresses": _dedupe(item.get("value") for item in objects if item.get("report_scope_role") == "related_internal_address"),
    }


def _source_conflicts(objects: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    conflicts: List[Dict[str, Any]] = []
    by_value: Dict[str, List[Dict[str, Any]]] = {}
    for item in objects:
        value = _text(item.get("value") or item.get("object"))
        if value:
            by_value.setdefault(value, []).append(item)
    for value, rows in by_value.items():
        roles = set(_text(row.get("report_scope_role")) for row in rows if _text(row.get("report_scope_role")))
        if "confirmed_affected_asset" in roles and "candidate_asset" in roles:
            conflicts.append(
                {
                    "type": "scope_role_conflict",
                    "object": value,
                    "roles": sorted(roles),
                    "source_ids": _dedupe(row.get("source_id") for row in rows),
                }
            )
    return conflicts


def build_report_source_bundle(
    incident: Dict[str, Any],
    *,
    evidence_store: Dict[str, Any] | None = None,
    delivery_decision: Dict[str, Any] | None = None,
    outline: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    evidence_store = _dict(evidence_store or incident.get("evidence_store"))
    delivery_decision = _dict(delivery_decision or incident.get("delivery_decision"))
    outline = _dict(outline)
    incident_state = _dict(incident.get("incident_state"))
    ops_report = _dict(outline.get("ops_report_contract") or outline.get("main_report_contract"))
    report_header = _dict(ops_report.get("report_header") or outline.get("report_header"))
    delivery_verdict = _dict(delivery_decision.get("delivery_verdict") or incident.get("delivery_verdict"))
    analysis_verdict = _dict(delivery_decision.get("analysis_verdict") or incident.get("analysis_verdict"))

    observations = _build_observations(incident_state, evidence_store)
    events = _build_events(incident, evidence_store)
    claims = _build_claims(evidence_store)
    objects = _build_objects(evidence_store, delivery_decision)
    gaps = _build_gaps(incident_state, evidence_store, delivery_decision)
    scope = _scope_from_objects(objects, delivery_decision)

    case_header = {
        "title": _text(ops_report.get("title") or report_header.get("event_title") or outline.get("title")),
        "analysis_window": _text(report_header.get("analysis_window") or _dict(incident.get("scope")).get("time_window")),
        "seed_alert": _dict(incident.get("seed") or incident_state.get("seed")),
        "final_verdict": delivery_verdict or analysis_verdict,
        "delivery_status": _text(delivery_decision.get("delivery_status") or delivery_verdict.get("status")),
        "delivery_status_label": _text(delivery_decision.get("delivery_status_label") or delivery_verdict.get("status_label")),
        "severity": _text(delivery_verdict.get("severity") or analysis_verdict.get("severity") or report_header.get("severity")),
        "confidence": _text(delivery_decision.get("confidence_band") or report_header.get("confidence")),
        "source_layer": "delivery_decision",
    }

    return {
        "schema_version": "report-source-bundle-v1",
        "case_header": case_header,
        "observations": observations,
        "events": events,
        "claims": claims,
        "objects": objects,
        "scope": scope,
        "timeline": events,
        "gaps": gaps,
        "counterevidence": [claim for claim in claims if _text(claim.get("relation")) == "counterevidence"]
        or _list(evidence_store.get("counterevidence")),
        "recommendations": [
            {
                "source_id": _ns_id("action", index),
                "text": _text(item),
                "exact_fact_text": _text(item),
                "source_layer": "incident.recommendations",
            }
            for index, item in enumerate(_list(incident.get("recommendations")), start=1)
            if _text(item)
        ],
        "citations": {
            "observation_index": {item["source_id"]: item for item in observations},
            "event_to_observations": {
                item["source_id"]: _dedupe(_list(item.get("observation_ids"))) for item in events if item.get("source_id")
            },
            "claim_to_observations": {
                item["source_id"]: _dedupe(_list(item.get("observation_ids"))) for item in claims if item.get("source_id")
            },
            "object_to_observations": {},
        },
        "appendix_inventory": {
            "ioc_available": bool(_list(_dict(outline.get("appendix_contract")).get("ioc_rows"))),
            "object_table_available": bool(_list(_dict(outline.get("appendix_contract")).get("key_object_rows"))),
            "observation_mapping_available": bool(observations),
        },
        "source_conflicts": _source_conflicts(objects),
        "source_counts": {
            "observations": len(observations),
            "events": len(events),
            "claims": len(claims),
            "objects": len(objects),
            "gaps": len(gaps),
        },
    }
