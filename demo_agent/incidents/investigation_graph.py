from __future__ import annotations

import hashlib
import ipaddress
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple


INVESTIGATION_GRAPH_SCHEMA_VERSION = "investigation-graph-v1"
INVESTIGATION_HYPOTHESIS_BOARD_SCHEMA_VERSION = "investigation-hypothesis-board-v2"


def _text(value: Any) -> str:
    return str(value or "").strip()


def _as_dict(value: Any) -> Dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _as_list(value: Any) -> List[Any]:
    return list(value) if isinstance(value, list) else []


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


def _stable_id(prefix: str, *parts: Any) -> str:
    payload = "|".join(_text(part) for part in parts if _text(part)) or prefix
    digest = hashlib.sha1(payload.encode("utf-8")).hexdigest()[:12]
    return f"{prefix}:{digest}"


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _slug(value: Any) -> str:
    text = re.sub(r"[^a-zA-Z0-9]+", "-", _text(value)).strip("-").lower()
    return text or "item"


def _normalize_event_id(event: Dict[str, Any], index: int) -> str:
    event_id = _text(event.get("id") or event.get("event_id") or event.get("source_id"))
    if event_id:
        return event_id
    return _stable_id(
        "event",
        event.get("ts") or event.get("time") or event.get("event_time"),
        event.get("asset_id") or event.get("asset"),
        event.get("summary") or event.get("description"),
        index,
    )


def _normalize_event(event: Dict[str, Any], index: int) -> Dict[str, Any]:
    event = _as_dict(event)
    event_id = _normalize_event_id(event, index)
    role = _text(event.get("role") or event.get("status") or event.get("classification"))
    summary = _text(event.get("summary") or event.get("text") or event.get("description") or event.get("label") or event_id)
    observation_ids = _dedupe(_as_list(event.get("observation_ids")))
    source_ids = _dedupe([event_id, _text(event.get("source_id"))])
    boundary = role in {"candidate", "background", "counterevidence"} or _text(event.get("grounding_status")) not in {"", "confirmed_supporting"}
    return {
        "event_id": event_id,
        "role": role or "context",
        "status": _text(event.get("status") or event.get("classification") or role or "unknown"),
        "summary": summary,
        "ts": _text(event.get("ts") or event.get("time") or event.get("event_time")),
        "asset_id": _text(event.get("asset_id") or event.get("asset") or event.get("host")),
        "domain": _text(event.get("domain")),
        "dst_ip": _text(event.get("dst_ip") or event.get("destination_ip") or ((event.get("dst") or {}).get("ip") if isinstance(event.get("dst"), dict) else "")),
        "src_ip": _text(event.get("src_ip") or event.get("source_ip") or ((event.get("src") or {}).get("ip") if isinstance(event.get("src"), dict) else "")),
        "fingerprint": _text(
            event.get("fingerprint")
            or event.get("trigger_fingerprint")
            or ((event.get("trigger_fingerprint") or {}).get("value") if isinstance(event.get("trigger_fingerprint"), dict) else "")
        ),
        "grounding_status": _text(event.get("grounding_status")),
        "boundary": bool(boundary),
        "observation_ids": observation_ids,
        "source_ids": source_ids,
        "properties": {
            "classification": _text(event.get("classification")),
            "source_type": _text(event.get("source_type")),
            "relation": _text(event.get("relation")),
        },
    }


def _is_candidate_text(value: Any) -> bool:
    text = _text(value).lower()
    return any(marker in text for marker in ["candidate", "候选", "待确认", "spread", "expansion", "scope", "扩线", "second hop", "related"])


def _is_background_text(value: Any) -> bool:
    text = _text(value).lower()
    return any(marker in text for marker in ["background", "counterevidence", "shared", "maintenance", "benign", "shared infra", "共享", "背景", "维护", "替代"])


def _is_limit_text(value: Any) -> bool:
    text = _text(value).lower()
    return any(marker in text for marker in ["missing", "limit", "缺少", "缺口", "未闭合", "不足", "command line", "log", "artifact", "scope", "范围", "attribute", "归因", "persistence", "持久化"])


def _gap_target_hypotheses(gap: Dict[str, Any]) -> List[str]:
    text = " ".join(
        [
            _text(gap.get("question")),
            _text(gap.get("status_reason")),
            _text(gap.get("gap_type")),
            _text(gap.get("priority")),
        ]
    )
    targets: List[str] = []
    if _is_candidate_text(text):
        targets.append("candidate_spread")
    if _is_background_text(text):
        targets.append("benign_or_shared_infra_alternative")
    if _is_limit_text(text):
        targets.append("insufficient_evidence_limits")
    if not targets and bool(gap.get("delivery_blocking")):
        targets.append("insufficient_evidence_limits")
    return _dedupe(targets)


def _gap_target_actions(gap: Dict[str, Any], target_hypotheses: List[str]) -> List[str]:
    actionable_tools = _dedupe(_as_list(gap.get("actionable_tools") or gap.get("tool_capability_hints")))
    if actionable_tools:
        return actionable_tools
    fallback: List[str] = []
    if "candidate_spread" in target_hypotheses:
        fallback.extend(["search_related_events", "expand_asset_scope"])
    if "benign_or_shared_infra_alternative" in target_hypotheses:
        fallback.extend(["check_counterevidence", "technical_source_search"])
    if "insufficient_evidence_limits" in target_hypotheses:
        fallback.extend(["expand_asset_scope", "ground_candidate_event"])
    return _dedupe(fallback)


def _gap_rows_with_delivery_overlay(incident_state: Dict[str, Any], finalized: Dict[str, Any]) -> List[Dict[str, Any]]:
    gap_rows = [dict(item) for item in _as_list(finalized.get("gap_ledger") or incident_state.get("gap_ledger"))]
    overlay_rows: Dict[str, Dict[str, Any]] = {}
    delivery_decision = _as_dict(finalized.get("delivery_decision") or incident_state.get("delivery_decision"))
    for bucket in ("blocking_gaps", "non_blocking_gaps"):
        for raw_gap in _as_list(delivery_decision.get(bucket)):
            gap = _as_dict(raw_gap)
            gap_id = _text(gap.get("gap_id") or gap.get("id"))
            if not gap_id:
                continue
            gap.setdefault("id", gap_id)
            gap.setdefault("gap_id", gap_id)
            if bucket == "blocking_gaps":
                gap["delivery_blocking"] = True
                gap["blocks_delivery_now"] = True
                gap["reportable_only"] = False
            else:
                gap["blocks_delivery_now"] = False
                gap["reportable_only"] = True
                gap.setdefault("status", "reportable_unresolved")
            overlay_rows[gap_id] = gap
    if not gap_rows:
        return list(overlay_rows.values())
    if not overlay_rows:
        return gap_rows
    merged: Dict[str, Dict[str, Any]] = {}
    for raw_gap in gap_rows:
        gap = _as_dict(raw_gap)
        gap_id = _text(gap.get("id") or gap.get("gap_id"))
        if gap_id:
            merged[gap_id] = gap
    for gap_id, overlay in overlay_rows.items():
        base = dict(merged.get(gap_id) or {})
        base.update(overlay)
        base.setdefault("id", gap_id)
        base.setdefault("gap_id", gap_id)
        merged[gap_id] = base
    return list(merged.values()) or gap_rows


def _event_target_hypotheses(event: Dict[str, Any], delivery_status: str) -> List[str]:
    role = _text(event.get("role") or event.get("status")).lower()
    targets: List[str] = []
    if role in {"seed", "confirmed", "supporting"}:
        targets.append("confirmed_main_chain")
    if role == "candidate":
        targets.append("candidate_spread")
    if role in {"background", "counterevidence"}:
        targets.append("benign_or_shared_infra_alternative")
    if role in {"candidate", "background", "counterevidence"}:
        targets.append("insufficient_evidence_limits")
    if delivery_status == "confirmed_incident" and role in {"background", "counterevidence"}:
        targets.append("false_positive_or_noise")
    if delivery_status != "confirmed_incident" and role == "seed":
        targets.append("false_positive_or_noise")
    return _dedupe(targets)


def _hypothesis_specs() -> List[Dict[str, Any]]:
    return [
        {
            "hypothesis_id": "confirmed_main_chain",
            "claim": "The confirmed main chain is sufficient for the current incident verdict.",
            "priority": 0,
            "status": "open",
        },
        {
            "hypothesis_id": "candidate_spread",
            "claim": "Candidate spread may extend the incident scope and still needs validation.",
            "priority": 1,
            "status": "open",
        },
        {
            "hypothesis_id": "benign_or_shared_infra_alternative",
            "claim": "Shared infrastructure, maintenance, or benign background may explain part of the signal.",
            "priority": 2,
            "status": "open",
        },
        {
            "hypothesis_id": "insufficient_evidence_limits",
            "claim": "Missing evidence still limits stronger claims about scope, attribution, or closure.",
            "priority": 3,
            "status": "open",
        },
        {
            "hypothesis_id": "false_positive_or_noise",
            "claim": "The seed could still be false positive or background noise if support stays weak.",
            "priority": 4,
            "status": "open",
        },
    ]


def _node_index(nodes: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    return {str(item.get("node_id") or "").strip(): item for item in nodes if str(item.get("node_id") or "").strip()}


def _edge_bucket(edges: List[Dict[str, Any]], *, source: str, target: str, relation: str) -> List[Dict[str, Any]]:
    return [item for item in edges if _text(item.get("source")) == source and _text(item.get("target")) == target and _text(item.get("relation")) == relation]


def _merge_node(existing: Dict[str, Any], update: Dict[str, Any]) -> Dict[str, Any]:
    for key in ("source_ids", "event_ids", "observation_ids", "gap_ids", "action_ids", "roles"):
        existing[key] = _dedupe([*list(existing.get(key) or []), *list(update.get(key) or [])])
    if _text(update.get("label")) and not _text(existing.get("label")):
        existing["label"] = _text(update.get("label"))
    if _text(update.get("status")) and _text(existing.get("status")) in {"", "unknown"}:
        existing["status"] = _text(update.get("status"))
    existing["boundary"] = bool(existing.get("boundary") or update.get("boundary"))
    properties = dict(existing.get("properties") or {})
    properties.update(dict(update.get("properties") or {}))
    existing["properties"] = properties
    return existing


def _add_node(nodes: Dict[str, Dict[str, Any]], node: Dict[str, Any]) -> None:
    node_id = _text(node.get("node_id"))
    if not node_id:
        return
    base = nodes.get(node_id)
    if base is None:
        nodes[node_id] = {
            "node_id": node_id,
            "node_type": _text(node.get("node_type")),
            "label": _text(node.get("label")),
            "status": _text(node.get("status") or "unknown"),
            "boundary": bool(node.get("boundary")),
            "source_ids": _dedupe(_as_list(node.get("source_ids"))),
            "event_ids": _dedupe(_as_list(node.get("event_ids"))),
            "observation_ids": _dedupe(_as_list(node.get("observation_ids"))),
            "gap_ids": _dedupe(_as_list(node.get("gap_ids"))),
            "action_ids": _dedupe(_as_list(node.get("action_ids"))),
            "roles": _dedupe(_as_list(node.get("roles"))),
            "properties": dict(node.get("properties") or {}),
        }
    else:
        nodes[node_id] = _merge_node(base, node)


def _add_edge(edges: Dict[str, Dict[str, Any]], edge: Dict[str, Any]) -> None:
    edge_id = _text(edge.get("edge_id"))
    if not edge_id:
        edge_id = _stable_id("edge", edge.get("source"), edge.get("relation"), edge.get("target"))
    base = edges.get(edge_id)
    if base is None:
        edges[edge_id] = {
            "edge_id": edge_id,
            "source": _text(edge.get("source")),
            "target": _text(edge.get("target")),
            "relation": _text(edge.get("relation")),
            "boundary": bool(edge.get("boundary")),
            "source_ids": _dedupe(_as_list(edge.get("source_ids"))),
            "event_ids": _dedupe(_as_list(edge.get("event_ids"))),
            "observation_ids": _dedupe(_as_list(edge.get("observation_ids"))),
            "properties": dict(edge.get("properties") or {}),
        }
    else:
        base["source_ids"] = _dedupe([*base.get("source_ids", []), *_dedupe(_as_list(edge.get("source_ids")))])
        base["event_ids"] = _dedupe([*base.get("event_ids", []), *_dedupe(_as_list(edge.get("event_ids")))])
        base["observation_ids"] = _dedupe([*base.get("observation_ids", []), *_dedupe(_as_list(edge.get("observation_ids")))])
        base["boundary"] = bool(base.get("boundary") or edge.get("boundary"))
        properties = dict(base.get("properties") or {})
        properties.update(dict(edge.get("properties") or {}))
        base["properties"] = properties


def _add_relation(
    edges: Dict[str, Dict[str, Any]],
    *,
    source: str,
    target: str,
    relation: str,
    source_ids: Iterable[Any] = (),
    event_ids: Iterable[Any] = (),
    observation_ids: Iterable[Any] = (),
    boundary: bool = False,
    properties: Optional[Dict[str, Any]] = None,
) -> None:
    _add_edge(
        edges,
        {
            "source": source,
            "target": target,
            "relation": relation,
            "source_ids": _dedupe(source_ids),
            "event_ids": _dedupe(event_ids),
            "observation_ids": _dedupe(observation_ids),
            "boundary": bool(boundary),
            "properties": dict(properties or {}),
        },
    )


def _build_event_nodes(
    seed_event: Dict[str, Any],
    finalized: Dict[str, Any],
    incident_state: Dict[str, Any],
    nodes: Dict[str, Dict[str, Any]],
    edges: Dict[str, Dict[str, Any]],
    *,
    delivery_status: str,
) -> Dict[str, Dict[str, Any]]:
    annotated_events = _as_list(finalized.get("annotated_events") or incident_state.get("annotated_events"))
    if not annotated_events and seed_event:
        annotated_events = [seed_event]
    observation_to_event: Dict[str, List[str]] = {}
    for item in _as_list(finalized.get("evidence_ledger") or incident_state.get("evidence_ledger")):
        observation_id = _text(item.get("observation_id"))
        for event_id in _as_list(item.get("event_ids")):
            event_id_text = _text(event_id)
            if observation_id and event_id_text:
                observation_to_event.setdefault(event_id_text, []).append(observation_id)

    event_records: Dict[str, Dict[str, Any]] = {}
    for index, raw_event in enumerate(annotated_events):
        event = _normalize_event(_as_dict(raw_event), index)
        event_id = event["event_id"]
        event_records[event_id] = event
        event["observation_ids"] = _dedupe([*event["observation_ids"], *observation_to_event.get(event_id, [])])
        _add_node(
            nodes,
            {
                "node_id": f"event:{event_id}",
                "node_type": "event",
                "label": event["summary"],
                "status": event["status"],
                "boundary": event["boundary"],
                "source_ids": event["source_ids"],
                "event_ids": [event_id],
                "observation_ids": event["observation_ids"],
                "roles": [event["role"]],
                "properties": {
                    "ts": event["ts"],
                    "asset_id": event["asset_id"],
                    "domain": event["domain"],
                    "dst_ip": event["dst_ip"],
                    "src_ip": event["src_ip"],
                    "fingerprint": event["fingerprint"],
                    "grounding_status": event["grounding_status"],
                },
            },
        )
    return event_records


def _collect_asset_roles(incident_state: Dict[str, Any], finalized: Dict[str, Any]) -> Dict[str, List[str]]:
    role_map: Dict[str, List[str]] = {}
    entities = _as_dict(finalized.get("entities") or incident_state.get("entities"))
    scope = _as_dict(finalized.get("scope") or incident_state.get("scope"))

    for asset in _dedupe([entities.get("seed_asset")] + _as_list(entities.get("assets"))):
        if asset:
            role_map.setdefault(asset, []).append("related_asset")
    for asset in _dedupe(_as_list(scope.get("confirmed_assets"))):
        if asset:
            role_map.setdefault(asset, []).append("affected_asset")
    for asset in _dedupe(_as_list(scope.get("candidate_assets"))):
        if asset:
            role_map.setdefault(asset, []).append("candidate_asset")
    for asset in _dedupe(_as_list(scope.get("external_infrastructure"))):
        if asset:
            role_map.setdefault(asset, []).append("external_infrastructure")
    seed_asset = _text(entities.get("seed_asset"))
    if seed_asset:
        role_map.setdefault(seed_asset, []).append("seed_asset")
    for event in _as_list(finalized.get("annotated_events") or incident_state.get("annotated_events")):
        asset = _text((event or {}).get("asset_id") or (event or {}).get("asset") or (event or {}).get("host"))
        if asset:
            role_map.setdefault(asset, []).append(_text((event or {}).get("role") or "related_asset"))
    return {asset: _dedupe(roles) for asset, roles in role_map.items()}


def _build_asset_nodes(
    incident_state: Dict[str, Any],
    finalized: Dict[str, Any],
    nodes: Dict[str, Dict[str, Any]],
    edges: Dict[str, Dict[str, Any]],
    event_records: Dict[str, Dict[str, Any]],
) -> None:
    role_map = _collect_asset_roles(incident_state, finalized)
    for asset, roles in sorted(role_map.items(), key=lambda item: item[0]):
        if not asset:
            continue
        event_ids: List[str] = []
        observation_ids: List[str] = []
        for event_id, event in event_records.items():
            if _text(event.get("asset_id")) == asset:
                event_ids.append(event_id)
                observation_ids.extend(_as_list(event.get("observation_ids")))
        node_roles = roles or ["related_asset"]
        boundary = any(role in {"candidate_asset", "external_infrastructure"} for role in node_roles)
        _add_node(
            nodes,
            {
                "node_id": f"asset:{asset}",
                "node_type": "asset",
                "label": asset,
                "status": "candidate" if "candidate_asset" in node_roles else ("confirmed" if "affected_asset" in node_roles or "seed_asset" in node_roles else "context"),
                "boundary": boundary,
                "source_ids": [*event_ids, *observation_ids],
                "event_ids": event_ids,
                "observation_ids": observation_ids,
                "roles": node_roles,
                "properties": {"roles": node_roles},
            },
        )
        for event_id in event_ids:
            event = event_records.get(event_id) or {}
            relation = "supports"
            if _text(event.get("role")) == "candidate":
                relation = "candidate_extension_of"
            elif _text(event.get("role")) in {"background", "counterevidence"}:
                relation = "background_for"
            _add_relation(
                edges,
                source=f"event:{event_id}",
                target=f"asset:{asset}",
                relation=relation,
                source_ids=[event_id, *event.get("source_ids", [])],
                event_ids=[event_id],
                observation_ids=event.get("observation_ids") or [],
                boundary=bool(boundary or event.get("boundary")),
            )


def _indicator_type_for(value: str, *, field_name: str = "") -> str:
    text = _text(value)
    if _is_ip(text):
        return "ip"
    if "." in text and not any(char in text for char in " /\\"):
        return "domain"
    if _text(field_name).lower() in {"fingerprint", "ja3", "ja4", "ssl_sha1", "cert_sha1"}:
        return "fingerprint"
    return "indicator"


def _collect_indicator_values(incident_state: Dict[str, Any], finalized: Dict[str, Any], event_records: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    values: Dict[str, Dict[str, Any]] = {}
    entities = _as_dict(finalized.get("entities") or incident_state.get("entities"))
    scope = _as_dict(finalized.get("scope") or incident_state.get("scope"))

    def add(value: Any, *, source_kind: str = "", field_name: str = "", event_id: str = "", observation_id: str = "") -> None:
        text = _text(value)
        if not text:
            return
        indicator_type = _indicator_type_for(text, field_name=field_name)
        node_id = f"indicator:{text}"
        entry = values.setdefault(
            node_id,
            {
                "value": text,
                "indicator_type": indicator_type,
                "source_kinds": [],
                "event_ids": [],
                "observation_ids": [],
            },
        )
        entry["source_kinds"] = _dedupe([*entry["source_kinds"], source_kind or indicator_type])
        if event_id:
            entry["event_ids"] = _dedupe([*entry["event_ids"], event_id])
        if observation_id:
            entry["observation_ids"] = _dedupe([*entry["observation_ids"], observation_id])

    for event_id, event in event_records.items():
        add(event.get("dst_ip"), source_kind="event", field_name="dst_ip", event_id=event_id, observation_id=",".join(event.get("observation_ids") or []))
        add(event.get("src_ip"), source_kind="event", field_name="src_ip", event_id=event_id, observation_id=",".join(event.get("observation_ids") or []))
        add(event.get("domain"), source_kind="event", field_name="domain", event_id=event_id, observation_id=",".join(event.get("observation_ids") or []))
        add(event.get("fingerprint"), source_kind="event", field_name="fingerprint", event_id=event_id, observation_id=",".join(event.get("observation_ids") or []))

    for value in _dedupe(_as_list(entities.get("external_ips"))):
        add(value, source_kind="entity", field_name="external_ips")
    for value in _dedupe(_as_list(entities.get("domains"))):
        add(value, source_kind="entity", field_name="domains")
    for value in _dedupe(_as_list(entities.get("families"))):
        add(value, source_kind="entity", field_name="families")
    for value in _dedupe(_as_list(scope.get("primary_external_indicators")) + _as_list(scope.get("contextual_external_indicators")) + _as_list(scope.get("external_indicators"))):
        add(value, source_kind="scope", field_name="external_indicators")
    trigger_fingerprint = _as_dict(seed_event := finalized.get("seed") or incident_state.get("seed") or {})
    add(((trigger_fingerprint.get("trigger_fingerprint") or {}).get("value") if isinstance(trigger_fingerprint.get("trigger_fingerprint"), dict) else ""), source_kind="seed", field_name="fingerprint")
    return values


def _build_indicator_nodes(
    incident_state: Dict[str, Any],
    finalized: Dict[str, Any],
    nodes: Dict[str, Dict[str, Any]],
    edges: Dict[str, Dict[str, Any]],
    event_records: Dict[str, Dict[str, Any]],
) -> None:
    indicator_values = _collect_indicator_values(incident_state, finalized, event_records)
    for node_id, payload in sorted(indicator_values.items(), key=lambda item: item[0]):
        value = _text(payload.get("value"))
        if not value:
            continue
        indicator_type = _text(payload.get("indicator_type") or "indicator")
        source_kinds = _dedupe(_as_list(payload.get("source_kinds")))
        event_ids = _dedupe(_as_list(payload.get("event_ids")))
        observation_ids = _dedupe(_as_list(payload.get("observation_ids")))
        boundary = any(kind in {"entity", "scope"} for kind in source_kinds) and indicator_type in {"ip", "domain", "fingerprint"}
        _add_node(
            nodes,
            {
                "node_id": node_id,
                "node_type": "indicator",
                "label": value,
                "status": "boundary" if boundary else "context",
                "boundary": boundary,
                "source_ids": [*event_ids, *observation_ids],
                "event_ids": event_ids,
                "observation_ids": observation_ids,
                "roles": source_kinds,
                "properties": {"indicator_type": indicator_type, "source_kinds": source_kinds},
            },
        )
        for event_id in event_ids:
            event = event_records.get(event_id) or {}
            relation = "supports"
            if _text(event.get("role")) == "candidate":
                relation = "candidate_extension_of"
            elif _text(event.get("role")) in {"background", "counterevidence"}:
                relation = "background_for"
            _add_relation(
                edges,
                source=f"event:{event_id}",
                target=node_id,
                relation=relation,
                source_ids=[event_id, *event.get("source_ids", [])],
                event_ids=[event_id],
                observation_ids=event.get("observation_ids") or [],
                boundary=bool(boundary or event.get("boundary")),
            )


def _build_hypothesis_nodes(
    incident_state: Dict[str, Any],
    finalized: Dict[str, Any],
    nodes: Dict[str, Dict[str, Any]],
) -> None:
    delivery_decision = _as_dict(finalized.get("delivery_decision") or incident_state.get("delivery_decision"))
    readiness = _as_dict(finalized.get("readiness") or incident_state.get("readiness"))
    for spec in _hypothesis_specs():
        _add_node(
            nodes,
            {
                "node_id": f"hypothesis:{spec['hypothesis_id']}",
                "node_type": "hypothesis",
                "label": spec["claim"],
                "status": spec["status"],
                "boundary": False,
                "source_ids": [],
                "event_ids": [],
                "observation_ids": [],
                "gap_ids": [],
                "action_ids": [],
                "roles": [spec["hypothesis_id"]],
                "properties": {
                    "hypothesis_id": spec["hypothesis_id"],
                    "claim": spec["claim"],
                    "priority": spec["priority"],
                    "delivery_status": _text(delivery_decision.get("status")),
                    "ready_for_delivery": bool(readiness.get("ready_for_delivery")),
                },
            },
        )


def _connect_events_to_hypotheses(
    event_records: Dict[str, Dict[str, Any]],
    edges: Dict[str, Dict[str, Any]],
    *,
    delivery_status: str,
) -> None:
    for event_id, event in event_records.items():
        role = _text(event.get("role")).lower()
        source_node = f"event:{event_id}"
        source_ids = [event_id, *event.get("source_ids", [])]
        observation_ids = event.get("observation_ids") or []
        if role in {"seed", "confirmed", "supporting"}:
            _add_relation(
                edges,
                source=source_node,
                target="hypothesis:confirmed_main_chain",
                relation="supports",
                source_ids=source_ids,
                event_ids=[event_id],
                observation_ids=observation_ids,
            )
            _add_relation(
                edges,
                source=source_node,
                target="hypothesis:false_positive_or_noise",
                relation="refutes" if delivery_status == "confirmed_incident" else "supports",
                source_ids=source_ids,
                event_ids=[event_id],
                observation_ids=observation_ids,
            )
        elif role == "candidate":
            _add_relation(
                edges,
                source=source_node,
                target="hypothesis:candidate_spread",
                relation="supports",
                source_ids=source_ids,
                event_ids=[event_id],
                observation_ids=observation_ids,
                boundary=True,
            )
            _add_relation(
                edges,
                source=source_node,
                target="hypothesis:false_positive_or_noise",
                relation="refutes",
                source_ids=source_ids,
                event_ids=[event_id],
                observation_ids=observation_ids,
                boundary=True,
            )
        elif role in {"background", "counterevidence"}:
            _add_relation(
                edges,
                source=source_node,
                target="hypothesis:benign_or_shared_infra_alternative",
                relation="supports",
                source_ids=source_ids,
                event_ids=[event_id],
                observation_ids=observation_ids,
                boundary=True,
            )
            _add_relation(
                edges,
                source=source_node,
                target="hypothesis:confirmed_main_chain",
                relation="refutes",
                source_ids=source_ids,
                event_ids=[event_id],
                observation_ids=observation_ids,
                boundary=True,
            )
            _add_relation(
                edges,
                source=source_node,
                target="hypothesis:candidate_spread",
                relation="refutes",
                source_ids=source_ids,
                event_ids=[event_id],
                observation_ids=observation_ids,
                boundary=True,
            )


def _gap_nodes_and_actions(
    incident_state: Dict[str, Any],
    finalized: Dict[str, Any],
    nodes: Dict[str, Dict[str, Any]],
    edges: Dict[str, Dict[str, Any]],
) -> None:
    gap_rows = _gap_rows_with_delivery_overlay(incident_state, finalized)
    action_nodes: Dict[str, Dict[str, Any]] = {}
    for index, raw_gap in enumerate(gap_rows):
        gap = _as_dict(raw_gap)
        gap_id = _text(gap.get("id") or gap.get("gap_id") or _stable_id("gap", index))
        target_hypotheses = _gap_target_hypotheses(gap)
        target_actions = _gap_target_actions(gap, target_hypotheses)
        boundary = _text(gap.get("status")).lower() not in {"closed", ""}
        _add_node(
            nodes,
            {
                "node_id": f"gap:{gap_id}",
                "node_type": "gap",
                "label": _text(gap.get("question") or gap.get("status_reason") or gap_id),
                "status": _text(gap.get("status") or "open"),
                "boundary": bool(boundary),
                "source_ids": [gap_id],
                "event_ids": [],
                "observation_ids": [],
                "gap_ids": [gap_id],
                "roles": [gap.get("gap_type") or "gap"],
                "properties": {
                    "question": _text(gap.get("question")),
                    "status_reason": _text(gap.get("status_reason")),
                    "priority": _text(gap.get("priority")),
                    "delivery_blocking": bool(gap.get("delivery_blocking")),
                    "actionable_now": bool(gap.get("actionable_now")),
                    "blocks_delivery_now": bool(gap.get("blocks_delivery_now", gap.get("delivery_blocking"))),
                    "reportable_only": bool(gap.get("reportable_only")),
                    "target_hypotheses": target_hypotheses,
                    "target_actions": target_actions,
                },
            },
        )
        for hypothesis_id in target_hypotheses:
            _add_relation(
                edges,
                source=f"gap:{gap_id}",
                target=f"hypothesis:{hypothesis_id}",
                relation="limits",
                source_ids=[gap_id],
                event_ids=[],
                observation_ids=[],
                boundary=True,
                properties={"gap_id": gap_id},
            )
        for tool_name in target_actions:
            action_node = action_nodes.setdefault(
                tool_name,
                {
                    "tool_name": tool_name,
                    "gap_ids": [],
                    "target_hypotheses": [],
                    "reason_parts": [],
                    "boundary": False,
                    "candidate_kind": "planned",
                },
            )
            action_node["gap_ids"] = _dedupe([*action_node["gap_ids"], gap_id])
            action_node["target_hypotheses"] = _dedupe([*action_node["target_hypotheses"], *target_hypotheses])
            action_node["reason_parts"] = _dedupe(
                [
                    *action_node["reason_parts"],
                    _text(gap.get("question")),
                    _text(gap.get("status_reason")),
                ]
            )
    if not action_nodes:
        event_records = _as_list(finalized.get("annotated_events") or incident_state.get("annotated_events"))
        event_roles = {_text((event or {}).get("role") or (event or {}).get("status")) for event in event_records}
        if any(role == "candidate" for role in event_roles):
            action_nodes["search_related_events"] = {
                "tool_name": "search_related_events",
                "gap_ids": [],
                "target_hypotheses": ["candidate_spread"],
                "reason_parts": ["candidate events exist but no gap-backed action was compiled."],
                "boundary": False,
                "candidate_kind": "fallback",
            }
        if any(role in {"background", "counterevidence"} for role in event_roles):
            action_nodes.setdefault(
                "check_counterevidence",
                {
                    "tool_name": "check_counterevidence",
                    "gap_ids": [],
                    "target_hypotheses": ["benign_or_shared_infra_alternative"],
                    "reason_parts": ["background or counterevidence events exist but no gap-backed action was compiled."],
                    "boundary": False,
                    "candidate_kind": "fallback",
                },
            )
    for tool_name, payload in sorted(action_nodes.items(), key=lambda item: item[0]):
        target_hypotheses = _dedupe(_as_list(payload.get("target_hypotheses")))
        gap_ids = _dedupe(_as_list(payload.get("gap_ids")))
        reason = "; ".join(_dedupe(_as_list(payload.get("reason_parts"))))
        node_id = f"action:{tool_name}"
        _add_node(
            nodes,
            {
                "node_id": node_id,
                "node_type": "action",
                "label": tool_name,
                "status": "candidate",
                "boundary": False,
                "source_ids": gap_ids,
                "event_ids": [],
                "observation_ids": [],
                "gap_ids": gap_ids,
                "action_ids": [node_id],
                "roles": ["candidate_action"],
                "properties": {
                    "tool_name": tool_name,
                    "target_gap_ids": gap_ids,
                    "target_hypotheses": target_hypotheses,
                    "reason": reason,
                    "candidate_kind": _text(payload.get("candidate_kind") or "planned"),
                },
            },
        )
        for hypothesis_id in target_hypotheses:
            _add_relation(
                edges,
                source=node_id,
                target=f"hypothesis:{hypothesis_id}",
                relation="suggests_next",
                source_ids=gap_ids or [tool_name],
                boundary=False,
                properties={"tool_name": tool_name},
            )


def _runtime_summary(
    seed_event: Dict[str, Any],
    session_state: Dict[str, Any],
    incident_state: Dict[str, Any],
    finalized: Dict[str, Any],
    event_records: Dict[str, Dict[str, Any]],
    nodes: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    readiness = _as_dict(finalized.get("readiness") or incident_state.get("readiness"))
    delivery_decision = _as_dict(finalized.get("delivery_decision") or incident_state.get("delivery_decision"))
    gap_rows = _gap_rows_with_delivery_overlay(incident_state, finalized)
    open_gaps = [gap for gap in gap_rows if _text(gap.get("status")).lower() != "closed"]
    candidate_event_ids = [event_id for event_id, event in event_records.items() if _text(event.get("role")) == "candidate"]
    background_event_ids = [event_id for event_id, event in event_records.items() if _text(event.get("role")) in {"background", "counterevidence"}]
    support_event_ids = [event_id for event_id, event in event_records.items() if _text(event.get("role")) in {"seed", "confirmed", "supporting"}]
    blocking_gap_ids = [
        gap_id
        for gap_id, gap in ((str(item.get("id") or item.get("gap_id") or "").strip(), item) for item in open_gaps)
        if bool(gap.get("delivery_blocking"))
        and bool(gap.get("actionable_now"))
        and bool(gap.get("blocks_delivery_now", gap.get("delivery_blocking")))
    ]
    reportable_gap_ids = [
        gap_id
        for gap_id, gap in ((str(item.get("id") or item.get("gap_id") or "").strip(), item) for item in open_gaps)
        if gap_id
        and (
            bool(gap.get("reportable_only"))
            or bool(gap.get("reportable_if_unresolved"))
            or _text(gap.get("status")).lower() in {"reportable_unresolved", "unresolved_but_deliverable", "open_unaddressable"}
            or not bool(gap.get("blocks_delivery_now", gap.get("delivery_blocking")))
        )
    ]
    action_ids = [node_id for node_id, node in nodes.items() if _text(node.get("node_type")) == "action"]
    return {
        "seed_event_id": _normalize_event_id(seed_event, 0),
        "step_index": int(session_state.get("step_index") or 0),
        "delivery_status": _text(delivery_decision.get("status")),
        "ready_for_delivery": bool(readiness.get("ready_for_delivery")),
        "candidate_event_ids": candidate_event_ids,
        "background_event_ids": background_event_ids,
        "support_event_ids": support_event_ids,
        "open_gap_ids": [str(item.get("id") or item.get("gap_id") or "").strip() for item in open_gaps if str(item.get("id") or item.get("gap_id") or "").strip()],
        "blocking_gap_ids": blocking_gap_ids,
        "reportable_gap_ids": _dedupe(reportable_gap_ids),
        "action_ids": action_ids,
        "event_count": len(event_records),
        "candidate_count": len(candidate_event_ids),
        "background_count": len(background_event_ids),
    }


def build_investigation_graph(
    seed_event: Dict[str, Any],
    session_state: Dict[str, Any],
    incident_state: Dict[str, Any],
    finalized: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    finalized = _as_dict(finalized)
    seed_event = _as_dict(seed_event)
    session_state = _as_dict(session_state)
    incident_state = _as_dict(incident_state)
    nodes: Dict[str, Dict[str, Any]] = {}
    edges: Dict[str, Dict[str, Any]] = {}
    event_records = _build_event_nodes(
        seed_event,
        finalized,
        incident_state,
        nodes,
        edges,
        delivery_status=_text(_as_dict(finalized.get("delivery_verdict") or incident_state.get("delivery_verdict")).get("status")),
    )
    _build_asset_nodes(incident_state, finalized, nodes, edges, event_records)
    _build_indicator_nodes(incident_state, finalized, nodes, edges, event_records)
    _build_hypothesis_nodes(incident_state, finalized, nodes)
    _connect_events_to_hypotheses(
        event_records,
        edges,
        delivery_status=_text(_as_dict(finalized.get("delivery_verdict") or incident_state.get("delivery_verdict")).get("status")),
    )
    _gap_nodes_and_actions(incident_state, finalized, nodes, edges)
    node_list = sorted(nodes.values(), key=lambda item: _text(item.get("node_id")))
    edge_list = sorted(edges.values(), key=lambda item: _text(item.get("edge_id")))
    summary = _runtime_summary(seed_event, session_state, incident_state, finalized, event_records, nodes)
    graph = {
        "schema_version": INVESTIGATION_GRAPH_SCHEMA_VERSION,
        "seed": seed_event,
        "runtime_summary": summary,
        "nodes": node_list,
        "edges": edge_list,
        "graph_stats": {
            "node_count": len(node_list),
            "edge_count": len(edge_list),
            "event_node_count": len([item for item in node_list if _text(item.get("node_type")) == "event"]),
            "asset_node_count": len([item for item in node_list if _text(item.get("node_type")) == "asset"]),
            "indicator_node_count": len([item for item in node_list if _text(item.get("node_type")) == "indicator"]),
            "hypothesis_node_count": len([item for item in node_list if _text(item.get("node_type")) == "hypothesis"]),
            "gap_node_count": len([item for item in node_list if _text(item.get("node_type")) == "gap"]),
            "action_node_count": len([item for item in node_list if _text(item.get("node_type")) == "action"]),
            "event_count": summary["event_count"],
            "candidate_event_count": summary["candidate_count"],
            "background_event_count": summary["background_count"],
        },
    }
    graph["hypothesis_board"] = build_investigation_hypothesis_board(graph)
    return graph


def build_investigation_hypothesis_board(graph: Dict[str, Any]) -> Dict[str, Any]:
    graph = _as_dict(graph)
    nodes = [_as_dict(item) for item in _as_list(graph.get("nodes"))]
    edges = [_as_dict(item) for item in _as_list(graph.get("edges"))]
    runtime_summary = _as_dict(graph.get("runtime_summary"))
    node_map = _node_index(nodes)

    def node_for(node_id: str) -> Dict[str, Any]:
        return _as_dict(node_map.get(node_id))

    hypotheses: List[Dict[str, Any]] = []
    for node in nodes:
        if _text(node.get("node_type")) != "hypothesis":
            continue
        node_id = _text(node.get("node_id"))
        hypothesis_id = _text((node.get("properties") or {}).get("hypothesis_id") or node_id.split(":", 1)[-1])
        incoming_support = [edge for edge in edges if _text(edge.get("target")) == node_id and _text(edge.get("relation")) == "supports"]
        incoming_refute = [edge for edge in edges if _text(edge.get("target")) == node_id and _text(edge.get("relation")) == "refutes"]
        incoming_limits = [edge for edge in edges if _text(edge.get("target")) == node_id and _text(edge.get("relation")) == "limits"]
        incoming_actions = [edge for edge in edges if _text(edge.get("target")) == node_id and _text(edge.get("relation")) == "suggests_next"]

        support_event_ids = _dedupe(
            [
                *(_text(event_id) for edge in incoming_support for event_id in _as_list(edge.get("event_ids"))),
                *(_text(source_id) for edge in incoming_support for source_id in _as_list(edge.get("source_ids"))),
                *(_text(event_id) for edge in incoming_support for event_id in _as_list(node_for(_text(edge.get("source"))).get("event_ids"))),
            ]
        )
        refute_event_ids = _dedupe(
            [
                *(_text(event_id) for edge in incoming_refute for event_id in _as_list(edge.get("event_ids"))),
                *(_text(source_id) for edge in incoming_refute for source_id in _as_list(edge.get("source_ids"))),
                *(_text(event_id) for edge in incoming_refute for event_id in _as_list(node_for(_text(edge.get("source"))).get("event_ids"))),
            ]
        )
        support_observation_ids = _dedupe(
            [
                *(_text(obs_id) for edge in incoming_support for obs_id in _as_list(edge.get("observation_ids"))),
                *(_text(obs_id) for edge in incoming_support for obs_id in _as_list(node_for(_text(edge.get("source"))).get("observation_ids"))),
            ]
        )
        refute_observation_ids = _dedupe(
            [
                *(_text(obs_id) for edge in incoming_refute for obs_id in _as_list(edge.get("observation_ids"))),
                *(_text(obs_id) for edge in incoming_refute for obs_id in _as_list(node_for(_text(edge.get("source"))).get("observation_ids"))),
            ]
        )
        gap_ids = _dedupe(
            [
                *(_text(edge.get("source")).split(":", 1)[-1] for edge in incoming_limits if _text(edge.get("source"))),
                *(_text(gap_id) for edge in incoming_limits for gap_id in _as_list(node_for(_text(edge.get("source"))).get("gap_ids"))),
            ]
        )
        candidate_action_ids = _dedupe(
            [
                *(_text(edge.get("source")) for edge in incoming_actions),
                *(_text(action_id) for edge in incoming_actions for action_id in _as_list(node_for(_text(edge.get("source"))).get("action_ids"))),
            ]
        )
        support_score = len(support_event_ids) + len(support_observation_ids)
        refute_score = len(refute_event_ids) + len(refute_observation_ids)
        gap_score = len(gap_ids)
        action_score = len(candidate_action_ids)
        status = _text(node.get("status") or "open")
        delivery_status = _text(runtime_summary.get("delivery_status"))
        ready_for_delivery = bool(runtime_summary.get("ready_for_delivery"))

        if hypothesis_id == "false_positive_or_noise" and delivery_status == "confirmed_incident":
            status = "closed"
        elif hypothesis_id == "confirmed_main_chain" and ready_for_delivery and not gap_score and not action_score and support_score > 0:
            status = "closed"
        elif hypothesis_id == "insufficient_evidence_limits" and not gap_score:
            status = "closed" if ready_for_delivery else ("weakened" if refute_score > 0 else "open")
        elif support_score > refute_score and support_score > 0:
            status = "supported"
        elif refute_score > support_score and refute_score > 0:
            status = "weakened"
        elif gap_score or action_score:
            status = "open"
        else:
            status = "open"

        why_next_map = {
            "confirmed_main_chain": "Keep the main chain tightly bounded and avoid promoting candidate evidence to confirmed without grounding.",
            "candidate_spread": "Validate whether candidate spread is real before merging it into the confirmed scope.",
            "benign_or_shared_infra_alternative": "Continue checking shared infrastructure and background explanations before stronger attribution.",
            "insufficient_evidence_limits": "Close the remaining gaps before claiming a stronger conclusion.",
            "false_positive_or_noise": "Only revisit this hypothesis if the seed remains weak after the main chain is checked.",
        }
        hypotheses.append(
            {
                "hypothesis_id": hypothesis_id,
                "claim": _text(node.get("label") or (node.get("properties") or {}).get("claim") or hypothesis_id),
                "status": status,
                "priority": int((node.get("properties") or {}).get("priority") or 0),
                "support_event_ids": support_event_ids,
                "support_observation_ids": support_observation_ids,
                "refute_event_ids": refute_event_ids,
                "refute_observation_ids": refute_observation_ids,
                "gap_ids": gap_ids,
                "candidate_action_ids": candidate_action_ids,
                "last_updated_round": int(runtime_summary.get("step_index") or 0),
                "why_next": why_next_map.get(hypothesis_id, "Continue using explicit evidence deltas to refine the hypothesis."),
            }
        )

    hypotheses.sort(key=lambda item: (int(item.get("priority") or 0), str(item.get("hypothesis_id") or "")))
    return {
        "schema_version": INVESTIGATION_HYPOTHESIS_BOARD_SCHEMA_VERSION,
        "graph_schema_version": _text(graph.get("schema_version")),
        "last_updated_round": int(runtime_summary.get("step_index") or 0),
        "hypotheses": hypotheses,
    }
