from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Tuple

from .contracts import unique_preserve_order


EVENT_TOOL_NAMES = {"search_seed_context", "search_related_events", "expand_asset_scope"}
STAGE_LABELS = {
    "initial-access": "初始访问",
    "execution": "执行",
    "command-and-control": "命令与控制",
    "lateral-movement": "横向移动",
    "credential-access": "凭据获取",
    "persistence": "持久化",
    "discovery": "侦察",
    "collection": "收集",
    "exfiltration": "数据外传",
    "impact": "破坏",
}
OBJECT_ROLE_LABELS = {
    "seed_asset": "种子资产",
    "affected_asset": "已确认受影响资产",
    "related_asset": "待确认关联资产",
    "core_external_indicator": "核心外部基础设施",
    "contextual_indicator": "背景/上下文指标",
    "seed_fingerprint": "种子命中指纹",
    "family_hint": "家族/工具提示",
    "expansion_candidate": "扩展查询候选",
    "related_internal_address": "关联内部地址",
}
OBJECT_ROLE_PRIORITY = {
    "seed_asset": 0,
    "affected_asset": 1,
    "related_asset": 2,
    "core_external_indicator": 3,
    "contextual_indicator": 4,
    "seed_fingerprint": 5,
    "family_hint": 6,
    "related_internal_address": 7,
    "expansion_candidate": 8,
}
OBJECT_TYPE_LABELS = {
    "asset": "资产",
    "IP": "IP",
    "internal_ip": "内网 IP",
    "domain": "域名",
    "URL": "URL",
    "JA3": "JA3",
    "JA4": "JA4",
    "SSL_SHA1": "SSL 指纹",
    "CERT_SHA1": "证书指纹",
    "fingerprint": "指纹",
    "family": "家族提示",
    "indicator": "指标",
    "user": "账号",
}
GAP_STATUS_LABELS = {
    "open": "待补",
    "partially_closed": "部分收敛",
    "unresolved_but_deliverable": "可交付但未完全闭合",
    "closed": "已闭合",
}


def _dedupe_text(values: List[Any]) -> List[str]:
    seen: set[str] = set()
    result: List[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def _join_items(values: List[Any]) -> str:
    items = [str(value or "").strip() for value in values if str(value or "").strip()]
    return "、".join(items) if items else "未识别"


def _stage_label(stage: str) -> str:
    text = str(stage or "").strip()
    return STAGE_LABELS.get(text, text)


def _format_stage_list(stages: List[Any]) -> str:
    return _join_items([_stage_label(str(stage or "").strip()) for stage in list(stages or []) if str(stage or "").strip()])


def _reader_clean_text(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    replacements = {
        "command-and-control": "命令与控制",
        "initial-access": "初始访问",
        "monitor_only": "持续观察",
        "needs_review": "待人工复核",
        "confirmed_incident": "确认事件",
        "seed alert": "种子告警",
        "seed 指标": "种子告警涉及的指标",
        "pivot": "枢纽",
        "dst_ip": "目标 IP",
        "JA4": "通信指纹",
        "JA3": "通信指纹",
        "事件簇": "当前关联事件",
        "自动结论": "当前结论",
        "主支撑信号": "主要支撑迹象",
    }
    for source, target in replacements.items():
        text = text.replace(source, target)
    return text


def _meaningful_family_hint(text: str) -> str:
    hint = str(text or "").strip()
    lowered = hint.lower()
    if not hint:
        return ""
    if lowered.startswith("unknown"):
        return ""
    if lowered in {"suspicious", "unknown suspicious tls fingerprint"}:
        return ""
    if lowered in {
        "suspicious shared-infra beacon candidate",
        "backup traffic outlier candidate",
    }:
        return ""
    if "candidate" in lowered and "possible" not in lowered:
        return ""
    return hint


def _is_ip_text(value: str) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _is_internal_ip_text(value: str) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False
    if ip.version == 4:
        private_networks = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        ]
        return any(ip in network for network in private_networks)
    return bool(ip in ipaddress.ip_network("fc00::/7"))


def _indicator_type_from_value(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return "indicator"
    upper = text.upper()
    if upper.startswith("JA3 "):
        return "JA3"
    if upper.startswith("JA4 "):
        return "JA4"
    if _is_ip_text(text):
        return "internal_ip" if _is_internal_ip_text(text) else "IP"
    if text.startswith(("http://", "https://")):
        return "URL"
    if "." in text and "/" not in text and " " not in text:
        return "domain"
    return "indicator"


def _object_role_label(role: str) -> str:
    return OBJECT_ROLE_LABELS.get(str(role or "").strip(), str(role or "").strip() or "未命名角色")


def _object_type_label(object_type: str) -> str:
    return OBJECT_TYPE_LABELS.get(str(object_type or "").strip(), str(object_type or "").strip() or "对象")


def _gap_status_for_report(status: str) -> str:
    text = str(status or "").strip()
    if text == "closed":
        return "closed"
    if text == "reportable_unresolved":
        return "unresolved_but_deliverable"
    if text in {"stalled", "open_unaddressable"}:
        return "partially_closed"
    return "open"


def _gap_status_label(status: str) -> str:
    return GAP_STATUS_LABELS.get(str(status or "").strip(), str(status or "").strip() or "待补")


def _gap_followup_text(gap: Dict[str, Any]) -> str:
    return _reader_clean_text(
        str(gap.get("status_reason") or "").strip()
        or str(gap.get("question") or "").strip()
        or "当前需继续补充相关证据。"
    )


def _observation_provenance(observation: Dict[str, Any]) -> str:
    relation = str(observation.get("relation") or "").strip().lower()
    source_type = str(observation.get("source_type") or "").strip().lower()
    tool_name = str(observation.get("tool_name") or "").strip().lower()
    if relation == "counterevidence" or tool_name == "check_counterevidence":
        return "counterevidence"
    if source_type.startswith("trace_store"):
        return "local_observation"
    if source_type.startswith("internal_digest"):
        return "analyst_note"
    if source_type.startswith("intel_tool") or source_type.startswith("page_content") or source_type.startswith("candidate_grounding"):
        return "external_intel"
    if relation == "candidate":
        return "unverified_inference"
    return "derived_relation"


def _hypothesis_view_from_parts(
    hypothesis: Dict[str, Any],
    summary: Dict[str, Any],
    decision_basis: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "stages": list(hypothesis.get("stages") or summary.get("stage_labels") or []),
        "primary": str(decision_basis.get("focus_statement") or "").strip(),
        "positive_summary": str(decision_basis.get("positive_summary") or "").strip(),
        "negative_summary": str(decision_basis.get("negative_summary") or "").strip(),
    }


def _hypothesis_view(incident: Dict[str, Any]) -> Dict[str, Any]:
    return _hypothesis_view_from_parts(
        dict(incident.get("hypothesis") or {}),
        dict(incident.get("summary") or {}),
        dict(incident.get("decision_basis") or {}),
    )


def _coverage_view_from_parts(entities: Dict[str, Any], scope: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "seed_asset": str(entities.get("seed_asset") or "").strip(),
        "suspected_assets": unique_preserve_order(entities.get("suspected_assets") or []),
        "related_assets": unique_preserve_order(entities.get("related_assets") or []),
        "primary_external_indicators": unique_preserve_order(scope.get("primary_external_indicators") or []),
        "contextual_external_indicators": unique_preserve_order(scope.get("contextual_external_indicators") or []),
        "event_count": int(scope.get("event_count") or 0),
        "time_window": dict(scope.get("time_window") or {}),
        "current_boundary": str(scope.get("current_boundary") or "").strip(),
    }


def _coverage_view(incident: Dict[str, Any]) -> Dict[str, Any]:
    return _coverage_view_from_parts(
        dict(incident.get("entities") or {}),
        dict(incident.get("scope") or {}),
    )


def _event_projection(event: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": str(event.get("id") or "").strip(),
        "role": str(event.get("role") or "").strip(),
        "asset_id": str(event.get("asset_id") or "").strip(),
        "kind": str(event.get("kind") or "").strip(),
        "ts": str(event.get("ts") or "").strip(),
        "summary": str(event.get("summary") or "").strip(),
        "domain": str(event.get("domain") or "").strip(),
        "dst_ip": str(event.get("dst_ip") or "").strip(),
        "stages": list(event.get("stages") or []),
        "tags": list(event.get("tags") or []),
        "classification": str(event.get("classification") or "").strip(),
    }


def _candidate_events_from_cluster_events(cluster_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [
        _event_projection(event)
        for event in list(cluster_events or [])
        if str(event.get("role") or "").strip() == "candidate"
    ]


def _candidate_events(incident: Dict[str, Any]) -> List[Dict[str, Any]]:
    return _candidate_events_from_cluster_events(list(((incident.get("cluster") or {}).get("events")) or []))


def _confirmed_events_from_cluster_events(cluster_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [
        _event_projection(event)
        for event in list(cluster_events or [])
        if str(event.get("role") or "").strip() != "candidate"
    ]


def _confirmed_events(incident: Dict[str, Any]) -> List[Dict[str, Any]]:
    return _confirmed_events_from_cluster_events(list(((incident.get("cluster") or {}).get("events")) or []))


def _family_context_from_parts(
    seed: Dict[str, Any],
    entities: Dict[str, Any],
    incident_state: Dict[str, Any],
    decision_basis: Dict[str, Any],
    hypothesis: Dict[str, Any],
) -> Dict[str, Any] | None:
    hints = _dedupe_text(
        [_meaningful_family_hint((((seed.get("enrichment") or {}).get("info")) or ""))]
        + [_meaningful_family_hint(item) for item in list(entities.get("families") or [])]
    )
    if not hints:
        return None
    background_observation_ids = [
        str(item.get("observation_id") or "").strip()
        for item in list(incident_state.get("observations") or [])
        if str(item.get("tool_name") or "").strip() not in EVENT_TOOL_NAMES
    ]
    if not background_observation_ids:
        background_observation_ids = list((decision_basis.get("positive_observation_ids")) or [])

    primary_hint = hints[0]
    stage_labels = list((hypothesis.get("stages")) or [])
    stage_text = _format_stage_list(stage_labels)
    if stage_labels:
        summary = f"当前可获得的背景提示主要来自 seed 告警自带的家族/工具描述：{primary_hint}。它与本案已经观察到的阶段形态 {stage_text} 基本一致，更适合作为解释当前事件链的辅助背景。"
    else:
        summary = f"当前可获得的背景提示主要来自 seed 告警自带的家族/工具描述：{primary_hint}。它可以帮助理解为什么该告警被优先纳入调查，但不足以单独决定最终结论。"
    return {
        "hint": primary_hint,
        "summary": summary,
        "observation_ids": background_observation_ids,
        "limits": "这类背景提示更适合帮助理解攻击链或工具形态，不应直接当作样本级确认或强归因结论。",
    }


def _family_context(incident: Dict[str, Any]) -> Dict[str, Any] | None:
    return _family_context_from_parts(
        dict(incident.get("seed") or {}),
        dict(incident.get("entities") or {}),
        dict(incident.get("incident_state") or {}),
        dict(incident.get("decision_basis") or {}),
        dict(incident.get("hypothesis") or {}),
    )


def _collect_observations(incident_state: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    observations: List[Dict[str, Any]] = []
    observation_map: Dict[str, Dict[str, Any]] = {}
    for index, raw in enumerate(list(incident_state.get("observations") or []), start=1):
        observation_id = str(raw.get("observation_id") or "").strip() or f"obs-{index:03d}"
        claim_texts = _dedupe_text(
            [
                str((item.get("text") if isinstance(item, dict) else item) or "").strip()
                for item in list(raw.get("claims") or [])
            ]
            + [str(raw.get("summary") or "").strip()]
        )
        derived_entities = {
            str(key): _dedupe_text([str(item or "").strip() for item in list(values or []) if str(item or "").strip()])
            for key, values in dict(raw.get("derived_entities") or {}).items()
            if list(values or [])
        }
        event_ids = _dedupe_text(
            [str(item.get("id") or "").strip() for item in list(raw.get("events") or []) if str(item.get("id") or "").strip()]
        )
        relation_event_ids = _dedupe_text(list(raw.get("relation_event_ids") or []) or event_ids)
        checked_event_ids = _dedupe_text(list(raw.get("checked_event_ids") or []) or event_ids)
        boundary_event_ids = _dedupe_text(list(raw.get("boundary_event_ids") or []))
        normalized = {
            "id": observation_id,
            "observation_id": observation_id,
            "tool_name": str(raw.get("tool_name") or "").strip(),
            "relation": str(raw.get("relation") or "").strip() or "context",
            "grounding_status": str(raw.get("grounding_status") or "").strip(),
            "source_type": str(raw.get("source_type") or "").strip(),
            "source_ref": str(raw.get("source_ref") or "").strip(),
            "summary": str(raw.get("summary") or "").strip() or "无摘要",
            "status": str(raw.get("status") or "").strip() or "unknown",
            "raw_status": str(raw.get("status") or "").strip() or "unknown",
            "provenance": _observation_provenance(raw),
            "event_ids": relation_event_ids,
            "checked_event_ids": checked_event_ids,
            "boundary_event_ids": boundary_event_ids,
            "derived_entities": derived_entities,
            "claim_texts": claim_texts,
            "confidence": raw.get("confidence"),
        }
        observations.append(normalized)
        observation_map[observation_id] = normalized
    return observations, observation_map


def _collect_claims_from_ledger(
    evidence_ledger: List[Dict[str, Any]],
    observation_map: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    claims: List[Dict[str, Any]] = []
    seen_claims: set[str] = set()
    for item in list(evidence_ledger or []):
        observation_id = str(item.get("observation_id") or "").strip()
        observation = observation_map.get(observation_id, {})
        relation = str(item.get("relation") or observation.get("relation") or "").strip() or "context"
        claim_texts = _dedupe_text(
            [str(text or "").strip() for text in list(item.get("claim_texts") or []) if str(text or "").strip()]
            + list(observation.get("claim_texts") or [])
            + [str(item.get("summary") or "").strip()]
        )
        for text in claim_texts:
            signature = f"{observation_id}|{relation}|{text}"
            if signature in seen_claims:
                continue
            seen_claims.add(signature)
            claim_id = f"CL-{len(claims) + 1:02d}"
            source_refs = _dedupe_text(
                [
                    str(item.get("source_ref") or "").strip(),
                    str(observation.get("source_ref") or "").strip(),
                ]
            )
            claims.append(
                {
                    "claim_id": claim_id,
                    "text": text,
                    "relation": relation,
                    "provenance": str(observation.get("provenance") or _observation_provenance(item)).strip(),
                    "observation_ids": [observation_id] if observation_id else [],
                    "event_ids": _dedupe_text(
                        [str(event_id or "").strip() for event_id in list(item.get("event_ids") or []) if str(event_id or "").strip()]
                    ),
                    "source_refs": source_refs,
                    "confidence": item.get("confidence") or observation.get("confidence"),
                }
            )
    return claims


def _collect_claims(incident: Dict[str, Any], observation_map: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    return _collect_claims_from_ledger(list(incident.get("evidence_ledger") or []), observation_map)


def _collect_object_registry_from_parts(
    incident_state: Dict[str, Any],
    entities: Dict[str, Any],
    scope: Dict[str, Any],
    seed: Dict[str, Any],
    cluster_events: List[Dict[str, Any]],
    family_context: Dict[str, Any] | None,
) -> List[Dict[str, Any]]:
    registry: Dict[str, Dict[str, Any]] = {}
    object_status_priority = {"待确认": 1, "仅上下文": 2, "已验证待确认": 3, "已确认": 4}

    def add_object(value: Any, *, object_type: str, role: str, in_evidence_chain: bool, note: str = "", status: str = "") -> None:
        text = str(value or "").strip()
        if not text:
            return
        key = f"{object_type}:{text}"
        entry = registry.setdefault(
            key,
            {
                "value": text,
                "object_type": object_type,
                "type_label": _object_type_label(object_type),
                "current_role": role,
                "role_label": _object_role_label(role),
                "roles": [],
                "status": status or ("已确认" if in_evidence_chain else "待确认"),
                "in_evidence_chain": bool(in_evidence_chain),
                "notes": [],
            },
        )
        entry["roles"] = _dedupe_text(list(entry.get("roles") or []) + [role])
        current_role = str(entry.get("current_role") or "").strip()
        if OBJECT_ROLE_PRIORITY.get(role, 99) < OBJECT_ROLE_PRIORITY.get(current_role, 99):
            entry["current_role"] = role
            entry["role_label"] = _object_role_label(role)
        entry["in_evidence_chain"] = bool(entry.get("in_evidence_chain")) or bool(in_evidence_chain)
        incoming_status = "已确认" if in_evidence_chain else (status or "待确认")
        current_status = str(entry.get("status") or "").strip()
        if object_status_priority.get(incoming_status, 0) >= object_status_priority.get(current_status, 0):
            entry["status"] = incoming_status
        if note:
            entry["notes"] = _dedupe_text(list(entry.get("notes") or []) + [note])

    seed_asset = str(entities.get("seed_asset") or "").strip()
    if seed_asset:
        add_object(seed_asset, object_type="asset", role="seed_asset", in_evidence_chain=True, note="种子告警首先落在该资产上。")
    for asset in list(entities.get("suspected_assets") or []):
        add_object(asset, object_type="asset", role="affected_asset", in_evidence_chain=True, note="当前已纳入主证据链的资产。")
    for asset in list(entities.get("related_assets") or []):
        add_object(asset, object_type="asset", role="related_asset", in_evidence_chain=False, note="当前仍需独立验证是否真正受影响。")
    for asset in list(entities.get("assets") or []):
        role = "affected_asset" if asset in list(entities.get("suspected_assets") or []) else "expansion_candidate"
        add_object(asset, object_type="asset", role=role, in_evidence_chain=role != "expansion_candidate", note="事件中出现过的资产对象。")

    for ip in list(entities.get("internal_ips") or []):
        add_object(ip, object_type="internal_ip", role="related_internal_address", in_evidence_chain=True, note="事件链中出现的内部地址。")

    for value in list(scope.get("primary_external_indicators") or []):
        object_type = _indicator_type_from_value(str(value or "").strip())
        role = "related_internal_address" if object_type == "internal_ip" else "core_external_indicator"
        note = "当前主证据链中反复出现的关键对象。" if role == "core_external_indicator" else "事件链中的内部关联地址。"
        add_object(value, object_type=object_type, role=role, in_evidence_chain=True, note=note)
    for value in list(scope.get("contextual_external_indicators") or []):
        object_type = _indicator_type_from_value(str(value or "").strip())
        role = "related_internal_address" if object_type == "internal_ip" else "contextual_indicator"
        add_object(value, object_type=object_type, role=role, in_evidence_chain=True, note="用于补充边界或背景解释的对象。")

    fingerprint = seed.get("trigger_fingerprint") or {}
    fingerprint_type = str(fingerprint.get("type") or "").strip()
    fingerprint_value = str(fingerprint.get("value") or "").strip()
    if fingerprint_type and fingerprint_value:
        add_object(
            fingerprint_value,
            object_type=fingerprint_type.upper(),
            role="seed_fingerprint",
            in_evidence_chain=True,
            note="种子告警命中的关键通信指纹。",
        )

    if family_context and family_context.get("hint"):
        add_object(
            family_context.get("hint"),
            object_type="family",
            role="family_hint",
            in_evidence_chain=True,
            note="辅助解释本案的家族或工具背景，不直接等于强归因。",
        )

    pivots = incident_state.get("pivots") or {}
    for asset in list(pivots.get("asset_ids") or []):
        add_object(asset, object_type="asset", role="expansion_candidate", in_evidence_chain=False, note="当前 pivot 里出现的扩线候选资产。")
    for domain in list(pivots.get("domains") or []):
        add_object(domain, object_type="domain", role="expansion_candidate", in_evidence_chain=False, note="当前 pivot 里出现的扩线候选域名。")
    for ip in list(pivots.get("dst_ips") or []):
        object_type = _indicator_type_from_value(str(ip or "").strip())
        role = "related_internal_address" if object_type == "internal_ip" else "expansion_candidate"
        add_object(ip, object_type=object_type, role=role, in_evidence_chain=False, note="当前 pivot 里出现的扩线候选地址。")
        for fingerprint_value in list(pivots.get("fingerprints") or []):
            add_object(
                fingerprint_value,
                object_type="fingerprint",
                role="expansion_candidate",
            in_evidence_chain=False,
            note="当前 pivot 里出现的扩线候选指纹。",
        )

    for event in cluster_events:
        if str(event.get("role") or "").strip() != "candidate":
            continue
        add_object(
            event.get("asset_id"),
            object_type="asset",
            role="expansion_candidate",
            in_evidence_chain=False,
            note="事件聚类中仍需独立验证的候选资产。",
        )
        if event.get("domain"):
            add_object(
                event.get("domain"),
                object_type="domain",
                role="expansion_candidate",
                in_evidence_chain=False,
                note="候选事件涉及的域名，尚未进入已确认主链。",
            )
        if event.get("dst_ip"):
            object_type = _indicator_type_from_value(str(event.get("dst_ip") or "").strip())
            add_object(
                event.get("dst_ip"),
                object_type=object_type,
                role="expansion_candidate" if object_type != "internal_ip" else "related_internal_address",
                in_evidence_chain=False,
                note="候选事件涉及的地址，尚待独立验证。",
            )

    event_map = {
        str(item.get("id") or "").strip(): dict(item)
        for item in cluster_events
        if str(item.get("id") or "").strip()
    }
    boundary_grounding_status: Dict[str, str] = {}
    boundary_grounding_note: Dict[str, str] = {}
    for observation in list(incident_state.get("observations") or []):
        if str(observation.get("tool_name") or "").strip() != "ground_candidate_event":
            continue
        grounding_status = str(observation.get("grounding_status") or "").strip()
        boundary_event_ids = _dedupe_text(
            [str(item or "").strip() for item in list(observation.get("boundary_event_ids") or []) if str(item or "").strip()]
        )
        status_text = "仅上下文" if grounding_status == "context_only" else "已验证待确认"
        note_text = (
            "候选事件缺少可独立验证指示物，当前只作为上下文边界保留。"
            if grounding_status == "context_only"
            else "已完成 grounding 但暂未获得独立支撑，当前作为边界线索保留。"
        )
        for event_id in boundary_event_ids:
            boundary_grounding_status[event_id] = status_text
            boundary_grounding_note[event_id] = note_text

    for observation in list(incident_state.get("observations") or []):
        if str(observation.get("tool_name") or "").strip() != "ground_candidate_event":
            continue
        boundary_event_ids = _dedupe_text(
            [str(item or "").strip() for item in list(observation.get("boundary_event_ids") or []) if str(item or "").strip()]
        )
        for event_id in boundary_event_ids:
            event = dict(event_map.get(event_id) or {})
            if not event:
                continue
            note = boundary_grounding_note.get(event_id, "已完成 grounding 但暂未获得独立支撑，当前作为边界线索保留。")
            status = boundary_grounding_status.get(event_id, "已验证待确认")
            add_object(
                event.get("asset_id"),
                object_type="asset",
                role="expansion_candidate",
                in_evidence_chain=False,
                note=note,
                status=status,
            )
            if event.get("domain"):
                add_object(
                    event.get("domain"),
                    object_type="domain",
                    role="expansion_candidate",
                    in_evidence_chain=False,
                    note=note,
                    status=status,
                )
            if event.get("dst_ip"):
                object_type = _indicator_type_from_value(str(event.get("dst_ip") or "").strip())
                add_object(
                    event.get("dst_ip"),
                    object_type=object_type,
                    role="expansion_candidate" if object_type != "internal_ip" else "related_internal_address",
                    in_evidence_chain=False,
                    note=note,
                    status=status,
                )

    object_registry = sorted(
        registry.values(),
        key=lambda item: (
            OBJECT_ROLE_PRIORITY.get(str(item.get("current_role") or "").strip(), 99),
            str(item.get("object_type") or ""),
            str(item.get("value") or ""),
        ),
    )
    for index, item in enumerate(object_registry, start=1):
        item["object_id"] = f"OBJ-{index:02d}"
        item["notes"] = _dedupe_text([str(note or "").strip() for note in list(item.get("notes") or []) if str(note or "").strip()])
    return object_registry


def _collect_object_registry(incident: Dict[str, Any], family_context: Dict[str, Any] | None) -> List[Dict[str, Any]]:
    return _collect_object_registry_from_parts(
        dict(incident.get("incident_state") or {}),
        dict(incident.get("entities") or {}),
        dict(incident.get("scope") or {}),
        dict(incident.get("seed") or {}),
        list(((incident.get("cluster") or {}).get("events")) or []),
        family_context,
    )


def _collect_gap_rows_from_ledger(gaps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    gap_rows: List[Dict[str, Any]] = []
    for gap in list(gaps or []):
        report_status = _gap_status_for_report(str(gap.get("status") or "").strip())
        actionable_tools = _dedupe_text(
            [str(item or "").strip() for item in list(gap.get("actionable_tools") or []) if str(item or "").strip()]
            + [str(item or "").strip() for item in list(gap.get("addressable_tools") or []) if str(item or "").strip()]
            + [str(item or "").strip() for item in list(gap.get("tool_capability_hints") or []) if str(item or "").strip()]
        )
        gap_rows.append(
            {
                "gap_id": str(gap.get("id") or "").strip(),
                "question": str(gap.get("question") or "").strip(),
                "gap_type": str(gap.get("gap_type") or "").strip(),
                "priority": str(gap.get("priority") or "").strip() or "medium",
                "status": report_status,
                "status_label": _gap_status_label(report_status),
                "legacy_status": str(gap.get("status") or "").strip(),
                "status_reason": str(gap.get("status_reason") or "").strip(),
                "materiality": str(gap.get("materiality") or "").strip(),
                "delivery_blocking": bool(gap.get("delivery_blocking")),
                "actionable_now": bool(gap.get("actionable_now")),
                "actionable_tools": actionable_tools,
                "next_best_query": _gap_followup_text(gap),
            }
        )
    return gap_rows


def _collect_gap_rows(incident: Dict[str, Any]) -> List[Dict[str, Any]]:
    return _collect_gap_rows_from_ledger(
        list(incident.get("gap_ledger") or ((incident.get("incident_state") or {}).get("gap_ledger")) or [])
    )


def _collect_pivots(incident_state: Dict[str, Any]) -> Dict[str, Any]:
    pivots = incident_state.get("pivots") or {}
    return {
        key: (
            _dedupe_text([str(item or "").strip() for item in list(value or []) if str(item or "").strip()])
            if isinstance(value, list)
            else str(value or "").strip()
        )
        for key, value in dict(pivots).items()
        if value
    }


def _collect_evidence_parts(incident: Dict[str, Any]) -> Dict[str, Any]:
    incident_state = incident.get("incident_state") or {}
    entities = dict(incident.get("entities") or {})
    scope = dict(incident.get("scope") or {})
    seed = dict(incident.get("seed") or {})
    hypothesis = dict(incident.get("hypothesis") or {})
    summary = dict(incident.get("summary") or {})
    decision_basis = dict(incident.get("decision_basis") or {})
    cluster_events = list(((incident.get("cluster") or {}).get("events")) or [])
    observations, observation_map = _collect_observations(incident_state)
    claims = _collect_claims_from_ledger(list(incident.get("evidence_ledger") or []), observation_map)
    family_context = _family_context_from_parts(seed, entities, incident_state, decision_basis, hypothesis)
    object_registry = _collect_object_registry_from_parts(
        incident_state,
        entities,
        scope,
        seed,
        cluster_events,
        family_context,
    )
    evidence_gaps = _collect_gap_rows_from_ledger(list(incident.get("gap_ledger") or incident_state.get("gap_ledger") or []))
    pivots = _collect_pivots(incident_state)
    counterevidence = [claim for claim in claims if str(claim.get("relation") or "").strip() == "counterevidence"]
    citation_map = {
        str(claim.get("claim_id") or "").strip(): {
            "observation_ids": list(claim.get("observation_ids") or []),
            "event_ids": list(claim.get("event_ids") or []),
            "source_refs": list(claim.get("source_refs") or []),
            "provenance": str(claim.get("provenance") or "").strip(),
        }
        for claim in claims
        if str(claim.get("claim_id") or "").strip()
    }
    return {
        "version": "1.0",
        "observations": observations,
        "claims": claims,
        "object_registry": object_registry,
        "pivots": pivots,
        "counterevidence": counterevidence,
        "evidence_gaps": evidence_gaps,
        "citation_map": citation_map,
        "hypotheses": _hypothesis_view_from_parts(hypothesis, summary, decision_basis),
        "coverage": _coverage_view_from_parts(entities, scope),
        "candidate_events": _candidate_events_from_cluster_events(cluster_events),
        "confirmed_events": _confirmed_events_from_cluster_events(cluster_events),
    }


def _assemble_evidence_store(
    *,
    version: str,
    observations: List[Dict[str, Any]],
    object_registry: List[Dict[str, Any]],
    claims: List[Dict[str, Any]],
    evidence_gaps: List[Dict[str, Any]],
    citation_map: Dict[str, Any],
    pivots: Dict[str, Any],
    counterevidence: List[Dict[str, Any]],
    hypotheses: Dict[str, Any],
    coverage: Dict[str, Any],
    candidate_events: List[Dict[str, Any]],
    confirmed_events: List[Dict[str, Any]],
) -> Dict[str, Any]:
    return {
        "schema_version": "evidence-store-v1",
        "observations": observations,
        "objects": object_registry,
        "claims": claims,
        "hypotheses": hypotheses,
        "gaps": evidence_gaps,
        "coverage": coverage,
        "candidate_events": candidate_events,
        "confirmed_events": confirmed_events,
        "provenance_index": citation_map,
        # Compatibility aliases during migration.
        "version": version,
        "object_registry": object_registry,
        "evidence_gaps": evidence_gaps,
        "citation_map": citation_map,
        "pivots": pivots,
        "counterevidence": counterevidence,
    }


def build_legacy_evidence_contract(incident: Dict[str, Any]) -> Dict[str, Any]:
    return _collect_evidence_parts(incident)


def build_evidence_store(incident: Dict[str, Any], legacy_contract: Dict[str, Any] | None = None) -> Dict[str, Any]:
    hypotheses = _hypothesis_view(incident)
    coverage = _coverage_view(incident)
    candidate_events = _candidate_events(incident)
    confirmed_events = _confirmed_events(incident)
    if legacy_contract:
        observations = list(legacy_contract.get("observations") or [])
        object_registry = list(legacy_contract.get("object_registry") or [])
        claims = list(legacy_contract.get("claims") or [])
        evidence_gaps = list(legacy_contract.get("evidence_gaps") or [])
        citation_map = dict(legacy_contract.get("citation_map") or {})
        pivots = dict(legacy_contract.get("pivots") or {})
        counterevidence = list(legacy_contract.get("counterevidence") or [])
        version = str(legacy_contract.get("version") or "1.0")
        return _assemble_evidence_store(
            version=version,
            observations=observations,
            object_registry=object_registry,
            claims=claims,
            evidence_gaps=evidence_gaps,
            citation_map=citation_map,
            pivots=pivots,
            counterevidence=counterevidence,
            hypotheses=hypotheses,
            coverage=coverage,
            candidate_events=candidate_events,
            confirmed_events=confirmed_events,
        )

    parts = _collect_evidence_parts(incident)
    return _assemble_evidence_store(
        version=str(parts.get("version") or "1.0"),
        observations=list(parts.get("observations") or []),
        object_registry=list(parts.get("object_registry") or []),
        claims=list(parts.get("claims") or []),
        evidence_gaps=list(parts.get("evidence_gaps") or []),
        citation_map=dict(parts.get("citation_map") or {}),
        pivots=dict(parts.get("pivots") or {}),
        counterevidence=list(parts.get("counterevidence") or []),
        hypotheses=dict(parts.get("hypotheses") or hypotheses),
        coverage=dict(parts.get("coverage") or coverage),
        candidate_events=list(parts.get("candidate_events") or candidate_events),
        confirmed_events=list(parts.get("confirmed_events") or confirmed_events),
    )


def _runtime_evidence_snapshot(
    seed_event: Dict[str, Any],
    incident_state: Dict[str, Any],
    finalized: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    finalized = dict(finalized or {})
    runtime_gap_ledger = list(finalized.get("gap_ledger") or incident_state.get("gap_ledger") or [])
    runtime_entities = dict(finalized.get("entities") or incident_state.get("entities") or {})
    runtime_scope = dict(finalized.get("scope") or incident_state.get("scope") or {})
    runtime_hypothesis = dict(finalized.get("hypothesis") or incident_state.get("hypothesis") or {})
    runtime_summary = finalized.get("summary") or incident_state.get("summary") or {}
    runtime_decision_basis = dict(finalized.get("decision_basis") or incident_state.get("decision_basis") or {})
    runtime_cluster_events = list(finalized.get("annotated_events") or [])

    return {
        "seed": seed_event,
        "incident_state": {
            "observations": list(incident_state.get("observations") or []),
            "pivots": dict(incident_state.get("pivots") or {}),
            "entities": dict(incident_state.get("entities") or {}),
            "gap_ledger": runtime_gap_ledger,
        },
        "entities": runtime_entities,
        "scope": runtime_scope,
        "cluster": {"events": runtime_cluster_events},
        "summary": runtime_summary,
        "hypothesis": runtime_hypothesis,
        "decision_basis": runtime_decision_basis,
        "evidence_ledger": list(incident_state.get("evidence_ledger") or []),
        "gap_ledger": runtime_gap_ledger,
        "analysis_verdict": dict(
            finalized.get("analysis_verdict")
            or incident_state.get("analysis_verdict")
            or incident_state.get("provisional_verdict")
            or {}
        ),
        "provisional_verdict": dict(
            finalized.get("provisional_verdict")
            or incident_state.get("provisional_verdict")
            or {}
        ),
        "cluster_events": runtime_cluster_events,
    }


def build_runtime_evidence_store(
    seed_event: Dict[str, Any],
    incident_state: Dict[str, Any],
    finalized: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    snapshot = _runtime_evidence_snapshot(seed_event, incident_state, finalized)
    observations, observation_map = _collect_observations(dict(snapshot.get("incident_state") or {}))
    claims = _collect_claims_from_ledger(list(snapshot.get("evidence_ledger") or []), observation_map)
    family_context = _family_context_from_parts(
        dict(snapshot.get("seed") or {}),
        dict(snapshot.get("entities") or {}),
        dict(snapshot.get("incident_state") or {}),
        dict(snapshot.get("decision_basis") or {}),
        dict(snapshot.get("hypothesis") or {}),
    )
    object_registry = _collect_object_registry_from_parts(
        dict(snapshot.get("incident_state") or {}),
        dict(snapshot.get("entities") or {}),
        dict(snapshot.get("scope") or {}),
        dict(snapshot.get("seed") or {}),
        list(snapshot.get("cluster_events") or []),
        family_context,
    )
    evidence_gaps = _collect_gap_rows_from_ledger(list(snapshot.get("gap_ledger") or []))
    pivots = _collect_pivots(dict(snapshot.get("incident_state") or {}))
    counterevidence = [claim for claim in claims if str(claim.get("relation") or "").strip() == "counterevidence"]
    citation_map = {
        str(claim.get("claim_id") or "").strip(): {
            "observation_ids": list(claim.get("observation_ids") or []),
            "event_ids": list(claim.get("event_ids") or []),
            "source_refs": list(claim.get("source_refs") or []),
            "provenance": str(claim.get("provenance") or "").strip(),
        }
        for claim in claims
        if str(claim.get("claim_id") or "").strip()
    }
    evidence_store = _assemble_evidence_store(
        version="runtime-v1",
        observations=observations,
        object_registry=object_registry,
        claims=claims,
        evidence_gaps=evidence_gaps,
        citation_map=citation_map,
        pivots=pivots,
        counterevidence=counterevidence,
        hypotheses=_hypothesis_view_from_parts(
            dict(snapshot.get("hypothesis") or {}),
            dict(snapshot.get("summary") or {}),
            dict(snapshot.get("decision_basis") or {}),
        ),
        coverage=_coverage_view_from_parts(
            dict(snapshot.get("entities") or {}),
            dict(snapshot.get("scope") or {}),
        ),
        candidate_events=_candidate_events_from_cluster_events(list(snapshot.get("cluster_events") or [])),
        confirmed_events=_confirmed_events_from_cluster_events(list(snapshot.get("cluster_events") or [])),
    )
    evidence_store["runtime_snapshot"] = {
        "known_events": list((incident_state.get("known_events") or {}).values()),
        "evidence_ledger": list(incident_state.get("evidence_ledger") or []),
        "context_bundle": dict(incident_state.get("context_bundle") or {}),
        "entity_hints": dict(incident_state.get("entities") or {}),
        "gap_ledger": list(snapshot.get("gap_ledger") or []),
        "pivots": dict((snapshot.get("incident_state") or {}).get("pivots") or {}),
        "analysis_verdict": dict(snapshot.get("analysis_verdict") or {}),
        "provisional_verdict": dict(snapshot.get("provisional_verdict") or {}),
        "source_contract": "runtime_snapshot_v1",
    }
    return evidence_store
