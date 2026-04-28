from __future__ import annotations

from typing import Any, Dict, List, Tuple

from .contracts import unique_preserve_order


ROLE_TO_STATUS = {
    "seed_asset": "confirmed",
    "affected_asset": "confirmed",
    "core_external_indicator": "confirmed",
    "related_internal_address": "confirmed",
    "related_asset": "candidate",
    "expansion_candidate": "candidate",
    "contextual_indicator": "background",
    "family_hint": "background",
    "seed_fingerprint": "background",
}
ROLE_TO_SCOPE_STATUS = {
    "seed_asset": "confirmed_scope",
    "affected_asset": "confirmed_scope",
    "core_external_indicator": "confirmed_scope",
    "related_internal_address": "confirmed_scope",
    "related_asset": "candidate_scope",
    "expansion_candidate": "candidate_scope",
    "contextual_indicator": "background_only",
    "family_hint": "background_only",
    "seed_fingerprint": "background_only",
}
ROLE_PRIORITY = {
    "seed_asset": 0,
    "affected_asset": 1,
    "related_asset": 2,
    "core_external_indicator": 3,
    "related_internal_address": 4,
    "contextual_indicator": 5,
    "family_hint": 6,
    "seed_fingerprint": 7,
    "expansion_candidate": 8,
}
SEVERITY_BAND = {
    "critical": "高",
    "high": "高",
    "高危": "高",
    "高": "高",
    "medium": "中",
    "中危": "中",
    "中": "中",
    "low": "低",
    "info": "低",
    "低危": "低",
    "低": "低",
}
CONFIDENCE_BAND = {
    "high": "高",
    "较高": "高",
    "高": "高",
    "medium": "中",
    "中": "中",
    "low": "低",
    "低": "低",
}


def _text(value: Any) -> str:
    return str(value or "").strip()


def _dedupe_text(values: List[Any]) -> List[str]:
    return unique_preserve_order(_text(value) for value in list(values or []) if _text(value))


def _format_time(value: Any) -> str:
    text = _text(value)
    if not text:
        return "unknown"
    return text.replace("T", " ").replace("Z", " UTC")


def _join_slash(values: List[Any], fallback: str = "") -> str:
    items = _dedupe_text(values)
    return " / ".join(items) if items else fallback


def _action_text(value: Any) -> str:
    return _text(value).rstrip("。！？!?；;")


def _normalize_severity(value: Any) -> str:
    text = _text(value)
    if not text:
        return "未评估"
    return SEVERITY_BAND.get(text.lower(), SEVERITY_BAND.get(text, text))


def _normalize_confidence(value: Any) -> str:
    text = _text(value)
    if not text:
        return "未评估"
    return CONFIDENCE_BAND.get(text.lower(), CONFIDENCE_BAND.get(text, text))


def _evidence_objects(evidence_store: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [dict(item) for item in list(evidence_store.get("objects") or evidence_store.get("object_registry") or []) if isinstance(item, dict)]


def _observations(evidence_store: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [dict(item) for item in list(evidence_store.get("observations") or []) if isinstance(item, dict)]


def _confirmed_events(evidence_store: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [dict(item) for item in list(evidence_store.get("confirmed_events") or []) if isinstance(item, dict)]


def _candidate_events(evidence_store: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [dict(item) for item in list(evidence_store.get("candidate_events") or []) if isinstance(item, dict)]


def _counterevidence_claims(evidence_store: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [
        dict(item)
        for item in list(evidence_store.get("counterevidence") or [])
        if isinstance(item, dict)
    ]


def _coverage(evidence_store: Dict[str, Any]) -> Dict[str, Any]:
    return dict(evidence_store.get("coverage") or {})


def _event_observation_refs(evidence_store: Dict[str, Any]) -> Dict[str, List[str]]:
    mapping: Dict[str, List[str]] = {}
    for observation in _observations(evidence_store):
        observation_id = _text(observation.get("id") or observation.get("observation_id"))
        if not observation_id:
            continue
        event_ids = _dedupe_text(
            list(observation.get("event_ids") or [])
            + list(observation.get("checked_event_ids") or [])
            + list(observation.get("boundary_event_ids") or [])
        )
        for event_id in event_ids:
            mapping.setdefault(event_id, []).append(observation_id)
    return {key: _dedupe_text(values) for key, values in mapping.items()}


def _entity_observation_refs(evidence_store: Dict[str, Any]) -> Dict[str, List[str]]:
    mapping: Dict[str, List[str]] = {}
    for observation in _observations(evidence_store):
        observation_id = _text(observation.get("id") or observation.get("observation_id"))
        if not observation_id:
            continue
        derived_entities = dict(observation.get("derived_entities") or {})
        for values in derived_entities.values():
            for value in _dedupe_text(list(values or [])):
                mapping.setdefault(value, []).append(observation_id)
    return {key: _dedupe_text(values) for key, values in mapping.items()}


def _event_action(event: Dict[str, Any]) -> str:
    kind = _text(event.get("kind")).lower()
    stages = {_text(stage) for stage in list(event.get("stages") or []) if _text(stage)}
    dst_ip = _text(event.get("dst_ip"))
    domain = _text(event.get("domain"))
    classification = _text(event.get("classification")).lower()
    if kind == "asset_context" and classification == "benign":
        return "背景说明"
    if "lateral-movement" in stages and dst_ip:
        return "访问内网目标"
    if "execution" in stages:
        return "出现执行迹象"
    if "dns" in kind:
        return "解析域名"
    if domain or dst_ip:
        return "对外通信"
    return "出现关联事件"


def _event_fallback_object_text(event: Dict[str, Any]) -> str:
    kind = _text(event.get("kind")).lower()
    classification = _text(event.get("classification")).lower()
    if kind == "process":
        return "相关主机执行活动"
    if kind == "asset_context" and classification == "benign":
        return "维护或计划内背景活动"
    if kind == "asset_context":
        return "主机侧上下文线索"
    return _text(event.get("summary")) or _text(event.get("id")) or "相关对象"


def _event_object_text(event: Dict[str, Any]) -> str:
    return _join_slash([event.get("domain"), event.get("dst_ip")], fallback=_event_fallback_object_text(event))


def _event_status(event: Dict[str, Any], delivery_decision: Dict[str, Any]) -> str:
    role = _text(event.get("role"))
    classification = _text(event.get("classification")).lower()
    asset_id = _text(event.get("asset_id"))
    confirmed_scope = set(_dedupe_text(list(delivery_decision.get("confirmed_scope") or [])))
    candidate_scope = set(_dedupe_text(list(delivery_decision.get("candidate_scope") or [])))
    stages = {_text(stage) for stage in list(event.get("stages") or []) if _text(stage)}
    if role == "candidate":
        return "candidate"
    if classification == "benign":
        return "background"
    if asset_id and asset_id in candidate_scope:
        return "candidate"
    if asset_id and confirmed_scope and asset_id not in confirmed_scope and asset_id not in candidate_scope:
        return "background"
    if not stages and classification in {"unknown", "benign"}:
        return "background"
    return "confirmed"


def _event_summary_line(event: Dict[str, Any], *, status: str) -> str:
    ts = _format_time(event.get("ts"))
    asset_id = _text(event.get("asset_id")) or "相关资产"
    object_text = _event_object_text(event)
    action = _event_action(event)
    if status == "confirmed":
        return f"{ts} 资产 `{asset_id}` {action} `{object_text}`。"
    if status == "background":
        return f"{ts} 资产 `{asset_id}` 当前出现仅用于边界说明的背景事件 `{object_text}`。"
    return f"{ts} 资产 `{asset_id}` 与 `{object_text}` 出现待确认关联命中。"


def _scope_summary_line(item: Dict[str, Any]) -> str:
    value = _text(item.get("value")) or "相关对象"
    role_label = _text(item.get("role_label")) or _text(item.get("current_role")) or "对象"
    status = ROLE_TO_STATUS.get(_text(item.get("current_role")), "candidate")
    if status == "confirmed":
        return f"对象 `{value}` 当前作为{role_label}纳入已确认范围。"
    if status == "background":
        return f"对象 `{value}` 当前只作为{role_label}保留为背景指标。"
    return f"对象 `{value}` 当前作为{role_label}保留为待确认范围。"


def _gap_summary_line(gap: Dict[str, Any]) -> str:
    question = _text(gap.get("question")) or "当前仍存在未闭合问题"
    return f"当前仍需对“{question}”补充独立确认。"


def _counterevidence_summary_line(claim: Dict[str, Any]) -> str:
    text = _text(claim.get("text"))
    return text or "已观察到需要纳入边界说明的反证线索。"


def _recommendation_rows(evidence_store: Dict[str, Any], delivery_decision: Dict[str, Any]) -> List[Tuple[str, str]]:
    coverage = _coverage(evidence_store)
    confirmed_scope = _dedupe_text(list(delivery_decision.get("confirmed_scope") or []))
    candidate_scope = _dedupe_text(list(delivery_decision.get("candidate_scope") or []))
    core_indicators = _dedupe_text(list(coverage.get("primary_external_indicators") or []))
    next_best_questions = _dedupe_text(list(delivery_decision.get("next_best_questions") or []))
    focus_assets = confirmed_scope or ([_text(coverage.get("seed_asset"))] if _text(coverage.get("seed_asset")) else [])

    rows: List[Tuple[str, str]] = []
    if focus_assets:
        rows.append(("immediate", _action_text(f"优先隔离或重点监控资产：{'、'.join(focus_assets[:4])}")))
    if core_indicators:
        rows.append(("immediate", _action_text(f"在边界和代理设备上排查并封禁外部基础设施：{'、'.join(core_indicators[:4])}")))
    if candidate_scope:
        rows.append(("short_term", _action_text(f"继续核实待确认关联资产 {'、'.join(candidate_scope[:4])}")))
    if next_best_questions:
        rows.append(("follow_up", _action_text(f"优先补查：{next_best_questions[0]}")))
    if not rows:
        rows.append(("short_term", "围绕种子资产与核心外部指示物继续收敛处置"))
    return rows


def _conclusion_statement(evidence_store: Dict[str, Any], delivery_decision: Dict[str, Any]) -> str:
    coverage = _coverage(evidence_store)
    confirmed_scope = _dedupe_text(list(delivery_decision.get("confirmed_scope") or []))
    seed_asset = _text(coverage.get("seed_asset")) or "相关资产"
    primary_external = _dedupe_text(list(coverage.get("primary_external_indicators") or []))
    indicator_text = "、".join(primary_external[:2]) if primary_external else "当前关键通信对象"
    delivery_status = _text(delivery_decision.get("delivery_status")) or "needs_review"
    if delivery_status == "confirmed_incident":
        subject = "、".join(confirmed_scope) if confirmed_scope else seed_asset
        return f"{subject} 围绕 {indicator_text} 已形成可以稳定交付的异常链。"
    candidate_scope = _dedupe_text(list(delivery_decision.get("candidate_scope") or []))
    if candidate_scope:
        return f"{seed_asset} 围绕 {indicator_text} 已出现连续异常迹象，但 {candidate_scope[0]} 仍需独立确认。"
    return f"{seed_asset} 围绕 {indicator_text} 已形成需要继续收敛的异常事件链。"


def _boundary_statement(evidence_store: Dict[str, Any], delivery_decision: Dict[str, Any]) -> str:
    coverage = _coverage(evidence_store)
    confirmed_scope = _dedupe_text(list(delivery_decision.get("confirmed_scope") or []))
    candidate_scope = _dedupe_text(list(delivery_decision.get("candidate_scope") or []))
    current_boundary = _text(coverage.get("current_boundary"))
    non_blocking_gaps = [dict(item) for item in list(delivery_decision.get("non_blocking_gaps") or []) if isinstance(item, dict)]
    if confirmed_scope and candidate_scope:
        return f"当前确认范围收敛在 {'、'.join(confirmed_scope)}；{'、'.join(candidate_scope)} 保持待确认状态。"
    if current_boundary:
        return current_boundary
    if non_blocking_gaps:
        return _text(non_blocking_gaps[0].get("status_reason") or non_blocking_gaps[0].get("question")) or "当前仍有边界未闭合。"
    if confirmed_scope:
        return f"当前确认范围收敛在 {'、'.join(confirmed_scope)}。"
    return "当前仍需继续收敛交付边界。"


def _scope_objects_for_cards(evidence_store: Dict[str, Any]) -> List[Dict[str, Any]]:
    allowed_roles = set(ROLE_TO_STATUS)
    rows = [item for item in _evidence_objects(evidence_store) if _text(item.get("current_role")) in allowed_roles]
    return sorted(
        rows,
        key=lambda item: (
            ROLE_PRIORITY.get(_text(item.get("current_role")), 99),
            _text(item.get("value")),
        ),
    )


def build_report_fact_cards(evidence_store: Dict[str, Any], delivery_decision: Dict[str, Any]) -> Dict[str, Any]:
    event_obs_refs = _event_observation_refs(evidence_store)
    entity_obs_refs = _entity_observation_refs(evidence_store)
    fact_cards: List[Dict[str, Any]] = []

    event_fact_ids: List[str] = []
    candidate_event_fact_ids: List[str] = []
    confirmed_scope_fact_ids: List[str] = []
    candidate_scope_fact_ids: List[str] = []
    packet_confirmed_scope_fact_ids: List[str] = []
    packet_candidate_scope_fact_ids: List[str] = []
    gap_fact_ids: List[str] = []
    counterevidence_fact_ids: List[str] = []

    for event in sorted(_confirmed_events(evidence_store), key=lambda item: (_text(item.get("ts")), _text(item.get("id")))):
        event_id = _text(event.get("id")) or f"evt-{len(event_fact_ids) + 1}"
        fact_id = f"fact-event-{event_id}"
        event_status = _event_status(event, delivery_decision)
        card = {
            "fact_id": fact_id,
            "fact_type": "event",
            "status": event_status,
            "summary_line": _event_summary_line(event, status=event_status),
            "evidence_refs": list(event_obs_refs.get(event_id) or []),
            "time": _format_time(event.get("ts")),
            "subject": _text(event.get("asset_id")) or "相关资产",
            "action": _event_action(event),
            "object": _event_object_text(event),
            "qualifiers": {
                "event_id": event_id,
                "kind": _text(event.get("kind")),
                "stages": _dedupe_text(list(event.get("stages") or [])),
                "classification": _text(event.get("classification")),
            },
        }
        fact_cards.append(card)
        if event_status == "confirmed":
            event_fact_ids.append(fact_id)
        elif event_status == "candidate":
            candidate_event_fact_ids.append(fact_id)

    for event in sorted(_candidate_events(evidence_store), key=lambda item: (_text(item.get("ts")), _text(item.get("id")))):
        event_id = _text(event.get("id")) or f"candidate-{len(candidate_event_fact_ids) + 1}"
        fact_id = f"fact-event-{event_id}"
        card = {
            "fact_id": fact_id,
            "fact_type": "event",
            "status": "candidate",
            "summary_line": _event_summary_line(event, status="candidate"),
            "evidence_refs": list(event_obs_refs.get(event_id) or []),
            "time": _format_time(event.get("ts")),
            "subject": _text(event.get("asset_id")) or "相关资产",
            "action": _event_action(event),
            "object": _event_object_text(event),
            "qualifiers": {
                "event_id": event_id,
                "kind": _text(event.get("kind")),
                "stages": _dedupe_text(list(event.get("stages") or [])),
                "classification": _text(event.get("classification")),
            },
        }
        fact_cards.append(card)
        candidate_event_fact_ids.append(fact_id)

    for item in _scope_objects_for_cards(evidence_store):
        object_id = _text(item.get("object_id")) or _text(item.get("value")) or f"scope-{len(confirmed_scope_fact_ids) + len(candidate_scope_fact_ids) + 1}"
        fact_id = f"fact-scope-{object_id.lower()}"
        current_role = _text(item.get("current_role"))
        card_status = ROLE_TO_STATUS.get(current_role, "candidate")
        card = {
            "fact_id": fact_id,
            "fact_type": "scope",
            "status": card_status,
            "summary_line": _scope_summary_line(item),
            "evidence_refs": list(entity_obs_refs.get(_text(item.get("value"))) or []),
            "entity": _text(item.get("value")),
            "role": current_role,
            "scope_status": ROLE_TO_SCOPE_STATUS.get(current_role, "candidate_scope"),
        }
        fact_cards.append(card)
        if card_status == "confirmed":
            confirmed_scope_fact_ids.append(fact_id)
        elif card_status == "candidate":
            candidate_scope_fact_ids.append(fact_id)
        if current_role in {"seed_asset", "affected_asset", "core_external_indicator"}:
            packet_confirmed_scope_fact_ids.append(fact_id)
        elif current_role == "related_asset":
            packet_candidate_scope_fact_ids.append(fact_id)

    gap_rows: List[Dict[str, Any]] = [
        dict(item)
        for item in list(delivery_decision.get("blocking_gaps") or []) + list(delivery_decision.get("non_blocking_gaps") or [])
        if isinstance(item, dict)
    ]
    for gap in gap_rows:
        gap_id = _text(gap.get("gap_id")) or f"gap-{len(gap_fact_ids) + 1}"
        fact_id = f"fact-gap-{gap_id}"
        status = "blocked" if bool(gap.get("blocks_delivery_now")) else "candidate"
        card = {
            "fact_id": fact_id,
            "fact_type": "gap",
            "status": status,
            "summary_line": _gap_summary_line(gap),
            "evidence_refs": [],
            "question": _text(gap.get("question")),
            "blocking_effect": _text(gap.get("status_reason") or gap.get("next_best_question")),
        }
        fact_cards.append(card)
        gap_fact_ids.append(fact_id)

    for claim in _counterevidence_claims(evidence_store):
        claim_id = _text(claim.get("claim_id")) or f"claim-{len(counterevidence_fact_ids) + 1}"
        fact_id = f"fact-counter-{claim_id.lower()}"
        card = {
            "fact_id": fact_id,
            "fact_type": "counterevidence",
            "status": "background",
            "summary_line": _counterevidence_summary_line(claim),
            "evidence_refs": _dedupe_text(list(claim.get("observation_ids") or [])),
            "claim": _text(claim.get("text")),
            "impact": "用于说明为什么部分背景流量不足以推翻主判断。",
        }
        fact_cards.append(card)
        counterevidence_fact_ids.append(fact_id)

    action_rows = _recommendation_rows(evidence_store, delivery_decision)
    action_card_ids: List[str] = []
    immediate_actions: List[str] = []
    next_steps: List[str] = []
    for index, (priority, action_text) in enumerate(action_rows, start=1):
        fact_id = f"fact-action-{index:02d}"
        card = {
            "fact_id": fact_id,
            "fact_type": "action_basis",
            "status": "confirmed",
            "summary_line": action_text,
            "evidence_refs": [],
            "recommended_action": action_text,
            "priority": priority,
        }
        fact_cards.append(card)
        action_card_ids.append(fact_id)
        if priority == "immediate":
            immediate_actions.append(action_text)
        else:
            next_steps.append(action_text)

    delivery_verdict = dict(delivery_decision.get("delivery_verdict") or {})
    analysis_verdict = dict(delivery_decision.get("analysis_verdict") or {})
    verdict_packet = {
        "severity": _normalize_severity(
            delivery_verdict.get("severity") or analysis_verdict.get("severity") or delivery_decision.get("severity")
        ),
        "confidence": _normalize_confidence(delivery_decision.get("confidence_band") or analysis_verdict.get("confidence_band")),
        "conclusion_statement": _conclusion_statement(evidence_store, delivery_decision),
        "supporting_fact_ids": _dedupe_text(event_fact_ids[:3] + packet_confirmed_scope_fact_ids[:4] + counterevidence_fact_ids[:1]),
    }
    scope_packet = {
        "confirmed_entities": _dedupe_text(list(delivery_decision.get("confirmed_scope") or [])),
        "candidate_entities": _dedupe_text(list(delivery_decision.get("candidate_scope") or [])),
        "supporting_fact_ids": _dedupe_text(packet_confirmed_scope_fact_ids + packet_candidate_scope_fact_ids[:4]),
    }
    constraint_packet = {
        "blocking_gaps": [
            _text(item.get("question") or item.get("status_reason"))
            for item in gap_rows
            if _text(item.get("question") or item.get("status_reason"))
        ],
        "counterevidence": [_text(item.get("claim")) for item in fact_cards if item.get("fact_type") == "counterevidence"][:2],
        "boundary_statement": _boundary_statement(evidence_store, delivery_decision),
        "supporting_fact_ids": _dedupe_text(gap_fact_ids + counterevidence_fact_ids + candidate_event_fact_ids[:2]),
    }
    action_packet = {
        "immediate_actions": immediate_actions[:3],
        "next_steps": next_steps[:3],
        "supporting_fact_ids": _dedupe_text(packet_confirmed_scope_fact_ids[:4] + gap_fact_ids[:2] + action_card_ids),
    }

    type_counts: Dict[str, int] = {}
    for card in fact_cards:
        fact_type = _text(card.get("fact_type")) or "unknown"
        type_counts[fact_type] = int(type_counts.get(fact_type) or 0) + 1

    return {
        "schema_version": "report-fact-cards-v1",
        "source_contract": {
            "evidence_store_schema": _text(evidence_store.get("schema_version") or evidence_store.get("version")) or "unknown",
            "delivery_decision_schema": _text(delivery_decision.get("schema_version")) or "unknown",
        },
        "card_counts": type_counts,
        "fact_cards": fact_cards,
        "verdict_packet": verdict_packet,
        "scope_packet": scope_packet,
        "constraint_packet": constraint_packet,
        "action_packet": action_packet,
    }
