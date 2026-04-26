from __future__ import annotations

from typing import Any, Dict, List

from .contracts import severity_from_confidence, unique_preserve_order


STATUS_LABELS = {
    "confirmed_incident": "确认安全事件",
    "needs_review": "可疑事件，建议继续复核",
    "monitor_only": "背景活动，建议持续观察",
}
HIGH_RISK_STAGES = {
    "execution",
    "lateral-movement",
    "credential-access",
    "persistence",
    "exfiltration",
    "impact",
}
SUPPLEMENTAL_PROVENANCE = {"external_intel", "analyst_note"}
SUPPLEMENTAL_SOURCE_PREFIXES = ("intel_tool", "page_content", "internal_digest", "candidate_grounding")


def _confidence_band(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return "未评估"
    try:
        score = float(text)
    except ValueError:
        return text
    if score <= 1:
        score *= 100
    score = max(0, min(int(round(score)), 100))
    if score >= 85:
        return "高"
    if score >= 70:
        return "较高"
    if score >= 50:
        return "中"
    return "低"


def _readiness_check(check_id: str, ok: bool, reason: str, *, delivery_blocking: bool = True) -> Dict[str, Any]:
    return {
        "id": check_id,
        "ok": bool(ok),
        "reason": str(reason or "").strip(),
        "delivery_blocking": bool(delivery_blocking),
    }


def _safe_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _list_of_dicts(value: Any) -> List[Dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, dict)]


def _provisional_verdict(incident: Dict[str, Any]) -> Dict[str, Any]:
    return (
        incident.get("analysis_verdict")
        or incident.get("provisional_verdict")
        or ((incident.get("incident_state") or {}).get("analysis_verdict"))
        or ((incident.get("incident_state") or {}).get("provisional_verdict"))
        or incident.get("verdict")
        or {}
    )


def _asset_scope(objects: List[Dict[str, Any]], *, roles: set[str], confirmed_only: bool) -> List[str]:
    values: List[str] = []
    for item in objects:
        if str(item.get("object_type") or "").strip() != "asset":
            continue
        current_role = str(item.get("current_role") or "").strip()
        item_roles = {str(role or "").strip() for role in list(item.get("roles") or [])}
        if current_role not in roles and not item_roles.intersection(roles):
            continue
        if confirmed_only and not (bool(item.get("in_evidence_chain")) or str(item.get("status") or "").strip() == "已确认"):
            continue
        values.append(str(item.get("value") or "").strip())
    return unique_preserve_order(values)


def _event_asset_scope(events: List[Dict[str, Any]]) -> List[str]:
    return unique_preserve_order(str(item.get("asset_id") or "").strip() for item in list(events or []) if str(item.get("asset_id") or "").strip())


def _evidence_objects(evidence_store: Dict[str, Any]) -> List[Dict[str, Any]]:
    return list(evidence_store.get("objects") or evidence_store.get("object_registry") or [])


def _evidence_gaps(evidence_store: Dict[str, Any]) -> List[Dict[str, Any]]:
    return list(evidence_store.get("gaps") or evidence_store.get("evidence_gaps") or [])


def _evidence_observations(evidence_store: Dict[str, Any]) -> List[Dict[str, Any]]:
    return list(evidence_store.get("observations") or [])


def _confirmed_events(evidence_store: Dict[str, Any]) -> List[Dict[str, Any]]:
    return list(evidence_store.get("confirmed_events") or [])


def _candidate_events(evidence_store: Dict[str, Any]) -> List[Dict[str, Any]]:
    return list(evidence_store.get("candidate_events") or [])


def _coverage(evidence_store: Dict[str, Any]) -> Dict[str, Any]:
    return dict(evidence_store.get("coverage") or {})


def _hypotheses(evidence_store: Dict[str, Any]) -> Dict[str, Any]:
    return dict(evidence_store.get("hypotheses") or {})


def _provisional_assessment(incident: Dict[str, Any]) -> Dict[str, Any]:
    verdict = dict(_provisional_verdict(incident))
    status = str(verdict.get("status") or "").strip() or "needs_review"
    confidence = _safe_int(verdict.get("confidence"))
    return {
        "status": status,
        "status_label": str(verdict.get("status_label") or "").strip() or STATUS_LABELS.get(status, status),
        "confidence": confidence,
        "severity": str(verdict.get("severity") or "").strip() or severity_from_confidence(confidence, status),
        "rationale": unique_preserve_order(
            [str(item or "").strip() for item in list(verdict.get("rationale") or []) if str(item or "").strip()]
        ),
    }


def _recent_tool_effects(incident: Dict[str, Any]) -> List[Dict[str, Any]]:
    session_state = incident.get("session_state") or {}
    rows: List[Dict[str, Any]] = []
    for item in list(session_state.get("tool_history") or [])[-3:]:
        delta = dict(item.get("output_delta") or {})
        rows.append(
            {
                "step_index": _safe_int(item.get("step_index")),
                "tool_name": str(item.get("tool_name") or "").strip(),
                "novelty_score": _safe_int(delta.get("novelty_score")),
                "summary": str(delta.get("summary") or "").strip(),
            }
        )
    return rows


def _is_supplemental_observation(observation: Dict[str, Any]) -> bool:
    provenance = str(observation.get("provenance") or "").strip().lower()
    source_type = str(observation.get("source_type") or "").strip().lower()
    return provenance in SUPPLEMENTAL_PROVENANCE or source_type.startswith(SUPPLEMENTAL_SOURCE_PREFIXES)


def _counterevidence_reviewed(evidence_store: Dict[str, Any]) -> bool:
    for observation in _evidence_observations(evidence_store):
        relation = str(observation.get("relation") or "").strip().lower()
        provenance = str(observation.get("provenance") or "").strip().lower()
        tool_name = str(observation.get("tool_name") or "").strip().lower()
        if relation == "counterevidence" or provenance == "counterevidence" or tool_name == "check_counterevidence":
            return True
    return False


def _runtime_summary(incident: Dict[str, Any], evidence_store: Dict[str, Any]) -> Dict[str, Any]:
    session_state = incident.get("session_state") or {}
    budgets = dict(session_state.get("budgets") or {})
    coverage = _coverage(evidence_store)
    confirmed_events = _confirmed_events(evidence_store)
    candidate_events = _candidate_events(evidence_store)
    observed_event_count = len(confirmed_events) + len(candidate_events)
    context_bundle = incident.get("context_bundle") or {}
    minimal_event_count = _safe_int(context_bundle.get("minimal_event_count"))
    recent_tool_effects = _recent_tool_effects(incident)
    recent_low_novelty_count = len([item for item in recent_tool_effects if _safe_int(item.get("novelty_score")) <= 1])

    return {
        "context_built": bool(minimal_event_count) or bool(confirmed_events),
        "cluster_built": observed_event_count >= max(2, minimal_event_count or 0),
        "timeline_built": bool(confirmed_events),
        "scope_assessed": bool(
            str(coverage.get("seed_asset") or "").strip()
            or list(coverage.get("suspected_assets") or [])
            or list(coverage.get("primary_external_indicators") or [])
        ),
        "counterevidence_reviewed": _counterevidence_reviewed(evidence_store),
        "supplemental_context_reviewed": any(_is_supplemental_observation(item) for item in _evidence_observations(evidence_store)),
        "candidate_event_count": len(candidate_events),
        "observed_event_count": observed_event_count,
        "consecutive_low_value_steps": _safe_int(session_state.get("consecutive_low_value_steps")),
        "recent_low_novelty_count": recent_low_novelty_count,
        "stop_reason": str(session_state.get("stop_reason") or "").strip(),
        "budget_usage": {
            "max_steps": _safe_int(budgets.get("max_steps")),
            "remaining_steps": _safe_int(budgets.get("remaining_steps")),
            "max_tool_calls": _safe_int(budgets.get("max_tool_calls")),
            "remaining_tool_calls": _safe_int(budgets.get("remaining_tool_calls")),
            "max_event_queries": _safe_int(budgets.get("max_event_queries")),
            "remaining_event_queries": _safe_int(budgets.get("remaining_event_queries")),
            "max_intel_queries": _safe_int(budgets.get("max_intel_queries")),
            "remaining_intel_queries": _safe_int(budgets.get("remaining_intel_queries")),
        },
    }


def build_reviewer_input(incident: Dict[str, Any], evidence_store: Dict[str, Any]) -> Dict[str, Any]:
    runtime_summary = _runtime_summary(incident, evidence_store)
    return {
        "schema_version": "reviewer-input-v1",
        "provisional_assessment": _provisional_assessment(incident),
        "runtime_summary": runtime_summary,
        "session_trace_summary": {
            "stop_reason": str(runtime_summary.get("stop_reason") or "").strip(),
            "consecutive_low_value_steps": _safe_int(runtime_summary.get("consecutive_low_value_steps")),
            "recent_tool_effects": _recent_tool_effects(incident),
            "budget_usage": dict(runtime_summary.get("budget_usage") or {}),
        },
    }


def _gap_blocks_delivery(gap: Dict[str, Any]) -> bool:
    status = str(gap.get("legacy_status") or gap.get("status") or "").strip().lower()
    if not bool(gap.get("delivery_blocking")):
        return False
    if status == "closed":
        return False
    if status in {"reportable_unresolved", "unresolved_but_deliverable"}:
        return False
    if status in {"stalled", "open_unaddressable"} and bool(gap.get("reportable_if_unresolved")) and not bool(gap.get("actionable_now")):
        return False
    return True


def _gap_is_boundary_only(gap: Dict[str, Any]) -> bool:
    return bool(gap.get("delivery_blocking")) and not _gap_blocks_delivery(gap)


def _gap_affects_candidate_boundary(gap: Dict[str, Any]) -> bool:
    gap_type = str(gap.get("gap_type") or "").strip()
    materiality = str(gap.get("materiality") or "").strip()
    return bool(gap.get("reportable_if_unresolved")) or materiality == "boundary_sensitive" or gap_type in {
        "candidate_grounding",
        "cluster_scope",
        "scope_expansion",
    }


def _gap_view(gap: Dict[str, Any], *, blocks_delivery: bool) -> Dict[str, Any]:
    raw_status = str(gap.get("status") or "").strip() or "open"
    view_status = raw_status
    status_reason = str(gap.get("status_reason") or "").strip()
    if _gap_is_boundary_only(gap):
        view_status = "unresolved_but_deliverable"
        if not status_reason:
            status_reason = "该 gap 当前只限制边界说明，不再阻塞核心结论交付。"
    return {
        "gap_id": str(gap.get("gap_id") or gap.get("id") or "").strip(),
        "question": str(gap.get("question") or "").strip(),
        "priority": str(gap.get("priority") or "").strip() or "medium",
        "status": view_status,
        "status_reason": status_reason,
        "delivery_blocking": bool(gap.get("delivery_blocking")),
        "actionable_now": bool(gap.get("actionable_now")),
        "blocks_delivery_now": bool(blocks_delivery),
        "next_best_question": str(
            gap.get("next_best_query")
            or ((status_reason if not bool(gap.get("actionable_now")) else "") or gap.get("question") or "")
        ).strip(),
    }


def _candidate_grounding_check(
    candidate_events: List[Dict[str, Any]],
    effective_blocking_gaps: List[Dict[str, Any]],
    carryable_gaps: List[Dict[str, Any]],
) -> Dict[str, Any]:
    if not candidate_events:
        return _readiness_check(
            "candidate_events_grounded",
            True,
            "当前没有仍待单独 grounding 的候选事件。",
        )
    boundary_related_blockers = [gap for gap in effective_blocking_gaps if _gap_affects_candidate_boundary(gap)]
    boundary_related_carryable = [gap for gap in carryable_gaps if _gap_affects_candidate_boundary(gap)]
    if boundary_related_blockers:
        return _readiness_check(
            "candidate_events_grounded",
            False,
            f"仍有 {len(candidate_events)} 条候选扩线事件没有完成独立验证。",
        )
    if boundary_related_carryable:
        return _readiness_check(
            "candidate_events_grounded",
            True,
            "仍有候选事件未独立验证，但它们当前只限制扩展边界，不再阻塞核心结论交付。",
        )
    return _readiness_check(
        "candidate_events_grounded",
        True,
        "扩线得到的候选事件已经完成独立验证或明确降级为上下文。",
    )


def _evidence_chain_check(
    provisional_status: str,
    evidence_store: Dict[str, Any],
    confirmed_scope: List[str],
    runtime_summary: Dict[str, Any],
) -> Dict[str, Any]:
    confirmed_events = _confirmed_events(evidence_store)
    supporting_claims = [
        item for item in list(evidence_store.get("claims") or []) if str(item.get("relation") or "").strip() == "supporting"
    ]
    counter_claims = [
        item for item in list(evidence_store.get("claims") or []) if str(item.get("relation") or "").strip() == "counterevidence"
    ]
    high_risk_stage_seen = any(
        str(stage or "").strip() in HIGH_RISK_STAGES
        for event in confirmed_events
        for stage in list(event.get("stages") or [])
    )
    coverage = _coverage(evidence_store)
    has_external_indicator = bool(list(coverage.get("primary_external_indicators") or []) or list(coverage.get("contextual_external_indicators") or []))
    counterevidence_reviewed = bool(runtime_summary.get("counterevidence_reviewed"))

    if provisional_status == "confirmed_incident":
        ok = bool(high_risk_stage_seen or len(confirmed_scope) > 1)
        reason = (
            "确认事件前至少需要执行、横向移动、外传等高风险阶段，或已经保守收敛到多资产范围，目前该条件已满足。"
            if ok
            else "当前内部方向偏向确认事件，但仍缺少足够强的高风险阶段证据或保守收敛后的多资产范围。"
        )
        return _readiness_check("evidence_chain_ready", ok, reason)
    if provisional_status == "monitor_only":
        ok = bool(counterevidence_reviewed and counter_claims)
        reason = (
            "存在明确反证并且已经执行显式反证检查，可以把结论稳定降级为观察。"
            if ok
            else "若要稳定降级为观察，仍需要显式反证检查及至少一条可引用的反证。"
        )
        return _readiness_check("evidence_chain_ready", ok, reason)
    ok = bool((supporting_claims or confirmed_events) and has_external_indicator)
    reason = (
        "当前已经具备最小支撑证据链，并且事件范围能够落到具体外部指示物。"
        if ok
        else "当前还没有形成最小支撑证据链，或事件范围尚未落到具体外部指示物。"
    )
    return _readiness_check("evidence_chain_ready", ok, reason)


def _reviewer_readiness(
    evidence_store: Dict[str, Any],
    reviewer_input: Dict[str, Any],
    confirmed_scope: List[str],
    effective_blocking_gaps: List[Dict[str, Any]],
    carryable_gaps: List[Dict[str, Any]],
) -> Dict[str, Any]:
    runtime_summary = dict(reviewer_input.get("runtime_summary") or {})
    provisional = dict(reviewer_input.get("provisional_assessment") or {})
    provisional_status = str(provisional.get("status") or "").strip() or "needs_review"
    candidate_events = _candidate_events(evidence_store)

    checks = [
        _readiness_check(
            "context_built",
            bool(runtime_summary.get("context_built")),
            "已围绕 seed alert 建立最小上下文。"
            if bool(runtime_summary.get("context_built"))
            else "仍未围绕 seed alert 建立最小上下文。",
        ),
        _readiness_check(
            "cluster_built",
            bool(runtime_summary.get("cluster_built")),
            "事件簇规模已经足以支撑时间线和范围判断。"
            if bool(runtime_summary.get("cluster_built"))
            else "事件簇仍然过薄，无法支撑稳定交付。",
        ),
        _candidate_grounding_check(candidate_events, effective_blocking_gaps, carryable_gaps),
        _readiness_check(
            "timeline_built",
            bool(runtime_summary.get("timeline_built")),
            "已形成时间线，可解释关键观察的先后关系。"
            if bool(runtime_summary.get("timeline_built"))
            else "仍未形成可交付的时间线。",
        ),
        _readiness_check(
            "scope_assessed",
            bool(runtime_summary.get("scope_assessed")),
            "当前事件范围已经落到资产或核心外部指示物上。"
            if bool(runtime_summary.get("scope_assessed"))
            else "当前还无法清楚说明事件影响范围。",
        ),
        _evidence_chain_check(provisional_status, evidence_store, confirmed_scope, runtime_summary),
        _readiness_check(
            "counterevidence_checked",
            bool(runtime_summary.get("counterevidence_reviewed")),
            "已执行显式反证检查。"
            if bool(runtime_summary.get("counterevidence_reviewed"))
            else "尚未执行显式反证检查。",
        ),
        _readiness_check(
            "supplemental_context_reviewed",
            bool(runtime_summary.get("supplemental_context_reviewed")),
            "已执行至少一次情报或结构化整理动作，可支撑 deterministic report 生成。"
            if bool(runtime_summary.get("supplemental_context_reviewed"))
            else "仍缺少情报或结构化整理动作，报告材料尚未收束。",
        ),
    ]
    blocking_checks = [item for item in checks if not bool(item.get("ok")) and bool(item.get("delivery_blocking", True))]
    ready_for_delivery = not blocking_checks and not effective_blocking_gaps
    if ready_for_delivery:
        if provisional_status == "confirmed_incident":
            summary = "主支撑证据、反证检查与报告材料均已到位，可按确认事件交付。"
        elif provisional_status == "monitor_only":
            summary = "反证链路和背景解释已经完成交付级核查，可按降级观察交付。"
        else:
            summary = "最小事件链、交付材料和反证检查均已到位，可按待人工复核结论交付。"
    else:
        failure_reasons = [
            str(item.get("reason") or "").strip()
            for item in blocking_checks
            if str(item.get("reason") or "").strip()
        ]
        gap_questions = [
            str(item.get("question") or "").strip()
            for item in effective_blocking_gaps
            if str(item.get("question") or "").strip()
        ]
        summary_parts = unique_preserve_order(failure_reasons + gap_questions)
        summary = "交付门槛尚未满足：" + "；".join(summary_parts[:4]) if summary_parts else "交付门槛尚未满足。"
    return {
        "ready_for_delivery": ready_for_delivery,
        "summary": summary,
        "checks": checks,
        "blocking_checks": blocking_checks,
    }


def _final_delivery_verdict(
    provisional: Dict[str, Any],
    delivery_status: str,
    readiness: Dict[str, Any],
    reviewer_rationale: str,
) -> Dict[str, Any]:
    final_status = delivery_status if bool(readiness.get("ready_for_delivery")) else "needs_review"
    confidence = _safe_int(provisional.get("confidence"))
    if final_status == "needs_review" and str(provisional.get("status") or "").strip() != "needs_review":
        confidence = min(confidence, 68)
    rationale = unique_preserve_order(
        [str(item or "").strip() for item in list(provisional.get("rationale") or []) if str(item or "").strip()]
        + ([reviewer_rationale] if reviewer_rationale else [])
    )
    blocking_ids = [
        str(item.get("id") or "").strip()
        for item in list(readiness.get("blocking_checks") or [])
        if str(item.get("id") or "").strip()
    ]
    return {
        "status": final_status,
        "status_label": STATUS_LABELS.get(final_status, final_status),
        "confidence": confidence,
        "severity": severity_from_confidence(confidence, final_status),
        "rationale": rationale,
        "delivery_ready": bool(readiness.get("ready_for_delivery")),
        "blocked_by": blocking_ids,
        "provisional_status": str(provisional.get("status") or "").strip(),
        "provisional_status_label": str(provisional.get("status_label") or "").strip(),
    }


def _insufficient_progress_signals(
    reviewer_input: Dict[str, Any],
    effective_blocking_gaps: List[Dict[str, Any]],
    confirmed_scope: List[str],
) -> List[str]:
    signals: List[str] = []
    runtime_summary = dict(reviewer_input.get("runtime_summary") or {})
    trace_summary = dict(reviewer_input.get("session_trace_summary") or {})
    recent_history = _list_of_dicts(trace_summary.get("recent_tool_effects"))
    low_novelty_count = len([item for item in recent_history if _safe_int(item.get("novelty_score")) <= 1])
    if len(recent_history) >= 2 and low_novelty_count >= 2:
        signals.append("最近多轮工具调用的新颖度偏低，调查推进可能已经放缓。")
    if _safe_int(runtime_summary.get("consecutive_low_value_steps")) >= 2:
        signals.append("最近连续多轮没有带来明显的 material 增量。")
    if effective_blocking_gaps:
        signals.append("当前仍存在阻塞交付的关键缺口。")
    if not confirmed_scope:
        signals.append("当前还没有形成稳定的已确认影响范围。")
    return unique_preserve_order(signals)


def build_delivery_decision(evidence_store: Dict[str, Any], reviewer_input: Dict[str, Any]) -> Dict[str, Any]:
    hypotheses = _hypotheses(evidence_store)
    provisional = dict(reviewer_input.get("provisional_assessment") or {})
    objects = _evidence_objects(evidence_store)
    gaps = _evidence_gaps(evidence_store)
    open_gaps = [gap for gap in gaps if str(gap.get("status") or "").strip() != "closed"]
    effective_blocking_gap_rows = [gap for gap in open_gaps if _gap_blocks_delivery(gap)]
    carryable_gap_rows = [gap for gap in open_gaps if _gap_is_boundary_only(gap)]
    blocking_gaps = [_gap_view(gap, blocks_delivery=True) for gap in effective_blocking_gap_rows]
    non_blocking_gaps = [
        _gap_view(gap, blocks_delivery=False)
        for gap in open_gaps
        if gap not in effective_blocking_gap_rows
    ]

    provisional_status = str(provisional.get("status") or "").strip() or "needs_review"
    confirmed_scope = _asset_scope(objects, roles={"seed_asset", "affected_asset"}, confirmed_only=True)
    seed_scope = set(_asset_scope(objects, roles={"seed_asset"}, confirmed_only=False))
    candidate_scope = [
        value
        for value in unique_preserve_order(
            _asset_scope(objects, roles={"related_asset"}, confirmed_only=False)
            + _event_asset_scope(list(evidence_store.get("candidate_events") or []))
        )
        if value not in set(confirmed_scope) and value not in seed_scope
    ]

    readiness = _reviewer_readiness(
        evidence_store,
        reviewer_input,
        confirmed_scope,
        effective_blocking_gap_rows,
        carryable_gap_rows,
    )
    approved = bool(readiness.get("ready_for_delivery"))
    reviewer_rationale = (
        str(readiness.get("summary") or "").strip()
        or str(hypotheses.get("positive_summary") or "").strip()
        or str(hypotheses.get("primary") or "").strip()
        or "当前交付判断主要依据现有证据链和剩余缺口。"
    )
    delivery_verdict = _final_delivery_verdict(provisional, provisional_status, readiness, reviewer_rationale)
    delivery_status = str(delivery_verdict.get("status") or "").strip() or "needs_review"
    if delivery_status != "confirmed_incident" or not approved:
        confirmed_scope = []
    analysis_verdict = {
        "status": provisional_status,
        "status_label": str(provisional.get("status_label") or "").strip() or STATUS_LABELS.get(provisional_status, "待确认"),
        "confidence": _safe_int(provisional.get("confidence")),
        "severity": str(provisional.get("severity") or "").strip() or severity_from_confidence(_safe_int(provisional.get("confidence")), provisional_status),
        "rationale": list(provisional.get("rationale") or []),
    }
    confidence_value = delivery_verdict.get("confidence") or analysis_verdict.get("confidence")
    next_best_questions = unique_preserve_order(
        [str(item.get("question") or "").strip() for item in blocking_gaps if str(item.get("question") or "").strip()]
        + [str(item.get("question") or "").strip() for item in non_blocking_gaps if str(item.get("question") or "").strip()]
    )

    return {
        "schema_version": "delivery-decision-v1",
        "approved": approved,
        "delivery_status": delivery_status,
        "delivery_status_label": STATUS_LABELS.get(
            delivery_status,
            delivery_status,
        ),
        "confidence_band": _confidence_band(confidence_value),
        "confirmed_scope": confirmed_scope,
        "candidate_scope": candidate_scope,
        "blocking_gaps": blocking_gaps,
        "non_blocking_gaps": non_blocking_gaps,
        "next_best_questions": next_best_questions,
        "reviewer_rationale": reviewer_rationale,
        "insufficient_progress_signals": _insufficient_progress_signals(reviewer_input, effective_blocking_gap_rows, confirmed_scope),
        "delivery_verdict": delivery_verdict,
        "analysis_verdict": analysis_verdict,
        "readiness": readiness,
    }
