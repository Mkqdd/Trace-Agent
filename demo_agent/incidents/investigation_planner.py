from __future__ import annotations

from typing import Any, Dict, Iterable, List, Tuple


OPPORTUNITY_TRACE_SCHEMA_VERSION = "investigation-opportunity-trace-v1"


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


def _graph_nodes_by_type(graph: Dict[str, Any], node_type: str) -> List[Dict[str, Any]]:
    return [
        _as_dict(item)
        for item in _as_list(graph.get("nodes"))
        if _text((_as_dict(item)).get("node_type")) == node_type
    ]


def _node_by_id(graph: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {
        _text((_as_dict(item)).get("node_id")): _as_dict(item)
        for item in _as_list(graph.get("nodes"))
        if _text((_as_dict(item)).get("node_id"))
    }


def _gap_node_lookup(graph: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    lookup: Dict[str, Dict[str, Any]] = {}
    for node in _graph_nodes_by_type(graph, "gap"):
        for gap_id in _as_list(node.get("gap_ids")):
            gap_id_text = _text(gap_id)
            if gap_id_text:
                lookup[gap_id_text] = node
        raw_node_id = _text(node.get("node_id"))
        if raw_node_id.startswith("gap:"):
            lookup[raw_node_id.split(":", 1)[1]] = node
    return lookup


def _action_node_lookup(graph: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    lookup: Dict[str, Dict[str, Any]] = {}
    for node in _graph_nodes_by_type(graph, "action"):
        properties = _as_dict(node.get("properties"))
        tool_name = _text(properties.get("tool_name") or node.get("label"))
        if tool_name:
            lookup[tool_name] = node
    return lookup


def _hypothesis_lookup(graph: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    board = _as_dict(graph.get("hypothesis_board"))
    return {
        _text(item.get("hypothesis_id")): _as_dict(item)
        for item in _as_list(board.get("hypotheses"))
        if _text(item.get("hypothesis_id"))
    }


def _hypothesis_status_counts(hypotheses: Dict[str, Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for hypothesis in hypotheses.values():
        status = _text(hypothesis.get("status") or "open")
        counts[status] = counts.get(status, 0) + 1
    return counts


def _target_hypotheses_for_tool(
    graph: Dict[str, Any],
    tool: Dict[str, Any],
    action_node: Dict[str, Any],
    target_gap_ids: List[str],
) -> List[str]:
    hypotheses: List[str] = []
    action_properties = _as_dict(action_node.get("properties"))
    hypotheses.extend(_as_list(action_properties.get("target_hypotheses")))
    gap_lookup = _gap_node_lookup(graph)
    for gap_id in target_gap_ids:
        gap_node = _as_dict(gap_lookup.get(gap_id))
        hypotheses.extend(_as_list(_as_dict(gap_node.get("properties")).get("target_hypotheses")))
    metadata_blob = " ".join(
        [
            _text(tool.get("tool_name")),
            _text(tool.get("category")),
            " ".join(_text(item) for item in _as_list(tool.get("capability_tags"))),
            " ".join(_text(item) for item in _as_list(tool.get("evidence_types"))),
            _text(tool.get("expected_gain")),
            " ".join(target_gap_ids),
        ]
    ).lower()
    if any(marker in metadata_blob for marker in ["candidate", "spread", "scope", "expansion", "related", "候选", "扩线"]):
        hypotheses.append("candidate_spread")
    if any(marker in metadata_blob for marker in ["counterevidence", "background", "shared", "maintenance", "benign", "反证", "背景", "共享", "维护"]):
        hypotheses.append("benign_or_shared_infra_alternative")
    if any(marker in metadata_blob for marker in ["gap", "missing", "limit", "command", "artifact", "log", "缺口", "缺少", "未闭合"]):
        hypotheses.append("insufficient_evidence_limits")
    return _dedupe(hypotheses)


def _tool_category(tool: Dict[str, Any]) -> str:
    category = _text(tool.get("category"))
    if category:
        return category
    tool_name = _text(tool.get("tool_name"))
    if tool_name in {"search_seed_context", "search_related_events", "expand_asset_scope", "check_counterevidence"}:
        return "event"
    if tool_name in {"fetch_page_content", "extract_claim_candidates_from_page", "extract_entities_from_page"}:
        return "page"
    return "intel"


def _budget_allows(tool: Dict[str, Any], budgets: Dict[str, Any]) -> Tuple[bool, str]:
    category = _tool_category(tool)
    remaining_tools = int(budgets.get("remaining_tool_calls") or 0)
    if remaining_tools <= 0:
        return False, "tool_budget_exhausted"
    if category == "event" and int(budgets.get("remaining_event_queries") or 0) <= 0:
        return False, "event_query_budget_exhausted"
    if category in {"intel", "page"} and int(budgets.get("remaining_intel_queries") or 0) <= 0:
        return False, "intel_query_budget_exhausted"
    return True, ""


def _reportable_boundary_quality_signal(
    gap_properties: List[Dict[str, Any]],
    target_hypothesis_ids: List[str],
) -> Tuple[bool, str]:
    if not gap_properties:
        return False, ""
    if not any(bool(properties.get("actionable_now")) for properties in gap_properties):
        return False, ""
    priorities = {_text(properties.get("priority")).lower() for properties in gap_properties}
    high_or_medium_priority = bool(priorities.intersection({"critical", "high", "medium"}))
    boundary_hypotheses = {
        "candidate_spread",
        "benign_or_shared_infra_alternative",
        "insufficient_evidence_limits",
    }
    if not high_or_medium_priority or not set(target_hypothesis_ids).intersection(boundary_hypotheses):
        return False, ""
    if "candidate_spread" in target_hypothesis_ids:
        return True, "report_quality_candidate_boundary"
    if "benign_or_shared_infra_alternative" in target_hypothesis_ids:
        return True, "report_quality_counterevidence_boundary"
    return True, "report_quality_limit_boundary"


def _recent_repeat_penalty(tool: Dict[str, Any], recent_tool_effects: List[Dict[str, Any]]) -> Tuple[int, List[str], bool]:
    tool_name = _text(tool.get("tool_name"))
    fingerprint = _text(tool.get("input_fingerprint"))
    if not tool_name or not fingerprint:
        return 0, [], False
    for recent in reversed(recent_tool_effects):
        if _text(recent.get("tool_name")) != tool_name:
            continue
        if _text(recent.get("input_fingerprint")) != fingerprint:
            continue
        novelty = int(recent.get("novelty_score") or recent.get("material_score") or 0)
        if novelty <= 1:
            return -4, ["repeat_low_delta"], True
    return 0, [], False


def _recent_reportable_boundary_progress(
    target_gap_ids: List[str],
    recent_tool_effects: List[Dict[str, Any]],
) -> Tuple[int, bool]:
    target_ids = {_text(item) for item in target_gap_ids if _text(item)}
    if not target_ids:
        return 0, False
    progress_count = 0
    recent_low_value = False
    for recent in reversed(recent_tool_effects):
        recent_gap_ids = {_text(item) for item in _as_list(recent.get("target_gap_ids")) if _text(item)}
        if not recent_gap_ids.intersection(target_ids):
            continue
        novelty = int(recent.get("novelty_score") or recent.get("material_score") or 0)
        material = int(recent.get("material_score") or 0)
        closed_candidates = int(recent.get("closed_candidate_event_count") or 0)
        closed_gaps = int(recent.get("closed_gap_count") or 0)
        if closed_candidates > 0 or closed_gaps > 0 or material >= 2 or novelty >= 3:
            progress_count += 1
        elif material <= 1 and novelty <= 1:
            recent_low_value = True
    return progress_count, recent_low_value


def _active_hypothesis_ids(hypotheses: Dict[str, Dict[str, Any]]) -> List[str]:
    return _dedupe(
        hypothesis_id
        for hypothesis_id, hypothesis in hypotheses.items()
        if _text(hypothesis.get("status")) in {"open", "supported"}
    )


def _score_action(
    graph: Dict[str, Any],
    tool: Dict[str, Any],
    *,
    budgets: Dict[str, Any],
    recent_tool_effects: List[Dict[str, Any]],
) -> Dict[str, Any]:
    action_lookup = _action_node_lookup(graph)
    gap_lookup = _gap_node_lookup(graph)
    runtime = _as_dict(graph.get("runtime_summary"))
    hypotheses = _hypothesis_lookup(graph)
    tool_name = _text(tool.get("tool_name"))
    action_node = _as_dict(action_lookup.get(tool_name))
    action_properties = _as_dict(action_node.get("properties"))
    target_gap_ids = _dedupe(
        [
            *_as_list(tool.get("target_gap_ids")),
            *_as_list(tool.get("relevant_gap_ids")),
            *_as_list(action_properties.get("target_gap_ids")),
        ]
    )
    target_hypothesis_ids = _target_hypotheses_for_tool(graph, tool, action_node, target_gap_ids)
    score = 0
    score_reasons: List[str] = []
    penalty_reasons: List[str] = []

    budget_ok, budget_reason = _budget_allows(tool, budgets)
    blocking_gap_ids = set(_as_list(runtime.get("blocking_gap_ids")))
    reportable_gap_ids = set(_as_list(runtime.get("reportable_gap_ids")))
    open_gap_ids = set(_as_list(runtime.get("open_gap_ids")))
    background_event_ids = set(_as_list(runtime.get("background_event_ids")))
    delivery_relevant_open_gap_ids = open_gap_ids - reportable_gap_ids
    targets_reportable_only = bool(target_gap_ids) and set(target_gap_ids).issubset(reportable_gap_ids)
    reportable_gap_properties = [
        _as_dict(_as_dict(_as_dict(gap_lookup.get(gap_id)).get("properties")))
        for gap_id in target_gap_ids
        if gap_id in reportable_gap_ids
    ]
    reportable_quality, reportable_quality_reason = _reportable_boundary_quality_signal(
        reportable_gap_properties,
        target_hypothesis_ids,
    )

    if set(target_gap_ids).intersection(blocking_gap_ids):
        score += 5
        score_reasons.append("closes_blocking_gap")
    elif set(target_gap_ids).intersection(delivery_relevant_open_gap_ids):
        score += 3
        score_reasons.append("reduces_open_gap")
    elif targets_reportable_only:
        score += 1
        score_reasons.append("documents_reportable_boundary")

    for gap_id in target_gap_ids:
        gap_node = _as_dict(gap_lookup.get(gap_id))
        properties = _as_dict(gap_node.get("properties"))
        if bool(properties.get("actionable_now")) and gap_id not in reportable_gap_ids:
            score += 1
            score_reasons.append("actionable_gap")
            break

    if "candidate_spread" in target_hypothesis_ids and (
        not targets_reportable_only or reportable_quality
    ) and (
        _as_list(runtime.get("candidate_event_ids"))
        or _text(_as_dict(hypotheses.get("candidate_spread")).get("status")) in {"open", "supported"}
    ):
        score += 3 if targets_reportable_only else 4
        score_reasons.append(reportable_quality_reason or "candidate_boundary_impact")
    if "benign_or_shared_infra_alternative" in target_hypothesis_ids and (
        not targets_reportable_only or reportable_quality
    ) and (
        background_event_ids
        or _text(_as_dict(hypotheses.get("benign_or_shared_infra_alternative")).get("status")) in {"open", "supported"}
    ):
        if targets_reportable_only:
            if len(background_event_ids) >= 2:
                score -= 2
                penalty_reasons.append("background_boundary_already_sampled")
            elif background_event_ids:
                score += 1
                score_reasons.append("counterevidence_boundary_progress")
            else:
                score += 2
                score_reasons.append(reportable_quality_reason or "counterevidence_boundary_impact")
        else:
            score += 3
            score_reasons.append("counterevidence_boundary_impact")
    if "insufficient_evidence_limits" in target_hypothesis_ids and (
        (delivery_relevant_open_gap_ids and not targets_reportable_only) or reportable_quality
    ):
        score += 1 if targets_reportable_only else 2
        score_reasons.append(reportable_quality_reason or "limit_reduction")
    if targets_reportable_only and reportable_quality_reason and reportable_quality_reason not in score_reasons:
        score_reasons.append(reportable_quality_reason)
    if targets_reportable_only and not reportable_quality and not set(target_gap_ids).intersection(blocking_gap_ids):
        score -= 2
        penalty_reasons.append("reportable_boundary_not_delivery_blocking")

    if bool(tool.get("recommended_now")):
        score += 1
        score_reasons.append("already_safe_candidate")
    if not target_hypothesis_ids and not target_gap_ids:
        score -= 2
        penalty_reasons.append("untargeted_action")
    penalty, penalty_markers, repeat_ineligible = _recent_repeat_penalty(tool, recent_tool_effects)
    score += penalty
    penalty_reasons.extend(penalty_markers)
    if targets_reportable_only and reportable_quality:
        boundary_progress_count, recent_boundary_low_value = _recent_reportable_boundary_progress(
            target_gap_ids,
            recent_tool_effects,
        )
        if boundary_progress_count >= 2:
            score -= 5
            penalty_reasons.append("reportable_boundary_already_sampled")
        elif recent_boundary_low_value:
            score -= 4
            penalty_reasons.append("recent_reportable_boundary_low_delta")

    eligible = bool(budget_ok and score > 0 and not repeat_ineligible)
    if not budget_ok:
        penalty_reasons.append(budget_reason)
    if repeat_ineligible:
        eligible = False

    score = max(score, -10)
    expected_information_gain = "high" if score >= 6 else ("medium" if score >= 3 else ("low" if score > 0 else "none"))
    expected_report_impact = "scope_or_boundary_change" if any(
        hypothesis in target_hypothesis_ids for hypothesis in ["candidate_spread", "benign_or_shared_infra_alternative"]
    ) else ("limit_reduction" if "insufficient_evidence_limits" in target_hypothesis_ids else "minor_context")
    active_hypotheses = _active_hypothesis_ids(hypotheses)
    why_not_finish = (
        "High-value hypotheses remain open: " + ", ".join(target_hypothesis_ids or active_hypotheses[:3])
        if eligible and score >= 3
        else "No high-value targeted action remains beyond reportable boundaries."
    )
    why_this_tool = "; ".join(score_reasons[:5]) if score_reasons else _text(tool.get("expected_gain")) or "No strong deterministic gain signal."
    return {
        "tool_name": tool_name,
        "score": score,
        "eligible": eligible,
        "target_gap_ids": target_gap_ids,
        "target_hypothesis_ids": target_hypothesis_ids,
        "expected_information_gain": expected_information_gain,
        "expected_report_impact": expected_report_impact,
        "why_this_tool": why_this_tool,
        "why_not_finish": why_not_finish,
        "score_reasons": _dedupe(score_reasons),
        "penalty_reasons": _dedupe(penalty_reasons),
        "input_fingerprint": _text(tool.get("input_fingerprint")),
        "recommended_params": _as_dict(tool.get("recommended_params") or tool.get("safe_params_hint")),
    }


def _value_of_information(ranked_actions: List[Dict[str, Any]], graph: Dict[str, Any]) -> Dict[str, Any]:
    eligible = [item for item in ranked_actions if bool(item.get("eligible"))]
    best = eligible[0] if eligible else {}
    best_score = int(best.get("score") or 0)
    runtime = _as_dict(graph.get("runtime_summary"))
    hypotheses = _hypothesis_lookup(graph)
    active_hypotheses = _active_hypothesis_ids(hypotheses)
    reportable_gap_ids = set(_as_list(runtime.get("reportable_gap_ids")))
    delivery_relevant_open_gap_ids = [
        gap_id
        for gap_id in _as_list(runtime.get("open_gap_ids"))
        if gap_id not in reportable_gap_ids
    ]
    finish_score = 3 if not eligible and not delivery_relevant_open_gap_ids else (1 if best_score >= 3 else 2)

    if not eligible:
        level = "exhausted"
    elif best_score >= 6:
        level = "high"
    elif best_score >= 3:
        level = "medium"
    else:
        level = "low"
    reason = (
        f"Best action {best.get('tool_name')} scores {best_score} against active hypotheses {', '.join(active_hypotheses[:4])}."
        if best
        else "No eligible high-value action remains after budget, repeat, and target checks."
    )
    return {
        "level": level,
        "best_action": _text(best.get("tool_name")),
        "best_action_score": best_score,
        "finish_score": finish_score,
        "active_hypothesis_ids": active_hypotheses,
        "reason": reason,
    }


def score_investigation_opportunities(
    graph: Dict[str, Any],
    tool_catalog: List[Dict[str, Any]],
    *,
    budgets: Dict[str, Any],
    recent_tool_effects: List[Dict[str, Any]],
    top_k: int = 3,
) -> Dict[str, Any]:
    graph = _as_dict(graph)
    budgets = _as_dict(budgets)
    recent_tool_effects = [_as_dict(item) for item in _as_list(recent_tool_effects)]
    ranked_actions = [
        _score_action(graph, _as_dict(tool), budgets=budgets, recent_tool_effects=recent_tool_effects)
        for tool in _as_list(tool_catalog)
        if _text(_as_dict(tool).get("tool_name"))
    ]
    ranked_actions.sort(
        key=lambda item: (
            0 if bool(item.get("eligible")) else 1,
            -int(item.get("score") or 0),
            _text(item.get("tool_name")),
        )
    )
    value = _value_of_information(ranked_actions, graph)
    stop = bool(value.get("level") in {"low", "exhausted"})
    stop_reason = (
        "Remaining actions are low value or exhausted; unresolved items should become reportable boundaries."
        if stop
        else "At least one high-value investigation action remains."
    )
    return {
        "schema_version": OPPORTUNITY_TRACE_SCHEMA_VERSION,
        "graph_schema_version": _text(graph.get("schema_version")),
        "ranked_actions": ranked_actions,
        "top_k": ranked_actions[: max(1, int(top_k or 3))],
        "value_of_information": value,
        "stop_recommendation": {
            "should_stop": stop,
            "reason": stop_reason,
        },
        "hypothesis_status_counts": _hypothesis_status_counts(_hypothesis_lookup(graph)),
    }
