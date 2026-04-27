from __future__ import annotations

import json
import os
import time
import ipaddress
import hashlib
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from ..tools import (
    abuse_ch_lookup,
    extract_claim_candidates_from_page,
    extract_entities_from_page,
    fetch_page_content,
    local_intel_lookup,
    malware_profile_lookup,
    pivot_related_indicators,
    technical_source_search,
    threatfox_ioc_lookup,
    urlhaus_ioc_lookup,
    vt_enrich_ioc,
)
from ..types.event import normalize_alert
from .contracts import infer_stages, parse_timestamp, severity_from_confidence, suspicion_score, unique_preserve_order
from .evidence_store import build_runtime_evidence_store
from .pipeline import (
    _annotate_events,
    _build_decision_basis,
    _build_evidence_clusters,
    _build_hypothesis,
    _build_incident_summary,
    _build_recommendations,
    _build_timeline,
    _build_uncertainties,
    _extract_entities,
)
from .render import build_incident_report_outline, build_incident_topology, render_incident_report_with_llm
from .reviewer import build_delivery_decision, build_reviewer_input
from .store import FixtureTraceStoreAdapter, TraceStore


DEFAULT_BUDGETS = {
    "max_steps": 8,
    "max_tool_calls": 12,
    "max_event_queries": 8,
    "max_intel_queries": 4,
    "max_runtime_s": 120,
}

COUNTEREVIDENCE_TOOL_NAME = "check_counterevidence"
GROUND_CANDIDATE_TOOL_NAME = "ground_candidate_event"
EVENT_TOOL_NAMES = {"search_seed_context", "search_related_events", "expand_asset_scope", COUNTEREVIDENCE_TOOL_NAME}
INTEL_TOOL_NAMES = {
    GROUND_CANDIDATE_TOOL_NAME,
    "local_intel_lookup",
    "vt_enrich_ioc",
    "abuse_ch_lookup",
    "technical_source_search",
    "malware_profile_lookup",
    "pivot_related_indicators",
    "threatfox_ioc_lookup",
    "urlhaus_ioc_lookup",
}
PAGE_TOOL_NAMES = {"fetch_page_content", "extract_claim_candidates_from_page", "extract_entities_from_page"}
ALL_TOOL_NAMES = EVENT_TOOL_NAMES | INTEL_TOOL_NAMES | PAGE_TOOL_NAMES
STATUS_LABELS = {
    "confirmed_incident": "确认事件",
    "needs_review": "待人工复核",
    "monitor_only": "降级观察",
}
DECISION_MODE_HEURISTIC = "heuristic"
DECISION_MODE_LLM_SELECTOR = "llm_selector"
DECISION_MODE_LLM_AGENT = "llm_agent"
DECISION_MODE_HYBRID = "hybrid"
VALID_DECISION_MODES = {
    DECISION_MODE_HEURISTIC,
    DECISION_MODE_LLM_SELECTOR,
    DECISION_MODE_LLM_AGENT,
    DECISION_MODE_HYBRID,
}
REVIEWER_DECISIONS = {"allow", "block", "redundant", "deliverable", "not_deliverable"}
REVIEWER_NEXT_ACTION_TYPES = {"tool", "finish", "none"}
GROUNDING_STATUS_CONTEXT_ONLY = "context_only"
GROUNDING_STATUS_GROUNDED = "grounded_but_unconfirmed"
GROUNDING_STATUS_CONFIRMED = "confirmed_supporting"
ORDERED_TOOL_NAMES = [
    "search_seed_context",
    "search_related_events",
    GROUND_CANDIDATE_TOOL_NAME,
    COUNTEREVIDENCE_TOOL_NAME,
    "expand_asset_scope",
    "local_intel_lookup",
    "vt_enrich_ioc",
    "abuse_ch_lookup",
    "technical_source_search",
    "threatfox_ioc_lookup",
    "urlhaus_ioc_lookup",
    "malware_profile_lookup",
    "pivot_related_indicators",
    "fetch_page_content",
    "extract_claim_candidates_from_page",
    "extract_entities_from_page",
]
TOOL_CAPABILITY_PROFILES = {
    "search_seed_context": {
        "tool_mode": "investigation",
        "capability_tags": ["context_building", "cluster_expand", "timeline", "scope"],
        "evidence_types": ["event_context", "network_event"],
    },
    "search_related_events": {
        "tool_mode": "investigation",
        "capability_tags": ["cluster_expand", "timeline", "scope", "asset_scope", "host_confirmation"],
        "evidence_types": ["event_context", "network_event"],
    },
    GROUND_CANDIDATE_TOOL_NAME: {
        "tool_mode": "intel",
        "capability_tags": ["candidate_grounding", "local_intel", "external_intel", "infra_context", "structured_intel"],
        "evidence_types": ["candidate_validation", "structured_intel", "ioc_reputation"],
    },
    COUNTEREVIDENCE_TOOL_NAME: {
        "tool_mode": "investigation",
        "capability_tags": ["counterevidence", "background_validation"],
        "evidence_types": ["counterevidence", "asset_context"],
    },
    "expand_asset_scope": {
        "tool_mode": "investigation",
        "capability_tags": ["asset_scope", "scope", "host_confirmation"],
        "evidence_types": ["asset_context", "scope_context"],
    },
    "local_intel_lookup": {
        "tool_mode": "intel",
        "capability_tags": ["local_intel", "infra_context", "structured_intel", "fingerprint_lookup"],
        "evidence_types": ["local_intel", "structured_intel"],
    },
    "vt_enrich_ioc": {
        "tool_mode": "intel",
        "capability_tags": ["external_intel", "infra_context", "structured_intel", "ioc_reputation"],
        "evidence_types": ["ioc_reputation", "structured_intel"],
    },
    "abuse_ch_lookup": {
        "tool_mode": "intel",
        "capability_tags": ["external_intel", "infra_context", "structured_intel"],
        "evidence_types": ["structured_intel", "reference_search"],
    },
    "technical_source_search": {
        "tool_mode": "intel",
        "capability_tags": ["external_intel", "family_validation", "infra_context"],
        "evidence_types": ["external_intel", "reference_search"],
    },
    "threatfox_ioc_lookup": {
        "tool_mode": "intel",
        "capability_tags": ["external_intel", "family_validation", "infra_context"],
        "evidence_types": ["structured_intel", "ioc_reputation"],
    },
    "urlhaus_ioc_lookup": {
        "tool_mode": "intel",
        "capability_tags": ["external_intel", "family_validation", "infra_context"],
        "evidence_types": ["structured_intel", "ioc_reputation"],
    },
    "malware_profile_lookup": {
        "tool_mode": "intel",
        "capability_tags": ["external_intel", "family_validation"],
        "evidence_types": ["family_profile", "reference_search"],
    },
    "pivot_related_indicators": {
        "tool_mode": "intel",
        "capability_tags": ["external_intel", "infra_context"],
        "evidence_types": ["related_ioc", "reference_search"],
    },
    "fetch_page_content": {
        "tool_mode": "retrieval",
        "capability_tags": ["source_retrieval", "external_intel"],
        "evidence_types": ["page_content", "reference_text"],
    },
    "extract_claim_candidates_from_page": {
        "tool_mode": "structuring",
        "capability_tags": ["evidence_structuring"],
        "evidence_types": ["structured_claim"],
    },
    "extract_entities_from_page": {
        "tool_mode": "structuring",
        "capability_tags": ["entity_structuring"],
        "evidence_types": ["structured_entity"],
    },
}
GROUNDING_STATUS_LABELS = {
    GROUNDING_STATUS_CONTEXT_ONLY: "仅上下文",
    GROUNDING_STATUS_GROUNDED: "已验证待确认",
    GROUNDING_STATUS_CONFIRMED: "已确认支撑",
}


def _gap_record(
    gap_id: str,
    *,
    priority: str,
    question: str,
    gap_type: str,
    materiality: str,
    tool_capability_hints: List[str],
    delivery_blocking: bool,
    reportable_if_unresolved: bool,
    closure_criteria: Optional[List[str]] = None,
) -> Dict[str, Any]:
    return {
        "id": gap_id,
        "priority": priority,
        "question": question,
        "gap_type": gap_type,
        "materiality": materiality,
        "tool_capability_hints": unique_preserve_order(tool_capability_hints),
        "delivery_blocking": delivery_blocking,
        "reportable_if_unresolved": reportable_if_unresolved,
        "closure_criteria": unique_preserve_order(list(closure_criteria or [])),
    }


def _grounding_status_label(status: str) -> str:
    return GROUNDING_STATUS_LABELS.get(str(status or "").strip(), str(status or "").strip())


def _canonical_gap_candidates(seed_event: Dict[str, Any], session_state: Dict[str, Any], incident_state: Dict[str, Any]) -> List[Dict[str, Any]]:
    verdict = (
        incident_state.get("provisional_verdict")
        or incident_state.get("analysis_verdict")
        or incident_state.get("delivery_verdict")
        or incident_state.get("verdict")
        or {"status": "needs_review"}
    )
    return _open_questions(seed_event, session_state, incident_state, verdict)


def _display_open_questions_from_gap_ledger(gap_ledger: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    display_rows: List[Dict[str, Any]] = []
    for gap in list(gap_ledger or []):
        if str(gap.get("status") or "").strip() == "closed":
            continue
        display_rows.append(
            {
                "id": str(gap.get("id") or "").strip(),
                "question": str(gap.get("question") or "").strip(),
                "gap_type": str(gap.get("gap_type") or "").strip(),
                "priority": str(gap.get("priority") or "").strip() or "medium",
                "status": str(gap.get("status") or "").strip() or "open",
                "status_reason": str(gap.get("status_reason") or "").strip(),
                "delivery_blocking": bool(gap.get("delivery_blocking")),
                "actionable_now": bool(gap.get("actionable_now")),
                "closure_criteria": unique_preserve_order(list(gap.get("closure_criteria") or [])),
            }
        )
    return display_rows


def _carryable_gap_view(gap: Dict[str, Any], *, status_reason: str = "") -> Dict[str, Any]:
    carryable = dict(gap)
    carryable["status"] = "reportable_unresolved"
    carryable["status_reason"] = str(carryable.get("status_reason") or "").strip() or status_reason
    carryable["actionable_now"] = False
    carryable["actionable_tools"] = []
    carryable["delivery_blocking"] = False
    return carryable


def _gap_map(rows: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    return {
        str(item.get("id") or item.get("gap_id") or "").strip(): dict(item)
        for item in list(rows or [])
        if str(item.get("id") or item.get("gap_id") or "").strip()
    }


def _merged_gap_map(*row_groups: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    merged: Dict[str, Dict[str, Any]] = {}
    for rows in row_groups:
        for item in list(rows or []):
            gap_id = str(item.get("id") or item.get("gap_id") or "").strip()
            if not gap_id:
                continue
            base = dict(merged.get(gap_id) or {})
            base.update(dict(item))
            if "id" not in base:
                base["id"] = gap_id
            merged[gap_id] = base
    return merged


def _selected_gap_ids_for_action(tool_name: str, gap_rows: List[Dict[str, Any]], explicit_ids: Optional[List[str]] = None) -> List[str]:
    explicit = [str(item or "").strip() for item in list(explicit_ids or []) if str(item or "").strip()]
    if explicit:
        return unique_preserve_order(explicit)
    return _matching_gap_ids_for_tool(str(tool_name or "").strip(), list(gap_rows or []))


def _selected_gap_view(gap_rows: List[Dict[str, Any]], selected_gap_ids: List[str]) -> List[Dict[str, Any]]:
    gap_lookup = _gap_map(gap_rows)
    selected: List[Dict[str, Any]] = []
    for gap_id in list(selected_gap_ids or []):
        gap = dict(gap_lookup.get(str(gap_id or "").strip()) or {})
        if not gap:
            continue
        selected.append(
            {
                "gap_id": str(gap.get("id") or gap.get("gap_id") or "").strip(),
                "question": str(gap.get("question") or "").strip(),
                "gap_type": str(gap.get("gap_type") or "").strip(),
                "status": str(gap.get("status") or "").strip() or "open",
                "delivery_blocking": bool(gap.get("delivery_blocking")),
                "closure_criteria": unique_preserve_order(list(gap.get("closure_criteria") or [])),
            }
        )
    return selected


def _candidate_alignment_view(alignment: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "priority_tier": str(alignment.get("priority_tier") or "").strip(),
        "reason": str(alignment.get("reason") or "").strip(),
        "focus_question": str(alignment.get("focus_question") or "").strip(),
        "focus_gap_ids": list(alignment.get("focus_gap_ids") or []),
        "blocking_gap_ids": list(alignment.get("blocking_gap_ids") or []),
        "reportable_only": bool(alignment.get("reportable_only")),
        "blocking_focus_missing": bool(alignment.get("blocking_focus_missing")),
    }


def _candidate_control_alignment(
    tool_name: str,
    target_gap_ids: List[str],
    gap_rows: List[Dict[str, Any]],
    acceptance_state: Dict[str, Any],
    control_summary: Dict[str, Any],
) -> Dict[str, Any]:
    selected_gap_ids = [
        str(item or "").strip()
        for item in list(target_gap_ids or [])
        if str(item or "").strip()
    ]
    gap_lookup = _gap_map(gap_rows)
    next_focus = dict(control_summary.get("next_focus") or {})
    focus_gap_id = str(next_focus.get("gap_id") or "").strip()
    focus_question = str(next_focus.get("question") or control_summary.get("primary_goal") or "").strip()
    blocking_gap_ids = {
        str(item.get("id") or item.get("gap_id") or "").strip()
        for item in list(acceptance_state.get("blocking_actionable_gaps") or [])
        if str(item.get("id") or item.get("gap_id") or "").strip()
    }
    actionable_gap_ids = {
        str(item.get("id") or item.get("gap_id") or "").strip()
        for item in list(acceptance_state.get("actionable_gaps") or [])
        if str(item.get("id") or item.get("gap_id") or "").strip()
    }
    reportable_gap_ids = {
        str(item.get("id") or item.get("gap_id") or "").strip()
        for item in list(acceptance_state.get("reportable_gaps") or [])
        if str(item.get("id") or item.get("gap_id") or "").strip()
    }
    focus_overlap_ids = [
        gap_id
        for gap_id in selected_gap_ids
        if gap_id and gap_id == focus_gap_id
    ]
    blocking_overlap_ids = [
        gap_id
        for gap_id in selected_gap_ids
        if gap_id in blocking_gap_ids
    ]
    actionable_overlap_ids = [
        gap_id
        for gap_id in selected_gap_ids
        if gap_id in actionable_gap_ids
    ]
    reportable_only = bool(selected_gap_ids) and all(
        gap_id in reportable_gap_ids
        or str((gap_lookup.get(gap_id) or {}).get("status") or "").strip() in {"reportable_unresolved", "open_unaddressable"}
        or not bool((gap_lookup.get(gap_id) or {}).get("actionable_now", True))
        for gap_id in selected_gap_ids
    )
    blocking_focus_missing = bool(blocking_gap_ids) and bool(selected_gap_ids) and not bool(blocking_overlap_ids)

    priority_tier = "unmapped"
    reason = "当前动作没有明确映射到未闭合问题。"
    if reportable_only:
        priority_tier = "boundary_only"
        reason = "当前只对应已转为报告边界或暂不可解的问题，不宜继续优先调查。"
    elif focus_overlap_ids:
        priority_tier = "primary_focus"
        reason = f"直接对应当前主焦点：{focus_question or '当前最优先未闭合问题'}"
    elif blocking_overlap_ids:
        priority_tier = "blocking_gap"
        reason = "可直接缩小当前仍阻塞交付的关键 gap。"
    elif actionable_overlap_ids:
        priority_tier = "actionable_gap"
        reason = "可继续缩小未闭合且当前仍可行动的问题。"
    elif selected_gap_ids:
        priority_tier = "supporting"
        reason = "更偏补充性动作，可增强背景或结构化程度。"

    return {
        "tool_name": str(tool_name or "").strip(),
        "priority_tier": priority_tier,
        "reason": reason,
        "focus_question": focus_question,
        "focus_gap_ids": unique_preserve_order(focus_overlap_ids),
        "blocking_gap_ids": unique_preserve_order(blocking_overlap_ids),
        "reportable_only": reportable_only,
        "blocking_focus_missing": blocking_focus_missing,
    }


def _proposal_alignment_view(
    action_type: str,
    tool_name: str,
    target_gap_ids: List[str],
    gap_rows: List[Dict[str, Any]],
    acceptance_state: Dict[str, Any],
    control_summary: Dict[str, Any],
) -> Dict[str, Any]:
    normalized_action = str(action_type or "").strip()
    if normalized_action == "finish":
        blocking_gap_ids = [
            str(item.get("id") or item.get("gap_id") or "").strip()
            for item in list(acceptance_state.get("blocking_actionable_gaps") or [])
            if str(item.get("id") or item.get("gap_id") or "").strip()
        ]
        return {
            "tool_name": "",
            "priority_tier": "finish_request",
            "reason": (
                "当前没有仍可继续缩小的关键 gap，可以优先结束调查。"
                if not blocking_gap_ids
                else "当前仍存在可继续缩小的关键 gap，finish 需要更强理由。"
            ),
            "focus_question": str((control_summary.get("next_focus") or {}).get("question") or control_summary.get("primary_goal") or "").strip(),
            "focus_gap_ids": [],
            "blocking_gap_ids": blocking_gap_ids,
            "reportable_only": False,
            "blocking_focus_missing": bool(blocking_gap_ids),
        }
    return _candidate_control_alignment(
        tool_name,
        target_gap_ids,
        gap_rows,
        acceptance_state,
        control_summary,
    )


def _acceptance_priority_bonus(
    candidate: Dict[str, Any],
    acceptance_state: Dict[str, Any],
    control_summary: Dict[str, Any],
) -> int:
    candidate_gap_ids = {
        str(item or "").strip()
        for item in list(candidate.get("target_gap_ids") or [])
        if str(item or "").strip()
    }
    alignment = dict(candidate.get("alignment") or {})
    priority_tier = str(alignment.get("priority_tier") or "").strip()
    score = 0
    if priority_tier == "primary_focus":
        score += 72
    elif priority_tier == "blocking_gap":
        score += 44
    elif priority_tier == "actionable_gap":
        score += 18
    elif priority_tier == "boundary_only":
        score -= 36
    elif priority_tier == "unmapped":
        score -= 22
    if bool(alignment.get("blocking_focus_missing")):
        score -= 18
    if bool(alignment.get("reportable_only")):
        score -= 12
    if bool(acceptance_state.get("preferred_stop")) and priority_tier not in {"primary_focus", "blocking_gap"}:
        score -= 20
    if not candidate_gap_ids and list(acceptance_state.get("blocking_actionable_gaps") or []):
        score -= 20
    if not str((control_summary.get("next_focus") or {}).get("gap_id") or "").strip() and priority_tier == "actionable_gap":
        score += 6
    return score


def _candidate_action_priority(candidate: Dict[str, Any], gap_rows: List[Dict[str, Any]]) -> int:
    gap_lookup = _gap_map(gap_rows)
    score = 0
    tool_name = str(candidate.get("tool_name") or "").strip()
    for gap_id in list(candidate.get("target_gap_ids") or []):
        gap = dict(gap_lookup.get(str(gap_id or "").strip()) or {})
        if not gap:
            continue
        score += _gap_priority_score(str(gap.get("priority") or ""))
        score += _tool_gap_match_score(tool_name, gap) * 6
        if bool(gap.get("delivery_blocking")):
            score += 20
        status = str(gap.get("status") or "").strip()
        if status == "open":
            score += 8
        elif status == "stalled":
            score -= 6
        elif status in {"reportable_unresolved", "open_unaddressable"}:
            score -= 12
    category = str(candidate.get("category") or "").strip()
    if category == "event":
        score += 2
    if str(candidate.get("tool_name") or "").strip() == COUNTEREVIDENCE_TOOL_NAME:
        score += 4
    if bool(candidate.get("recent_materially_depleted")):
        score -= 25
    repeat_risk = str(candidate.get("repeat_risk") or "").strip().lower()
    if repeat_risk == "medium":
        score -= 8
    elif repeat_risk == "high":
        score -= 15
    score += int(candidate.get("recent_material_score") or 0)
    score += int(candidate.get("acceptance_priority_bonus") or 0)
    return score


def _gap_transition_view(
    before_rows: List[Dict[str, Any]],
    after_rows: List[Dict[str, Any]],
    selected_gap_ids: List[str],
) -> Dict[str, Any]:
    before_map = _gap_map(before_rows)
    after_map = _gap_map(after_rows)
    status_changes: List[Dict[str, Any]] = []
    changed_ids: List[str] = []
    closed_ids: List[str] = []

    for gap_id in list(selected_gap_ids or []):
        before = dict(before_map.get(str(gap_id or "").strip()) or {})
        after = dict(after_map.get(str(gap_id or "").strip()) or {})
        before_status = str(before.get("status") or "").strip() or "missing"
        after_status = str(after.get("status") or "").strip() or "missing"
        if before_status != after_status or str(before.get("status_reason") or "").strip() != str(after.get("status_reason") or "").strip():
            changed_ids.append(str(gap_id))
            status_changes.append(
                {
                    "gap_id": str(gap_id),
                    "before_status": before_status,
                    "after_status": after_status,
                    "before_reason": str(before.get("status_reason") or "").strip(),
                    "after_reason": str(after.get("status_reason") or "").strip(),
                }
            )
        if before_status != "closed" and after_status == "closed":
            closed_ids.append(str(gap_id))

    return {
        "changed_gap_ids": unique_preserve_order(changed_ids),
        "closed_gap_ids": unique_preserve_order(closed_ids),
        "status_changes": status_changes,
    }


def _meaningful_family_hint(seed_event: Dict[str, Any]) -> str:
    hint = str((((seed_event.get("enrichment") or {}).get("info")) or "")).strip()
    lowered = hint.lower()
    if not hint:
        return ""
    if lowered.startswith("unknown"):
        return ""
    if lowered in {"suspicious", "unknown suspicious tls fingerprint"}:
        return ""
    if "candidate" in lowered and "possible" not in lowered:
        return ""
    return hint


_RELATION_PRIORITY = {
    "candidate": 10,
    "context": 20,
    "alternative": 20,
    "counterevidence": 30,
    "supporting": 40,
}


def _normalize_relation_hint(value: Any) -> str:
    text = str(value or "").strip().lower()
    return text if text in _RELATION_PRIORITY else ""


def _merge_relation_hint(existing: str, incoming: str) -> str:
    if not incoming:
        return existing
    if not existing:
        return incoming
    if int(_RELATION_PRIORITY.get(incoming, 0)) >= int(_RELATION_PRIORITY.get(existing, 0)):
        return incoming
    return existing


def _event_relation_hints_from_ledger(incident_state: Dict[str, Any]) -> Dict[str, str]:
    hints: Dict[str, str] = {}
    for item in list(incident_state.get("evidence_ledger") or []):
        relation = _normalize_relation_hint(item.get("relation"))
        if not relation:
            continue
        for event_id in list(item.get("event_ids") or []):
            normalized_id = str(event_id or "").strip()
            if not normalized_id:
                continue
            hints[normalized_id] = _merge_relation_hint(hints.get(normalized_id, ""), relation)
    return hints


def _annotated_event_state(seed_event: Dict[str, Any], incident_state: Dict[str, Any]) -> Dict[str, Any]:
    known_events = list((incident_state.get("known_events") or {}).values())
    known_events.sort(key=lambda item: str(item.get("ts") or ""))
    return _annotate_events(
        seed_event,
        known_events,
        event_relation_hints=_event_relation_hints_from_ledger(incident_state),
    )


def _candidate_event_priority(event: Dict[str, Any], *, seed_asset: str = "") -> int:
    score = max(0, suspicion_score(event))
    score += len(infer_stages(event)) * 3
    asset_id = str(event.get("asset_id") or "").strip()
    if asset_id and seed_asset and asset_id != seed_asset:
        score += 2
    if str(event.get("dst_ip") or "").strip():
        score += 1
    if str(event.get("domain") or "").strip():
        score += 1
    if str(event.get("ja4") or "").strip() or str(event.get("ja3") or "").strip():
        score += 1
    return score


def _candidate_events(seed_event: Dict[str, Any], incident_state: Dict[str, Any]) -> List[Dict[str, Any]]:
    annotation = _annotated_event_state(seed_event, incident_state)
    seed_asset = _seed_asset_hint(seed_event)
    candidates = [
        dict(item)
        for item in list(annotation.get("events") or [])
        if str(item.get("role") or "").strip() == "candidate"
    ]
    candidates.sort(
        key=lambda item: (
            -_candidate_event_priority(item, seed_asset=seed_asset),
            str(item.get("ts") or ""),
            str(item.get("id") or ""),
        )
    )
    return candidates


def _event_indicator_candidates(event: Dict[str, Any]) -> List[Dict[str, str]]:
    indicators: List[Dict[str, str]] = []
    seen = set()

    def _add(indicator_type: str, value: Any, label: str) -> None:
        text = str(value or "").strip()
        key = (indicator_type, text)
        if not text or key in seen:
            return
        seen.add(key)
        indicators.append({"indicator_type": indicator_type, "indicator_value": text, "label": label})

    dst_ip = str(event.get("dst_ip") or "").strip()
    if dst_ip and not _is_internal_ip(dst_ip):
        _add("IP", dst_ip, "dst_ip")
    _add("DOMAIN", event.get("domain"), "domain")
    _add("JA4", event.get("ja4"), "ja4")
    _add("JA3", event.get("ja3"), "ja3")
    _add("SSL_SHA1", event.get("ssl_sha1"), "ssl_sha1")
    _add("CERT_SHA1", event.get("cert_sha1"), "cert_sha1")
    return indicators


def _event_trace_params(event: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "event_id": str(event.get("id") or "").strip(),
        "asset_id": str(event.get("asset_id") or "").strip(),
        "dst_ip": str(event.get("dst_ip") or "").strip(),
        "domain": str(event.get("domain") or "").strip(),
        "ja4": str(event.get("ja4") or "").strip(),
        "ja3": str(event.get("ja3") or "").strip(),
    }


def _default_indicator_target(seed_event: Dict[str, Any], incident_state: Dict[str, Any]) -> Dict[str, str]:
    for event in _candidate_events(seed_event, incident_state):
        indicators = _event_indicator_candidates(event)
        if indicators:
            return {**indicators[0], "event_id": str(event.get("id") or "").strip()}
    primary_indicator = _primary_indicator(seed_event, incident_state)
    indicator_type = _extract_indicator_type(primary_indicator)
    if primary_indicator and indicator_type:
        return {
            "indicator_type": indicator_type,
            "indicator_value": primary_indicator,
            "label": "primary_indicator",
            "event_id": "",
        }
    return {}


def _virustotal_indicator_target(seed_event: Dict[str, Any], incident_state: Dict[str, Any]) -> Dict[str, str]:
    indicator_target = _default_indicator_target(seed_event, incident_state)
    if str(indicator_target.get("indicator_type") or "").strip().upper() == "IP":
        return indicator_target

    entities = incident_state.get("entities") or {}
    scope = incident_state.get("scope") or {}
    candidates = [
        (list(scope.get("primary_external_indicators") or []) or [None])[0],
        (list(entities.get("external_ips") or []) or [None])[0],
        ((seed_event.get("dst") or {}).get("ip")) or "",
    ]
    for value in candidates:
        text = str(value or "").strip()
        if _extract_indicator_type(text) == "IP":
            return {
                "indicator_type": "IP",
                "indicator_value": text,
                "label": "primary_external_ip",
                "event_id": "",
            }
    return {}


def _tool_json(tool: Any, payload: Dict[str, Any]) -> Dict[str, Any]:
    try:
        raw = tool.invoke(payload)
        if isinstance(raw, dict):
            return raw
        if isinstance(raw, str):
            return json.loads(raw)
    except Exception as exc:
        return {"ok": False, "error": str(exc), "payload": payload}
    return {"ok": False, "error": "empty tool response", "payload": payload}


def _extract_indicator_type(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if text.startswith(("http://", "https://")):
        return "URL"
    parts = text.split(".")
    if len(parts) == 4 and all(part.isdigit() for part in parts):
        return "IP"
    if re.fullmatch(r"[a-fA-F0-9]{32}", text):
        return "MD5"
    if re.fullmatch(r"[a-fA-F0-9]{40}", text):
        return "SSL_SHA1"
    if re.fullmatch(r"[a-fA-F0-9]{64}", text):
        return "SHA256"
    if "." in text and "/" not in text and " " not in text:
        return "DOMAIN"
    return ""


def _is_internal_ip(value: str) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    try:
        ip_obj = ipaddress.ip_address(text)
        internal_networks = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("127.0.0.0/8"),
            ipaddress.ip_network("169.254.0.0/16"),
        )
        return any(ip_obj in network for network in internal_networks)
    except ValueError:
        return False


def _sanitize_external_indicators(values: List[Any]) -> List[str]:
    return unique_preserve_order(
        value
        for value in list(values or [])
        if str(value or "").strip() and not _is_internal_ip(str(value or "").strip())
    )


def _seed_asset_hint(seed_event: Dict[str, Any]) -> str:
    raw_alert = seed_event.get("raw_alert") or {}
    return str(raw_alert.get("asset_id") or raw_alert.get("hostname") or raw_alert.get("host") or "").strip()


def _normalize_decision_mode(value: Any) -> str:
    text = str(value or "").strip().lower()
    aliases = {
        "": DECISION_MODE_HEURISTIC,
        "default": DECISION_MODE_HEURISTIC,
        "heuristic_fallback": DECISION_MODE_HEURISTIC,
        "llm": DECISION_MODE_LLM_SELECTOR,
        "selector": DECISION_MODE_LLM_SELECTOR,
        "agent": DECISION_MODE_LLM_AGENT,
        "open_agent": DECISION_MODE_LLM_AGENT,
    }
    normalized = aliases.get(text, text)
    if normalized not in VALID_DECISION_MODES:
        return DECISION_MODE_HEURISTIC
    return normalized


def _resolve_selector_policy(decision_mode: Optional[str], llm: Any) -> Dict[str, Any]:
    return _resolve_selector_policy_with_runtime(decision_mode, llm, None)


def _resolve_selector_policy_with_runtime(
    decision_mode: Optional[str],
    llm: Any,
    llm_runtime: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    requested = _normalize_decision_mode(decision_mode or os.getenv("INCIDENT_AGENT_DECISION_MODE") or "")
    llm_available = llm is not None
    effective = requested
    fallback_reason = ""
    unavailable_reason = ""
    if requested in {DECISION_MODE_LLM_SELECTOR, DECISION_MODE_LLM_AGENT, DECISION_MODE_HYBRID} and not llm_available:
        effective = DECISION_MODE_HEURISTIC
        fallback_reason = "llm_unavailable"
        unavailable_reason = str((llm_runtime or {}).get("reason") or "").strip()

    if effective == DECISION_MODE_HEURISTIC and requested != DECISION_MODE_HEURISTIC:
        policy_mode = "heuristic_fallback"
    elif effective == DECISION_MODE_HEURISTIC:
        policy_mode = "heuristic_selector"
    elif effective == DECISION_MODE_LLM_AGENT:
        policy_mode = "llm_open_agent"
    elif effective == DECISION_MODE_HYBRID:
        policy_mode = "hybrid_selector"
    else:
        policy_mode = "llm_selector"

    return {
        "requested_mode": requested,
        "effective_mode": effective,
        "llm_available": llm_available,
        "fallback_reason": fallback_reason,
        "llm_unavailable_reason": unavailable_reason,
        "policy_mode": policy_mode,
        "llm_runtime": dict(llm_runtime or {}),
    }


def _initial_open_questions(seed_event: Dict[str, Any]) -> List[Dict[str, Any]]:
    seed_dst = str(((seed_event.get("dst") or {}).get("ip")) or "").strip()
    fingerprint = str((((seed_event.get("trigger_fingerprint") or {}).get("value")) or "")).strip()
    questions = [
        _gap_record(
            "build_context",
            priority="high",
            question="围绕 seed alert 建立最小事件上下文，确认它是不是孤立命中。",
            gap_type="context",
            materiality="delivery_blocking",
            tool_capability_hints=["context_building", "timeline"],
            delivery_blocking=True,
            reportable_if_unresolved=False,
            closure_criteria=["补齐最小事件窗", "确认告警不是孤立命中"],
        ),
        _gap_record(
            "expand_scope",
            priority="high",
            question="确认是否存在同资产重复通信、同基础设施复现或关联资产扩展。",
            gap_type="scope",
            materiality="delivery_blocking",
            tool_capability_hints=["cluster_expand", "scope", "asset_scope"],
            delivery_blocking=True,
            reportable_if_unresolved=False,
            closure_criteria=["确认重复通信或关联范围", "排除明显的孤立误报形态"],
        ),
        _gap_record(
            "ground_infra",
            priority="medium",
            question=f"补充 {seed_dst or fingerprint or 'seed 指示物'} 的外部基础设施或家族背景。",
            gap_type="external_context",
            materiality="confidence_supporting",
            tool_capability_hints=["infra_context", "external_intel"],
            delivery_blocking=False,
            reportable_if_unresolved=True,
            closure_criteria=["补足外部基础设施背景", "或明确该背景缺失不影响交付"],
        ),
        _gap_record(
            "check_counterevidence",
            priority="medium",
            question="确认是否存在维护窗口、补丁、备份或共享基线等反证。",
            gap_type="counterevidence",
            materiality="delivery_blocking",
            tool_capability_hints=["counterevidence", "background_validation"],
            delivery_blocking=True,
            reportable_if_unresolved=False,
            closure_criteria=["完成显式反证检查", "明确是否存在降级解释"],
        ),
    ]
    return questions


def _initial_working_hypotheses(seed_event: Dict[str, Any]) -> List[Dict[str, Any]]:
    family_hint = _meaningful_family_hint(seed_event)
    primary_title = f"疑似 {family_hint} 相关外联事件" if family_hint else "疑似恶意外联事件"
    return [
        {
            "id": "primary",
            "kind": "primary",
            "title": primary_title,
            "score": 0,
            "status": "open",
            "supporting_observation_ids": [],
            "counter_observation_ids": [],
        },
        {
            "id": "secondary",
            "kind": "secondary",
            "title": "共享基础设施上的弱关联或待复核扩展",
            "score": 0,
            "status": "open",
            "supporting_observation_ids": [],
            "counter_observation_ids": [],
        },
        {
            "id": "benign",
            "kind": "benign",
            "title": "计划内活动、正常更新或共享基线解释",
            "score": 0,
            "status": "open",
            "supporting_observation_ids": [],
            "counter_observation_ids": [],
        },
    ]


def _initial_session_state(seed_event: Dict[str, Any], budgets: Dict[str, int], selector_policy: Dict[str, Any]) -> Dict[str, Any]:
    seed_src = str(((seed_event.get("src") or {}).get("ip")) or "").strip()
    seed_dst = str(((seed_event.get("dst") or {}).get("ip")) or "").strip()
    fingerprint = str((((seed_event.get("trigger_fingerprint") or {}).get("value")) or "")).strip()
    return {
        "goal": f"围绕 seed alert {seed_src or 'unknown'} -> {seed_dst or fingerprint or 'unknown'} 收敛为事件级研判结论。",
        "budgets": {
            "max_steps": int(budgets["max_steps"]),
            "remaining_steps": int(budgets["max_steps"]),
            "max_tool_calls": int(budgets["max_tool_calls"]),
            "remaining_tool_calls": int(budgets["max_tool_calls"]),
            "max_event_queries": int(budgets["max_event_queries"]),
            "remaining_event_queries": int(budgets["max_event_queries"]),
            "max_intel_queries": int(budgets["max_intel_queries"]),
            "remaining_intel_queries": int(budgets["max_intel_queries"]),
            "max_runtime_s": int(budgets["max_runtime_s"]),
        },
        "step_index": 0,
        "tool_history": [],
        "open_questions": _initial_open_questions(seed_event),
        "working_hypotheses": _initial_working_hypotheses(seed_event),
        "stop_reason": "",
        "consecutive_low_value_steps": 0,
        "requested_decision_mode": selector_policy.get("requested_mode") or DECISION_MODE_HEURISTIC,
        "decision_mode": selector_policy.get("effective_mode") or DECISION_MODE_HEURISTIC,
        "selector_llm_available": bool(selector_policy.get("llm_available")),
        "selector_history": [],
        "agent_history": [],
        "reviewer_history": [],
        "guardrail_feedback": [],
        "blocked_finish_attempts": 0,
        "policy_mode": str(selector_policy.get("policy_mode") or "heuristic_selector"),
        "selector_state": {
            "requested_mode": selector_policy.get("requested_mode") or DECISION_MODE_HEURISTIC,
            "effective_mode": selector_policy.get("effective_mode") or DECISION_MODE_HEURISTIC,
            "llm_available": bool(selector_policy.get("llm_available")),
            "fallback_reason": str(selector_policy.get("fallback_reason") or "").strip(),
            "llm_unavailable_reason": str(selector_policy.get("llm_unavailable_reason") or "").strip(),
            "llm_runtime": dict(selector_policy.get("llm_runtime") or {}),
            "last_decision": {},
        },
        "agent_state": {
            "last_decision": {},
        },
        "reviewer_state": {
            "last_decision": {},
            "tool_cooldowns": [],
            "active_tool_cooldowns": [],
            "state_signature": "",
        },
    }


def _initial_incident_state(seed_event: Dict[str, Any]) -> Dict[str, Any]:
    src_ip = str(((seed_event.get("src") or {}).get("ip")) or "").strip()
    dst_ip = str(((seed_event.get("dst") or {}).get("ip")) or "").strip()
    fingerprint = str((((seed_event.get("trigger_fingerprint") or {}).get("value")) or "")).strip()
    seed_asset = _seed_asset_hint(seed_event)
    state = {
        "seed": seed_event,
        "pivots": {
            "seed_ts": str(seed_event.get("event_time") or ""),
            "asset_ids": unique_preserve_order([seed_asset]),
            "src_ips": unique_preserve_order([src_ip]),
            "dst_ips": unique_preserve_order([dst_ip]),
            "domains": [],
            "fingerprints": unique_preserve_order([fingerprint]),
        },
        "observations": [],
        "known_events": {},
        "page_candidates": [],
        "page_documents": [],
        "claim_signatures": [],
        "entities": {
            "seed_asset": seed_asset or None,
            "assets": unique_preserve_order([seed_asset]),
            "domains": [],
            "external_ips": unique_preserve_order([dst_ip]),
            "internal_ips": unique_preserve_order([src_ip]),
            "families": unique_preserve_order([_meaningful_family_hint(seed_event)]),
        },
        "timeline": [],
        "scope": {},
        "evidence_ledger": [],
        "gap_ledger": [],
        "counterevidence": [],
        "provisional_verdict": {"status": "needs_review", "status_label": STATUS_LABELS["needs_review"]},
        "delivery_verdict": {"status": "needs_review", "status_label": STATUS_LABELS["needs_review"]},
        "verdict": {"status": "needs_review", "status_label": STATUS_LABELS["needs_review"]},
        "confidence": 45,
        "report_ready": False,
        "readiness": {
            "ready_for_delivery": False,
            "summary": "尚未完成交付级检查。",
            "checks": [],
            "blocking_checks": [],
        },
        "context_bundle": {"minimal_event_ids": [], "minimal_event_count": 0},
        "evidence_store": {},
        "reviewer_input": {},
        "delivery_decision": {},
    }
    state["evidence_store"] = build_runtime_evidence_store(seed_event, state)
    return state


def _compose_digest(seed_event: Dict[str, Any], incident_state: Dict[str, Any], session_state: Dict[str, Any]) -> str:
    lines: List[str] = []
    lines.append("Seed alert summary:")
    lines.append(
        f"- src={((seed_event.get('src') or {}).get('ip')) or 'unknown'} "
        f"dst={((seed_event.get('dst') or {}).get('ip')) or 'unknown'} "
        f"fp={(((seed_event.get('trigger_fingerprint') or {}).get('value')) or 'unknown')}"
    )
    family_hint = _meaningful_family_hint(seed_event)
    if family_hint:
        lines.append(f"- family_hint={family_hint}")
    hypotheses = list(session_state.get("working_hypotheses") or [])
    if hypotheses:
        lines.append("Current working hypotheses:")
        for item in hypotheses[:3]:
            lines.append(f"- {item.get('id')}: {item.get('title')} (score={item.get('score')})")
    events = list((incident_state.get("known_events") or {}).values())
    events.sort(key=lambda item: str(item.get("ts") or ""))
    if events:
        lines.append("Event summaries:")
        for item in events[:10]:
            lines.append(f"- {item.get('summary')}")
    ledger = list(incident_state.get("evidence_ledger") or [])
    if ledger:
        lines.append("Evidence ledger:")
        for item in ledger[:8]:
            refs = ",".join(item.get("event_ids") or [])
            lines.append(f"- {item.get('relation')}: {item.get('summary')} [{refs}]")
    return "\n".join(lines)


def _tool_called(session_state: Dict[str, Any], tool_name: str) -> bool:
    return any(str(item.get("tool_name") or "") == tool_name for item in list(session_state.get("tool_history") or []))


def _fingerprintable_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _fingerprintable_value(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, list):
        return [_fingerprintable_value(item) for item in value]
    if isinstance(value, str):
        if len(value) > 160:
            return {
                "sha1": hashlib.sha1(value.encode("utf-8")).hexdigest()[:12],
                "len": len(value),
            }
        return value
    return value


def _stable_hash(value: Any) -> str:
    payload = json.dumps(_fingerprintable_value(value), ensure_ascii=False, sort_keys=True)
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()[:12]


def _action_input_fingerprint(tool_name: str, payload: Dict[str, Any], meta: Optional[Dict[str, Any]] = None) -> str:
    relevant_meta = {
        str(key): value
        for key, value in dict(meta or {}).items()
        if str(key) in {"content_origin", "source_url"}
    }
    return _stable_hash(
        {
            "tool_name": str(tool_name or "").strip(),
            "payload": dict(payload or {}),
            "meta": relevant_meta,
        }
    )


def _claim_signature(claim: Dict[str, Any]) -> str:
    return _stable_hash(
        {
            "text": str(claim.get("text") or "").strip(),
            "kind": str(claim.get("kind") or "").strip(),
            "score": claim.get("score"),
        }
    )


def _incident_snapshot(incident_state: Dict[str, Any]) -> Dict[str, Any]:
    entities = incident_state.get("entities") or {}
    return {
        "event_ids": set(str(key) for key in list((incident_state.get("known_events") or {}).keys()) if str(key).strip()),
        "assets": set(str(item) for item in list(entities.get("assets") or []) if str(item).strip()),
        "domains": set(str(item) for item in list(entities.get("domains") or []) if str(item).strip()),
        "external_ips": set(str(item) for item in list(entities.get("external_ips") or []) if str(item).strip()),
        "internal_ips": set(str(item) for item in list(entities.get("internal_ips") or []) if str(item).strip()),
        "families": set(str(item) for item in list(entities.get("families") or []) if str(item).strip()),
        "claim_signatures": set(str(item) for item in list(incident_state.get("claim_signatures") or []) if str(item).strip()),
        "page_document_count": len(list(incident_state.get("page_documents") or [])),
    }


def _runtime_incident_view(
    seed_event: Dict[str, Any],
    session_state: Dict[str, Any],
    incident_state: Dict[str, Any],
    evidence_store: Dict[str, Any],
    finalized: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    finalized = dict(finalized or {})
    analysis_verdict = dict(
        finalized.get("analysis_verdict")
        or incident_state.get("analysis_verdict")
        or incident_state.get("provisional_verdict")
        or {}
    )
    provisional_verdict = dict(
        finalized.get("provisional_verdict")
        or incident_state.get("provisional_verdict")
        or analysis_verdict
    )
    delivery_verdict = dict(
        finalized.get("delivery_verdict")
        or incident_state.get("delivery_verdict")
        or incident_state.get("verdict")
        or {}
    )
    return {
        "seed": seed_event,
        "session_state": session_state,
        "context_bundle": dict(incident_state.get("context_bundle") or {}),
        "incident_state": {
            "analysis_verdict": analysis_verdict,
            "provisional_verdict": provisional_verdict,
            "delivery_verdict": delivery_verdict,
            "verdict": delivery_verdict,
        },
        "analysis_verdict": analysis_verdict,
        "provisional_verdict": provisional_verdict,
        "delivery_verdict": delivery_verdict,
        "verdict": delivery_verdict,
        "evidence_store": evidence_store,
    }


def _refresh_runtime_evidence_store(
    seed_event: Dict[str, Any],
    incident_state: Dict[str, Any],
    finalized: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    evidence_store = build_runtime_evidence_store(seed_event, incident_state, finalized)
    incident_state["evidence_store"] = evidence_store
    return evidence_store


def _runtime_reviewer_state(
    seed_event: Dict[str, Any],
    session_state: Dict[str, Any],
    incident_state: Dict[str, Any],
    finalized: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    evidence_store = dict(incident_state.get("evidence_store") or {})
    if not evidence_store:
        evidence_store = _refresh_runtime_evidence_store(seed_event, incident_state, finalized)
    reviewer_incident = _runtime_incident_view(
        seed_event,
        session_state,
        incident_state,
        evidence_store,
        finalized,
    )
    reviewer_input = build_reviewer_input(reviewer_incident, evidence_store)
    delivery_decision = build_delivery_decision(evidence_store, reviewer_input)
    incident_state["reviewer_input"] = reviewer_input
    incident_state["delivery_decision"] = delivery_decision
    return {
        "evidence_store": evidence_store,
        "reviewer_input": reviewer_input,
        "delivery_decision": delivery_decision,
    }


def _matching_tool_run(session_state: Dict[str, Any], tool_name: str, input_fingerprint: str) -> Dict[str, Any]:
    for item in reversed(list(session_state.get("tool_history") or [])):
        if (
            str(item.get("tool_name") or "").strip() == str(tool_name or "").strip()
            and str(item.get("input_fingerprint") or "").strip() == str(input_fingerprint or "").strip()
        ):
            return dict(item)
    return {}


def _tool_reuse_advisory(session_state: Dict[str, Any], tool_name: str, input_fingerprint: str) -> Dict[str, Any]:
    last_run = _matching_tool_run(session_state, tool_name, input_fingerprint)
    status = str(last_run.get("status") or "").strip().lower()
    repeat_suppressed = bool(last_run) and status in {"ok", "empty"}
    repeat_risk = "high" if repeat_suppressed else ("medium" if last_run else "low")
    delta = dict(last_run.get("output_delta") or {})
    return {
        "repeat_risk": repeat_risk,
        "repeat_suppressed": repeat_suppressed,
        "last_step_index": int(last_run.get("step_index") or 0) if last_run else None,
        "last_status": status if last_run else "",
        "last_delta_summary": str(delta.get("summary") or "").strip(),
        "last_novelty_score": int(delta.get("novelty_score") or 0) if last_run else 0,
    }


def _tool_capability_profile(tool_name: str) -> Dict[str, Any]:
    profile = dict(TOOL_CAPABILITY_PROFILES.get(str(tool_name or "").strip(), {}))
    return {
        "tool_mode": str(profile.get("tool_mode") or "unknown"),
        "capability_tags": unique_preserve_order(list(profile.get("capability_tags") or [])),
        "evidence_types": unique_preserve_order(list(profile.get("evidence_types") or [])),
    }


def _material_delta_score(delta: Dict[str, Any]) -> int:
    return (
        int(delta.get("new_event_count") or 0)
        + int(delta.get("new_asset_count") or 0)
        + int(delta.get("new_domain_count") or 0)
        + int(delta.get("new_external_ip_count") or 0)
        + int(delta.get("new_family_count") or 0)
        + (2 if bool(delta.get("became_ready")) else 0)
        + (2 if bool(delta.get("verdict_changed")) else 0)
    )


def _editorial_delta_score(delta: Dict[str, Any]) -> int:
    return int(delta.get("new_claim_count") or 0) + int(delta.get("new_page_document_count") or 0)


def _tool_recent_stats(session_state: Dict[str, Any], tool_name: str) -> Dict[str, Any]:
    runs = [
        dict(item)
        for item in list(session_state.get("tool_history") or [])
        if str(item.get("tool_name") or "").strip() == str(tool_name or "").strip()
    ][-3:]
    shaped_runs: List[Dict[str, Any]] = []
    material_scores: List[int] = []
    editorial_scores: List[int] = []
    for item in runs:
        delta = dict(item.get("output_delta") or {})
        material_score = _material_delta_score(delta)
        editorial_score = _editorial_delta_score(delta)
        material_scores.append(material_score)
        editorial_scores.append(editorial_score)
        shaped_runs.append(
            {
                "step_index": int(item.get("step_index") or 0),
                "status": str(item.get("status") or "").strip(),
                "material_score": material_score,
                "editorial_score": editorial_score,
                "delta_summary": str(delta.get("summary") or "").strip(),
            }
        )
    recent_material = sum(material_scores)
    recent_editorial = sum(editorial_scores)
    depleted = len(material_scores) >= 2 and all(score <= 0 for score in material_scores[-2:])
    return {
        "run_count": len(runs),
        "recent_material_score": recent_material,
        "recent_editorial_score": recent_editorial,
        "last_material_score": material_scores[-1] if material_scores else 0,
        "last_editorial_score": editorial_scores[-1] if editorial_scores else 0,
        "materially_depleted": depleted,
        "recent_runs": shaped_runs,
    }


def _gap_attempt_stats(session_state: Dict[str, Any], gap: Dict[str, Any], *, after_step: int = 0) -> Dict[str, Any]:
    runs: List[Dict[str, Any]] = []
    for item in list(session_state.get("tool_history") or []):
        tool_name = str(item.get("tool_name") or "").strip()
        if not tool_name or not _tool_matches_gap(tool_name, gap):
            continue
        if int(item.get("step_index") or 0) <= int(after_step or 0):
            continue
        delta = dict(item.get("output_delta") or {})
        material_score = _material_delta_score(delta)
        editorial_score = _editorial_delta_score(delta)
        runs.append(
            {
                "step_index": int(item.get("step_index") or 0),
                "tool_name": tool_name,
                "material_score": material_score,
                "editorial_score": editorial_score,
                "summary": str(delta.get("summary") or "").strip(),
            }
        )
    recent_runs = runs[-3:]
    material_attempts = [item for item in runs if int(item.get("material_score") or 0) > 0]
    editorial_only_attempts = [
        item
        for item in runs
        if int(item.get("material_score") or 0) <= 0 and int(item.get("editorial_score") or 0) > 0
    ]
    zero_delta_attempts = [
        item
        for item in runs
        if int(item.get("material_score") or 0) <= 0 and int(item.get("editorial_score") or 0) <= 0
    ]
    recent_materially_stalled = len(recent_runs) >= 2 and all(int(item.get("material_score") or 0) <= 0 for item in recent_runs[-2:])
    return {
        "attempt_count": len(runs),
        "material_attempt_count": len(material_attempts),
        "editorial_only_attempt_count": len(editorial_only_attempts),
        "zero_delta_attempt_count": len(zero_delta_attempts),
        "last_attempt_step": int(runs[-1].get("step_index") or 0) if runs else 0,
        "last_attempt_tool": str(runs[-1].get("tool_name") or "").strip() if runs else "",
        "recent_materially_stalled": recent_materially_stalled,
        "recent_runs": recent_runs,
    }


def _matching_gap_ids_for_tool(tool_name: str, gaps: List[Dict[str, Any]]) -> List[str]:
    return [
        str(item.get("id") or "").strip()
        for item in gaps
        if str(item.get("id") or "").strip() and _tool_matches_gap(tool_name, item)
    ]


def _tool_precondition_view(
    seed_event: Dict[str, Any],
    session_state: Dict[str, Any],
    incident_state: Dict[str, Any],
    tool_name: str,
) -> Dict[str, Any]:
    gap_source = []
    if not bool(incident_state.get("_syncing_gap_ledger")):
        gap_source = [
            dict(item)
            for item in list(incident_state.get("gap_ledger") or [])
            if str(item.get("status") or "").strip() != "closed"
        ]
    if not gap_source:
        gap_source = list(_canonical_gap_candidates(seed_event, session_state, incident_state))
    actionable_gaps = [
        item
        for item in gap_source
        if bool(item.get("actionable_now")) or "actionable_now" not in item
    ]
    relevant_gap_ids = _matching_gap_ids_for_tool(tool_name, actionable_gaps)
    page_urls = _page_candidate_urls(incident_state)
    page_document = _latest_page_document(incident_state)
    pivots = incident_state.get("pivots") or {}
    entities = incident_state.get("entities") or {}
    seed_assets = _seed_assets_from_state(incident_state)
    related_assets = [asset for asset in list(entities.get("related_assets") or []) if asset]
    candidate_events = _candidate_events(seed_event, incident_state)
    indicator_target = _default_indicator_target(seed_event, incident_state)
    allow_live_intel = str(os.getenv("INCIDENT_AGENT_LIVE_INTEL") or "").strip().lower() in {"1", "true", "yes"}
    context_built = bool(incident_state.get("context_bundle", {}).get("minimal_event_count"))

    available = True
    reason = ""

    if tool_name == "search_seed_context":
        available = True
        reason = "seed alert 可直接建立最小上下文。"
    elif tool_name == "search_related_events":
        available = context_built and any(list(values or []) for values in pivots.values()) and bool(relevant_gap_ids)
        reason = "需要先建立最小上下文，再基于可用 pivot 扩大事件簇。"
    elif tool_name == GROUND_CANDIDATE_TOOL_NAME:
        available = bool(candidate_events) and bool(relevant_gap_ids)
        reason = "需要存在尚未独立验证的候选事件，且当前还有候选验证类 gap。"
    elif tool_name == COUNTEREVIDENCE_TOOL_NAME:
        available = context_built and bool(seed_assets) and bool(relevant_gap_ids)
        reason = "需要先确认涉及资产，再做显式反证检查。"
    elif tool_name == "expand_asset_scope":
        available = bool(related_assets or seed_assets) and bool(relevant_gap_ids)
        reason = "需要存在关联资产或种子资产，且当前还有范围确认类 gap。"
    elif tool_name == "local_intel_lookup":
        available = bool(indicator_target) and bool(relevant_gap_ids)
        reason = "需要存在待验证的关键指示物，且当前还有本地情报/指纹验证类 gap。"
    elif tool_name == "vt_enrich_ioc":
        available = allow_live_intel and bool(_virustotal_indicator_target(seed_event, incident_state)) and bool(relevant_gap_ids)
        reason = "需要开启 live intel，且当前存在可送入 VirusTotal 的外部 IP 指示物。"
    elif tool_name in {"technical_source_search", "threatfox_ioc_lookup", "urlhaus_ioc_lookup", "malware_profile_lookup", "pivot_related_indicators", "abuse_ch_lookup"}:
        available = allow_live_intel and bool(relevant_gap_ids)
        reason = "需要开启 live intel，且当前仍有外部情报/家族验证类 gap。"
    elif tool_name == "fetch_page_content":
        available = bool(page_urls) and bool(relevant_gap_ids)
        reason = "需要存在待读取页面，且当前仍有依赖外部正文的 gap。"
    elif tool_name == "extract_claim_candidates_from_page":
        available = bool(relevant_gap_ids) and bool(str(page_document.get("content") or "").strip() or _compose_digest(seed_event, incident_state, session_state))
        reason = "需要当前仍有结构化证据类 gap，且已有正文或调查摘要可供整理。"
    elif tool_name == "extract_entities_from_page":
        available = bool(relevant_gap_ids) and bool(str(page_document.get("content") or "").strip() or _compose_digest(seed_event, incident_state, session_state))
        reason = "需要当前仍有实体抽取类 gap，且已有正文或调查摘要可供整理。"

    return {
        "available": available,
        "reason": reason,
        "relevant_gap_ids": relevant_gap_ids,
        "page_url_count": len(page_urls),
        "has_page_document": bool(str(page_document.get("content") or "").strip()),
    }


def _addressable_tool_names(seed_event: Dict[str, Any], session_state: Dict[str, Any], incident_state: Dict[str, Any]) -> List[str]:
    names: List[str] = []
    for tool_name in ORDERED_TOOL_NAMES:
        precondition = _tool_precondition_view(seed_event, session_state, incident_state, tool_name)
        if not bool(precondition.get("available")):
            continue
        request = _default_tool_request(seed_event, session_state, incident_state, tool_name)
        if not request:
            continue
        input_fingerprint = _action_input_fingerprint(
            tool_name,
            dict(request.get("params") or {}),
            dict(request.get("meta") or {}),
        )
        reuse = _tool_reuse_advisory(session_state, tool_name, input_fingerprint)
        if reuse.get("repeat_suppressed"):
            continue
        names.append(tool_name)
    return names


def _tool_matches_gap(tool_name: str, gap: Dict[str, Any]) -> bool:
    return _tool_gap_match_score(tool_name, gap) > 0


def _tool_gap_match_score(tool_name: str, gap: Dict[str, Any]) -> int:
    hints = {
        str(item).strip()
        for item in list(gap.get("tool_capability_hints") or [])
        if str(item).strip()
    }
    if not hints:
        return 0
    capabilities = {
        str(item).strip()
        for item in list((_tool_capability_profile(tool_name).get("capability_tags") or []))
        if str(item).strip()
    }
    return len(hints & capabilities)


def _material_gap_view(seed_event: Dict[str, Any], session_state: Dict[str, Any], incident_state: Dict[str, Any]) -> List[Dict[str, Any]]:
    available_tools = _addressable_tool_names(seed_event, session_state, incident_state)
    prior_gap_map = {
        str(item.get("id") or "").strip(): dict(item)
        for item in list(incident_state.get("gap_ledger") or [])
        if str(item.get("id") or "").strip()
    }
    gaps: List[Dict[str, Any]] = []
    for item in list(_canonical_gap_candidates(seed_event, session_state, incident_state)):
        gap = dict(item)
        prior_gap = prior_gap_map.get(str(gap.get("id") or "").strip()) or {}
        addressable_tools = [tool_name for tool_name in available_tools if _tool_matches_gap(tool_name, gap)]
        actionable_tools = [
            tool_name
            for tool_name in addressable_tools
            if not bool(_tool_recent_stats(session_state, tool_name).get("materially_depleted"))
        ]
        attempt_stats = _gap_attempt_stats(session_state, gap, after_step=int(prior_gap.get("first_seen_step") or 0))
        status = "open"
        status_reason = ""
        if (
            bool(gap.get("reportable_if_unresolved"))
            and int(attempt_stats.get("attempt_count") or 0) >= 2
            and int(attempt_stats.get("material_attempt_count") or 0) <= 0
        ):
            actionable_tools = []
            status = "reportable_unresolved"
            status_reason = "该 gap 已经过多轮相关尝试但没有 material delta，更适合作为报告未决事项。"
        elif not actionable_tools and addressable_tools:
            status = "stalled"
            status_reason = "存在理论上相关的工具，但它们近期已经进入低收益状态。"
        elif not addressable_tools and bool(gap.get("reportable_if_unresolved")):
            status = "reportable_unresolved"
            status_reason = "当前没有仍然适合继续缩小该 gap 的工具，更适合作为报告边界说明。"
        elif not addressable_tools:
            status = "open_unaddressable"
            status_reason = "当前工具面还不足以继续缩小该 gap。"
        gap["attempt_count"] = int(attempt_stats.get("attempt_count") or 0)
        gap["material_attempt_count"] = int(attempt_stats.get("material_attempt_count") or 0)
        gap["editorial_only_attempt_count"] = int(attempt_stats.get("editorial_only_attempt_count") or 0)
        gap["zero_delta_attempt_count"] = int(attempt_stats.get("zero_delta_attempt_count") or 0)
        gap["last_attempt_step"] = int(attempt_stats.get("last_attempt_step") or 0)
        gap["last_attempt_tool"] = str(attempt_stats.get("last_attempt_tool") or "").strip()
        gap["recent_attempts"] = list(attempt_stats.get("recent_runs") or [])
        gap["addressable_tools"] = addressable_tools
        gap["actionable_tools"] = actionable_tools
        gap["status"] = status
        gap["status_reason"] = status_reason
        gap["actionable_now"] = bool(actionable_tools) and status == "open"
        gaps.append(gap)
    return gaps


def _sync_gap_ledger(
    seed_event: Dict[str, Any],
    session_state: Dict[str, Any],
    incident_state: Dict[str, Any],
) -> List[Dict[str, Any]]:
    previous = {
        str(item.get("id") or "").strip(): dict(item)
        for item in list(incident_state.get("gap_ledger") or [])
        if str(item.get("id") or "").strip()
    }
    incident_state["_syncing_gap_ledger"] = True
    try:
        current = _material_gap_view(seed_event, session_state, incident_state)
    finally:
        incident_state.pop("_syncing_gap_ledger", None)
    current_ids = {str(item.get("id") or "").strip() for item in current if str(item.get("id") or "").strip()}
    step_index = int(session_state.get("step_index") or 0)
    ledger: List[Dict[str, Any]] = []

    for gap in current:
        gap_id = str(gap.get("id") or "").strip()
        prior = dict(previous.get(gap_id) or {})
        merged = dict(prior)
        merged.update(gap)
        merged["first_seen_step"] = int(prior.get("first_seen_step") or step_index or 1)
        merged["last_seen_step"] = step_index
        merged["closed_step"] = None
        ledger.append(merged)

    for gap_id, prior in previous.items():
        if gap_id in current_ids:
            continue
        closed = dict(prior)
        closed["status"] = "closed"
        closed["actionable_now"] = False
        closed["actionable_tools"] = []
        closed["addressable_tools"] = []
        closed["status_reason"] = "该 gap 已不再出现在当前 canonical gap 集合中。"
        closed["last_seen_step"] = step_index
        closed["closed_step"] = int(prior.get("closed_step") or step_index)
        ledger.append(closed)

    incident_state["gap_ledger"] = ledger
    return ledger


def _completion_advice(
    seed_event: Dict[str, Any],
    session_state: Dict[str, Any],
    incident_state: Dict[str, Any],
    finalized: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    acceptance = _acceptance_state(seed_event, session_state, incident_state, finalized)
    return {
        "should_finish": bool(acceptance.get("preferred_stop")),
        "reason": str(acceptance.get("preferred_stop_reason") or "").strip(),
        "ready_for_delivery": bool(acceptance.get("ready_for_delivery")),
        "open_question_count": int(acceptance.get("open_question_count") or 0),
        "blocking_material_gap_count": int(acceptance.get("blocking_material_gap_count") or 0),
        "material_gaps": list(acceptance.get("material_gaps") or []),
        "blocking_check_count": int(acceptance.get("blocking_check_count") or 0),
    }


def _delivery_gap_rows(
    incident_state: Dict[str, Any],
    finalized: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    finalized = dict(finalized or {})
    delivery_decision = dict(finalized.get("delivery_decision") or incident_state.get("delivery_decision") or {})
    evidence_store = dict(finalized.get("evidence_store") or incident_state.get("evidence_store") or {})
    canonical_gap_map = {
        str(item.get("gap_id") or item.get("id") or "").strip(): dict(item)
        for item in list(evidence_store.get("gaps") or [])
        if str(item.get("gap_id") or item.get("id") or "").strip()
    }
    rows: List[Dict[str, Any]] = []
    for bucket in ("blocking_gaps", "non_blocking_gaps"):
        for item in list(delivery_decision.get(bucket) or []):
            gap_id = str(item.get("gap_id") or item.get("id") or "").strip()
            merged = dict(canonical_gap_map.get(gap_id) or {})
            if gap_id and "id" not in merged:
                merged["id"] = gap_id
            if gap_id and "gap_id" not in merged:
                merged["gap_id"] = gap_id
            merged.update(item)
            if gap_id:
                rows.append(merged)
    if rows:
        return rows
    return [
        dict(item)
        for item in list(evidence_store.get("gaps") or incident_state.get("gap_ledger") or [])
        if isinstance(item, dict)
    ]


def _acceptance_state(
    seed_event: Dict[str, Any],
    session_state: Dict[str, Any],
    incident_state: Dict[str, Any],
    finalized: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    finalized = dict(finalized or {})
    delivery_decision = dict(finalized.get("delivery_decision") or incident_state.get("delivery_decision") or {})
    readiness = dict(delivery_decision.get("readiness") or finalized.get("readiness") or incident_state.get("readiness") or {})
    material_gaps = [
        dict(item)
        for item in _delivery_gap_rows(incident_state, finalized)
        if str(item.get("status") or "open").strip() != "closed"
    ]
    blocking_checks = list(readiness.get("blocking_checks") or [])
    ready_for_delivery = bool(readiness.get("ready_for_delivery"))
    approved = bool(delivery_decision.get("approved")) and ready_for_delivery
    actionable_gaps = [gap for gap in material_gaps if bool(gap.get("actionable_now"))]
    blocking_material_gaps = [
        gap
        for gap in actionable_gaps
        if bool(gap.get("delivery_blocking")) and bool(gap.get("blocks_delivery_now", gap.get("delivery_blocking")))
    ]
    reportable_gaps = [
        gap
        for gap in material_gaps
        if str(gap.get("status") or "").strip() in {"reportable_unresolved", "unresolved_but_deliverable"}
        or (bool(gap.get("delivery_blocking")) and not bool(gap.get("blocks_delivery_now", True)))
    ]
    preferred_stop = approved and not blocking_checks and not blocking_material_gaps
    if preferred_stop:
        if material_gaps:
            reason = "当前已满足可交付条件；剩余问题要么不可由现有工具继续缩小，要么更适合作为报告未决事项。"
        else:
            reason = "当前已满足可交付条件，且没有未闭合问题；默认应 finish，而不是继续补充低增量证据。"
    elif ready_for_delivery and blocking_material_gaps:
        gap_titles = "；".join(str(item.get("question") or "").strip() for item in blocking_material_gaps[:2])
        reason = f"虽然已接近交付，但仍存在可由当前工具继续缩小的关键问题：{gap_titles}"
    elif ready_for_delivery and material_gaps:
        reason = "虽然仍有未决问题，但它们当前更适合作为报告未决事项记录，而不是继续补充低增量证据。"
    else:
        reason = (
            str(delivery_decision.get("reviewer_rationale") or "").strip()
            or str(readiness.get("summary") or "尚未达到交付条件。").strip()
            or "尚未达到交付条件。"
        )
    insufficient_progress_signals = unique_preserve_order(
        list(delivery_decision.get("insufficient_progress_signals") or [])
        + (
            ["已有工具进入冷却阶段，继续重复调用需要新的状态变化支撑。"]
            if _active_tool_cooldowns(session_state, incident_state, finalized)
            else []
        )
    )
    return {
        "preferred_stop": preferred_stop,
        "deliverable_now": preferred_stop,
        "preferred_stop_reason": reason,
        "ready_for_delivery": ready_for_delivery,
        "open_question_count": len(material_gaps),
        "blocking_material_gap_count": len(blocking_material_gaps),
        "actionable_gap_count": len(actionable_gaps),
        "material_gaps": material_gaps,
        "blocking_check_count": len(blocking_checks),
        "blocking_checks": blocking_checks,
        "actionable_gaps": actionable_gaps,
        "blocking_actionable_gaps": blocking_material_gaps,
        "reportable_gaps": reportable_gaps,
        "insufficient_progress_signals": unique_preserve_order(insufficient_progress_signals),
    }


def _control_phase(
    seed_event: Dict[str, Any],
    session_state: Dict[str, Any],
    incident_state: Dict[str, Any],
    finalized: Optional[Dict[str, Any]] = None,
) -> str:
    return str(_control_summary(seed_event, session_state, incident_state, finalized).get("compat_phase") or "stabilize_evidence")


def _control_summary(
    seed_event: Dict[str, Any],
    session_state: Dict[str, Any],
    incident_state: Dict[str, Any],
    finalized: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    finalized = dict(finalized or {})
    delivery_decision = dict(finalized.get("delivery_decision") or incident_state.get("delivery_decision") or {})
    evidence_store = dict(finalized.get("evidence_store") or incident_state.get("evidence_store") or {})
    readiness = dict(delivery_decision.get("readiness") or finalized.get("readiness") or incident_state.get("readiness") or {})
    acceptance_state = _acceptance_state(seed_event, session_state, incident_state, finalized)
    gap_rows = list(acceptance_state.get("material_gaps") or (finalized or {}).get("gap_ledger") or incident_state.get("gap_ledger") or [])
    candidate_events = list(evidence_store.get("candidate_events") or [])
    if not candidate_events:
        if finalized and isinstance(finalized.get("annotated_events"), list):
            candidate_events = [
                item
                for item in list(finalized.get("annotated_events") or [])
                if str(item.get("role") or "").strip() == "candidate"
            ]
        else:
            candidate_events = _candidate_events(seed_event, incident_state)
    context_built = bool((incident_state.get("context_bundle") or {}).get("minimal_event_count"))
    actionable_blocking_gaps = [dict(item) for item in list(acceptance_state.get("blocking_actionable_gaps") or [])]
    actionable_gaps = [dict(item) for item in list(acceptance_state.get("actionable_gaps") or [])]
    reportable_gaps = [dict(item) for item in list(acceptance_state.get("reportable_gaps") or [])]
    blocking_checks = [
        {
            "id": str(item.get("id") or "").strip(),
            "reason": str(item.get("reason") or "").strip(),
        }
        for item in list(acceptance_state.get("blocking_checks") or [])
        if str(item.get("id") or "").strip()
    ]
    preferred_stop = bool(acceptance_state.get("preferred_stop"))
    recent_tool_effects = _recent_tool_effects(session_state)
    recent_low_value_steps = len(
        [
            item
            for item in recent_tool_effects[-3:]
            if int(item.get("material_score") or 0) <= 0 and int(item.get("editorial_score") or 0) <= 0
        ]
    )
    scope_followup_actions = _novel_scope_followup_actions(seed_event, session_state, incident_state)
    scope_followup_pending = bool(scope_followup_actions) and any(
        str(item.get("id") or item.get("gap_id") or "").strip() == "expand_cluster_scope"
        and bool(item.get("actionable_now"))
        for item in list(actionable_blocking_gaps or actionable_gaps)
    )

    primary_gap = (
        dict(actionable_blocking_gaps[0])
        if actionable_blocking_gaps
        else (
            dict(actionable_gaps[0])
            if actionable_gaps
            else (dict(reportable_gaps[0]) if reportable_gaps else {})
        )
    )

    if not context_built:
        focus_mode = "context_bootstrap"
        primary_goal = "围绕 seed alert 建立最小上下文"
        primary_reason = "当前还没有足够的事件窗与上下文，不能可靠判断告警是否孤立。"
        compat_phase = "build_context"
    elif scope_followup_pending:
        focus_mode = "blocking_gap_reduction"
        primary_goal = "仍需围绕当前 pivot 做一次显式扩线，确认是否存在同指标的更大范围复现。"
        primary_reason = "上一轮扩线已经打开新的可调查范围，应该先补完新的 scope follow-up，再决定是否收束到候选验证。"
        compat_phase = "shrink_blocking_gaps"
    elif candidate_events and any(
        _tool_matches_gap(GROUND_CANDIDATE_TOOL_NAME, gap)
        for gap in list(actionable_blocking_gaps or actionable_gaps)
    ):
        focus_mode = "candidate_validation"
        primary_goal = "优先验证扩线出来的候选事件"
        primary_reason = "扩线结果默认只是 candidate，仍需独立 grounding 后才能并入主证据链。"
        compat_phase = "ground_candidates"
    elif actionable_blocking_gaps:
        focus_mode = "blocking_gap_reduction"
        primary_goal = str(primary_gap.get("question") or "").strip() or "缩小当前阻塞交付的关键缺口"
        primary_reason = (
            str(primary_gap.get("status_reason") or "").strip()
            or "当前仍存在会直接影响交付判断的关键 gap。"
        )
        compat_phase = "shrink_blocking_gaps"
    elif preferred_stop:
        focus_mode = "finish_ready"
        primary_goal = "当前默认应结束调查并进入交付"
        primary_reason = str(acceptance_state.get("preferred_stop_reason") or "").strip()
        compat_phase = "delivery_gate"
    elif actionable_gaps:
        focus_mode = "remaining_gap_reduction"
        primary_goal = str(primary_gap.get("question") or "").strip() or "继续缩小剩余未闭合问题"
        primary_reason = (
            str(primary_gap.get("status_reason") or "").strip()
            or "虽然已接近收束，但当前仍有未闭合问题可被继续缩小。"
        )
        compat_phase = "shrink_remaining_gaps"
    elif bool(readiness.get("ready_for_delivery")):
        focus_mode = "boundary_documentation"
        primary_goal = "当前重点转为保守表达边界，而不是继续扩张证据范围"
        primary_reason = str(acceptance_state.get("preferred_stop_reason") or "").strip()
        compat_phase = "delivery_gate"
    else:
        focus_mode = "stabilize"
        primary_goal = "稳定现有证据链并观察是否还有高价值动作"
        primary_reason = "当前没有更高优先级的阻塞问题，但也尚未完全进入默认 finish 状态。"
        compat_phase = "stabilize_evidence"

    next_focus = {}
    if primary_gap:
        next_focus = {
            "gap_id": str(primary_gap.get("id") or primary_gap.get("gap_id") or "").strip(),
            "question": str(primary_gap.get("question") or "").strip(),
            "priority": str(primary_gap.get("priority") or "").strip() or "medium",
            "actionable_now": bool(primary_gap.get("actionable_now")),
            "suggested_tools": unique_preserve_order(
                list(primary_gap.get("actionable_tools") or [])
                or list(primary_gap.get("addressable_tools") or [])
            )[:3],
        }

    return {
        "focus_mode": focus_mode,
        "primary_goal": primary_goal,
        "primary_reason": primary_reason,
        "next_focus": next_focus,
        "context_built": context_built,
        "candidate_event_count": len(candidate_events),
        "blocking_check_ids": [str(item.get("id") or "").strip() for item in blocking_checks if str(item.get("id") or "").strip()],
        "blocking_gap_ids": [
            str(item.get("id") or item.get("gap_id") or "").strip()
            for item in actionable_blocking_gaps
            if str(item.get("id") or item.get("gap_id") or "").strip()
        ],
        "actionable_gap_count": len(actionable_gaps),
        "reportable_gap_count": len(reportable_gaps),
        "deliverable_now": preferred_stop,
        "ready_for_delivery": bool(readiness.get("ready_for_delivery")),
        "recent_low_value_steps": recent_low_value_steps,
        "scope_followup_pending": scope_followup_pending,
        "scope_followup_tools": [
            str(item.get("tool_name") or "").strip()
            for item in scope_followup_actions
            if str(item.get("tool_name") or "").strip()
        ],
        "compat_phase": compat_phase,
    }


def _cooldown_state_signature(
    incident_state: Dict[str, Any],
    finalized: Optional[Dict[str, Any]] = None,
    *,
    related_gap_ids: Optional[List[str]] = None,
) -> str:
    gap_rows = list((finalized or {}).get("gap_ledger") or incident_state.get("gap_ledger") or [])
    readiness = (finalized or {}).get("readiness") or incident_state.get("readiness") or {}
    related_ids = {str(item or "").strip() for item in list(related_gap_ids or []) if str(item or "").strip()}
    if related_ids:
        gap_rows = [item for item in gap_rows if str(item.get("id") or "").strip() in related_ids]
    blocking_checks = [
        str(item.get("id") or "").strip()
        for item in list(readiness.get("blocking_checks") or [])
        if str(item.get("id") or "").strip()
    ]
    if related_ids:
        blocking_checks = [gap_id for gap_id in blocking_checks if gap_id in related_ids]
    shaped_rows = [
        {
            "id": str(item.get("id") or "").strip(),
            "status": str(item.get("status") or "").strip(),
            "delivery_blocking": bool(item.get("delivery_blocking")),
            "actionable_now": bool(item.get("actionable_now")),
            "attempt_count": int(item.get("attempt_count") or 0),
            "material_attempt_count": int(item.get("material_attempt_count") or 0),
            "last_attempt_step": int(item.get("last_attempt_step") or 0),
            "last_attempt_tool": str(item.get("last_attempt_tool") or "").strip(),
        }
        for item in sorted(gap_rows, key=lambda row: str(row.get("id") or ""))
    ]
    return _stable_hash(
        {
            "related_gap_ids": sorted(related_ids),
            "ready_for_delivery": bool(readiness.get("ready_for_delivery")),
            "blocking_checks": blocking_checks,
            "gap_rows": shaped_rows,
        }
    )


def _active_tool_cooldowns(
    session_state: Dict[str, Any],
    incident_state: Dict[str, Any],
    finalized: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    reviewer_state = session_state.setdefault("reviewer_state", {})
    cooldowns = list(reviewer_state.get("tool_cooldowns") or [])
    active: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for item in reversed(cooldowns):
        tool_name = str(item.get("tool_name") or "").strip()
        if not tool_name or tool_name in seen:
            continue
        current_signature = _cooldown_state_signature(
            incident_state,
            finalized,
            related_gap_ids=list(item.get("related_gap_ids") or []),
        )
        if str(item.get("state_signature") or "").strip() != current_signature:
            continue
        active.append(dict(item))
        seen.add(tool_name)
    active.reverse()
    reviewer_state["active_tool_cooldowns"] = active
    reviewer_state["state_signature"] = _cooldown_state_signature(incident_state, finalized)
    return active


def _cooldown_reason_text(reason: str) -> str:
    text = str(reason or "").strip()
    return text or "在相关 gap 状态没有变化前，继续调用该工具的收益很低。"


def _normalize_reviewer_rows(value: Any) -> List[Dict[str, str]]:
    if not isinstance(value, list):
        return []
    rows: List[Dict[str, str]] = []
    for item in value:
        if isinstance(item, dict):
            tool_name = str(item.get("tool_name") or "").strip()
            reason = str(item.get("reason") or "").strip()
        else:
            tool_name = str(item or "").strip()
            reason = ""
        if tool_name:
            rows.append({"tool_name": tool_name, "reason": reason})
    return rows


def _canonical_blocking_gaps(material_gaps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    prioritized = [
        dict(item)
        for item in material_gaps
        if bool(item.get("delivery_blocking")) and bool(item.get("actionable_now"))
    ]
    if not prioritized:
        prioritized = [dict(item) for item in material_gaps if bool(item.get("actionable_now"))]
    if not prioritized:
        prioritized = [dict(item) for item in material_gaps if str(item.get("status") or "").strip() != "reportable_unresolved"]
    rows: List[Dict[str, Any]] = []
    for item in prioritized[:3]:
        rows.append(
            {
                "gap_id": str(item.get("id") or item.get("gap_id") or "").strip(),
                "question": str(item.get("question") or "").strip(),
                "priority": str(item.get("priority") or "").strip(),
                "status": str(item.get("status") or "").strip(),
                "delivery_blocking": bool(item.get("delivery_blocking")),
                "actionable_now": bool(item.get("actionable_now")),
                "reason": str(item.get("status_reason") or "").strip() or str(item.get("question") or "").strip(),
                "actionable_tools": unique_preserve_order(list(item.get("actionable_tools") or []))[:4],
            }
        )
    return rows


def _low_value_repeat_rows(tool_catalog: List[Dict[str, Any]], blocked_tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    blocked_reason_map = {
        str(item.get("tool_name") or "").strip(): str(item.get("reason") or "").strip()
        for item in list(blocked_tools or [])
        if str(item.get("tool_name") or "").strip()
    }
    rows: List[Dict[str, Any]] = []
    for item in tool_catalog:
        tool_name = str(item.get("tool_name") or "").strip()
        if not tool_name:
            continue
        reason = blocked_reason_map.get(tool_name, "")
        repeat_risk = str(item.get("repeat_risk") or "").strip().lower()
        if not reason:
            if bool(item.get("recent_materially_depleted")):
                reason = "最近两次相关调用都没有带来 material delta。"
            elif repeat_risk == "high":
                reason = "相同输入已经成功执行过，短期内重复价值很低。"
            elif repeat_risk == "medium" and int(item.get("recent_material_score") or 0) <= 0:
                reason = "近期重复调用的信息增益有限，当前不适合继续优先尝试。"
        if not reason:
            continue
        rows.append(
            {
                "tool_name": tool_name,
                "reason": reason,
                "repeat_risk": repeat_risk,
                "recent_material_score": int(item.get("recent_material_score") or 0),
                "recent_runs": list(item.get("recent_runs") or []),
            }
        )
    return rows[:4]


def _build_reviewer_next_focus(tool_catalog: List[Dict[str, Any]], blocking_gaps: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not blocking_gaps:
        return {}
    primary_gap = dict(blocking_gaps[0])
    gap_id = str(primary_gap.get("gap_id") or "").strip()
    actionable_tool_names = {
        str(item or "").strip()
        for item in list(primary_gap.get("actionable_tools") or [])
        if str(item or "").strip()
    }
    candidate_catalog = [
        item
        for item in tool_catalog
        if not actionable_tool_names or str(item.get("tool_name") or "").strip() in actionable_tool_names
    ]
    if not candidate_catalog:
        candidate_catalog = list(tool_catalog)
    ranked = sorted(
        candidate_catalog,
        key=lambda item: _rank_reviewer_tool(
            item,
            [
                {
                    "id": gap_id,
                    "priority": primary_gap.get("priority"),
                    "delivery_blocking": primary_gap.get("delivery_blocking"),
                    "actionable_now": primary_gap.get("actionable_now"),
                }
            ],
        ),
        reverse=True,
    )
    suggested_tool = str(ranked[0].get("tool_name") or "").strip() if ranked else ""
    return {
        "gap_id": gap_id,
        "question": str(primary_gap.get("question") or "").strip(),
        "suggested_tool": suggested_tool,
        "reason": str(primary_gap.get("reason") or "").strip(),
    }


def _reviewer_allowed_tools_from_next_action(next_action: Dict[str, Any]) -> List[str]:
    if str((next_action or {}).get("action_type") or "").strip() != "tool":
        return []
    tool_name = str((next_action or {}).get("tool_name") or "").strip()
    return [tool_name] if tool_name else []


def _tool_action_contract(
    request: Dict[str, Any],
    *,
    reason: str = "",
    override_reason: str = "",
    target_gap_ids: Optional[List[str]] = None,
    question: str = "",
) -> Dict[str, Any]:
    tool_name = str(request.get("tool_name") or "").strip()
    params = dict(request.get("params") or {})
    meta = dict(request.get("meta") or {})
    resolved_reason = str(reason or request.get("reason") or request.get("llm_reason") or "").strip()
    resolved_override = str(override_reason or request.get("override_reason") or "").strip()
    return {
        **dict(request or {}),
        "action_type": "tool",
        "tool_name": tool_name,
        "category": request.get("category"),
        "question": str(question or request.get("question") or "").strip(),
        "params": params,
        "meta": meta,
        "trace_params": dict(request.get("trace_params") or params),
        "expected_gain": str(request.get("expected_gain") or "").strip(),
        "target_gap_ids": _text_list(
            target_gap_ids if target_gap_ids is not None else request.get("target_gap_ids"),
            limit=4,
        ),
        "reason": resolved_reason,
        "llm_reason": resolved_reason,
        "override_reason": resolved_override,
        "input_fingerprint": str(
            request.get("input_fingerprint")
            or _action_input_fingerprint(tool_name, params, meta)
        ),
    }


def _finish_action_contract(reason: str, *, question: str = "") -> Dict[str, Any]:
    return {
        "action_type": "finish",
        "tool_name": "",
        "category": "",
        "question": str(question or "").strip(),
        "params": {},
        "meta": {},
        "trace_params": {},
        "expected_gain": "",
        "target_gap_ids": [],
        "reason": str(reason or "").strip(),
        "llm_reason": str(reason or "").strip(),
        "override_reason": "",
        "input_fingerprint": "",
    }


def _none_action_contract(
    reason: str,
    *,
    target_gap_ids: Optional[List[str]] = None,
    question: str = "",
) -> Dict[str, Any]:
    return {
        "action_type": "none",
        "tool_name": "",
        "category": "",
        "question": str(question or "").strip(),
        "params": {},
        "meta": {},
        "trace_params": {},
        "expected_gain": "",
        "target_gap_ids": _text_list(target_gap_ids, limit=4),
        "reason": str(reason or "").strip(),
        "llm_reason": str(reason or "").strip(),
        "override_reason": "",
        "input_fingerprint": "",
    }


def _normalize_reviewer_next_action(
    value: Any,
    seed_event: Dict[str, Any],
    session_state: Dict[str, Any],
    incident_state: Dict[str, Any],
    tool_catalog: List[Dict[str, Any]],
    canonical_gap_map: Dict[str, Dict[str, Any]],
    *,
    proposal: Optional[Dict[str, Any]] = None,
    fallback_reason: str = "",
    default_action_type: str = "none",
) -> Dict[str, Any]:
    available_tools = {
        str(item.get("tool_name") or "").strip()
        for item in tool_catalog
        if str(item.get("tool_name") or "").strip()
    }
    default_type = str(default_action_type or "none").strip().lower()
    if default_type not in REVIEWER_NEXT_ACTION_TYPES:
        default_type = "none"
    row = dict(value or {})
    action_type = str(row.get("action_type") or row.get("action") or default_type).strip().lower()
    if action_type not in REVIEWER_NEXT_ACTION_TYPES:
        action_type = default_type
    target_gap_ids = _text_list(row.get("target_gap_ids"), limit=4)
    focus_gap_id = str(row.get("gap_id") or "").strip()
    if focus_gap_id:
        target_gap_ids = unique_preserve_order([focus_gap_id] + target_gap_ids)
    target_gap_ids = [
        gap_id
        for gap_id in target_gap_ids
        if gap_id in canonical_gap_map or not canonical_gap_map
    ]
    proposal_tool_name = str((proposal or {}).get("tool_name") or "").strip()
    if not target_gap_ids and proposal_tool_name and proposal_tool_name == str(row.get("tool_name") or "").strip():
        target_gap_ids = _text_list((proposal or {}).get("target_gap_ids"), limit=4)
    question = str(row.get("question") or "").strip()
    if not question:
        for gap_id in target_gap_ids:
            question = str((canonical_gap_map.get(gap_id) or {}).get("question") or "").strip()
            if question:
                break
    if not question and proposal_tool_name and proposal_tool_name == str(row.get("tool_name") or "").strip():
        question = str((proposal or {}).get("question") or "").strip()
    reason = str(row.get("reason") or fallback_reason or "").strip()
    override_reason = str(row.get("override_reason") or "").strip()
    if action_type == "finish":
        return _finish_action_contract(reason, question=question)
    tool_name = str(row.get("tool_name") or "").strip()
    if action_type == "tool" and tool_name in available_tools:
        proposal_tool_name = str((proposal or {}).get("tool_name") or "").strip()
        base_params = dict(row.get("params") or {})
        if not base_params and tool_name == proposal_tool_name:
            base_params = dict((proposal or {}).get("params") or {})
        try:
            action = _normalize_open_agent_action(
                seed_event,
                session_state,
                incident_state,
                tool_name,
                base_params,
                reason=reason,
                override_reason=override_reason,
            )
        except Exception:
            return _none_action_contract(
                reason,
                target_gap_ids=target_gap_ids,
                question=question,
            )
        return _tool_action_contract(
            action,
            reason=reason,
            override_reason=override_reason,
            target_gap_ids=target_gap_ids,
            question=question,
        )
    return _none_action_contract(
        reason,
        target_gap_ids=target_gap_ids,
        question=question,
    )


def _fallback_reviewer_next_action(
    *,
    seed_event: Dict[str, Any],
    session_state: Dict[str, Any],
    incident_state: Dict[str, Any],
    decision: str,
    tool_catalog: List[Dict[str, Any]],
    proposal: Dict[str, Any],
    blocking_gaps: List[Dict[str, Any]],
    next_focus: Dict[str, Any],
    fallback_reason: str = "",
    preferred_tool_name: str = "",
    preferred_gap_ids: Optional[List[str]] = None,
    excluded_tools: Optional[set[str]] = None,
) -> Dict[str, Any]:
    excluded = {
        str(item or "").strip()
        for item in list(excluded_tools or set())
        if str(item or "").strip()
    }
    available_tools = {
        str(item.get("tool_name") or "").strip()
        for item in tool_catalog
        if str(item.get("tool_name") or "").strip()
    }
    reason = str(fallback_reason or "").strip()
    if decision == "deliverable":
        return _finish_action_contract(reason)

    proposed_tool = str(proposal.get("tool_name") or "").strip()
    proposed_gap_ids = _text_list(proposal.get("target_gap_ids"), limit=4)
    if decision == "allow" and proposed_tool and proposed_tool in available_tools and proposed_tool not in excluded:
        return _tool_action_contract(
            proposal,
            reason=reason,
            override_reason=str(proposal.get("override_reason") or "").strip(),
            target_gap_ids=proposed_gap_ids,
            question=str((proposal.get("alignment") or {}).get("focus_question") or "").strip(),
        )

    focus = dict(next_focus or {})
    if not focus:
        focus = _build_reviewer_next_focus(tool_catalog, blocking_gaps)
    focus_gap_id = str(focus.get("gap_id") or "").strip()
    focus_question = str(focus.get("question") or "").strip()
    candidate_tool_names = unique_preserve_order([preferred_tool_name, str(focus.get("suggested_tool") or "").strip()])
    for candidate_tool_name in candidate_tool_names:
        if not candidate_tool_name or candidate_tool_name not in available_tools or candidate_tool_name in excluded:
            continue
        resolved_gap_ids = (
            unique_preserve_order(list(preferred_gap_ids or []) + ([focus_gap_id] if focus_gap_id else []))
            if candidate_tool_name == proposed_tool
            else ([focus_gap_id] if focus_gap_id else [])
        )
        try:
            action = _normalize_open_agent_action(
                seed_event,
                session_state,
                incident_state,
                candidate_tool_name,
                {},
                reason=reason or str(focus.get("reason") or "").strip(),
            )
        except Exception:
            continue
        return _tool_action_contract(
            action,
            reason=reason or str(focus.get("reason") or "").strip(),
            target_gap_ids=resolved_gap_ids,
            question=focus_question,
        )

    return _none_action_contract(
        reason or str(focus.get("reason") or "").strip(),
        target_gap_ids=unique_preserve_order(list(preferred_gap_ids or []) + ([focus_gap_id] if focus_gap_id else [])),
        question=focus_question,
    )


def _merge_tool_cooldowns(
    session_state: Dict[str, Any],
    incident_state: Dict[str, Any],
    finalized: Optional[Dict[str, Any]],
    suggestions: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    reviewer_state = session_state.setdefault("reviewer_state", {})
    existing = list(reviewer_state.get("tool_cooldowns") or [])
    active_existing = []
    for item in existing:
        current_signature = _cooldown_state_signature(
            incident_state,
            finalized,
            related_gap_ids=list(item.get("related_gap_ids") or []),
        )
        if str(item.get("state_signature") or "").strip() == current_signature:
            active_existing.append(dict(item))
    merged: Dict[str, Dict[str, Any]] = {
        str(item.get("tool_name") or "").strip(): item
        for item in active_existing
        if str(item.get("tool_name") or "").strip()
    }
    for item in suggestions:
        tool_name = str(item.get("tool_name") or "").strip()
        if tool_name:
            merged[tool_name] = dict(item)
    reviewer_state["tool_cooldowns"] = list(merged.values())[:12]
    return _active_tool_cooldowns(session_state, incident_state, finalized)


def _recent_tool_effects(session_state: Dict[str, Any]) -> List[Dict[str, Any]]:
    effects: List[Dict[str, Any]] = []
    for item in list(session_state.get("tool_history") or [])[-6:]:
        delta = dict(item.get("output_delta") or {})
        effects.append(
            {
                "step_index": item.get("step_index"),
                "tool_name": item.get("tool_name"),
                "input_fingerprint": item.get("input_fingerprint"),
                "status": item.get("status"),
                "novelty_score": int(delta.get("novelty_score") or 0),
                "material_score": _material_delta_score(delta),
                "editorial_score": _editorial_delta_score(delta),
                "delta_summary": str(delta.get("summary") or "").strip(),
            }
        )
    return effects


def _page_candidate_urls(incident_state: Dict[str, Any]) -> List[str]:
    return unique_preserve_order(item.get("url") for item in list(incident_state.get("page_candidates") or []))


def _latest_page_document(incident_state: Dict[str, Any]) -> Dict[str, Any]:
    documents = list(incident_state.get("page_documents") or [])
    for item in reversed(documents):
        if str(item.get("content") or "").strip():
            return item
    return {}


def _status_label(status: str) -> str:
    return STATUS_LABELS.get(str(status or "").strip(), str(status or "").strip())


def _primary_indicator(seed_event: Dict[str, Any], incident_state: Dict[str, Any]) -> str:
    entities = incident_state.get("entities") or {}
    scope = incident_state.get("scope") or {}
    return str(
        (list(scope.get("primary_external_indicators") or []) or [None])[0]
        or (list(entities.get("external_ips") or []) or [None])[0]
        or (list(entities.get("domains") or []) or [None])[0]
        or (((seed_event.get("dst") or {}).get("ip")) or "")
    ).strip()


def _seed_assets_from_state(incident_state: Dict[str, Any]) -> List[str]:
    entities = incident_state.get("entities") or {}
    pivots = incident_state.get("pivots") or {}
    return unique_preserve_order(
        [entities.get("seed_asset")] + list(pivots.get("asset_ids") or []) + list(entities.get("assets") or [])
    )


def _tool_category(tool_name: str) -> str:
    if tool_name in EVENT_TOOL_NAMES:
        return "event"
    if tool_name in INTEL_TOOL_NAMES:
        return "intel"
    if tool_name in PAGE_TOOL_NAMES:
        return "page"
    return "unknown"


def _clamp_int(value: Any, *, default: int, lower: int, upper: int) -> int:
    try:
        parsed = int(value)
    except Exception:
        parsed = default
    return max(lower, min(parsed, upper))


def _text_list(value: Any, *, limit: int = 8) -> List[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return []
    return unique_preserve_order(str(item or "").strip() for item in value if str(item or "").strip())[:limit]


def _sanitize_pivots(value: Any) -> Dict[str, List[str]]:
    if not isinstance(value, dict):
        return {}
    return {
        "asset_ids": _text_list(value.get("asset_ids"), limit=6),
        "src_ips": _text_list(value.get("src_ips"), limit=6),
        "dst_ips": _text_list(value.get("dst_ips"), limit=6),
        "domains": _text_list(value.get("domains"), limit=6),
        "fingerprints": _text_list(value.get("fingerprints"), limit=6),
    }


def _default_tool_request(seed_event: Dict[str, Any], session_state: Dict[str, Any], incident_state: Dict[str, Any], tool_name: str) -> Optional[Dict[str, Any]]:
    budgets = session_state.get("budgets") or {}
    remaining_event = int(budgets.get("remaining_event_queries") or 0)
    remaining_intel = int(budgets.get("remaining_intel_queries") or 0)
    pivots = incident_state.get("pivots") or {}
    entities = incident_state.get("entities") or {}
    family_hint = _meaningful_family_hint(seed_event)
    primary_indicator = _primary_indicator(seed_event, incident_state)
    indicator_target = _default_indicator_target(seed_event, incident_state)
    vt_indicator_target = _virustotal_indicator_target(seed_event, incident_state)
    candidate_events = _candidate_events(seed_event, incident_state)
    digest = _compose_digest(seed_event, incident_state, session_state)
    page_urls = _page_candidate_urls(incident_state)
    page_document = _latest_page_document(incident_state)
    seed_assets = _seed_assets_from_state(incident_state)
    related_assets = [asset for asset in list(entities.get("assets") or []) if asset and asset != entities.get("seed_asset")]
    allow_live_intel = str(os.getenv("INCIDENT_AGENT_LIVE_INTEL") or "").strip().lower() in {"1", "true", "yes"}

    if tool_name in EVENT_TOOL_NAMES and remaining_event <= 0:
        return None
    if tool_name in (INTEL_TOOL_NAMES | PAGE_TOOL_NAMES) and remaining_intel <= 0:
        return None

    if tool_name == "search_seed_context":
        return {
            "tool_name": tool_name,
            "category": "event",
            "question": "建立围绕 seed alert 的最小上下文。",
            "params": {},
            "meta": {},
            "trace_params": {
                "src_ip": ((seed_event.get("src") or {}).get("ip")) or "",
                "dst_ip": ((seed_event.get("dst") or {}).get("ip")) or "",
            },
            "expected_gain": "确认 seed 是否孤立、是否已有重复通信或相邻事件。",
        }
    if tool_name == "search_related_events":
        return {
            "tool_name": tool_name,
            "category": "event",
            "question": "基于当前 pivot 扩大事件簇。",
            "params": {"pivots": pivots, "window_minutes": 120, "limit": 60},
            "meta": {},
            "trace_params": {
                "asset_ids": pivots.get("asset_ids") or [],
                "dst_ips": pivots.get("dst_ips") or [],
                "domains": pivots.get("domains") or [],
            },
            "expected_gain": "确认是否存在同资产重复通信、同域名/同 IP 复现或更多可疑事件。",
        }
    if tool_name == GROUND_CANDIDATE_TOOL_NAME and candidate_events:
        candidate = dict(candidate_events[0])
        return {
            "tool_name": tool_name,
            "category": "intel",
            "question": "对扩线得到的候选事件做独立 grounding。",
            "params": {"event_id": str(candidate.get("id") or ""), "max_indicators": 4},
            "meta": {},
            "trace_params": _event_trace_params(candidate),
            "expected_gain": "确认该候选事件是否应升级为支撑证据，还是只保留为边界/上下文。",
        }
    if tool_name == COUNTEREVIDENCE_TOOL_NAME and seed_assets:
        return {
            "tool_name": tool_name,
            "category": "event",
            "question": "显式检查维护窗口、补丁、备份或共享基线等反证。",
            "params": {"asset_ids": seed_assets[:3], "window_minutes": 240, "limit": 80},
            "meta": {},
            "trace_params": {"asset_ids": seed_assets[:3], "focus": "maintenance_or_backup"},
            "expected_gain": "确认当前结论是否存在足以降级或保留为 needs_review 的背景解释。",
        }
    if tool_name == "expand_asset_scope" and (related_assets or seed_assets):
        asset_ids = related_assets or seed_assets[:3]
        return {
            "tool_name": tool_name,
            "category": "event",
            "question": "围绕关联资产补采主机上下文。",
            "params": {"asset_ids": asset_ids, "window_minutes": 180, "limit": 60},
            "meta": {},
            "trace_params": {"asset_ids": asset_ids},
            "expected_gain": "确认关联资产是共享背景，还是已经进入同一事件范围。",
        }
    if tool_name == "technical_source_search" and allow_live_intel and (family_hint or primary_indicator):
        query = family_hint or primary_indicator
        goal = "behavior_context" if family_hint else "infra_context"
        return {
            "tool_name": tool_name,
            "category": "intel",
            "question": "补齐家族行为与基础设施背景。",
            "params": {"query": query, "goal": goal, "max_results": 5},
            "meta": {},
            "trace_params": {"query": query, "goal": goal},
            "expected_gain": "补足围绕家族、TTP 或基础设施的外部解释。",
        }
    if tool_name == "local_intel_lookup" and indicator_target:
        return {
            "tool_name": tool_name,
            "category": "intel",
            "question": "检查关键指示物是否命中本地情报库。",
            "params": {
                "indicator_value": indicator_target.get("indicator_value"),
                "indicator_type": indicator_target.get("indicator_type"),
            },
            "meta": {},
            "trace_params": indicator_target,
            "expected_gain": "补足 JA4DB / 本地 IOC 库中的指纹或 IOC 命中，并明确命中来源。",
        }
    if tool_name == "vt_enrich_ioc" and allow_live_intel and vt_indicator_target:
        return {
            "tool_name": tool_name,
            "category": "intel",
            "question": "检查关键外部 IP 是否具有 VirusTotal reputation 信号。",
            "params": {
                "indicator_value": vt_indicator_target.get("indicator_value"),
                "indicator_type": vt_indicator_target.get("indicator_type"),
            },
            "meta": {},
            "trace_params": vt_indicator_target,
            "expected_gain": "补足 IP 侧 reputation / ASN / 国家信息，帮助解释外部基础设施是否更可疑。",
        }
    if tool_name == "abuse_ch_lookup" and allow_live_intel and indicator_target:
        return {
            "tool_name": tool_name,
            "category": "intel",
            "question": "聚合查询 abuse.ch 情报。",
            "params": {
                "indicator_value": indicator_target.get("indicator_value"),
                "indicator_type": indicator_target.get("indicator_type"),
                "max_results": 5,
            },
            "meta": {},
            "trace_params": indicator_target,
            "expected_gain": "快速补足围绕域名 / IP / URL / Hash 的 abuse.ch 结构化命中。",
        }
    if tool_name in {"threatfox_ioc_lookup", "urlhaus_ioc_lookup"} and allow_live_intel and indicator_target:
        return {
            "tool_name": tool_name,
            "category": "intel",
            "question": "检查关键指示物是否命中社区结构化情报。",
            "params": {
                "indicator_value": indicator_target.get("indicator_value"),
                "indicator_type": indicator_target.get("indicator_type"),
            },
            "meta": {},
            "trace_params": indicator_target,
            "expected_gain": "快速增强对外部基础设施或恶意投递链的解释。",
        }
    if tool_name == "malware_profile_lookup" and allow_live_intel and family_hint:
        return {
            "tool_name": tool_name,
            "category": "intel",
            "question": "为已知家族补齐高质量 profile。",
            "params": {"query": family_hint, "max_results": 4},
            "meta": {},
            "trace_params": {"query": family_hint},
            "expected_gain": "补足家族背景和行为概要。",
        }
    if tool_name == "pivot_related_indicators" and allow_live_intel and (primary_indicator or indicator_target):
        query = str(indicator_target.get("indicator_value") or primary_indicator or "").strip()
        return {
            "tool_name": tool_name,
            "category": "intel",
            "question": "围绕关键指示物搜索二跳 IOC 或基础设施。",
            "params": {"query": query, "max_results": 5},
            "meta": {},
            "trace_params": {"query": query},
            "expected_gain": "补充与主事件相关的基础设施侧线索。",
        }
    if tool_name == "fetch_page_content":
        default_url = page_urls[0] if page_urls else ""
        params: Dict[str, Any] = {"max_chars": 5000}
        if default_url:
            params["url"] = default_url
        return {
            "tool_name": tool_name,
            "category": "page",
            "question": "读取最相关技术页面正文。",
            "params": params,
            "meta": {},
            "trace_params": {"url": default_url},
            "expected_gain": "把检索结果转化为可直接引用的正文证据。",
        }
    if tool_name == "extract_claim_candidates_from_page":
        content_ref = "latest_page_document" if page_document else "investigation_digest"
        return {
            "tool_name": tool_name,
            "category": "page",
            "question": "把当前事实整理成可引用的 claim。",
            "params": {"content_ref": content_ref, "focus": family_hint or primary_indicator or "", "content": digest if content_ref == "investigation_digest" else ""},
            "meta": {
                "content_origin": page_document.get("content_origin") if content_ref == "latest_page_document" else "internal_digest",
                "source_url": page_document.get("url") if content_ref == "latest_page_document" else "",
            },
            "trace_params": {"content_ref": content_ref, "focus": family_hint or primary_indicator or ""},
            "expected_gain": "把当前调查事实压缩成结构化证据与 TTP 线索，并保留来源边界。",
        }
    if tool_name == "extract_entities_from_page":
        content_ref = "latest_page_document" if page_document else "investigation_digest"
        return {
            "tool_name": tool_name,
            "category": "page",
            "question": "抽取域名、IP、家族等实体。",
            "params": {"content_ref": content_ref, "content": digest if content_ref == "investigation_digest" else ""},
            "meta": {
                "content_origin": page_document.get("content_origin") if content_ref == "latest_page_document" else "internal_digest",
                "source_url": page_document.get("url") if content_ref == "latest_page_document" else "",
            },
            "trace_params": {"content_ref": content_ref},
            "expected_gain": "补齐 pivot 集合，同时避免把内部摘要误当成外部证据。",
        }
    return None


def _novel_scope_followup_actions(
    seed_event: Dict[str, Any],
    session_state: Dict[str, Any],
    incident_state: Dict[str, Any],
) -> List[Dict[str, Any]]:
    if not bool((incident_state.get("context_bundle") or {}).get("minimal_event_count")):
        return []
    rows: List[Dict[str, Any]] = []
    for tool_name in ("search_related_events", "expand_asset_scope"):
        request = _default_tool_request(seed_event, session_state, incident_state, tool_name)
        if not request:
            continue
        payload = dict(request.get("params") or {})
        meta = dict(request.get("meta") or {})
        input_fingerprint = _action_input_fingerprint(tool_name, payload, meta)
        if not input_fingerprint or _matching_tool_run(session_state, tool_name, input_fingerprint):
            continue
        trace_params = dict(request.get("trace_params") or payload)
        target_count = 0
        for value in trace_params.values():
            if isinstance(value, list):
                target_count += len([item for item in value if str(item or "").strip()])
            elif str(value or "").strip():
                target_count += 1
        rows.append(
            {
                "tool_name": tool_name,
                "question": str(request.get("question") or "").strip(),
                "trace_params": trace_params,
                "expected_gain": str(request.get("expected_gain") or "").strip(),
                "input_fingerprint": input_fingerprint,
                "target_count": target_count,
            }
        )
    rows.sort(
        key=lambda item: (
            -int(item.get("target_count") or 0),
            str(item.get("tool_name") or ""),
        )
    )
    return rows


def _available_tool_catalog(seed_event: Dict[str, Any], session_state: Dict[str, Any], incident_state: Dict[str, Any]) -> List[Dict[str, Any]]:
    acceptance_state = _acceptance_state(seed_event, session_state, incident_state)
    control_summary = _control_summary(seed_event, session_state, incident_state)
    material_gaps = list(acceptance_state.get("material_gaps") or _material_gap_view(seed_event, session_state, incident_state))
    active_cooldown_map = {
        str(item.get("tool_name") or "").strip(): dict(item)
        for item in _active_tool_cooldowns(session_state, incident_state)
        if str(item.get("tool_name") or "").strip()
    }
    descriptions = {
        "search_seed_context": "围绕 seed alert 取最小时间窗上下文，适合先确认告警是否孤立。",
        "search_related_events": "基于当前 pivot 扩大事件簇，但结果默认只是候选线索，不应直接并入主证据链。",
        GROUND_CANDIDATE_TOOL_NAME: "对单条候选事件做独立 grounding，会自动检查本地情报库和结构化 IOC 情报；只有命中后才适合升级为支撑证据。",
        "expand_asset_scope": "围绕指定资产补采上下文，适合确认关联资产是否真正受影响。",
        COUNTEREVIDENCE_TOOL_NAME: "检查维护、补丁、备份、共享基线等反证，适合在交付前降误报。",
        "local_intel_lookup": "查询本地 MySQL 情报库，适合 JA4DB / JA3 / SSL / CERT / IP / 域名等内部已知指示物验证。",
        "vt_enrich_ioc": "查询 VirusTotal 的外部 IP reputation / ASN 侧情报，适合继续验证关键外部基础设施。",
        "abuse_ch_lookup": "聚合查询 abuse.ch 系列情报，优先走结构化结果，必要时再回退到 abuse.ch 站内搜索。",
        "technical_source_search": "搜索技术来源，获取家族、TTP 或基础设施背景。",
        "threatfox_ioc_lookup": "查询 ThreatFox 结构化 IOC 情报。",
        "urlhaus_ioc_lookup": "查询 URLhaus 结构化 IOC 情报。",
        "malware_profile_lookup": "为已知家族查询 profile 结果。",
        "pivot_related_indicators": "围绕主指示物搜索二跳 IOC 或相关基础设施。",
        "fetch_page_content": "抓取技术页面正文，给后续 claim/entity 抽取做输入。",
        "extract_claim_candidates_from_page": "从最新页面正文或调查摘要中抽取可引用 claim；优先用 content_ref，不要直接粘贴长文本。",
        "extract_entities_from_page": "从最新页面正文或调查摘要中抽取实体；优先用 content_ref，不要直接粘贴长文本。",
    }
    param_notes = {
        "search_seed_context": {"params": {}, "defaults": "无参数，直接围绕 seed alert 检索。"},
        "search_related_events": {"params": {"pivots": "asset_ids/src_ips/dst_ips/domains/fingerprints", "window_minutes": "int", "limit": "int"}},
        GROUND_CANDIDATE_TOOL_NAME: {"params": {"event_id": "str", "max_indicators": "int"}},
        "expand_asset_scope": {"params": {"asset_ids": "list[str]", "window_minutes": "int", "limit": "int"}},
        COUNTEREVIDENCE_TOOL_NAME: {"params": {"asset_ids": "list[str]", "window_minutes": "int", "limit": "int"}},
        "local_intel_lookup": {"params": {"indicator_value": "str", "indicator_type": "IP|DOMAIN|JA3|JA4|SSL_SHA1|CERT_SHA1|..."}, "defaults": "查询本地 threat_intel / JA4DB 等来源。"},
        "vt_enrich_ioc": {"params": {"indicator_value": "str", "indicator_type": "IP"}, "defaults": "当前主要暴露 IP reputation 视角。"},
        "abuse_ch_lookup": {"params": {"indicator_value": "str", "indicator_type": "IP|DOMAIN|URL|SHA256|...", "max_results": "int"}},
        "technical_source_search": {"params": {"query": "str", "goal": "family_attribution|behavior_context|infra_context", "max_results": "int"}},
        "threatfox_ioc_lookup": {"params": {"indicator_value": "str", "indicator_type": "IP|DOMAIN|URL|..."}},
        "urlhaus_ioc_lookup": {"params": {"indicator_value": "str", "indicator_type": "IP|DOMAIN|URL|..."}},
        "malware_profile_lookup": {"params": {"query": "str", "max_results": "int"}},
        "pivot_related_indicators": {"params": {"query": "str", "max_results": "int"}},
        "fetch_page_content": {"params": {"url": "str", "max_chars": "int"}},
        "extract_claim_candidates_from_page": {"params": {"content_ref": "latest_page_document|investigation_digest", "focus": "str"}},
        "extract_entities_from_page": {"params": {"content_ref": "latest_page_document|investigation_digest"}},
    }
    catalog: List[Dict[str, Any]] = []
    for tool_name in ORDERED_TOOL_NAMES:
        precondition = _tool_precondition_view(seed_event, session_state, incident_state, tool_name)
        if not bool(precondition.get("available")):
            continue
        request = _default_tool_request(seed_event, session_state, incident_state, tool_name)
        if not request:
            continue
        input_fingerprint = _action_input_fingerprint(
            tool_name,
            dict(request.get("params") or {}),
            dict(request.get("meta") or {}),
        )
        reuse = _tool_reuse_advisory(session_state, tool_name, input_fingerprint)
        if reuse.get("repeat_suppressed"):
            continue
        profile = _tool_capability_profile(tool_name)
        recent_stats = _tool_recent_stats(session_state, tool_name)
        cooldown = dict(active_cooldown_map.get(tool_name) or {})
        target_gap_ids = _selected_gap_ids_for_action(
            tool_name,
            material_gaps,
            explicit_ids=list(precondition.get("relevant_gap_ids") or []),
        )
        alignment = _candidate_control_alignment(
            tool_name,
            target_gap_ids,
            material_gaps,
            acceptance_state,
            control_summary,
        )
        priority_tier = str(alignment.get("priority_tier") or "").strip()
        recommended_now = (
            not bool(cooldown)
            and priority_tier in {"primary_focus", "blocking_gap", "actionable_gap"}
            and not (bool(acceptance_state.get("preferred_stop")) and priority_tier not in {"primary_focus", "blocking_gap"})
        )
        catalog.append(
            {
                "tool_name": tool_name,
                "category": request.get("category"),
                "description": descriptions.get(tool_name, ""),
                "question": request.get("question"),
                "expected_gain": request.get("expected_gain"),
                "recommended_params": request.get("trace_params") or request.get("params") or {},
                "param_notes": param_notes.get(tool_name, {}),
                "input_fingerprint": input_fingerprint,
                "repeat_risk": reuse.get("repeat_risk"),
                "last_success_step": reuse.get("last_step_index"),
                "last_delta_summary": reuse.get("last_delta_summary"),
                "tool_mode": profile.get("tool_mode"),
                "capability_tags": list(profile.get("capability_tags") or []),
                "evidence_types": list(profile.get("evidence_types") or []),
                "relevant_gap_ids": list(precondition.get("relevant_gap_ids") or []),
                "target_gap_ids": target_gap_ids,
                "alignment": _candidate_alignment_view(alignment),
                "precondition_reason": str(precondition.get("reason") or "").strip(),
                "has_page_document": bool(precondition.get("has_page_document")),
                "page_url_count": int(precondition.get("page_url_count") or 0),
                "recent_material_score": recent_stats.get("recent_material_score"),
                "recent_editorial_score": recent_stats.get("recent_editorial_score"),
                "recent_materially_depleted": recent_stats.get("materially_depleted"),
                "recent_runs": list(recent_stats.get("recent_runs") or []),
                "cooldown_active": bool(cooldown),
                "cooldown_reason": str(cooldown.get("reason") or "").strip(),
                "cooldown_release_hint": str(cooldown.get("release_hint") or "").strip(),
                "cooldown_related_gap_ids": list(cooldown.get("related_gap_ids") or []),
                "recommended_now": recommended_now,
                "why_now": (
                    str(cooldown.get("reason") or "").strip()
                    if bool(cooldown)
                    else (
                        str(alignment.get("reason") or "").strip()
                        if recommended_now
                        else (
                            str(acceptance_state.get("preferred_stop_reason") or "").strip()
                            if bool(acceptance_state.get("preferred_stop"))
                            else str(request.get("expected_gain") or "").strip()
                        )
                    )
                ),
            }
        )
    return catalog


def _action_candidates(seed_event: Dict[str, Any], session_state: Dict[str, Any], incident_state: Dict[str, Any]) -> List[Dict[str, Any]]:
    acceptance_state = _acceptance_state(seed_event, session_state, incident_state)
    control_summary = _control_summary(seed_event, session_state, incident_state)
    material_gaps = list(acceptance_state.get("material_gaps") or _material_gap_view(seed_event, session_state, incident_state))
    filtered_candidates: List[Dict[str, Any]] = []
    for tool_entry in _available_tool_catalog(seed_event, session_state, incident_state):
        tool_name = str(tool_entry.get("tool_name") or "").strip()
        if not tool_name:
            continue
        request = _default_tool_request(seed_event, session_state, incident_state, tool_name)
        if not request:
            continue
        item = {
            "tool_name": tool_name,
            "category": request.get("category"),
            "question": request.get("question"),
            "params": dict(request.get("params") or {}),
            "meta": dict(request.get("meta") or {}),
            "trace_params": dict(request.get("trace_params") or request.get("params") or {}),
            "expected_gain": request.get("expected_gain"),
        }
        target_gap_ids = [
            str(item or "").strip()
            for item in list(tool_entry.get("target_gap_ids") or [])
            if str(item or "").strip()
        ]
        if not target_gap_ids:
            continue
        item["input_fingerprint"] = str(tool_entry.get("input_fingerprint") or "").strip()
        item["target_gap_ids"] = target_gap_ids
        item["alignment"] = dict(tool_entry.get("alignment") or {})
        item["repeat_risk"] = str(tool_entry.get("repeat_risk") or "").strip()
        item["recent_material_score"] = int(tool_entry.get("recent_material_score") or 0)
        item["recent_materially_depleted"] = bool(tool_entry.get("recent_materially_depleted"))
        item["acceptance_priority_bonus"] = _acceptance_priority_bonus(item, acceptance_state, control_summary)
        item["candidate_score"] = _candidate_action_priority(item, material_gaps)
        filtered_candidates.append(item)
    filtered_candidates.sort(
        key=lambda item: (
            -int(item.get("candidate_score") or 0),
            str(item.get("tool_name") or ""),
        )
    )
    return filtered_candidates


def _format_llm_session_summary(
    seed_event: Dict[str, Any],
    session_state: Dict[str, Any],
    incident_state: Dict[str, Any],
    finalized: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    ledger = list(incident_state.get("evidence_ledger") or [])
    latest_ledger = [
        {
            "observation_id": item.get("observation_id"),
            "relation": item.get("relation"),
            "summary": item.get("summary"),
        }
        for item in ledger[-5:]
    ]
    readiness = (finalized or {}).get("readiness") or incident_state.get("readiness") or {}
    acceptance_state = _acceptance_state(seed_event, session_state, incident_state, finalized)
    control_summary = _control_summary(seed_event, session_state, incident_state, finalized)
    active_cooldowns = _active_tool_cooldowns(session_state, incident_state, finalized)
    if finalized and isinstance(finalized.get("annotated_events"), list):
        candidate_events = [
            {
                "event_id": str(item.get("id") or "").strip(),
                "asset_id": str(item.get("asset_id") or "").strip(),
                "classification": str(item.get("classification") or "").strip(),
                "summary": str(item.get("summary") or "").strip(),
                "indicators": _event_indicator_candidates(item),
            }
            for item in list(finalized.get("annotated_events") or [])
            if str(item.get("role") or "").strip() == "candidate"
        ][:6]
    else:
        candidate_events = [
            {
                "event_id": str(item.get("id") or "").strip(),
                "asset_id": str(item.get("asset_id") or "").strip(),
                "classification": str(item.get("classification") or "").strip(),
                "summary": str(item.get("summary") or "").strip(),
                "indicators": _event_indicator_candidates(item),
            }
            for item in _candidate_events(seed_event, incident_state)[:6]
        ]
    return {
        "open_questions": list(session_state.get("open_questions") or []),
        "material_gaps": list(acceptance_state.get("material_gaps") or []),
        "working_hypotheses": list(session_state.get("working_hypotheses") or []),
        "budgets": session_state.get("budgets") or {},
        "latest_evidence": latest_ledger,
        "tool_history": _recent_tool_effects(session_state),
        "guardrail_feedback": list(session_state.get("guardrail_feedback") or [])[-4:],
        "control_summary": control_summary,
        "control_phase": str(control_summary.get("compat_phase") or ""),
        "active_tool_cooldowns": [
            {
                "tool_name": str(item.get("tool_name") or "").strip(),
                "reason": str(item.get("reason") or "").strip(),
                "related_gap_ids": list(item.get("related_gap_ids") or []),
                "release_hint": str(item.get("release_hint") or "").strip(),
                "override_required": bool(item.get("override_required")),
                "issued_for_focus": str(item.get("issued_for_focus") or "").strip(),
                "issued_for_goal": str(item.get("issued_for_goal") or "").strip(),
                "issued_in_phase": str(item.get("issued_in_phase") or "").strip(),
            }
            for item in active_cooldowns
        ],
        "acceptance_state": acceptance_state,
        "page_candidates": _page_candidate_urls(incident_state)[:3],
        "candidate_events": candidate_events,
        "entities": incident_state.get("entities") or {},
        "provisional_verdict": incident_state.get("provisional_verdict") or {},
        "delivery_verdict": incident_state.get("delivery_verdict") or incident_state.get("verdict") or {},
        "readiness": {
            "ready_for_delivery": bool(readiness.get("ready_for_delivery")),
            "summary": str(readiness.get("summary") or "").strip(),
            "blocking_checks": list(readiness.get("blocking_checks") or []),
        },
        "completion_advice": _completion_advice(seed_event, session_state, incident_state, finalized),
        "decision_mode": {
            "requested_mode": session_state.get("requested_decision_mode"),
            "effective_mode": session_state.get("decision_mode"),
            "policy_mode": session_state.get("policy_mode"),
        },
    }


def _selector_candidate_view(candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [
        {
            "tool_name": item.get("tool_name"),
            "category": item.get("category"),
            "question": item.get("question"),
            "trace_params": item.get("trace_params"),
            "expected_gain": item.get("expected_gain"),
            "target_gap_ids": list(item.get("target_gap_ids") or []),
            "candidate_score": int(item.get("candidate_score") or 0),
            "alignment": _candidate_alignment_view(dict(item.get("alignment") or {})),
            "repeat_risk": str(item.get("repeat_risk") or "").strip(),
            "recent_materially_depleted": bool(item.get("recent_materially_depleted")),
        }
        for item in candidates
    ]


def _selector_guardrail_choice(finalized: Dict[str, Any], candidates: List[Dict[str, Any]]) -> Dict[str, str]:
    del finalized
    ranked = sorted(
        [dict(item) for item in list(candidates or []) if str(item.get("tool_name") or "").strip()],
        key=lambda item: int(item.get("candidate_score") or 0),
        reverse=True,
    )
    for item in ranked:
        alignment = dict(item.get("alignment") or {})
        priority_tier = str(alignment.get("priority_tier") or "").strip()
        if priority_tier in {"primary_focus", "blocking_gap"}:
            return {
                "tool_name": str(item.get("tool_name") or "").strip(),
                "reason": f"当前仍有关键未闭合问题；{str(alignment.get('reason') or '').strip()}",
            }
    for item in ranked:
        alignment = dict(item.get("alignment") or {})
        if str(alignment.get("priority_tier") or "").strip() == "actionable_gap" and not bool(alignment.get("reportable_only")):
            return {
                "tool_name": str(item.get("tool_name") or "").strip(),
                "reason": f"当前仍有可继续缩小的问题；{str(alignment.get('reason') or '').strip()}",
            }
    return {"tool_name": "", "reason": ""}


def _extract_selector_json(content: str) -> Dict[str, Any]:
    text = str(content or "").strip()
    if not text:
        raise ValueError("empty selector response")
    if "```" in text:
        fragments = [fragment.strip() for fragment in text.split("```") if fragment.strip()]
        for fragment in fragments:
            normalized = fragment
            if normalized.lower().startswith("json"):
                normalized = normalized[4:].strip()
            if normalized.startswith("{") and normalized.endswith("}"):
                return json.loads(normalized)
    if text.startswith("{") and text.endswith("}"):
        return json.loads(text)
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        return json.loads(text[start : end + 1])
    raise ValueError("selector response does not contain JSON object")


def _choose_action(
    llm: Any,
    seed_event: Dict[str, Any],
    session_state: Dict[str, Any],
    incident_state: Dict[str, Any],
    candidates: List[Dict[str, Any]],
) -> Dict[str, Any]:
    selector_decision = {
        "step_index": int(session_state.get("step_index") or 0) + 1,
        "requested_mode": session_state.get("requested_decision_mode") or DECISION_MODE_HEURISTIC,
        "effective_mode": session_state.get("decision_mode") or DECISION_MODE_HEURISTIC,
        "policy_mode_before": session_state.get("policy_mode") or "",
        "candidate_tools": [str(item.get("tool_name") or "").strip() for item in candidates],
        "candidate_count": len(candidates),
        "chosen_by": "",
        "chosen_tool_name": "",
        "reason": "",
        "raw_response": "",
        "fallback_used": False,
        "fallback_reason": "",
        "stop_requested": False,
        "stop_accepted": False,
        "stop_override_reason": "",
        "outcome": "",
    }
    if not candidates:
        selector_decision["chosen_by"] = "none"
        selector_decision["outcome"] = "no_candidates"
        return {"action": None, "selector_decision": selector_decision}

    decision_mode = str(session_state.get("decision_mode") or DECISION_MODE_HEURISTIC).strip() or DECISION_MODE_HEURISTIC
    if decision_mode == DECISION_MODE_HEURISTIC or llm is None:
        chosen = dict(candidates[0])
        selector_decision["chosen_by"] = "heuristic"
        selector_decision["chosen_tool_name"] = str(chosen.get("tool_name") or "").strip()
        selector_decision["outcome"] = "selected_action"
        if llm is None and str(session_state.get("requested_decision_mode") or "") in {
            DECISION_MODE_LLM_SELECTOR,
            DECISION_MODE_HYBRID,
        }:
            selector_decision["fallback_used"] = True
            selector_decision["fallback_reason"] = "llm_unavailable"
        return {"action": chosen, "selector_decision": selector_decision}

    try:
        from langchain_core.prompts import ChatPromptTemplate

        prompt = ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    "你是 incident investigator 的动作选择器。"
                    "你只能在给定 candidates 中选一个最有价值的动作，不能编造新工具。"
                    "如果 candidates 里没有高价值动作，可返回 stop=true。"
                    "session.control_summary 是当前主要控制摘要，优先看 primary_goal / primary_reason / next_focus；session.control_phase 只是兼容标签。"
                    "candidates[*].alignment 描述了动作与当前控制焦点的对齐程度，优先选择 alignment.priority_tier 更高的动作。"
                    "如果 session.control_summary.scope_followup_pending 为 true，说明当前存在还没跑过的新 scope 查询，不要过早切到候选验证或 finish。"
                    "如果还存在未完成的反证检查、结构化整理或最小上下文构建，优先继续调查，不要过早停止。"
                    "如果 session.control_summary.deliverable_now 为 true，默认应 stop=true；只有在某个 candidate 能直接缩小 next_focus 对应的未闭合问题时，才继续。"
                    "输出 JSON：{{\"tool_name\":\"...\",\"stop\":false,\"reason\":\"...\",\"confidence\":0}}。"
                    "如果 stop=true，则 tool_name 置为空字符串。",
                ),
                (
                    "user",
                    "seed:\n{seed_json}\n\nsession:\n{session_json}\n\ncandidates:\n{candidates_json}",
                ),
            ]
        )
        response = llm.invoke(
            prompt.format_messages(
                seed_json=json.dumps(seed_event, ensure_ascii=False),
                session_json=json.dumps(_format_llm_session_summary(seed_event, session_state, incident_state), ensure_ascii=False),
                candidates_json=json.dumps(_selector_candidate_view(candidates), ensure_ascii=False),
            )
        )
        content = str(getattr(response, "content", "") or "").strip()
        selector_decision["raw_response"] = content[:800]
        parsed = _extract_selector_json(content)
        if parsed.get("stop"):
            selector_decision["chosen_by"] = "llm"
            selector_decision["reason"] = str(parsed.get("reason") or "").strip()
            selector_decision["stop_requested"] = True
            selector_decision["outcome"] = "stop_requested"
            return {"action": None, "selector_decision": selector_decision}
        tool_name = str(parsed.get("tool_name") or "").strip()
        for item in candidates:
            if str(item.get("tool_name") or "") == tool_name:
                chosen = dict(item)
                chosen["llm_reason"] = str(parsed.get("reason") or "").strip()
                selector_decision["chosen_by"] = "llm"
                selector_decision["chosen_tool_name"] = tool_name
                selector_decision["reason"] = str(parsed.get("reason") or "").strip()
                selector_decision["outcome"] = "selected_action"
                session_state["policy_mode"] = (
                    "hybrid_action_selector"
                    if decision_mode == DECISION_MODE_HYBRID
                    else "llm_action_selector"
                )
                return {"action": chosen, "selector_decision": selector_decision}
        selector_decision["chosen_by"] = "llm"
        selector_decision["reason"] = str(parsed.get("reason") or "").strip()
        selector_decision["fallback_used"] = True
        selector_decision["fallback_reason"] = f"unknown_tool:{tool_name or 'empty'}"
    except Exception as exc:
        selector_decision["fallback_used"] = True
        selector_decision["fallback_reason"] = f"selector_error:{exc}"

    chosen = dict(candidates[0])
    selector_decision["chosen_by"] = "heuristic_fallback"
    selector_decision["chosen_tool_name"] = str(chosen.get("tool_name") or "").strip()
    selector_decision["outcome"] = "selected_action"
    session_state["policy_mode"] = "heuristic_fallback"
    return {"action": chosen, "selector_decision": selector_decision}


def _resolve_page_tool_payload(
    tool_name: str,
    raw_params: Dict[str, Any],
    seed_event: Dict[str, Any],
    session_state: Dict[str, Any],
    incident_state: Dict[str, Any],
    default_request: Dict[str, Any],
) -> Dict[str, Any]:
    payload = dict(default_request.get("params") or {})
    meta = dict(default_request.get("meta") or {})
    explicit_content = str(raw_params.get("content") or "").strip()
    requested_ref = str(raw_params.get("content_ref") or payload.get("content_ref") or "").strip()
    page_document = _latest_page_document(incident_state)
    if requested_ref in {"latest_page_document", "latest_page", "page", "page_document"} and str(page_document.get("content") or "").strip():
        payload["content"] = str(page_document.get("content") or "")
        payload["content_ref"] = "latest_page_document"
        meta["content_origin"] = str(page_document.get("content_origin") or "page_content")
        meta["source_url"] = str(page_document.get("url") or "")
    elif explicit_content:
        payload["content"] = explicit_content
        payload["content_ref"] = "inline_content"
        meta["content_origin"] = "inline_content"
        meta["source_url"] = ""
    else:
        payload["content"] = _compose_digest(seed_event, incident_state, session_state)
        payload["content_ref"] = "investigation_digest"
        meta["content_origin"] = "internal_digest"
        meta["source_url"] = ""
    if tool_name == "extract_claim_candidates_from_page":
        payload["focus"] = str(raw_params.get("focus") or payload.get("focus") or "").strip()
    return {"params": payload, "meta": meta}


def _normalize_open_agent_action(
    seed_event: Dict[str, Any],
    session_state: Dict[str, Any],
    incident_state: Dict[str, Any],
    tool_name: str,
    raw_params: Dict[str, Any],
    *,
    reason: str = "",
    override_reason: str = "",
) -> Dict[str, Any]:
    default_request = _default_tool_request(seed_event, session_state, incident_state, tool_name)
    if not default_request:
        raise ValueError(f"tool_not_available:{tool_name}")

    payload = dict(default_request.get("params") or {})
    meta = dict(default_request.get("meta") or {})
    raw_params = dict(raw_params or {})

    if tool_name == "search_related_events":
        pivots = _sanitize_pivots(raw_params.get("pivots"))
        if any(pivots.values()):
            payload["pivots"] = pivots
        payload["window_minutes"] = _clamp_int(raw_params.get("window_minutes"), default=int(payload.get("window_minutes") or 120), lower=15, upper=720)
        payload["limit"] = _clamp_int(raw_params.get("limit"), default=int(payload.get("limit") or 60), lower=5, upper=100)
    elif tool_name == GROUND_CANDIDATE_TOOL_NAME:
        payload["event_id"] = str(raw_params.get("event_id") or payload.get("event_id") or "").strip()
        payload["max_indicators"] = _clamp_int(raw_params.get("max_indicators"), default=int(payload.get("max_indicators") or 4), lower=1, upper=6)
        candidate_ids = {
            str(item.get("id") or "").strip()
            for item in _candidate_events(seed_event, incident_state)
            if str(item.get("id") or "").strip()
        }
        if not payload["event_id"]:
            raise ValueError("missing_event_id:ground_candidate_event")
        if payload["event_id"] not in candidate_ids:
            raise ValueError(f"unknown_candidate_event:{payload['event_id']}")
    elif tool_name in {"expand_asset_scope", COUNTEREVIDENCE_TOOL_NAME}:
        asset_ids = _text_list(raw_params.get("asset_ids"), limit=6)
        if asset_ids:
            payload["asset_ids"] = asset_ids
        payload["window_minutes"] = _clamp_int(
            raw_params.get("window_minutes"),
            default=int(payload.get("window_minutes") or (240 if tool_name == COUNTEREVIDENCE_TOOL_NAME else 180)),
            lower=30,
            upper=1440,
        )
        payload["limit"] = _clamp_int(
            raw_params.get("limit"),
            default=int(payload.get("limit") or (80 if tool_name == COUNTEREVIDENCE_TOOL_NAME else 60)),
            lower=5,
            upper=120,
        )
        if not list(payload.get("asset_ids") or []):
            raise ValueError(f"missing_asset_ids:{tool_name}")
    elif tool_name == "technical_source_search":
        payload["query"] = str(raw_params.get("query") or payload.get("query") or "").strip()
        payload["goal"] = str(raw_params.get("goal") or payload.get("goal") or "family_attribution").strip().lower()
        if payload["goal"] not in {"family_attribution", "behavior_context", "infra_context"}:
            payload["goal"] = str(default_request.get("params", {}).get("goal") or "family_attribution")
        payload["max_results"] = _clamp_int(raw_params.get("max_results"), default=int(payload.get("max_results") or 5), lower=2, upper=8)
        if not payload["query"]:
            raise ValueError("missing_query:technical_source_search")
    elif tool_name in {"local_intel_lookup", "vt_enrich_ioc", "threatfox_ioc_lookup", "urlhaus_ioc_lookup"}:
        payload["indicator_value"] = str(raw_params.get("indicator_value") or payload.get("indicator_value") or "").strip()
        payload["indicator_type"] = str(raw_params.get("indicator_type") or payload.get("indicator_type") or "").strip().upper()
        if not payload["indicator_value"]:
            raise ValueError(f"missing_indicator:{tool_name}")
        if not payload["indicator_type"]:
            payload["indicator_type"] = _extract_indicator_type(payload["indicator_value"])
    elif tool_name == "abuse_ch_lookup":
        payload["indicator_value"] = str(raw_params.get("indicator_value") or payload.get("indicator_value") or "").strip()
        payload["indicator_type"] = str(raw_params.get("indicator_type") or payload.get("indicator_type") or "").strip().upper()
        payload["max_results"] = _clamp_int(raw_params.get("max_results"), default=int(payload.get("max_results") or 5), lower=2, upper=8)
        if not payload["indicator_value"]:
            raise ValueError("missing_indicator:abuse_ch_lookup")
        if not payload["indicator_type"]:
            payload["indicator_type"] = _extract_indicator_type(payload["indicator_value"])
    elif tool_name in {"malware_profile_lookup", "pivot_related_indicators"}:
        key = "query"
        payload[key] = str(raw_params.get(key) or payload.get(key) or "").strip()
        payload["max_results"] = _clamp_int(raw_params.get("max_results"), default=int(payload.get("max_results") or 5), lower=2, upper=8)
        if not payload[key]:
            raise ValueError(f"missing_query:{tool_name}")
    elif tool_name == "fetch_page_content":
        payload["url"] = str(raw_params.get("url") or payload.get("url") or "").strip()
        payload["max_chars"] = _clamp_int(raw_params.get("max_chars"), default=int(payload.get("max_chars") or 5000), lower=500, upper=12000)
        if not payload["url"]:
            raise ValueError("missing_url:fetch_page_content")
    elif tool_name in {"extract_claim_candidates_from_page", "extract_entities_from_page"}:
        resolved = _resolve_page_tool_payload(tool_name, raw_params, seed_event, session_state, incident_state, default_request)
        payload = resolved["params"]
        meta = resolved["meta"]
    elif tool_name == "search_seed_context":
        payload = {}

    action = dict(default_request)
    action["params"] = payload
    action["meta"] = meta
    action["trace_params"] = {
        key: value
        for key, value in payload.items()
        if key not in {"content"}
    }
    return _tool_action_contract(
        action,
        reason=reason,
        override_reason=override_reason,
    )


def _consume_non_tool_step_budget(session_state: Dict[str, Any]) -> None:
    budgets = session_state.get("budgets") or {}
    budgets["remaining_steps"] = max(0, int(budgets.get("remaining_steps") or 0) - 1)


def _choose_open_agent_action(
    llm: Any,
    seed_event: Dict[str, Any],
    session_state: Dict[str, Any],
    incident_state: Dict[str, Any],
    finalized: Dict[str, Any],
) -> Dict[str, Any]:
    tool_catalog = _available_tool_catalog(seed_event, session_state, incident_state)
    acceptance_state = _acceptance_state(seed_event, session_state, incident_state, finalized)
    completion_advice = _completion_advice(seed_event, session_state, incident_state, finalized)
    runtime_summary = _format_llm_session_summary(seed_event, session_state, incident_state, finalized)
    decision = {
        "step_index": int(session_state.get("step_index") or 0) + 1,
        "requested_mode": session_state.get("requested_decision_mode") or DECISION_MODE_LLM_AGENT,
        "effective_mode": session_state.get("decision_mode") or DECISION_MODE_LLM_AGENT,
        "policy_mode_before": session_state.get("policy_mode") or "",
        "action_type": "",
        "tool_name": "",
        "params": {},
        "reason": "",
        "raw_response": "",
        "fallback_used": False,
        "fallback_reason": "",
        "tool_catalog": [item.get("tool_name") for item in tool_catalog],
        "target_gap_ids": [],
        "why_not_finish": "",
        "override_reason": "",
        "finish_requested": False,
        "finish_accepted": False,
        "finish_blocked_reason": "",
        "validator_override": "",
        "validator_feedback": "",
        "completion_advice": completion_advice,
        "material_gaps": list(completion_advice.get("material_gaps") or []),
        "outcome": "",
    }
    if llm is None:
        decision["fallback_used"] = True
        decision["fallback_reason"] = "llm_unavailable"
        decision["outcome"] = "fallback"
        return {"action_type": "fallback", "decision": decision}
    if not tool_catalog:
        decision["action_type"] = "finish"
        decision["finish_requested"] = True
        decision["finish_accepted"] = True
        decision["reason"] = "没有可继续调用的工具。"
        decision["outcome"] = "finish"
        return {"action_type": "finish", "decision": decision}

    try:
        from langchain_core.prompts import ChatPromptTemplate

        prompt = ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    "你是 investigator agent。"
                    "你只负责提出下一步调查建议，最终是否执行由 reviewer 审批。"
                    "你可以在每一轮建议调用哪个工具、传什么参数，或者在调查结束时建议 finish。"
                    "只允许使用 tool_catalog 里给出的工具名。"
                    "tool_catalog[*].alignment 是当前动作与控制焦点的对齐摘要，优先选择 priority_tier 更高、reason 更直接的动作。"
                    "runtime.control_summary 是当前主要控制摘要，优先依据 primary_goal、primary_reason、next_focus 推进；runtime.control_phase 只是兼容标签，不要机械按 phase 名走固定流程。"
                    "优先依据当前 state、latest_evidence、recent tool effects、material_gaps、acceptance_state.blocking_checks 推进。"
                    "runtime.active_tool_cooldowns 表示 reviewer 仍在生效的工具冷却建议。"
                    "如果 runtime.control_summary.scope_followup_pending 为 true，应优先考虑 tool_catalog 中仍未执行过的新 scope 动作，而不是过早转入 finish 或纯验证收尾。"
                    "如果建议继续行动，必须明确指出你要缩小哪个 material gap，以及为什么该 gap 的 recent_attempts 尚未说明它已经耗尽。"
                    "如果 blocking_checks 仍存在，不要建议 finish，除非你明确判断没有任何更高价值工具。"
                    "如果 acceptance_state.preferred_stop 为 true，默认应该建议 finish；只有在你能明确指出还有哪个未闭合问题会因下一步工具而减少时，才继续行动。"
                    "如果 runtime.control_summary.focus_mode 是 candidate_validation，不要把 candidate 当成 confirmed 事件继续扩线，应优先做 grounding 或显式情报验证。"
                    "如果 runtime.control_summary.recent_low_value_steps >= 2，除非状态发生了可解释变化，否则不要继续重复低收益工具。"
                    "如果 material_gaps 里的 status 是 reportable_unresolved，不要继续为它调用工具，应把它留给报告待确认事项。"
                    "不要重复调用同一输入已经成功执行过的确定性工具。"
                    "如果你要选择 active_tool_cooldowns 中仍在冷却的工具，必须提供 override_reason，说明什么状态发生了变化，或为什么这次调用与之前的低收益尝试不同。"
                    "search_related_events / expand_asset_scope 找到的可疑事件默认只是 candidate，不等于已经完成验证；如果要把它们并入主证据链，应优先调用 ground_candidate_event 或显式情报工具。"
                    "对 extract_claim_candidates_from_page / extract_entities_from_page，优先传 content_ref，而不是直接粘贴长文本。"
                    "输出 JSON："
                    "{{\"action\":\"tool\",\"tool_name\":\"...\",\"params\":{{}},\"target_gap_ids\":[\"...\"],\"reason\":\"...\",\"why_not_finish\":\"...\",\"override_reason\":\"...\"}}"
                    " 或 "
                    "{{\"action\":\"finish\",\"reason\":\"...\"}}。",
                ),
                (
                    "user",
                    "seed:\n{seed_json}\n\nruntime:\n{runtime_json}\n\ntool_catalog:\n{tool_catalog_json}",
                ),
            ]
        )
        response = llm.invoke(
            prompt.format_messages(
                seed_json=json.dumps(seed_event, ensure_ascii=False),
                runtime_json=json.dumps(runtime_summary, ensure_ascii=False),
                tool_catalog_json=json.dumps(tool_catalog, ensure_ascii=False),
            )
        )
        content = str(getattr(response, "content", "") or "").strip()
        decision["raw_response"] = content[:1200]
        parsed = _extract_selector_json(content)
        action_type = str(parsed.get("action") or "tool").strip().lower()
        if action_type == "finish":
            decision["action_type"] = "finish"
            decision["finish_requested"] = True
            decision["reason"] = str(parsed.get("reason") or "").strip()
            decision["outcome"] = "finish"
            return {"action_type": "finish", "decision": decision}
        tool_name = str(parsed.get("tool_name") or "").strip()
        if tool_name not in {item.get("tool_name") for item in tool_catalog}:
            raise ValueError(f"unknown_tool:{tool_name or 'empty'}")
        decision["action_type"] = "tool"
        decision["tool_name"] = tool_name
        decision["params"] = dict(parsed.get("params") or {})
        decision["target_gap_ids"] = _text_list(parsed.get("target_gap_ids"), limit=4)
        decision["reason"] = str(parsed.get("reason") or "").strip()
        decision["why_not_finish"] = str(parsed.get("why_not_finish") or "").strip()
        decision["override_reason"] = str(parsed.get("override_reason") or "").strip()
        if bool(acceptance_state.get("preferred_stop")) and not decision["why_not_finish"]:
            decision["validator_feedback"] = (
                "当前默认已可交付；若继续调用工具，应明确说明 why_not_finish，指出这一步将缩小哪个未闭合问题。"
            )
        decision["outcome"] = "tool"
        return {"action_type": "tool", "decision": decision}
    except Exception as exc:
        decision["fallback_used"] = True
        decision["fallback_reason"] = f"agent_error:{exc}"
        decision["outcome"] = "fallback"
        return {"action_type": "fallback", "decision": decision}


def _normalize_blocked_tools(value: Any) -> List[Dict[str, str]]:
    if not isinstance(value, list):
        return []
    blocked: List[Dict[str, str]] = []
    for item in value:
        if isinstance(item, dict):
            tool_name = str(item.get("tool_name") or "").strip()
            reason = str(item.get("reason") or "").strip()
        else:
            tool_name = str(item or "").strip()
            reason = ""
        if tool_name:
            blocked.append({"tool_name": tool_name, "reason": reason})
    return blocked


def _reviewer_context_view(
    seed_event: Dict[str, Any],
    session_state: Dict[str, Any],
    incident_state: Dict[str, Any],
    finalized: Dict[str, Any],
) -> Dict[str, Any]:
    acceptance_state = _acceptance_state(seed_event, session_state, incident_state, finalized)
    control_summary = _control_summary(seed_event, session_state, incident_state, finalized)
    return {
        "runtime": _format_llm_session_summary(seed_event, session_state, incident_state, finalized),
        "gap_ledger": list((finalized or {}).get("gap_ledger") or incident_state.get("gap_ledger") or []),
        "recent_tool_effects": _recent_tool_effects(session_state),
        "acceptance_state": acceptance_state,
        "readiness": finalized.get("readiness") or {},
        "delivery_verdict": finalized.get("delivery_verdict") or finalized.get("verdict") or {},
        "scope": finalized.get("scope") or {},
        "uncertainties": finalized.get("uncertainties") or [],
        "control_summary": control_summary,
        "control_phase": str(control_summary.get("compat_phase") or ""),
        "active_tool_cooldowns": _active_tool_cooldowns(session_state, incident_state, finalized),
    }


def _normalize_blocking_gap_rows(
    value: Any,
    canonical_gap_map: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    if not isinstance(value, list):
        return []
    rows: List[Dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        gap_id = str(item.get("gap_id") or item.get("id") or "").strip()
        base = dict(canonical_gap_map.get(gap_id) or {})
        if gap_id and "gap_id" not in base:
            base["gap_id"] = gap_id
        base.update(item)
        if str(base.get("gap_id") or base.get("id") or "").strip():
            rows.append(base)
    return rows


def _normalize_tool_cooldown_rows(
    value: Any,
    canonical_gap_map: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    if not isinstance(value, list):
        return []
    rows: List[Dict[str, Any]] = []
    for item in value:
        if isinstance(item, dict):
            tool_name = str(item.get("tool_name") or "").strip()
            reason = str(item.get("reason") or "").strip()
            related_gap_ids = _text_list(item.get("related_gap_ids"), limit=4)
        else:
            tool_name = str(item or "").strip()
            reason = ""
            related_gap_ids = []
        related_gap_ids = [
            gap_id
            for gap_id in related_gap_ids
            if gap_id in canonical_gap_map or not canonical_gap_map
        ]
        if tool_name:
            rows.append(
                {
                    "tool_name": tool_name,
                    "reason": reason,
                    "related_gap_ids": related_gap_ids,
                }
            )
    return rows


def _proposal_cooldown_violation(
    proposal: Dict[str, Any],
    active_cooldowns: List[Dict[str, Any]],
) -> Dict[str, Any]:
    if str(proposal.get("action_type") or "").strip() != "tool":
        return {}
    tool_name = str(proposal.get("tool_name") or "").strip()
    if not tool_name:
        return {}
    override_reason = str(proposal.get("override_reason") or "").strip()
    for item in list(active_cooldowns or []):
        if str(item.get("tool_name") or "").strip() != tool_name:
            continue
        if override_reason:
            return {}
        return {
            "tool_name": tool_name,
            "reason": _cooldown_reason_text(str(item.get("reason") or "").strip()),
            "related_gap_ids": list(item.get("related_gap_ids") or []),
            "release_hint": str(item.get("release_hint") or "").strip(),
        }
    return {}


def _apply_reviewer_control_metadata(
    seed_event: Dict[str, Any],
    session_state: Dict[str, Any],
    incident_state: Dict[str, Any],
    finalized: Dict[str, Any],
    tool_catalog: List[Dict[str, Any]],
    proposal: Dict[str, Any],
    review: Dict[str, Any],
) -> Dict[str, Any]:
    acceptance_state = _acceptance_state(seed_event, session_state, incident_state, finalized)
    control_summary = _control_summary(seed_event, session_state, incident_state, finalized)
    control_phase = str(control_summary.get("compat_phase") or "stabilize_evidence")
    issued_for_focus = str(control_summary.get("focus_mode") or "").strip()
    preexisting_active_cooldowns = _active_tool_cooldowns(session_state, incident_state, finalized)
    proposal_violation = _proposal_cooldown_violation(
        proposal,
        preexisting_active_cooldowns,
    )
    decision = str(review.get("decision") or "allow").strip().lower()
    if decision not in REVIEWER_DECISIONS:
        decision = "allow"
    review["decision"] = decision
    review["proposal_alignment"] = dict(proposal.get("alignment") or {})
    review["material_gaps"] = list(review.get("material_gaps") or acceptance_state.get("material_gaps") or [])
    canonical_gap_map = _merged_gap_map(
        list(finalized.get("gap_ledger") or []),
        list(incident_state.get("gap_ledger") or []),
        list(review.get("material_gaps") or []),
    )
    blocking_gaps = _normalize_blocking_gap_rows(review.get("blocking_gaps"), canonical_gap_map)
    if not blocking_gaps:
        blocking_gaps = _canonical_blocking_gaps(list(review.get("material_gaps") or []))

    blocked_tools = _normalize_blocked_tools(review.get("blocked_tools"))
    low_value_repeats = _normalize_reviewer_rows(review.get("low_value_repeats"))
    if not low_value_repeats:
        low_value_repeats = _low_value_repeat_rows(tool_catalog, blocked_tools)

    next_focus = dict(review.get("next_focus") or {})
    if not next_focus:
        next_focus = _build_reviewer_next_focus(tool_catalog, blocking_gaps)
    compat_allowed_tools = [
        str(item or "").strip()
        for item in list(review.get("allowed_tools") or [])
        if str(item or "").strip()
    ]
    next_action = _normalize_reviewer_next_action(
        review.get("next_action"),
        seed_event,
        session_state,
        incident_state,
        tool_catalog,
        canonical_gap_map,
        proposal=proposal,
        fallback_reason=str(review.get("reason") or "").strip(),
        default_action_type="finish" if decision == "deliverable" else "none",
    )
    if str(next_action.get("action_type") or "").strip() == "none" and compat_allowed_tools and decision != "deliverable":
        next_action = _normalize_reviewer_next_action(
            {
                "action_type": "tool",
                "tool_name": compat_allowed_tools[0],
                "target_gap_ids": list(next_action.get("target_gap_ids") or []),
                "reason": str(review.get("reason") or "").strip(),
            },
            seed_event,
            session_state,
            incident_state,
            tool_catalog,
            canonical_gap_map,
            proposal=proposal,
            fallback_reason=str(review.get("reason") or "").strip(),
            default_action_type="tool",
        )

    if decision == "deliverable" and not bool(acceptance_state.get("deliverable_now")):
        review["decision"] = "not_deliverable"
        review["deliverable_now"] = False
        review["reason"] = "当前仍存在可由现有工具继续缩小的关键问题，尚不适合交付。"
        review["outcome"] = "not_deliverable"
        decision = "not_deliverable"
        if str(next_action.get("action_type") or "").strip() == "finish":
            next_action = {
                **_none_action_contract(str(review.get("reason") or "").strip()),
            }

    if decision == "deliverable":
        reason = str(review.get("reason") or "").strip() or "当前已满足交付条件，可以结束调查。"
        review["deliverable_now"] = True
        review["material_gaps"] = [
            _carryable_gap_view(
                gap,
                status_reason="当前核心结论已经达到交付门槛，剩余问题应作为报告边界说明，而不是继续阻塞交付。",
            )
            for gap in list(review.get("material_gaps") or acceptance_state.get("reportable_gaps") or [])
            if str(gap.get("status") or "").strip() != "closed"
        ]
        review["next_action"] = {
            **_finish_action_contract(reason),
        }
        review["allowed_tools"] = []
        review["blocked_tools"] = []
        review["blocking_gaps"] = []
        review["low_value_repeats"] = []
        review["tool_cooldown_suggestions"] = []
        review["next_focus"] = {}
        review["control_summary"] = control_summary
        review["control_phase"] = control_phase
        review["cooldown_state_signature"] = _cooldown_state_signature(incident_state, finalized)
        session_state.setdefault("reviewer_state", {})["tool_cooldowns"] = []
        review["active_tool_cooldowns"] = []
        return review

    issued_for_goal = str(
        next_focus.get("question")
        or (control_summary.get("next_focus") or {}).get("question")
        or control_summary.get("primary_goal")
        or ""
    ).strip()

    cooldown_suggestions = _normalize_tool_cooldown_rows(review.get("tool_cooldown_suggestions"), canonical_gap_map)
    if not cooldown_suggestions:
        current_signature = _cooldown_state_signature(
            incident_state,
            finalized,
            related_gap_ids=[str(item.get("gap_id") or "").strip() for item in blocking_gaps if str(item.get("gap_id") or "").strip()],
        )
        release_hint = "当相关 gap 状态发生变化、出现新的 grounded evidence，或 reviewer 的 blocking_gaps 改变后，再考虑重试。"
        for item in low_value_repeats[:3]:
            related_gap_ids = [
                gap_id
                for gap_id in [str(gap.get("gap_id") or "").strip() for gap in blocking_gaps]
                if gap_id
            ]
            cooldown_suggestions.append(
                {
                    "tool_name": str(item.get("tool_name") or "").strip(),
                    "reason": _cooldown_reason_text(str(item.get("reason") or "").strip()),
                    "related_gap_ids": related_gap_ids,
                    "state_signature": current_signature,
                    "issued_step": int(session_state.get("step_index") or 0) + 1,
                    "issued_for_focus": issued_for_focus,
                    "issued_for_goal": issued_for_goal,
                    "issued_in_phase": control_phase,
                    "override_required": True,
                    "release_hint": release_hint,
                }
            )
        if proposal_violation:
            cooldown_suggestions.append(
                {
                    "tool_name": str(proposal_violation.get("tool_name") or "").strip(),
                    "reason": _cooldown_reason_text(str(proposal_violation.get("reason") or "").strip()),
                    "related_gap_ids": list(proposal_violation.get("related_gap_ids") or []),
                    "state_signature": _cooldown_state_signature(
                        incident_state,
                        finalized,
                        related_gap_ids=list(proposal_violation.get("related_gap_ids") or []),
                    ),
                    "issued_step": int(session_state.get("step_index") or 0) + 1,
                    "issued_for_focus": issued_for_focus,
                    "issued_for_goal": issued_for_goal,
                    "issued_in_phase": control_phase,
                    "override_required": True,
                    "release_hint": str(proposal_violation.get("release_hint") or "").strip() or release_hint,
                }
            )
    else:
        normalized_rows: List[Dict[str, Any]] = []
        for item in cooldown_suggestions:
            related_gap_ids = [gap_id for gap_id in list(item.get("related_gap_ids") or []) if gap_id]
            normalized_rows.append(
                {
                    "tool_name": str(item.get("tool_name") or "").strip(),
                    "reason": _cooldown_reason_text(str(item.get("reason") or "").strip()),
                    "related_gap_ids": related_gap_ids,
                    "state_signature": _cooldown_state_signature(incident_state, finalized, related_gap_ids=related_gap_ids),
                    "issued_step": int(session_state.get("step_index") or 0) + 1,
                    "issued_for_focus": issued_for_focus,
                    "issued_for_goal": issued_for_goal,
                    "issued_in_phase": control_phase,
                    "override_required": True,
                    "release_hint": "当相关 gap 状态发生变化、出现新的 grounded evidence，或 reviewer 的 blocking_gaps 改变后，再考虑重试。",
                }
            )
        cooldown_suggestions = normalized_rows

    blocked_tool_names = {
        str(item.get("tool_name") or "").strip()
        for item in blocked_tools
        if str(item.get("tool_name") or "").strip()
    }
    if proposal_violation:
        blocked_tools.append(
            {
                "tool_name": str(proposal_violation.get("tool_name") or "").strip(),
                "reason": _cooldown_reason_text(str(proposal_violation.get("reason") or "").strip()),
            }
        )
        blocked_tool_names.add(str(proposal_violation.get("tool_name") or "").strip())
        review["decision"] = "block"
        review["outcome"] = "block"
        review["deliverable_now"] = False
        review["reason"] = (
            f"{_cooldown_reason_text(str(proposal_violation.get('reason') or '').strip())} "
            "当前若要继续调用该工具，investigator 必须给出明确的 override_reason。"
        )
        review["cooldown_override_required"] = True
        review["cooldown_override_missing"] = True
        decision = "block"

    if str(next_action.get("action_type") or "").strip() == "tool" and str(next_action.get("tool_name") or "").strip() in blocked_tool_names:
        next_action = {
            "action_type": "none",
            "tool_name": "",
            "target_gap_ids": list(next_action.get("target_gap_ids") or []),
            "question": str(next_action.get("question") or "").strip(),
            "reason": str(next_action.get("reason") or review.get("reason") or "").strip(),
        }

    if str(next_action.get("action_type") or "").strip() == "none":
        next_action = _fallback_reviewer_next_action(
            seed_event=seed_event,
            session_state=session_state,
            incident_state=incident_state,
            decision=decision,
            tool_catalog=tool_catalog,
            proposal=proposal,
            blocking_gaps=blocking_gaps,
            next_focus=next_focus,
            fallback_reason=str(review.get("reason") or "").strip(),
            preferred_tool_name=compat_allowed_tools[0] if compat_allowed_tools else "",
            preferred_gap_ids=list(next_action.get("target_gap_ids") or []),
            excluded_tools=blocked_tool_names,
        )

    review["next_action"] = next_action
    review["allowed_tools"] = _reviewer_allowed_tools_from_next_action(next_action)
    review["blocked_tools"] = blocked_tools
    review["blocking_gaps"] = blocking_gaps
    review["low_value_repeats"] = low_value_repeats
    review["tool_cooldown_suggestions"] = cooldown_suggestions[:4]
    review["next_focus"] = next_focus
    review["control_summary"] = control_summary
    review["control_phase"] = control_phase
    review["cooldown_state_signature"] = _cooldown_state_signature(incident_state, finalized)
    review["active_tool_cooldowns"] = _merge_tool_cooldowns(session_state, incident_state, finalized, list(review.get("tool_cooldown_suggestions") or []))
    return review


def _review_open_agent_proposal(
    llm: Any,
    seed_event: Dict[str, Any],
    session_state: Dict[str, Any],
    incident_state: Dict[str, Any],
    finalized: Dict[str, Any],
    tool_catalog: List[Dict[str, Any]],
    proposal: Dict[str, Any],
) -> Dict[str, Any]:
    tool_names = [str(item.get("tool_name") or "").strip() for item in tool_catalog if str(item.get("tool_name") or "").strip()]
    acceptance_state = _acceptance_state(seed_event, session_state, incident_state, finalized)
    review_context = _reviewer_context_view(seed_event, session_state, incident_state, finalized)
    review = {
        "step_index": int(session_state.get("step_index") or 0) + 1,
        "role": "reviewer",
        "decision": "allow",
        "deliverable_now": bool(acceptance_state.get("deliverable_now")),
        "material_gaps": list(acceptance_state.get("material_gaps") or []),
        "allowed_tools": tool_names,
        "next_action": {},
        "blocked_tools": [],
        "blocking_gaps": [],
        "low_value_repeats": [],
        "tool_cooldown_suggestions": [],
        "next_focus": {},
        "reason": "",
        "raw_response": "",
        "fallback_used": False,
        "fallback_reason": "",
        "outcome": "allow",
    }
    if llm is None:
        review["fallback_used"] = True
        review["fallback_reason"] = "llm_unavailable"
        return review

    try:
        from langchain_core.prompts import ChatPromptTemplate

        prompt = ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    "你是 incident delivery reviewer，是 investigator 的验收员，不是第二个调查员。"
                    "你不能调用工具，只能对 investigator 的提案做交付审查。"
                    "你的目标是避免三类错误：过早交付、继续执行低价值工具、以及让 reviewer 自己变成第二个规划器。"
                    "review_context.control_summary 是当前主要控制摘要，优先依据 primary_goal、primary_reason、next_focus 和 recent_low_value_steps 判断；control_phase 只是兼容标签。"
                    "proposal.alignment 是提案与当前控制焦点的结构化对齐摘要，优先依据它判断该提案是否真的推进了当前主目标。"
                    "如果 review_context.control_summary.scope_followup_pending 为 true，默认不应把系统判成 deliverable，也不应允许与该焦点无关的收尾动作。"
                    "判断依据是 acceptance_state、material_gaps、recent_tool_effects、tool capabilities 和 proposal。"
                    "review_context.active_tool_cooldowns 表示当前仍生效的工具冷却建议。"
                    "如果 proposal 不能明显推进 review_context.control_summary.primary_goal 或 next_focus，应优先判定为 block 或 redundant。"
                    "只允许输出 5 种决策语义：allow、block、redundant、deliverable、not_deliverable。"
                    "deliverable 表示当前已经可以交付，不应继续执行工具。"
                    "not_deliverable 表示当前还不能交付，但 reviewer 不替 investigator 规划完整路径；只允许给出 1 个显式 next_action 作为替代执行合同。"
                    "如果 material_gaps 中某项 status=reportable_unresolved，说明它应进入报告边界，不应继续为它放行工具。"
                    "如果仍有 candidate 事件未完成独立 grounding，不应把 search_related_events / expand_asset_scope 的结果直接视作可交付证据。"
                    "如果 proposal 选择了 active_tool_cooldowns 中仍在冷却的工具，而 proposal.override_reason 为空或明显不具体，应直接 block 或 redundant。"
                    "如果 decision=allow，next_action 通常应直接复述 proposal 中被批准的完整动作合同，至少保留 tool_name、params、target_gap_ids 和 override_reason。"
                    "如果 decision 是 block、redundant 或 not_deliverable，next_action 应明确指出唯一的替代动作，并给出足够执行该动作的 params。"
                    "如果继续调查，next_action.action_type 只能是 tool，且 tool_name 只能有 1 个。"
                    "如果 next_action.action_type=tool，next_action.params 必须是可直接执行的参数对象；不要只给工具名而不带必要参数。"
                    "如果已经可以交付，next_action.action_type 应为 finish。"
                    "如果你判断当前不该继续，但也没有明确替代动作，可输出 next_action.action_type=none。"
                    "如果某工具最近只产生整理型收益或没有 material delta，可以标记为 redundant。"
                    "不要根据具体 case 名、具体 IP、域名或题目答案做判断。"
                    "输出 JSON："
                    "{{\"decision\":\"allow|block|redundant|deliverable|not_deliverable\","
                    "\"deliverable_now\":true,"
                    "\"material_gaps\":[{{\"gap_id\":\"...\",\"reason\":\"...\",\"actionable_now\":true}}],"
                    "\"blocking_gaps\":[{{\"gap_id\":\"...\",\"reason\":\"...\"}}],"
                    "\"low_value_repeats\":[{{\"tool_name\":\"...\",\"reason\":\"...\"}}],"
                    "\"tool_cooldown_suggestions\":[{{\"tool_name\":\"...\",\"reason\":\"...\",\"related_gap_ids\":[\"...\"]}}],"
                    "\"next_focus\":{{\"gap_id\":\"...\",\"question\":\"...\",\"suggested_tool\":\"...\",\"reason\":\"...\"}},"
                    "\"next_action\":{{\"action_type\":\"tool|finish|none\",\"tool_name\":\"...\",\"params\":{{}},\"target_gap_ids\":[\"...\"],\"question\":\"...\",\"reason\":\"...\",\"override_reason\":\"...\"}},"
                    "\"blocked_tools\":[{{\"tool_name\":\"...\",\"reason\":\"...\"}}],"
                    "\"reason\":\"...\"}}。",
                ),
                (
                    "user",
                    "seed:\n{seed_json}\n\nreview_context:\n{context_json}\n\nproposal:\n{proposal_json}\n\ntool_catalog:\n{tool_catalog_json}",
                ),
            ]
        )
        response = llm.invoke(
            prompt.format_messages(
                seed_json=json.dumps(seed_event, ensure_ascii=False),
                context_json=json.dumps(review_context, ensure_ascii=False),
                proposal_json=json.dumps(proposal, ensure_ascii=False),
                tool_catalog_json=json.dumps(tool_catalog, ensure_ascii=False),
            )
        )
        content = str(getattr(response, "content", "") or "").strip()
        review["raw_response"] = content[:1200]
        parsed = _extract_selector_json(content)
        decision = str(parsed.get("decision") or "allow").strip().lower()
        if decision not in REVIEWER_DECISIONS:
            decision = "allow"
        canonical_gap_map = _merged_gap_map(
            list(finalized.get("gap_ledger") or []),
            list(incident_state.get("gap_ledger") or []),
            list(review.get("material_gaps") or []),
        )
        parsed_material_gaps: List[Dict[str, Any]] = []
        for item in list(parsed.get("material_gaps") or []):
            if not isinstance(item, dict):
                continue
            gap_id = str(item.get("gap_id") or item.get("id") or "").strip()
            base = dict(canonical_gap_map.get(gap_id) or {})
            if gap_id and "id" not in base:
                base["id"] = gap_id
            if gap_id and "gap_id" not in item:
                item = {**item, "gap_id": gap_id}
            base.update(item)
            parsed_material_gaps.append(base)
        if not parsed_material_gaps:
            parsed_material_gaps = list(review.get("material_gaps") or [])
        compat_allowed_tools = _text_list(parsed.get("allowed_tools"), limit=1)
        compat_allowed_tools = [tool_name for tool_name in compat_allowed_tools if tool_name in tool_names]
        parsed_next_action = _normalize_reviewer_next_action(
            parsed.get("next_action"),
            seed_event,
            session_state,
            incident_state,
            tool_catalog,
            canonical_gap_map,
            proposal=proposal,
            fallback_reason=str(parsed.get("reason") or "").strip(),
            default_action_type="finish" if decision == "deliverable" else "none",
        )
        if str(parsed_next_action.get("action_type") or "").strip() == "none" and compat_allowed_tools and decision != "deliverable":
            parsed_next_action = _normalize_reviewer_next_action(
                {
                    "action_type": "tool",
                    "tool_name": compat_allowed_tools[0],
                    "reason": str(parsed.get("reason") or "").strip(),
                },
                seed_event,
                session_state,
                incident_state,
                tool_catalog,
                canonical_gap_map,
                proposal=proposal,
                fallback_reason=str(parsed.get("reason") or "").strip(),
                default_action_type="tool",
            )
        review.update(
            {
                "decision": decision,
                "deliverable_now": bool(parsed.get("deliverable_now")) or decision == "deliverable",
                "material_gaps": parsed_material_gaps,
                "allowed_tools": compat_allowed_tools,
                "next_action": parsed_next_action,
                "blocked_tools": _normalize_blocked_tools(parsed.get("blocked_tools")),
                "blocking_gaps": _normalize_blocking_gap_rows(parsed.get("blocking_gaps"), canonical_gap_map),
                "low_value_repeats": _normalize_reviewer_rows(parsed.get("low_value_repeats")),
                "tool_cooldown_suggestions": _normalize_tool_cooldown_rows(parsed.get("tool_cooldown_suggestions"), canonical_gap_map),
                "next_focus": dict(parsed.get("next_focus") or {}),
                "reason": str(parsed.get("reason") or "").strip(),
                "outcome": decision,
            }
        )
    except Exception as exc:
        review["fallback_used"] = True
        review["fallback_reason"] = f"reviewer_error:{exc}"
    review = _apply_reviewer_control_metadata(
        seed_event,
        session_state,
        incident_state,
        finalized,
        tool_catalog,
        proposal,
        review,
    )
    return review


def _review_blocks_tool(review: Dict[str, Any], tool_name: str) -> bool:
    normalized = str(tool_name or "").strip()
    if not normalized:
        return False
    blocked_names = {
        str(item.get("tool_name") or "").strip()
        for item in list(review.get("blocked_tools") or [])
        if str(item.get("tool_name") or "").strip()
    }
    if normalized in blocked_names:
        return True
    allowed = [str(item or "").strip() for item in list(review.get("allowed_tools") or []) if str(item or "").strip()]
    return bool(allowed and normalized not in allowed)


def _reviewer_replacement_tool(
    review: Dict[str, Any],
    tool_catalog: List[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    next_action = dict(review.get("next_action") or {})
    if str(next_action.get("action_type") or "").strip() != "tool":
        return None
    tool_name = str(next_action.get("tool_name") or "").strip()
    available = {str(item.get("tool_name") or "").strip() for item in tool_catalog}
    if not tool_name or tool_name not in available:
        return None
    return _tool_action_contract(
        next_action,
        reason=str(next_action.get("reason") or review.get("reason") or "").strip(),
        override_reason=str(next_action.get("override_reason") or "").strip(),
        target_gap_ids=list(next_action.get("target_gap_ids") or []),
        question=str(next_action.get("question") or "").strip(),
    )


def _gap_priority_score(priority: str) -> int:
    return {"high": 30, "medium": 20, "low": 10}.get(str(priority or "").strip().lower(), 0)


def _rank_reviewer_tool(tool_entry: Dict[str, Any], material_gaps: List[Dict[str, Any]]) -> int:
    tool_name = str(tool_entry.get("tool_name") or "").strip()
    score = 0
    for gap in material_gaps:
        if not bool(gap.get("actionable_now")):
            continue
        if _tool_matches_gap(tool_name, gap):
            score += _tool_gap_match_score(tool_name, gap) * 6
            score += _gap_priority_score(str(gap.get("priority") or ""))
            if bool(gap.get("delivery_blocking")):
                score += 15
    if str(tool_entry.get("tool_mode") or "") in {"investigation", "intel"}:
        score += 8
    if bool(tool_entry.get("recent_materially_depleted")):
        score -= 25
    repeat_risk = str(tool_entry.get("repeat_risk") or "").strip().lower()
    if repeat_risk == "medium":
        score -= 8
    elif repeat_risk == "high":
        score -= 15
    score += int(tool_entry.get("recent_material_score") or 0)
    return score


def _fallback_reviewer_decision(
    seed_event: Dict[str, Any],
    session_state: Dict[str, Any],
    incident_state: Dict[str, Any],
    finalized: Dict[str, Any],
    tool_catalog: List[Dict[str, Any]],
    proposal: Dict[str, Any],
    review: Dict[str, Any],
) -> Dict[str, Any]:
    acceptance_state = _acceptance_state(seed_event, session_state, incident_state, finalized)
    ready_for_delivery = bool(acceptance_state.get("ready_for_delivery"))
    deliverable_now = bool(acceptance_state.get("deliverable_now"))
    material_gaps = list(review.get("material_gaps") or acceptance_state.get("material_gaps") or [])
    blocking_actionable_gaps = [
        gap
        for gap in list(review.get("blocking_gaps") or acceptance_state.get("blocking_actionable_gaps") or [])
        if bool(gap.get("delivery_blocking")) and bool(gap.get("actionable_now", True))
    ]
    blocking_gap_ids = {
        str(gap.get("id") or gap.get("gap_id") or "").strip()
        for gap in blocking_actionable_gaps
        if str(gap.get("id") or gap.get("gap_id") or "").strip()
    }
    next_focus = _build_reviewer_next_focus(tool_catalog, blocking_actionable_gaps)
    ranked_tools = sorted(tool_catalog, key=lambda item: _rank_reviewer_tool(item, material_gaps), reverse=True)
    best_tool_name = str(next_focus.get("suggested_tool") or "").strip()
    if not best_tool_name:
        best_tool_name = str(ranked_tools[0].get("tool_name") or "").strip() if ranked_tools else ""
    proposed_tool = str(proposal.get("tool_name") or "").strip()
    proposal_alignment = dict(proposal.get("alignment") or {})
    proposal_priority_tier = str(proposal_alignment.get("priority_tier") or "").strip()
    proposed_gap_ids = {
        str(item).strip()
        for item in list(proposal.get("target_gap_ids") or [])
        if str(item).strip()
    }
    proposed_targets_blocking_gap = bool(proposed_gap_ids & blocking_gap_ids) or bool(proposal_alignment.get("blocking_gap_ids"))
    proposal_reportable_only = bool(proposal_alignment.get("reportable_only"))

    blocked_tools: List[Dict[str, str]] = []
    for item in tool_catalog:
        tool_name = str(item.get("tool_name") or "").strip()
        if not tool_name:
            continue
        if bool(item.get("recent_materially_depleted")):
            blocked_tools.append(
                {
                    "tool_name": tool_name,
                    "reason": "最近两次调用都没有带来 material delta，当前不宜继续优先调用。",
                }
            )
        elif ready_for_delivery and blocking_actionable_gaps and not any(_tool_matches_gap(tool_name, gap) for gap in blocking_actionable_gaps):
            blocked_tools.append(
                {
                    "tool_name": tool_name,
                    "reason": "当前工具不能缩小剩余的 material gap。",
                }
            )
    blocked_tool_names = {
        str(item.get("tool_name") or "").strip()
        for item in blocked_tools
        if str(item.get("tool_name") or "").strip()
    }

    def _protocol_action(decision_name: str, fallback_reason: str, *, extra_excluded: Optional[set[str]] = None) -> Dict[str, Any]:
        excluded = set(blocked_tool_names)
        if extra_excluded:
            excluded.update(str(item or "").strip() for item in extra_excluded if str(item or "").strip())
        return _fallback_reviewer_next_action(
            seed_event=seed_event,
            session_state=session_state,
            incident_state=incident_state,
            decision=decision_name,
            tool_catalog=tool_catalog,
            proposal=proposal,
            blocking_gaps=blocking_actionable_gaps,
            next_focus=next_focus,
            fallback_reason=fallback_reason,
            preferred_tool_name=best_tool_name,
            preferred_gap_ids=list(proposal.get("target_gap_ids") or []),
            excluded_tools=excluded,
        )

    if deliverable_now:
        reason = "当前已满足交付条件，剩余问题不再能被现有工具实质缩小。"
        review.update(
            {
                "decision": "deliverable",
                "deliverable_now": True,
                "next_action": _protocol_action("deliverable", reason),
                "allowed_tools": [],
                "blocked_tools": blocked_tools,
                "blocking_gaps": [],
                "reason": reason,
                "outcome": "deliverable",
            }
        )
        return review

    if str(proposal.get("action_type") or "").strip() == "finish":
        if deliverable_now:
            reason = "investigator 建议 finish，且当前不存在仍可继续缩小的关键缺口。"
            review.update(
                {
                    "decision": "deliverable",
                    "deliverable_now": True,
                    "next_action": _protocol_action("deliverable", reason),
                    "allowed_tools": [],
                    "blocked_tools": blocked_tools,
                    "blocking_gaps": [],
                    "reason": reason,
                    "outcome": "deliverable",
                }
            )
            return review
        reason = "investigator 过早建议 finish，仍存在可由当前工具继续缩小的关键缺口。"
        next_action = _protocol_action("not_deliverable", reason)
        review.update(
            {
                "decision": "not_deliverable",
                "deliverable_now": False,
                "next_action": next_action,
                "allowed_tools": _reviewer_allowed_tools_from_next_action(next_action),
                "blocked_tools": blocked_tools,
                "blocking_gaps": blocking_actionable_gaps,
                "reason": reason,
                "outcome": "not_deliverable",
            }
        )
        return review

    if proposed_tool and proposal_reportable_only:
        decision_name = "deliverable" if deliverable_now else "redundant"
        reason = "当前提议只对应已转为报告边界或暂不可解的问题，不应继续优先执行。"
        next_action = _protocol_action(decision_name, reason)
        review.update(
            {
                "decision": decision_name,
                "deliverable_now": deliverable_now,
                "next_action": next_action,
                "allowed_tools": _reviewer_allowed_tools_from_next_action(next_action),
                "blocked_tools": blocked_tools,
                "blocking_gaps": [] if decision_name == "deliverable" else blocking_actionable_gaps,
                "reason": reason,
                "outcome": decision_name,
            }
        )
        return review

    if proposed_tool and blocking_actionable_gaps and proposal_priority_tier not in {"primary_focus", "blocking_gap"} and not proposed_targets_blocking_gap:
        reason = (
            str(proposal_alignment.get("reason") or "").strip()
            or "当前提议的工具没有直接缩小剩余关键缺口，建议改为更相关的工具。"
        )
        next_action = _protocol_action("block", reason, extra_excluded={proposed_tool})
        review.update(
            {
                "decision": "block",
                "deliverable_now": False,
                "next_action": next_action,
                "allowed_tools": _reviewer_allowed_tools_from_next_action(next_action),
                "blocked_tools": blocked_tools,
                "blocking_gaps": blocking_actionable_gaps,
                "reason": reason,
                "outcome": "block",
            }
        )
        return review

    if proposed_tool and any(item.get("tool_name") == proposed_tool for item in blocked_tools):
        if deliverable_now:
            reason = "当前提议工具已进入低收益状态，且剩余问题更适合作为报告未决事项。"
            review.update(
                {
                    "decision": "deliverable",
                    "deliverable_now": True,
                    "next_action": _protocol_action("deliverable", reason),
                    "allowed_tools": [],
                    "blocked_tools": blocked_tools,
                    "blocking_gaps": [],
                    "reason": reason,
                    "outcome": "deliverable",
                }
            )
            return review
        reason = "当前提议工具最近没有 material delta，建议切换到仍有希望缩小关键缺口的工具。"
        next_action = _protocol_action("redundant", reason, extra_excluded={proposed_tool})
        review.update(
            {
                "decision": "redundant",
                "deliverable_now": deliverable_now,
                "next_action": next_action,
                "allowed_tools": _reviewer_allowed_tools_from_next_action(next_action),
                "blocked_tools": blocked_tools,
                "blocking_gaps": blocking_actionable_gaps,
                "reason": reason,
                "outcome": "redundant",
            }
        )
        return review

    reason = str(proposal_alignment.get("reason") or "").strip() or "当前提议与剩余关键缺口一致，可以继续执行。"
    next_action = _protocol_action("allow", reason)
    review.update(
        {
            "decision": "allow",
            "deliverable_now": deliverable_now,
            "next_action": next_action,
            "allowed_tools": _reviewer_allowed_tools_from_next_action(next_action),
            "blocked_tools": blocked_tools,
            "blocking_gaps": blocking_actionable_gaps,
            "reason": reason,
            "outcome": "allow",
        }
    )
    return review


def _enforce_active_cooldown_gate(
    seed_event: Dict[str, Any],
    session_state: Dict[str, Any],
    incident_state: Dict[str, Any],
    finalized: Dict[str, Any],
    tool_catalog: List[Dict[str, Any]],
    proposal: Dict[str, Any],
    review: Dict[str, Any],
    active_cooldowns: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    if str(review.get("decision") or "").strip() == "deliverable":
        return review
    if bool(review.get("cooldown_override_missing")) and str(review.get("decision") or "").strip() == "block":
        return review
    cooldown_rows = (
        list(active_cooldowns)
        if active_cooldowns is not None
        else _active_tool_cooldowns(session_state, incident_state, finalized)
    )
    violation = _proposal_cooldown_violation(
        proposal,
        cooldown_rows,
    )
    if not violation:
        return review
    blocked_tools = _normalize_blocked_tools(review.get("blocked_tools"))
    blocked_tools.append(
        {
            "tool_name": str(violation.get("tool_name") or "").strip(),
            "reason": _cooldown_reason_text(str(violation.get("reason") or "").strip()),
        }
    )
    review.update(
        {
            "decision": "block",
            "deliverable_now": False,
            "next_action": {},
            "allowed_tools": [],
            "blocked_tools": blocked_tools,
            "reason": f"{_cooldown_reason_text(str(violation.get('reason') or '').strip())} 当前若要继续调用该工具，investigator 必须给出明确的 override_reason。",
            "outcome": "block",
            "cooldown_override_required": True,
            "cooldown_override_missing": True,
        }
    )
    return _apply_reviewer_control_metadata(
        seed_event,
        session_state,
        incident_state,
        finalized,
        tool_catalog,
        proposal,
        review,
    )


def _observation_base(tool_name: str, payload: Dict[str, Any], source_type: str, observation_id: str) -> Dict[str, Any]:
    return {
        "observation_id": observation_id,
        "tool_name": tool_name,
        "query": payload,
        "source_type": source_type,
        "source_ref": "",
        "events": [],
        "checked_event_ids": [],
        "relation_event_ids": [],
        "boundary_event_ids": [],
        "derived_entities": {"asset_ids": [], "src_ips": [], "dst_ips": [], "domains": [], "fingerprints": [], "families": []},
        "claims": [],
        "confidence": 20,
        "supports_hypothesis": [],
        "contradicts_hypothesis": [],
        "relation": "context",
        "summary": "",
        "note": "",
        "page_candidates": [],
        "documents": [],
        "status": "ok",
        "grounding_status": "",
    }


def _event_ids(events: List[Dict[str, Any]]) -> List[str]:
    return unique_preserve_order(str(item.get("id") or "").strip() for item in list(events or []) if str(item.get("id") or "").strip())


def _normalize_event_batch(tool_name: str, payload: Dict[str, Any], batch_payload: Dict[str, Any], observation_id: str) -> Dict[str, Any]:
    events = list(batch_payload.get("events") or [])
    suspicious_events = [
        item
        for item in events
        if str(item.get("classification") or "").strip().lower() in {"malicious", "suspicious", "needs_review"}
        or infer_stages(item)
    ]
    benign_events = [item for item in events if str(item.get("classification") or "").strip().lower() == "benign"]
    unknown_events = [item for item in events if item not in suspicious_events and item not in benign_events]
    derived_entities = dict(batch_payload.get("derived_entities") or {})
    observation = _observation_base(tool_name, payload, str(batch_payload.get("source_type") or "trace_store"), observation_id)
    observation["events"] = events
    observation["checked_event_ids"] = _event_ids(events)
    observation["derived_entities"] = {
        **observation["derived_entities"],
        **derived_entities,
    }
    observation["confidence"] = min(
        90,
        25 + len(suspicious_events) * 12 + len(benign_events) * 6 + len(unique_preserve_order(derived_entities.get("asset_ids") or [])) * 4,
    )
    if suspicious_events:
        domains = unique_preserve_order(item.get("domain") for item in suspicious_events)
        dst_ips = unique_preserve_order(item.get("dst_ip") for item in suspicious_events)
        indicator_text = "、".join((domains + dst_ips)[:3]) or "当前 pivot"
        if tool_name in {"search_related_events", "expand_asset_scope"}:
            summary = f"扩线检索到 {len(suspicious_events)} 条可疑关联事件，围绕 {indicator_text} 展开；当前先作为待验证候选线索。"
            observation["relation"] = "candidate"
            observation["relation_event_ids"] = _event_ids(suspicious_events)
            observation["supports_hypothesis"] = ["secondary"]
            claim_kind = "candidate_event_batch"
        else:
            summary = f"检索到 {len(suspicious_events)} 条偏可疑事件，围绕 {indicator_text} 展开。"
            observation["relation"] = "supporting"
            observation["relation_event_ids"] = _event_ids(suspicious_events)
            observation["supports_hypothesis"] = ["primary"]
            claim_kind = "event_batch"
        observation["claims"] = [
            {
                "text": summary,
                "kind": claim_kind,
                "score": observation["confidence"],
            }
        ]
        if unknown_events and len(unique_preserve_order(item.get("asset_id") for item in unknown_events)) > 1:
            observation["supports_hypothesis"].append("secondary")
    elif benign_events:
        summary = f"检索到 {len(benign_events)} 条更接近维护、更新或正常基线的事件。"
        observation["relation"] = "counterevidence"
        observation["relation_event_ids"] = _event_ids(benign_events)
        observation["supports_hypothesis"] = ["benign"]
        observation["contradicts_hypothesis"] = ["primary"]
        observation["claims"] = [
            {
                "text": summary,
                "kind": "event_batch",
                "score": observation["confidence"],
            }
        ]
    else:
        assets = unique_preserve_order(item.get("asset_id") for item in unknown_events)
        summary = f"检索到 {len(events)} 条上下文事件，当前主要用于扩边界和补足范围。"
        observation["relation"] = "context"
        observation["relation_event_ids"] = _event_ids(unknown_events)
        if len(assets) > 1:
            observation["supports_hypothesis"] = ["secondary"]
        observation["claims"] = [{"text": summary, "kind": "context", "score": observation["confidence"]}]
    observation["summary"] = summary
    observation["note"] = str(batch_payload.get("note") or "")
    return observation


def _grounding_hit_claim(source_name: str, indicator: Dict[str, str], rows: List[Dict[str, Any]]) -> str:
    top = dict(rows[0] if rows else {})
    snippet = str(top.get("snippet") or top.get("title") or "").strip()
    if len(snippet) > 200:
        snippet = snippet[:197] + "..."
    indicator_type = str(indicator.get("indicator_type") or "").strip()
    indicator_value = str(indicator.get("indicator_value") or "").strip()
    if snippet:
        return f"{source_name} 命中 {indicator_type} `{indicator_value}`：{snippet}"
    return f"{source_name} 命中 {indicator_type} `{indicator_value}`。"


def _result_source_names(rows: List[Dict[str, Any]]) -> List[str]:
    return unique_preserve_order(str(item.get("source") or "").strip() for item in rows if str(item.get("source") or "").strip())


def _ground_candidate_event_observation(
    seed_event: Dict[str, Any],
    payload: Dict[str, Any],
    incident_state: Dict[str, Any],
    observation_id: str,
) -> Dict[str, Any]:
    event_id = str(payload.get("event_id") or "").strip()
    max_indicators = max(1, min(int(payload.get("max_indicators") or 4), 6))
    candidate_map = {
        str(item.get("id") or "").strip(): dict(item)
        for item in _candidate_events(seed_event, incident_state)
        if str(item.get("id") or "").strip()
    }
    event = dict(candidate_map.get(event_id) or {})
    observation = _observation_base(GROUND_CANDIDATE_TOOL_NAME, payload, "candidate_grounding", observation_id)
    observation["source_ref"] = f"candidate_event:{event_id}" if event_id else ""

    if not event:
        observation["status"] = "error"
        observation["summary"] = f"候选事件 {event_id or 'unknown'} 当前不可用于 grounding。"
        return observation

    indicators = _event_indicator_candidates(event)[:max_indicators]
    observation["checked_event_ids"] = _event_ids([event])
    if not indicators:
        observation["events"] = [event]
        observation["relation"] = "context"
        observation["relation_event_ids"] = _event_ids([event])
        observation["boundary_event_ids"] = _event_ids([event])
        observation["grounding_status"] = GROUNDING_STATUS_CONTEXT_ONLY
        observation["confidence"] = 28
        observation["summary"] = f"候选事件 {event_id} 缺少可独立验证的指示物，当前不并入主证据链，仅保留为边界线索。"
        observation["claims"] = [
            {
                "text": observation["summary"],
                "kind": "candidate_grounding",
                "score": observation["confidence"],
            }
        ]
        return observation

    allow_live_intel = str(os.getenv("INCIDENT_AGENT_LIVE_INTEL") or "").strip().lower() in {"1", "true", "yes"}
    supported_live_types = {"IP", "DOMAIN", "URL", "MD5", "SHA256"}
    hit_claims: List[str] = []
    families: List[str] = []
    checked_sources: List[str] = []

    for indicator in indicators:
        local_raw = _tool_json(
            local_intel_lookup,
            {
                "indicator_value": indicator.get("indicator_value"),
                "indicator_type": indicator.get("indicator_type"),
            },
        )
        local_rows = [dict(item) for item in list(local_raw.get("results") or []) if isinstance(item, dict)]
        if bool(local_raw.get("enabled")):
            checked_sources.append("local_intel")
        if local_rows:
            local_label = "本地情报库"
            local_sources = _result_source_names(local_rows)
            if local_sources:
                local_label = f"本地情报库（{' / '.join(local_sources[:2])}）"
            hit_claims.append(_grounding_hit_claim(local_label, indicator, local_rows))
            families.extend(str(item.get("family") or "").strip() for item in local_rows if str(item.get("family") or "").strip())

        if allow_live_intel and str(indicator.get("indicator_type") or "").strip().upper() in supported_live_types:
            abuse_raw = _tool_json(
                abuse_ch_lookup,
                {
                    "indicator_value": indicator.get("indicator_value"),
                    "indicator_type": indicator.get("indicator_type"),
                    "max_results": 4,
                },
            )
            abuse_rows = [dict(item) for item in list(abuse_raw.get("results") or []) if isinstance(item, dict)]
            checked_sources.append("abuse_ch")
            if int(abuse_raw.get("structured_hits") or 0) > 0 and abuse_rows:
                hit_claims.append(_grounding_hit_claim("abuse.ch", indicator, abuse_rows))
                families.extend(str(item.get("family") or "").strip() for item in abuse_rows if str(item.get("family") or "").strip())

    if not checked_sources:
        observation["status"] = "empty"
        observation["summary"] = f"候选事件 {event_id} 当前没有可用的本地或外部情报源可供 grounding。"
        return observation

    observation["events"] = [event]
    observation["derived_entities"] = {
        **observation["derived_entities"],
        "asset_ids": unique_preserve_order([event.get("asset_id")]),
        "src_ips": unique_preserve_order([event.get("src_ip")]),
        "dst_ips": unique_preserve_order([event.get("dst_ip")]),
        "domains": unique_preserve_order([event.get("domain")]),
        "fingerprints": unique_preserve_order(
            [event.get("ja4"), event.get("ja3"), event.get("ssl_sha1"), event.get("cert_sha1")]
        ),
        "families": unique_preserve_order(families),
    }
    checked_text = "、".join(unique_preserve_order(checked_sources))

    if hit_claims:
        observation["relation"] = "supporting"
        observation["relation_event_ids"] = _event_ids([event])
        observation["grounding_status"] = GROUNDING_STATUS_CONFIRMED
        observation["supports_hypothesis"] = ["primary"]
        observation["confidence"] = min(88, 58 + len(hit_claims) * 7)
        observation["summary"] = f"候选事件 {event_id} 已通过 {checked_text} 获得独立支撑，可升级为主证据链的一部分。"
        observation["claims"] = [
            {
                "text": claim,
                "kind": "candidate_grounding",
                "score": observation["confidence"],
            }
            for claim in hit_claims[:4]
        ]
        return observation

    observation["relation"] = "context"
    observation["relation_event_ids"] = _event_ids([event])
    observation["boundary_event_ids"] = _event_ids([event])
    observation["grounding_status"] = GROUNDING_STATUS_GROUNDED
    observation["confidence"] = 34
    observation["summary"] = f"候选事件 {event_id} 已完成 {checked_text} grounding，但暂未命中独立情报，当前不直接并入主证据链。"
    observation["claims"] = [
        {
            "text": observation["summary"],
            "kind": "candidate_grounding",
            "score": observation["confidence"],
        }
    ]
    return observation


def _normalize_intel_observation(tool_name: str, payload: Dict[str, Any], raw: Dict[str, Any], observation_id: str) -> Dict[str, Any]:
    observation = _observation_base(tool_name, payload, "intel_tool", observation_id)
    results = list(raw.get("results") or [])
    observation["page_candidates"] = [
        {"url": item.get("url"), "title": item.get("title"), "source": urlparse(str(item.get("url") or "")).netloc}
        for item in results[:3]
        if item.get("url")
    ]
    if tool_name in {"technical_source_search", "malware_profile_lookup", "pivot_related_indicators"}:
        observation["derived_entities"]["domains"] = unique_preserve_order(
            urlparse(str(item.get("url") or "")).netloc for item in results if item.get("url")
        )
        if results:
            top_titles = unique_preserve_order(item.get("title") for item in results)[:3]
            observation["relation"] = "context"
            observation["supports_hypothesis"] = ["primary"]
            observation["confidence"] = 48
            observation["summary"] = f"{tool_name} 返回了 {len(results)} 条候选技术来源，可用于后续正文证据提取。"
            observation["claims"] = [
                {
                    "text": f"候选技术来源包括：{'；'.join(title for title in top_titles if title)}",
                    "kind": "search_results",
                    "score": 48,
                }
            ]
        else:
            observation["status"] = "empty"
            observation["confidence"] = 18
            observation["summary"] = f"{tool_name} 没有返回可直接利用的技术结果。"
        return observation

    if tool_name == "abuse_ch_lookup" and int(raw.get("structured_hits") or 0) <= 0:
        if results:
            top_titles = unique_preserve_order(item.get("title") for item in results)[:3]
            observation["relation"] = "context"
            observation["supports_hypothesis"] = ["primary"]
            observation["confidence"] = 42
            observation["summary"] = "abuse.ch 聚合查询当前只返回了候选来源，还没有结构化命中。"
            observation["claims"] = [
                {
                    "text": f"候选来源包括：{'；'.join(title for title in top_titles if title)}",
                    "kind": "search_results",
                    "score": 42,
                }
            ]
        else:
            observation["status"] = "empty"
            observation["confidence"] = 18
            observation["summary"] = "abuse.ch 聚合查询未命中结构化情报。"
        return observation

    families = unique_preserve_order(
        item.get("family")
        for item in results
        if str(item.get("family") or "").strip()
    )
    source_names = _result_source_names(results)
    source_hint = f"（{' / '.join(source_names[:2])}）" if source_names else ""
    observation["derived_entities"]["families"] = families
    observation["derived_entities"]["dst_ips"] = unique_preserve_order(
        (item.get("ioc") or item.get("indicator_value"))
        for item in results
        if _extract_indicator_type(str(item.get("ioc") or item.get("indicator_value") or "")) == "IP"
    )
    observation["derived_entities"]["domains"] = unique_preserve_order(
        (item.get("ioc") or item.get("indicator_value"))
        for item in results
        if _extract_indicator_type(str(item.get("ioc") or item.get("indicator_value") or "")) == "DOMAIN"
    )
    if results:
        top = results[0]
        label = str(top.get("malware") or top.get("family") or top.get("threat_type") or "").strip()
        claim = str(top.get("snippet") or top.get("title") or "").strip()
        observation["relation"] = "supporting"
        observation["supports_hypothesis"] = ["primary"]
        observation["confidence"] = 62
        if tool_name == "local_intel_lookup":
            observation["summary"] = f"本地情报库{source_hint}返回了结构化命中，可用于支撑指纹或 IOC 解释。"
        elif tool_name == "vt_enrich_ioc":
            observation["summary"] = f"VirusTotal{source_hint}返回了正向 reputation 信号，可用于支撑外部基础设施解释。"
        elif tool_name == "abuse_ch_lookup":
            observation["summary"] = f"abuse.ch 聚合查询{source_hint}返回了结构化命中，可用于支撑外部基础设施解释。"
        else:
            observation["summary"] = f"{tool_name}{source_hint} 返回了结构化情报结果，可用于支撑外部基础设施解释。"
        observation["claims"] = [
            {
                "text": f"{label or '结构化情报'}：{claim}",
                "kind": "structured_intel",
                "score": 62,
            }
        ]
    else:
        observation["status"] = "empty"
        observation["confidence"] = 18
        if tool_name == "local_intel_lookup":
            observation["summary"] = "本地情报库未命中该指示物。"
        elif tool_name == "vt_enrich_ioc":
            observation["summary"] = "VirusTotal 已查询该外部 IP，但未返回正向恶意检测。"
        else:
            observation["summary"] = f"{tool_name} 未命中结构化情报。"
    return observation


def _normalize_counterevidence_observation(
    payload: Dict[str, Any],
    batch_payload: Dict[str, Any],
    observation_id: str,
) -> Dict[str, Any]:
    events = list(batch_payload.get("events") or [])
    benign_events = [item for item in events if str(item.get("classification") or "").strip().lower() == "benign"]
    suspicious_events = [
        item
        for item in events
        if str(item.get("classification") or "").strip().lower() in {"malicious", "suspicious", "needs_review"} or infer_stages(item)
    ]
    observation = _observation_base(COUNTEREVIDENCE_TOOL_NAME, payload, str(batch_payload.get("source_type") or "trace_store"), observation_id)
    observation["events"] = events
    observation["checked_event_ids"] = _event_ids(events)
    observation["derived_entities"] = {
        **observation["derived_entities"],
        **dict(batch_payload.get("derived_entities") or {}),
    }
    observation["confidence"] = min(78, 28 + len(events) * 4 + len(benign_events) * 8)
    if benign_events:
        observation["relation"] = "counterevidence"
        observation["relation_event_ids"] = _event_ids(benign_events)
        observation["supports_hypothesis"] = ["benign"]
        observation["contradicts_hypothesis"] = ["primary"]
        observation["summary"] = f"显式反证检查发现 {len(benign_events)} 条更接近维护、更新、补丁或备份背景的事件。"
        observation["claims"] = [
            {
                "text": observation["summary"],
                "kind": "counterevidence_check",
                "score": observation["confidence"],
            }
        ]
    elif suspicious_events:
        observation["relation"] = "context"
        observation["relation_event_ids"] = []
        observation["summary"] = f"显式反证检查覆盖了 {len(events)} 条同资产上下文，未发现足以降级当前判断的明确背景解释。"
        observation["claims"] = [
            {
                "text": observation["summary"],
                "kind": "counterevidence_check",
                "score": observation["confidence"],
            }
        ]
    else:
        observation["relation"] = "context"
        observation["relation_event_ids"] = []
        observation["confidence"] = 24
        observation["summary"] = "已执行显式反证检查，但未发现足以解释当前异常的明确背景事件。"
        observation["claims"] = [
            {
                "text": observation["summary"],
                "kind": "counterevidence_check",
                "score": observation["confidence"],
            }
        ]
    observation["note"] = str(batch_payload.get("note") or "")
    return observation


def _normalize_page_observation(
    tool_name: str,
    payload: Dict[str, Any],
    meta: Dict[str, Any],
    raw: Dict[str, Any],
    observation_id: str,
) -> Dict[str, Any]:
    default_origin = "page_content" if tool_name == "fetch_page_content" else "internal_digest"
    content_origin = str(meta.get("content_origin") or default_origin).strip() or default_origin
    source_type = "page_content" if content_origin == "page_content" else "internal_digest"
    observation = _observation_base(tool_name, payload, source_type, observation_id)
    observation["source_ref"] = str(meta.get("source_url") or payload.get("url") or "").strip()
    if tool_name == "fetch_page_content":
        content = str(raw.get("content") or "")
        entities_hint = dict(raw.get("entities_hint") or {})
        observation["derived_entities"] = {
            **observation["derived_entities"],
            "domains": unique_preserve_order(entities_hint.get("domains") or []),
            "dst_ips": unique_preserve_order(entities_hint.get("ips") or []),
            "families": [],
        }
        if content:
            observation["confidence"] = 42
            observation["summary"] = "成功读取技术页面正文，可继续抽取 claim 和实体。"
            observation["note"] = content[:500]
            observation["relation"] = "context"
            observation["source_ref"] = str(payload.get("url") or "").strip()
            observation["documents"] = [
                {
                    "url": str(payload.get("url") or "").strip(),
                    "content": content,
                    "content_origin": "page_content",
                }
            ]
        else:
            observation["status"] = "empty"
            observation["summary"] = "未读取到可用页面正文。"
        return observation

    if tool_name == "extract_claim_candidates_from_page":
        claims = list(raw.get("claims") or [])
        entities = dict(raw.get("entities") or {})
        observation["derived_entities"] = {
            **observation["derived_entities"],
            "domains": unique_preserve_order(entities.get("domains") or []),
            "dst_ips": unique_preserve_order(entities.get("ips") or []),
            "families": unique_preserve_order([str(payload.get("focus") or "").strip()]) if str(payload.get("focus") or "").strip() else [],
        }
        observation["claims"] = claims[:5]
        if claims:
            primary_claims = [
                item
                for item in claims
                if str(item.get("kind") or "") in {"family_or_indicator", "ttp", "ioc"}
            ]
            observation["confidence"] = min(70, 35 + len(primary_claims) * 7 + len(claims) * 2)
            if content_origin == "page_content":
                observation["summary"] = f"从外部页面正文中抽取出 {len(claims)} 条可直接引用的 claim。"
            else:
                observation["summary"] = f"从内部调查摘要中整理出 {len(claims)} 条 claim，用于结构化报告而不是新增外部证据。"
            if primary_claims and content_origin == "page_content":
                observation["relation"] = "supporting"
                observation["supports_hypothesis"] = ["primary"]
            else:
                observation["relation"] = "context"
        else:
            observation["status"] = "empty"
            if content_origin == "page_content":
                observation["summary"] = "当前页面正文中没有抽取出高价值 claim。"
            else:
                observation["summary"] = "当前内部摘要中没有整理出高价值 claim。"
        return observation

    if tool_name == "extract_entities_from_page":
        entities = dict(raw.get("entities") or {})
        observation["derived_entities"] = {
            **observation["derived_entities"],
            "domains": unique_preserve_order(entities.get("domains") or []),
            "dst_ips": unique_preserve_order(entities.get("ips") or []),
            "families": [],
        }
        observation["confidence"] = 36 if any(observation["derived_entities"].values()) else 16
        if content_origin == "page_content":
            observation["summary"] = "从外部页面正文中抽取了可供扩查的实体集合。"
        else:
            observation["summary"] = "从内部调查摘要中整理了可供扩查的实体集合。"
        observation["relation"] = "context"
        return observation

    observation["status"] = "empty"
    observation["summary"] = f"{tool_name} 返回了未识别的页面工具结果。"
    return observation


def _execute_action(
    seed_event: Dict[str, Any],
    action: Dict[str, Any],
    store: TraceStore,
    incident_state: Dict[str, Any],
    observation_id: str,
) -> Dict[str, Any]:
    tool_name = str(action.get("tool_name") or "")
    payload = dict(action.get("params") or {})
    meta = dict(action.get("meta") or {})
    if tool_name == "search_seed_context":
        batch = store.build_seed_context(seed_event)
        return _normalize_event_batch(tool_name, payload, batch.to_payload(), observation_id)
    if tool_name == "search_related_events":
        batch = store.query_related_events(
            payload.get("pivots") or {},
            window_minutes=int(payload.get("window_minutes") or 120),
            limit=int(payload.get("limit") or 60),
        )
        return _normalize_event_batch(tool_name, payload, batch.to_payload(), observation_id)
    if tool_name == GROUND_CANDIDATE_TOOL_NAME:
        return _ground_candidate_event_observation(seed_event, payload, incident_state, observation_id)
    if tool_name == "expand_asset_scope":
        batch = store.get_asset_context(
            list(payload.get("asset_ids") or []),
            window_minutes=int(payload.get("window_minutes") or 120),
            limit=int(payload.get("limit") or 60),
        )
        return _normalize_event_batch(tool_name, payload, batch.to_payload(), observation_id)
    if tool_name == COUNTEREVIDENCE_TOOL_NAME:
        batch = store.get_asset_context(
            list(payload.get("asset_ids") or []),
            window_minutes=int(payload.get("window_minutes") or 240),
            limit=int(payload.get("limit") or 80),
        )
        return _normalize_counterevidence_observation(payload, batch.to_payload(), observation_id)

    if tool_name == "local_intel_lookup":
        return _normalize_intel_observation(tool_name, payload, _tool_json(local_intel_lookup, payload), observation_id)
    if tool_name == "vt_enrich_ioc":
        return _normalize_intel_observation(tool_name, payload, _tool_json(vt_enrich_ioc, payload), observation_id)
    if tool_name == "abuse_ch_lookup":
        return _normalize_intel_observation(tool_name, payload, _tool_json(abuse_ch_lookup, payload), observation_id)
    if tool_name == "technical_source_search":
        return _normalize_intel_observation(tool_name, payload, _tool_json(technical_source_search, payload), observation_id)
    if tool_name == "malware_profile_lookup":
        return _normalize_intel_observation(tool_name, payload, _tool_json(malware_profile_lookup, payload), observation_id)
    if tool_name == "pivot_related_indicators":
        return _normalize_intel_observation(tool_name, payload, _tool_json(pivot_related_indicators, payload), observation_id)
    if tool_name == "threatfox_ioc_lookup":
        return _normalize_intel_observation(tool_name, payload, _tool_json(threatfox_ioc_lookup, payload), observation_id)
    if tool_name == "urlhaus_ioc_lookup":
        return _normalize_intel_observation(tool_name, payload, _tool_json(urlhaus_ioc_lookup, payload), observation_id)
    if tool_name == "fetch_page_content":
        return _normalize_page_observation(tool_name, payload, meta, _tool_json(fetch_page_content, payload), observation_id)
    if tool_name == "extract_claim_candidates_from_page":
        page_payload = {
            "content": payload.get("content") or "",
            "focus": payload.get("focus") or "",
        }
        return _normalize_page_observation(
            tool_name,
            payload,
            meta,
            _tool_json(extract_claim_candidates_from_page, page_payload),
            observation_id,
        )
    if tool_name == "extract_entities_from_page":
        page_payload = {
            "content": payload.get("content") or "",
        }
        return _normalize_page_observation(
            tool_name,
            payload,
            meta,
            _tool_json(extract_entities_from_page, page_payload),
            observation_id,
        )

    observation = _observation_base(tool_name, payload, "unknown", observation_id)
    observation["status"] = "error"
    observation["summary"] = f"未知工具：{tool_name}"
    return observation


def _update_budgets(session_state: Dict[str, Any], tool_name: str) -> None:
    budgets = session_state.get("budgets") or {}
    budgets["remaining_steps"] = max(0, int(budgets.get("remaining_steps") or 0) - 1)
    budgets["remaining_tool_calls"] = max(0, int(budgets.get("remaining_tool_calls") or 0) - 1)
    if tool_name in EVENT_TOOL_NAMES:
        budgets["remaining_event_queries"] = max(0, int(budgets.get("remaining_event_queries") or 0) - 1)
    elif tool_name in INTEL_TOOL_NAMES or tool_name in PAGE_TOOL_NAMES:
        budgets["remaining_intel_queries"] = max(0, int(budgets.get("remaining_intel_queries") or 0) - 1)


def _merge_entities_from_observation(base: Dict[str, Any], observation: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(base)
    derived = observation.get("derived_entities") or {}
    derived_ips = unique_preserve_order(derived.get("dst_ips") or [])
    internal_ips = [ip for ip in derived_ips if _is_internal_ip(ip)]
    external_ips = [ip for ip in derived_ips if ip and not _is_internal_ip(ip)]
    for key in ("assets", "domains", "external_ips", "internal_ips", "families"):
        merged.setdefault(key, [])
    merged["assets"] = unique_preserve_order(
        list(merged.get("assets") or [])
        + list(derived.get("asset_ids") or [])
    )
    merged["internal_ips"] = unique_preserve_order(
        list(merged.get("internal_ips") or [])
        + list(derived.get("src_ips") or [])
        + internal_ips
    )
    merged["external_ips"] = unique_preserve_order(
        list(merged.get("external_ips") or [])
        + external_ips
    )
    merged["domains"] = unique_preserve_order(
        list(merged.get("domains") or [])
        + list(derived.get("domains") or [])
    )
    merged["families"] = unique_preserve_order(
        list(merged.get("families") or [])
        + list(derived.get("families") or [])
    )
    return merged


def _update_pivots_from_events(pivots: Dict[str, Any], events: List[Dict[str, Any]], observation: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(pivots)
    merged["asset_ids"] = unique_preserve_order(list(merged.get("asset_ids") or []) + [item.get("asset_id") for item in events])
    merged["src_ips"] = unique_preserve_order(list(merged.get("src_ips") or []) + [item.get("src_ip") for item in events])
    merged["dst_ips"] = unique_preserve_order(list(merged.get("dst_ips") or []) + [item.get("dst_ip") for item in events] + list((observation.get("derived_entities") or {}).get("dst_ips") or []))
    merged["domains"] = unique_preserve_order(list(merged.get("domains") or []) + [item.get("domain") for item in events] + list((observation.get("derived_entities") or {}).get("domains") or []))
    merged["fingerprints"] = unique_preserve_order(
        list(merged.get("fingerprints") or [])
        + [item.get("ja4") for item in events]
        + [item.get("ja3") for item in events]
        + [item.get("ssl_sha1") for item in events]
        + [item.get("cert_sha1") for item in events]
        + list((observation.get("derived_entities") or {}).get("fingerprints") or [])
    )
    return merged


def _scores_from_events(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    suspicious_events = []
    benign_events = []
    unknown_events = []
    candidate_events = []
    primary_score = 0
    benign_score = 0
    repeated_indicators = set()
    stage_labels = set()
    for event in events:
        role = str(event.get("role") or "").strip()
        if role == "candidate":
            candidate_events.append(event)
            continue
        score = suspicion_score(event)
        stages = infer_stages(event)
        if role == "counterevidence":
            benign_events.append(event)
            benign_score += max(abs(score), 1)
            continue
        if role not in {"seed", "supporting"}:
            unknown_events.append(event)
            continue

        stage_labels.update(stages)
        if score > 0 or stages:
            suspicious_events.append(event)
            primary_score += max(score, 1) + len(stages)
            if event.get("dst_ip"):
                repeated_indicators.add(str(event.get("dst_ip")))
            if event.get("domain"):
                repeated_indicators.add(str(event.get("domain")))
        elif score < 0:
            benign_events.append(event)
            benign_score += abs(score)
        else:
            unknown_events.append(event)
    return {
        "suspicious_events": suspicious_events,
        "benign_events": benign_events,
        "unknown_events": unknown_events,
        "candidate_events": candidate_events,
        "primary_score": primary_score,
        "benign_score": benign_score,
        "stage_labels": unique_preserve_order(stage_labels),
        "execution_seen": "execution" in stage_labels,
        "lateral_seen": "lateral-movement" in stage_labels,
        "exfil_seen": "exfiltration" in stage_labels,
        "repeated_indicator_count": len(repeated_indicators),
    }


def _build_provisional_verdict(
    seed_event: Dict[str, Any],
    annotated_events: List[Dict[str, Any]],
    evidence_ledger: List[Dict[str, Any]],
    entities: Dict[str, Any],
) -> Dict[str, Any]:
    event_scores = _scores_from_events(annotated_events)
    primary_score = int(event_scores["primary_score"])
    benign_score = int(event_scores["benign_score"])
    execution_seen = bool(event_scores["execution_seen"])
    lateral_seen = bool(event_scores["lateral_seen"])
    exfil_seen = bool(event_scores["exfil_seen"])
    suspected_assets = list(entities.get("suspected_assets") or [])
    related_assets = list(entities.get("related_assets") or [])
    supporting_obs = [item for item in evidence_ledger if item.get("relation") == "supporting"]
    benign_obs = [item for item in evidence_ledger if item.get("relation") == "counterevidence"]
    alternative_obs = [item for item in evidence_ledger if item.get("relation") == "alternative"]
    family_hint = _meaningful_family_hint(seed_event)
    high_risk_progression = execution_seen or lateral_seen or exfil_seen
    strong_single_asset_progression = bool(
        high_risk_progression
        and primary_score >= 6
        and len(supporting_obs) >= 2
        and benign_score < primary_score + 3
        and (
            list(entities.get("external_ips") or [])
            or list(entities.get("domains") or [])
        )
    )

    if benign_score >= primary_score + 4 and primary_score <= 4:
        status = "monitor_only"
        confidence = min(55, 28 + benign_score * 4 + len(benign_obs) * 2)
        reasons = ["当前证据更容易被维护窗口、补丁、备份或共享基线解释。"]
    elif primary_score >= 10 and (high_risk_progression or len(suspected_assets) > 1):
        status = "confirmed_incident"
        confidence = min(94, 64 + primary_score * 2 + len(suspected_assets) * 5 + (8 if execution_seen else 0))
        reasons = ["事件簇已经从单点异常推进到高风险阶段或保守收敛后的多资产范围，足以支撑事件成立。"]
    elif strong_single_asset_progression:
        status = "confirmed_incident"
        confidence = min(
            90,
            60 + primary_score * 2 + len(supporting_obs) * 3 + (6 if execution_seen else 0) + (4 if lateral_seen or exfil_seen else 0),
        )
        reasons = ["虽然当前主要集中在单个重点资产，但已经看到主机执行或后续阶段进展，足以把单点异常提升为确认事件。"]
    elif primary_score >= 6:
        status = "needs_review"
        confidence = min(76, 52 + primary_score * 2 + len(alternative_obs) * 2)
        reasons = ["当前已形成可疑事件簇，但关键阶段或影响范围仍需人工复核。"]
    elif benign_score >= max(3, primary_score + 2):
        status = "monitor_only"
        confidence = min(52, 30 + benign_score * 3)
        reasons = ["现有事件更偏向正常背景，自动化倾向降级观察。"]
    else:
        status = "needs_review"
        confidence = 48 + len(supporting_obs) * 3
        reasons = ["当前只有有限正向证据，仍需继续围绕关键资产和指示物复核。"]

    if family_hint and status != "monitor_only":
        reasons.append(f"seed alert 自带家族/工具提示：{family_hint}。")
    if related_assets and status != "monitor_only":
        reasons.append("已观察到关联资产或共享基础设施上的扩展信号，但尚需继续确认是否属于同一事件。")
    if benign_obs and status == "needs_review":
        reasons.append("同时也存在可解释为背景活动的信号，因此暂未自动推进为确认事件。")

    return {
        "status": status,
        "status_label": _status_label(status),
        "confidence": int(confidence),
        "severity": severity_from_confidence(int(confidence), status),
        "rationale": unique_preserve_order(reasons),
    }

def _update_working_hypotheses(
    session_state: Dict[str, Any],
    incident_state: Dict[str, Any],
    verdict: Dict[str, Any],
    evidence_ledger: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    supporting_ids = [item["observation_id"] for item in evidence_ledger if item.get("relation") == "supporting"]
    counter_ids = [item["observation_id"] for item in evidence_ledger if item.get("relation") == "counterevidence"]
    secondary_ids = [item["observation_id"] for item in evidence_ledger if item.get("relation") in {"alternative", "context"}]
    family_hint = _meaningful_family_hint(incident_state.get("seed") or {})
    entities = incident_state.get("entities") or {}
    primary_assets = list(entities.get("suspected_assets") or [])
    primary_indicators = list((incident_state.get("scope") or {}).get("primary_external_indicators") or [])

    primary_title = (
        f"{'、'.join(primary_assets) or '种子资产'} 疑似 {family_hint} 相关事件"
        if family_hint
        else f"{'、'.join(primary_assets) or '种子资产'} 疑似恶意外联事件"
    )
    secondary_title = "共享基础设施上的待复核扩展"
    if list(entities.get("related_assets") or []):
        secondary_title = f"{'、'.join(list(entities.get('related_assets') or [])[:2])} 等资产的关联范围仍待确认"
    benign_title = "维护、补丁、备份或共享基线解释"
    if primary_indicators:
        benign_title = f"围绕 {'、'.join(primary_indicators[:2])} 的通信可能存在正常背景解释"

    hypotheses = [
        {
            "id": "primary",
            "kind": "primary",
            "title": primary_title,
            "score": len(supporting_ids) * 3 + (6 if verdict.get("status") == "confirmed_incident" else 0),
            "status": "leading" if verdict.get("status") == "confirmed_incident" else "supported",
            "supporting_observation_ids": unique_preserve_order(supporting_ids),
            "counter_observation_ids": unique_preserve_order(counter_ids),
        },
        {
            "id": "secondary",
            "kind": "secondary",
            "title": secondary_title,
            "score": len(secondary_ids) * 2 + (3 if verdict.get("status") == "needs_review" else 0),
            "status": "supported" if secondary_ids else "open",
            "supporting_observation_ids": unique_preserve_order(secondary_ids),
            "counter_observation_ids": [],
        },
        {
            "id": "benign",
            "kind": "benign",
            "title": benign_title,
            "score": len(counter_ids) * 3 + (5 if verdict.get("status") == "monitor_only" else 0),
            "status": "leading" if verdict.get("status") == "monitor_only" else ("supported" if counter_ids else "open"),
            "supporting_observation_ids": unique_preserve_order(counter_ids),
            "counter_observation_ids": unique_preserve_order(supporting_ids),
        },
    ]
    session_state["working_hypotheses"] = hypotheses
    return hypotheses


def _open_questions(
    seed_event: Dict[str, Any],
    session_state: Dict[str, Any],
    incident_state: Dict[str, Any],
    verdict: Dict[str, Any],
) -> List[Dict[str, Any]]:
    entities = incident_state.get("entities") or {}
    scope = incident_state.get("scope") or {}
    stage_labels = list((incident_state.get("summary") or {}).get("stage_labels") or [])
    candidate_events = _candidate_events(seed_event, incident_state)
    observation_tools = {
        str(item.get("tool_name") or "").strip()
        for item in list(incident_state.get("observations") or [])
    }
    scope_followup_actions = _novel_scope_followup_actions(seed_event, session_state, incident_state)
    scope_followup_pending = bool(scope_followup_actions)
    questions: List[Dict[str, Any]] = []
    if not incident_state.get("context_bundle", {}).get("minimal_event_count"):
        questions.append(
            _gap_record(
                "build_context",
                priority="high",
                question="仍需围绕 seed alert 补足最小上下文。",
                gap_type="context",
                materiality="delivery_blocking",
                tool_capability_hints=["context_building", "timeline"],
                delivery_blocking=True,
                reportable_if_unresolved=False,
                closure_criteria=["补齐最小事件窗", "确认告警不是孤立命中"],
            )
        )
    if verdict.get("status") != "monitor_only" and not list(entities.get("assets") or []):
        questions.append(
            _gap_record(
                "identify_assets",
                priority="high",
                question="仍需确认事件涉及的关键资产。",
                gap_type="asset_identity",
                materiality="delivery_blocking",
                tool_capability_hints=["context_building", "asset_scope"],
                delivery_blocking=True,
                reportable_if_unresolved=False,
                closure_criteria=["确认关键资产身份", "避免影响范围仍为空"],
            )
        )
    if verdict.get("status") != "monitor_only" and "execution" not in stage_labels:
        questions.append(
            _gap_record(
                "execution_gap",
                priority="medium",
                question="是否存在主机侧执行、持久化或横向移动证据？",
                gap_type="host_confirmation",
                materiality="confidence_supporting",
                tool_capability_hints=["host_confirmation"],
                delivery_blocking=False,
                reportable_if_unresolved=True,
                closure_criteria=["确认是否存在主机侧执行线索", "或保留为主机侧待确认事项"],
            )
        )
    if (
        verdict.get("status") != "monitor_only"
        and (
            "search_related_events" not in observation_tools
            or scope_followup_pending
        )
        and (
            list(scope.get("primary_external_indicators") or scope.get("external_indicators") or [])
            or any(str(item.get("tool_name") or "").strip() in {"search_related_events", "expand_asset_scope"} for item in scope_followup_actions)
        )
    ):
        questions.append(
            _gap_record(
                "expand_cluster_scope",
                priority="high",
                question="仍需围绕当前 pivot 做一次显式扩线，确认是否存在同指标的更大范围复现。",
                gap_type="cluster_scope",
                materiality="delivery_blocking",
                tool_capability_hints=["cluster_expand", "scope"],
                delivery_blocking=True,
                reportable_if_unresolved=True,
                closure_criteria=["至少完成一次基于当前 pivot 的扩线搜索", "确认是否存在更多同指标复现或明确当前范围已经收敛"],
            )
        )
    if verdict.get("status") == "needs_review" and list(entities.get("related_assets") or []):
        questions.append(
            _gap_record(
                "related_assets_review",
                priority="medium",
                question=f"关联资产 {'、'.join(list(entities.get('related_assets') or [])[:3])} 是否真正受影响？",
                gap_type="scope_expansion",
                materiality="boundary_sensitive",
                tool_capability_hints=["asset_scope", "cluster_expand", "scope"],
                delivery_blocking=True,
                reportable_if_unresolved=True,
                closure_criteria=["确认关联资产是否进入同一事件范围", "或收敛为报告边界说明"],
            )
        )
    if candidate_events:
        questions.append(
            _gap_record(
                "validate_candidate_events",
                priority="high" if verdict.get("status") != "monitor_only" else "medium",
                question=f"扩线得到的 {len(candidate_events)} 条关联事件尚未完成独立验证，是否应并入主事件范围？",
                gap_type="candidate_grounding",
                materiality="delivery_blocking",
                tool_capability_hints=["candidate_grounding", "local_intel", "external_intel", "infra_context", "structured_intel"],
                delivery_blocking=True,
                reportable_if_unresolved=True,
                closure_criteria=["对候选事件完成独立 grounding", "明确哪些事件进入主证据链，哪些仅保留为上下文/边界"],
            )
        )
    if verdict.get("status") != "monitor_only" and not list(scope.get("primary_external_indicators") or []):
        questions.append(
            _gap_record(
                "ground_infra",
                priority="medium",
                question="仍需补足外部基础设施、域名或家族背景。",
                gap_type="external_context",
                materiality="delivery_blocking",
                tool_capability_hints=["infra_context", "external_intel"],
                delivery_blocking=True,
                reportable_if_unresolved=False,
                closure_criteria=["补足外部基础设施背景", "支持当前结论的可解释性"],
            )
        )
    if COUNTEREVIDENCE_TOOL_NAME not in observation_tools:
        questions.append(
            _gap_record(
                "check_counterevidence",
                priority="medium",
                question="仍需显式检查维护窗口、补丁、备份或共享基线等反证。",
                gap_type="counterevidence",
                materiality="delivery_blocking",
                tool_capability_hints=["counterevidence", "background_validation"],
                delivery_blocking=True,
                reportable_if_unresolved=False,
                closure_criteria=["完成显式反证检查", "明确是否存在降级解释"],
            )
        )
    if not any(name in (INTEL_TOOL_NAMES | PAGE_TOOL_NAMES) for name in observation_tools):
        questions.append(
            _gap_record(
                "structure_evidence",
                priority="medium",
                question="仍需把当前事件事实沉淀为 claim 或可引用实体，避免报告只剩原始事件聚合。",
                gap_type="report_structuring",
                materiality="delivery_blocking",
                tool_capability_hints=["evidence_structuring", "entity_structuring", "source_retrieval"],
                delivery_blocking=True,
                reportable_if_unresolved=False,
                closure_criteria=["至少完成一次结构化沉淀", "报告可直接引用当前事实"],
            )
        )
    family_hint = _meaningful_family_hint(seed_event)
    if family_hint and verdict.get("status") == "needs_review":
        questions.append(
            _gap_record(
                "validate_family_hint",
                priority="low",
                question=f"seed 自带的家族提示 {family_hint} 是否有更多外部证据支撑？",
                gap_type="family_validation",
                materiality="confidence_supporting",
                tool_capability_hints=["family_validation", "external_intel"],
                delivery_blocking=False,
                reportable_if_unresolved=True,
                closure_criteria=["补足家族提示支撑", "或明确仅作弱提示引用"],
            )
        )
    return questions


def _observation_high_value(observation: Dict[str, Any]) -> bool:
    delta = dict(observation.get("output_delta") or {})
    if bool(delta.get("became_ready")) or bool(delta.get("verdict_changed")):
        return True
    if int(delta.get("novelty_score") or 0) > 0:
        return True
    if list(observation.get("events") or []):
        return True
    if list(observation.get("claims") or []):
        return True
    if any(list(values or []) for values in (observation.get("derived_entities") or {}).values()):
        return True
    return False


def _attach_observation(incident_state: Dict[str, Any], observation: Dict[str, Any]) -> None:
    incident_state.setdefault("observations", []).append(observation)
    if observation.get("events"):
        for event in list(observation.get("events") or []):
            incident_state.setdefault("known_events", {})[str(event.get("id") or "")] = event
    claim_signatures = unique_preserve_order(
        list(incident_state.get("claim_signatures") or [])
        + [_claim_signature(item) for item in list(observation.get("claims") or []) if isinstance(item, dict)]
    )
    incident_state["claim_signatures"] = claim_signatures
    for candidate in list(observation.get("page_candidates") or []):
        incident_state.setdefault("page_candidates", []).append(candidate)
    for document in list(observation.get("documents") or []):
        incident_state.setdefault("page_documents", []).append(document)
    incident_state["entities"] = _merge_entities_from_observation(incident_state.get("entities") or {}, observation)
    incident_state["pivots"] = _update_pivots_from_events(
        incident_state.get("pivots") or {},
        list(observation.get("events") or []),
        observation,
    )


def _build_observation_delta(
    before_snapshot: Dict[str, Any],
    incident_state: Dict[str, Any],
    observation: Dict[str, Any],
    finalized_before: Dict[str, Any],
    finalized_after: Dict[str, Any],
) -> Dict[str, Any]:
    after_snapshot = _incident_snapshot(incident_state)
    new_event_ids = sorted(after_snapshot["event_ids"] - before_snapshot["event_ids"])
    new_assets = sorted(after_snapshot["assets"] - before_snapshot["assets"])
    new_domains = sorted(after_snapshot["domains"] - before_snapshot["domains"])
    new_external_ips = sorted(after_snapshot["external_ips"] - before_snapshot["external_ips"])
    new_families = sorted(after_snapshot["families"] - before_snapshot["families"])
    new_claim_count = len(after_snapshot["claim_signatures"] - before_snapshot["claim_signatures"])
    new_page_documents = max(0, int(after_snapshot["page_document_count"]) - int(before_snapshot["page_document_count"]))

    readiness_before = bool(((finalized_before.get("readiness") or {}).get("ready_for_delivery")))
    readiness_after = bool(((finalized_after.get("readiness") or {}).get("ready_for_delivery")))
    verdict_before = str(((finalized_before.get("delivery_verdict") or {}).get("status")) or "").strip()
    verdict_after = str(((finalized_after.get("delivery_verdict") or {}).get("status")) or "").strip()
    candidate_before = {
        str(item).strip()
        for item in list(((finalized_before.get("annotation") or {}).get("candidate_event_ids") or []))
        if str(item).strip()
    }
    candidate_after = {
        str(item).strip()
        for item in list(((finalized_after.get("annotation") or {}).get("candidate_event_ids") or []))
        if str(item).strip()
    }
    closed_candidate_ids = sorted(candidate_before - candidate_after)
    gap_before = {
        str(item.get("id") or "").strip()
        for item in list(finalized_before.get("gap_ledger") or [])
        if str(item.get("status") or "").strip() != "closed" and str(item.get("id") or "").strip()
    }
    gap_after = {
        str(item.get("id") or "").strip()
        for item in list(finalized_after.get("gap_ledger") or [])
        if str(item.get("status") or "").strip() != "closed" and str(item.get("id") or "").strip()
    }
    closed_gap_ids = sorted(gap_before - gap_after)
    verdict_changed = bool(verdict_before != verdict_after and verdict_after)
    became_ready = bool(not readiness_before and readiness_after)

    novelty_score = (
        len(new_event_ids)
        + len(new_assets)
        + len(new_domains)
        + len(new_external_ips)
        + len(new_families)
        + new_claim_count
        + new_page_documents
        + len(closed_candidate_ids)
        + len(closed_gap_ids)
        + (2 if became_ready else 0)
        + (2 if verdict_changed else 0)
    )

    summary_parts: List[str] = []
    if new_event_ids:
        summary_parts.append(f"新增 {len(new_event_ids)} 条事件")
    if new_assets:
        summary_parts.append(f"新增 {len(new_assets)} 个资产")
    if new_domains or new_external_ips:
        summary_parts.append(f"新增 {len(new_domains) + len(new_external_ips)} 个外部指示物")
    if new_families:
        summary_parts.append(f"新增 {len(new_families)} 个家族提示")
    if new_claim_count:
        summary_parts.append(f"新增 {new_claim_count} 条 claim")
    if new_page_documents:
        summary_parts.append(f"新增 {new_page_documents} 份页面正文")
    if closed_candidate_ids:
        summary_parts.append(f"完成 {len(closed_candidate_ids)} 条候选事件验证")
    if closed_gap_ids:
        summary_parts.append(f"关闭 {len(closed_gap_ids)} 个 gap")
    if became_ready:
        summary_parts.append("达到可交付状态")
    elif verdict_changed:
        summary_parts.append(f"交付结论更新为 {verdict_after}")
    if not summary_parts:
        summary_parts.append("没有新增实质信息")

    return {
        "new_event_count": len(new_event_ids),
        "new_event_ids": new_event_ids[:6],
        "new_asset_count": len(new_assets),
        "new_domain_count": len(new_domains),
        "new_external_ip_count": len(new_external_ips),
        "new_family_count": len(new_families),
        "new_claim_count": new_claim_count,
        "new_page_document_count": new_page_documents,
        "closed_candidate_event_count": len(closed_candidate_ids),
        "closed_candidate_event_ids": closed_candidate_ids[:6],
        "closed_gap_count": len(closed_gap_ids),
        "closed_gap_ids": closed_gap_ids[:6],
        "readiness_changed": readiness_before != readiness_after,
        "became_ready": became_ready,
        "verdict_changed": verdict_changed,
        "novelty_score": novelty_score,
        "summary": "；".join(summary_parts),
    }


def _tool_history_record(action: Dict[str, Any], observation: Dict[str, Any], session_state: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "step_index": session_state["step_index"],
        "tool_name": observation.get("tool_name"),
        "observation_id": observation.get("observation_id"),
        "relation": observation.get("relation"),
        "source_type": observation.get("source_type"),
        "status": observation.get("status"),
        "target_gap_ids": unique_preserve_order(list(action.get("target_gap_ids") or [])),
        "input_fingerprint": action.get("input_fingerprint") or _action_input_fingerprint(
            str(observation.get("tool_name") or ""),
            dict(observation.get("query") or {}),
            {},
        ),
        "output_delta": dict(observation.get("output_delta") or {}),
    }


def _evidence_entry_from_observation(observation: Dict[str, Any]) -> Dict[str, Any]:
    event_ids = unique_preserve_order(
        list(observation.get("relation_event_ids") or [])
        or [str(item.get("id") or "") for item in list(observation.get("events") or []) if item.get("id")]
    )
    checked_event_ids = unique_preserve_order(
        list(observation.get("checked_event_ids") or [])
        or [str(item.get("id") or "") for item in list(observation.get("events") or []) if item.get("id")]
    )
    boundary_event_ids = unique_preserve_order(list(observation.get("boundary_event_ids") or []))
    claims = list(observation.get("claims") or [])
    summary = str(observation.get("summary") or "").strip()
    if not summary and claims:
        summary = str(claims[0].get("text") or "").strip()
    return {
        "observation_id": observation.get("observation_id"),
        "tool_name": observation.get("tool_name"),
        "relation": observation.get("relation") or "context",
        "grounding_status": str(observation.get("grounding_status") or "").strip(),
        "source_type": observation.get("source_type"),
        "source_ref": observation.get("source_ref"),
        "summary": summary,
        "event_ids": event_ids,
        "checked_event_ids": checked_event_ids,
        "boundary_event_ids": boundary_event_ids,
        "claim_texts": [str(item.get("text") or "").strip() for item in claims[:4] if str(item.get("text") or "").strip()],
        "confidence": int(observation.get("confidence") or 0),
        "supports_hypothesis": list(observation.get("supports_hypothesis") or []),
        "contradicts_hypothesis": list(observation.get("contradicts_hypothesis") or []),
    }


def _finalize_runtime_state(seed_event: Dict[str, Any], session_state: Dict[str, Any], incident_state: Dict[str, Any]) -> Dict[str, Any]:
    runtime_snapshot = dict(((incident_state.get("evidence_store") or {}).get("runtime_snapshot")) or {})
    known_events = list(runtime_snapshot.get("known_events") or (incident_state.get("known_events") or {}).values())
    known_events.sort(key=lambda item: str(item.get("ts") or ""))
    event_relation_hints = _event_relation_hints_from_ledger(incident_state)
    annotation = _annotate_events(seed_event, known_events, event_relation_hints=event_relation_hints)
    annotated_events = list(annotation.get("events") or [])
    entities = _extract_entities(seed_event, annotated_events, seed_event_id=str(annotation.get("seed_event_id") or ""))

    # Merge in intel/page-derived entities that may not exist in event rows.
    observation_entities = dict(runtime_snapshot.get("entity_hints") or incident_state.get("entities") or {})
    entities["observed_assets"] = unique_preserve_order(list(entities.get("observed_assets") or []) + list(observation_entities.get("assets") or []))
    entities["assets"] = unique_preserve_order(
        ([entities.get("seed_asset")] if entities.get("seed_asset") else [])
        + list(entities.get("suspected_assets") or [])
        + list(entities.get("related_assets") or [])
    )
    entities["internal_ips"] = unique_preserve_order(list(entities.get("internal_ips") or []) + list(observation_entities.get("internal_ips") or []))
    entities["external_ips"] = unique_preserve_order(list(entities.get("external_ips") or []) + list(observation_entities.get("external_ips") or []))
    entities["domains"] = unique_preserve_order(list(entities.get("domains") or []) + list(observation_entities.get("domains") or []))
    entities["primary_external_ips"] = unique_preserve_order(list(entities.get("primary_external_ips") or []) + list(observation_entities.get("external_ips") or []))
    entities["primary_domains"] = unique_preserve_order(list(entities.get("primary_domains") or []) + list(observation_entities.get("domains") or []))

    timeline = _build_timeline(annotated_events)
    evidence_clusters = _build_evidence_clusters(annotated_events)
    suspicious_scope_events = [item for item in annotated_events if str(item.get("role") or "") in {"seed", "supporting"}]
    counterevidence_events = [item for item in annotated_events if str(item.get("role") or "") == "counterevidence"]
    scope = {
        "event_count": len(annotated_events),
        "primary_event_count": len(suspicious_scope_events),
        "candidate_event_count": len(annotation.get("candidate_event_ids") or []),
        "context_event_count": len([item for item in annotated_events if str(item.get("role") or "") == "context"]),
        "counterevidence_count": len(counterevidence_events),
        "time_window": {
            "start": timeline[0]["ts"] if timeline else None,
            "end": timeline[-1]["ts"] if timeline else None,
        },
        "affected_assets": entities.get("suspected_assets") or [],
        "related_assets": entities.get("related_assets") or [],
        "primary_external_indicators": _sanitize_external_indicators(
            [item.get("dst_ip") for item in suspicious_scope_events]
            + [item.get("domain") for item in suspicious_scope_events]
            + list(observation_entities.get("families") or [])
        ),
        "contextual_external_indicators": _sanitize_external_indicators(
            [item.get("dst_ip") for item in counterevidence_events]
            + [item.get("domain") for item in counterevidence_events]
        ),
    }
    scope["external_indicators"] = _sanitize_external_indicators(
        list(scope.get("primary_external_indicators") or []) + list(scope.get("contextual_external_indicators") or [])
    )

    evidence_ledger = list(runtime_snapshot.get("evidence_ledger") or incident_state.get("evidence_ledger") or [])
    provisional_verdict = _build_provisional_verdict(seed_event, annotated_events, evidence_ledger, entities)
    counterevidence_assets = unique_preserve_order(
        str(item.get("asset_id") or "").strip()
        for item in counterevidence_events
        if str(item.get("asset_id") or "").strip()
    )
    if str(provisional_verdict.get("status") or "").strip() == "monitor_only":
        entities["assets"] = unique_preserve_order(
            list(entities.get("assets") or []) + counterevidence_assets
        )
    else:
        entities["assets"] = unique_preserve_order(
            ([entities.get("seed_asset")] if entities.get("seed_asset") else [])
            + list(entities.get("suspected_assets") or [])
            + list(entities.get("related_assets") or [])
        )
    working_hypotheses = _update_working_hypotheses(session_state, incident_state, provisional_verdict, evidence_ledger)
    hypothesis = _build_hypothesis(seed_event, provisional_verdict, annotated_events, entities)
    decision_basis = _build_decision_basis(
        verdict=provisional_verdict,
        events=annotated_events,
        evidence_clusters=evidence_clusters,
        entities=entities,
        scope=scope,
    )

    event_to_observation_ids: Dict[str, List[str]] = {}
    for item in evidence_ledger:
        for event_id in list(item.get("event_ids") or []):
            event_to_observation_ids.setdefault(event_id, []).append(str(item.get("observation_id") or ""))

    for bucket in ("positive_signals", "counterevidence"):
        for signal in list(decision_basis.get(bucket) or []):
            obs_ids = unique_preserve_order(event_to_observation_ids.get(str(signal.get("event_id") or ""), []))
            if obs_ids:
                signal["observation_ids"] = obs_ids
    decision_basis["positive_observation_ids"] = unique_preserve_order(
        item.get("observation_id") for item in evidence_ledger if item.get("relation") == "supporting"
    )
    decision_basis["counter_observation_ids"] = unique_preserve_order(
        item.get("observation_id") for item in evidence_ledger if item.get("relation") == "counterevidence"
    )

    session_state["working_hypotheses"] = working_hypotheses
    incident_state["entities"] = entities
    incident_state["timeline"] = timeline
    incident_state["scope"] = scope
    incident_state["analysis_verdict"] = provisional_verdict
    incident_state["provisional_verdict"] = provisional_verdict
    incident_state["verdict"] = provisional_verdict
    incident_state["confidence"] = provisional_verdict.get("confidence")
    incident_state["delivery_verdict"] = provisional_verdict
    incident_state["report_ready"] = False
    incident_state["readiness"] = {"ready_for_delivery": False, "summary": "", "checks": [], "blocking_checks": []}
    gap_ledger = _sync_gap_ledger(seed_event, session_state, incident_state)
    incident_state["gap_ledger"] = gap_ledger

    analysis_summary = _build_incident_summary(
        verdict=provisional_verdict,
        entities=entities,
        scope=scope,
        hypothesis=hypothesis,
    )
    incident_state["summary"] = analysis_summary
    partial_finalized = {
        "annotation": annotation,
        "annotated_events": annotated_events,
        "entities": entities,
        "timeline": timeline,
        "evidence_clusters": evidence_clusters,
        "scope": scope,
        "analysis_verdict": provisional_verdict,
        "provisional_verdict": provisional_verdict,
        "hypothesis": hypothesis,
        "summary": analysis_summary,
        "decision_basis": decision_basis,
        "gap_ledger": gap_ledger,
    }
    evidence_store = _refresh_runtime_evidence_store(seed_event, incident_state, partial_finalized)
    reviewer_state = _runtime_reviewer_state(seed_event, session_state, incident_state, partial_finalized)
    reviewer_input = dict(reviewer_state.get("reviewer_input") or {})
    delivery_decision = dict(reviewer_state.get("delivery_decision") or {})
    readiness = dict(delivery_decision.get("readiness") or {})
    delivery_verdict = dict(delivery_decision.get("delivery_verdict") or provisional_verdict)
    incident_summary = _build_incident_summary(verdict=delivery_verdict, entities=entities, scope=scope, hypothesis=hypothesis)
    incident_state["summary"] = incident_summary
    report_ready = bool(delivery_decision.get("approved")) and bool(readiness.get("ready_for_delivery"))
    uncertainties = _build_uncertainties(delivery_verdict, annotated_events, entities)
    recommendations = _build_recommendations(delivery_verdict, entities, scope, annotated_events)
    evidence_store = _refresh_runtime_evidence_store(
        seed_event,
        incident_state,
        {
            **partial_finalized,
            "delivery_verdict": delivery_verdict,
            "verdict": delivery_verdict,
            "summary": incident_summary,
        },
    )
    incident_state["evidence_store"] = evidence_store
    incident_state["reviewer_input"] = reviewer_input
    incident_state["delivery_decision"] = delivery_decision

    runtime_summary = dict(reviewer_input.get("runtime_summary") or {})
    state = {
        "context_built": bool(runtime_summary.get("context_built")),
        "entry_assessed": True,
        "cluster_built": bool(runtime_summary.get("cluster_built")),
        "entities_grounded": any(entities.values()),
        "timeline_built": bool(runtime_summary.get("timeline_built")),
        "scope_assessed": bool(runtime_summary.get("scope_assessed")),
        "intrusion_hypothesis_grounded": provisional_verdict["status"] == "confirmed_incident",
        "external_infra_grounded": bool((evidence_store.get("coverage") or {}).get("primary_external_indicators") or scope.get("external_indicators")),
        "counterevidence_checked": bool(runtime_summary.get("counterevidence_reviewed")),
        "provisional_status": provisional_verdict.get("status"),
        "delivery_status": delivery_verdict.get("status"),
        "report_ready": report_ready,
        "readiness": readiness,
        "decision_mode": session_state.get("decision_mode"),
        "policy_mode": session_state.get("policy_mode"),
    }

    incident_state["delivery_verdict"] = delivery_verdict
    incident_state["verdict"] = delivery_verdict
    incident_state["confidence"] = delivery_verdict.get("confidence")
    incident_state["report_ready"] = report_ready
    incident_state["readiness"] = readiness
    session_state["open_questions"] = _display_open_questions_from_gap_ledger(gap_ledger)
    if session_state["open_questions"]:
        uncertainties = unique_preserve_order(
            list(uncertainties)
            + [str(item.get("question") or "").strip() for item in session_state["open_questions"] if str(item.get("question") or "").strip()]
        )

    return {
        "annotation": annotation,
        "annotated_events": annotated_events,
        "entities": entities,
        "timeline": timeline,
        "evidence_clusters": evidence_clusters,
        "scope": scope,
        "analysis_verdict": provisional_verdict,
        "provisional_verdict": provisional_verdict,
        "delivery_verdict": delivery_verdict,
        "verdict": delivery_verdict,
        "hypothesis": hypothesis,
        "summary": incident_summary,
        "uncertainties": uncertainties,
        "recommendations": recommendations,
        "decision_basis": decision_basis,
        "gap_ledger": gap_ledger,
        "report_ready": report_ready,
        "readiness": readiness,
        "evidence_store": evidence_store,
        "reviewer_input": reviewer_input,
        "delivery_decision": delivery_decision,
        "state": state,
    }


def _stop_decision(
    seed_event: Dict[str, Any],
    started_at: float,
    session_state: Dict[str, Any],
    incident_state: Dict[str, Any],
    finalized: Dict[str, Any],
) -> Dict[str, Any]:
    budgets = session_state.get("budgets") or {}
    elapsed_s = time.perf_counter() - started_at
    acceptance_state = _acceptance_state(seed_event, session_state, incident_state, finalized)
    delivery_decision = dict(finalized.get("delivery_decision") or incident_state.get("delivery_decision") or {})
    blocking_gaps = [dict(item) for item in list(delivery_decision.get("blocking_gaps") or [])]
    actionable_gaps = [dict(item) for item in list(acceptance_state.get("actionable_gaps") or [])]
    insufficient_progress_signals = [
        str(item).strip()
        for item in list(
            delivery_decision.get("insufficient_progress_signals")
            or acceptance_state.get("insufficient_progress_signals")
            or []
        )
        if str(item).strip()
    ]
    reviewer_prefers_stop = bool(acceptance_state.get("preferred_stop"))
    reviewer_has_actionable_path = bool(actionable_gaps)
    reviewer_is_stalled = bool(insufficient_progress_signals) and not reviewer_has_actionable_path and not reviewer_prefers_stop
    decision_mode = str(session_state.get("decision_mode") or DECISION_MODE_HEURISTIC).strip() or DECISION_MODE_HEURISTIC
    if int(budgets.get("remaining_steps") or 0) <= 0:
        return {"stop": True, "reason": "step_budget_exhausted"}
    if int(budgets.get("remaining_tool_calls") or 0) <= 0:
        return {"stop": True, "reason": "tool_budget_exhausted"}
    if elapsed_s >= float(budgets.get("max_runtime_s") or DEFAULT_BUDGETS["max_runtime_s"]):
        return {"stop": True, "reason": "runtime_budget_exhausted"}
    if decision_mode != DECISION_MODE_LLM_AGENT and reviewer_prefers_stop and int(session_state.get("step_index") or 0) >= 2:
        return {"stop": True, "reason": "delivery_ready"}
    if (
        decision_mode == DECISION_MODE_LLM_AGENT
        and int(session_state.get("blocked_finish_attempts") or 0) >= 3
        and int(session_state.get("step_index") or 0) >= 2
    ):
        return {"stop": True, "reason": "repeated_blocked_finish"}
    if (
        int(session_state.get("consecutive_low_value_steps") or 0) >= 2
        and int(session_state.get("step_index") or 0) >= 2
        and (
            reviewer_prefers_stop
            or reviewer_is_stalled
            or (not blocking_gaps and not reviewer_has_actionable_path)
        )
    ):
        return {"stop": True, "reason": "two_low_value_steps"}
    return {"stop": False, "reason": "continue"}


def run_incident_agent_case(
    *,
    seed_alert: Dict[str, Any],
    fixture_dir: str,
    llm: Any = None,
    llm_runtime: Optional[Dict[str, Any]] = None,
    store: Optional[TraceStore] = None,
    budgets: Optional[Dict[str, int]] = None,
    decision_mode: Optional[str] = None,
) -> Dict[str, Any]:
    resolved_budgets = dict(DEFAULT_BUDGETS)
    if budgets:
        resolved_budgets.update({key: int(value) for key, value in budgets.items()})

    seed_event = normalize_alert(seed_alert)
    resolved_store = store or FixtureTraceStoreAdapter.from_fixture_dir(Path(fixture_dir))  # type: ignore[name-defined]
    selector_policy = _resolve_selector_policy_with_runtime(decision_mode, llm, llm_runtime)
    session_state = _initial_session_state(seed_event, resolved_budgets, selector_policy)
    incident_state = _initial_incident_state(seed_event)
    investigation_trace: List[Dict[str, Any]] = []
    started_at = time.perf_counter()

    while True:
        open_agent_mode = str(session_state.get("decision_mode") or "") == DECISION_MODE_LLM_AGENT
        finalized = _finalize_runtime_state(seed_event, session_state, incident_state)
        candidates = _action_candidates(seed_event, session_state, incident_state)
        runtime_control = _control_summary(seed_event, session_state, incident_state, finalized)
        completion_advice = _completion_advice(seed_event, session_state, incident_state, finalized)
        tool_catalog = _available_tool_catalog(seed_event, session_state, incident_state)
        decision = _stop_decision(seed_event, started_at, session_state, incident_state, finalized)
        delivery_style_stop = str(decision.get("reason") or "").strip() == "delivery_ready"
        if open_agent_mode and decision["stop"] and (not delivery_style_stop or bool(completion_advice.get("should_finish"))):
            session_state["stop_reason"] = decision["reason"]
            break
        if not open_agent_mode and decision["stop"]:
            session_state["stop_reason"] = decision["reason"]
            if (
                not delivery_style_stop
                or bool(completion_advice.get("should_finish"))
                or not candidates
            ):
                break

        if open_agent_mode:
            planning = _choose_open_agent_action(llm, seed_event, session_state, incident_state, finalized)
            agent_decision = dict(planning.get("decision") or {})

            if planning.get("action_type") == "tool":
                try:
                    chosen = _normalize_open_agent_action(
                        seed_event,
                        session_state,
                        incident_state,
                        str(agent_decision.get("tool_name") or ""),
                        dict(agent_decision.get("params") or {}),
                        reason=str(agent_decision.get("reason") or "").strip(),
                    )
                    chosen["override_reason"] = str(agent_decision.get("override_reason") or "").strip()
                    session_state["policy_mode"] = "llm_open_agent"
                except Exception as exc:
                    agent_decision["fallback_used"] = True
                    agent_decision["fallback_reason"] = f"normalize_error:{exc}"
                    planning["action_type"] = "fallback"
                    chosen = None
            else:
                chosen = None

            if planning.get("action_type") == "fallback":
                session_state["policy_mode"] = "llm_agent_fallback"
                if candidates:
                    chosen = dict(candidates[0])
                elif tool_catalog:
                    chosen = _default_tool_request(
                        seed_event,
                        session_state,
                        incident_state,
                        str(tool_catalog[0].get("tool_name") or ""),
                    )
                if chosen is not None:
                    chosen = _tool_action_contract(
                        chosen,
                        reason=str(agent_decision.get("reason") or "").strip(),
                        override_reason=str(agent_decision.get("override_reason") or "").strip(),
                    )
            proposal_target_gap_ids = list(agent_decision.get("target_gap_ids") or [])
            if not proposal_target_gap_ids and chosen is not None:
                proposal_target_gap_ids = _selected_gap_ids_for_action(
                    str(chosen.get("tool_name") or ""),
                    list(finalized.get("gap_ledger") or []),
                    explicit_ids=list(chosen.get("target_gap_ids") or []),
                )
            proposal_alignment = _proposal_alignment_view(
                str(planning.get("action_type") or ""),
                str(agent_decision.get("tool_name") or ""),
                proposal_target_gap_ids,
                list(finalized.get("gap_ledger") or []),
                _acceptance_state(seed_event, session_state, incident_state, finalized),
                runtime_control,
            )
            agent_decision["proposal_alignment"] = proposal_alignment
            proposal_question = ""
            proposal_category = ""
            proposal_expected_gain = ""
            proposal_meta: Dict[str, Any] = {}
            proposal_trace_params: Dict[str, Any] = {}
            proposal_input_fingerprint = ""
            if chosen is not None:
                proposal_question = str(chosen.get("question") or "").strip()
                proposal_category = str(chosen.get("category") or "").strip()
                proposal_expected_gain = str(chosen.get("expected_gain") or "").strip()
                proposal_meta = dict(chosen.get("meta") or {})
                proposal_trace_params = dict(chosen.get("trace_params") or {})
                proposal_input_fingerprint = str(chosen.get("input_fingerprint") or "").strip()
            proposal = {
                "action_type": str(planning.get("action_type") or ""),
                "tool_name": str(agent_decision.get("tool_name") or ""),
                "params": dict(agent_decision.get("params") or {}),
                "target_gap_ids": proposal_target_gap_ids,
                "question": proposal_question,
                "category": proposal_category,
                "expected_gain": proposal_expected_gain,
                "meta": proposal_meta,
                "trace_params": proposal_trace_params,
                "input_fingerprint": proposal_input_fingerprint,
                "alignment": proposal_alignment,
                "reason": str(agent_decision.get("reason") or "").strip(),
                "why_not_finish": str(agent_decision.get("why_not_finish") or "").strip(),
                "override_reason": str(agent_decision.get("override_reason") or "").strip(),
                "fallback_used": bool(agent_decision.get("fallback_used")),
                "fallback_reason": str(agent_decision.get("fallback_reason") or "").strip(),
            }
            active_cooldowns_before_review = _active_tool_cooldowns(
                session_state,
                incident_state,
                finalized,
            )
            reviewer_decision = _review_open_agent_proposal(
                llm,
                seed_event,
                session_state,
                incident_state,
                finalized,
                tool_catalog,
                proposal,
            )
            if (
                reviewer_decision.get("fallback_used")
                or str(reviewer_decision.get("decision") or "").strip() not in REVIEWER_DECISIONS
            ):
                reviewer_decision = _fallback_reviewer_decision(
                    seed_event,
                    session_state,
                    incident_state,
                    finalized,
                    tool_catalog,
                    proposal,
                    reviewer_decision,
                )
                reviewer_decision = _apply_reviewer_control_metadata(
                    seed_event,
                    session_state,
                    incident_state,
                    finalized,
                    tool_catalog,
                    proposal,
                    reviewer_decision,
                )
            acceptance_state = _acceptance_state(seed_event, session_state, incident_state, finalized)
            if str(reviewer_decision.get("decision") or "").strip() == "deliverable" and not bool(acceptance_state.get("deliverable_now")):
                reviewer_decision = _fallback_reviewer_decision(
                    seed_event,
                    session_state,
                    incident_state,
                    finalized,
                    tool_catalog,
                    proposal,
                    reviewer_decision,
                )
                reviewer_decision = _apply_reviewer_control_metadata(
                    seed_event,
                    session_state,
                    incident_state,
                    finalized,
                    tool_catalog,
                    proposal,
                    reviewer_decision,
                )
            reviewer_decision = _enforce_active_cooldown_gate(
                seed_event,
                session_state,
                incident_state,
                finalized,
                tool_catalog,
                proposal,
                reviewer_decision,
                active_cooldowns=active_cooldowns_before_review,
            )

            session_state.setdefault("agent_state", {})["last_decision"] = agent_decision
            session_state.setdefault("agent_history", []).append(agent_decision)
            session_state.setdefault("reviewer_state", {})["last_decision"] = reviewer_decision
            session_state.setdefault("reviewer_history", []).append(reviewer_decision)

            if str(agent_decision.get("action_type") or "").strip() == "finish":
                agent_decision["finish_requested"] = True
                if str(reviewer_decision.get("decision") or "").strip() == "deliverable":
                    agent_decision["finish_accepted"] = True
                    agent_decision["finish_blocked_reason"] = ""
                    session_state["blocked_finish_attempts"] = 0
                else:
                    agent_decision["finish_accepted"] = False
                    agent_decision["finish_blocked_reason"] = str(reviewer_decision.get("reason") or "").strip()
                    session_state["blocked_finish_attempts"] = int(session_state.get("blocked_finish_attempts") or 0) + 1

            if str(reviewer_decision.get("decision") or "").strip() == "deliverable":
                session_state["step_index"] = int(session_state.get("step_index") or 0) + 1
                _consume_non_tool_step_budget(session_state)
                agent_decision["finish_requested"] = True
                agent_decision["finish_accepted"] = True
                session_state["stop_reason"] = "agent_finish"
                step_trace = {
                    "step_index": session_state["step_index"],
                    "control_summary": runtime_control,
                    "open_questions": list(session_state.get("open_questions") or []),
                    "working_hypotheses": list(session_state.get("working_hypotheses") or []),
                    "available_tools": tool_catalog,
                    "agent_decision": agent_decision,
                    "reviewer_decision": reviewer_decision,
                    "selected_action": {
                        "tool_name": "finish",
                        "question": "finish investigation",
                        "trace_params": {},
                        "expected_gain": "",
                        "alignment": _candidate_alignment_view(proposal_alignment),
                        "llm_reason": str(reviewer_decision.get("reason") or agent_decision.get("reason") or "").strip(),
                    },
                    "observation_ids": [],
                    "state_updates": {
                        "verdict": finalized["verdict"],
                        "provisional_verdict": finalized["provisional_verdict"],
                        "delivery_verdict": finalized["delivery_verdict"],
                        "readiness": finalized["readiness"],
                        "report_ready": finalized["report_ready"],
                        "known_event_count": len(finalized["annotated_events"]),
                        "supporting_observation_ids": finalized["decision_basis"].get("positive_observation_ids") or [],
                        "counter_observation_ids": finalized["decision_basis"].get("counter_observation_ids") or [],
                    },
                    "stop_reason": "agent_finish",
                }
                investigation_trace.append(step_trace)
                break

            approved_action = chosen
            if approved_action is not None and (
                str(reviewer_decision.get("decision") or "").strip() in {"block", "redundant"}
                or _review_blocks_tool(reviewer_decision, str(approved_action.get("tool_name") or ""))
            ):
                approved_action = None
            if approved_action is None:
                approved_action = _reviewer_replacement_tool(
                    reviewer_decision,
                    tool_catalog,
                )
            if approved_action is None:
                feedback = str(reviewer_decision.get("reason") or "").strip()
                if feedback:
                    session_state["guardrail_feedback"] = (list(session_state.get("guardrail_feedback") or []) + [feedback])[-4:]
                if bool((finalized.get("readiness") or {}).get("ready_for_delivery")):
                    session_state["step_index"] = int(session_state.get("step_index") or 0) + 1
                    _consume_non_tool_step_budget(session_state)
                    session_state["stop_reason"] = "agent_finish"
                    step_trace = {
                        "step_index": session_state["step_index"],
                        "control_summary": runtime_control,
                        "open_questions": list(session_state.get("open_questions") or []),
                        "working_hypotheses": list(session_state.get("working_hypotheses") or []),
                        "available_tools": tool_catalog,
                        "agent_decision": agent_decision,
                        "reviewer_decision": reviewer_decision,
                        "selected_action": {
                            "tool_name": "finish",
                            "question": "finish investigation",
                            "trace_params": {},
                            "expected_gain": "",
                            "alignment": _candidate_alignment_view(proposal_alignment),
                            "llm_reason": str(reviewer_decision.get("reason") or "").strip(),
                        },
                        "observation_ids": [],
                        "state_updates": {
                            "verdict": finalized["verdict"],
                            "provisional_verdict": finalized["provisional_verdict"],
                            "delivery_verdict": finalized["delivery_verdict"],
                            "readiness": finalized["readiness"],
                            "report_ready": finalized["report_ready"],
                            "known_event_count": len(finalized["annotated_events"]),
                            "supporting_observation_ids": finalized["decision_basis"].get("positive_observation_ids") or [],
                            "counter_observation_ids": finalized["decision_basis"].get("counter_observation_ids") or [],
                        },
                        "stop_reason": "agent_finish",
                    }
                    investigation_trace.append(step_trace)
                    break
                session_state["stop_reason"] = decision["reason"] if decision["stop"] else "no_high_value_action"
                break

            session_state["guardrail_feedback"] = []
            if str(agent_decision.get("action_type") or "").strip() != "finish":
                session_state["blocked_finish_attempts"] = 0
            session_state["step_index"] = int(session_state.get("step_index") or 0) + 1
            observation_id = f"obs-{int(session_state['step_index']):03d}"
            material_gaps_before = list(finalized.get("gap_ledger") or [])
            selected_gap_ids = _selected_gap_ids_for_action(
                str(approved_action.get("tool_name") or ""),
                material_gaps_before,
                explicit_ids=list(approved_action.get("target_gap_ids") or proposal.get("target_gap_ids") or []),
            )
            approved_action["target_gap_ids"] = selected_gap_ids
            selected_gap_rows = _selected_gap_view(material_gaps_before, selected_gap_ids)
            step_trace = {
                "step_index": session_state["step_index"],
                "control_summary": runtime_control,
                "open_questions": list(session_state.get("open_questions") or []),
                "working_hypotheses": list(session_state.get("working_hypotheses") or []),
                "available_tools": tool_catalog,
                "agent_decision": agent_decision,
                "reviewer_decision": reviewer_decision,
                "selected_gap_ids": selected_gap_ids,
                "selected_gaps": selected_gap_rows,
                "expected_closure_criteria": unique_preserve_order(
                    criterion
                    for item in selected_gap_rows
                    for criterion in list(item.get("closure_criteria") or [])
                ),
                "selected_action": {
                    "tool_name": approved_action.get("tool_name"),
                    "question": approved_action.get("question"),
                    "trace_params": approved_action.get("trace_params"),
                    "expected_gain": approved_action.get("expected_gain"),
                    "target_gap_ids": selected_gap_ids,
                    "alignment": _candidate_alignment_view(
                        dict(
                            approved_action.get("alignment")
                            or proposal.get("alignment")
                            or _candidate_control_alignment(
                                str(approved_action.get("tool_name") or ""),
                                selected_gap_ids,
                                material_gaps_before,
                                _acceptance_state(seed_event, session_state, incident_state, finalized_before),
                                runtime_control,
                            )
                        )
                    ),
                    "llm_reason": approved_action.get("llm_reason") or str(reviewer_decision.get("reason") or agent_decision.get("reason") or "").strip(),
                    "override_reason": str(agent_decision.get("override_reason") or approved_action.get("override_reason") or "").strip(),
                },
            }

            approved_action["input_fingerprint"] = str(
                approved_action.get("input_fingerprint")
                or _action_input_fingerprint(
                    str(approved_action.get("tool_name") or ""),
                    dict(approved_action.get("params") or {}),
                    dict(approved_action.get("meta") or {}),
                )
            )
            before_snapshot = _incident_snapshot(incident_state)
            finalized_before = dict(finalized)
            observation = _execute_action(seed_event, approved_action, resolved_store, incident_state, observation_id)
            _update_budgets(session_state, str(approved_action.get("tool_name") or ""))
            _attach_observation(incident_state, observation)
            ledger_entry = _evidence_entry_from_observation(observation)
            incident_state.setdefault("evidence_ledger", []).append(ledger_entry)
            if observation.get("relation") == "counterevidence":
                incident_state.setdefault("counterevidence", []).append(ledger_entry)

            if observation.get("tool_name") == "search_seed_context":
                incident_state["context_bundle"] = {
                    "minimal_event_ids": [str(item.get("id") or "") for item in list(observation.get("events") or [])],
                    "minimal_event_count": len(list(observation.get("events") or [])),
                }

            finalized = _finalize_runtime_state(seed_event, session_state, incident_state)
            observation["output_delta"] = _build_observation_delta(
                before_snapshot,
                incident_state,
                observation,
                finalized_before,
                finalized,
            )
            if _observation_high_value(observation):
                session_state["consecutive_low_value_steps"] = 0
            else:
                session_state["consecutive_low_value_steps"] = int(session_state.get("consecutive_low_value_steps") or 0) + 1

            session_state.setdefault("tool_history", []).append(_tool_history_record(approved_action, observation, session_state))
            followup = _stop_decision(seed_event, started_at, session_state, incident_state, finalized)
            step_trace["observation_ids"] = [observation.get("observation_id")]
            step_trace["state_updates"] = {
                "verdict": finalized["verdict"],
                "provisional_verdict": finalized["provisional_verdict"],
                "delivery_verdict": finalized["delivery_verdict"],
                "readiness": finalized["readiness"],
                "report_ready": finalized["report_ready"],
                "known_event_count": len(finalized["annotated_events"]),
                "supporting_observation_ids": finalized["decision_basis"].get("positive_observation_ids") or [],
                "counter_observation_ids": finalized["decision_basis"].get("counter_observation_ids") or [],
                "observation_delta": dict(observation.get("output_delta") or {}),
                "gap_transition": _gap_transition_view(material_gaps_before, list(finalized.get("gap_ledger") or []), selected_gap_ids),
            }
            if followup["stop"]:
                step_trace["stop_reason"] = followup["reason"]
                session_state["stop_reason"] = followup["reason"]
            else:
                step_trace["continue_reason"] = followup["reason"]
            investigation_trace.append(step_trace)
            if followup["stop"]:
                break
            continue

        selection = _choose_action(llm, seed_event, session_state, incident_state, candidates)
        selector_decision = dict(selection.get("selector_decision") or {})
        guardrail = {"tool_name": "", "reason": ""}
        if selector_decision.get("stop_requested"):
            guardrail = _selector_guardrail_choice(finalized, candidates)
            if guardrail.get("tool_name"):
                chosen = next(
                    (dict(item) for item in candidates if str(item.get("tool_name") or "") == str(guardrail.get("tool_name") or "")),
                    None,
                )
                selector_decision["stop_accepted"] = False
                selector_decision["fallback_used"] = True
                selector_decision["fallback_reason"] = "stop_blocked_by_guardrail"
                selector_decision["stop_override_reason"] = str(guardrail.get("reason") or "").strip()
                selector_decision["chosen_tool_name"] = str(guardrail.get("tool_name") or "").strip()
                selector_decision["chosen_by"] = "guardrail_fallback"
                selector_decision["outcome"] = "selected_action"
                session_state["policy_mode"] = "guardrail_override"
            else:
                chosen = None
                selector_decision["stop_accepted"] = True
                selector_decision["outcome"] = "selector_stop"
        else:
            chosen = selection.get("action")

        session_state.setdefault("selector_history", []).append(selector_decision)
        session_state.setdefault("selector_state", {})["last_decision"] = selector_decision
        if chosen is None:
            session_state["stop_reason"] = (
                "selector_stop"
                if selector_decision.get("stop_accepted")
                else (decision["reason"] if decision["stop"] else "no_high_value_action")
            )
            break

        session_state["step_index"] = int(session_state.get("step_index") or 0) + 1
        observation_id = f"obs-{int(session_state['step_index']):03d}"
        material_gaps_before = list(finalized.get("gap_ledger") or [])
        selected_gap_ids = _selected_gap_ids_for_action(
            str(chosen.get("tool_name") or ""),
            material_gaps_before,
            explicit_ids=list(chosen.get("target_gap_ids") or []),
        )
        chosen["target_gap_ids"] = selected_gap_ids
        selected_gap_rows = _selected_gap_view(material_gaps_before, selected_gap_ids)
        step_trace = {
            "step_index": session_state["step_index"],
            "control_summary": runtime_control,
            "open_questions": list(session_state.get("open_questions") or []),
            "working_hypotheses": list(session_state.get("working_hypotheses") or []),
            "candidate_actions": _selector_candidate_view(candidates),
            "selector_decision": selector_decision,
            "selected_gap_ids": selected_gap_ids,
            "selected_gaps": selected_gap_rows,
            "expected_closure_criteria": unique_preserve_order(
                criterion
                for item in selected_gap_rows
                for criterion in list(item.get("closure_criteria") or [])
            ),
            "selected_action": {
                "tool_name": chosen.get("tool_name"),
                "question": chosen.get("question"),
                "trace_params": chosen.get("trace_params"),
                "expected_gain": chosen.get("expected_gain"),
                "target_gap_ids": selected_gap_ids,
                "alignment": _candidate_alignment_view(
                    dict(
                        chosen.get("alignment")
                        or _candidate_control_alignment(
                            str(chosen.get("tool_name") or ""),
                            selected_gap_ids,
                            material_gaps_before,
                            _acceptance_state(seed_event, session_state, incident_state, finalized),
                            runtime_control,
                        )
                    )
                ),
                "llm_reason": chosen.get("llm_reason") or selector_decision.get("reason") or "",
            },
        }

        chosen["input_fingerprint"] = str(
            chosen.get("input_fingerprint")
            or _action_input_fingerprint(
                str(chosen.get("tool_name") or ""),
                dict(chosen.get("params") or {}),
                dict(chosen.get("meta") or {}),
            )
        )
        before_snapshot = _incident_snapshot(incident_state)
        finalized_before = dict(finalized)
        observation = _execute_action(seed_event, chosen, resolved_store, incident_state, observation_id)
        _update_budgets(session_state, str(chosen.get("tool_name") or ""))
        _attach_observation(incident_state, observation)
        ledger_entry = _evidence_entry_from_observation(observation)
        incident_state.setdefault("evidence_ledger", []).append(ledger_entry)
        if observation.get("relation") == "counterevidence":
            incident_state.setdefault("counterevidence", []).append(ledger_entry)

        if observation.get("tool_name") == "search_seed_context":
            incident_state["context_bundle"] = {
                "minimal_event_ids": [str(item.get("id") or "") for item in list(observation.get("events") or [])],
                "minimal_event_count": len(list(observation.get("events") or [])),
            }

        finalized = _finalize_runtime_state(seed_event, session_state, incident_state)
        observation["output_delta"] = _build_observation_delta(
            before_snapshot,
            incident_state,
            observation,
            finalized_before,
            finalized,
        )
        if _observation_high_value(observation):
            session_state["consecutive_low_value_steps"] = 0
        else:
            session_state["consecutive_low_value_steps"] = int(session_state.get("consecutive_low_value_steps") or 0) + 1

        session_state.setdefault("tool_history", []).append(_tool_history_record(chosen, observation, session_state))
        followup = _stop_decision(seed_event, started_at, session_state, incident_state, finalized)
        step_trace["observation_ids"] = [observation.get("observation_id")]
        step_trace["state_updates"] = {
            "verdict": finalized["verdict"],
            "provisional_verdict": finalized["provisional_verdict"],
            "delivery_verdict": finalized["delivery_verdict"],
            "readiness": finalized["readiness"],
            "report_ready": finalized["report_ready"],
            "known_event_count": len(finalized["annotated_events"]),
            "supporting_observation_ids": finalized["decision_basis"].get("positive_observation_ids") or [],
            "counter_observation_ids": finalized["decision_basis"].get("counter_observation_ids") or [],
            "observation_delta": dict(observation.get("output_delta") or {}),
            "gap_transition": _gap_transition_view(material_gaps_before, list(finalized.get("gap_ledger") or []), selected_gap_ids),
        }
        if followup["stop"]:
            step_trace["stop_reason"] = followup["reason"]
            session_state["stop_reason"] = followup["reason"]
        else:
            step_trace["continue_reason"] = followup["reason"]
        investigation_trace.append(step_trace)
        if followup["stop"]:
            break

    finalized = _finalize_runtime_state(seed_event, session_state, incident_state)
    incident = {
        "schema_version": "0.3",
        "mode": "incident-agent",
        "fixture_case": getattr(resolved_store, "fixture_dir", Path(fixture_dir)).name,  # type: ignore[name-defined]
        "decision_mode": {
            "requested_mode": session_state.get("requested_decision_mode"),
            "effective_mode": session_state.get("decision_mode"),
            "policy_mode": session_state.get("policy_mode"),
            "llm_available": bool((session_state.get("selector_state") or {}).get("llm_available")),
            "llm_unavailable_reason": str((session_state.get("selector_state") or {}).get("llm_unavailable_reason") or "").strip(),
            "llm_runtime": dict((session_state.get("selector_state") or {}).get("llm_runtime") or {}),
        },
        "seed": seed_event,
        "state": finalized["state"],
        "readiness": finalized["readiness"],
        "session_state": session_state,
        "selector_history": list(session_state.get("selector_history") or []),
        "agent_history": list(session_state.get("agent_history") or []),
        "reviewer_history": list(session_state.get("reviewer_history") or []),
        "incident_state": {
            "seed": seed_event,
            "pivots": incident_state.get("pivots") or {},
            "observations": list(incident_state.get("observations") or []),
            "page_documents": list(incident_state.get("page_documents") or []),
            "entities": finalized["entities"],
            "timeline": finalized["timeline"],
            "scope": finalized["scope"],
            "evidence_ledger": list(incident_state.get("evidence_ledger") or []),
            "gap_ledger": list(incident_state.get("gap_ledger") or []),
            "counterevidence": list(incident_state.get("counterevidence") or []),
            "analysis_verdict": finalized["analysis_verdict"],
            "provisional_verdict": finalized["provisional_verdict"],
            "delivery_verdict": finalized["delivery_verdict"],
            "verdict": finalized["verdict"],
            "confidence": finalized["verdict"].get("confidence"),
            "report_ready": finalized["report_ready"],
            "readiness": finalized["readiness"],
            "evidence_store": finalized.get("evidence_store") or incident_state.get("evidence_store") or {},
            "reviewer_input": finalized.get("reviewer_input") or incident_state.get("reviewer_input") or {},
            "delivery_decision": finalized.get("delivery_decision") or incident_state.get("delivery_decision") or {},
        },
        "open_questions": list(session_state.get("open_questions") or []),
        "working_hypotheses": list(session_state.get("working_hypotheses") or []),
        "analysis_verdict": finalized["analysis_verdict"],
        "provisional_verdict": finalized["provisional_verdict"],
        "delivery_verdict": finalized["delivery_verdict"],
        "verdict": finalized["verdict"],
        "summary": finalized["summary"],
        "decision_basis": finalized["decision_basis"],
        "context_bundle": incident_state.get("context_bundle") or {"minimal_event_ids": [], "minimal_event_count": 0},
        "cluster": {
            "seed_event_id": finalized["annotation"].get("seed_event_id"),
            "supporting_event_ids": finalized["annotation"].get("supporting_event_ids") or [],
            "counterevidence_event_ids": finalized["annotation"].get("counterevidence_event_ids") or [],
            "candidate_event_ids": finalized["annotation"].get("candidate_event_ids") or [],
            "events": finalized["annotated_events"],
            "event_count": len(finalized["annotated_events"]),
        },
        "entities": finalized["entities"],
        "timeline": finalized["timeline"],
        "evidence_clusters": finalized["evidence_clusters"],
        "evidence_ledger": list(incident_state.get("evidence_ledger") or []),
        "gap_ledger": list(incident_state.get("gap_ledger") or []),
        "hypothesis": finalized["hypothesis"],
        "scope": finalized["scope"],
        "uncertainties": finalized["uncertainties"],
        "recommendations": finalized["recommendations"],
        "evidence_store": finalized.get("evidence_store") or incident_state.get("evidence_store") or {},
        "reviewer_input": finalized.get("reviewer_input") or incident_state.get("reviewer_input") or {},
        "delivery_decision": finalized.get("delivery_decision") or incident_state.get("delivery_decision") or {},
    }
    report_outline = build_incident_report_outline(incident)
    rendered_report = render_incident_report_with_llm(incident, llm=llm, outline=report_outline)
    topology = build_incident_topology(incident)
    return {
        "incident": incident,
        "investigation_trace": investigation_trace,
        "report_markdown": rendered_report.get("report_markdown") or "",
        "report_polished_markdown": rendered_report.get("report_polished_markdown") or "",
        "report_appendix_markdown": rendered_report.get("report_appendix_markdown") or "",
        "report_polish_input": rendered_report.get("report_polish_input") or {},
        "report_polish_brief": rendered_report.get("report_polish_brief") or "",
        "report_polish_error": rendered_report.get("report_polish_error") or "",
        "report_outline": report_outline,
        "ops_report_contract": report_outline.get("ops_report_contract") or report_outline.get("main_report_contract") or {},
        "appendix_contract": report_outline.get("appendix_contract") or report_outline.get("appendix") or {},
        "topology": topology,
    }
