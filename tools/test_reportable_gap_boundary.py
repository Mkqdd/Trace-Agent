from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from demo_agent.incidents.evidence_store import _collect_gap_rows_from_ledger  # noqa: E402
from demo_agent.incidents.agent import _material_gap_view  # noqa: E402
from demo_agent.incidents.investigation_graph import build_investigation_graph  # noqa: E402
from demo_agent.incidents.reviewer import build_delivery_decision  # noqa: E402


def test_reportable_boundary_gap_survives_ledger_and_review_layers() -> None:
    seed_event = {
        "event_time": "2026-07-14 01:10:00",
        "src": {"ip": "10.0.0.5"},
        "dst": {"ip": "203.0.113.10"},
        "trigger_fingerprint": {"type": "JA4", "value": "t13d-demo"},
    }
    session_state = {
        "step_index": 5,
        "tool_history": [
            {
                "step_index": 3,
                "tool_name": "search_related_events",
                "input_fingerprint": "search-001",
                "output_delta": {"new_event_count": 6, "new_claim_count": 1, "novelty_score": 7},
            },
            {
                "step_index": 4,
                "tool_name": "expand_asset_scope",
                "input_fingerprint": "expand-001",
                "output_delta": {"new_claim_count": 1, "novelty_score": 1},
            },
            {
                "step_index": 5,
                "tool_name": "search_related_events",
                "input_fingerprint": "search-002",
                "output_delta": {"new_claim_count": 1, "novelty_score": 1},
            },
        ],
        "budgets": {
            "remaining_tool_calls": 3,
            "remaining_event_queries": 3,
            "remaining_intel_queries": 3,
        },
    }
    incident_state = {
        "context_bundle": {"minimal_event_count": 1},
        "pivots": {"domains": ["x.example"], "external_ips": ["203.0.113.10"]},
        "entities": {"assets": ["ws-a"], "seed_asset": "ws-a"},
        "scope": {
            "primary_external_indicators": ["203.0.113.10"],
            "external_indicators": ["203.0.113.10"],
        },
        "observations": [],
        "summary": {"stage_labels": []},
        "analysis_verdict": {"status": "needs_review"},
        "gap_ledger": [
            {
                "id": "expand_cluster_scope",
                "question": "仍需围绕当前 pivot 做一次显式扩线，确认是否存在同指标的更大范围复现。",
                "gap_type": "cluster_scope",
                "priority": "high",
                "status": "stalled",
                "status_reason": "存在理论上相关的工具，但它们近期已经进入低收益状态。",
                "materiality": "delivery_blocking",
                "delivery_blocking": True,
                "reportable_if_unresolved": True,
                "actionable_now": False,
                "actionable_tools": ["search_related_events", "expand_asset_scope"],
            }
        ],
    }

    gap_rows = _collect_gap_rows_from_ledger(incident_state["gap_ledger"])
    assert gap_rows[0]["status"] == "partially_closed"
    assert gap_rows[0]["reportable_if_unresolved"] is True

    evidence_store = {
        "gaps": gap_rows,
        "claims": [{"relation": "supporting", "claim_id": "claim-1"}],
        "confirmed_events": [{"event_id": "evt-1"}],
        "coverage": {"primary_external_indicators": ["203.0.113.10"]},
        "counterevidence": [{"claim_id": "counter-1"}],
        "objects": [{"object_type": "asset", "value": "ws-a", "current_role": "seed_asset", "in_evidence_chain": True}],
    }
    reviewer_input = {
        "provisional_assessment": {"status": "needs_review", "confidence": 72},
        "runtime_summary": {
            "context_built": True,
            "cluster_built": True,
            "timeline_built": True,
            "scope_assessed": True,
            "counterevidence_reviewed": False,
            "supplemental_context_reviewed": False,
            "consecutive_low_value_steps": 2,
            "recent_low_novelty_count": 2,
            "stop_reason": "",
            "budget_usage": {"remaining_steps": 3, "remaining_tool_calls": 3, "remaining_event_queries": 3, "remaining_intel_queries": 3},
        },
        "session_trace_summary": {
            "stop_reason": "",
            "consecutive_low_value_steps": 2,
            "recent_tool_effects": [
                {"step_index": 4, "tool_name": "expand_asset_scope", "novelty_score": 1, "summary": "没有新增实质信息"},
                {"step_index": 5, "tool_name": "search_related_events", "novelty_score": 1, "summary": "没有新增实质信息"},
            ],
            "budget_usage": {"remaining_steps": 3, "remaining_tool_calls": 3, "remaining_event_queries": 3, "remaining_intel_queries": 3},
        },
    }

    decision = build_delivery_decision(evidence_store, reviewer_input)

    assert decision["readiness"]["ready_for_delivery"] is True
    assert decision["blocking_gaps"] == []

    graph = build_investigation_graph(
        seed_event,
        session_state,
        incident_state,
        {
            "gap_ledger": gap_rows,
            "readiness": {"ready_for_delivery": True, "blocking_checks": []},
            "delivery_decision": {"approved": True, "readiness": {"ready_for_delivery": True, "blocking_checks": []}},
        },
    )
    runtime_summary = graph["runtime_summary"]
    assert "expand_cluster_scope" in runtime_summary["reportable_gap_ids"]
    assert "expand_cluster_scope" not in runtime_summary["blocking_gap_ids"]


def test_reportable_boundary_gap_becomes_non_blocking_after_repeated_low_delta_attempts() -> None:
    seed_event = {
        "event_time": "2026-07-14 01:10:00",
        "src": {"ip": "10.0.0.5"},
        "dst": {"ip": "203.0.113.10"},
        "trigger_fingerprint": {"type": "JA4", "value": "t13d-demo"},
    }
    session_state = {
        "step_index": 6,
        "tool_history": [
            {
                "step_index": 3,
                "tool_name": "search_related_events",
                "input_fingerprint": "search-001",
                "status": "ok",
                "output_delta": {"new_event_count": 1, "novelty_score": 3},
            },
            {
                "step_index": 4,
                "tool_name": "expand_asset_scope",
                "input_fingerprint": "expand-001",
                "status": "ok",
                "output_delta": {"new_claim_count": 1, "novelty_score": 1},
            },
            {
                "step_index": 5,
                "tool_name": "search_related_events",
                "input_fingerprint": "search-002",
                "status": "ok",
                "output_delta": {"new_claim_count": 1, "novelty_score": 0},
            },
            {
                "step_index": 6,
                "tool_name": "expand_asset_scope",
                "input_fingerprint": "expand-002",
                "status": "ok",
                "output_delta": {"new_claim_count": 1, "novelty_score": 0},
            },
        ],
        "budgets": {
            "remaining_tool_calls": 3,
            "remaining_event_queries": 3,
            "remaining_intel_queries": 3,
        },
    }
    incident_state = {
        "context_bundle": {"minimal_event_count": 1},
        "pivots": {"domains": ["x.example"], "external_ips": ["203.0.113.10"], "asset_ids": ["ws-a"]},
        "entities": {"assets": ["ws-a"], "seed_asset": "ws-a", "related_assets": ["ws-b"]},
        "scope": {
            "primary_external_indicators": ["203.0.113.10"],
            "external_indicators": ["203.0.113.10"],
        },
        "observations": [],
        "summary": {"stage_labels": []},
        "analysis_verdict": {"status": "needs_review"},
        "provisional_verdict": {"status": "needs_review"},
        "gap_ledger": [],
    }

    gap_rows = _material_gap_view(seed_event, session_state, incident_state)
    gap = next(item for item in gap_rows if item["id"] == "expand_cluster_scope")
    assert gap["status"] == "reportable_unresolved"
    assert gap["actionable_now"] is False
    assert gap["actionable_tools"] == []

    evidence_store = {
        "gaps": gap_rows,
        "claims": [{"relation": "supporting", "claim_id": "claim-1"}],
        "confirmed_events": [{"event_id": "evt-1"}],
        "coverage": {"primary_external_indicators": ["203.0.113.10"]},
        "counterevidence": [{"claim_id": "counter-1"}],
        "objects": [{"object_type": "asset", "value": "ws-a", "current_role": "seed_asset", "in_evidence_chain": True}],
        "candidate_events": [],
    }
    reviewer_input = {
        "provisional_assessment": {"status": "needs_review", "confidence": 72},
        "runtime_summary": {
            "context_built": True,
            "cluster_built": True,
            "timeline_built": True,
            "scope_assessed": True,
            "counterevidence_reviewed": False,
            "supplemental_context_reviewed": False,
            "consecutive_low_value_steps": 2,
            "recent_low_novelty_count": 2,
            "stop_reason": "",
            "budget_usage": {"remaining_steps": 3, "remaining_tool_calls": 3, "remaining_event_queries": 3, "remaining_intel_queries": 3},
        },
        "session_trace_summary": {
            "stop_reason": "",
            "consecutive_low_value_steps": 2,
            "recent_tool_effects": [
                {"step_index": 5, "tool_name": "search_related_events", "novelty_score": 0, "summary": "没有新增实质信息"},
                {"step_index": 6, "tool_name": "expand_asset_scope", "novelty_score": 0, "summary": "没有新增实质信息"},
            ],
            "budget_usage": {"remaining_steps": 3, "remaining_tool_calls": 3, "remaining_event_queries": 3, "remaining_intel_queries": 3},
        },
    }

    decision = build_delivery_decision(evidence_store, reviewer_input)
    assert decision["readiness"]["ready_for_delivery"] is True
    assert decision["blocking_gaps"] == []


if __name__ == "__main__":
    test_reportable_boundary_gap_survives_ledger_and_review_layers()
    test_reportable_boundary_gap_becomes_non_blocking_after_repeated_low_delta_attempts()
    print("reportable gap boundary smoke passed")
