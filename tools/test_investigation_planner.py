from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from demo_agent.incidents.investigation_graph import build_investigation_graph  # noqa: E402
from demo_agent.incidents.investigation_planner import score_investigation_opportunities  # noqa: E402
from tools.test_investigation_graph import (  # noqa: E402
    _sample_finalized,
    _sample_incident_state,
    _sample_seed,
    _sample_session_state,
)


def _sample_tool_catalog() -> list[dict]:
    return [
        {
            "tool_name": "search_related_events",
            "category": "event",
            "target_gap_ids": ["gap-candidate-spread"],
            "capability_tags": ["scope_expansion", "candidate_discovery"],
            "evidence_types": ["candidate_event"],
            "input_fingerprint": "related-fp-001",
            "expected_gain": "Check whether the candidate asset is part of the same incident.",
            "recommended_params": {"asset_ids": ["ws-eng-03"], "window_minutes": 120},
            "recommended_now": True,
        },
        {
            "tool_name": "check_counterevidence",
            "category": "event",
            "target_gap_ids": ["gap-shared-infra"],
            "capability_tags": ["counterevidence", "background_validation"],
            "evidence_types": ["background_or_counterevidence"],
            "input_fingerprint": "counter-fp-001",
            "expected_gain": "Check whether maintenance or shared infrastructure explains boundary signals.",
            "recommended_params": {"asset_ids": ["ws-eng-02", "ws-eng-03"], "window_minutes": 240},
            "recommended_now": True,
        },
        {
            "tool_name": "fetch_page_content",
            "category": "page",
            "target_gap_ids": [],
            "capability_tags": ["page_context"],
            "evidence_types": ["page_content"],
            "input_fingerprint": "page-fp-001",
            "expected_gain": "Read external background page content.",
            "recommended_params": {"max_chars": 5000},
            "recommended_now": False,
        },
    ]


def test_opportunity_scorer_prefers_high_value_candidate_or_counterevidence_actions() -> None:
    incident_state = _sample_incident_state()
    incident_state["gap_ledger"] = [
        {
            **gap,
            "delivery_blocking": True,
            "blocks_delivery_now": True,
        }
        if gap.get("id") == "gap-shared-infra"
        else gap
        for gap in incident_state["gap_ledger"]
    ]
    finalized = {
        **_sample_finalized(),
        "gap_ledger": incident_state["gap_ledger"],
    }
    graph = build_investigation_graph(
        _sample_seed(),
        _sample_session_state(),
        incident_state,
        finalized,
    )
    trace = score_investigation_opportunities(
        graph,
        _sample_tool_catalog(),
        budgets={"remaining_tool_calls": 3, "remaining_event_queries": 2, "remaining_intel_queries": 1},
        recent_tool_effects=[],
        top_k=2,
    )

    assert trace["schema_version"] == "investigation-opportunity-trace-v1"
    assert trace["value_of_information"]["level"] == "high"
    assert trace["stop_recommendation"]["should_stop"] is False
    top_by_tool = {item["tool_name"]: item for item in trace["top_k"]}
    assert set(top_by_tool) == {"search_related_events", "check_counterevidence"}
    assert "candidate_spread" in top_by_tool["search_related_events"]["target_hypothesis_ids"]
    assert "benign_or_shared_infra_alternative" in top_by_tool["check_counterevidence"]["target_hypothesis_ids"]


def test_opportunity_scorer_penalizes_repeated_low_delta_actions_without_blocking_gaps() -> None:
    graph = build_investigation_graph(
        _sample_seed(),
        _sample_session_state(),
        {
            **_sample_incident_state(),
            "gap_ledger": [],
        },
        {
            **_sample_finalized(),
            "gap_ledger": [],
            "annotated_events": [
                item
                for item in _sample_finalized()["annotated_events"]
                if item["id"] == "evt-seed"
            ],
        },
    )
    trace = score_investigation_opportunities(
        graph,
        [
            {
                "tool_name": "search_related_events",
                "category": "event",
                "target_gap_ids": [],
                "capability_tags": ["scope_expansion"],
                "evidence_types": ["candidate_event"],
                "input_fingerprint": "related-fp-001",
                "expected_gain": "Repeat the same scope query.",
                "recommended_params": {},
                "recommended_now": True,
            }
        ],
        budgets={"remaining_tool_calls": 1, "remaining_event_queries": 1, "remaining_intel_queries": 0},
        recent_tool_effects=[
            {
                "tool_name": "search_related_events",
                "input_fingerprint": "related-fp-001",
                "novelty_score": 0,
                "material_score": 0,
                "delta_summary": "no material delta",
            }
        ],
        top_k=1,
    )

    assert trace["value_of_information"]["level"] in {"low", "exhausted"}
    assert trace["stop_recommendation"]["should_stop"] is True
    assert trace["ranked_actions"][0]["eligible"] is False
    assert "repeat_low_delta" in trace["ranked_actions"][0]["penalty_reasons"]


def test_opportunity_scorer_does_not_treat_reportable_boundaries_as_blocking_work() -> None:
    incident_state = {
        **_sample_incident_state(),
        "gap_ledger": [
            {
                "id": "gap-command-line",
                "question": "Need more endpoint detail before writing a stronger execution claim.",
                "status": "open",
                "delivery_blocking": True,
                "actionable_now": True,
                "blocks_delivery_now": True,
                "actionable_tools": ["expand_asset_scope"],
            }
        ],
    }
    finalized = {
        **_sample_finalized(),
        "gap_ledger": incident_state["gap_ledger"],
        "delivery_decision": {
            "approved": True,
            "status": "confirmed_incident",
            "readiness": {"ready_for_delivery": True, "blocking_checks": []},
            "blocking_gaps": [],
            "non_blocking_gaps": [
                {
                    "gap_id": "gap-command-line",
                    "status": "reportable_unresolved",
                    "blocks_delivery_now": False,
                    "gate_type": "reportable_limit",
                }
            ],
        },
    }
    graph = build_investigation_graph(_sample_seed(), _sample_session_state(), incident_state, finalized)
    trace = score_investigation_opportunities(
        graph,
        [
            {
                "tool_name": "expand_asset_scope",
                "category": "event",
                "target_gap_ids": ["gap-command-line"],
                "capability_tags": ["missing_artifact", "limit_reduction"],
                "evidence_types": ["host_artifact"],
                "input_fingerprint": "command-line-gap-fp-001",
                "expected_gain": "May add detail, but the reviewer has already marked the gap as reportable.",
                "recommended_params": {"asset_ids": ["ws-eng-02"], "window_minutes": 120},
                "recommended_now": True,
            }
        ],
        budgets={"remaining_tool_calls": 1, "remaining_event_queries": 1, "remaining_intel_queries": 0},
        recent_tool_effects=[],
        top_k=1,
    )

    assert "gap-command-line" not in graph["runtime_summary"]["blocking_gap_ids"]
    assert "gap-command-line" in graph["runtime_summary"]["reportable_gap_ids"]
    assert trace["value_of_information"]["level"] in {"low", "exhausted"}
    assert trace["stop_recommendation"]["should_stop"] is True
    assert "reportable_boundary_not_delivery_blocking" in trace["ranked_actions"][0]["penalty_reasons"]


def test_opportunity_scorer_can_continue_high_value_reportable_boundary_work() -> None:
    incident_state = {
        **_sample_incident_state(),
        "gap_ledger": [
            {
                "id": "gap-candidate-boundary",
                "question": "Validate whether candidate scope changes the report boundary.",
                "gap_type": "cluster_scope",
                "priority": "high",
                "status": "open",
                "delivery_blocking": True,
                "actionable_now": True,
                "blocks_delivery_now": True,
                "actionable_tools": ["expand_asset_scope"],
            }
        ],
    }
    finalized = {
        **_sample_finalized(),
        "gap_ledger": incident_state["gap_ledger"],
        "delivery_decision": {
            "approved": True,
            "status": "confirmed_incident",
            "readiness": {"ready_for_delivery": True, "blocking_checks": []},
            "blocking_gaps": [],
            "non_blocking_gaps": [
                {
                    "gap_id": "gap-candidate-boundary",
                    "status": "reportable_unresolved",
                    "priority": "high",
                    "actionable_now": True,
                    "blocks_delivery_now": False,
                    "gate_type": "reportable_limit",
                }
            ],
        },
    }
    graph = build_investigation_graph(_sample_seed(), _sample_session_state(), incident_state, finalized)
    trace = score_investigation_opportunities(
        graph,
        [
            {
                "tool_name": "expand_asset_scope",
                "category": "event",
                "target_gap_ids": ["gap-candidate-boundary"],
                "capability_tags": ["scope_expansion", "candidate_discovery"],
                "evidence_types": ["candidate_event"],
                "input_fingerprint": "candidate-boundary-fp-001",
                "expected_gain": "May validate whether candidate scope changes the report boundary.",
                "recommended_params": {"asset_ids": ["ws-eng-03"], "window_minutes": 120},
                "recommended_now": True,
            }
        ],
        budgets={"remaining_tool_calls": 1, "remaining_event_queries": 1, "remaining_intel_queries": 0},
        recent_tool_effects=[],
        top_k=1,
    )

    ranked = trace["ranked_actions"][0]
    assert "gap-candidate-boundary" not in graph["runtime_summary"]["blocking_gap_ids"]
    assert "gap-candidate-boundary" in graph["runtime_summary"]["reportable_gap_ids"]
    assert ranked["eligible"] is True
    assert "closes_blocking_gap" not in ranked["score_reasons"]
    assert "report_quality_candidate_boundary" in ranked["score_reasons"]
    assert trace["stop_recommendation"]["should_stop"] is False


def test_opportunity_scorer_stops_after_repeated_reportable_boundary_progress() -> None:
    incident_state = {
        **_sample_incident_state(),
        "gap_ledger": [
            {
                "id": "gap-candidate-boundary",
                "question": "Validate whether candidate scope changes the report boundary.",
                "gap_type": "cluster_scope",
                "priority": "high",
                "status": "open",
                "delivery_blocking": True,
                "actionable_now": True,
                "blocks_delivery_now": True,
                "actionable_tools": ["ground_candidate_event"],
            }
        ],
    }
    finalized = {
        **_sample_finalized(),
        "gap_ledger": incident_state["gap_ledger"],
        "delivery_decision": {
            "approved": True,
            "status": "confirmed_incident",
            "readiness": {"ready_for_delivery": True, "blocking_checks": []},
            "blocking_gaps": [],
            "non_blocking_gaps": [
                {
                    "gap_id": "gap-candidate-boundary",
                    "status": "reportable_unresolved",
                    "priority": "high",
                    "actionable_now": True,
                    "blocks_delivery_now": False,
                    "gate_type": "reportable_limit",
                }
            ],
        },
    }
    graph = build_investigation_graph(_sample_seed(), _sample_session_state(), incident_state, finalized)
    trace = score_investigation_opportunities(
        graph,
        [
            {
                "tool_name": "ground_candidate_event",
                "category": "intel",
                "target_gap_ids": ["gap-candidate-boundary"],
                "capability_tags": ["candidate_validation"],
                "evidence_types": ["candidate_event"],
                "input_fingerprint": "candidate-boundary-grounding-fp-003",
                "expected_gain": "May ground one more candidate event.",
                "recommended_params": {"event_id": "candidate-event"},
                "recommended_now": True,
            }
        ],
        budgets={"remaining_tool_calls": 1, "remaining_event_queries": 0, "remaining_intel_queries": 1},
        recent_tool_effects=[
            {
                "tool_name": "ground_candidate_event",
                "target_gap_ids": ["gap-candidate-boundary"],
                "input_fingerprint": "candidate-boundary-grounding-fp-001",
                "novelty_score": 3,
                "material_score": 2,
                "closed_candidate_event_count": 1,
                "closed_gap_count": 0,
            },
            {
                "tool_name": "ground_candidate_event",
                "target_gap_ids": ["gap-candidate-boundary"],
                "input_fingerprint": "candidate-boundary-grounding-fp-002",
                "novelty_score": 2,
                "material_score": 2,
                "closed_candidate_event_count": 1,
                "closed_gap_count": 0,
            },
        ],
        top_k=1,
    )

    ranked = trace["ranked_actions"][0]
    assert "reportable_boundary_already_sampled" in ranked["penalty_reasons"]
    assert trace["value_of_information"]["level"] == "low"
    assert trace["stop_recommendation"]["should_stop"] is True


def test_opportunity_scorer_stops_after_background_boundary_is_sampled() -> None:
    incident_state = {
        **_sample_incident_state(),
        "gap_ledger": [
            {
                "id": "gap-shared-infra",
                "question": "Check whether maintenance or shared infrastructure explains boundary signals.",
                "gap_type": "counterevidence",
                "priority": "medium",
                "status": "open",
                "delivery_blocking": True,
                "actionable_now": True,
                "blocks_delivery_now": True,
                "actionable_tools": ["check_counterevidence"],
            }
        ],
    }
    finalized = {
        **_sample_finalized(),
        "gap_ledger": incident_state["gap_ledger"],
        "annotated_events": [
            *_sample_finalized()["annotated_events"],
            {
                "id": "evt-background-2",
                "role": "background",
                "status": "background",
                "summary": "A second background maintenance signal overlaps the incident window.",
                "ts": "2026-07-14 01:26:00",
                "asset_id": "ws-eng-03",
                "grounding_status": "context_only",
                "observation_ids": ["obs-3"],
            },
        ],
        "delivery_decision": {
            "approved": True,
            "status": "confirmed_incident",
            "readiness": {"ready_for_delivery": True, "blocking_checks": []},
            "blocking_gaps": [],
            "non_blocking_gaps": [
                {
                    "gap_id": "gap-shared-infra",
                    "status": "reportable_unresolved",
                    "priority": "medium",
                    "actionable_now": True,
                    "blocks_delivery_now": False,
                    "gate_type": "reportable_limit",
                }
            ],
        },
    }
    graph = build_investigation_graph(_sample_seed(), _sample_session_state(), incident_state, finalized)
    trace = score_investigation_opportunities(
        graph,
        [
            {
                "tool_name": "check_counterevidence",
                "category": "event",
                "target_gap_ids": ["gap-shared-infra"],
                "capability_tags": ["counterevidence", "background_validation"],
                "evidence_types": ["background_or_counterevidence"],
                "input_fingerprint": "sampled-background-fp-001",
                "expected_gain": "Check whether more background context exists.",
                "recommended_params": {"asset_ids": ["ws-eng-02", "ws-eng-03"], "window_minutes": 240},
                "recommended_now": True,
            }
        ],
        budgets={"remaining_tool_calls": 1, "remaining_event_queries": 1, "remaining_intel_queries": 0},
        recent_tool_effects=[],
        top_k=1,
    )

    ranked = trace["ranked_actions"][0]
    assert len(graph["runtime_summary"]["background_event_ids"]) >= 2
    assert "background_boundary_already_sampled" in ranked["penalty_reasons"]
    assert trace["value_of_information"]["level"] == "low"
    assert trace["stop_recommendation"]["should_stop"] is True


if __name__ == "__main__":
    test_opportunity_scorer_prefers_high_value_candidate_or_counterevidence_actions()
    test_opportunity_scorer_penalizes_repeated_low_delta_actions_without_blocking_gaps()
    test_opportunity_scorer_does_not_treat_reportable_boundaries_as_blocking_work()
    test_opportunity_scorer_can_continue_high_value_reportable_boundary_work()
    test_opportunity_scorer_stops_after_repeated_reportable_boundary_progress()
    test_opportunity_scorer_stops_after_background_boundary_is_sampled()
    print("investigation planner checks passed")
