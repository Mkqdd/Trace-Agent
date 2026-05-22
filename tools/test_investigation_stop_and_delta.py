from __future__ import annotations

import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from demo_agent.incidents.agent import (  # noqa: E402
    DEFAULT_BUDGETS,
    _fallback_post_action_review,
    _review_finish_request,
    _finish_review_fallback,
    _stop_decision,
    STOP_REASON_DELIVERY_READY,
)
from tools.test_investigation_graph import _sample_seed  # noqa: E402


class _AlwaysDeliverableFinishLLM:
    def invoke(self, messages):
        del messages
        return type(
            "Resp",
            (),
            {
                "content": (
                    '{"decision":"deliverable","deliverable_now":true,'
                    '"blocking_gaps":[],"next_round_feedback":[],'
                    '"stop_recommendation":{"should_stop":true,"reason":"ready"},'
                    '"reason":"ready"}'
                )
            },
        )()


def test_stop_gate_does_not_stop_ready_case_when_high_value_action_remains() -> None:
    session_state = {
        "step_index": 2,
        "decision_mode": "llm_agent",
        "budgets": {**DEFAULT_BUDGETS, "remaining_steps": 3, "remaining_tool_calls": 3},
        "value_of_information": {
            "level": "high",
            "best_action": "check_counterevidence",
            "best_action_score": 7,
        },
    }
    finalized = {
        "readiness": {"ready_for_delivery": True, "blocking_checks": []},
        "delivery_decision": {
            "approved": True,
            "readiness": {"ready_for_delivery": True, "blocking_checks": []},
            "blocking_gaps": [],
            "non_blocking_gaps": [],
        },
        "gap_ledger": [],
    }

    decision = _stop_decision(_sample_seed(), time.perf_counter(), session_state, {}, finalized)

    assert decision["stop"] is False
    assert decision["reason"] == "continue"


def test_stop_gate_stops_ready_case_when_only_boundary_followups_remain() -> None:
    session_state = {
        "step_index": 2,
        "decision_mode": "llm_agent",
        "budgets": {**DEFAULT_BUDGETS, "remaining_steps": 3, "remaining_tool_calls": 2},
        "value_of_information": {
            "level": "low",
            "best_action": "extract_claim_candidates_from_page",
            "best_action_score": 2,
        },
        "investigation_opportunity_trace": {
            "stop_recommendation": {
                "should_stop": True,
                "reason": "Remaining actions are low value or exhausted; unresolved items should become reportable boundaries.",
            },
            "value_of_information": {
                "level": "low",
                "best_action": "extract_claim_candidates_from_page",
                "best_action_score": 2,
            },
        },
    }
    finalized = {
        "readiness": {"ready_for_delivery": True, "blocking_checks": []},
        "delivery_decision": {
            "approved": True,
            "readiness": {"ready_for_delivery": True, "blocking_checks": []},
            "blocking_gaps": [],
            "non_blocking_gaps": [
                {
                    "gap_id": "expand_cluster_scope",
                    "question": "Boundary follow-up remains, but it should not block delivery.",
                    "status": "unresolved_but_deliverable",
                    "delivery_blocking": True,
                    "blocks_delivery_now": False,
                    "actionable_now": True,
                }
            ],
        },
        "gap_ledger": [
            {
                "id": "expand_cluster_scope",
                "question": "Boundary follow-up remains, but it should not block delivery.",
                "status": "stalled",
                "delivery_blocking": True,
                "reportable_if_unresolved": True,
                "actionable_now": False,
            }
        ],
    }

    decision = _stop_decision(_sample_seed(), time.perf_counter(), session_state, {}, finalized)

    assert decision["stop"] is True
    assert decision["reason"] == STOP_REASON_DELIVERY_READY


def test_finish_review_defers_ready_case_when_high_value_action_remains() -> None:
    session_state = {
        "step_index": 2,
        "budgets": {**DEFAULT_BUDGETS, "remaining_steps": 3, "remaining_tool_calls": 2},
        "value_of_information": {
            "level": "high",
            "best_action": "expand_asset_scope",
            "best_action_score": 8,
        },
    }
    finalized = {
        "readiness": {"ready_for_delivery": True, "blocking_checks": []},
        "delivery_decision": {
            "approved": True,
            "readiness": {"ready_for_delivery": True, "blocking_checks": []},
            "blocking_gaps": [],
            "non_blocking_gaps": [],
        },
        "gap_ledger": [],
    }

    review = _review_finish_request(
        _AlwaysDeliverableFinishLLM(),
        _sample_seed(),
        session_state,
        {},
        finalized,
        {"action_type": "finish", "reason": "ready"},
    )

    assert review["decision"] == "not_deliverable"
    assert review["deliverable_now"] is False
    assert (review.get("stop_recommendation") or {}).get("should_stop") is False
    assert review["next_action"]["action_type"] == "none"


def test_finish_review_fallback_defers_ready_case_when_high_value_action_remains() -> None:
    session_state = {
        "step_index": 2,
        "budgets": {**DEFAULT_BUDGETS, "remaining_steps": 3, "remaining_tool_calls": 2},
        "value_of_information": {
            "level": "medium",
            "best_action": "check_counterevidence",
            "best_action_score": 6,
        },
    }
    finalized = {
        "readiness": {"ready_for_delivery": True, "blocking_checks": []},
        "delivery_decision": {
            "approved": True,
            "readiness": {"ready_for_delivery": True, "blocking_checks": []},
            "blocking_gaps": [],
            "non_blocking_gaps": [
                {
                    "gap_id": "counterevidence-boundary",
                    "question": "There is still a meaningful counterevidence follow-up.",
                    "status": "open",
                    "delivery_blocking": False,
                    "blocks_delivery_now": False,
                    "actionable_now": True,
                }
            ],
        },
        "gap_ledger": [],
    }

    review = _finish_review_fallback(
        _sample_seed(),
        session_state,
        {},
        finalized,
        {"action_type": "finish", "reason": "ready"},
    )

    assert review["decision"] == "not_deliverable"
    assert review["deliverable_now"] is False
    assert review["next_round_feedback"]
    assert review["stop_recommendation"]["should_stop"] is False


def test_fallback_post_action_review_emits_standard_delta_labels() -> None:
    review = _fallback_post_action_review(
        session_state={"step_index": 3},
        finalized_after={
            "acceptance_state": {"deliverable_now": False, "material_gaps": []},
            "gap_ledger": [],
        },
        action={"tool_name": "ground_candidate_event", "target_gap_ids": ["candidate_grounding"]},
        observation={
            "relation": "candidate",
            "output_delta": {
                "new_event_count": 1,
                "new_asset_count": 1,
                "closed_candidate_event_count": 1,
                "closed_gap_count": 1,
                "closed_gap_ids": ["candidate_grounding"],
                "novelty_score": 4,
            },
        },
    )

    assert "new_candidate_event" in review["delta_labels"]
    assert "candidate_grounded" in review["delta_labels"]
    assert "scope_changed" in review["delta_labels"]
    assert "actionability_improved" in review["delta_labels"]
    assert "no_material_delta" not in review["delta_labels"]


if __name__ == "__main__":
    test_stop_gate_does_not_stop_ready_case_when_high_value_action_remains()
    test_finish_review_defers_ready_case_when_high_value_action_remains()
    test_finish_review_fallback_defers_ready_case_when_high_value_action_remains()
    test_fallback_post_action_review_emits_standard_delta_labels()
    print("investigation stop and delta checks passed")
