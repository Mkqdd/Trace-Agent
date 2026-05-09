from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from demo_agent.incidents.reviewer import build_delivery_decision


def _confirmed_input() -> tuple[dict, dict]:
    evidence_store = {
        "objects": [
            {
                "object_type": "asset",
                "value": "host-a",
                "current_role": "seed_asset",
                "status": "已确认",
                "in_evidence_chain": True,
            },
            {
                "object_type": "asset",
                "value": "host-b",
                "current_role": "related_asset",
                "status": "待确认",
            },
        ],
        "confirmed_events": [
            {
                "id": "event-1",
                "asset_id": "host-a",
                "stages": ["execution"],
            }
        ],
        "candidate_events": [
            {
                "id": "candidate-1",
                "asset_id": "host-b",
                "stages": ["lateral-movement"],
            }
        ],
        "coverage": {
            "seed_asset": "host-a",
            "primary_external_indicators": ["203.0.113.10"],
        },
        "gaps": [
            {
                "id": "validate_candidate_events",
                "question": "候选扩线是否应并入主事件范围？",
                "gap_type": "candidate_grounding",
                "materiality": "delivery_blocking",
                "delivery_blocking": True,
                "reportable_if_unresolved": True,
                "actionable_now": True,
                "status": "open",
            },
            {
                "id": "check_counterevidence",
                "question": "是否存在维护窗口等反证？",
                "gap_type": "counterevidence",
                "materiality": "delivery_blocking",
                "delivery_blocking": True,
                "reportable_if_unresolved": False,
                "actionable_now": True,
                "status": "open",
            },
            {
                "id": "structure_evidence",
                "question": "是否需要进一步结构化报告材料？",
                "gap_type": "report_structuring",
                "materiality": "delivery_blocking",
                "delivery_blocking": True,
                "reportable_if_unresolved": False,
                "actionable_now": True,
                "status": "open",
            },
        ],
    }
    reviewer_input = {
        "provisional_assessment": {
            "status": "confirmed_incident",
            "status_label": "确认事件",
            "confidence": 92,
            "severity": "高危",
            "rationale": ["主链存在执行阶段证据。"],
        },
        "runtime_summary": {
            "context_built": True,
            "cluster_built": True,
            "timeline_built": True,
            "scope_assessed": True,
            "counterevidence_reviewed": False,
            "supplemental_context_reviewed": False,
        },
    }
    return evidence_store, reviewer_input


def test_confirmed_main_chain_keeps_delivery_with_reportable_boundaries() -> None:
    evidence_store, reviewer_input = _confirmed_input()

    decision = build_delivery_decision(evidence_store, reviewer_input)

    assert decision["approved"] is True
    assert decision["delivery_status"] == "confirmed_incident"
    assert decision["readiness"]["ready_for_delivery"] is True
    assert decision["blocking_gaps"] == []
    assert {item["gap_id"] for item in decision["non_blocking_gaps"]} == {
        "validate_candidate_events",
        "check_counterevidence",
        "structure_evidence",
    }
    assert {item["id"] for item in decision["readiness"]["blocking_checks"]} == set()
    non_blocking_check_ids = {
        item["id"]
        for item in decision["readiness"]["reportable_limit_checks"]
        + decision["readiness"]["reviewer_judgment_checks"]
    }
    assert non_blocking_check_ids >= {
        "candidate_events_grounded",
        "counterevidence_checked",
        "supplemental_context_reviewed",
    }


def test_missing_core_evidence_chain_still_blocks_delivery() -> None:
    evidence_store, reviewer_input = _confirmed_input()
    evidence_store["confirmed_events"] = [
        {
            "id": "event-1",
            "asset_id": "host-a",
            "stages": ["reconnaissance"],
        }
    ]

    decision = build_delivery_decision(evidence_store, reviewer_input)

    assert decision["approved"] is False
    assert decision["delivery_status"] == "needs_review"
    assert "evidence_chain_ready" in {
        item["id"] for item in decision["readiness"]["blocking_checks"]
    }


if __name__ == "__main__":
    test_confirmed_main_chain_keeps_delivery_with_reportable_boundaries()
    test_missing_core_evidence_chain_still_blocks_delivery()
    print("reviewer delivery decision checks passed")
