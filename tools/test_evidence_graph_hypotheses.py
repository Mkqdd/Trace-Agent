from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from demo_agent.incidents.evidence_graph import build_hypothesis_board  # noqa: E402


def test_hypothesis_board_separates_confirmed_candidate_and_benign_explanations() -> None:
    graph = {
        "schema_version": "report-evidence-graph-v1",
        "nodes": [
            {
                "node_id": "fact:confirmed",
                "node_type": "fact",
                "label": "confirmed",
                "boundary": False,
                "fact_ids": ["fact:confirmed"],
                "source_ids": ["event:1"],
                "roles": ["主支撑事件"],
            },
            {
                "node_id": "fact:candidate",
                "node_type": "fact",
                "label": "candidate",
                "boundary": True,
                "fact_ids": ["fact:candidate"],
                "source_ids": ["event:2"],
                "roles": ["候选扩线"],
            },
            {
                "node_id": "fact:background",
                "node_type": "fact",
                "label": "background",
                "boundary": True,
                "fact_ids": ["fact:background"],
                "source_ids": ["event:3"],
                "roles": ["反证事实"],
            },
            {
                "node_id": "fact:gap",
                "node_type": "fact",
                "label": "gap",
                "boundary": True,
                "fact_ids": ["fact:gap"],
                "source_ids": ["gap:1"],
                "roles": ["未闭合缺口"],
            },
        ],
        "edges": [],
    }
    lenses = {
        "schema_version": "report-evidence-graph-lenses-v1",
        "lenses": {
            "main_chain": {"fact_ids": ["fact:confirmed"]},
            "candidate_expansion": {"fact_ids": ["fact:candidate"]},
            "counterevidence": {"fact_ids": ["fact:background"]},
            "open_gaps": {"fact_ids": ["fact:gap"]},
            "actions": {"fact_ids": []},
        },
    }

    board = build_hypothesis_board(graph, lenses)

    assert board["schema_version"] == "report-hypothesis-board-v1"
    names = [item["hypothesis_id"] for item in board["hypotheses"]]
    assert "confirmed_main_chain" in names
    assert "candidate_expansion" in names
    assert "benign_or_shared_infra_alternative" in names
    assert "insufficient_evidence_limits" in names

    confirmed = next(item for item in board["hypotheses"] if item["hypothesis_id"] == "confirmed_main_chain")
    assert confirmed["supporting_fact_ids"] == ["fact:confirmed"]
    assert confirmed["claim_policy"] == "can_support_current_verdict_only"

    candidate = next(item for item in board["hypotheses"] if item["hypothesis_id"] == "candidate_expansion")
    assert candidate["supporting_fact_ids"] == ["fact:candidate"]
    assert candidate["claim_policy"] == "candidate_not_confirmed"


if __name__ == "__main__":
    test_hypothesis_board_separates_confirmed_candidate_and_benign_explanations()
    print("evidence graph hypothesis checks passed")
