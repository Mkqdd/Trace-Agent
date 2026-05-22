from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from demo_agent.incidents.investigation_graph import (  # noqa: E402
    build_investigation_graph,
    build_investigation_hypothesis_board,
)


def _sample_seed() -> dict:
    return {
        "event_time": "2026-07-14 01:10:00",
        "src": {"ip": "10.0.0.5"},
        "dst": {"ip": "203.0.113.10"},
        "trigger_fingerprint": {"type": "JA4", "value": "t13d-demo"},
    }


def _sample_session_state() -> dict:
    return {
        "step_index": 3,
        "working_hypotheses": [
            {"id": "primary", "kind": "primary", "title": "疑似外联事件", "score": 4, "status": "open"},
            {"id": "secondary", "kind": "secondary", "title": "共享基础设施或第二跳扩线", "score": 2, "status": "open"},
        ],
        "tool_history": [
            {
                "step_index": 1,
                "tool_name": "search_seed_context",
                "input_fingerprint": "seed-fp-001",
                "output_delta": {"summary": "建立了最小上下文", "novelty_score": 3},
            }
        ],
        "hypothesis_board": {
            "schema_version": "investigation-hypothesis-board-v2",
            "last_updated_round": 1,
            "hypotheses": [],
        },
    }


def _sample_incident_state() -> dict:
    return {
        "known_events": {},
        "evidence_ledger": [
            {
                "observation_id": "obs-1",
                "relation": "supporting",
                "summary": "seed host connected to a suspicious external endpoint",
                "event_ids": ["evt-seed"],
            },
            {
                "observation_id": "obs-2",
                "relation": "candidate",
                "summary": "candidate rundll32 execution without full command line",
                "event_ids": ["evt-candidate"],
            },
            {
                "observation_id": "obs-3",
                "relation": "counterevidence",
                "summary": "scheduled SCCM activity could explain part of the signal",
                "event_ids": ["evt-background"],
            },
        ],
        "gap_ledger": [
            {
                "id": "gap-command-line",
                "question": "Need the full rundll32 command line.",
                "status": "open",
                "delivery_blocking": True,
                "actionable_now": True,
                "blocks_delivery_now": True,
                "priority": "high",
                "actionable_tools": ["expand_asset_scope"],
                "status_reason": "Host command line remains missing.",
            },
            {
                "id": "gap-shared-infra",
                "question": "Need to separate shared infrastructure from malicious infrastructure.",
                "status": "open",
                "delivery_blocking": False,
                "actionable_now": True,
                "blocks_delivery_now": False,
                "priority": "medium",
                "actionable_tools": ["check_counterevidence"],
                "status_reason": "Shared infrastructure is still ambiguous.",
            },
        ],
        "counterevidence": [
            {
                "source_id": "counterevidence:sccm-window",
                "status": "background",
                "summary_line": "SCCM maintenance window overlaps the incident period.",
                "report_scope_role": "background_event",
            }
        ],
        "entities": {
            "seed_asset": "ws-eng-02",
            "assets": ["ws-eng-02", "ws-eng-03"],
            "domains": ["cdn-notify-edge.net"],
            "external_ips": ["203.0.113.10"],
            "internal_ips": ["10.0.0.5"],
            "families": ["rundll32"],
        },
        "scope": {
            "confirmed_assets": ["ws-eng-02"],
            "candidate_assets": ["ws-eng-03"],
            "external_infrastructure": ["203.0.113.10", "cdn-notify-edge.net"],
        },
        "observations": [],
        "timeline": [],
    }


def _sample_finalized() -> dict:
    return {
        "annotated_events": [
            {
                "id": "evt-seed",
                "role": "seed",
                "status": "confirmed",
                "summary": "ws-eng-02 connected to 203.0.113.10.",
                "ts": "2026-07-14 01:10:00",
                "asset_id": "ws-eng-02",
                "dst_ip": "203.0.113.10",
                "domain": "cdn-notify-edge.net",
                "grounding_status": "confirmed_supporting",
                "observation_ids": ["obs-1"],
            },
            {
                "id": "evt-candidate",
                "role": "candidate",
                "status": "candidate",
                "summary": "ws-eng-02 launched rundll32.exe but the full command line is missing.",
                "ts": "2026-07-14 01:32:00",
                "asset_id": "ws-eng-02",
                "grounding_status": "grounded_but_unconfirmed",
                "observation_ids": ["obs-2"],
            },
            {
                "id": "evt-background",
                "role": "counterevidence",
                "status": "background",
                "summary": "SCCM maintenance activity overlapped the incident window.",
                "ts": "2026-07-14 01:20:00",
                "asset_id": "ws-eng-03",
                "grounding_status": "context_only",
                "observation_ids": ["obs-3"],
            },
        ],
        "gap_ledger": _sample_incident_state()["gap_ledger"],
        "decision_basis": {"positive_observation_ids": ["obs-1"], "counter_observation_ids": ["obs-3"]},
        "delivery_verdict": {"status": "confirmed_incident", "confidence": 82, "approved": True},
        "readiness": {"ready_for_delivery": True, "blocking_checks": []},
        "entities": _sample_incident_state()["entities"],
        "scope": _sample_incident_state()["scope"],
        "timeline": [],
        "evidence_ledger": _sample_incident_state()["evidence_ledger"],
    }


def test_build_investigation_graph_keeps_boundary_states_and_provenance() -> None:
    graph = build_investigation_graph(
        _sample_seed(),
        _sample_session_state(),
        _sample_incident_state(),
        _sample_finalized(),
    )

    assert graph["schema_version"] == "investigation-graph-v1"
    node_ids = {node["node_id"] for node in graph["nodes"]}
    assert "event:evt-seed" in node_ids
    assert "event:evt-candidate" in node_ids
    assert "event:evt-background" in node_ids
    assert "asset:ws-eng-02" in node_ids
    assert "indicator:203.0.113.10" in node_ids
    assert "indicator:cdn-notify-edge.net" in node_ids

    candidate_node = next(node for node in graph["nodes"] if node["node_id"] == "event:evt-candidate")
    background_node = next(node for node in graph["nodes"] if node["node_id"] == "event:evt-background")
    assert candidate_node["boundary"] is True
    assert background_node["boundary"] is True
    assert candidate_node["observation_ids"] == ["obs-2"]
    assert background_node["observation_ids"] == ["obs-3"]

    graph_board = graph["hypothesis_board"]
    hypothesis_ids = [item["hypothesis_id"] for item in graph_board["hypotheses"]]
    assert "confirmed_main_chain" in hypothesis_ids
    assert "candidate_spread" in hypothesis_ids
    assert "benign_or_shared_infra_alternative" in hypothesis_ids
    assert "insufficient_evidence_limits" in hypothesis_ids

    confirmed = next(item for item in graph_board["hypotheses"] if item["hypothesis_id"] == "confirmed_main_chain")
    assert confirmed["status"] in {"supported", "closed"}
    assert "evt-seed" in confirmed["support_event_ids"]

    candidate = next(item for item in graph_board["hypotheses"] if item["hypothesis_id"] == "candidate_spread")
    assert "evt-candidate" in candidate["support_event_ids"]
    assert candidate["status"] in {"supported", "open"}


def test_build_investigation_hypothesis_board_distinguishes_support_refute_and_limits() -> None:
    graph = build_investigation_graph(
        _sample_seed(),
        _sample_session_state(),
        _sample_incident_state(),
        _sample_finalized(),
    )
    board = build_investigation_hypothesis_board(graph)

    assert board["schema_version"] == "investigation-hypothesis-board-v2"
    confirmed = next(item for item in board["hypotheses"] if item["hypothesis_id"] == "confirmed_main_chain")
    candidate = next(item for item in board["hypotheses"] if item["hypothesis_id"] == "candidate_spread")
    benign = next(item for item in board["hypotheses"] if item["hypothesis_id"] == "benign_or_shared_infra_alternative")
    limits = next(item for item in board["hypotheses"] if item["hypothesis_id"] == "insufficient_evidence_limits")

    assert confirmed["support_event_ids"] == ["evt-seed"]
    assert "evt-background" in benign["support_event_ids"]
    assert "evt-background" in confirmed["refute_event_ids"]
    assert candidate["support_event_ids"] == ["evt-candidate"]
    assert "gap-command-line" in limits["gap_ids"]
    assert limits["candidate_action_ids"] == ["action:expand_asset_scope"]


if __name__ == "__main__":
    test_build_investigation_graph_keeps_boundary_states_and_provenance()
    test_build_investigation_hypothesis_board_distinguishes_support_refute_and_limits()
    print("investigation graph checks passed")
