from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from demo_agent.incidents.report_inputs import build_report_inputs  # noqa: E402


def test_process_execution_recommendation_names_concrete_host_fields() -> None:
    evidence_store = {
        "coverage": {
            "seed_asset": "ws-eng-02",
            "primary_external_indicators": ["203.0.113.77"],
        },
        "confirmed_events": [
            {
                "id": "evt-process",
                "role": "supporting",
                "asset_id": "ws-eng-02",
                "kind": "process",
                "ts": "2026-07-14T01:18:00Z",
                "summary": "Suspicious rundll32.exe launched a loader DLL from a user-writable path shortly after the beacon sequence.",
                "stages": ["execution"],
                "classification": "suspicious",
            }
        ],
        "candidate_events": [],
        "objects": [],
        "hypotheses": {},
        "gaps": [],
    }
    delivery_decision = {
        "delivery_status": "confirmed_incident",
        "confirmed_scope": ["ws-eng-02"],
        "candidate_scope": [],
        "next_best_questions": [],
    }

    report_inputs = build_report_inputs(evidence_store, delivery_decision)
    recommendations = list(report_inputs.get("recommendations") or [])

    host_actions = [item for item in recommendations if "rundll32.exe" in item]
    assert host_actions, recommendations
    action = host_actions[0]
    assert "ws-eng-02" in action
    assert "2026-07-14 01:18:00 UTC" in action
    assert "完整命令行" in action
    assert "父进程" in action
    assert "执行用户" in action
    assert "模块/库" in action
    assert "DLL" in action
    assert "哈希" in action


if __name__ == "__main__":
    test_process_execution_recommendation_names_concrete_host_fields()
    print("report action guidance checks passed")
