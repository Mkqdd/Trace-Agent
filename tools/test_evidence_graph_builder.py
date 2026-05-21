from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from demo_agent.incidents.evidence_graph import build_evidence_graph, build_evidence_graph_lenses  # noqa: E402


def _sample_source_bundle() -> dict:
    return {
        "case_header": {
            "case_id": "sample-case",
            "verdict_status": "confirmed",
            "severity": "high",
        },
        "source_counts": {"events": 3, "actions": 1},
    }


def _sample_fact_catalog() -> list[dict]:
    return [
        {
            "fact_id": "fact:event:001",
            "source_id": "event:evt-001",
            "fact_type": "event",
            "status": "confirmed",
            "time": "2026-07-14 01:10:00 UTC",
            "asset": "host-a",
            "objects": ["c2.example", "203.0.113.10"],
            "summary_line": "host-a connected to c2.example / 203.0.113.10.",
            "exact_fact_text": "host-a connected to c2.example / 203.0.113.10.",
            "reporting_focus": "主支撑事件",
            "boundary_note": "",
            "candidate_or_boundary": False,
        },
        {
            "fact_id": "fact:event:002",
            "source_id": "event:evt-002",
            "fact_type": "event",
            "status": "candidate",
            "time": "2026-07-14 01:39:20 UTC",
            "asset": "host-b",
            "objects": ["host-c"],
            "summary_line": "host-b had a candidate remote event toward host-c.",
            "exact_fact_text": "host-b had a candidate remote event toward host-c.",
            "reporting_focus": "候选扩线",
            "boundary_note": "needs independent validation",
            "candidate_or_boundary": True,
        },
        {
            "fact_id": "fact:gap:001",
            "source_id": "gap:host-command-line",
            "fact_type": "gap",
            "status": "open",
            "summary_line": "Full command line is missing.",
            "exact_fact_text": "Full command line is missing.",
            "reporting_focus": "未闭合缺口",
            "boundary_note": "limits execution conclusion",
            "candidate_or_boundary": True,
        },
        {
            "fact_id": "fact:action:001",
            "source_id": "action:collect-command-line",
            "fact_type": "action",
            "status": "recommended",
            "asset": "host-a",
            "objects": ["rundll32.exe"],
            "summary_line": "Collect full rundll32.exe command line.",
            "exact_fact_text": "Collect full rundll32.exe command line.",
            "reporting_focus": "处置建议",
            "boundary_note": "",
            "candidate_or_boundary": False,
        },
    ]


def test_build_evidence_graph_preserves_fact_provenance() -> None:
    graph = build_evidence_graph(_sample_source_bundle(), _sample_fact_catalog())

    assert graph["schema_version"] == "report-evidence-graph-v1"
    assert graph["case_header"]["case_id"] == "sample-case"
    assert graph["graph_stats"]["fact_count"] == 4
    assert graph["graph_stats"]["node_count"] >= 6
    assert graph["graph_stats"]["edge_count"] >= 3

    node_ids = {node["node_id"] for node in graph["nodes"]}
    assert "asset:host-a" in node_ids
    assert "asset:host-c" in node_ids
    assert "domain:c2.example" in node_ids
    assert "ip:203.0.113.10" in node_ids

    for node in graph["nodes"]:
        assert node["node_id"]
        assert node["node_type"]
        assert node["label"]
        assert node["fact_ids"] or node["source_ids"]

    for edge in graph["edges"]:
        assert edge["edge_id"]
        assert edge["source"] in node_ids
        assert edge["target"] in node_ids
        assert edge["relation"]
        assert edge["fact_ids"] or edge["source_ids"]


def test_build_evidence_graph_lenses_separate_confirmed_candidate_gap_and_actions() -> None:
    graph = build_evidence_graph(_sample_source_bundle(), _sample_fact_catalog())
    lenses = build_evidence_graph_lenses(graph)

    assert lenses["schema_version"] == "report-evidence-graph-lenses-v1"
    assert "main_chain" in lenses["lenses"]
    assert "candidate_expansion" in lenses["lenses"]
    assert "open_gaps" in lenses["lenses"]
    assert "actions" in lenses["lenses"]

    candidate = lenses["lenses"]["candidate_expansion"]
    assert "asset:host-c" in candidate["node_ids"]
    assert candidate["boundary_policy"] == "candidate_only"

    actions = lenses["lenses"]["actions"]
    assert "fact:action:001" in actions["fact_ids"]


if __name__ == "__main__":
    test_build_evidence_graph_preserves_fact_provenance()
    test_build_evidence_graph_lenses_separate_confirmed_candidate_gap_and_actions()
    print("evidence graph builder checks passed")
