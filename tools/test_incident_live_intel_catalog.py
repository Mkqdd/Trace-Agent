from __future__ import annotations

import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from demo_agent.incidents.agent import _available_tool_catalog  # noqa: E402


def test_serpapi_key_exposes_external_context_search_without_extra_flag() -> None:
    previous_serpapi = os.environ.get("SERPAPI_API_KEY")
    previous_live = os.environ.get("INCIDENT_AGENT_LIVE_INTEL")
    os.environ["SERPAPI_API_KEY"] = "test-key"
    os.environ.pop("INCIDENT_AGENT_LIVE_INTEL", None)
    try:
        seed_event = {
            "src": {"ip": "10.0.0.5"},
            "dst": {"ip": "203.0.113.77"},
            "trigger_fingerprint": {"type": "JA4", "value": "t13d-test"},
            "enrichment": {"info": "Suspected beacon family"},
        }
        session_state = {
            "decision_mode": "llm_agent",
            "tool_runs": [],
            "budgets": {"remaining_intel_queries": 3, "remaining_event_queries": 3},
        }
        incident_state = {
            "provisional_verdict": {"status": "confirmed_incident"},
            "context_bundle": {"minimal_event_count": 3},
            "entities": {"assets": ["host-a"], "related_assets": []},
            "scope": {"primary_external_indicators": ["203.0.113.77"]},
            "summary": {"stage_labels": ["命令与控制"]},
            "observations": [{"tool_name": "search_seed_context"}],
            "gap_ledger": [],
        }

        tool_names = [
            str(item.get("tool_name") or "")
            for item in _available_tool_catalog(seed_event, session_state, incident_state)
        ]
    finally:
        if previous_serpapi is None:
            os.environ.pop("SERPAPI_API_KEY", None)
        else:
            os.environ["SERPAPI_API_KEY"] = previous_serpapi
        if previous_live is None:
            os.environ.pop("INCIDENT_AGENT_LIVE_INTEL", None)
        else:
            os.environ["INCIDENT_AGENT_LIVE_INTEL"] = previous_live

    assert "technical_source_search" in tool_names


def test_serpapi_auto_mode_does_not_change_heuristic_catalog() -> None:
    previous_serpapi = os.environ.get("SERPAPI_API_KEY")
    previous_live = os.environ.get("INCIDENT_AGENT_LIVE_INTEL")
    os.environ["SERPAPI_API_KEY"] = "test-key"
    os.environ.pop("INCIDENT_AGENT_LIVE_INTEL", None)
    try:
        seed_event = {
            "src": {"ip": "10.0.0.5"},
            "dst": {"ip": "203.0.113.77"},
            "trigger_fingerprint": {"type": "JA4", "value": "t13d-test"},
            "enrichment": {"info": "Suspected beacon family"},
        }
        session_state = {
            "decision_mode": "heuristic",
            "tool_runs": [],
            "budgets": {"remaining_intel_queries": 3, "remaining_event_queries": 3},
        }
        incident_state = {
            "provisional_verdict": {"status": "confirmed_incident"},
            "context_bundle": {"minimal_event_count": 3},
            "entities": {"assets": ["host-a"], "related_assets": []},
            "scope": {"primary_external_indicators": ["203.0.113.77"]},
            "summary": {"stage_labels": ["命令与控制"]},
            "observations": [{"tool_name": "search_seed_context"}],
            "gap_ledger": [],
        }

        tool_names = [
            str(item.get("tool_name") or "")
            for item in _available_tool_catalog(seed_event, session_state, incident_state)
        ]
    finally:
        if previous_serpapi is None:
            os.environ.pop("SERPAPI_API_KEY", None)
        else:
            os.environ["SERPAPI_API_KEY"] = previous_serpapi
        if previous_live is None:
            os.environ.pop("INCIDENT_AGENT_LIVE_INTEL", None)
        else:
            os.environ["INCIDENT_AGENT_LIVE_INTEL"] = previous_live

    assert "technical_source_search" not in tool_names


if __name__ == "__main__":
    test_serpapi_key_exposes_external_context_search_without_extra_flag()
    test_serpapi_auto_mode_does_not_change_heuristic_catalog()
    print("incident live intel catalog checks passed")
