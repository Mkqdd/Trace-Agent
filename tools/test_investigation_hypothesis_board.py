from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from demo_agent.incidents.agent import (  # noqa: E402
    INVESTIGATOR_SYSTEM_PROMPT,
    _build_agent_context_v1,
    _finalize_runtime_state,
    _initial_incident_state,
    _initial_session_state,
    _reviewer_context_view,
)


def _sample_seed() -> dict:
    return {
        "event_time": "2026-07-14 01:10:00",
        "src": {"ip": "10.0.0.5"},
        "dst": {"ip": "203.0.113.10"},
        "trigger_fingerprint": {"type": "JA4", "value": "t13d-demo"},
        "enrichment": {"info": "sample suspicious traffic"},
    }


def _sample_budgets() -> dict:
    return {
        "max_steps": 4,
        "max_tool_calls": 4,
        "max_event_queries": 2,
        "max_intel_queries": 2,
        "max_runtime_s": 60,
    }


def _sample_policy() -> dict:
    return {
        "requested_mode": "llm_agent",
        "effective_mode": "llm_agent",
        "policy_mode": "llm_open_agent",
        "llm_available": True,
    }


def test_initial_session_state_has_advisory_hypothesis_board() -> None:
    session_state = _initial_session_state(_sample_seed(), _sample_budgets(), _sample_policy())

    assert session_state["hypothesis_board"] == {
        "schema_version": "investigation-hypothesis-board-v1",
        "active": [],
        "closed": [],
        "last_updated_round": 0,
    }


def test_hypothesis_board_is_visible_to_investigator_and_reviewer_contexts() -> None:
    seed = _sample_seed()
    session_state = _initial_session_state(seed, _sample_budgets(), _sample_policy())
    session_state["hypothesis_board"]["active"].append(
        {
            "hypothesis_id": "shared_infra_alternative",
            "claim": "Shared infrastructure could explain part of the signal.",
            "status": "open",
        }
    )
    incident_state = _initial_incident_state(seed)
    finalized = _finalize_runtime_state(seed, session_state, incident_state)

    agent_context = _build_agent_context_v1(seed, session_state, incident_state, finalized, tool_catalog=[])
    reviewer_context = _reviewer_context_view(seed, session_state, incident_state, finalized)

    assert agent_context["hypothesis_board"]["active"][0]["hypothesis_id"] == "shared_infra_alternative"
    assert reviewer_context["hypothesis_board"]["active"][0]["hypothesis_id"] == "shared_infra_alternative"


def test_investigator_prompt_treats_hypothesis_board_as_advisory_disambiguation() -> None:
    assert "优先选择最能区分这些假设的工具调用" in INVESTIGATOR_SYSTEM_PROMPT
    assert "共享基础设施" in INVESTIGATOR_SYSTEM_PROMPT
    assert "不能因为 hypothesis_board 仍有开放候选就自动拒绝 finish" in INVESTIGATOR_SYSTEM_PROMPT


if __name__ == "__main__":
    test_initial_session_state_has_advisory_hypothesis_board()
    test_hypothesis_board_is_visible_to_investigator_and_reviewer_contexts()
    test_investigator_prompt_treats_hypothesis_board_as_advisory_disambiguation()
    print("investigation hypothesis board checks passed")
