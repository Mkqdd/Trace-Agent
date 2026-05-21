from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from demo_agent.incidents.agent import (
    DECISION_MODE_LLM_AGENT,
    STOP_REASON_DELIVERY_READY,
    STOP_REASON_RUNTIME_BUDGET,
    _stop_decision,
    run_incident_agent_case,
)
from demo_agent.utils.io import load_json


FIXTURE_DIR = ROOT / "fixtures" / "incidents" / "web_initial_access_without_execution"


class FakeResp:
    def __init__(self, content: str) -> None:
        self.content = content


def _extract_section(text: str, start_marker: str, end_marker: Optional[str] = None) -> Dict[str, Any]:
    start = text.index(start_marker) + len(start_marker)
    end = text.index(end_marker, start) if end_marker else len(text)
    return json.loads(text[start:end].strip())


def _system_text(messages: List[Any]) -> str:
    return str(getattr(messages[0], "content", "") or "")


def _user_text(messages: List[Any]) -> str:
    return str(getattr(messages[-1], "content", "") or "")


class FakeProtocolSmokeLLM:
    def __init__(self) -> None:
        self.investigator_calls = 0
        self.post_action_reviews = 0
        self.finish_reviews = 0
        self.used_fingerprints: set[tuple[str, str]] = set()
        self.investigator_inputs: List[str] = []

    def invoke(self, messages: List[Any]) -> FakeResp:
        system = _system_text(messages)
        user = _user_text(messages)
        if "post-action reviewer" in system:
            return self._post_action_review(user)
        if "finish reviewer" in system:
            return self._finish_review(user)
        if "investigator agent" in system:
            return self._investigate(user)
        raise AssertionError(f"unexpected system prompt: {system[:120]}")

    def _post_action_review(self, user: str) -> FakeResp:
        self.post_action_reviews += 1
        after_context = _extract_section(user, "after_context:\n")
        deliverable = bool(((after_context.get("acceptance_state") or {}).get("deliverable_now")))
        return FakeResp(
            json.dumps(
                {
                    "review_result": "stop_ready" if deliverable else "continue",
                    "material_delta": "medium",
                    "closed_gap_ids": [],
                    "next_round_feedback": [] if deliverable else ["上一轮已审查，下一轮继续围绕未闭合 gap 收敛。"],
                    "constraints": [],
                    "stop_recommendation": {
                        "should_stop": deliverable,
                        "reason": "达到交付门槛。" if deliverable else "仍需继续。",
                    },
                    "reason": "post-action protocol smoke",
                },
                ensure_ascii=False,
            )
        )

    def _finish_review(self, user: str) -> FakeResp:
        self.finish_reviews += 1
        review_context = _extract_section(user, "review_context:\n", "\n\nfinish_request:")
        acceptance = review_context.get("acceptance_state") or {}
        deliverable = bool(acceptance.get("deliverable_now"))
        blocking_gaps = []
        if not deliverable:
            for gap in list(acceptance.get("material_gaps") or [])[:1]:
                blocking_gaps.append(
                    {
                        "gap_id": str(gap.get("id") or gap.get("gap_id") or "remaining_gap"),
                        "reason": str(gap.get("question") or "仍有未闭合 gap"),
                    }
                )
        return FakeResp(
            json.dumps(
                {
                    "decision": "deliverable" if deliverable else "not_deliverable",
                    "deliverable_now": deliverable,
                    "blocking_gaps": blocking_gaps,
                    "next_round_feedback": [] if deliverable else ["finish 尚未达到交付门槛。"],
                    "stop_recommendation": {
                        "should_stop": deliverable,
                        "reason": "finish review smoke",
                    },
                    "reason": "finish review smoke",
                },
                ensure_ascii=False,
            )
        )

    def _investigate(self, user: str) -> FakeResp:
        self.investigator_calls += 1
        assert "agent_context:\n" in user
        assert "runtime:\n" not in user
        self.investigator_inputs.append(user)

        context = _extract_section(user, "agent_context:\n")
        deliverable = bool(((context.get("gap_view") or {}).get("primary_focus") or {}).get("deliverable_now"))
        if deliverable or self.investigator_calls >= 5:
            return FakeResp('{"action":"finish","reason":"当前上下文显示可尝试结束。"}')

        preferred_tools = [
            "search_seed_context",
            "check_counterevidence",
            "extract_claim_candidates_from_page",
            "search_related_events",
            "ground_candidate_event",
            "expand_asset_scope",
            "extract_entities_from_page",
        ]
        options = list(context.get("action_options") or [])
        chosen: Dict[str, Any] = {}
        for tool_name in preferred_tools:
            for option in options:
                fingerprint = str(option.get("input_fingerprint") or "")
                key = (str(option.get("tool_name") or ""), fingerprint)
                if option.get("tool_name") == tool_name and key not in self.used_fingerprints:
                    chosen = dict(option)
                    self.used_fingerprints.add(key)
                    break
            if chosen:
                break
        if not chosen and options:
            chosen = dict(options[0])
        if not chosen:
            return FakeResp('{"action":"finish","reason":"没有可安全构造的动作。"}')

        return FakeResp(
            json.dumps(
                {
                    "action": "tool",
                    "tool_name": chosen.get("tool_name"),
                    "params": chosen.get("safe_params_hint") or {},
                    "target_gap_ids": chosen.get("target_gap_ids") or [],
                    "reason": "protocol smoke 选择可行动作",
                    "why_not_finish": "仍需先缩小当前 gap。",
                },
                ensure_ascii=False,
            )
        )


class FakePreflightBlockSmokeLLM(FakeProtocolSmokeLLM):
    def _investigate(self, user: str) -> FakeResp:
        self.investigator_calls += 1
        assert "agent_context:\n" in user
        assert "runtime:\n" not in user
        self.investigator_inputs.append(user)
        if self.investigator_calls == 1:
            return FakeResp(
                json.dumps(
                    {
                        "action": "tool",
                        "tool_name": "search_seed_context",
                        "params": {},
                        "target_gap_ids": ["gap-that-does-not-exist"],
                        "reason": "故意输出未知 gap id，验证 preflight block 不会被计为 reviewer replacement。",
                        "why_not_finish": "protocol smoke",
                    },
                    ensure_ascii=False,
                )
            )
        return FakeResp('{"action":"finish","reason":"结束 preflight block smoke。"}')


def _run_protocol_smoke() -> Dict[str, Any]:
    llm = FakeProtocolSmokeLLM()
    result = run_incident_agent_case(
        seed_alert=load_json(FIXTURE_DIR / "seed_alert.json"),
        fixture_dir=str(FIXTURE_DIR),
        llm=llm,
        llm_runtime={"enabled": True, "provider": "fake"},
        budgets={
            "max_steps": 6,
            "max_tool_calls": 8,
            "max_event_queries": 5,
            "max_intel_queries": 5,
            "max_runtime_s": 60,
        },
        decision_mode="llm_agent",
    )
    incident = result.get("incident") or {}
    metrics = result.get("run_metrics") or incident.get("run_metrics") or {}
    reviewer_history = list(incident.get("reviewer_history") or [])

    assert llm.investigator_calls >= 1
    assert llm.post_action_reviews >= 1
    assert metrics.get("reviewer_replacement_count") == 0
    assert metrics.get("stop_reason_in_enum") is True
    assert any(item.get("role") == "post_action_reviewer" for item in reviewer_history)
    assert all(
        item.get("role") != "finish_reviewer" or (item.get("next_action") or {}).get("action_type") != "tool"
        for item in reviewer_history
    )
    return {
        "ok": True,
        "investigator_calls": llm.investigator_calls,
        "post_action_reviews": llm.post_action_reviews,
        "finish_reviews": llm.finish_reviews,
        "stop_reason": metrics.get("stop_reason"),
        "reviewer_replacement_count": metrics.get("reviewer_replacement_count"),
        "stop_reason_in_enum": metrics.get("stop_reason_in_enum"),
    }


def _run_preflight_block_smoke() -> Dict[str, Any]:
    llm = FakePreflightBlockSmokeLLM()
    result = run_incident_agent_case(
        seed_alert=load_json(FIXTURE_DIR / "seed_alert.json"),
        fixture_dir=str(FIXTURE_DIR),
        llm=llm,
        llm_runtime={"enabled": True, "provider": "fake"},
        budgets={
            "max_steps": 2,
            "max_tool_calls": 4,
            "max_event_queries": 3,
            "max_intel_queries": 3,
            "max_runtime_s": 60,
        },
        decision_mode="llm_agent",
    )
    incident = result.get("incident") or {}
    metrics = result.get("run_metrics") or incident.get("run_metrics") or {}
    execution_sources = dict(metrics.get("execution_source_counts") or {})

    assert int(metrics.get("preflight_block_count") or 0) >= 1
    assert metrics.get("reviewer_replacement_count") == 0
    assert int(execution_sources.get("preflight_blocked") or 0) >= 1
    return {
        "ok": True,
        "stop_reason": metrics.get("stop_reason"),
        "preflight_block_count": metrics.get("preflight_block_count"),
        "reviewer_replacement_count": metrics.get("reviewer_replacement_count"),
        "execution_source_counts": execution_sources,
    }


def _run_stop_reason_priority_smoke() -> Dict[str, Any]:
    session_state = {
        "budgets": {
            "remaining_steps": 1,
            "remaining_tool_calls": 1,
            "remaining_event_queries": 1,
            "remaining_intel_queries": 1,
            "max_runtime_s": 0,
        },
        "step_index": 2,
        "decision_mode": DECISION_MODE_LLM_AGENT,
        "reviewer_history": [],
        "tool_history": [],
    }
    finalized = {
        "delivery_decision": {
            "approved": True,
            "blocking_gaps": [],
            "readiness": {
                "ready_for_delivery": True,
                "blocking_checks": [],
            },
        },
        "readiness": {
            "ready_for_delivery": True,
            "blocking_checks": [],
        },
        "evidence_store": {
            "gaps": [],
        },
    }
    decision = _stop_decision(
        seed_event={},
        started_at=0.0,
        session_state=session_state,
        incident_state={},
        finalized=finalized,
    )
    assert decision.get("stop") is True
    assert decision.get("reason") == STOP_REASON_DELIVERY_READY
    assert STOP_REASON_RUNTIME_BUDGET in list(decision.get("secondary_stop_reasons") or [])
    return {
        "ok": True,
        "stop_reason": decision.get("reason"),
        "secondary_stop_reasons": decision.get("secondary_stop_reasons"),
    }


def main() -> None:
    protocol = _run_protocol_smoke()
    preflight = _run_preflight_block_smoke()
    stop_priority = _run_stop_reason_priority_smoke()
    print(
        json.dumps(
            {
                "ok": True,
                "protocol_smoke": protocol,
                "preflight_block_smoke": preflight,
                "stop_reason_priority_smoke": stop_priority,
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
