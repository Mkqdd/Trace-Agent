from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from demo_agent.incidents.agent import run_incident_agent_case
from demo_agent.utils.io import load_json


FIXTURE_DIR = ROOT / "fixtures" / "incidents" / "single_host_c2_beacon"


def _extract_section(text: str, start_marker: str, end_marker: str | None = None) -> Dict[str, Any]:
    start = text.index(start_marker) + len(start_marker)
    end = text.index(end_marker, start) if end_marker else len(text)
    return json.loads(text[start:end].strip())


def _system_text(messages: List[Any]) -> str:
    return str(getattr(messages[0], "content", "") or "")


def _extract_runtime(messages: List[Any]) -> Dict[str, Any]:
    content = str(getattr(messages[-1], "content", "") or "")
    return _extract_section(content, "runtime:\n", "\n\ntool_catalog:\n")


class FakeResp:
    def __init__(self, content: str):
        self.content = content


class ScriptedHappyPathLLM:
    def __init__(self) -> None:
        self.calls = 0
        self.investigator_calls = 0
        self.reviewer_calls = 0
        self.runtimes: List[Dict[str, Any]] = []
        self.reviews: List[str] = []

    def invoke(self, messages: List[Any]) -> FakeResp:
        self.calls += 1
        system_text = _system_text(messages)
        if "delivery reviewer" in system_text:
            self.reviewer_calls += 1
            mapping = {
                1: '{"decision":"allow","deliverable_now":false,"material_gaps":[{"gap_id":"build_context","reason":"需要先建立最小上下文","actionable_now":true}],"next_action":{"action_type":"tool","tool_name":"search_seed_context","target_gap_ids":["build_context"],"reason":"先补最小上下文"},"allowed_tools":["search_seed_context"],"blocked_tools":[],"reason":"先补最小上下文"}',
                2: '{"decision":"allow","deliverable_now":false,"material_gaps":[{"gap_id":"check_counterevidence","reason":"仍需显式反证检查","actionable_now":true}],"next_action":{"action_type":"tool","tool_name":"check_counterevidence","target_gap_ids":["check_counterevidence"],"reason":"继续补反证"},"allowed_tools":["check_counterevidence"],"blocked_tools":[],"reason":"继续补反证"}',
                3: '{"decision":"allow","deliverable_now":false,"material_gaps":[{"gap_id":"structure_evidence","reason":"仍需结构化整理","actionable_now":true}],"next_action":{"action_type":"tool","tool_name":"extract_claim_candidates_from_page","target_gap_ids":["structure_evidence"],"reason":"允许做一次结构化整理"},"allowed_tools":["extract_claim_candidates_from_page"],"blocked_tools":[],"reason":"允许做一次结构化整理"}',
                4: '{"decision":"allow","deliverable_now":false,"material_gaps":[{"gap_id":"expand_cluster_scope","reason":"仍需做一次显式扩线确认当前范围","actionable_now":true,"delivery_blocking":true}],"next_action":{"action_type":"tool","tool_name":"search_related_events","target_gap_ids":["expand_cluster_scope"],"reason":"先把范围扩查补齐"},"allowed_tools":["search_related_events"],"blocked_tools":[],"reason":"先把范围扩查补齐"}',
                5: '{"decision":"deliverable","deliverable_now":true,"material_gaps":[],"next_action":{"action_type":"finish","reason":"当前已满足交付条件，可以结束调查"},"allowed_tools":[],"blocked_tools":[],"reason":"当前已满足交付条件，可以结束调查"}',
            }
            self.reviews.append(mapping.get(self.reviewer_calls, mapping[5]))
            return FakeResp(mapping.get(self.reviewer_calls, mapping[5]))

        self.investigator_calls += 1
        self.runtimes.append(_extract_runtime(messages))
        mapping = {
            1: '{"action":"tool","tool_name":"search_seed_context","params":{},"target_gap_ids":["build_context"],"reason":"先建立最小上下文","why_not_finish":"当前还没有最小事件上下文"}',
            2: '{"action":"tool","tool_name":"check_counterevidence","params":{"asset_ids":["ws-finance-23"]},"target_gap_ids":["check_counterevidence"],"reason":"补反证检查","why_not_finish":"显式反证检查仍未完成"}',
            3: '{"action":"tool","tool_name":"extract_claim_candidates_from_page","params":{"content_ref":"investigation_digest","focus":"Possible Cobalt Strike beacon"},"target_gap_ids":["structure_evidence"],"reason":"整理主结论 claim","why_not_finish":"还缺少结构化证据沉淀"}',
            4: '{"action":"tool","tool_name":"search_related_events","params":{"window_minutes":240},"target_gap_ids":["expand_cluster_scope"],"reason":"想再补一次扩线确认范围","why_not_finish":"仍想确认是否还有同基础设施复现"}',
            5: '{"action":"finish","reason":"readiness 已满足，可以结束调查"}',
        }
        return FakeResp(mapping.get(self.investigator_calls, mapping[5]))


class FinishBlockedRecoveryLLM:
    def __init__(self) -> None:
        self.calls = 0
        self.investigator_calls = 0
        self.reviewer_calls = 0
        self.runtimes: List[Dict[str, Any]] = []
        self.reviews: List[str] = []

    def invoke(self, messages: List[Any]) -> FakeResp:
        self.calls += 1
        system_text = _system_text(messages)
        if "delivery reviewer" in system_text:
            self.reviewer_calls += 1
            mapping = {
                1: '{"decision":"not_deliverable","deliverable_now":false,"material_gaps":[{"gap_id":"build_context","reason":"仍需最小上下文","actionable_now":true}],"next_action":{"action_type":"tool","tool_name":"search_seed_context","target_gap_ids":["build_context"],"reason":"当前不能 finish，先补最小上下文"},"allowed_tools":["search_seed_context"],"blocked_tools":[],"reason":"当前不能 finish，先补最小上下文"}',
                2: '{"decision":"allow","deliverable_now":false,"material_gaps":[{"gap_id":"check_counterevidence","reason":"仍需显式反证检查","actionable_now":true}],"next_action":{"action_type":"tool","tool_name":"check_counterevidence","target_gap_ids":["check_counterevidence"],"reason":"继续补反证"},"allowed_tools":["check_counterevidence"],"blocked_tools":[],"reason":"继续补反证"}',
                3: '{"decision":"allow","deliverable_now":false,"material_gaps":[{"gap_id":"structure_evidence","reason":"仍需结构化整理","actionable_now":true}],"next_action":{"action_type":"tool","tool_name":"extract_claim_candidates_from_page","target_gap_ids":["structure_evidence"],"reason":"允许做结构化整理"},"allowed_tools":["extract_claim_candidates_from_page"],"blocked_tools":[],"reason":"允许做结构化整理"}',
                4: '{"decision":"allow","deliverable_now":false,"material_gaps":[{"gap_id":"expand_cluster_scope","reason":"仍需确认是否存在同基础设施复现","actionable_now":true,"delivery_blocking":true}],"next_action":{"action_type":"tool","tool_name":"search_related_events","target_gap_ids":["expand_cluster_scope"],"reason":"先补一次范围扩查"},"allowed_tools":["search_related_events"],"blocked_tools":[],"reason":"先补一次范围扩查"}',
                5: '{"decision":"deliverable","deliverable_now":true,"material_gaps":[],"next_action":{"action_type":"finish","reason":"当前已经满足交付条件"},"allowed_tools":[],"blocked_tools":[],"reason":"当前已经满足交付条件"}',
                6: '{"decision":"deliverable","deliverable_now":true,"material_gaps":[],"next_action":{"action_type":"finish","reason":"当前已经满足交付条件"},"allowed_tools":[],"blocked_tools":[],"reason":"当前已经满足交付条件"}',
            }
            self.reviews.append(mapping.get(self.reviewer_calls, mapping[6]))
            return FakeResp(mapping.get(self.reviewer_calls, mapping[6]))

        self.investigator_calls += 1
        runtime = _extract_runtime(messages)
        self.runtimes.append(runtime)
        if self.investigator_calls == 1:
            return FakeResp('{"action":"finish","reason":"先尝试结束，看看是否已经满足交付条件"}')
        if self.investigator_calls == 2:
            return FakeResp('{"action":"tool","tool_name":"check_counterevidence","params":{"asset_ids":["ws-finance-23"]},"target_gap_ids":["check_counterevidence"],"reason":"finish 被拒后先补反证","why_not_finish":"显式反证检查仍未完成"}')
        if self.investigator_calls == 3:
            return FakeResp('{"action":"tool","tool_name":"extract_claim_candidates_from_page","params":{"content_ref":"investigation_digest","focus":"Possible Cobalt Strike beacon"},"target_gap_ids":["structure_evidence"],"reason":"整理结构化证据","why_not_finish":"还缺少结构化证据沉淀"}')
        if self.investigator_calls == 4:
            return FakeResp('{"action":"tool","tool_name":"search_related_events","params":{"window_minutes":240},"target_gap_ids":["expand_cluster_scope"],"reason":"继续补一次扩查确认影响范围","why_not_finish":"还没有确认是否存在同基础设施复现"}')
        if self.investigator_calls == 5:
            return FakeResp('{"action":"tool","tool_name":"ground_candidate_event","params":{"event_id":"evt-007","max_indicators":4},"target_gap_ids":["validate_candidate_events"],"reason":"先验证扩线得到的候选事件","why_not_finish":"新扩出的候选事件还没有独立落证"}')
        return FakeResp('{"action":"finish","reason":"当前已经满足交付条件"}')


class CooldownGuardLLM:
    def __init__(self) -> None:
        self.calls = 0
        self.investigator_calls = 0
        self.reviewer_calls = 0
        self.runtimes: List[Dict[str, Any]] = []
        self.reviews: List[str] = []

    def invoke(self, messages: List[Any]) -> FakeResp:
        self.calls += 1
        system_text = _system_text(messages)
        if "delivery reviewer" in system_text:
            self.reviewer_calls += 1
            mapping = {
                1: '{"decision":"allow","deliverable_now":false,"material_gaps":[{"gap_id":"build_context","reason":"需要先建立最小上下文","actionable_now":true}],"next_action":{"action_type":"tool","tool_name":"search_seed_context","target_gap_ids":["build_context"],"reason":"先建上下文"},"allowed_tools":["search_seed_context"],"blocked_tools":[],"reason":"先建上下文"}',
                2: '{"decision":"allow","deliverable_now":false,"material_gaps":[{"gap_id":"check_counterevidence","reason":"仍需显式反证检查","actionable_now":true,"delivery_blocking":true}],"next_action":{"action_type":"tool","tool_name":"search_related_events","target_gap_ids":["expand_cluster_scope"],"reason":"先允许做一次扩线，但后续应先补反证"},"allowed_tools":["search_related_events"],"blocked_tools":[{"tool_name":"search_related_events","reason":"在显式反证检查完成前，继续重复扩线的价值较低。"}],"tool_cooldown_suggestions":[{"tool_name":"search_related_events","reason":"在显式反证检查完成前，继续重复扩线的价值较低。","related_gap_ids":["check_counterevidence"]}],"reason":"先允许做一次扩线，但后续应先补反证"}',
                3: '{"decision":"allow","deliverable_now":false,"material_gaps":[{"gap_id":"check_counterevidence","reason":"仍需显式反证检查","actionable_now":true,"delivery_blocking":true}],"next_action":{"action_type":"tool","tool_name":"search_related_events","target_gap_ids":["expand_cluster_scope"],"reason":"模型仍想继续扩线"},"allowed_tools":["search_related_events"],"blocked_tools":[],"reason":"模型仍想继续扩线"}',
                4: '{"decision":"deliverable","deliverable_now":true,"material_gaps":[],"next_action":{"action_type":"finish","reason":"已经足够交付"},"allowed_tools":[],"blocked_tools":[],"reason":"已经足够交付"}',
            }
            self.reviews.append(mapping.get(self.reviewer_calls, mapping[4]))
            return FakeResp(mapping.get(self.reviewer_calls, mapping[4]))

        self.investigator_calls += 1
        self.runtimes.append(_extract_runtime(messages))
        mapping = {
            1: '{"action":"tool","tool_name":"search_seed_context","params":{},"target_gap_ids":["build_context"],"reason":"先建立上下文","why_not_finish":"还没有最小上下文"}',
            2: '{"action":"tool","tool_name":"search_related_events","params":{"window_minutes":120},"target_gap_ids":["expand_cluster_scope"],"reason":"先看关联事件","why_not_finish":"还没看到扩线结果"}',
            3: '{"action":"tool","tool_name":"search_related_events","params":{"window_minutes":240},"target_gap_ids":["expand_cluster_scope"],"reason":"想继续扩线","why_not_finish":"还想再看一轮"}',
            4: '{"action":"finish","reason":"当前已经满足交付条件"}',
        }
        return FakeResp(mapping.get(self.investigator_calls, mapping[4]))


class ReviewerOwnsAcceptanceLLM:
    def __init__(self) -> None:
        self.calls = 0
        self.investigator_calls = 0
        self.reviewer_calls = 0
        self.runtimes: List[Dict[str, Any]] = []
        self.reviews: List[str] = []

    def invoke(self, messages: List[Any]) -> FakeResp:
        self.calls += 1
        system_text = _system_text(messages)
        if "delivery reviewer" in system_text:
            self.reviewer_calls += 1
            mapping = {
                1: '{"decision":"allow","deliverable_now":false,"material_gaps":[{"gap_id":"build_context","reason":"需要先建立最小上下文","actionable_now":true}],"next_action":{"action_type":"tool","tool_name":"search_seed_context","target_gap_ids":["build_context"],"reason":"先补最小上下文"},"allowed_tools":["search_seed_context"],"blocked_tools":[],"reason":"先补最小上下文"}',
                2: '{"decision":"allow","deliverable_now":false,"material_gaps":[{"gap_id":"check_counterevidence","reason":"仍需显式反证检查","actionable_now":true}],"next_action":{"action_type":"tool","tool_name":"check_counterevidence","target_gap_ids":["check_counterevidence"],"reason":"继续补反证"},"allowed_tools":["check_counterevidence"],"blocked_tools":[],"reason":"继续补反证"}',
                3: '{"decision":"allow","deliverable_now":false,"material_gaps":[{"gap_id":"structure_evidence","reason":"仍需结构化整理","actionable_now":true}],"next_action":{"action_type":"tool","tool_name":"extract_claim_candidates_from_page","target_gap_ids":["structure_evidence"],"reason":"允许做一次结构化整理"},"allowed_tools":["extract_claim_candidates_from_page"],"blocked_tools":[],"reason":"允许做一次结构化整理"}',
                4: '{"decision":"allow","deliverable_now":false,"material_gaps":[{"gap_id":"expand_cluster_scope","reason":"仍需做一次显式扩线确认当前范围","actionable_now":true,"delivery_blocking":true}],"next_action":{"action_type":"tool","tool_name":"search_related_events","target_gap_ids":["expand_cluster_scope"],"reason":"先把范围扩查补齐"},"allowed_tools":["search_related_events"],"blocked_tools":[],"reason":"先把范围扩查补齐"}',
                5: '{"decision":"deliverable","deliverable_now":true,"material_gaps":[],"next_action":{"action_type":"finish","reason":"当前已经达到交付条件，不需要再补额外工具调用"},"allowed_tools":[],"blocked_tools":[],"reason":"当前已经达到交付条件，不需要再补额外工具调用"}',
            }
            self.reviews.append(mapping.get(self.reviewer_calls, mapping[5]))
            return FakeResp(mapping.get(self.reviewer_calls, mapping[5]))

        self.investigator_calls += 1
        self.runtimes.append(_extract_runtime(messages))
        mapping = {
            1: '{"action":"tool","tool_name":"search_seed_context","params":{},"target_gap_ids":["build_context"],"reason":"先建立最小上下文","why_not_finish":"当前还没有最小事件上下文"}',
            2: '{"action":"tool","tool_name":"check_counterevidence","params":{"asset_ids":["ws-finance-23"]},"target_gap_ids":["check_counterevidence"],"reason":"补反证检查","why_not_finish":"显式反证检查仍未完成"}',
            3: '{"action":"tool","tool_name":"extract_claim_candidates_from_page","params":{"content_ref":"investigation_digest","focus":"Possible Cobalt Strike beacon"},"target_gap_ids":["structure_evidence"],"reason":"整理主结论 claim","why_not_finish":"还缺少结构化证据沉淀"}',
            4: '{"action":"tool","tool_name":"search_related_events","params":{"window_minutes":240},"target_gap_ids":["expand_cluster_scope"],"reason":"想再补一次扩线确认范围","why_not_finish":"仍想确认是否还有同基础设施复现"}',
            5: '{"action":"finish","reason":"当前已经满足交付条件"}',
        }
        return FakeResp(mapping.get(self.investigator_calls, mapping[5]))


class RepeatedBlockedFinishLLM:
    def __init__(self) -> None:
        self.calls = 0
        self.investigator_calls = 0
        self.reviewer_calls = 0
        self.runtimes: List[Dict[str, Any]] = []
        self.reviews: List[str] = []

    def invoke(self, messages: List[Any]) -> FakeResp:
        self.calls += 1
        system_text = _system_text(messages)
        if "delivery reviewer" in system_text:
            self.reviewer_calls += 1
            mapping = {
                1: '{"decision":"not_deliverable","deliverable_now":false,"material_gaps":[{"gap_id":"build_context","reason":"仍需最小上下文","actionable_now":true}],"next_action":{"action_type":"tool","tool_name":"search_seed_context","params":{},"target_gap_ids":["build_context"],"reason":"先补最小上下文"},"allowed_tools":["search_seed_context"],"blocked_tools":[],"reason":"当前不能 finish，先补最小上下文"}',
                2: '{"decision":"not_deliverable","deliverable_now":false,"material_gaps":[{"gap_id":"check_counterevidence","reason":"仍需显式反证检查","actionable_now":true}],"next_action":{"action_type":"tool","tool_name":"check_counterevidence","params":{"asset_ids":["ws-finance-23"],"window_minutes":180,"limit":40},"target_gap_ids":["check_counterevidence"],"reason":"finish 仍然过早，先补反证"},"allowed_tools":["check_counterevidence"],"blocked_tools":[],"reason":"finish 仍然过早，先补反证"}',
                3: '{"decision":"not_deliverable","deliverable_now":false,"material_gaps":[{"gap_id":"structure_evidence","reason":"仍需结构化整理","actionable_now":true}],"next_action":{"action_type":"tool","tool_name":"extract_claim_candidates_from_page","params":{"content_ref":"investigation_digest","focus":"Possible Cobalt Strike beacon"},"target_gap_ids":["structure_evidence"],"reason":"finish 仍然过早，先补结构化证据"},"allowed_tools":["extract_claim_candidates_from_page"],"blocked_tools":[],"reason":"finish 仍然过早，先补结构化证据"}',
            }
            review = mapping.get(self.reviewer_calls, mapping[3])
            self.reviews.append(review)
            return FakeResp(review)

        self.investigator_calls += 1
        self.runtimes.append(_extract_runtime(messages))
        return FakeResp('{"action":"finish","reason":"当前应该已经可以结束调查"}')


def _run_case(fake_llm: Any) -> Dict[str, Any]:
    alert = load_json(FIXTURE_DIR / "seed_alert.json")
    return run_incident_agent_case(
        seed_alert=alert,
        fixture_dir=str(FIXTURE_DIR),
        llm=fake_llm,
        decision_mode="llm_agent",
    )


def _selected_tools(trace: List[Dict[str, Any]]) -> List[str]:
    return [str(((item.get("selected_action") or {}).get("tool_name")) or "").strip() for item in trace]


def _next_action(review: Dict[str, Any]) -> Dict[str, Any]:
    return dict(review.get("next_action") or {})


def _next_action_tool(review: Dict[str, Any]) -> str:
    return str(_next_action(review).get("tool_name") or "").strip()


def _next_action_gap_ids(review: Dict[str, Any]) -> List[str]:
    return [str(item or "").strip() for item in list(_next_action(review).get("target_gap_ids") or []) if str(item or "").strip()]


def _next_action_params(review: Dict[str, Any]) -> Dict[str, Any]:
    return dict(_next_action(review).get("params") or {})


def _assert_happy_path() -> Dict[str, Any]:
    llm = ScriptedHappyPathLLM()
    result = _run_case(llm)
    incident = result["incident"]
    trace = result["investigation_trace"]
    history = list(incident.get("agent_history") or [])
    reviewer_history = list(incident.get("reviewer_history") or [])
    selected_tools = _selected_tools(trace)

    assert (incident.get("decision_mode") or {}).get("effective_mode") == "llm_agent"
    assert ((incident.get("session_state") or {}).get("policy_mode")) == "llm_open_agent"
    assert len(history) >= 5
    assert len(reviewer_history) >= 5
    assert selected_tools[:3] == [
        "search_seed_context",
        "check_counterevidence",
        "extract_claim_candidates_from_page",
    ]
    assert "search_related_events" in selected_tools
    assert "ground_candidate_event" in selected_tools
    assert selected_tools[-1] == "finish"
    assert all(isinstance(item.get("control_summary"), dict) for item in llm.runtimes)
    assert llm.runtimes[0]["control_summary"]["focus_mode"] == "context_bootstrap"
    assert llm.runtimes[0]["control_summary"]["compat_phase"] == llm.runtimes[0]["control_phase"]
    assert any(
        item.get("decision") == "not_deliverable" and _next_action_tool(item) == "ground_candidate_event"
        for item in reviewer_history
    )
    assert _next_action(reviewer_history[-1]).get("action_type") == "finish"
    assert reviewer_history[-1]["decision"] == "deliverable"
    assert reviewer_history[-1]["control_summary"]["deliverable_now"] is True
    assert str(((incident.get("session_state") or {}).get("stop_reason")) or "") == "agent_finish"
    assert bool(((incident.get("readiness") or {}).get("ready_for_delivery"))) is True

    return {
        "scenario": "happy_path",
        "agent_decision_count": len(history),
        "reviewer_decision_count": len(reviewer_history),
        "llm_calls_total": llm.calls,
        "selected_tools": selected_tools,
        "stop_reason": (incident.get("session_state") or {}).get("stop_reason"),
    }


def _assert_finish_blocked_recovery() -> Dict[str, Any]:
    llm = FinishBlockedRecoveryLLM()
    result = _run_case(llm)
    incident = result["incident"]
    trace = result["investigation_trace"]
    history = list(incident.get("agent_history") or [])
    reviewer_history = list(incident.get("reviewer_history") or [])
    selected_tools = _selected_tools(trace)
    session_state = incident.get("session_state") or {}

    assert len(history) >= 6
    assert len(reviewer_history) >= 6
    assert history[0]["action_type"] == "finish"
    assert history[0]["finish_requested"] is True
    assert history[0]["finish_accepted"] is False
    assert reviewer_history[0]["decision"] == "not_deliverable"
    assert _next_action(reviewer_history[0]).get("action_type") == "tool"
    assert _next_action_tool(reviewer_history[0]) == "search_seed_context"
    assert selected_tools[0] == _next_action_tool(reviewer_history[0])
    assert trace[0].get("reviewer_decision", {}).get("decision") == "not_deliverable"
    assert trace[0].get("agent_decision", {}).get("action_type") == "finish"
    assert "check_counterevidence" in selected_tools
    assert "extract_claim_candidates_from_page" in selected_tools
    assert "search_related_events" in selected_tools
    assert "ground_candidate_event" in selected_tools
    assert history[3]["tool_name"] == "search_related_events"
    assert history[4]["tool_name"] == "ground_candidate_event"
    assert history[-1]["action_type"] == "finish"
    assert history[-1]["finish_accepted"] is True
    assert any(
        item.get("decision") == "not_deliverable" and _next_action_tool(item) == "ground_candidate_event"
        for item in reviewer_history
    )
    assert _next_action(reviewer_history[-1]).get("action_type") == "finish"
    assert selected_tools[-1] == "finish"
    assert session_state.get("blocked_finish_attempts") == 0
    assert str(session_state.get("stop_reason") or "") == "agent_finish"

    return {
        "scenario": "finish_blocked_recovery",
        "agent_decision_count": len(history),
        "reviewer_decision_count": len(reviewer_history),
        "llm_calls_total": llm.calls,
        "selected_tools": selected_tools,
        "first_reviewer_decision": trace[0].get("reviewer_decision") or {},
        "stop_reason": session_state.get("stop_reason"),
    }


def _assert_cooldown_guard() -> Dict[str, Any]:
    llm = CooldownGuardLLM()
    result = _run_case(llm)
    incident = result["incident"]
    trace = result["investigation_trace"]
    reviewer_history = list(incident.get("reviewer_history") or [])
    agent_history = list(incident.get("agent_history") or [])
    selected_tools = _selected_tools(trace)

    assert len(reviewer_history) >= 3
    assert reviewer_history[1]["tool_cooldown_suggestions"]
    assert reviewer_history[1]["tool_cooldown_suggestions"][0]["tool_name"] == "search_related_events"
    assert reviewer_history[1]["tool_cooldown_suggestions"][0]["issued_for_focus"] == "blocking_gap_reduction"
    assert isinstance(reviewer_history[1].get("proposal_alignment"), dict)
    assert reviewer_history[1]["active_tool_cooldowns"]
    assert reviewer_history[1]["active_tool_cooldowns"][0]["tool_name"] == "search_related_events"
    assert _next_action(reviewer_history[1]).get("action_type") == "tool"
    assert _next_action_tool(reviewer_history[1]) == "check_counterevidence"
    assert _next_action_gap_ids(reviewer_history[1]) == ["check_counterevidence"]
    assert _next_action_params(reviewer_history[1]).get("asset_ids") == ["ws-finance-23"]
    assert _next_action_tool(reviewer_history[2]) == "search_related_events"
    assert _next_action_gap_ids(reviewer_history[2]) == ["expand_cluster_scope"]
    assert _next_action_params(reviewer_history[2]).get("window_minutes") == 240
    assert selected_tools[:3] == [
        "search_seed_context",
        "check_counterevidence",
        "search_related_events",
    ]
    assert agent_history[2]["tool_name"] == "search_related_events"
    assert isinstance((trace[1].get("selected_action") or {}).get("alignment"), dict)
    assert "check_counterevidence" in selected_tools
    assert "ground_candidate_event" in selected_tools
    assert selected_tools[-1] == "finish"

    return {
        "scenario": "cooldown_guard",
        "selected_tools": selected_tools,
        "cooldown_review": reviewer_history[1],
        "post_cooldown_review": reviewer_history[2],
        "post_cooldown_agent_decision": agent_history[2],
    }


def _assert_repeated_blocked_finish() -> Dict[str, Any]:
    llm = RepeatedBlockedFinishLLM()
    result = _run_case(llm)
    incident = result["incident"]
    trace = result["investigation_trace"]
    history = list(incident.get("agent_history") or [])
    reviewer_history = list(incident.get("reviewer_history") or [])
    selected_tools = _selected_tools(trace)
    session_state = incident.get("session_state") or {}

    assert selected_tools == [
        "search_seed_context",
        "check_counterevidence",
        "extract_claim_candidates_from_page",
    ]
    assert len(history) == 3
    assert len(reviewer_history) == 3
    assert all(item.get("action_type") == "finish" for item in history)
    assert all(item.get("finish_requested") is True for item in history)
    assert all(item.get("finish_accepted") is False for item in history)
    assert session_state.get("blocked_finish_attempts") == 3
    assert str(session_state.get("stop_reason") or "") == "repeated_blocked_finish"
    assert _next_action_tool(reviewer_history[1]) == "check_counterevidence"
    assert _next_action_gap_ids(reviewer_history[1]) == ["check_counterevidence"]
    assert _next_action_params(reviewer_history[1]) == {
        "asset_ids": ["ws-finance-23"],
        "window_minutes": 180,
        "limit": 40,
    }
    assert _next_action_tool(reviewer_history[2]) == "extract_claim_candidates_from_page"
    assert _next_action_gap_ids(reviewer_history[2]) == ["structure_evidence"]
    assert _next_action_params(reviewer_history[2]).get("content_ref") == "inline_content"
    assert _next_action_params(reviewer_history[2]).get("focus") == "Possible Cobalt Strike beacon"
    assert "Seed alert summary:" in str(_next_action_params(reviewer_history[2]).get("content") or "")
    assert (trace[1].get("selected_action") or {}).get("trace_params") == {
        "asset_ids": ["ws-finance-23"],
        "window_minutes": 180,
        "limit": 40,
    }
    assert (trace[2].get("selected_action") or {}).get("trace_params") == {
        "content_ref": "inline_content",
        "focus": "Possible Cobalt Strike beacon",
    }

    return {
        "scenario": "repeated_blocked_finish",
        "selected_tools": selected_tools,
        "stop_reason": session_state.get("stop_reason"),
        "blocked_finish_attempts": session_state.get("blocked_finish_attempts"),
    }


def _assert_reviewer_owns_acceptance() -> Dict[str, Any]:
    llm = ReviewerOwnsAcceptanceLLM()
    result = _run_case(llm)
    incident = result["incident"]
    trace = result["investigation_trace"]
    reviewer_history = list(incident.get("reviewer_history") or [])
    agent_history = list(incident.get("agent_history") or [])
    selected_tools = _selected_tools(trace)

    assert len(agent_history) >= 4
    assert len(reviewer_history) >= 4
    assert agent_history[-1]["action_type"] == "finish"
    assert agent_history[-1]["finish_requested"] is True
    assert agent_history[-1]["finish_accepted"] is True
    assert reviewer_history[-1]["decision"] == "deliverable"
    assert reviewer_history[-1]["blocking_gaps"] == []
    assert _next_action(reviewer_history[-1]).get("action_type") == "finish"
    assert reviewer_history[-1]["control_summary"]["deliverable_now"] is True
    assert reviewer_history[-1]["proposal_alignment"]["priority_tier"] == "finish_request"
    assert any(
        item.get("decision") == "not_deliverable" and _next_action_tool(item) == "ground_candidate_event"
        for item in reviewer_history
    )
    assert "search_related_events" in selected_tools
    assert "ground_candidate_event" in selected_tools
    assert selected_tools[-1] == "finish"
    assert str(((incident.get("session_state") or {}).get("stop_reason")) or "") == "agent_finish"

    return {
        "scenario": "reviewer_owns_acceptance",
        "selected_tools": selected_tools,
        "final_agent_decision": agent_history[-1],
        "final_reviewer_decision": reviewer_history[-1],
        "stop_reason": (incident.get("session_state") or {}).get("stop_reason"),
    }


def main() -> None:
    summary = {
        "ok": True,
        "results": [
            _assert_happy_path(),
            _assert_finish_blocked_recovery(),
            _assert_cooldown_guard(),
            _assert_repeated_blocked_finish(),
            _assert_reviewer_owns_acceptance(),
        ],
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
