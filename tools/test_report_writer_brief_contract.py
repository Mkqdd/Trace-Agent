from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from demo_agent.incidents.report_agent import (
    _build_round_user_prompt,
    _fallback_materials_from_preload,
    _repair_materials_contract,
    classify_material_route_status,
)
from demo_agent.incidents.report_agent_tools import validate_report_writer_materials
from demo_agent.incidents.report_agent_writer import build_report_writer_brief, build_report_writer_prompt_brief


META_CONCLUSION_FRAGMENT = "生成报告材料"


def test_fallback_materials_use_source_derived_thesis_and_evidence_claims() -> None:
    materials = _fallback_materials_from_preload(
        [
            {
                "tool_name": "get_case_overview",
                "result": {
                    "case_header": {
                        "delivery_status": "confirmed_incident",
                        "delivery_status_label": "确认安全事件",
                        "severity_normalized": "高",
                        "confidence_normalized": "高",
                        "final_verdict_summary": {
                            "exact_fact_text": "基于已确认执行链和跨主机通信，当前可交付为确认安全事件。"
                        },
                    },
                    "confirmed_scope": ["host-a"],
                    "candidate_scope": ["host-b"],
                },
            },
            {
                "tool_name": "get_timeline",
                "result": {
                    "events": [
                        {
                            "source_id": "event:evt-1",
                            "classification": "malicious",
                            "exact_fact_text": "2026-07-14T01:18:00Z host-a 出现远程服务创建线索。",
                        },
                        {
                            "source_id": "event:evt-2",
                            "classification": "suspicious",
                            "exact_fact_text": "2026-07-14T01:21:00Z host-b 与同一外部基础设施通信。",
                        },
                    ]
                },
            },
        ]
    )

    thesis = materials["case_thesis"]
    assert META_CONCLUSION_FRAGMENT not in thesis["why_this_judgment_holds"]
    assert "已确认执行链" in thesis["why_this_judgment_holds"]

    claims = [item["claim"] for item in materials["evidence_argument_map"]]
    assert claims
    assert not {"suspicious", "malicious"} & set(claims)
    assert any("远程服务创建" in claim for claim in claims)


def test_writer_header_ignores_low_information_evidence_labels() -> None:
    materials = {
        "schema_version": "report-writer-materials-v2",
        "report_plan": {"title": "测试报告", "sections": []},
        "case_thesis": {
            "conclusion": "确认安全事件",
            "severity": "高",
            "confidence": "高",
            "confirmed_scope": ["host-a"],
            "candidate_scope": ["host-b"],
            "why_this_judgment_holds": "当前只能依据已整理的交付判断和证据包保守生成报告材料。",
            "why_not_stronger_or_broader": "候选范围尚未独立验证。",
            "source_ids": ["verdict:delivery"],
        },
        "evidence_argument_map": [
            {"claim": "suspicious", "source_ids": ["event:evt-1"]},
            {"claim": "malicious", "source_ids": ["event:evt-2"]},
        ],
        "source_fact_catalog": [
            {
                "fact_id": "fact-verdict-delivery",
                "source_id": "verdict:delivery",
                "fact_type": "verdict",
                "status": "",
                "summary_line": "确认安全事件；主链证据足以支撑确认事件，候选范围需保留边界。",
                "exact_fact_text": "确认安全事件；主链证据足以支撑确认事件，候选范围需保留边界。",
            },
            {
                "fact_id": "fact-event-evt-1",
                "source_id": "event:evt-1",
                "fact_type": "event",
                "status": "confirmed",
                "summary_line": "2026-07-14T01:18:00Z host-a 出现远程服务创建线索。",
                "exact_fact_text": "2026-07-14T01:18:00Z host-a 出现远程服务创建线索。",
            },
            {
                "fact_id": "fact-event-evt-2",
                "source_id": "event:evt-2",
                "fact_type": "event",
                "status": "confirmed",
                "summary_line": "2026-07-14T01:21:00Z host-b 与同一外部基础设施通信。",
                "exact_fact_text": "2026-07-14T01:21:00Z host-b 与同一外部基础设施通信。",
            },
        ],
    }

    header = build_report_writer_brief(materials)["header_packet"]

    assert header["strongest_evidence"]
    assert "suspicious" not in header["strongest_evidence"]
    assert "malicious" not in header["strongest_evidence"]
    assert any("远程服务创建" in item for item in header["strongest_evidence"])
    assert META_CONCLUSION_FRAGMENT not in header["one_sentence_conclusion"]
    assert "主链证据足以支撑确认事件" in header["one_sentence_conclusion"]


def test_validator_reports_meta_thesis_and_label_claims_as_advisory() -> None:
    bundle = {
        "case_header": {
            "delivery_status": "confirmed_incident",
            "delivery_status_label": "确认安全事件",
            "final_verdict": {
                "status": "confirmed_incident",
                "status_label": "确认安全事件",
                "severity": "高",
                "confidence": "高",
                "rationale": ["主链证据足以支撑确认事件。"],
            },
        },
        "events": [
            {
                "source_id": "event:evt-1",
                "status": "confirmed",
                "classification": "malicious",
                "exact_fact_text": "host-a 出现远程服务创建线索。",
            }
        ],
        "claims": [{"source_id": "claim:1", "exact_fact_text": "主链证据足以支撑确认事件。"}],
        "objects": [{"source_id": "object:1", "value": "host-a", "report_scope_role": "confirmed_affected_asset"}],
        "gaps": [{"source_id": "gap:1", "status": "open", "question": "候选范围尚未验证。"}],
    }
    materials = {
        "schema_version": "report-writer-materials-v2",
        "case_thesis": {
            "conclusion": "确认安全事件",
            "severity": "高",
            "confidence": "高",
            "why_this_judgment_holds": "当前只能依据已整理的交付判断和证据包保守生成报告材料。",
            "why_not_stronger_or_broader": "候选范围尚未验证。",
            "exact_fact_text": "确认安全事件",
            "source_ids": ["verdict:delivery"],
        },
        "narrative_spine": [{"step_label": "入口", "source_ids": ["event:evt-1"], "exact_fact_text": "host-a 出现远程服务创建线索。"}],
        "evidence_argument_map": [{"claim": "malicious", "source_ids": ["event:evt-1"], "exact_fact_text": "host-a 出现远程服务创建线索。"}],
        "scope_role_matrix": [{"object": "host-a", "role": "confirmed_affected_asset", "source_ids": ["object:1"], "exact_fact_text": "host-a"}],
        "report_plan": {
            "schema_version": "report-plan-v1",
            "sections": [
                {
                    "section_type": "investigation_entry",
                    "title": "调查起点",
                    "mode": "full",
                    "source_ids": ["event:evt-1"],
                }
            ],
        },
        "section_briefs": [
            {
                "section_type": "investigation_entry",
                "source_ids": ["event:evt-1"],
                "key_facts": [{"source_ids": ["event:evt-1"], "fact_role": "入口事实"}],
                "paragraph_groups": [
                    {
                        "group_id": "investigation_entry-g1",
                        "paragraph_role": "入口",
                        "paragraph_claim": "说明入口事实",
                        "source_ids": ["event:evt-1"],
                        "write_focus": "说明入口事实",
                        "contrast_or_boundary": "不扩大结论",
                        "must_not_repeat": "不重复证据判断",
                    }
                ],
            }
        ],
        "reportable_limits": ["候选范围尚未验证。"],
    }

    feedback = validate_report_writer_materials(bundle, materials)["agent_feedback"]
    by_code = {item["code"]: item for item in feedback}

    assert by_code["meta_case_thesis_text"]["severity"] == "advisory"
    assert by_code["low_information_evidence_claims"]["severity"] == "advisory"


def test_trace_status_distinguishes_deterministic_plan_with_agent_route() -> None:
    status = classify_material_route_status(
        plan_origin="deterministic_base",
        raw_has_paragraph_groups=True,
    )

    assert status == "deterministic_plan_with_agent_route"


def test_plan_decision_accepts_deterministic_plan_as_agent_reviewed() -> None:
    bundle = {
        "case_header": {
            "delivery_status": "confirmed_incident",
            "delivery_status_label": "确认安全事件",
            "severity": "高",
            "confidence": "高",
        },
        "events": [
            {
                "source_id": "event:evt-1",
                "status": "confirmed",
                "classification": "suspicious",
                "exact_fact_text": "host-a 连接 203.0.113.77。",
            }
        ],
        "objects": [{"source_id": "object:1", "value": "host-a", "report_scope_role": "confirmed_affected_asset"}],
        "gaps": [{"source_id": "gap:1", "status": "open", "question": "候选范围尚未验证。"}],
    }
    tool_results = [{"tool_name": "get_case_overview", "result": {"case_header": bundle["case_header"]}}]
    previous = {
        "schema_version": "report-writer-materials-v2",
        "case_thesis": {"source_ids": ["verdict:delivery"]},
        "report_plan": {
            "schema_version": "report-plan-v1",
            "plan_origin": "deterministic_base",
            "title": "测试报告",
            "planning_rationale": "工程兜底计划",
            "sections": [
                {
                    "section_type": "investigation_entry",
                    "title": "调查起点",
                    "mode": "full",
                    "source_ids": ["event:evt-1"],
                }
            ],
        },
        "section_briefs": [
            {
                "section_type": "investigation_entry",
                "source_ids": ["event:evt-1"],
                "key_facts": [{"source_ids": ["event:evt-1"], "fact_role": "入口事实"}],
                "paragraph_groups": [
                    {
                        "group_id": "investigation_entry-g1",
                        "paragraph_role": "入口",
                        "paragraph_claim": "说明入口事实",
                        "source_ids": ["event:evt-1"],
                        "write_focus": "说明入口事实",
                        "contrast_or_boundary": "不扩大结论",
                        "must_not_repeat": "不重复证据判断",
                    }
                ],
            }
        ],
        "reportable_limits": ["候选范围尚未验证。"],
    }
    patch = {
        "plan_decision": {
            "decision": "accept_deterministic_plan",
            "reason": "章节顺序和复杂章节承接关系已经覆盖当前 case。",
            "source_ids": ["verdict:delivery", "event:evt-1"],
        }
    }

    repaired = _repair_materials_contract(patch, tool_results, bundle, previous_materials=previous)

    plan = repaired["report_plan"]
    assert plan["plan_origin"] == "agent_accepted_deterministic"
    assert plan["plan_decision"]["decision"] == "accept_deterministic_plan"
    assert classify_material_route_status(
        plan_origin=plan["plan_origin"],
        raw_has_paragraph_groups=True,
    ) == "agent_accepted_deterministic_plan_with_route"


def test_plan_decision_modify_without_plan_patch_is_traced_honestly() -> None:
    bundle = {
        "case_header": {
            "delivery_status": "confirmed_incident",
            "delivery_status_label": "确认安全事件",
            "severity": "高",
            "confidence": "高",
        },
        "events": [
            {
                "source_id": "event:evt-1",
                "status": "confirmed",
                "classification": "suspicious",
                "exact_fact_text": "host-a 连接 203.0.113.77。",
            }
        ],
        "objects": [{"source_id": "object:1", "value": "host-a", "report_scope_role": "confirmed_affected_asset"}],
        "gaps": [{"source_id": "gap:1", "status": "open", "question": "候选范围尚未验证。"}],
    }
    tool_results = [{"tool_name": "get_case_overview", "result": {"case_header": bundle["case_header"]}}]
    previous = {
        "schema_version": "report-writer-materials-v2",
        "case_thesis": {"source_ids": ["verdict:delivery"]},
        "report_plan": {
            "schema_version": "report-plan-v1",
            "plan_origin": "agent_accepted_deterministic",
            "title": "测试报告",
            "sections": [
                {
                    "section_type": "investigation_entry",
                    "title": "调查起点",
                    "mode": "full",
                    "source_ids": ["event:evt-1"],
                }
            ],
        },
        "section_briefs": [
            {
                "section_type": "investigation_entry",
                "source_ids": ["event:evt-1"],
                "key_facts": [{"source_ids": ["event:evt-1"], "fact_role": "入口事实"}],
                "paragraph_groups": [
                    {
                        "group_id": "investigation_entry-g1",
                        "paragraph_role": "入口",
                        "paragraph_claim": "说明入口事实",
                        "source_ids": ["event:evt-1"],
                        "write_focus": "说明入口事实",
                        "contrast_or_boundary": "不扩大结论",
                        "must_not_repeat": "不重复证据判断",
                    }
                ],
            }
        ],
        "reportable_limits": ["候选范围尚未验证。"],
    }
    patch = {
        "plan_decision": {
            "decision": "modify_deterministic_plan",
            "reason": "需要调整反证章节。",
            "source_ids": ["event:evt-1"],
        }
    }

    repaired = _repair_materials_contract(patch, tool_results, bundle, previous_materials=previous)

    plan = repaired["report_plan"]
    assert plan["plan_origin"] == "agent_requested_plan_modify_without_plan_patch"
    assert plan["plan_decision"]["decision"] == "modify_deterministic_plan"
    assert classify_material_route_status(
        plan_origin=plan["plan_origin"],
        raw_has_paragraph_groups=True,
    ) == "agent_requested_plan_modify_without_plan_patch_with_route"


def test_route_patch_prompt_uses_planning_workbench_and_requires_plan_decision() -> None:
    draft_materials = {
        "schema_version": "report-writer-materials-v2",
        "report_plan": {
            "schema_version": "report-plan-v1",
            "plan_origin": "deterministic_base",
            "sections": [
                {
                    "section_type": "timeline_process",
                    "title": "事件过程",
                    "source_ids": ["event:evt-1"],
                }
            ],
        },
        "section_briefs": [
            {
                "section_type": "timeline_process",
                "source_ids": ["event:evt-1"],
                "key_facts": [{"source_ids": ["event:evt-1"], "fact_role": "事件推进"}],
                "paragraph_groups": [],
            }
        ],
        "source_fact_catalog": [
            {
                "fact_id": "fact-event-evt-1",
                "source_id": "event:evt-1",
                "fact_type": "event",
                "status": "confirmed",
                "summary_line": "host-a 连接 203.0.113.77。",
            }
        ],
    }
    prompt = _build_round_user_prompt(
        round_index=1,
        max_rounds=3,
        bundle={},
        tool_results=[],
        draft_materials=draft_materials,
        feedback=[
            {
                "code": "patch_route_from_deterministic_draft",
                "severity": "instruction",
                "message_for_agent": "补 route",
            }
        ],
    )

    assert "planning_workbench" in prompt
    assert "plan_decision" in prompt
    assert "accept_deterministic_plan" in prompt
    assert "modify_deterministic_plan" in prompt
    assert "replace_with_agent_plan" in prompt


def test_route_patch_prompt_does_not_show_conservative_paragraph_claims() -> None:
    draft_materials = {
        "schema_version": "report-writer-materials-v2",
        "report_plan": {
            "schema_version": "report-plan-v1",
            "plan_origin": "deterministic_base",
            "sections": [
                {
                    "section_type": "timeline_process",
                    "title": "事件过程",
                    "source_ids": ["event:evt-1"],
                }
            ],
        },
        "section_briefs": [
            {
                "section_type": "timeline_process",
                "source_ids": ["event:evt-1"],
                "key_facts": [{"source_ids": ["event:evt-1"], "fact_role": "事件推进"}],
                "paragraph_groups": [
                    {
                        "group_id": "timeline_process-g1",
                        "paragraph_role": "事件推进",
                        "paragraph_claim": "事件推进节点",
                        "fact_ids": ["fact-event-evt-1"],
                        "source_ids": ["event:evt-1"],
                        "write_focus": "说明事件推进的关键节点",
                        "contrast_or_boundary": "不要重复证据判断",
                        "must_not_repeat": "不要重复证据判断",
                    }
                ],
            }
        ],
        "source_fact_catalog": [
            {
                "fact_id": "fact-event-evt-1",
                "source_id": "event:evt-1",
                "fact_type": "event",
                "status": "confirmed",
                "summary_line": "host-a 连接 203.0.113.77。",
            }
        ],
    }
    prompt = _build_round_user_prompt(
        round_index=1,
        max_rounds=3,
        bundle={},
        tool_results=[],
        draft_materials=draft_materials,
        feedback=[
            {
                "code": "patch_route_from_deterministic_draft",
                "severity": "instruction",
                "message_for_agent": "补 route",
            }
        ],
    )

    assert "conservative_group_count" in prompt
    assert "事件推进节点" not in prompt
    assert "说明事件推进的关键节点" not in prompt


def test_writer_prompt_brief_omits_full_fact_catalog_but_keeps_routed_snapshots() -> None:
    materials = {
        "schema_version": "report-writer-materials-v2",
        "report_plan": {
            "schema_version": "report-plan-v1",
            "title": "测试报告",
            "sections": [
                {
                    "section_type": "timeline_process",
                    "title": "事件过程",
                    "mode": "full",
                    "source_ids": ["event:evt-1"],
                }
            ],
        },
        "case_thesis": {
            "conclusion": "确认安全事件",
            "severity": "高",
            "confidence": "高",
            "confirmed_scope": ["host-a"],
            "why_this_judgment_holds": "主链证据足以支撑确认事件。",
            "why_not_stronger_or_broader": "候选范围尚未验证。",
            "source_ids": ["verdict:delivery"],
        },
        "section_briefs": [
            {
                "section_type": "timeline_process",
                "source_ids": ["event:evt-1"],
                "paragraph_groups": [
                    {
                        "group_id": "timeline_process-g1",
                        "paragraph_role": "事件推进",
                        "paragraph_claim": "说明确认事件的起点。",
                        "fact_ids": ["fact-event-evt-1"],
                        "source_ids": ["event:evt-1"],
                        "write_focus": "展开事件起点。",
                        "contrast_or_boundary": "不要写候选范围。",
                        "must_not_repeat": "不要重复证据判断。",
                    }
                ],
            }
        ],
        "source_fact_catalog": [
            {
                "fact_id": "fact-event-evt-1",
                "source_id": "event:evt-1",
                "fact_type": "event",
                "status": "confirmed",
                "time": "2026-07-14T01:10:00Z",
                "asset": "host-a",
                "objects": ["203.0.113.77"],
                "summary_line": "2026-07-14 01:10:00 UTC，host-a 连接 203.0.113.77。",
                "exact_fact_text": "2026-07-14 01:10:00 UTC，host-a 连接 203.0.113.77。",
            },
            {
                "fact_id": "fact-event-evt-unused",
                "source_id": "event:evt-unused",
                "fact_type": "event",
                "status": "background",
                "time": "2026-07-14T01:20:00Z",
                "asset": "host-b",
                "objects": ["198.51.100.44"],
                "summary_line": "未路由事实不应进入 writer prompt brief。",
                "exact_fact_text": "未路由事实不应进入 writer prompt brief。",
            },
        ],
    }

    full_brief = build_report_writer_brief(materials)
    prompt_brief = build_report_writer_prompt_brief(full_brief)

    assert len(full_brief["fact_catalog"]) == 2
    assert "fact_catalog" not in prompt_brief
    paragraph_plan = prompt_brief["section_fact_map"][0]["paragraph_plan"]
    assert paragraph_plan[0]["fact_snapshots"][0]["fact_id"] == "fact-event-evt-1"
    assert "fact-event-evt-unused" not in str(prompt_brief)


if __name__ == "__main__":
    test_fallback_materials_use_source_derived_thesis_and_evidence_claims()
    test_writer_header_ignores_low_information_evidence_labels()
    test_validator_reports_meta_thesis_and_label_claims_as_advisory()
    test_trace_status_distinguishes_deterministic_plan_with_agent_route()
    test_plan_decision_accepts_deterministic_plan_as_agent_reviewed()
    test_plan_decision_modify_without_plan_patch_is_traced_honestly()
    test_route_patch_prompt_uses_planning_workbench_and_requires_plan_decision()
    test_route_patch_prompt_does_not_show_conservative_paragraph_claims()
    test_writer_prompt_brief_omits_full_fact_catalog_but_keeps_routed_snapshots()
    print("report writer brief contract checks passed")
