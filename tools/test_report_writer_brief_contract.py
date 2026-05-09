from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from demo_agent.incidents.report_agent import _fallback_materials_from_preload
from demo_agent.incidents.report_agent_tools import validate_report_writer_materials
from demo_agent.incidents.report_agent_writer import build_report_writer_brief


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


if __name__ == "__main__":
    test_fallback_materials_use_source_derived_thesis_and_evidence_claims()
    test_writer_header_ignores_low_information_evidence_labels()
    test_validator_reports_meta_thesis_and_label_claims_as_advisory()
    print("report writer brief contract checks passed")
