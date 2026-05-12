from __future__ import annotations

import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from demo_agent.incidents.report_agent_writer import (  # noqa: E402
    build_report_writer_section_prompt_brief,
    render_polished_body_from_writer_brief,
)


class _FakeResponse:
    def __init__(self, content: str) -> None:
        self.content = content


class _FakeLLM:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def bind(self, **kwargs):
        return self

    def invoke(self, messages):
        text = "\n".join(str(getattr(message, "content", message)) for message in messages)
        self.calls.append(text)
        if "只生成首页摘要" in text:
            return _FakeResponse("# 首页摘要\n\n**结论**：确认安全事件\n**严重度**：高\n**研判把握**：高\n**已确认范围**：host-a\n**最强证据**：host-a 命中 C2。\n**关键缺口**：候选范围待验证。\n**立即动作**：隔离 host-a。\n**一句话结论**：当前足以支撑确认事件。")
        if "section_type=timeline_process" in text:
            return _FakeResponse("## 事件过程\n\n2026-01-01 00:00:00 UTC，host-a 连接 c2.example，形成事件推进。")
        if "section_type=evidence_judgment" in text:
            return _FakeResponse("## 证据判断\n\n该通信事实支撑确认事件判断，但不能扩大到候选资产。")
        return _FakeResponse("unexpected")


class _OverclaimFakeLLM(_FakeLLM):
    def invoke(self, messages):
        text = "\n".join(str(getattr(message, "content", message)) for message in messages)
        self.calls.append(text)
        if "只生成首页摘要" in text:
            return _FakeResponse("# 首页摘要\n\n**结论**：确认安全事件\n**严重度**：高\n**研判把握**：高\n**已确认范围**：host-a\n**最强证据**：host-a 命中 C2。\n**关键缺口**：候选范围待验证。\n**立即动作**：隔离 host-a。\n**一句话结论**：当前足以支撑确认事件。")
        if "section_type=timeline_process" in text:
            return _FakeResponse("## 事件过程\n\n2026-01-01 00:00:00 UTC，host-a 连接 c2.example，形成事件推进。")
        if "section_type=evidence_judgment" in text:
            return _FakeResponse("## 证据判断\n\n该通信事实证实了横向移动的存在，并表明恶意活动已经扩散到了多个资产。")
        return _FakeResponse("unexpected")


def _sample_writer_brief() -> dict:
    return {
        "schema_version": "report-writer-brief-v1",
        "header_packet": {
            "conclusion": "确认安全事件",
            "severity": "高",
            "confidence": "高",
            "confirmed_scope": ["host-a"],
            "candidate_scope": ["host-b"],
            "strongest_evidence": ["2026-01-01 00:00:00 UTC host-a 连接 c2.example。"],
            "key_limits": ["候选范围待验证。"],
            "immediate_actions": ["隔离 host-a。"],
            "one_sentence_conclusion": "当前足以支撑确认事件。",
        },
        "section_fact_map": [
            {
                "section_type": "timeline_process",
                "title": "事件过程",
                "question_to_answer": "事件如何推进？",
                "allowed_fact_ids": ["fact-1"],
                "paragraph_target": 1,
                "complex_section": True,
                "paragraph_plan": [
                    {
                        "group_id": "timeline-g1",
                        "paragraph_role": "事件推进",
                        "paragraph_claim": "说明事件推进。",
                        "fact_ids": ["fact-1"],
                        "write_focus": "写清时间和对象。",
                        "contrast_or_boundary": "不写证据强度。",
                        "must_not_repeat": "不重复证据判断。",
                        "fact_snapshots": [
                            {
                                "fact_id": "fact-1",
                                "fact_type": "event",
                                "status": "confirmed",
                                "time": "2026-01-01 00:00:00 UTC",
                                "asset": "host-a",
                                "objects": ["c2.example"],
                                "fact_text": "2026-01-01 00:00:00 UTC，host-a 连接 c2.example。",
                            }
                        ],
                    }
                ],
            },
            {
                "section_type": "evidence_judgment",
                "title": "证据判断",
                "question_to_answer": "为什么判断成立？",
                "allowed_fact_ids": ["fact-1"],
                "paragraph_target": 1,
                "complex_section": True,
                "paragraph_plan": [
                    {
                        "group_id": "evidence-g1",
                        "paragraph_role": "判断作用",
                        "paragraph_claim": "说明事实如何支撑判断。",
                        "fact_ids": ["fact-1"],
                        "write_focus": "写清判断作用。",
                        "contrast_or_boundary": "不扩大到候选资产。",
                        "must_not_repeat": "不重复事件过程。",
                        "fact_snapshots": [
                            {
                                "fact_id": "fact-1",
                                "fact_type": "event",
                                "status": "confirmed",
                                "time": "2026-01-01 00:00:00 UTC",
                                "asset": "host-a",
                                "objects": ["c2.example"],
                                "fact_text": "2026-01-01 00:00:00 UTC，host-a 连接 c2.example。",
                            }
                        ],
                    }
                ],
            },
        ],
        "writing_constraints": {
            "global_rules": ["不能新增事实。"],
            "candidate_or_boundary_fact_ids": [],
            "external_infrastructure_fact_ids": ["fact-1"],
            "action_fact_ids": [],
        },
        "appendix_note": "详见技术附录。",
    }


def test_section_prompt_brief_contains_only_selected_section() -> None:
    brief = build_report_writer_section_prompt_brief(_sample_writer_brief(), "evidence_judgment")

    assert brief["section"]["section_type"] == "evidence_judgment"
    assert brief["section"]["title"] == "证据判断"
    assert brief["all_section_titles"] == ["事件过程", "证据判断"]
    assert "section_fact_map" not in brief


def test_section_writer_mode_generates_header_and_each_section_independently() -> None:
    previous = os.environ.get("INCIDENT_AGENT_WRITER_SECTION_MODE")
    os.environ["INCIDENT_AGENT_WRITER_SECTION_MODE"] = "1"
    try:
        llm = _FakeLLM()
        markdown = render_polished_body_from_writer_brief(llm, _sample_writer_brief())
    finally:
        if previous is None:
            os.environ.pop("INCIDENT_AGENT_WRITER_SECTION_MODE", None)
        else:
            os.environ["INCIDENT_AGENT_WRITER_SECTION_MODE"] = previous

    assert markdown.startswith("# 首页摘要")
    assert "## 事件过程" in markdown
    assert "## 证据判断" in markdown
    assert markdown.index("## 事件过程") < markdown.index("## 证据判断")
    assert len(llm.calls) == 3
    assert "section_type=timeline_process" in llm.calls[1]
    assert "section_type=evidence_judgment" in llm.calls[2]


def test_section_writer_mode_softens_overclaim_language_after_assembly() -> None:
    previous = os.environ.get("INCIDENT_AGENT_WRITER_SECTION_MODE")
    os.environ["INCIDENT_AGENT_WRITER_SECTION_MODE"] = "1"
    try:
        markdown = render_polished_body_from_writer_brief(_OverclaimFakeLLM(), _sample_writer_brief())
    finally:
        if previous is None:
            os.environ.pop("INCIDENT_AGENT_WRITER_SECTION_MODE", None)
        else:
            os.environ["INCIDENT_AGENT_WRITER_SECTION_MODE"] = previous

    assert "证实了横向移动的存在" not in markdown
    assert "恶意活动已经扩散" not in markdown
    assert "提示存在横向移动线索" in markdown
    assert "异常线索已经扩展" in markdown


if __name__ == "__main__":
    test_section_prompt_brief_contains_only_selected_section()
    test_section_writer_mode_generates_header_and_each_section_independently()
    test_section_writer_mode_softens_overclaim_language_after_assembly()
    print("report section writer checks passed")
