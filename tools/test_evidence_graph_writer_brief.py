from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from demo_agent.incidents.evidence_graph import build_graph_writer_brief  # noqa: E402
from demo_agent.incidents.report_agent_writer import render_polished_body_from_graph_writer_brief  # noqa: E402


class _FakeResponse:
    def __init__(self, content: str) -> None:
        self.content = content


class _GraphOverclaimFakeLLM:
    def bind(self, **kwargs):
        return self

    def invoke(self, messages):
        return _FakeResponse(
            "# 首页摘要\n\n"
            "- **结论**：确认安全事件\n"
            "- **严重度**：高\n"
            "- **研判把握**：高\n"
            "- **已确认范围**：host-a、host-b\n"
            "- **一句话结论**：北京时间 2026 年 7 月 14 日 09:04，攻击者成功入侵 host-b，并把它变成攻击者控制链上的新节点。\n"
            "- **立即动作**：隔离 host-a、host-b。\n"
        )


class _GraphLookbackFakeLLM:
    def bind(self, **kwargs):
        return self

    def invoke(self, messages):
        return _FakeResponse(
            "# 首页摘要\n\n"
            "- **结论**：确认安全事件\n"
            "- **严重度**：高\n"
            "- **研判把握**：中\n"
            "- **已确认范围**：host-a\n"
            "- **一句话结论**：host-a 出现异常通信。\n"
            "- **立即动作**：通过 EDR 或 Sysmon 日志源，提取并分析 `2026-06-20 10:00:00 UTC` 至 `11:30:00 UTC` 间的所有进程创建、网络连接和 DNS 查询事件。\n"
            "- **后续核查**：通过 EDR 日志和网络流量日志，复核它们在 `2026-06-20 10:30:00 UTC` 至 `11:30:00 UTC` 窗口内的进程和网络行为。\n"
        )


def test_graph_writer_brief_contains_graph_lenses_hypotheses_and_constraints() -> None:
    source_bundle = {
        "case_header": {"case_id": "sample-case", "verdict_status": "confirmed"},
        "source_counts": {"events": 1},
    }
    fact_catalog = [
        {
            "fact_id": "fact:event:001",
            "source_id": "event:evt-001",
            "fact_type": "event",
            "status": "confirmed",
            "time": "2026-07-14 01:10:00 UTC",
            "asset": "host-a",
            "objects": ["c2.example"],
            "summary_line": "host-a connected to c2.example.",
            "exact_fact_text": "host-a connected to c2.example.",
            "reporting_focus": "主支撑事件",
            "candidate_or_boundary": False,
        }
    ]

    brief = build_graph_writer_brief(source_bundle, fact_catalog)

    assert brief["schema_version"] == "report-graph-writer-brief-v1"
    assert brief["writer_mode"] == "evidence_graph"
    assert brief["evidence_graph"]["schema_version"] == "report-evidence-graph-v1"
    assert brief["graph_lenses"]["schema_version"] == "report-evidence-graph-lenses-v1"
    assert brief["hypothesis_board"]["schema_version"] == "report-hypothesis-board-v1"
    assert "required_shape" in brief["writing_contract"]
    assert "candidate_not_confirmed" in " ".join(brief["writing_contract"]["claim_policies"])


def test_graph_writer_normalization_restores_utc_and_softens_control_overclaims() -> None:
    brief = build_graph_writer_brief(
        {"case_header": {"case_id": "sample-case"}, "source_counts": {"events": 1}},
        [
            {
                "fact_id": "fact:event:001",
                "source_id": "event:evt-001",
                "fact_type": "event",
                "status": "confirmed",
                "time": "2026-07-14 01:04:00 UTC",
                "asset": "host-a",
                "objects": ["host-b"],
                "summary_line": "2026-07-14 01:04:00 UTC，host-a had a remote service creation signal toward host-b.",
                "exact_fact_text": "2026-07-14 01:04:00 UTC，host-a had a remote service creation signal toward host-b.",
                "reporting_focus": "主支撑事件",
                "candidate_or_boundary": False,
            }
        ],
    )

    markdown = render_polished_body_from_graph_writer_brief(_GraphOverclaimFakeLLM(), brief)

    assert "北京时间" not in markdown
    assert "2026-07-14 01:04:00 UTC" in markdown
    assert "成功入侵" not in markdown
    assert "攻击者控制链上的新节点" not in markdown
    assert "纳入确认受影响范围" in markdown or "受影响节点" in markdown


def test_graph_writer_rewrites_unsupported_lookback_windows_to_current_window() -> None:
    brief = build_graph_writer_brief(
        {"case_header": {"case_id": "sample-case"}, "source_counts": {"events": 1}},
        [
            {
                "fact_id": "fact:event:001",
                "source_id": "event:evt-001",
                "fact_type": "event",
                "status": "confirmed",
                "time": "2026-07-14 01:04:00 UTC",
                "asset": "host-a",
                "objects": ["host-b"],
                "summary_line": "2026-07-14 01:04:00 UTC，host-a had a remote service creation signal toward host-b.",
                "exact_fact_text": "2026-07-14 01:04:00 UTC，host-a had a remote service creation signal toward host-b.",
                "reporting_focus": "主支撑事件",
                "candidate_or_boundary": False,
            }
        ],
    )

    markdown = render_polished_body_from_graph_writer_brief(_GraphLookbackFakeLLM(), brief)

    assert "2026-06-20 10:00:00 UTC" not in markdown
    assert "2026-06-20 10:30:00 UTC" not in markdown
    assert "11:30:00 UTC" not in markdown
    assert "当前调查窗口" in markdown or "当前调查范围" in markdown


if __name__ == "__main__":
    test_graph_writer_brief_contains_graph_lenses_hypotheses_and_constraints()
    test_graph_writer_normalization_restores_utc_and_softens_control_overclaims()
    test_graph_writer_rewrites_unsupported_lookback_windows_to_current_window()
    print("evidence graph writer brief checks passed")
