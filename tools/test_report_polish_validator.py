from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from demo_agent.incidents.report_polish_validator import validate_report_polish  # noqa: E402


def test_chinese_sentence_boundary_prevents_cross_sentence_event_tuple() -> None:
    fact_cards = {
        "fact_cards": [
            {
                "fact_type": "event",
                "time": "2026-07-14 01:24:00 UTC",
                "subject": "ws-eng-05",
                "object": "维护或计划内背景活动",
            },
            {
                "fact_type": "event",
                "time": "2026-07-14 01:26:00 UTC",
                "subject": "ws-eng-05",
                "object": "download.windowsupdate.com / 13.107.246.45",
            },
        ],
        "scope_packet": {},
    }
    body = (
        "## 反证、缺口与结论边界\n\n"
        "具体而言，ws-eng-05 在 2026-07-14 01:24:00 UTC 有经批准的 SCCM 补丁暂存活动，"
        "且同一天 01:26:00 UTC 又从 download.windowsupdate.com / 13.107.246.45 下载了 Windows 更新内容。"
        "这些背景事件不能直接推翻横向移动的线索。"
    )

    validation = validate_report_polish(body, fact_cards)

    assert validation["status"] == "clean"
    assert validation["issues"] == []


def test_event_tuple_mismatch_is_not_judged_by_polish_validator() -> None:
    fact_cards = {
        "fact_cards": [
            {
                "fact_type": "event",
                "time": "2026-07-14 01:24:00 UTC",
                "subject": "host-a",
                "object": "计划内维护活动",
            },
            {
                "fact_type": "event",
                "time": "2026-07-14 01:21:10 UTC",
                "subject": "host-b",
                "object": "10.0.0.5",
            },
        ],
        "scope_packet": {},
    }
    body = (
        "## 边界\n\n"
        "2026-07-14 01:24:00 UTC，host-a 与 10.0.0.5 的通信告警处在相近窗口，"
        "需要继续核查是否只是背景重叠。"
    )

    validation = validate_report_polish(body, fact_cards)

    assert validation["status"] == "clean"
    assert validation["issue_counts"]["hard_fail"] == 0
    assert validation["issue_counts"]["soft_warn"] == 0
    assert validation["issues"] == []


def test_conditional_candidate_scope_language_is_not_a_hard_failure() -> None:
    fact_cards = {
        "fact_cards": [
            {
                "fact_type": "scope",
                "entity": "ws-eng-09",
            },
        ],
        "scope_packet": {"candidate_entities": ["ws-eng-09"]},
    }
    body = (
        "## 处置建议与后续核查\n\n"
        "查找是否存在来自 ws-eng-05 的 WMI 远程执行成功后的落地文件、持久化任务或独立外联，"
        "以决定是否将 ws-eng-09 从候选边界提升为已确认受影响范围。"
    )

    validation = validate_report_polish(body, fact_cards)

    assert validation["status"] == "clean"
    assert validation["issues"] == []


if __name__ == "__main__":
    test_chinese_sentence_boundary_prevents_cross_sentence_event_tuple()
    test_event_tuple_mismatch_is_not_judged_by_polish_validator()
    test_conditional_candidate_scope_language_is_not_a_hard_failure()
    print("report polish validator checks passed")
