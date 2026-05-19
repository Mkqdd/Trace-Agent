from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from demo_agent.incidents import report_agent_writer  # noqa: E402
from demo_agent.incidents.render import _reader_clean_text  # noqa: E402


def test_writer_prompts_do_not_name_fixture_specific_techniques_or_times() -> None:
    prompt_text = "\n".join(
        [
            report_agent_writer.REPORT_AGENT_WRITER_SYSTEM_PROMPT,
            report_agent_writer.REPORT_AGENT_WRITER_SECTION_PROMPT,
            "\n".join(report_agent_writer.build_report_writer_brief({"schema_version": "report-writer-materials-v2"}).get("writing_constraints", {}).get("global_rules", [])),
        ]
    )

    forbidden_fragments = [
        "rundll32",
        "PsExec",
        "WMI",
        "loader DLL",
        "2026-07-14 01:04:00 UTC",
    ]
    assert not [fragment for fragment in forbidden_fragments if fragment in prompt_text]


def test_reader_clean_text_does_not_rewrite_exact_fixture_sentences() -> None:
    fixture_sentences = [
        "Windows update content was downloaded from an approved Microsoft endpoint during the maintenance window.",
        "A QA telemetry job also touched the same hosting IP through a different vendor domain, indicating the secondary IP is shared infrastructure.",
        "The EDR sensor on host-a reported degraded process telemetry, so the execution lineage behind the second beacon cannot be reconstructed.",
    ]

    cleaned = [_reader_clean_text(sentence) for sentence in fixture_sentences]

    assert all("Windows 更新" not in item for item in cleaned)
    assert all("QA 遥测" not in item for item in cleaned)
    assert all("第二条 beacon" not in item for item in cleaned)


if __name__ == "__main__":
    test_writer_prompts_do_not_name_fixture_specific_techniques_or_times()
    test_reader_clean_text_does_not_rewrite_exact_fixture_sentences()
    print("case overfit rule checks passed")
