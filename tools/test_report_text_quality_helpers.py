from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from demo_agent.incidents.report_text_quality import (  # noqa: E402
    is_low_information_evidence_label,
    is_meta_material_text,
)


def test_meta_material_text_detection_is_shared() -> None:
    assert is_meta_material_text("当前只能依据已整理的交付判断和证据包保守生成报告材料。")
    assert is_meta_material_text("只能依据已整理证据包输出。")
    assert not is_meta_material_text("主链证据已达到确认事件交付门槛。")


def test_low_information_evidence_label_detection_is_shared() -> None:
    assert is_low_information_evidence_label("suspicious")
    assert is_low_information_evidence_label("malicious")
    assert is_low_information_evidence_label("主支撑证据")
    assert not is_low_information_evidence_label("2026-07-14 01:18:00 UTC host-a 出现远程服务创建线索。")


if __name__ == "__main__":
    test_meta_material_text_detection_is_shared()
    test_low_information_evidence_label_detection_is_shared()
    print("report text quality helper checks passed")
