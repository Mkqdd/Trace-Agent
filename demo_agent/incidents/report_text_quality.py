from __future__ import annotations

from typing import Any


LOW_INFORMATION_EVIDENCE_LABELS = {
    "suspicious",
    "malicious",
    "benign",
    "confirmed",
    "candidate",
    "needs_review",
    "unknown",
    "主支撑证据",
    "范围证据",
    "边界证据",
    "章节事实",
    "关键事件事实",
    "可疑",
    "恶意",
}

META_MATERIAL_TEXT_MARKERS = {
    "生成报告材料",
    "证据包保守生成",
    "只能依据已整理",
    "只能依据已整理证据包",
}


def _text(value: Any) -> str:
    return str(value or "").strip()


def is_low_information_evidence_label(value: Any) -> bool:
    text = _text(value)
    if not text:
        return False
    return text in LOW_INFORMATION_EVIDENCE_LABELS or text.lower() in LOW_INFORMATION_EVIDENCE_LABELS


def is_meta_material_text(value: Any) -> bool:
    text = _text(value)
    return bool(text and any(marker in text for marker in META_MATERIAL_TEXT_MARKERS))
