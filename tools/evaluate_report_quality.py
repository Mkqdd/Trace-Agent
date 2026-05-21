from __future__ import annotations

import argparse
import json
from pathlib import Path


DIMENSIONS = [
    "factual_grounding",
    "boundary_correctness",
    "actionability",
    "analytical_depth",
    "non_repetition",
    "operator_readability",
]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.exists() else ""


def _load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _validation_status(case_dir: Path) -> dict:
    validation = _load_json(case_dir / "report_polish_validation.json")
    if not validation:
        return {"status": "missing", "issue_counts": {"hard_fail": 0, "soft_warn": 0}}
    return validation


def _case_summary(case_dir: Path) -> dict:
    report = _read(case_dir / "report_polished.md")
    validation = _validation_status(case_dir)
    trace = _load_json(case_dir / "report_material_loop_trace.json")
    writer_brief = _load_json(case_dir / "report_writer_brief.json")
    return {
        "case": case_dir.name,
        "writer_mode": writer_brief.get("writer_mode") or "",
        "report_chars": len(report),
        "report_lines": len(report.splitlines()),
        "validation_status": validation.get("status"),
        "validation_issues": validation.get("issue_counts"),
        "material_status": trace.get("status"),
        "material_agent_bypassed": trace.get("material_agent_bypassed"),
        "mentions_candidate": "候选" in report,
        "mentions_boundary": "边界" in report or "限制" in report,
        "mentions_action_fields": any(term in report for term in ["命令行", "日志", "字段", "哈希", "父进程", "DLL", "验证目标"]),
        "manual_scores": {dimension: None for dimension in DIMENSIONS},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Summarize Trace-Agent report quality signals for manual review.")
    parser.add_argument("--root", required=True, help="output root containing one directory per case")
    parser.add_argument("--out", default="", help="optional JSON summary output path")
    args = parser.parse_args()

    root = Path(args.root)
    cases = sorted(path for path in root.iterdir() if path.is_dir())
    summary = {"root": str(root), "cases": [_case_summary(case_dir) for case_dir in cases]}
    text = json.dumps(summary, ensure_ascii=False, indent=2)
    print(text)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
