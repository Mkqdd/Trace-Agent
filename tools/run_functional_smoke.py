from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


ROOT = Path(__file__).resolve().parents[1]
OUTPUT_ROOT = ROOT / "outputs" / "functional_tests"
DEFAULT_TIMEOUT_S = int(os.getenv("SMOKE_TIMEOUT_S") or "120")


@dataclass
class SmokeCase:
    name: str
    mode: str
    alert_path: Optional[Path] = None
    alert_payload: Optional[Any] = None
    env_overrides: Optional[Dict[str, str]] = None
    expect_gap_trigger: Optional[bool] = None
    notes: str = ""
    timeout_s: Optional[int] = None


def _now_tag() -> str:
    return time.strftime("%Y%m%d_%H%M%S", time.localtime())


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _build_cases(run_dir: Path) -> List[SmokeCase]:
    demo_alerts = _load_json(ROOT / "demo_alert.json")
    if not isinstance(demo_alerts, list) or len(demo_alerts) < 3:
        raise RuntimeError("demo_alert.json does not contain expected smoke cases")

    ip_only_path = run_dir / "inputs" / "ip_only.json"
    _write_json(ip_only_path, [demo_alerts[1]])

    ja4_only_path = run_dir / "inputs" / "ja4_only.json"
    _write_json(ja4_only_path, [demo_alerts[2]])

    return [
        SmokeCase(
            name="batch_plan_full",
            mode="plan",
            alert_path=ROOT / "demo_alert.json",
            env_overrides={"REPORT_RENDERER": "local"},
            notes="主链批量样例，覆盖 JA3/IP/JA4/SSL_SHA1。",
            timeout_s=120,
        ),
        SmokeCase(
            name="gap_probe_plan",
            mode="plan",
            alert_path=ROOT / "react_gap_probe.json",
            env_overrides={"REPORT_RENDERER": "local"},
            expect_gap_trigger=True,
            notes="验证 plan 主链中的 gap -> React 补查链路是否触发。",
            timeout_s=90,
        ),
        SmokeCase(
            name="ip_without_vt",
            mode="plan",
            alert_path=ip_only_path,
            env_overrides={
                "REPORT_RENDERER": "local",
                "VT_API_KEY": "",
                "VIRUSTOTAL_API_KEY": "",
            },
            notes="验证 VT 缺失时是否安全降级。",
            timeout_s=90,
        ),
        SmokeCase(
            name="ja4_without_db",
            mode="plan",
            alert_path=ja4_only_path,
            env_overrides={
                "REPORT_RENDERER": "local",
                "DB_URL": "",
                "DB_HOST": "127.0.0.1",
                "DB_PORT": "1",
            },
            notes="验证本地 MySQL 不可用时是否安全降级。",
            timeout_s=90,
        ),
    ]


def _run_case(case: SmokeCase, run_dir: Path) -> Dict[str, Any]:
    case_out = run_dir / case.name
    env = os.environ.copy()
    for key, value in (case.env_overrides or {}).items():
        env[key] = value

    if case.alert_path is None:
        raise RuntimeError(f"case {case.name} missing alert_path")

    cmd = [
        sys.executable,
        "-m",
        "demo_agent.langchain_agent",
        "--alert",
        str(case.alert_path),
        "--out",
        str(case_out),
        "--mode",
        case.mode,
    ]
    timeout_s = int(case.timeout_s or DEFAULT_TIMEOUT_S)

    started = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(ROOT),
            env=env,
            text=True,
            capture_output=True,
            timeout=timeout_s,
        )
        duration_s = round(time.perf_counter() - started, 2)
    except subprocess.TimeoutExpired as exc:
        return {
            "name": case.name,
            "mode": case.mode,
            "notes": case.notes,
            "command": cmd,
            "returncode": None,
            "duration_s": round(time.perf_counter() - started, 2),
            "ok": False,
            "stdout_json_parsed": False,
            "stderr_tail": f"timeout after {timeout_s}s",
            "items": [],
            "gap_triggered": False,
            "expected_gap_trigger": case.expect_gap_trigger,
        }

    parsed_stdout: Dict[str, Any] = {}
    try:
        parsed_stdout = json.loads(proc.stdout or "{}")
    except Exception:
        parsed_stdout = {}

    items = list(parsed_stdout.get("items") or [])
    analyzed_items = [_analyze_item(item) for item in items]
    overall_ok = proc.returncode == 0 and all(item["ok"] for item in analyzed_items)

    gap_triggered = any(item.get("gap_triggered") for item in analyzed_items)
    if case.expect_gap_trigger is True and not gap_triggered:
        overall_ok = False

    return {
        "name": case.name,
        "mode": case.mode,
        "notes": case.notes,
        "command": cmd,
        "returncode": proc.returncode,
        "duration_s": duration_s,
        "ok": overall_ok,
        "stdout_json_parsed": bool(parsed_stdout),
        "stderr_tail": (proc.stderr or "").strip()[-4000:],
        "items": analyzed_items,
        "gap_triggered": gap_triggered,
        "expected_gap_trigger": case.expect_gap_trigger,
    }


def _analyze_item(item: Dict[str, Any]) -> Dict[str, Any]:
    out_dir = Path(str(item.get("out_dir") or ""))
    analysis_path = out_dir / "analysis.json"
    report_path = out_dir / "report.md"
    topology_path = out_dir / "topology.json"

    result = {
        "ok": True,
        "out_dir": str(out_dir),
        "analysis_exists": analysis_path.exists(),
        "report_exists": report_path.exists(),
        "topology_exists": topology_path.exists(),
        "issues": [],
    }

    if not analysis_path.exists():
        result["ok"] = False
        result["issues"].append("missing analysis.json")
        return result

    analysis = _load_json(analysis_path)
    report = report_path.read_text(encoding="utf-8") if report_path.exists() else ""
    topology = _load_json(topology_path) if topology_path.exists() else {}

    assessment = analysis.get("assessment") or {}
    derived = analysis.get("derived") or {}
    family = str(assessment.get("family") or derived.get("family") or "").strip()
    severity = str(assessment.get("severity") or derived.get("severity") or "").strip()
    confidence = assessment.get("confidence") or derived.get("confidence")

    evidence = list(analysis.get("evidence") or [])
    findings = list(analysis.get("findings") or [])
    gaps = list(analysis.get("gaps") or [])
    gap_types = [str(g.get("type") or "") for g in gaps]
    supplemental = analysis.get("supplemental") or {}
    supplemental_evidence = list(supplemental.get("supplemental_evidence") or [])
    local_intel = analysis.get("local_intel") or {}
    timings = analysis.get("timings") or {}

    topology_text = json.dumps(topology, ensure_ascii=False)
    gap_plan = ((item.get("result") or {}).get("gap_plan") or {}).get("items") or []

    result.update(
        {
            "indicator_type": str(((analysis.get("facts") or {}).get("fingerprint") or {}).get("type") or ""),
            "family": family,
            "severity": severity,
            "confidence": confidence,
            "evidence_count": len(evidence),
            "findings_count": len(findings),
            "gap_fill_needed": bool(analysis.get("gap_fill_needed")),
            "gap_types": gap_types,
            "gap_triggered": bool(gap_plan),
            "supplemental_evidence_count": len(supplemental_evidence),
            "local_matched": bool(local_intel.get("matched")),
            "pipeline_total_s": timings.get("pipeline_total_s"),
            "baseline_total_s": timings.get("baseline_total_s"),
            "gap_execution_mode": timings.get("gap_execution_mode"),
        }
    )

    if not report_path.exists():
        result["ok"] = False
        result["issues"].append("missing report.md")
    if not topology_path.exists():
        result["ok"] = False
        result["issues"].append("missing topology.json")
    if not family:
        result["ok"] = False
        result["issues"].append("missing assessment.family")
    if len(evidence) == 0:
        result["ok"] = False
        result["issues"].append("no evidence collected")
    if len(findings) == 0:
        result["ok"] = False
        result["issues"].append("no findings generated")
    if family and family != "Unknown" and report and family not in report:
        result["ok"] = False
        result["issues"].append("family not present in report")
    if family and topology and family not in topology_text:
        result["ok"] = False
        result["issues"].append("family not present in topology")
    if "gap_fill_needed" in report or "confidence_driver" in report:
        result["ok"] = False
        result["issues"].append("internal analysis fields leaked into report")
    if "Agent stopped due to iteration limit or time limit." in report:
        result["ok"] = False
        result["issues"].append("react report degraded to raw stop message")

    return result


def _make_markdown(summary: Dict[str, Any]) -> str:
    lines = [
        "# 功能测试结果",
        "",
        f"- 运行时间：{summary['started_at']}",
        f"- 总用例数：{summary['case_count']}",
        f"- 通过用例：{summary['passed_case_count']}",
        f"- 失败用例：{summary['failed_case_count']}",
        "",
        "| case | mode | ok | duration(s) | gap_triggered | notes |",
        "|------|------|----|-------------|---------------|-------|",
    ]
    for case in summary["cases"]:
        lines.append(
            f"| {case['name']} | {case['mode']} | {'PASS' if case['ok'] else 'FAIL'} | {case['duration_s']} | "
            f"{case['gap_triggered']} | {case['notes']} |"
        )
    lines.append("")
    lines.append("## 逐项结果")
    lines.append("")
    for case in summary["cases"]:
        lines.append(f"### {case['name']}")
        lines.append(f"- 状态：{'PASS' if case['ok'] else 'FAIL'}")
        lines.append(f"- 模式：{case['mode']}")
        lines.append(f"- 用时：{case['duration_s']}s")
        lines.append(f"- 触发补查：{case['gap_triggered']}")
        if case["stderr_tail"]:
            stderr_brief = case["stderr_tail"][:300].replace("`", "'")
            lines.append(f"- stderr 摘要：`{stderr_brief}`")
        for idx, item in enumerate(case["items"], start=1):
            lines.append(f"- item{idx}: type={item.get('indicator_type')} family={item.get('family')} evidence={item.get('evidence_count')} issues={'; '.join(item.get('issues') or ['none'])}")
        lines.append("")
    return "\n".join(lines).strip() + "\n"


def main() -> None:
    run_dir = OUTPUT_ROOT / _now_tag()
    run_dir.mkdir(parents=True, exist_ok=True)

    cases = _build_cases(run_dir)
    results = [_run_case(case, run_dir) for case in cases]

    summary = {
        "started_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "run_dir": str(run_dir),
        "case_count": len(results),
        "passed_case_count": sum(1 for case in results if case["ok"]),
        "failed_case_count": sum(1 for case in results if not case["ok"]),
        "cases": results,
    }

    _write_json(run_dir / "summary.json", summary)
    (run_dir / "summary.md").write_text(_make_markdown(summary), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
