from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = ROOT / "fixtures" / "incidents"
OUTPUT_ROOT = ROOT / "outputs" / "incident_tests"
EVENT_TOOL_NAMES = {"search_seed_context", "search_related_events", "expand_asset_scope", "check_counterevidence"}
INTEL_OR_PAGE_TOOL_NAMES = {
    "ground_candidate_event",
    "local_intel_lookup",
    "vt_enrich_ioc",
    "abuse_ch_lookup",
    "technical_source_search",
    "malware_profile_lookup",
    "pivot_related_indicators",
    "threatfox_ioc_lookup",
    "urlhaus_ioc_lookup",
    "fetch_page_content",
    "extract_claim_candidates_from_page",
    "extract_entities_from_page",
}


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _fixture_dirs() -> List[Path]:
    return sorted(path for path in FIXTURE_ROOT.iterdir() if path.is_dir() and (path / "seed_alert.json").exists())


def _contains_fragment(items: List[str], fragment: str) -> bool:
    lowered_fragment = fragment.lower()
    return any(lowered_fragment in item.lower() for item in items)


def _contains_text(text: str, fragment: str) -> bool:
    return str(fragment or "").strip().lower() in str(text or "").lower()


def _check_acceptance(
    incident: Dict[str, Any],
    acceptance: Dict[str, Any],
    *,
    report_text: str,
    appendix_text: str,
) -> List[str]:
    issues: List[str] = []
    verdict = incident.get("verdict") or {}
    provisional_verdict = incident.get("provisional_verdict") or {}
    readiness = incident.get("readiness") or {}
    entities = incident.get("entities") or {}
    hypothesis = incident.get("hypothesis") or {}
    timeline = [str(item.get("summary") or "") for item in list(incident.get("timeline") or [])]
    open_questions = [
        str((item.get("question") if isinstance(item, dict) else item) or "").strip()
        for item in list(incident.get("open_questions") or [])
    ]
    uncertainties = [str(item or "").strip() for item in list(incident.get("uncertainties") or [])]
    decision_basis = incident.get("decision_basis") or {}

    expected_status = str(acceptance.get("verdict_status") or "").strip()
    if expected_status and verdict.get("status") != expected_status:
        issues.append(f"verdict mismatch: expected {expected_status}, got {verdict.get('status')}")

    expected_provisional_status = str(acceptance.get("provisional_status") or "").strip()
    if expected_provisional_status and provisional_verdict.get("status") != expected_provisional_status:
        issues.append(
            f"provisional verdict mismatch: expected {expected_provisional_status}, got {provisional_verdict.get('status')}"
        )

    if "ready_for_delivery" in acceptance:
        expected_ready = bool(acceptance.get("ready_for_delivery"))
        actual_ready = bool(readiness.get("ready_for_delivery"))
        if actual_ready != expected_ready:
            issues.append(f"ready_for_delivery mismatch: expected {expected_ready}, got {actual_ready}")

    min_event_count = int(acceptance.get("min_event_count") or 0)
    actual_event_count = int(((incident.get("cluster") or {}).get("event_count")) or 0)
    if actual_event_count < min_event_count:
        issues.append(f"event count too small: expected >= {min_event_count}, got {actual_event_count}")

    for asset in list(acceptance.get("must_include_assets") or []):
        if asset not in list(entities.get("assets") or []):
            issues.append(f"missing expected asset: {asset}")

    for asset in list(acceptance.get("must_include_related_assets") or []):
        if asset not in list(entities.get("related_assets") or []):
            issues.append(f"missing expected related asset: {asset}")

    for asset in list(acceptance.get("must_not_include_assets") or []):
        if asset in list(entities.get("assets") or []):
            issues.append(f"unexpected asset present: {asset}")

    for asset in list(acceptance.get("must_not_include_related_assets") or []):
        if asset in list(entities.get("related_assets") or []):
            issues.append(f"unexpected related asset present: {asset}")

    max_suspected_assets = acceptance.get("max_suspected_asset_count")
    if max_suspected_assets is not None:
        actual_suspected = len(list(entities.get("suspected_assets") or []))
        if actual_suspected > int(max_suspected_assets):
            issues.append(
                f"suspected asset count too large: expected <= {int(max_suspected_assets)}, got {actual_suspected}"
            )

    for domain in list(acceptance.get("must_include_domains") or []):
        if domain not in list(entities.get("domains") or []):
            issues.append(f"missing expected domain: {domain}")

    stages = list(hypothesis.get("stages") or [])
    for stage in list(acceptance.get("must_include_stages") or []):
        if stage not in stages:
            issues.append(f"missing expected stage: {stage}")
    for stage in list(acceptance.get("must_not_include_stages") or []):
        if stage in stages:
            issues.append(f"unexpected stage present: {stage}")

    for fragment in list(acceptance.get("timeline_contains") or []):
        if not _contains_fragment(timeline, fragment):
            issues.append(f"timeline missing fragment: {fragment}")

    min_counterevidence_count = int(acceptance.get("min_counterevidence_count") or 0)
    actual_counterevidence_count = len(list(decision_basis.get("counterevidence") or []))
    if actual_counterevidence_count < min_counterevidence_count:
        issues.append(
            f"counterevidence count too small: expected >= {min_counterevidence_count}, got {actual_counterevidence_count}"
        )

    min_positive_signal_count = int(acceptance.get("min_positive_signal_count") or 0)
    actual_positive_signal_count = len(list(decision_basis.get("positive_signals") or []))
    if actual_positive_signal_count < min_positive_signal_count:
        issues.append(
            f"positive signal count too small: expected >= {min_positive_signal_count}, got {actual_positive_signal_count}"
        )

    for fragment in list(acceptance.get("open_questions_contains") or []):
        if not _contains_fragment(open_questions, fragment):
            issues.append(f"open questions missing fragment: {fragment}")

    for fragment in list(acceptance.get("uncertainties_contains") or []):
        if not _contains_fragment(uncertainties, fragment):
            issues.append(f"uncertainties missing fragment: {fragment}")

    for fragment in list(acceptance.get("report_contains") or []):
        if not _contains_text(report_text, fragment):
            issues.append(f"report missing fragment: {fragment}")

    for fragment in list(acceptance.get("report_not_contains") or []):
        if _contains_text(report_text, fragment):
            issues.append(f"report unexpectedly contains fragment: {fragment}")

    for fragment in list(acceptance.get("appendix_contains") or []):
        if not _contains_text(appendix_text, fragment):
            issues.append(f"appendix missing fragment: {fragment}")

    for fragment in list(acceptance.get("appendix_not_contains") or []):
        if _contains_text(appendix_text, fragment):
            issues.append(f"appendix unexpectedly contains fragment: {fragment}")

    return issues


def _check_agent_acceptance(
    incident: Dict[str, Any],
    trace: List[Dict[str, Any]],
    *,
    report_text: str,
    appendix_text: str,
    acceptance: Dict[str, Any],
) -> List[str]:
    issues: List[str] = []
    if len(trace) < 2:
        issues.append("agent trace too short: expected >= 2 rounds")

    tool_names = [
        str(((item.get("selected_action") or {}).get("tool_name")) or "").strip()
        for item in trace
    ]
    if not any(name in EVENT_TOOL_NAMES for name in tool_names):
        issues.append("agent trace missing event tool action")
    if not any(name in INTEL_OR_PAGE_TOOL_NAMES for name in tool_names):
        issues.append("agent trace missing intel/page tool action")
    if "check_counterevidence" not in tool_names:
        issues.append("agent trace missing explicit counterevidence check action")

    stop_reason = str(((incident.get("session_state") or {}).get("stop_reason")) or "").strip()
    if not stop_reason:
        issues.append("missing session_state.stop_reason")

    open_questions = list(incident.get("open_questions") or [])
    uncertainties = list(incident.get("uncertainties") or [])
    if open_questions and not uncertainties:
        issues.append("open_questions present but uncertainties not populated")

    readiness = incident.get("readiness") or ((incident.get("state") or {}).get("readiness") or {})
    if not isinstance(readiness, dict) or not list(readiness.get("checks") or []):
        issues.append("missing readiness checks")
    require_ready = bool(acceptance.get("require_ready_for_delivery", True))
    if require_ready and not bool(readiness.get("ready_for_delivery")):
        issues.append("incident-agent did not reach ready_for_delivery")

    report_ready = bool(((incident.get("state") or {}).get("report_ready")))
    if require_ready and not report_ready:
        issues.append("incident-agent did not reach report_ready")

    state = incident.get("state") or {}
    if not bool(state.get("counterevidence_checked")):
        issues.append("state.counterevidence_checked is false")

    delivery_verdict = incident.get("delivery_verdict") or {}
    top_level_verdict = incident.get("verdict") or {}
    if delivery_verdict and top_level_verdict != delivery_verdict:
        issues.append("incident.verdict is not aligned with delivery_verdict")
    if not (incident.get("provisional_verdict") or {}):
        issues.append("missing provisional_verdict")
    for key in [
        "report_contract",
        "report_outline",
        "main_report_contract",
        "ops_report_contract",
        "appendix_contract",
        "evidence_contract",
    ]:
        if key in incident:
            issues.append(f"incident should not cache report artifact alias: {key}")

    required_report_sections = [
        "## 首页摘要",
        "## 1. 事件背景与已知线索",
        "## 2. 范围界定与调查假设",
        "## 3. 对象覆盖策略与关键实体",
        "## 5. 关键证据与异常事实",
        "## 8. 影响分析",
        "## 9. 证据链摘要与观测缺口",
        "## 10. 结论与后续建议",
        "## 11. 技术附录提示",
    ]
    for section in required_report_sections:
        if section not in report_text:
            issues.append(f"report missing required section: {section}")

    required_appendix_sections = [
        "## 1. IOC / IOA 清单",
        "## 2. 关键对象清单",
        "## 3. 关键证据细目",
        "## 4. 观测引用对照",
        "## 5. 正文章节引用映射",
        "## 6. 证据来源与参考资料",
        "## 7. 证据缺口与待补查询",
    ]
    for section in required_appendix_sections:
        if section not in appendix_text:
            issues.append(f"report appendix missing required section: {section}")

    for fragment in ["tool_name", "source_type", "internal_digest", "trace_store.", "readiness check"]:
        if _contains_text(report_text, fragment):
            issues.append(f"main report leaked internal implementation fragment: {fragment}")

    return issues


def _run_agent(*, fixture_dir: Path, out_dir: Path, decision_mode: str) -> Dict[str, Any]:
    cmd = [
        sys.executable,
        "-m",
        "demo_agent",
        "--alert",
        str(fixture_dir),
        "--out",
        str(out_dir),
        "--mode",
        "incident-agent",
        "--decision-mode",
        decision_mode,
    ]
    proc = subprocess.run(
        cmd,
        cwd=str(ROOT),
        text=True,
        capture_output=True,
        timeout=90,
    )
    parsed_stdout = json.loads(proc.stdout or "{}") if proc.stdout.strip() else {}
    item = list(parsed_stdout.get("items") or [{}])[0]
    incident_path = Path(str(item.get("incident_json_path") or out_dir / "incident.json"))
    report_path = Path(str(item.get("report_path") or out_dir / "report.md"))
    report_appendix_path = Path(str(item.get("report_appendix_path") or out_dir / "report_appendix.md"))
    report_polished_path = Path(str(item.get("report_polished_path") or "")).resolve() if item.get("report_polished_path") else None
    trace_path = Path(str(item.get("investigation_trace_path") or out_dir / "investigation_trace.json"))
    issues: List[str] = []

    if proc.returncode != 0:
        issues.append(f"command failed: rc={proc.returncode}")
    if not incident_path.exists():
        issues.append("missing incident.json")
    if not report_path.exists():
        issues.append("missing report.md")
    if not report_appendix_path.exists():
        issues.append("missing report_appendix.md")
    if report_polished_path is not None and not report_polished_path.exists():
        issues.append("reported report_polished.md path does not exist")
    if not trace_path.exists():
        issues.append("missing investigation_trace.json")

    incident: Dict[str, Any] = {}
    trace: List[Dict[str, Any]] = []
    if not issues:
        incident = _load_json(incident_path)
        trace = _load_json(trace_path)
        acceptance = _load_json(fixture_dir / "acceptance.json")
        report_text = report_path.read_text(encoding="utf-8")
        appendix_text = report_appendix_path.read_text(encoding="utf-8")
        issues.extend(_check_acceptance(incident, acceptance, report_text=report_text, appendix_text=appendix_text))
        issues.extend(
            _check_agent_acceptance(
                incident,
                trace,
                report_text=report_text,
                appendix_text=appendix_text,
                acceptance=acceptance,
            )
        )

    return {
        "ok": not issues,
        "issues": issues,
        "stderr_tail": (proc.stderr or "").strip()[-1000:],
        "out_dir": str(out_dir),
        "decision_mode": decision_mode,
        "incident": incident,
        "trace": trace,
    }


def main() -> None:
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    results: List[Dict[str, Any]] = []
    decision_mode = str(os.getenv("INCIDENT_SMOKE_DECISION_MODE") or "heuristic").strip() or "heuristic"

    for fixture_dir in _fixture_dirs():
        agent_dir = OUTPUT_ROOT / fixture_dir.name / "agent"
        agent = _run_agent(fixture_dir=fixture_dir, out_dir=agent_dir, decision_mode=decision_mode)
        case_ok = agent["ok"]
        results.append(
            {
                "case": fixture_dir.name,
                "decision_mode": decision_mode,
                "ok": case_ok,
                "agent": {
                    "ok": agent["ok"],
                    "issues": agent["issues"],
                    "out_dir": agent["out_dir"],
                },
            }
        )

    summary = {"ok": all(item["ok"] for item in results), "decision_mode": decision_mode, "results": results}
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    if not summary["ok"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
