from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = ROOT / "fixtures" / "incidents"
OUTPUT_ROOT = ROOT / "outputs" / "incident_tests"
EVENT_TOOL_NAMES = {"search_seed_context", "search_related_events", "expand_asset_scope"}
INTEL_OR_PAGE_TOOL_NAMES = {
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


def _check_acceptance(incident: Dict[str, Any], acceptance: Dict[str, Any]) -> List[str]:
    issues: List[str] = []
    verdict = incident.get("verdict") or {}
    entities = incident.get("entities") or {}
    hypothesis = incident.get("hypothesis") or {}
    timeline = [str(item.get("summary") or "") for item in list(incident.get("timeline") or [])]

    expected_status = str(acceptance.get("verdict_status") or "").strip()
    if expected_status and verdict.get("status") != expected_status:
        issues.append(f"verdict mismatch: expected {expected_status}, got {verdict.get('status')}")

    min_event_count = int(acceptance.get("min_event_count") or 0)
    actual_event_count = int(((incident.get("cluster") or {}).get("event_count")) or 0)
    if actual_event_count < min_event_count:
        issues.append(f"event count too small: expected >= {min_event_count}, got {actual_event_count}")

    for asset in list(acceptance.get("must_include_assets") or []):
        if asset not in list(entities.get("assets") or []):
            issues.append(f"missing expected asset: {asset}")

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

    return issues


def _check_agent_acceptance(incident: Dict[str, Any], trace: List[Dict[str, Any]]) -> List[str]:
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

    stop_reason = str(((incident.get("session_state") or {}).get("stop_reason")) or "").strip()
    if not stop_reason:
        issues.append("missing session_state.stop_reason")

    open_questions = list(incident.get("open_questions") or [])
    uncertainties = list(incident.get("uncertainties") or [])
    if open_questions and not uncertainties:
        issues.append("open_questions present but uncertainties not populated")

    report_ready = bool(((incident.get("state") or {}).get("report_ready")))
    if not report_ready:
        issues.append("incident-agent did not reach report_ready")

    return issues


def _run_agent(*, fixture_dir: Path, out_dir: Path) -> Dict[str, Any]:
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
    trace_path = Path(str(item.get("investigation_trace_path") or out_dir / "investigation_trace.json"))
    issues: List[str] = []

    if proc.returncode != 0:
        issues.append(f"command failed: rc={proc.returncode}")
    if not incident_path.exists():
        issues.append("missing incident.json")
    if not report_path.exists():
        issues.append("missing report.md")
    if not trace_path.exists():
        issues.append("missing investigation_trace.json")

    incident: Dict[str, Any] = {}
    trace: List[Dict[str, Any]] = []
    if not issues:
        incident = _load_json(incident_path)
        trace = _load_json(trace_path)
        acceptance = _load_json(fixture_dir / "acceptance.json")
        issues.extend(_check_acceptance(incident, acceptance))
        issues.extend(_check_agent_acceptance(incident, trace))

    return {
        "ok": not issues,
        "issues": issues,
        "stderr_tail": (proc.stderr or "").strip()[-1000:],
        "out_dir": str(out_dir),
        "incident": incident,
        "trace": trace,
    }


def main() -> None:
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    results: List[Dict[str, Any]] = []

    for fixture_dir in _fixture_dirs():
        agent_dir = OUTPUT_ROOT / fixture_dir.name / "agent"
        agent = _run_agent(fixture_dir=fixture_dir, out_dir=agent_dir)
        case_ok = agent["ok"]
        results.append(
            {
                "case": fixture_dir.name,
                "ok": case_ok,
                "agent": {
                    "ok": agent["ok"],
                    "issues": agent["issues"],
                    "out_dir": agent["out_dir"],
                },
            }
        )

    summary = {"ok": all(item["ok"] for item in results), "results": results}
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    if not summary["ok"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
