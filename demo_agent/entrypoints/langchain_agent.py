import json
import os
from pathlib import Path
from typing import Any, Dict, Tuple

from ..config import DOTENV_AVAILABLE, DOTENV_IMPORT_ERROR, DOTENV_LOADED, ENV_FILE, load_config
from ..incidents import run_incident_agent_case
from ..renderers.graph_drawer_pyvis import draw_graph_pyvis
from ..services.api.llm import make_llm
from ..types.event import normalize_alert
from ..utils.io import load_json, save_json, save_text


ROOT = Path(__file__).resolve().parents[2]
DECISION_MODE_CHOICES = ["heuristic", "llm_selector", "llm_agent", "hybrid"]
LLM_DECISION_MODES = {"llm_selector", "llm_agent", "hybrid"}


def _normalize_decision_mode(value: Any) -> str:
    text = str(value or "").strip().lower()
    aliases = {
        "": "heuristic",
        "default": "heuristic",
        "heuristic_fallback": "heuristic",
        "llm": "llm_selector",
        "selector": "llm_selector",
        "agent": "llm_agent",
        "open_agent": "llm_agent",
    }
    normalized = aliases.get(text, text)
    if normalized not in DECISION_MODE_CHOICES:
        return "heuristic"
    return normalized


def _truthy_env(name: str) -> bool:
    return str(os.getenv(name) or "").strip().lower() in {"1", "true", "yes"}


def _load_optional_llm(decision_mode: str | None = None) -> Tuple[Any, Dict[str, Any]]:
    requested_mode = _normalize_decision_mode(decision_mode or os.getenv("INCIDENT_AGENT_DECISION_MODE") or "")
    enabled_by_flag = _truthy_env("INCIDENT_AGENT_ENABLE_LLM")
    should_attempt = enabled_by_flag or requested_mode in LLM_DECISION_MODES
    runtime = {
        "requested_mode": requested_mode,
        "enabled_by_env_flag": enabled_by_flag,
        "attempted": should_attempt,
        "available": False,
        "reason": "",
        "dotenv_available": DOTENV_AVAILABLE,
        "dotenv_loaded": DOTENV_LOADED,
        "dotenv_env_file": str(ENV_FILE),
        "dotenv_env_file_exists": ENV_FILE.exists(),
        "model": "",
        "base_url": "",
    }
    if not DOTENV_AVAILABLE and DOTENV_IMPORT_ERROR:
        runtime["dotenv_import_error"] = DOTENV_IMPORT_ERROR
    if not should_attempt:
        runtime["reason"] = "llm_not_requested"
        return None, runtime
    try:
        cfg = load_config()
        runtime["model"] = cfg.llm_model
        runtime["base_url"] = cfg.llm_base_url
    except Exception as exc:
        runtime["reason"] = f"config_error:{type(exc).__name__}:{exc}"
        return None, runtime
    try:
        llm = make_llm(cfg)
    except Exception as exc:
        runtime["reason"] = f"init_error:{type(exc).__name__}:{exc}"
        return None, runtime
    runtime["available"] = True
    runtime["reason"] = "ok"
    return llm, runtime


def _resolve_incident_paths(alert_path: Path, fixture_dir: Path | None) -> Tuple[Path, Path]:
    resolved_alert = alert_path.resolve()
    resolved_fixture = fixture_dir.resolve() if fixture_dir is not None else None

    if resolved_alert.is_dir():
        resolved_fixture = resolved_alert
        resolved_alert = resolved_fixture / "seed_alert.json"

    if resolved_fixture is None:
        candidate = resolved_alert.parent
        if (candidate / "trace_events.ndjson").exists():
            resolved_fixture = candidate

    if resolved_fixture is None:
        raise ValueError("incident-agent 模式需要 fixture 目录，或直接把 --alert 指到 fixture case 目录。")
    if not resolved_alert.exists():
        raise FileNotFoundError(f"missing seed alert file: {resolved_alert}")
    return resolved_alert, resolved_fixture


def _run_one_incident_agent(
    alert: Dict[str, Any],
    out_dir: Path,
    *,
    fixture_dir: Path,
    llm: Any,
    llm_runtime: Dict[str, Any],
    decision_mode: str | None,
) -> Dict[str, Any]:
    event = normalize_alert(alert)
    out_dir.mkdir(parents=True, exist_ok=True)
    save_json(out_dir / "input_alert.json", alert)
    save_json(out_dir / "event.json", event)

    result = run_incident_agent_case(
        seed_alert=alert,
        fixture_dir=str(fixture_dir),
        llm=llm,
        llm_runtime=llm_runtime,
        decision_mode=decision_mode,
    )
    incident = result.get("incident") or {}
    if isinstance(incident, dict):
        decision_block = dict(incident.get("decision_mode") or {})
        decision_block["llm_runtime"] = dict(llm_runtime or {})
        incident["decision_mode"] = decision_block
    trace = result.get("investigation_trace") or []
    topology = result.get("topology") or {}
    report_markdown = str(result.get("report_markdown") or "")
    report_polished_markdown = str(result.get("report_polished_markdown") or "")
    report_appendix_markdown = str(result.get("report_appendix_markdown") or "")
    report_polish_input = result.get("report_polish_input") or {}
    report_polish_brief = str(result.get("report_polish_brief") or "")
    report_polish_error = str(result.get("report_polish_error") or "")
    report_outline = result.get("report_outline") or {}
    evidence_store = incident.get("evidence_store") or {}
    reviewer_input = incident.get("reviewer_input") or {}
    delivery_decision = incident.get("delivery_decision") or {}
    report_polished_path = out_dir / "report_polished.md"
    report_polish_error_path = out_dir / "report_polish_error.txt"

    save_json(out_dir / "incident.json", incident)
    save_json(out_dir / "investigation_trace.json", trace)
    save_json(out_dir / "topology.json", topology)
    save_json(out_dir / "report_outline.json", report_outline)
    if report_polish_input:
        save_json(out_dir / "report_polish_input.json", report_polish_input)
    if report_polish_brief.strip():
        save_text(out_dir / "report_polish_brief.md", report_polish_brief)
    if evidence_store:
        save_json(out_dir / "evidence_store.json", evidence_store)
    if reviewer_input:
        save_json(out_dir / "reviewer_input.json", reviewer_input)
    if delivery_decision:
        save_json(out_dir / "delivery_decision.json", delivery_decision)
    save_text(out_dir / "report.md", report_markdown)
    save_text(out_dir / "report_appendix.md", report_appendix_markdown)
    if report_polished_markdown.strip():
        save_text(report_polished_path, report_polished_markdown)
    elif report_polished_path.exists():
        report_polished_path.unlink()
    if report_polish_error.strip():
        save_text(report_polish_error_path, report_polish_error + "\n")
    elif report_polish_error_path.exists():
        report_polish_error_path.unlink()
    topology_html_path = draw_graph_pyvis(topology, str(out_dir / "topology.html"))

    response = {
        "ok": True,
        "out_dir": str(out_dir),
        "decision_mode": decision_mode or os.getenv("INCIDENT_AGENT_DECISION_MODE") or "heuristic",
        "llm_runtime": dict(llm_runtime or {}),
        "incident_json_path": str((out_dir / "incident.json").resolve()),
        "investigation_trace_path": str((out_dir / "investigation_trace.json").resolve()),
        "topology_json_path": str((out_dir / "topology.json").resolve()),
        "topology_html_path": topology_html_path,
        "report_outline_path": str((out_dir / "report_outline.json").resolve()),
        "report_path": str((out_dir / "report.md").resolve()),
        "report_appendix_path": str((out_dir / "report_appendix.md").resolve()),
        "result": result,
    }
    if report_polish_input:
        response["report_polish_input_path"] = str((out_dir / "report_polish_input.json").resolve())
    if report_polish_brief.strip():
        response["report_polish_brief_path"] = str((out_dir / "report_polish_brief.md").resolve())
    if evidence_store:
        response["evidence_store_path"] = str((out_dir / "evidence_store.json").resolve())
    if reviewer_input:
        response["reviewer_input_path"] = str((out_dir / "reviewer_input.json").resolve())
    if delivery_decision:
        response["delivery_decision_path"] = str((out_dir / "delivery_decision.json").resolve())
    if report_polished_markdown.strip():
        response["report_polished_path"] = str((out_dir / "report_polished.md").resolve())
    if report_polish_error.strip():
        response["report_polish_error_path"] = str((out_dir / "report_polish_error.txt").resolve())
    return response


def run(
    alert_path: Path,
    out_dir: Path,
    *,
    mode: str = "incident-agent",
    fixture_dir: Path | None = None,
    decision_mode: str | None = None,
) -> Dict[str, Any]:
    if mode != "incident-agent":
        raise ValueError("Trace-Agent 当前只保留 --mode incident-agent。")

    resolved_alert_path, resolved_fixture_dir = _resolve_incident_paths(alert_path, fixture_dir)
    raw = load_json(resolved_alert_path)
    if not isinstance(raw, dict):
        raise ValueError("incident-agent 模式当前只支持单条 seed alert。")
    out_dir.mkdir(parents=True, exist_ok=True)
    llm, llm_runtime = _load_optional_llm(decision_mode=decision_mode)
    return {
        "mode": "incident-agent",
        "fixture_dir": str(resolved_fixture_dir),
        "decision_mode": decision_mode or os.getenv("INCIDENT_AGENT_DECISION_MODE") or "heuristic",
        "llm_runtime": dict(llm_runtime or {}),
        "items": [
            _run_one_incident_agent(
                raw,
                out_dir,
                fixture_dir=resolved_fixture_dir,
                llm=llm,
                llm_runtime=llm_runtime,
                decision_mode=decision_mode,
            )
        ],
    }


def main() -> None:
    import argparse

    default_fixture = ROOT / "fixtures" / "incidents" / "single_host_c2_beacon"
    parser = argparse.ArgumentParser(description="Trace-Agent incident-agent pipeline.")
    parser.add_argument("--alert", default=str(default_fixture), help="path to a fixture case directory or seed_alert.json")
    parser.add_argument("--out", default=str(ROOT / "outputs" / "incident_tests" / "single_host_c2_beacon" / "agent"), help="output directory")
    parser.add_argument("--mode", default="incident-agent", choices=["incident-agent"], help="agent mode")
    parser.add_argument("--fixture-dir", default=None, help="incident-agent 模式的 fixture 目录，可选")
    parser.add_argument(
        "--decision-mode",
        default=os.getenv("INCIDENT_AGENT_DECISION_MODE") or "heuristic",
        choices=DECISION_MODE_CHOICES,
        help="decision mode: heuristic, llm_selector, llm_agent, or hybrid",
    )
    args = parser.parse_args()

    resolved_fixture_dir = Path(args.fixture_dir).resolve() if args.fixture_dir else None
    res = run(
        alert_path=Path(args.alert).resolve(),
        out_dir=Path(args.out).resolve(),
        mode=args.mode,
        fixture_dir=resolved_fixture_dir,
        decision_mode=args.decision_mode,
    )
    print(json.dumps(res, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
