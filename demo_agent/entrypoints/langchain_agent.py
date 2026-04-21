import json
import os
from pathlib import Path
from typing import Any, Dict, Tuple

from ..config import load_config
from ..incidents import run_incident_agent_case
from ..renderers.graph_drawer_pyvis import draw_graph_pyvis
from ..services.api.llm import make_llm
from ..types.event import normalize_alert
from ..utils.io import load_json, save_json, save_text


ROOT = Path(__file__).resolve().parents[2]


def _load_optional_llm() -> Any:
    enabled = str(os.getenv("INCIDENT_AGENT_ENABLE_LLM") or "").strip().lower() in {"1", "true", "yes"}
    if not enabled:
        return None
    try:
        cfg = load_config()
        return make_llm(cfg)
    except Exception:
        return None


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


def _run_one_incident_agent(alert: Dict[str, Any], out_dir: Path, *, fixture_dir: Path, llm: Any) -> Dict[str, Any]:
    event = normalize_alert(alert)
    out_dir.mkdir(parents=True, exist_ok=True)
    save_json(out_dir / "input_alert.json", alert)
    save_json(out_dir / "event.json", event)

    result = run_incident_agent_case(seed_alert=alert, fixture_dir=str(fixture_dir), llm=llm)
    incident = result.get("incident") or {}
    trace = result.get("investigation_trace") or []
    topology = result.get("topology") or {}
    report_markdown = str(result.get("report_markdown") or "")
    report_polished_markdown = str(result.get("report_polished_markdown") or "")
    report_appendix_markdown = str(result.get("report_appendix_markdown") or "")
    report_outline = result.get("report_outline") or {}

    save_json(out_dir / "incident.json", incident)
    save_json(out_dir / "investigation_trace.json", trace)
    save_json(out_dir / "topology.json", topology)
    save_json(out_dir / "report_outline.json", report_outline)
    save_text(out_dir / "report.md", report_markdown)
    save_text(out_dir / "report_appendix.md", report_appendix_markdown)
    if report_polished_markdown.strip():
        save_text(out_dir / "report_polished.md", report_polished_markdown)
    topology_html_path = draw_graph_pyvis(topology, str(out_dir / "topology.html"))

    response = {
        "ok": True,
        "out_dir": str(out_dir),
        "incident_json_path": str((out_dir / "incident.json").resolve()),
        "investigation_trace_path": str((out_dir / "investigation_trace.json").resolve()),
        "topology_json_path": str((out_dir / "topology.json").resolve()),
        "topology_html_path": topology_html_path,
        "report_outline_path": str((out_dir / "report_outline.json").resolve()),
        "report_path": str((out_dir / "report.md").resolve()),
        "report_appendix_path": str((out_dir / "report_appendix.md").resolve()),
        "result": result,
    }
    if report_polished_markdown.strip():
        response["report_polished_path"] = str((out_dir / "report_polished.md").resolve())
    return response


def run(alert_path: Path, out_dir: Path, *, mode: str = "incident-agent", fixture_dir: Path | None = None) -> Dict[str, Any]:
    if mode != "incident-agent":
        raise ValueError("Trace-Agent 当前只保留 --mode incident-agent。")

    resolved_alert_path, resolved_fixture_dir = _resolve_incident_paths(alert_path, fixture_dir)
    raw = load_json(resolved_alert_path)
    if not isinstance(raw, dict):
        raise ValueError("incident-agent 模式当前只支持单条 seed alert。")
    out_dir.mkdir(parents=True, exist_ok=True)
    llm = _load_optional_llm()
    return {
        "mode": "incident-agent",
        "fixture_dir": str(resolved_fixture_dir),
        "items": [_run_one_incident_agent(raw, out_dir, fixture_dir=resolved_fixture_dir, llm=llm)],
    }


def main() -> None:
    import argparse

    default_fixture = ROOT / "fixtures" / "incidents" / "single_host_c2_beacon"
    parser = argparse.ArgumentParser(description="Trace-Agent incident-agent pipeline.")
    parser.add_argument("--alert", default=str(default_fixture), help="path to a fixture case directory or seed_alert.json")
    parser.add_argument("--out", default=str(ROOT / "outputs" / "incident_tests" / "single_host_c2_beacon" / "agent"), help="output directory")
    parser.add_argument("--mode", default="incident-agent", choices=["incident-agent"], help="agent mode")
    parser.add_argument("--fixture-dir", default=None, help="incident-agent 模式的 fixture 目录，可选")
    args = parser.parse_args()

    resolved_fixture_dir = Path(args.fixture_dir).resolve() if args.fixture_dir else None
    res = run(
        alert_path=Path(args.alert).resolve(),
        out_dir=Path(args.out).resolve(),
        mode=args.mode,
        fixture_dir=resolved_fixture_dir,
    )
    print(json.dumps(res, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
