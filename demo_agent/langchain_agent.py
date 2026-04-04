import json
from pathlib import Path
from typing import Any, Dict, Optional, Union

from .analysis import build_analysis
from .agents.plan_agent import run_plan_and_solve
from .agents.react_agent import build_react_executor, run_react
from .config import load_config
from .event import normalize_alert
from .storage.io import load_json, save_text, save_json
from .renderers.artifacts import build_topology_from_analysis
from .renderers.graph_drawer_pyvis import draw_graph_pyvis
from .renderers.report_markdown import render_report_from_analysis
from .clients.llm import make_llm
from .tooling import (
    advanced_web_search,
    build_topology_json,
    extract_claim_candidates_from_page,
    extract_entities_from_page,
    family_intel,
    fetch_page_content,
    local_intel_lookup,
    malware_profile_lookup,
    pivot_related_indicators,
    save_report_md,
    technical_source_search,
    vt_enrich_ioc,
    vt_enrich_ip,
    web_search,
)


ROOT = Path(__file__).resolve().parents[1]


def _needs_react_report_fallback(report_md: str) -> bool:
    text = str(report_md or "").strip()
    if not text:
        return True
    lowered = text.lower()
    return "agent stopped due to iteration limit or time limit" in lowered


def _run_one(alert: Dict[str, Any], out_dir: Path, *, executor) -> Dict[str, Any]:
    event = normalize_alert(alert)
    out_dir.mkdir(parents=True, exist_ok=True)
    save_json(out_dir / "input_alert.json", alert)
    save_json(out_dir / "event.json", event)

    if executor == "plan":
        cfg = load_config()
        result = run_plan_and_solve(make_llm(cfg), cfg, event=event, out_dir=str(out_dir))
        analysis = result.get("analysis") or build_analysis(event=event, mode="plan")
        save_text(out_dir / "agent_output.txt", "plan-and-solve finished")
    else:
        result = run_react(executor, event=event, out_dir=str(out_dir))
        report_md = str(result.get("result", {}).get("output", "")).strip()
        analysis = build_analysis(
            event=event,
            mode="react",
            report_markdown=None if _needs_react_report_fallback(report_md) else report_md,
            report_path=None,
        )
        if _needs_react_report_fallback(report_md):
            report_md = render_report_from_analysis(analysis)
        report_path = str((out_dir / "report.md").resolve())
        save_text(Path(report_path), report_md)
        analysis["report"] = {"path": report_path, "content": report_md}
        save_text(out_dir / "agent_output.txt", report_md)

    topology = build_topology_from_analysis(analysis)
    save_json(out_dir / "analysis.json", analysis)
    save_json(out_dir / "topology.json", topology)
    topology_html_path = draw_graph_pyvis(topology, str(out_dir / "topology.html"))

    return {
        "ok": True,
        "out_dir": str(out_dir),
        "analysis_json_path": str((out_dir / "analysis.json").resolve()),
        "topology_json_path": str((out_dir / "topology.json").resolve()),
        "topology_html_path": topology_html_path,
        "result": result,
    }


def run(alert_path: Path, out_dir: Path, *, mode: str = "react") -> Dict[str, Any]:
    raw: Union[Dict[str, Any], list] = load_json(alert_path)

    cfg = load_config()
    llm = make_llm(cfg)
    tools = [
        local_intel_lookup,
        vt_enrich_ioc,
        vt_enrich_ip,
        web_search,
        family_intel,
        advanced_web_search,
        technical_source_search,
        fetch_page_content,
        extract_claim_candidates_from_page,
        extract_entities_from_page,
        pivot_related_indicators,
        malware_profile_lookup,
        build_topology_json,
        save_report_md,
    ]
    executor = build_react_executor(llm, tools, verbose=False) if mode == "react" else "plan"

    out_dir.mkdir(parents=True, exist_ok=True)

    # Single alert object -> one report
    if isinstance(raw, dict):
        return {"mode": "single", "items": [_run_one(raw, out_dir, executor=executor)]}

    # List of alerts -> one report per item, written to subfolders 000/, 001/, ...
    if not isinstance(raw, list):
        raise ValueError("alert JSON must be an object or a list of objects")
    if not raw:
        raise ValueError("alert JSON list is empty")

    items: list = []
    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ValueError(f"alert JSON list item {i} is not an object")
        sub = out_dir / f"{i:03d}"
        items.append(_run_one(item, sub, executor=executor))

    return {"mode": "batch", "count": len(items), "out_dir": str(out_dir), "items": items}


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="LangChain ReAct Threat-Agent demo (DeepShield + VT + topology + report).")
    parser.add_argument("--alert", default=str(ROOT / "demo_alert.json"), help="path to alert JSON")
    parser.add_argument("--out", default=str(ROOT / "outputs" / "agent_runs" / "default"), help="output directory")
    parser.add_argument("--mode", default="plan", choices=["react", "plan"], help="agent mode: react or plan-and-solve")
    args = parser.parse_args()

    res = run(alert_path=Path(args.alert).resolve(), out_dir=Path(args.out).resolve(), mode=args.mode)
    print(json.dumps(res, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

