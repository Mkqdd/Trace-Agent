import json
from pathlib import Path
from typing import Any, Dict, Union

from ..main import build_query_engine
from ..renderers.artifacts import build_topology_from_analysis
from ..renderers.graph_drawer_pyvis import draw_graph_pyvis
from ..types.event import normalize_alert
from ..utils.io import load_json, save_json, save_text


ROOT = Path(__file__).resolve().parents[2]


def _run_one(alert: Dict[str, Any], out_dir: Path, *, engine: Any) -> Dict[str, Any]:
    event = normalize_alert(alert)
    out_dir.mkdir(parents=True, exist_ok=True)
    save_json(out_dir / "input_alert.json", alert)
    save_json(out_dir / "event.json", event)

    result = engine.run_case(event=event, out_dir=out_dir)
    analysis = result.get("analysis")
    save_text(out_dir / "agent_output.txt", "plan-and-solve finished")

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


def run(alert_path: Path, out_dir: Path, *, mode: str = "plan") -> Dict[str, Any]:
    raw: Union[Dict[str, Any], list] = load_json(alert_path)
    if mode != "plan":
        raise ValueError("Trace-Agent 已移除纯 react 运行路径，请使用 --mode plan。")

    out_dir.mkdir(parents=True, exist_ok=True)
    engine = build_query_engine()

    # Single alert object -> one report
    if isinstance(raw, dict):
        return {"mode": "single", "items": [_run_one(raw, out_dir, engine=engine)]}

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
        items.append(_run_one(item, sub, engine=engine))

    return {"mode": "batch", "count": len(items), "out_dir": str(out_dir), "items": items}


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Trace-Agent plan pipeline (baseline + gap fill + report/topology).")
    parser.add_argument("--alert", default=str(ROOT / "demo_alert.json"), help="path to alert JSON")
    parser.add_argument("--out", default=str(ROOT / "outputs" / "agent_runs" / "default"), help="output directory")
    parser.add_argument("--mode", default="plan", choices=["plan"], help="agent mode")
    args = parser.parse_args()

    res = run(alert_path=Path(args.alert).resolve(), out_dir=Path(args.out).resolve(), mode=args.mode)
    print(json.dumps(res, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

