import json
from pathlib import Path
from typing import Any, Dict, Optional, Union

from .agents.plan_agent import run_plan_and_solve
from .agents.react_agent import build_react_executor, run_react
from .config import load_config
from .event import normalize_alert
from .io import load_json, save_text, save_json
from .llm import make_llm
from .tools import build_topology_json, family_intel, save_report_md, vt_enrich_ip, web_search
from .vt_client import VirusTotalClient


ROOT = Path(__file__).resolve().parents[1]
def _run_one(alert: Dict[str, Any], out_dir: Path, *, executor) -> Dict[str, Any]:
    event = normalize_alert(alert)
    out_dir.mkdir(parents=True, exist_ok=True)
    save_json(out_dir / "input_alert.json", alert)
    save_json(out_dir / "event.json", event)

    if executor == "plan":
        result = run_plan_and_solve(make_llm(load_config()), event=event, out_dir=str(out_dir))
        save_text(out_dir / "agent_output.txt", "plan-and-solve finished")
        return {"ok": True, "out_dir": str(out_dir), "result": result}
    else:
        result = run_react(executor, event=event, out_dir=str(out_dir))
        save_text(out_dir / "agent_output.txt", str(result.get("result", {}).get("output", "")))
        return {"ok": True, "out_dir": str(out_dir), "result": result}


def run(alert_path: Path, out_dir: Path, *, mode: str = "react") -> Dict[str, Any]:
    raw: Union[Dict[str, Any], list] = load_json(alert_path)

    cfg = load_config()
    llm = make_llm(cfg)
    tools = [vt_enrich_ip, web_search, family_intel, build_topology_json, save_report_md]
    executor = build_react_executor(llm, tools, verbose=True) if mode == "react" else "plan"

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
    parser.add_argument("--out", default=str(ROOT / "demo_agent" / "out_langchain"), help="output directory")
    parser.add_argument("--mode", default="react", choices=["react", "plan"], help="agent mode: react or plan-and-solve")
    args = parser.parse_args()

    res = run(alert_path=Path(args.alert).resolve(), out_dir=Path(args.out).resolve(), mode=args.mode)
    print(json.dumps(res, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

