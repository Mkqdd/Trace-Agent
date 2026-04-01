from typing import Any, Dict

from ..config import AgentConfig
from ..pipeline.coordinator import run_pipeline


def run_plan_and_solve(llm: Any, cfg: AgentConfig, *, event: Dict[str, Any], out_dir: str) -> Dict[str, Any]:
    """
    Compatibility wrapper around the V2 pipeline coordinator.
    """
    return run_pipeline(llm, cfg, event=event, out_dir=out_dir)
