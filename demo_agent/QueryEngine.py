from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict

from .config import AgentConfig
from .query import run_query_pipeline


@dataclass
class QueryEngine:
    llm: Any
    cfg: AgentConfig

    def run_case(self, *, event: Dict[str, Any], out_dir: Path) -> Dict[str, Any]:
        return run_query_pipeline(self.llm, self.cfg, event=event, out_dir=str(out_dir))
