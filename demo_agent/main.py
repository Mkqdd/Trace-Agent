from __future__ import annotations

from typing import Any, Optional

from .QueryEngine import QueryEngine
from .config import AgentConfig, load_config
from .services.api.llm import make_llm


def build_query_engine(*, cfg: Optional[AgentConfig] = None, llm: Optional[Any] = None) -> QueryEngine:
    resolved_cfg = cfg or load_config()
    resolved_llm = llm or make_llm(resolved_cfg)
    return QueryEngine(llm=resolved_llm, cfg=resolved_cfg)
