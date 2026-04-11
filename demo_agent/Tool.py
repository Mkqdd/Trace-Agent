from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class ToolSpec:
    name: str
    kind: str
    read_only: bool = True
    networked: bool = False
    structured_output: bool = True
    baseline_allowed: bool = False
    react_allowed: bool = False
    supported_indicator_types: List[str] = field(default_factory=list)
    supported_gap_types: List[str] = field(default_factory=list)
    timeout_seconds: Optional[float] = None
    concurrency_safe: bool = True
    description: str = ""


@dataclass
class ToolContext:
    phase: str
    indicator_type: str = ""
    gap_types: List[str] = field(default_factory=list)


@dataclass
class ToolResult:
    ok: bool
    payload: Dict[str, Any]
    error: Optional[str] = None
