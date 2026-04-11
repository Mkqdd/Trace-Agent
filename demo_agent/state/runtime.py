from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class StageTrace:
    name: str
    started_at: Optional[float] = None
    duration_s: Optional[float] = None
    ok: bool = True
    notes: str = ""


@dataclass
class CaseRuntimeState:
    case_id: str = ""
    indicator_type: str = ""
    indicator_value: str = ""
    traces: List[StageTrace] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)
