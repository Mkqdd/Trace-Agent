from __future__ import annotations

from typing import Any, Dict, List, Optional, Type, TypeVar

from pydantic import BaseModel, Field, ValidationError


class GapPlanAction(BaseModel):
    model_config = {"extra": "allow"}

    tool: str
    query: Optional[str] = None
    constraint: Optional[str] = None
    url_slot: Optional[str] = None
    url: Optional[str] = None
    notes: Optional[str] = None
    kwargs: Dict[str, Any] = Field(default_factory=dict)


class GapPlanItem(BaseModel):
    gap_type: str
    goal: str
    actions: List[GapPlanAction] = Field(default_factory=list)


class GapPlan(BaseModel):
    items: List[GapPlanItem] = Field(default_factory=list)


class SupplementalEvidence(BaseModel):
    kind: str = "supplemental"
    source: str = ""
    type: str = "supplemental_search"
    query: Optional[str] = None
    url: Optional[str] = None
    title: str = ""
    claim: str = ""
    confidence: int = 50
    raw_ref: str = "react_gap_fill"


class GapUpdate(BaseModel):
    gap_id: str
    status: str
    note: str = ""


class SupplementalResult(BaseModel):
    supplemental_evidence: List[SupplementalEvidence] = Field(default_factory=list)
    gap_updates: List[GapUpdate] = Field(default_factory=list)
    candidate_family: Optional[str] = None
    supplemental_summary: str = ""


_ModelT = TypeVar("_ModelT", bound=BaseModel)


def validate_model(model_cls: Type[_ModelT], payload: Any, *, default: Optional[_ModelT] = None) -> _ModelT:
    try:
        return model_cls.model_validate(payload)
    except AttributeError:
        return model_cls.parse_obj(payload)  # type: ignore[return-value]
    except ValidationError:
        if default is not None:
            return default
        raise


def model_dump(model: BaseModel) -> Dict[str, Any]:
    try:
        return model.model_dump()
    except AttributeError:
        return model.dict()  # type: ignore[return-value]
