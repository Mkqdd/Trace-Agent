from __future__ import annotations

import json
from typing import Any, Dict, List

from langchain_core.prompts import ChatPromptTemplate

from ..schemas import GapPlan, GapPlanAction, GapPlanItem, model_dump, validate_model


def _fallback_actions(analysis: Dict[str, Any]) -> GapPlan:
    event = analysis.get("event") or {}
    assessment = analysis.get("assessment") or {}
    fp = event.get("trigger_fingerprint") or {}
    facts = analysis.get("facts") or {}
    dst = facts.get("dst") or {}
    fp_value = str(fp.get("value") or "")
    family = str(assessment.get("family") or "").strip()
    dst_ip = str(dst.get("ip") or "").strip()
    items: List[GapPlanItem] = []

    for gap in list(analysis.get("gaps") or []):
        gap_type = str(gap.get("type") or "")
        if gap_type == "vt_only_context":
            items.append(
                GapPlanItem(
                    gap_type=gap_type,
                    goal="family_attribution",
                    actions=[
                        GapPlanAction(tool="advanced_web_search", query=f"{fp_value} malware family attribution"),
                        GapPlanAction(tool="advanced_web_search", query=f"{fp_value} stealer trojan RAT family"),
                    ],
                )
            )
        elif gap_type == "missing_local_match":
            items.append(
                GapPlanItem(
                    gap_type=gap_type,
                    goal="find_secondary_attribution",
                    actions=[
                        GapPlanAction(tool="advanced_web_search", query=f"{fp_value} malware family attribution"),
                        GapPlanAction(tool="pivot_related_indicators", query=fp_value),
                    ],
                )
            )
        elif gap_type == "single_source_attribution":
            items.append(
                GapPlanItem(
                    gap_type=gap_type,
                    goal="secondary_confirmation",
                    actions=[
                        GapPlanAction(tool="malware_profile_lookup", query=family or fp_value),
                        GapPlanAction(tool="advanced_web_search", query=f"{family or fp_value} malware family TTP"),
                    ],
                )
            )
        elif gap_type == "no_secondary_confirmation":
            items.append(
                GapPlanItem(
                    gap_type=gap_type,
                    goal="secondary_confirmation",
                    actions=[
                        GapPlanAction(tool="malware_profile_lookup", query=family or fp_value),
                        GapPlanAction(tool="advanced_web_search", query=f"{family or fp_value} malware family profile"),
                    ],
                )
            )
        elif gap_type == "destination_context_missing":
            items.append(
                GapPlanItem(
                    gap_type=gap_type,
                    goal="destination_context",
                    actions=[
                        GapPlanAction(tool="advanced_web_search", query=f"{dst_ip or fp_value} infrastructure malware context"),
                        GapPlanAction(tool="pivot_related_indicators", query=dst_ip or fp_value),
                    ],
                )
            )
        elif gap_type == "behavior_context_missing":
            items.append(
                GapPlanItem(
                    gap_type=gap_type,
                    goal="behavior_context",
                    actions=[
                        GapPlanAction(tool="malware_profile_lookup", query=family or fp_value),
                        GapPlanAction(tool="advanced_web_search", query=f"{family or fp_value} TTP behavior"),
                    ],
                )
            )
        elif gap_type == "conflicting_attribution":
            items.append(
                GapPlanItem(
                    gap_type=gap_type,
                    goal="resolve_conflict",
                    actions=[
                        GapPlanAction(tool="advanced_web_search", query=f"{fp_value} malware family"),
                        GapPlanAction(tool="pivot_related_indicators", query=family or fp_value),
                    ],
                )
            )
    return GapPlan(items=items)


def plan_gap_actions(llm: Any, analysis: Dict[str, Any]) -> GapPlan:
    gaps = list(analysis.get("gaps") or [])
    if not gaps:
        return GapPlan(items=[])

    fallback = _fallback_actions(analysis)
    if llm is None or not hasattr(llm, "with_structured_output"):
        return fallback

    prompt = ChatPromptTemplate.from_messages(
        [
            (
                "system",
                "你是 Gap Planner。你的任务不是做全局调查规划，而是仅根据 analysis JSON 中的 gaps 生成局部补查计划。"
                "输出必须是结构化 GapPlan。"
                "只允许使用这些工具名：advanced_web_search, fetch_page_content, extract_entities_from_page, pivot_related_indicators, malware_profile_lookup。"
                "如果没有值得执行的补查动作，返回空 items。"
                "不要改写结论，不要编造工具动作。",
            ),
            ("user", "analysis:\n{analysis_json}"),
        ]
    )
    try:
        structured_llm = llm.with_structured_output(GapPlan)
        message = prompt.format_messages(analysis_json=json.dumps(analysis, ensure_ascii=False, indent=2))
        plan = structured_llm.invoke(message)
        validated = validate_model(GapPlan, model_dump(plan), default=fallback)
        if validated.items:
            return validated
        return fallback
    except Exception:
        return fallback
