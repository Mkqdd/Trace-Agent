from __future__ import annotations

import json
from typing import Any, Dict, List

from langchain_core.prompts import ChatPromptTemplate

from ..schemas import GapPlan, GapPlanAction, GapPlanItem, model_dump, validate_model


def _read_page_actions(*, focus: str, goal: str, notes_prefix: str = "") -> List[GapPlanAction]:
    note = notes_prefix.strip()
    if note:
        note = f"{note}；"
    return [
        GapPlanAction(
            tool="fetch_page_content",
            url_slot="top_result_from_previous_search",
            notes=f"{note}读取上一动作返回的最高价值技术页面正文",
        ),
        GapPlanAction(
            tool="extract_claim_candidates_from_page",
            focus=focus,
            goal=goal,
            content_slot="content_from_previous_page",
            notes="从正文中提取包含家族、TTP、基础设施或二跳 IOC 的具体句子",
        ),
        GapPlanAction(
            tool="extract_entities_from_page",
            focus=focus,
            content_slot="content_from_previous_page",
            notes="从同一正文中提取 IP、域名、URL、Hash 等二跳实体",
        ),
    ]


def _abuse_lookup_actions(*, indicator_type: str, indicator_value: str) -> List[GapPlanAction]:
    normalized_type = str(indicator_type or "").upper()
    if normalized_type not in {"IP", "DOMAIN", "URL", "MD5", "SHA256"}:
        return []
    actions = [
        GapPlanAction(
            tool="threatfox_ioc_lookup",
            query=indicator_value,
            kwargs={"indicator_type": normalized_type},
            notes="先查 ThreatFox 的结构化 IOC / hash 情报，优先拿家族映射和关联样本线索",
        )
    ]
    if normalized_type in {"IP", "DOMAIN", "URL", "SHA256"}:
        actions.append(
            GapPlanAction(
                tool="urlhaus_ioc_lookup",
                query=indicator_value,
                kwargs={"indicator_type": normalized_type},
                notes="再查 URLhaus 的结构化主机 / URL / 载荷情报，补恶意投递和基础设施上下文",
            )
        )
    return actions


def _fallback_actions(analysis: Dict[str, Any]) -> GapPlan:
    event = analysis.get("event") or {}
    assessment = analysis.get("assessment") or {}
    fp = event.get("trigger_fingerprint") or {}
    fp_type = str(fp.get("type") or "").upper()
    facts = analysis.get("facts") or {}
    dst = facts.get("dst") or {}
    fp_value = str(fp.get("value") or "")
    family = str(assessment.get("family") or "").strip()
    dst_ip = str(dst.get("ip") or "").strip()
    items: List[GapPlanItem] = []
    gap_types = {str(item.get("type") or "") for item in list(analysis.get("gaps") or [])}

    for gap in list(analysis.get("gaps") or []):
        gap_type = str(gap.get("type") or "")
        if gap_type == "missing_local_match" and "vt_only_context" in gap_types:
            continue
        if gap_type == "behavior_context_missing" and ("single_source_attribution" in gap_types or "no_secondary_confirmation" in gap_types):
            continue
        if gap_type == "vt_only_context":
            items.append(
                GapPlanItem(
                    gap_type=gap_type,
                    goal="family_attribution",
                    actions=[
                        *_abuse_lookup_actions(indicator_type=fp_type, indicator_value=fp_value),
                        GapPlanAction(
                            tool="technical_source_search",
                            query=fp_value,
                            goal="family_attribution",
                            max_results=6,
                            notes="优先在 any.run、abuse.ch、Malpedia、VirusTotal 等技术来源中寻找显式家族关联",
                        ),
                        *_read_page_actions(focus=fp_value, goal="family_attribution"),
                    ],
                )
            )
        elif gap_type == "missing_local_match":
            items.append(
                GapPlanItem(
                    gap_type=gap_type,
                    goal="find_secondary_attribution",
                    actions=[
                        *_abuse_lookup_actions(indicator_type=fp_type, indicator_value=fp_value),
                        GapPlanAction(
                            tool="technical_source_search",
                            query=fp_value,
                            goal="family_attribution",
                            max_results=6,
                            notes="优先寻找可将该指标直接映射到家族的技术页面或沙箱页面",
                        ),
                        *_read_page_actions(focus=fp_value, goal="family_attribution"),
                    ],
                )
            )
        elif gap_type == "single_source_attribution":
            items.append(
                GapPlanItem(
                    gap_type=gap_type,
                    goal="secondary_confirmation",
                    actions=[
                        GapPlanAction(
                            tool="malware_profile_lookup",
                            query=family or fp_value,
                            max_results=5,
                            notes="优先补充高质量家族背景页",
                        ),
                        *_read_page_actions(focus=family or fp_value, goal="behavior_context", notes_prefix="优先阅读技术背景页"),
                    ],
                )
            )
        elif gap_type == "no_secondary_confirmation":
            items.append(
                GapPlanItem(
                    gap_type=gap_type,
                    goal="secondary_confirmation",
                    actions=[
                        GapPlanAction(
                            tool="malware_profile_lookup",
                            query=family or fp_value,
                            max_results=5,
                            notes="优先寻找第二来源家族背景页",
                        ),
                        *_read_page_actions(focus=family or fp_value, goal="secondary_confirmation", notes_prefix="验证家族背景页"),
                    ],
                )
            )
        elif gap_type == "destination_context_missing":
            items.append(
                GapPlanItem(
                    gap_type=gap_type,
                    goal="destination_context",
                    actions=[
                        *_abuse_lookup_actions(indicator_type="IP", indicator_value=dst_ip or fp_value),
                        GapPlanAction(
                            tool="technical_source_search",
                            query=dst_ip or fp_value,
                            goal="infra_context",
                            max_results=6,
                            notes="查找与目标基础设施相关的上下文和关联指标",
                        ),
                        *_read_page_actions(focus=dst_ip or fp_value, goal="destination_context"),
                    ],
                )
            )
        elif gap_type == "behavior_context_missing":
            items.append(
                GapPlanItem(
                    gap_type=gap_type,
                    goal="behavior_context",
                    actions=[
                        GapPlanAction(
                            tool="technical_source_search",
                            query=family or fp_value,
                            goal="behavior_context",
                            max_results=6,
                            notes="优先寻找包含持久化、注入、窃密、C2 等行为线索的技术页面",
                        ),
                        *_read_page_actions(focus=family or fp_value, goal="behavior_context"),
                    ],
                )
            )
        elif gap_type == "conflicting_attribution":
            items.append(
                GapPlanItem(
                    gap_type=gap_type,
                    goal="resolve_conflict",
                    actions=[
                        *_abuse_lookup_actions(indicator_type=fp_type, indicator_value=fp_value),
                        GapPlanAction(
                            tool="technical_source_search",
                            query=fp_value,
                            goal="family_attribution",
                            max_results=6,
                            notes="寻找直接把该指标映射到家族的技术来源，以解决归因冲突",
                        ),
                        *_read_page_actions(focus=fp_value, goal="resolve_conflict"),
                        GapPlanAction(
                            tool="malware_profile_lookup",
                            query=family or fp_value,
                            max_results=5,
                            notes="对当前候选家族补充高质量技术背景",
                        ),
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
                "只允许使用这些工具名：advanced_web_search, technical_source_search, fetch_page_content, extract_claim_candidates_from_page, "
                "extract_entities_from_page, pivot_related_indicators, malware_profile_lookup, threatfox_ioc_lookup, urlhaus_ioc_lookup。"
                "优先使用高价值技术来源，尤其是 any.run、abuse.ch、Malpedia、Microsoft、Trend Micro、Proofpoint、Check Point、VirusTotal。"
                "如果 gap 与 IOC / 基础设施 / 恶意 URL / 载荷有关，优先先查 ThreatFox 或 URLhaus 这类结构化 abuse.ch 数据源，再决定是否需要搜索和读页面。"
                "当目标是家族归因、行为补充或二次佐证时，优先生成“搜索技术来源 -> 读取页面正文 -> 提取 claim/TTP/二跳 IOC”的动作链。"
                "可以使用 Google dorks，例如 site:any.run、site:malpedia.caad.fkie.fraunhofer.de、site:threatfox.abuse.ch、filetype:pdf。"
                "不要重查本地库或 VT，也不要重复 baseline 已经做过的固定动作。"
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
