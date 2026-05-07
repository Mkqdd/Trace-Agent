from __future__ import annotations

import json
from typing import Any, Dict, List, Tuple

from ..services.api.llm_observability import invoke_llm_with_trace
from .report_agent_tools import (
    REPORT_SECTION_TYPES,
    collect_material_source_ids,
    execute_report_agent_tool,
    source_index_for_materials,
    validate_report_writer_materials,
)


def _text(value: Any) -> str:
    return str(value or "").strip()


def _dict(value: Any) -> Dict[str, Any]:
    return dict(value or {}) if isinstance(value, dict) else {}


def _list(value: Any) -> List[Any]:
    return list(value or []) if isinstance(value, list) else []


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, default=str)


def _reader_friendly_text(value: Any) -> str:
    text = _text(value)
    if not text:
        return ""
    replacements = {
        "同 dst_ip": "相同目标 IP",
        "同 JA4": "相同 JA4 通信指纹",
        "同 JA3": "相同 JA3 通信指纹",
        "dst_ip": "目标 IP",
        "pivot": "关键关联指标",
        "seed alert": "种子告警",
    }
    for source, target in replacements.items():
        text = text.replace(source, target)
    text = text.replace("同域名 / 相同目标 IP / 相同 JA4 通信指纹", "相同域名、目标 IP 和 JA4 通信指纹")
    text = text.replace("同域名/相同目标 IP/相同 JA4 通信指纹", "相同域名、目标 IP 和 JA4 通信指纹")
    text = text.replace("同域名 / 相同目标 IP / 相同 JA3 通信指纹", "相同域名、目标 IP 和 JA3 通信指纹")
    text = text.replace("同域名/相同目标 IP/相同 JA3 通信指纹", "相同域名、目标 IP 和 JA3 通信指纹")
    return text


SECTION_TYPE_TITLES = {
    "investigation_entry": "调查起点与已知线索",
    "scope_hypothesis": "调查范围与研判假设",
    "entity_roles": "关键对象与角色边界",
    "evidence_judgment": "关键事实与证据判断",
    "conclusion_actions": "结论与后续动作",
    "timeline_process": "事件过程与行为模式",
    "relationship_scope": "关联范围与候选边界",
    "impact_assessment": "影响评估",
    "counterevidence_limits": "反证、缺口与结论边界",
    "external_context_intel": "外部背景与情报边界",
    "topology_path_analysis": "拓扑与路径关联分析",
}

SECTION_TYPE_QUESTIONS = {
    "investigation_entry": "为什么这起告警值得调查？",
    "scope_hypothesis": "这轮调查准备证明什么、排除什么？",
    "entity_roles": "关键对象各自是什么角色，为什么调查到这些对象先停？",
    "evidence_judgment": "当前判断主要站在哪些证据上？",
    "conclusion_actions": "最终判断是什么，接下来怎么做？",
    "timeline_process": "事件如何推进，是否形成可解释的行为模式？",
    "relationship_scope": "事件如何扩线，哪些关联已经确认，哪些仍是候选？",
    "impact_assessment": "当前确认影响到哪里，风险体现在哪里？",
    "counterevidence_limits": "当前结论被什么限制，哪些更强结论暂时不能写？",
    "external_context_intel": "公开情报、内部情报或家族/基础设施背景如何帮助理解本案？",
    "topology_path_analysis": "路径、拓扑、网络关系或基础设施结构如何支撑判断？",
}


def _parse_json_object(text: str) -> Dict[str, Any]:
    raw = _text(text)
    if raw.startswith("```"):
        raw = raw.strip("`")
        if raw.lower().startswith("json"):
            raw = raw[4:].strip()
    try:
        value = json.loads(raw)
        if isinstance(value, dict):
            return value
    except json.JSONDecodeError:
        pass
    start = raw.find("{")
    end = raw.rfind("}")
    if start >= 0 and end > start:
        value = json.loads(raw[start : end + 1])
        if isinstance(value, dict):
            return value
    raise ValueError("LLM did not return a JSON object")


def _tool_catalog() -> List[Dict[str, Any]]:
    return [
        {
            "tool_name": "get_case_overview",
            "params_schema": {},
            "use_when": "需要确认报告主判断、严重度、把握度、分析窗口、已确认范围、候选范围或 source 规模时优先使用。",
            "returns": [
                "case_header",
                "confirmed_scope",
                "candidate_scope",
                "external_infrastructure",
                "source_counts",
            ],
            "do_not_use_for": "不要用它读取完整缺口、完整时间线或细粒度事件事实；这些应分别使用 get_gaps_and_boundaries、get_timeline 或 get_source_details。",
            "description": "读取报告总览，是生成 case_thesis、首页摘要和 report_plan 规划依据的首选来源。",
        },
        {
            "tool_name": "list_source_items",
            "params_schema": {
                "item_type": "event|claim|object|gap|counterevidence|recommendation|observation",
                "status": "confirmed|candidate|background|any",
                "limit": 20,
            },
            "use_when": "需要按类型快速发现可引用 source_id、摘要、状态和对象时使用，尤其适合补齐某类材料索引。",
            "returns": ["item_type", "status", "items[source_id,id,status,time,object,summary,exact_fact_text,relation]"],
            "parameter_notes": [
                "item_type=event 用于找时间线或证据 source。",
                "item_type=claim 用于找归纳判断或整体观察，不能替代关键事件证据。",
                "item_type=object 用于找对象 source，但对象角色优先用 get_scope_roles。",
                "item_type=recommendation 用于找 action_rationale。",
                "status 对 event 最稳定；对 object、recommendation、observation 可能只是 role/relation 的近似过滤，不要过度依赖。",
            ],
            "do_not_use_for": "不要把它当作最终详情工具；若摘要不足以支撑材料，应再用 get_source_details 读取完整字段。",
            "description": "按类型列出 source bundle 中的材料索引，主要用于发现 source_id 和判断是否需要进一步取详情。",
        },
        {
            "tool_name": "get_source_details",
            "params_schema": {"ids": ["event:evt-1", "claim:CL-01"]},
            "use_when": "已经知道具体 source_id，且预加载结果或 list_source_items 的摘要不足以支撑 exact_fact_text 或边界说明时使用。",
            "returns": ["details", "missing_source_ids"],
            "parameter_notes": [
                "ids 必须来自工具结果中已经出现过的 source_id。",
                "一次只取真正需要的少量 source_id，避免把完整 bundle 重新塞回上下文。",
            ],
            "do_not_use_for": "不要在预加载结果已经包含足够 exact_fact_text 时重复调用；不要凭空构造 source_id。",
            "description": "读取已知 source_id 对应的完整事实字段、角色字段和引用字段，用于补足精确材料。",
        },
        {
            "tool_name": "get_scope_roles",
            "params_schema": {"mode": "key|full"},
            "use_when": "需要区分调查锚点、已确认受影响资产、待确认对象、核心外部基础设施和背景对象时使用。",
            "returns": ["scope", "objects[source_id,object,object_type,investigation_role,report_scope_role,may_be_written_as_affected]", "source_conflicts"],
            "parameter_notes": [
                "mode=key 适合正文规划和 scope_role_matrix 的默认取材。",
                "mode=full 适合 key 模式不足、对象角色冲突或需要附录级完整对象时使用。",
                "may_be_written_as_affected=true 的对象才能写入已确认受影响范围。",
            ],
            "do_not_use_for": "不要用普通 list_source_items(object) 替代对象角色判断；对象是否可写成受影响范围必须以本工具返回的角色为准。",
            "description": "读取对象角色矩阵，是生成 scope_role_matrix、范围章节和候选/确认边界的首选来源。",
        },
        {
            "tool_name": "get_timeline",
            "params_schema": {"mode": "core|with_candidates|full"},
            "use_when": "需要组织 narrative_spine、判断是否需要 timeline_process 章节、或确认事件是否存在起点到升级的时序推进时使用。",
            "returns": ["mode", "events[source_id,time,status,classification,stages,asset,exact_fact_text]"],
            "parameter_notes": [
                "mode=core 只返回 confirmed/background，适合主证据链。",
                "mode=with_candidates 返回 confirmed/background/candidate，适合判断候选扩线边界。",
                "mode=full 额外返回 observation_ids，适合需要追溯附录或细节引用时使用。",
            ],
            "do_not_use_for": "candidate 事件不能直接写成已确认传播路径；只有经过 grounding 或独立支撑后，才可进入主证据链。",
            "description": "读取事件时间线，用于把材料整理成起点、持续、升级、范围和边界的叙事主线。",
        },
        {
            "tool_name": "get_gaps_and_boundaries",
            "params_schema": {"include_closed": "boolean"},
            "use_when": "需要生成 counterarguments_and_boundaries、reportable_limits、关键缺口、反证说明或后续复核重点时使用。",
            "returns": ["gaps[source_id,question,status,status_reason,delivery_blocking,actionable_now,exact_fact_text]", "counterevidence", "source_conflicts"],
            "parameter_notes": [
                "include_closed=false 适合正文只关注仍限制结论的问题。",
                "include_closed=true 适合需要解释已关闭缺口、反证检查过程或附录完整边界时使用。",
                "delivery_blocking/actionable_now 用于判断缺口是继续取材对象，还是报告中的边界说明。",
            ],
            "do_not_use_for": "不要把 gap 问句直接改写成处置动作；action_rationale 应优先来自 recommendation/action source。",
            "description": "读取证据缺口、反证和交付边界，是生成边界章节与后续复核重点的首选来源。",
        },
    ]


REPORT_AGENT_SYSTEM_PROMPT = """你是 Trace-Agent 的 report material agent。
Trace-Agent 是面向安全告警调查的事件研判代理。你接手的是调查阶段已经生成的 report_source_bundle；你的职责不是继续调查，也不是直接写 Markdown 报告，而是用只读取材工具把 source bundle 组织成 report_writer_materials，供 writer 写出面向运维和安全运营协同对象的中文报告。

一、角色与硬边界
- 只能基于工具返回材料整理，不得新增事实、实体、时间、动作、IOC、影响范围或结论。
- 你可以生成 why_it_matters、explanation、why_this_judgment_holds 等分析性表述，但必须围绕 exact_fact_text 和 source_ids 解释，不得脱离 source 推断。
- source_ids 必须逐字复制自工具返回结果；不得拼接、改写、推断或生成新 id。唯一固定汇总结论 id 是工具结果中可见的 verdict:delivery。
- 每条 narrative/evidence/scope/counter/action 材料都必须带 source_ids。exact_fact_text 可以省略，系统会按 source_ids 从 source bundle 回填。
- 如果你自己输出 exact_fact_text，只能抽取或拼接工具返回的精确事实，不要改写实体、时间、动作或结论。
- 严重度和把握度只能输出 高 / 中 / 低 / 未评估；如果源材料写 高危 / 中危 / 低危，只能标准化为 高 / 中 / 低。
- candidate、候选事件、待确认对象只能用于待确认范围或边界说明，不能写成已确认传播、已确认影响或主证据链结论。
- 材料不足时写入 reportable_limits，不要编造。

二、取材策略
- 预加载结果通常已经包含 overview、scope、gaps、时间线、claim 索引和 recommendation 索引；如果足以组织材料，应直接 submit。
- 只有在缺少必要 source_id、缺少支撑关键判断的 exact_fact_text，或补取材会改变 case_thesis、confirmed/candidate scope、report_plan 章节边界时，才调用工具。
- 如果继续取材不会新增关键 source 类型、不会改变 case_thesis、不会改变 confirmed/candidate scope、不会改变 report_plan 章节边界，只会改善措辞或补充非关键细节，必须 submit。
- 如果某类 source 在预加载材料和一次针对性补取材后仍不存在，或只存在明显无关材料，不要为了满足覆盖目标硬凑；应 submit，并在 reportable_limits 说明该类源材料缺失或不可用于正文。
- 如果上一轮反馈是 schema、source_id、exact_fact_text 或核心覆盖问题，优先修复 materials；只有修复确实需要新 source 时才调用工具。
- force_submit=true 时必须 submit，不得再调用工具。
- tool action 只允许选择 tool_catalog 中的工具名，params 必须来自已见材料；无法构造安全参数时不要调用工具。

三、提交材料契约
- 输出材料的目标是让 writer 写“事实是什么 -> 为什么改变判断 -> 边界是什么”，不是堆事实清单。
- schema_version 必须是 report-writer-materials-v1。
- source_inventory 可以省略或保持很小；系统会按最终 materials 实际引用的 source_ids 重建。不要罗列未使用 source。
- case_thesis 必须说明 conclusion、severity、confidence、confirmed_scope、candidate_scope、why_this_judgment_holds、why_not_stronger_or_broader、source_ids。
- case_thesis 优先使用 get_case_overview.case_header.final_verdict_summary 和 verdict:delivery 作为结论来源；如果该字段缺失，使用 case_header 中已有 delivery_status/status_label，并在 reportable_limits 中说明结论来源不完整。
- narrative_spine 用 4 到 7 条组织起点、持续、升级、范围、边界；每条直接包含 step_label、source_ids、why_it_matters。
- evidence_argument_map 用 3 到 6 条覆盖关键支撑证据、范围证据和反证/缺口边界；每条直接包含 claim、source_ids、why_it_matters、limitation。claim:* 只能补充整体观察，不能替代关键 event:* 事实。
- scope_role_matrix 用 3 到 6 条区分调查锚点、已确认受影响资产、待确认对象、核心外部基础设施，并明确 may_be_written_as_affected。
- counterarguments_and_boundaries 用 1 到 4 条解释反证、缺口和结论边界。
- action_rationale 用 0 到 3 条，优先吸收 recommendation/action source；不要把 gap 问句直接改写成处置动作。
- 所有列表保持扁平，不要输出嵌套大段摘要。无值字段省略，不要输出 null 或空字符串占位。

四、report_plan 策略
- report_plan 由你负责选择章节；代码只做 schema、source_id 和核心覆盖校验，不会替你自动补章节。
- section_type 只能使用：investigation_entry、scope_hypothesis、entity_roles、evidence_judgment、conclusion_actions、timeline_process、relationship_scope、impact_assessment、counterevidence_limits、external_context_intel、topology_path_analysis。
- report_plan 的目标是覆盖问题而不是堆标题：confirmed_incident 通常强调证据闭环和处置；needs_review 通常强调证据、候选范围、缺口；monitor_only 不要写得像攻击事件。
- 正文通常 5 到 9 节；简单 case 可少于 5 节，但必须覆盖调查起点、范围或对象、证据判断、结论动作。
- 选择章节前先判断复杂度。如果存在多资产、候选扩线、横向移动线索、多个外部基础设施，或时序推进会改变判断，不要提交过薄的极简 plan。
- 条件章节只有材料支撑时才选：timeline_process 需要时间顺序改变判断；relationship_scope 需要多对象、扩线边界或核心外部基础设施关系；impact_assessment 需要独立影响/风险；external_context_intel 只有外部/内部情报影响边界时才独立成章。
- 如果时间线呈现“种子命中 -> 持续通信/执行线索 -> 横向动作/第二资产/候选扩线”的推进，timeline_process 通常应独立成章；除非 planning_rationale 说明时序不会改变判断，才允许并入 evidence_judgment。
- 如果材料同时包含已确认受影响资产、待确认资产、核心外部基础设施或候选扩线对象，relationship_scope 通常应独立成章；除非对象关系非常简单，才允许并入 scope_hypothesis/entity_roles。
- 相邻职责简单时可用 secondary_section_types 合并，例如 scope_hypothesis 合并 entity_roles，或 conclusion_actions 合并 impact_assessment；合并时必须在 must_include、must_not_repeat、boundary_notes 中写清边界。
- planning_rationale 不能只写“覆盖起点、范围、证据、结论”；必须说明为什么选择这些章节、为什么省略其他有条件章节。
- 章节顺序通常为：调查起点 -> 范围/对象 -> 事件过程 -> 证据判断 -> 关联范围/影响 -> 反证与边界 -> 结论与行动；只有 planning_rationale 能说明理由时才调整顺序。
- 每个 section 必须有 source_ids，优先引用细粒度 event/object/gap/verdict/action/claim source，不要只引用总览。
- 每个 section 的 must_not_repeat 要明确指出不要重复哪个相邻章节内容，帮助 writer 避免换标题复述同一条事件链。

五、覆盖目标与质量门
- 覆盖目标只在对应 source 类型存在时适用：优先引用 1 个 verdict、3 个 event、1 个 claim、3 个 object、1 个 gap；如果 recommendations 存在，优先引用 1 个 action。
- evidence_judgment 优先引用 4 到 8 个关键 event/claim/verdict；timeline_process 优先引用决定性 event；relationship_scope 优先引用 object/event/gap；counterevidence_limits 优先引用 gap/counterevidence/verdict；conclusion_actions 优先引用 action/gap/verdict。
- 避免过度定性：不要把“可疑执行线索”改写成“已感染/恶意软件已存在/攻击者已控制”，除非 exact_fact_text 明确提供这些结论。
- 为减少冗长输出，优先输出 source_ids、claim/summary、why_it_matters、limitation；不要大段复制工具结果。

六、输出格式
输出只能是一个 JSON object，不要 Markdown，不要解释段落，不要 null，不要用空字符串占位。

继续取材：
{
  "action": "tool",
  "tool_calls": [
    {"tool_name": "get_timeline", "params": {"mode": "core"}},
    {"tool_name": "get_source_details", "params": {"ids": ["event:evt-1"]}}
  ],
  "reason": "..."
}

提交最终材料：
{
  "action": "submit",
  "materials": {
    "schema_version": "report-writer-materials-v1",
    "source_inventory": [],
    "report_plan": {
      "schema_version": "report-plan-v1",
      "title": "...",
      "planning_rationale": "...",
      "sections": [
        {
          "section_type": "investigation_entry",
          "secondary_section_types": [],
          "title": "调查起点与已知线索",
          "question_to_answer": "为什么这起告警值得调查？",
          "mode": "full",
          "must_include": ["..."],
          "must_not_repeat": ["..."],
          "source_ids": ["verdict:delivery"],
          "boundary_notes": ["..."]
        }
      ],
      "appendix_note": "技术细节、IOC/IOA、关键对象清单、观测引用、证据细目和待补缺口详见技术附录。"
    },
    "case_thesis": {...},
    "narrative_spine": [...],
    "evidence_argument_map": [...],
    "scope_role_matrix": [...],
    "counterarguments_and_boundaries": [...],
    "action_rationale": [...],
    "section_briefs": [...],
    "reportable_limits": [...]
  }
}
"""


def _build_round_user_prompt(
    *,
    round_index: int,
    max_rounds: int,
    tool_results: List[Dict[str, Any]],
    draft_materials: Dict[str, Any],
    feedback: List[str],
    force_submit: bool = False,
) -> str:
    return (
        f"当前是 report material loop 第 {round_index}/{max_rounds} 轮。\n"
        f"force_submit={str(force_submit).lower()}。如果 force_submit=true，你必须提交 materials，不要再调用工具。\n\n"
        "可用工具：\n"
        f"{_json(_tool_catalog())}\n\n"
        "已收集工具结果：\n"
        f"{_json(tool_results)}\n\n"
        "取材建议：预加载结果已经包含 overview、scope、gaps、时间线、claim 索引和 recommendation 索引。"
        "如果这些结果已经足以形成材料，应直接 submit；只有缺少 exact_fact_text、source id，或继续取材会改变结论/范围/章节边界时才调用工具。"
        "如果继续取材只会改善润色或增加非关键细节，应 submit。\n\n"
        "当前 draft materials：\n"
        f"{_json(draft_materials)}\n\n"
        "上一轮反馈或校验问题：\n"
        f"{_json(feedback)}\n\n"
        "请输出一个 JSON object。"
    )


def _invoke_report_agent_json(llm: Any, messages: Any, *, role: str) -> Dict[str, Any]:
    response = invoke_llm_with_trace(llm, messages, role=role)
    return _parse_json_object(str(getattr(response, "content", "") or ""))


def _normalize_tool_calls(action: Dict[str, Any]) -> List[Dict[str, Any]]:
    calls = _list(action.get("tool_calls"))
    if not calls and _text(action.get("tool_name")):
        calls = [{"tool_name": action.get("tool_name"), "params": _dict(action.get("params"))}]
    normalized: List[Dict[str, Any]] = []
    for call in calls[:3]:
        if not isinstance(call, dict):
            continue
        normalized.append({"tool_name": _text(call.get("tool_name")), "params": _dict(call.get("params"))})
    return normalized


def _preload_results(bundle: Dict[str, Any]) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for tool_name, params in [
        ("get_case_overview", {}),
        ("get_scope_roles", {"mode": "key"}),
        ("get_gaps_and_boundaries", {"include_closed": False}),
        ("get_timeline", {"mode": "with_candidates"}),
        ("list_source_items", {"item_type": "claim", "status": "any", "limit": 8}),
        ("list_source_items", {"item_type": "recommendation", "status": "any", "limit": 8}),
    ]:
        results.append(
            {
                "round": "preload",
                "tool_name": tool_name,
                "params": params,
                "result": execute_report_agent_tool(bundle, tool_name, params),
            }
        )
    return results


def _source_inventory_from_bundle(bundle: Dict[str, Any], *, limit: int = 120) -> List[Dict[str, Any]]:
    index = source_index_for_materials(bundle)
    rows: List[Dict[str, Any]] = []
    for source_id in sorted(index.keys()):
        item = _dict(index.get(source_id))
        namespace = source_id.split(":", 1)[0] if ":" in source_id else ""
        summary = (
            _text(item.get("exact_fact_text"))
            or _text(item.get("summary"))
            or _text(item.get("text"))
            or _text(item.get("question"))
            or _text(item.get("value"))
        )
        rows.append(
            {
                "source_id": source_id,
                "source_type": _text(item.get("source_type") or namespace),
                "status": _text(item.get("status") or item.get("relation") or item.get("report_scope_role")),
                "summary": summary[:500],
            }
        )
        if len(rows) >= limit:
            break
    return rows


def _source_inventory_from_source_ids(bundle: Dict[str, Any], source_ids: List[str], *, limit: int = 120) -> List[Dict[str, Any]]:
    index = source_index_for_materials(bundle)
    rows: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for raw_source_id in source_ids:
        source_id = _text(raw_source_id)
        if not source_id or source_id in seen:
            continue
        seen.add(source_id)
        item = _dict(index.get(source_id))
        if not item:
            continue
        namespace = source_id.split(":", 1)[0] if ":" in source_id else ""
        summary = (
            _text(item.get("exact_fact_text"))
            or _text(item.get("summary"))
            or _text(item.get("text"))
            or _text(item.get("question"))
            or _text(item.get("value"))
        )
        rows.append(
            {
                "source_id": source_id,
                "source_type": _text(item.get("source_type") or namespace),
                "status": _text(item.get("status") or item.get("relation") or item.get("report_scope_role")),
                "summary": summary[:500],
            }
        )
        if len(rows) >= limit:
            break
    return rows


def _source_inventory_from_materials(bundle: Dict[str, Any], materials: Dict[str, Any], *, limit: int = 120) -> List[Dict[str, Any]]:
    material_refs = {key: value for key, value in materials.items() if key != "source_inventory"}
    return _source_inventory_from_source_ids(bundle, collect_material_source_ids(material_refs), limit=limit)


def _available_source_ids(index: Dict[str, Dict[str, Any]], namespace: str, *, limit: int = 6) -> List[str]:
    prefix = f"{namespace}:"
    return [source_id for source_id in index.keys() if source_id.startswith(prefix)][:limit]


def _material_source_ids_by_namespace(materials: Dict[str, Any], namespace: str, *, limit: int = 6) -> List[str]:
    prefix = f"{namespace}:"
    ids: List[str] = []

    def walk(value: Any) -> None:
        if len(ids) >= limit:
            return
        if isinstance(value, dict):
            for key, item in value.items():
                if key == "source_id":
                    text = _text(item)
                    if text.startswith(prefix) and text not in ids:
                        ids.append(text)
                elif key.endswith("_ids") or key == "source_ids":
                    for raw in _list(item):
                        text = _text(raw)
                        if text.startswith(prefix) and text not in ids:
                            ids.append(text)
                            if len(ids) >= limit:
                                return
                else:
                    walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
                if len(ids) >= limit:
                    return

    walk(materials)
    return ids[:limit]


def _first_existing_source_ids(index: Dict[str, Dict[str, Any]], *groups: List[str], limit: int = 6) -> List[str]:
    out: List[str] = []
    for group in groups:
        for source_id in group:
            if source_id in index and source_id not in out:
                out.append(source_id)
                if len(out) >= limit:
                    return out
    return out


def _plan_section(
    section_type: str,
    source_ids: List[str],
    *,
    secondary_section_types: List[str] | None = None,
    mode: str = "full",
    must_include: List[str] | None = None,
    must_not_repeat: List[str] | None = None,
    boundary_notes: List[str] | None = None,
) -> Dict[str, Any]:
    return {
        "section_type": section_type,
        "secondary_section_types": [item for item in (secondary_section_types or []) if item],
        "title": SECTION_TYPE_TITLES.get(section_type, section_type),
        "question_to_answer": SECTION_TYPE_QUESTIONS.get(section_type, "本节要回答什么问题？"),
        "mode": mode,
        "must_include": must_include or [],
        "must_not_repeat": must_not_repeat or [],
        "source_ids": source_ids,
        "boundary_notes": boundary_notes or [],
    }


def _fallback_report_plan(
    materials: Dict[str, Any],
    bundle: Dict[str, Any],
    *,
    title: str = "",
) -> Dict[str, Any]:
    index = source_index_for_materials(bundle)
    verdict_ids = _first_existing_source_ids(index, ["verdict:delivery"], limit=1)
    event_ids = _first_existing_source_ids(
        index,
        _material_source_ids_by_namespace(materials, "event", limit=6),
        _available_source_ids(index, "event", limit=6),
        limit=6,
    )
    claim_ids = _first_existing_source_ids(
        index,
        _material_source_ids_by_namespace(materials, "claim", limit=4),
        _available_source_ids(index, "claim", limit=4),
        limit=4,
    )
    object_ids = _first_existing_source_ids(
        index,
        _material_source_ids_by_namespace(materials, "object", limit=6),
        _available_source_ids(index, "object", limit=6),
        limit=6,
    )
    gap_ids = _first_existing_source_ids(
        index,
        _material_source_ids_by_namespace(materials, "gap", limit=4),
        _available_source_ids(index, "gap", limit=4),
        limit=4,
    )
    action_ids = _first_existing_source_ids(
        index,
        _material_source_ids_by_namespace(materials, "action", limit=4),
        _available_source_ids(index, "action", limit=4),
        limit=4,
    )
    sections: List[Dict[str, Any]] = [
        _plan_section(
            "investigation_entry",
            _first_existing_source_ids(index, verdict_ids, event_ids, claim_ids, limit=4),
            must_include=["调查起点", "初始命中线索", "为什么值得继续调查"],
            must_not_repeat=["不要展开完整证据链或对象清单"],
        ),
        _plan_section(
            "entity_roles",
            _first_existing_source_ids(index, object_ids, verdict_ids, limit=6),
            must_include=["调查锚点", "已确认受影响对象", "待确认对象或核心外部基础设施"],
            must_not_repeat=["不要评价证据强度或重复时间线"],
        ),
    ]
    sections.append(
        _plan_section(
            "evidence_judgment",
            _first_existing_source_ids(index, event_ids, claim_ids, verdict_ids, limit=6),
            must_include=["关键事实", "为什么改变判断", "证据边界"],
            must_not_repeat=["不要写成完整流水账；结论边界留给缺口章节"],
        )
    )
    if gap_ids:
        sections.append(
            _plan_section(
                "counterevidence_limits",
                _first_existing_source_ids(index, gap_ids, verdict_ids, event_ids, limit=6),
                must_include=["当前最关键缺口", "缺口限制的更强结论", "当前判断上限"],
                must_not_repeat=["不要重新复述完整证据链"],
                boundary_notes=["候选或未闭合对象不能写成已确认影响范围。"],
            )
        )
    sections.append(
        _plan_section(
            "conclusion_actions",
            _first_existing_source_ids(index, verdict_ids, action_ids, gap_ids, limit=6),
            secondary_section_types=["impact_assessment"] if not action_ids else [],
            must_include=["当前结论", "为什么不是相邻状态", "立即/短期/持续动作"],
            must_not_repeat=["不要重新展开所有证据细节"],
        )
    )
    return {
        "schema_version": "report-plan-v1",
        "title": title or "安全事件调查报告",
        "planning_rationale": "工程兜底计划：仅在 report material agent 未能提交可用 report_plan 时使用，保证失败路径仍可生成保守报告；正常路径不使用该计划替 agent 选择章节。",
        "sections": [section for section in sections if _list(section.get("source_ids"))],
        "appendix_note": "技术细节、IOC/IOA、关键对象清单、观测引用、证据细目和待补缺口详见技术附录。",
    }


def _normalize_report_plan(materials: Dict[str, Any], bundle: Dict[str, Any], title: str = "") -> Dict[str, Any]:
    index = source_index_for_materials(bundle)
    raw_plan = _dict(materials.get("report_plan"))
    if not raw_plan:
        return {
            "schema_version": "report-plan-v1",
            "title": title or "安全事件调查报告",
            "planning_rationale": "",
            "sections": [],
            "appendix_note": "技术细节、IOC/IOA、关键对象清单、观测引用、证据细目和待补缺口详见技术附录。",
        }
    normalized_sections: List[Dict[str, Any]] = []
    seen_primary: set[str] = set()
    for raw_section in _list(raw_plan.get("sections")):
        if not isinstance(raw_section, dict):
            continue
        section_type = _text(raw_section.get("section_type"))
        if section_type not in REPORT_SECTION_TYPES or section_type in seen_primary:
            continue
        seen_primary.add(section_type)
        secondary = [
            _text(item)
            for item in _list(raw_section.get("secondary_section_types"))
            if _text(item) in REPORT_SECTION_TYPES and _text(item) != section_type
        ]
        inline_source_ids = [
            _text(item)
            for item in _list(raw_section.get("must_include")) + _list(raw_section.get("boundary_notes"))
            if _text(item) in index
        ]
        source_ids = _first_existing_source_ids(index, _source_ids_from_item(raw_section), inline_source_ids, limit=8)
        normalized_sections.append(
            {
                "section_type": section_type,
                "secondary_section_types": secondary,
                "title": _text(raw_section.get("title")) or SECTION_TYPE_TITLES.get(section_type, section_type),
                "question_to_answer": _text(raw_section.get("question_to_answer")) or SECTION_TYPE_QUESTIONS.get(section_type, ""),
                "mode": _text(raw_section.get("mode")) if _text(raw_section.get("mode")) in {"full", "compact", "boundary_only"} else "full",
                "must_include": [_text(item) for item in _list(raw_section.get("must_include")) if _text(item)][:4],
                "must_not_repeat": [_text(item) for item in _list(raw_section.get("must_not_repeat")) if _text(item)][:4],
                "source_ids": source_ids,
                "boundary_notes": [_text(item) for item in _list(raw_section.get("boundary_notes")) if _text(item)][:4],
            }
        )
    normalized = {
        "schema_version": "report-plan-v1",
        "title": _text(raw_plan.get("title")) or title or "安全事件调查报告",
        "planning_rationale": _text(raw_plan.get("planning_rationale")) or "由 report material agent 基于材料选择章节。",
        "sections": normalized_sections,
        "appendix_note": _text(raw_plan.get("appendix_note"))
        or "技术细节、IOC/IOA、关键对象清单、观测引用、证据细目和待补缺口详见技术附录。",
    }
    # The model owns semantic section selection. Keep this function to schema
    # normalization only; validation/feedback handles missing coverage or refs.
    return normalized


def _fallback_materials_from_preload(tool_results: List[Dict[str, Any]], bundle: Dict[str, Any] | None = None) -> Dict[str, Any]:
    overview = {}
    scope_roles: List[Dict[str, Any]] = []
    gaps: List[Dict[str, Any]] = []
    timeline_events: List[Dict[str, Any]] = []
    recommendations: List[Dict[str, Any]] = []
    for item in tool_results:
        if item.get("tool_name") == "get_case_overview":
            overview = _dict(item.get("result"))
        elif item.get("tool_name") == "get_scope_roles":
            scope_roles = _list(_dict(item.get("result")).get("objects"))
        elif item.get("tool_name") == "get_gaps_and_boundaries":
            gaps = _list(_dict(item.get("result")).get("gaps"))
        elif item.get("tool_name") == "get_timeline":
            timeline_events = _list(_dict(item.get("result")).get("events"))
        elif item.get("tool_name") == "list_source_items" and _text(_dict(item.get("params")).get("item_type")) == "recommendation":
            recommendations = _list(_dict(item.get("result")).get("items"))
    header = _dict(overview.get("case_header"))
    confirmed = _list(overview.get("confirmed_scope"))
    candidates = _list(overview.get("candidate_scope"))
    key_events = [
        item
        for item in timeline_events
        if isinstance(item, dict) and _text(item.get("source_id")) and _text(item.get("exact_fact_text"))
    ][:6]
    materials = {
        "schema_version": "report-writer-materials-v1",
        "source_inventory": [],
        "case_thesis": {
            "conclusion": _text(header.get("delivery_status_label") or header.get("delivery_status")),
            "severity": _text(header.get("severity_normalized") or header.get("severity")),
            "confidence": _text(header.get("confidence_normalized") or header.get("confidence")),
            "confirmed_scope": confirmed,
            "candidate_scope": candidates,
            "why_this_judgment_holds": "当前只能依据已整理的交付判断和证据包保守生成报告材料。",
            "why_not_stronger_or_broader": "候选范围和未闭合缺口不能直接并入已确认范围。",
            "source_ids": ["verdict:delivery"],
            "exact_fact_text": _text(header.get("delivery_status_label") or header.get("delivery_status")),
        },
        "narrative_spine": [
            {
                "step_label": _text(item.get("classification") or item.get("status") or f"关键节点 {idx}"),
                "source_ids": [_text(item.get("source_id"))],
                "exact_fact_text": _text(item.get("exact_fact_text")),
                "why_it_matters": "该节点用于支撑事件过程、范围或边界判断。",
            }
            for idx, item in enumerate(key_events, start=1)
        ],
        "evidence_argument_map": [
            {
                "claim": _text(item.get("classification") or "关键事件事实"),
                "source_ids": [_text(item.get("source_id"))],
                "exact_fact_text": _text(item.get("exact_fact_text")),
                "why_it_matters": "该事实是当前判断的关键支撑之一，需要和其他证据共同解释。",
                "limitation": "该事实不能脱离上下文单独推出更强结论。",
            }
            for item in key_events[:4]
        ],
        "scope_role_matrix": [
            {
                "object": _text(item.get("object")),
                "role": _text(item.get("report_scope_role")),
                "may_be_written_as_affected": bool(item.get("may_be_written_as_affected")),
                "how_to_write": _text(item.get("report_scope_role")),
                "exact_fact_text": _text(item.get("exact_fact_text")),
                "source_ids": [_text(item.get("source_id"))],
            }
            for item in scope_roles
            if _text(item.get("source_id")) and _text(item.get("exact_fact_text"))
        ],
        "counterarguments_and_boundaries": [
            {
                "point": _text(item.get("question")),
                "effect_on_judgment": "limits_scope",
                "explanation": _text(item.get("status_reason")) or "该缺口限制更强范围结论。",
                "exact_fact_text": _text(item.get("exact_fact_text") or item.get("question")),
                "source_ids": [_text(item.get("source_id"))],
            }
            for item in gaps
            if _text(item.get("source_id")) and _text(item.get("question"))
        ],
        "action_rationale": [
            {
                "action": _reader_friendly_text(item.get("summary")),
                "why_now": "该动作直接对应当前处置建议或待补证据边界。",
                "reader_action": _reader_friendly_text(item.get("summary")),
                "exact_fact_text": _text(item.get("exact_fact_text") or item.get("summary")),
                "source_ids": [_text(item.get("source_id"))],
            }
            for item in recommendations[:3]
            if _text(item.get("source_id")) and _text(item.get("summary"))
        ],
        "section_briefs": [],
        "reportable_limits": ["report material agent 未能完成完整材料整理，当前使用保守 fallback materials。"],
    }
    if bundle:
        materials["report_plan"] = _fallback_report_plan(materials, bundle, title=_text(header.get("title")))
        materials["section_briefs"] = _section_briefs_from_plan(materials, bundle)
        materials["source_inventory"] = _source_inventory_from_materials(bundle, materials)
    return materials


def _overview_from_tool_results(tool_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    for item in tool_results:
        if item.get("tool_name") == "get_case_overview":
            return _dict(item.get("result"))
    return {}


def _normalize_source_ids_in_material(value: Any) -> Any:
    if isinstance(value, list):
        return [_normalize_source_ids_in_material(item) for item in value]
    if not isinstance(value, dict):
        return value
    normalized = {key: _normalize_source_ids_in_material(item) for key, item in value.items()}
    source_id = _text(normalized.get("source_id"))
    if source_id and not _list(normalized.get("source_ids")):
        normalized["source_ids"] = [source_id]
    if "can_be_written_as_affected" in normalized and "may_be_written_as_affected" not in normalized:
        normalized["may_be_written_as_affected"] = bool(normalized.get("can_be_written_as_affected"))
    return normalized


def _source_ids_from_item(item: Dict[str, Any]) -> List[str]:
    source_ids = _list(item.get("source_ids"))
    source_id = _text(item.get("source_id"))
    if source_id:
        source_ids.append(source_id)
    return [_text(source_id).replace(" ", "") for source_id in source_ids if _text(source_id)]


def _source_fact_text(index: Dict[str, Dict[str, Any]], source_ids: List[str], *, limit: int = 4) -> str:
    pieces: List[str] = []
    seen: set[str] = set()
    for source_id in source_ids:
        item = index.get(_text(source_id))
        if not item:
            continue
        text = (
            _text(item.get("exact_fact_text"))
            or _text(item.get("summary"))
            or _text(item.get("text"))
            or _text(item.get("question"))
            or _text(item.get("value"))
        )
        if not text or text in seen:
            continue
        seen.add(text)
        pieces.append(text)
        if len(pieces) >= limit:
            break
    return "；".join(pieces)


def _source_fact_rows(index: Dict[str, Dict[str, Any]], source_ids: List[str], *, limit: int = 6) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for source_id in source_ids:
        normalized_id = _text(source_id)
        if not normalized_id or normalized_id in seen:
            continue
        item = _dict(index.get(normalized_id))
        if not item:
            continue
        fact_text = (
            _text(item.get("exact_fact_text"))
            or _text(item.get("summary"))
            or _text(item.get("text"))
            or _text(item.get("question"))
            or _text(item.get("value"))
        )
        if not fact_text:
            continue
        seen.add(normalized_id)
        rows.append(
            {
                "source_id": normalized_id,
                "source_type": _text(item.get("source_type") or normalized_id.split(":", 1)[0]),
                "status": _text(item.get("status") or item.get("relation") or item.get("report_scope_role")),
                "reader_fact_text": _reader_friendly_text(fact_text),
                "exact_fact_text": fact_text,
            }
        )
        if len(rows) >= limit:
            break
    return rows


def _section_briefs_from_plan(materials: Dict[str, Any], bundle: Dict[str, Any]) -> List[Dict[str, Any]]:
    index = source_index_for_materials(bundle)
    briefs: List[Dict[str, Any]] = []
    for raw_section in _list(_dict(materials.get("report_plan")).get("sections")):
        section = _dict(raw_section)
        section_type = _text(section.get("section_type"))
        source_ids = _source_ids_from_item(section)
        if not section_type or not source_ids:
            continue
        briefs.append(
            {
                "section_type": section_type,
                "title": _text(section.get("title")),
                "question_to_answer": _text(section.get("question_to_answer")),
                "mode": _text(section.get("mode")) or "full",
                "must_include": _list(section.get("must_include")),
                "must_not_repeat": _list(section.get("must_not_repeat")),
                "boundary_notes": _list(section.get("boundary_notes")),
                "source_ids": source_ids,
                "key_facts": _source_fact_rows(index, source_ids, limit=6),
            }
        )
    return briefs


def _fill_missing_exact_fact_text(value: Any, index: Dict[str, Dict[str, Any]]) -> Any:
    if isinstance(value, list):
        return [_fill_missing_exact_fact_text(item, index) for item in value]
    if not isinstance(value, dict):
        return value
    filled = {key: _fill_missing_exact_fact_text(item, index) for key, item in value.items()}
    if not _text(filled.get("exact_fact_text")):
        source_ids = _source_ids_from_item(filled)
        fact_text = _source_fact_text(index, source_ids)
        if fact_text:
            filled["exact_fact_text"] = fact_text
    return filled


def _event_source_ids(source_ids: List[str]) -> List[str]:
    return [source_id for source_id in source_ids if _text(source_id).startswith("event:")]


def _source_statuses(index: Dict[str, Dict[str, Any]], source_ids: List[str]) -> List[str]:
    statuses: List[str] = []
    seen: set[str] = set()
    for source_id in source_ids:
        status = _text(_dict(index.get(source_id)).get("status"))
        if status and status not in seen:
            seen.add(status)
            statuses.append(status)
    return statuses


def _ensure_event_evidence_from_narrative(
    evidence_items: List[Dict[str, Any]],
    narrative_items: List[Dict[str, Any]],
    index: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    out = list(evidence_items)
    event_evidence_count = sum(1 for item in out if _event_source_ids(_source_ids_from_item(item)))
    existing_keys = {tuple(_event_source_ids(_source_ids_from_item(item))) for item in out}
    for narrative in narrative_items:
        if event_evidence_count >= 3:
            break
        event_ids = _event_source_ids(_source_ids_from_item(narrative))[:2]
        if not event_ids or tuple(event_ids) in existing_keys:
            continue
        statuses = _source_statuses(index, event_ids)
        is_candidate = "candidate" in statuses
        out.append(
            {
                "claim": _text(narrative.get("step_label") or narrative.get("summary") or "关键事件节点"),
                "source_ids": event_ids,
                "supporting_event_ids": event_ids,
                "why_it_matters": "该节点是事件主线中的关键事实，用于支撑时序推进和范围判断。",
                "limitation": "该节点仍需按候选边界表述，不能直接并入已确认范围。"
                if is_candidate
                else "该节点需要与其他证据共同使用，不能脱离上下文单独定性。",
            }
        )
        existing_keys.add(tuple(event_ids))
        event_evidence_count += 1
    return out


def _iter_nested_material_dicts(value: Any) -> List[Dict[str, Any]]:
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


def _flatten_narrative_spine(value: Any) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for item in _list(value):
        if not isinstance(item, dict):
            continue
        if _text(item.get("exact_fact_text")) or _source_ids_from_item(item):
            out.append(item)
            continue
        for key, nested in item.items():
            for nested_item in _iter_nested_material_dicts(nested):
                exact = _text(nested_item.get("exact_fact_text"))
                source_ids = _source_ids_from_item(nested_item)
                if not source_ids:
                    continue
                out.append(
                    {
                        "step_label": _text(nested_item.get("step_label") or key),
                        "summary": _text(nested_item.get("summary") or exact),
                        "reporting_role": _text(nested_item.get("reporting_role") or key),
                        "exact_fact_text": exact,
                        "source_ids": source_ids,
                    }
                )
    return out


def _flatten_evidence_argument_map(value: Any) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for item in _list(value):
        if not isinstance(item, dict):
            continue
        if _text(item.get("exact_fact_text")) or _source_ids_from_item(item):
            out.append(item)
            continue
        for key, nested_values in item.items():
            for nested in _iter_nested_material_dicts(nested_values):
                if not isinstance(nested, dict):
                    continue
                exact = _text(nested.get("exact_fact_text"))
                source_ids = _source_ids_from_item(nested)
                if not source_ids:
                    continue
                evidence_item: Dict[str, Any] = {
                    "claim": _text(nested.get("claim") or key),
                    "exact_fact_text": exact,
                    "source_ids": source_ids,
                    "why_it_matters": _text(nested.get("why_it_matters") or nested.get("rationale")),
                    "limitation": _text(nested.get("limitation")),
                    "recommended_sections": _list(nested.get("recommended_sections")),
                }
                if source_ids and source_ids[0].startswith("event:"):
                    evidence_item["supporting_event_ids"] = source_ids
                if source_ids and source_ids[0].startswith("claim:"):
                    evidence_item["supporting_claim_ids"] = source_ids
                out.append(evidence_item)
    return out


def _repair_materials_contract(
    materials: Dict[str, Any],
    tool_results: List[Dict[str, Any]],
    bundle: Dict[str, Any],
) -> Dict[str, Any]:
    repaired = _normalize_source_ids_in_material(_dict(materials))
    source_index = source_index_for_materials(bundle)
    overview = _overview_from_tool_results(tool_results)
    header = _dict(overview.get("case_header"))
    thesis = _dict(repaired.get("case_thesis"))
    conclusion = _text(
        header.get("delivery_status_label")
        or _dict(header.get("final_verdict")).get("status_label")
        or thesis.get("conclusion")
        or header.get("delivery_status")
    )
    thesis["conclusion"] = conclusion or "未评估"
    thesis["severity"] = _text(thesis.get("severity") or header.get("severity_normalized") or header.get("severity") or "未评估")
    thesis["confidence"] = _text(thesis.get("confidence") or header.get("confidence_normalized") or header.get("confidence") or "未评估")
    thesis.setdefault("confirmed_scope", _list(overview.get("confirmed_scope")))
    thesis.setdefault("candidate_scope", _list(overview.get("candidate_scope")))
    if not _text(thesis.get("why_this_judgment_holds")):
        thesis["why_this_judgment_holds"] = _text(thesis.get("why_it_matters")) or "当前判断来自已收集证据链与交付范围判断的综合结果。"
    if not _text(thesis.get("why_not_stronger_or_broader")):
        thesis["why_not_stronger_or_broader"] = (
            _text(thesis.get("scope_cannot_widen_reason"))
            or "候选范围、未独立验证事件或未闭合缺口不能直接并入已确认范围。"
        )
    thesis_source_ids = _list(thesis.get("source_ids"))
    if "verdict:delivery" not in thesis_source_ids:
        thesis_source_ids.insert(0, "verdict:delivery")
    thesis["source_ids"] = thesis_source_ids
    if not _text(thesis.get("exact_fact_text")):
        verdict_summary = _dict(header.get("final_verdict_summary"))
        thesis["exact_fact_text"] = (
            _text(verdict_summary.get("exact_fact_text"))
            or conclusion
            or _text(header.get("delivery_status_label") or header.get("delivery_status"))
        )
    repaired["case_thesis"] = thesis
    repaired["narrative_spine"] = _flatten_narrative_spine(repaired.get("narrative_spine"))
    repaired["evidence_argument_map"] = _flatten_evidence_argument_map(repaired.get("evidence_argument_map"))
    repaired["evidence_argument_map"] = _ensure_event_evidence_from_narrative(
        _list(repaired.get("evidence_argument_map")),
        _list(repaired.get("narrative_spine")),
        source_index,
    )
    repaired.setdefault("schema_version", "report-writer-materials-v1")
    for key in [
        "narrative_spine",
        "evidence_argument_map",
        "scope_role_matrix",
        "counterarguments_and_boundaries",
        "action_rationale",
        "section_briefs",
        "reportable_limits",
    ]:
        if not isinstance(repaired.get(key), list):
            repaired[key] = []
    repaired = _fill_missing_exact_fact_text(repaired, source_index)
    for item in _list(repaired.get("scope_role_matrix")):
        if not isinstance(item, dict):
            continue
        source_ids = _source_ids_from_item(item)
        source_item = source_index.get(source_ids[0]) if source_ids else {}
        report_scope_role = _text(_dict(source_item).get("report_scope_role"))
        if report_scope_role and not _text(item.get("role")):
            item["role"] = report_scope_role
        if report_scope_role and not _text(item.get("how_to_write")):
            item["how_to_write"] = report_scope_role
    for item in _list(repaired.get("action_rationale")):
        if not isinstance(item, dict):
            continue
        if not _text(item.get("action")):
            item["action"] = _text(item.get("exact_fact_text"))
        item["action"] = _reader_friendly_text(item.get("action"))
        item["reader_action"] = _reader_friendly_text(item.get("action"))
    repaired["report_plan"] = _normalize_report_plan(
        repaired,
        bundle,
        title=_text(header.get("title") or header.get("case_title")),
    )
    if not _list(repaired.get("section_briefs")):
        repaired["section_briefs"] = _section_briefs_from_plan(repaired, bundle)
    repaired["source_inventory"] = _source_inventory_from_materials(bundle, repaired)
    return repaired


def run_report_material_loop(
    bundle: Dict[str, Any],
    llm: Any,
    *,
    max_rounds: int = 3,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    try:
        from langchain_core.messages import HumanMessage, SystemMessage
    except Exception as exc:
        materials = _fallback_materials_from_preload(_preload_results(bundle), bundle)
        trace = {
            "schema_version": "report-material-loop-trace-v1",
            "status": "fallback",
            "error": f"message_import_failed:{type(exc).__name__}:{exc}",
            "tool_results": [],
        }
        return materials, trace

    # The final materials object can be several KB even when it only carries
    # source_ids and short rationales. A tight output cap often truncates JSON,
    # which forces the renderer onto the deterministic fallback path.
    agent_llm = llm.bind(max_tokens=3600, temperature=0) if hasattr(llm, "bind") else llm
    tool_results = _preload_results(bundle)
    feedback: List[str] = []
    draft_materials: Dict[str, Any] = {}
    trace: Dict[str, Any] = {
        "schema_version": "report-material-loop-trace-v1",
        "status": "running",
        "rounds": [],
        "tool_results": tool_results,
        "validation": {},
    }

    for round_index in range(1, max_rounds + 1):
        force_submit = round_index == max_rounds
        try:
            action = _invoke_report_agent_json(
                agent_llm,
                [
                    SystemMessage(content=REPORT_AGENT_SYSTEM_PROMPT),
                    HumanMessage(
                        content=_build_round_user_prompt(
                            round_index=round_index,
                            max_rounds=max_rounds,
                            tool_results=tool_results,
                            draft_materials=draft_materials,
                            feedback=feedback,
                            force_submit=force_submit,
                        )
                    ),
                ],
                role="report_material_loop",
            )
        except Exception as exc:
            feedback.append(f"round {round_index} parse/invoke error: {type(exc).__name__}: {exc}")
            trace["rounds"].append({"round": round_index, "error": feedback[-1]})
            continue

        trace["rounds"].append({"round": round_index, "action": action})
        action_type = _text(action.get("action"))
        if action_type == "submit":
            materials = _repair_materials_contract(_dict(action.get("materials")), tool_results, bundle)
            validation = validate_report_writer_materials(bundle, materials)
            trace["validation"] = validation
            if validation.get("ok"):
                trace["status"] = "submitted"
                trace["submitted_materials"] = materials
                return materials or _fallback_materials_from_preload(tool_results, bundle), trace
            feedback.append(f"materials validation failed: {_json(validation)}")
            draft_materials = materials
            continue

        if action_type == "tool" and not force_submit:
            calls = _normalize_tool_calls(action)
            if not calls:
                feedback.append("tool action missing tool_calls")
                continue
            for call in calls:
                tool_name = _text(call.get("tool_name"))
                params = _dict(call.get("params"))
                try:
                    result = execute_report_agent_tool(bundle, tool_name, params)
                    tool_results.append({"round": round_index, "tool_name": tool_name, "params": params, "result": result})
                except Exception as exc:
                    feedback.append(f"tool {tool_name} failed: {type(exc).__name__}: {exc}")
            continue

        feedback.append(f"invalid action at round {round_index}: {action_type or 'missing'}")

    materials = _fallback_materials_from_preload(tool_results, bundle)
    validation = validate_report_writer_materials(bundle, materials)
    trace["status"] = "fallback_after_rounds"
    trace["validation"] = validation
    return materials, trace
