from __future__ import annotations

import json
from typing import Any, Dict, List, Tuple

from ..services.api.llm_observability import invoke_llm_with_trace
from .report_agent_tools import (
    REPORT_SECTION_TYPES,
    build_source_fact_catalog,
    collect_material_source_ids,
    execute_report_agent_tool,
    source_index_for_materials,
    source_fact_indexes,
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


def _feedback_requests_paragraph_groups(feedback: List[Any]) -> bool:
    group_codes = {
        "patch_route_from_deterministic_draft",
        "missing_agent_paragraph_groups",
        "invalid_or_missing_paragraph_groups",
    }
    for raw in feedback:
        if isinstance(raw, dict):
            code = _text(raw.get("code"))
            severity = _text(raw.get("severity")) or "blocking"
            message = _text(raw.get("message_for_agent"))
            if severity != "advisory" and (code in group_codes or "paragraph_groups" in message):
                return True
        elif "paragraph_groups" in _text(raw):
            return True
    return False


AGENT_PARAGRAPH_GROUP_SECTION_TYPES = {
    "timeline_process",
    "evidence_judgment",
    "relationship_scope",
    "counterevidence_limits",
}


def _is_placeholder_text(value: Any) -> bool:
    return _text(value) in {"...", "……", "<...>", "TODO", "TBD"}


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


META_MATERIAL_TEXT_MARKERS = {
    "生成报告材料",
    "证据包保守生成",
    "只能依据已整理",
}


def _is_meta_material_text(value: Any) -> bool:
    text = _text(value)
    return bool(text and any(marker in text for marker in META_MATERIAL_TEXT_MARKERS))


def _source_derived_verdict_text(header: Dict[str, Any]) -> str:
    verdict_summary = _dict(header.get("final_verdict_summary"))
    exact = _reader_friendly_text(verdict_summary.get("exact_fact_text"))
    if exact and not _is_meta_material_text(exact):
        return exact
    rationale_parts = [
        _reader_friendly_text(item)
        for item in _list(verdict_summary.get("rationale"))
        if _text(item) and not _is_meta_material_text(item)
    ]
    if rationale_parts:
        return "；".join(rationale_parts[:4])
    return _reader_friendly_text(
        verdict_summary.get("status_label")
        or header.get("delivery_status_label")
        or header.get("delivery_status")
    )


def _fallback_scope_boundary_text(candidates: List[Any], gaps: List[Dict[str, Any]]) -> str:
    gap_texts = [
        _reader_friendly_text(item.get("exact_fact_text") or item.get("status_reason") or item.get("question"))
        for item in gaps
        if _text(item.get("exact_fact_text") or item.get("status_reason") or item.get("question"))
    ]
    if candidates and gap_texts:
        return "候选范围和未闭合缺口需要作为报告边界呈现，不能直接并入已确认范围。"
    if candidates:
        return "候选范围尚未独立验证，不能直接并入已确认范围。"
    if gap_texts:
        return gap_texts[0]
    return "当前材料没有提供可把范围或结论写得更广的 source-bound 依据。"


def _fallback_event_claim(item: Dict[str, Any]) -> str:
    text = _reader_friendly_text(
        item.get("exact_fact_text")
        or item.get("summary")
        or item.get("text")
        or item.get("event_summary")
    )
    if text:
        return text
    source_id = _text(item.get("source_id"))
    if source_id:
        return f"{source_id} 对应的关键事件事实"
    return "关键事件事实"


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
- section_briefs 是章节论证计划，不是事实摘要；不要在 section_briefs.key_facts 或 paragraph_groups 里输出 reader_fact_text、summary、claim 或 exact_fact_text。
- 严重度和把握度只能输出 高 / 中 / 低 / 未评估；如果源材料写 高危 / 中危 / 低危，只能标准化为 高 / 中 / 低。
- candidate、候选事件、待确认对象只能用于待确认范围或边界说明，不能写成已确认传播、已确认影响或主证据链结论。
- 材料不足时写入 reportable_limits，不要编造。

二、取材策略
- 预加载结果通常已经包含 overview、scope、gaps、时间线、claim 索引和 recommendation 索引；如果足以组织材料，应直接 submit。
- 只有在缺少必要 source_id、缺少支撑关键判断的 exact_fact_text，或补取材会改变 case_thesis、confirmed/candidate scope、report_plan 章节边界时，才调用工具。
- 如果继续取材不会新增关键 source 类型、不会改变 case_thesis、不会改变 confirmed/candidate scope、不会改变 report_plan 章节边界，只会改善措辞或补充非关键细节，必须 submit。
- 如果某类 source 在预加载材料和一次针对性补取材后仍不存在，或只存在明显无关材料，不要为了满足覆盖目标硬凑；应 submit，并在 reportable_limits 说明该类源材料缺失或不可用于正文。
- 如果上一轮反馈是 schema、source_id、exact_fact_text 或核心覆盖问题，优先修复 materials；只有修复确实需要新 source 时才调用工具。
- 如果上一轮反馈包含 validation feedback / repair_hints，必须把它当作本轮最高优先级修复任务。除非反馈明确要求新增 source，否则不要调用工具。
- force_submit=true 时必须 submit，不得再调用工具。
- tool action 只允许选择 tool_catalog 中的工具名，params 必须来自已见材料；无法构造安全参数时不要调用工具。

三、提交材料契约
- 输出材料的目标是让 writer 知道“本节分几段讲 -> 每段使用哪些原子事实 -> 这一段要证明什么 -> 和其他章节如何区分”，不是让你改写事实。
- schema_version 必须是 report-writer-materials-v2。
- source_fact_catalog 由系统确定性注入，你不要输出或修改它；你只能复制 prompt 中 deterministic source_fact_catalog 已有的 fact_id/source_id。
- source_inventory 可以省略或保持很小；系统会按最终 materials 实际引用的 source_ids 重建。不要罗列未使用 source。
- case_thesis 必须说明 conclusion、severity、confidence、confirmed_scope、candidate_scope、why_this_judgment_holds、why_not_stronger_or_broader、source_ids。
- case_thesis 优先使用 get_case_overview.case_header.final_verdict_summary 和 verdict:delivery 作为结论来源；如果该字段缺失，使用 case_header 中已有 delivery_status/status_label，并在 reportable_limits 中说明结论来源不完整。
- narrative_spine 是最小主线索引，通常只输出 4 条：起点、推进、扩线/范围、边界；每条 source_ids 1 到 2 个代表性 id。
- evidence_argument_map 是最小论证索引，通常只输出 3 条：主支撑证据、范围证据、边界证据；每条 source_ids 1 到 3 个代表性 id。claim:* 只能补充整体观察，不能替代关键 event:* 事实。
- scope_role_matrix 是最小对象索引，通常只输出 3 到 4 条：已确认受影响资产、待确认对象、核心外部基础设施、背景对象；每条 source_ids 1 到 3 个代表性 id，并明确 may_be_written_as_affected。
- counterarguments_and_boundaries 是最小边界索引，通常只输出 1 到 2 条，解释反证、缺口和结论边界。
- action_rationale 通常只输出 1 到 2 条，优先吸收 recommendation/action source；不要把 gap 问句直接改写成处置动作。
- section_briefs 是必填材料，且必须与 report_plan.sections 一一对应、顺序一致。它是 Section Argument Map，不是自然语言材料包。
- section_briefs 每个元素必须包含 section_type、source_ids、key_facts、paragraph_groups。
- key_facts 保留为 fact coverage 明细：每个 key_fact 必须带 source_ids 或 fact_ids，并至少包含 fact_role、why_it_matters、limitation、use_for 之一；它不是 writer 的段落计划。
- paragraph_groups 是主要写作计划：每个 group 必须带 group_id、paragraph_role、paragraph_claim、fact_ids 或 source_ids、write_focus、contrast_or_boundary、must_not_repeat。
- paragraph_groups 的目标是说明“这一段要回答什么、组合哪些原子事实、为什么这样组合、不能重复/推出什么”。一组可以引用 2 到 4 条 facts；不要把多条事件合并成无 source 的泛化摘要。
- 修复 validation feedback 时，不要因为只修某个章节就删除其他章节的 section_briefs；最终提交仍必须覆盖 report_plan.sections 中的每个 section_type。
- 当前 draft materials 如果非空，你可以提交 partial materials patch：只输出需要调整的 report_plan、section_briefs、reportable_limits 或少量核心列表；系统会保留 draft 中未被你覆盖的字段并重新校验。不要为了“完整”重吐 source_fact_catalog 或大段旧材料。
- 如果 draft materials 已经满足要求或你没有明确改动，直接输出 {"action":"submit","materials":{}}；这表示接受当前 deterministic route，不要把 draft 原样复制一遍。
- reportable_limits 只能写真实剩余限制，例如候选事件未验证、反证检查未完成、主机侧日志缺失；不要写“报告中包含了哪些内容”。
- 所有列表保持扁平，不要输出嵌套大段摘要。无值字段省略，不要输出 null 或空字符串占位。

四、report_plan 策略
- report_plan 由你负责选择章节；代码只做 schema、source_id 和核心覆盖校验，不会替你自动补章节。
- section_type 只能使用：investigation_entry、scope_hypothesis、entity_roles、evidence_judgment、conclusion_actions、timeline_process、relationship_scope、impact_assessment、counterevidence_limits、external_context_intel、topology_path_analysis。
- report_plan 的目标是覆盖问题而不是堆标题：confirmed_incident 通常强调证据闭环和处置；needs_review 通常强调证据、候选范围、缺口；monitor_only 不要写得像攻击事件。
- 正文通常 5 到 9 节；简单 case 可少于 5 节，但必须覆盖调查起点、范围或对象、证据判断、结论动作。
- 选择章节前必须先判断复杂度，并在 planning_rationale 里说明：是否存在多资产、候选扩线、核心外部基础设施、背景/反证事件、未闭合 gap、时序推进；这些信号分别由哪些章节承接。
- 如果存在多资产、候选扩线、横向移动线索、多个外部基础设施，或时序推进会改变判断，不要提交过薄的极简 plan。
- 条件章节只有材料支撑时才选：timeline_process 需要时间顺序改变判断；relationship_scope 需要多对象、扩线边界或核心外部基础设施关系；impact_assessment 需要独立影响/风险；external_context_intel 只有外部/内部情报影响边界时才独立成章。
- 如果时间线呈现“种子命中 -> 持续通信/执行线索 -> 横向动作/第二资产/候选扩线”的推进，timeline_process 通常应独立成章；除非 planning_rationale 说明时序不会改变判断，才允许并入 evidence_judgment。
- 如果材料同时包含已确认受影响资产、待确认资产、核心外部基础设施、候选事件或扩线 claim，relationship_scope 必须被承接：优先独立成章；只有对象关系非常简单时才允许并入 scope_hypothesis/entity_roles，且必须把 relationship_scope 写入 secondary_section_types，并在 must_include、boundary_notes、section_briefs 里说明确认/候选/外部基础设施边界。
- 相邻职责简单时可用 secondary_section_types 合并，例如 scope_hypothesis 合并 entity_roles，或 conclusion_actions 合并 impact_assessment；合并时必须在 must_include、must_not_repeat、boundary_notes 中写清边界。
- planning_rationale 不能只写“覆盖起点、范围、证据、结论”；必须说明为什么选择这些章节、为什么省略其他有条件章节。
- 章节顺序通常为：调查起点 -> 范围/对象 -> 事件过程 -> 证据判断 -> 关联范围/影响 -> 反证与边界 -> 结论与行动；只有 planning_rationale 能说明理由时才调整顺序。
- 每个 section 必须有 source_ids，优先引用细粒度 event/object/gap/verdict/action/claim source，不要只引用总览。
- 每个 section 的 source_ids 放代表性 source_id；复杂章节的完整事实覆盖应放在 section_briefs.key_facts 的 source_ids/fact_ids 中，由 deterministic source_fact_catalog 回填。
- 每个 section 的 must_not_repeat 要明确指出不要重复哪个相邻章节内容，帮助 writer 避免换标题复述同一条事件链。
- report_plan 只回答“写哪些节、每节回答什么”；section_briefs.paragraph_groups 回答“这一节分几段写、每段事实组合承担什么论证任务”。不要让两个结构互相复述。
- 章节材料分工：timeline_process 只讲事件如何推进；evidence_judgment 讲为什么当前判断成立；relationship_scope 讲已确认对象、候选对象、核心外部基础设施和扩线边界；counterevidence_limits 讲反证、未闭合 gap 和不能写强结论的原因；conclusion_actions 只讲结论和行动。

五、覆盖目标与质量门
- 覆盖目标只在对应 source 类型存在时适用：优先引用 1 个 verdict、3 个 event、1 个 claim、3 个 object、1 个 gap；如果 recommendations 存在，优先引用 1 个 action。
- evidence_judgment 优先引用 4 到 8 个关键 event/claim/verdict；timeline_process 优先引用决定性 event；relationship_scope 优先引用 object/event/gap；counterevidence_limits 优先引用 gap/counterevidence/verdict；conclusion_actions 优先引用 action/gap/verdict。
- 复杂 case 中，timeline_process、evidence_judgment、relationship_scope、counterevidence_limits 的 section_briefs 必须覆盖足够原子事实；这些章节每节至少 3 个 paragraph_groups。timeline_process 不要少于 4 条关键 event fact，evidence_judgment 不要少于 3 条关键 event fact。
- paragraph_groups 分工要求：timeline_process 按事件阶段分组；evidence_judgment 按通信连续性、执行/横向线索、范围证据、证据边界分组；relationship_scope 按已确认资产、候选对象、核心外部基础设施、共享/背景边界分组；counterevidence_limits 按未闭合 gap、背景事件、候选未验证、结论上限分组。
- paragraph_claim 和 write_focus 必须具体，不要只写“事件时间线事实”“主支撑事件”“行动建议”或“该事实需要结合其他证据使用”。
- section_briefs 每条 key_fact 可以引用 1 个原子事实；如果同一论证角色需要多条事件，请拆成多条 key_fact，不要合并成“可疑活动/横向移动”等泛句。
- 对 relationship_scope，key_facts 至少覆盖以下可用类别中的 2 类：已确认资产、候选资产/候选对象、核心外部基础设施、候选事件或扩线 claim、限制并入主链的 gap/claim。
- 对 counterevidence_limits，key_facts 优先覆盖未闭合 gap、背景/替代解释事件、候选未验证原因；不要只重复结论。
- 避免过度定性：不要把“可疑执行线索”改写成“已感染/恶意软件已存在/攻击者已控制”，除非 exact_fact_text 明确提供这些结论。
- 为减少冗长输出，section_briefs.key_facts 只输出 fact_ids、source_ids、fact_role、why_it_matters、limitation、use_for；paragraph_groups 只输出 group_id、paragraph_role、paragraph_claim、fact_ids、source_ids、write_focus、contrast_or_boundary、must_not_repeat；不要输出 claim、summary、reader_fact_text 或 exact_fact_text。
- 如果某节材料较复杂，优先把细粒度路由指令放进 section_briefs[*].key_facts，而不是把所有内容塞进 must_include。
- 为避免 JSON 截断，每个 key_fact 只写 fact_id/source_id、fact_role、why_it_matters、limitation/use_for；不要复制 summary_line 或 exact_fact_text。
- 提交前做 token 自检：source_inventory 固定输出 []；不要复制 tool_results 或 source_fact_catalog 原文；不要输出 reader_fact_text/exact_fact_text；section_briefs 不需要 title/question/mode/must_include；复杂章节 paragraph_groups 控制在 3 到 5 组。

复杂 case section_briefs 示例：
{
  "section_type": "relationship_scope",
  "source_ids": ["object:OBJ-01", "object:OBJ-03", "object:OBJ-04", "gap:validate_candidate_events"],
  "key_facts": [
    {
      "source_ids": ["object:OBJ-01", "object:OBJ-02"],
      "fact_ids": ["fact-object-obj-01", "fact-object-obj-02"],
      "fact_role": "已确认范围",
      "why_it_matters": "给 writer 明确确认范围的边界。",
      "limitation": "不要把待验证对象并入已确认范围。",
      "use_for": "用 source_fact_catalog 中对应对象事实说明确认范围。"
    },
    {
      "source_ids": ["object:OBJ-03"],
      "fact_ids": ["fact-object-obj-03"],
      "fact_role": "候选扩线",
      "why_it_matters": "解释为什么它需要出现在关联范围章节。",
      "limitation": "候选事件尚未独立验证，只能作为待确认范围。",
      "use_for": "用对应原子事实说明候选对象为何不能并入已确认范围。"
    },
    {
      "source_ids": ["object:OBJ-04", "gap:validate_candidate_events"],
      "fact_ids": ["fact-object-obj-04", "fact-gap-validate-candidate-events"],
      "fact_role": "外部基础设施与边界",
      "why_it_matters": "帮助 writer 区分核心外部基础设施、共享背景和候选关联。",
      "limitation": "共享基础设施不能单独证明候选对象已受影响。",
      "use_for": "用对应原子事实说明外部基础设施和候选边界。"
    }
  ],
  "paragraph_groups": [
    {
      "group_id": "relationship_scope-g1",
      "paragraph_role": "已确认范围",
      "paragraph_claim": "种子资产和已确认受影响资产可以写入当前确认范围，但候选对象不能并入。",
      "fact_ids": ["fact-object-obj-01", "fact-object-obj-02"],
      "source_ids": ["object:OBJ-01", "object:OBJ-02"],
      "write_focus": "用对象角色说明已确认范围的边界。",
      "contrast_or_boundary": "不要重复 timeline_process 的事件推进细节。",
      "must_not_repeat": "不要把待确认对象写成已确认受影响资产。"
    },
    {
      "group_id": "relationship_scope-g2",
      "paragraph_role": "候选扩线",
      "paragraph_claim": "候选对象和候选事件说明扩线方向，但尚缺独立验证。",
      "fact_ids": ["fact-object-obj-03", "fact-gap-validate-candidate-events"],
      "source_ids": ["object:OBJ-03", "gap:validate_candidate_events"],
      "write_focus": "说明为什么这些对象只进入候选范围。",
      "contrast_or_boundary": "不要把候选扩线写成已确认传播路径。",
      "must_not_repeat": "不要复述 evidence_judgment 的主证据链。"
    }
  ]
}

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
    "schema_version": "report-writer-materials-v2",
    "source_inventory": [],
    "report_plan": {
      "schema_version": "report-plan-v1",
      "title": "安全事件调查报告",
      "planning_rationale": "说明为什么选择这些章节，以及为什么省略其他条件章节。",
      "sections": [
        {
          "section_type": "investigation_entry",
          "secondary_section_types": [],
          "title": "调查起点与已知线索",
          "question_to_answer": "为什么这起告警值得调查？",
          "mode": "full",
          "must_include": ["调查起点", "初始命中线索", "为什么值得继续调查"],
          "must_not_repeat": ["不要展开完整证据链或对象清单"],
          "source_ids": ["verdict:delivery"],
          "boundary_notes": ["候选对象只能作为边界说明"]
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
    "section_briefs": [
      {
        "section_type": "evidence_judgment",
        "source_ids": ["event:evt-1", "event:evt-2"],
        "key_facts": [
          {
            "source_ids": ["event:evt-1"],
            "fact_ids": ["fact-event-evt-1"],
            "fact_role": "主支撑证据",
            "why_it_matters": "说明它为什么改变当前判断。",
            "limitation": "说明它不能推出什么更强结论。",
            "use_for": "用 source_fact_catalog 的原子事实展开，不要改写事实本身。"
          },
          {
            "source_ids": ["event:evt-2"],
            "fact_ids": ["fact-event-evt-2"],
            "fact_role": "边界或补强证据",
            "why_it_matters": "说明它与上一条事实如何共同支撑本节判断。",
            "limitation": "说明它仍需要哪些后续验证。",
            "use_for": "用 source_fact_catalog 的原子事实展开。"
          }
        ],
        "paragraph_groups": [
          {
            "group_id": "evidence_judgment-g1",
            "paragraph_role": "通信连续性支撑",
            "paragraph_claim": "同一外部基础设施在种子资产上重复出现，使单点告警具备事件级复核价值。",
            "fact_ids": ["fact-event-evt-1", "fact-event-evt-2"],
            "source_ids": ["event:evt-1", "event:evt-2"],
            "write_focus": "解释这些事件如何共同支撑当前判断。",
            "contrast_or_boundary": "不要写完整时间线，时间推进留给 timeline_process。",
            "must_not_repeat": "不要把可疑执行线索写成已确认恶意软件。"
          }
        ]
      }
    ],
    "reportable_limits": [...]
  }
}
"""

REPORT_AGENT_SYSTEM_PROMPT = """你是 Trace-Agent 的 report material agent。你不继续调查，也不写 Markdown；你只把 report_source_bundle 中已有事实组织成 report-writer-materials-v2。

硬边界：
- 只能复制已见 source_id / fact_id，不得新增事实、实体、时间、动作、IOC、影响范围或结论。
- source_fact_catalog 由系统确定性注入；不要输出、改写或总结其中的事实文本。
- section_briefs 是章节论证计划，不是事实摘要；不要输出 reader_fact_text、summary_line、exact_fact_text 或大段自然语言事实。
- candidate、候选事件、待确认对象只能进入候选范围、扩线线索或边界说明，不能写成已确认传播、已确认受影响或主证据链结论。
- 严重度和把握度只能是 高 / 中 / 低 / 未评估。
- 输出只能是一个 JSON object。

取材与停止：
- 预加载和 draft materials 通常已经足够；除非 feedback 明确要求新 source，否则不要调用工具。
- 如果收到 validation feedback / repair_hints，优先修复 materials；不要为了润色继续取材。
- force_submit=true 时必须 submit。
- 如果 draft materials 非空，可以提交 partial materials patch；系统会保留未覆盖字段并重新校验。

材料契约：
- schema_version 必须是 report-writer-materials-v2。
- report_plan.sections 决定章节；section_briefs 必须与 report_plan.sections 的 section_type 顺序一一对应。
- key_facts 只是 fact coverage 明细：每条只写 fact_ids、source_ids、fact_role、why_it_matters、limitation、use_for。
- paragraph_groups 是 writer 主要写作计划：每组必须写 group_id、paragraph_role、paragraph_claim、fact_ids 或 source_ids、write_focus、contrast_or_boundary、must_not_repeat。
- paragraph_groups 只说明“这一段组合哪些事实、要证明什么、与其他章节如何区分、不能推出什么”；不要改写事实文本。
- paragraph_claim/write_focus 是给 writer 的编辑指令，不是正文句子。不要写“这些事实/这些节点/这些对象/这些建议/本节为什么需要展开”这类可直接抄进正文的模板句。
- paragraph_claim/write_focus 必须短：只写段落论证意图，不要复制 fact_hints 中的时间、IP、域名、资产串；事实细节只放在 fact_ids/source_ids，writer 会回填。
- 同一章节内不要出现重复 paragraph_claim；如果两个段落都叫“背景或替代解释”，必须拆出不同用途，例如“维护窗口替代解释”“共享基础设施边界”“候选节点未验证”。
- reportable_limits 只能写真限制，例如候选事件未验证、反证检查未完成、主机侧日志缺失。

章节分工：
- timeline_process 讲事件推进，按阶段/时间节点分组。
- evidence_judgment 讲为什么当前判断成立，按通信连续性、执行/横向线索、范围证据、证据边界分组。
- relationship_scope 讲确认资产、候选资产、核心外部基础设施、共享/背景边界。
- counterevidence_limits 讲 gap、背景/替代解释、候选未验证、结论上限。
- conclusion_actions 只讲结论与建议动作；action fact 只能写成建议，不能写成已观测事实。

复杂 case 质量门：
- 如果存在多资产、候选扩线、核心外部基础设施、背景/反证事件、未闭合 gap 或时序推进，复杂章节不要过薄。
- timeline_process、evidence_judgment、relationship_scope、counterevidence_limits 在复杂 case 中通常至少 3 个 paragraph_groups。
- paragraph_claim / write_focus 必须具体；不要只写“事件时间线事实”“主支撑事件”“行动建议”或“该事实需要结合其他证据使用”。
- relationship_scope 必须把已确认对象、候选对象、核心外部基础设施分组；如果有 candidate event fact，也必须单独承接，不能只放在 report_plan.source_ids。
- counterevidence_limits 必须把 gap、背景/替代解释、候选未验证边界分开；不要用两个重复的“背景事件提供替代解释”段落。
- 同一 fact 跨章节复用时，paragraph_role 或 paragraph_claim 必须体现不同论证目的，避免 timeline/evidence/scope/limits 复述同一种用法。

允许的动作：
1. 继续取材：
{"action":"tool","tool_calls":[{"tool_name":"get_timeline","params":{"mode":"core"}}],"reason":"..."}

2. 提交材料或 patch：
{"action":"submit","materials":{"schema_version":"report-writer-materials-v2","source_inventory":[],"section_briefs":[{"section_type":"relationship_scope","source_ids":["object:..."],"paragraph_groups":[{"group_id":"relationship_scope-g1","paragraph_role":"已确认范围","paragraph_claim":"本段说明哪些对象能进入确认范围，哪些不能并入。","fact_ids":["fact-object-..."],"source_ids":["object:..."],"write_focus":"说明确认/候选/外部基础设施边界。","contrast_or_boundary":"不要重复 timeline_process 的事件推进。","must_not_repeat":"不要把候选对象写成已确认受影响资产。"}]}]}}
"""


def _build_round_user_prompt(
    *,
    round_index: int,
    max_rounds: int,
    bundle: Dict[str, Any],
    tool_results: List[Dict[str, Any]],
    draft_materials: Dict[str, Any],
    feedback: List[Any],
    force_submit: bool = False,
) -> str:
    has_draft = bool(draft_materials)
    tool_catalog_payload: Any = [
        {
            "note": "draft materials 已存在；除非 validation feedback 明确要求新 source，否则不要调用工具。"
        }
    ] if has_draft else _tool_catalog()
    tool_results_payload: Any = [
        {
            "note": "draft materials 已经包含本轮可用的 source-bound routes。为降低上下文压力，这里不重复展开预加载工具结果；如需判断复杂度，请使用下面的 source-derived complexity hints 和 draft section_briefs。",
            "preloaded_tool_names": _dedupe_texts([_text(item.get("tool_name")) for item in tool_results if isinstance(item, dict)]),
        }
    ] if has_draft else _compact_tool_results_for_prompt(tool_results)
    source_catalog_payload: Any = [
        {
            "note": "source_fact_catalog 已由系统注入 draft/base materials；patch 时优先复用 draft 中已有 fact_ids/source_ids。若确需新增事实，可只引用 source_id，系统会回填 fact_id。"
        }
    ] if has_draft else _compact_source_fact_catalog_for_prompt(bundle)
    if has_draft and _feedback_requests_paragraph_groups(feedback):
        plan_section_types = [
            _text(section.get("section_type"))
            for section in _list(_dict(draft_materials.get("report_plan")).get("sections"))
            if isinstance(section, dict) and _text(section.get("section_type"))
        ]
        required_patch_sections = [
            section_type
            for section_type in plan_section_types
            if section_type in AGENT_PARAGRAPH_GROUP_SECTION_TYPES
        ] or plan_section_types[:3]
        compact_routes = [
            row
            for row in _compact_section_routes_for_patch_prompt(
                _list(draft_materials.get("section_briefs")),
                _list(draft_materials.get("source_fact_catalog")),
            )
            if _text(row.get("section_type")) in required_patch_sections
        ]
        route_context = {
            "report_plan": _compact_report_plan_for_prompt(_dict(draft_materials.get("report_plan"))),
            "patch_required_section_types": required_patch_sections,
            "section_routes": compact_routes,
            "complexity_hints": _complexity_hints_from_tool_results(tool_results),
            "material_counts": {
                "narrative_spine": len(_list(draft_materials.get("narrative_spine"))),
                "evidence_argument_map": len(_list(draft_materials.get("evidence_argument_map"))),
                "scope_role_matrix": len(_list(draft_materials.get("scope_role_matrix"))),
                "counterarguments_and_boundaries": len(_list(draft_materials.get("counterarguments_and_boundaries"))),
                "action_rationale": len(_list(draft_materials.get("action_rationale"))),
            },
        }
        return (
            f"当前是 report material loop 第 {round_index}/{max_rounds} 轮。\n"
            f"force_submit={str(force_submit).lower()}。本轮优先尝试提交 paragraph_groups route patch。\n\n"
            "本轮不要调用工具，不要重吐完整 materials，不要输出 source_fact_catalog、reader_fact_text 或 exact_fact_text。\n"
            "只提交需要合并到 draft 的 materials patch，优先只包含 section_briefs；系统会保留 draft 中其他字段和未提交的简单章节。\n\n"
            "你只需要提交 patch_required_section_types 中列出的复杂章节；简单章节会沿用 deterministic conservative groups。\n"
            "如果无法比 deterministic route 更稳定地补强 paragraph_groups，可以提交 {\"action\":\"submit\",\"materials\":{}} 接受当前 draft。\n"
            "每个提交的 section_briefs 条目至少包含 section_type、source_ids、paragraph_groups；key_facts 可省略，系统会沿用 draft。\n"
            "每个 paragraph_group 必须包含 group_id、paragraph_role、paragraph_claim、fact_ids/source_ids、write_focus、contrast_or_boundary、must_not_repeat。\n"
            "复杂章节建议 3 到 5 组；每组优先引用 2 到 4 个 fact_id。\n"
            "paragraph_claim/write_focus 不能是可直接复制到正文的泛句；禁止“这些事实/这些节点/这些对象/这些建议/本节为什么需要展开”。\n"
            "paragraph_claim/write_focus 每项最多约 40 个中文字符；不要复制 fact_hints 中的时间、IP、域名、资产串，事实细节只保留在 fact_ids/source_ids。\n"
            "同一章节内禁止重复 paragraph_claim；重复主题要拆成不同论证目的。\n"
            "同一 fact 跨章节复用时，paragraph_role 或 paragraph_claim 必须体现不同论证目的。\n\n"
            "可用 route context（只能复制其中已有 fact_ids/source_ids，不要改写为新事实）：\n"
            f"{_json(route_context)}\n\n"
            "本轮必须修复的问题：\n"
            f"{_json(feedback)}\n\n"
            "输出格式示例：\n"
            "{\n"
            '  "action": "submit",\n'
            '  "materials": {\n'
            '    "section_briefs": [\n'
            '      {"section_type": "timeline_process", "source_ids": ["event:..."], "paragraph_groups": [{"group_id": "timeline_process-g1", "paragraph_role": "...", "paragraph_claim": "...", "fact_ids": ["fact-event-..."], "source_ids": ["event:..."], "write_focus": "...", "contrast_or_boundary": "...", "must_not_repeat": "..."}]}\n'
            "    ]\n"
            "  }\n"
            "}\n"
            "请只输出一个 JSON object。"
        )
    return (
        f"当前是 report material loop 第 {round_index}/{max_rounds} 轮。\n"
        f"force_submit={str(force_submit).lower()}。如果 force_submit=true，你必须提交 materials，不要再调用工具。\n\n"
        "可用工具：\n"
        f"{_json(tool_catalog_payload)}\n\n"
        "已收集工具结果（压缩索引；完整事实请引用 deterministic source_fact_catalog，不要要求这里重复精确事实）：\n"
        f"{_json(tool_results_payload)}\n\n"
        "source-derived complexity hints（只用于规划章节和材料密度，不代表新增事实）：\n"
        f"{_json(_complexity_hints_from_tool_results(tool_results))}\n\n"
        "deterministic source_fact_catalog（无损事实目录；你只能引用其中已有 fact_id/source_id，不能改写 summary_line 为新事实）：\n"
        f"{_json(source_catalog_payload)}\n\n"
        "取材建议：预加载结果已经包含 overview、scope、gaps、时间线、claim 索引和 recommendation 索引。"
        "如果这些结果已经足以形成材料，应直接 submit；只有缺少 exact_fact_text、source id，或继续取材会改变结论/范围/章节边界时才调用工具。"
        "如果继续取材只会改善润色或增加非关键细节，应 submit。\n\n"
        "当前 draft materials：\n"
        f"{_json(draft_materials)}\n\n"
        "Patch submit mode：如果 draft materials 非空，你的 submit.materials 可以只包含需要修订的字段；系统会保留 draft 中未覆盖的 case_thesis、narrative_spine、evidence_argument_map、scope_role_matrix、action_rationale 和 source_fact_catalog。"
        "优先只修 report_plan、section_briefs.paragraph_groups 和真实 reportable_limits，避免重吐整份 materials。"
        "如果本轮反馈要求补 paragraph_groups，不能输出空 materials；必须提交包含每节 paragraph_groups 的 route patch。\n\n"
        "本轮必须修复的问题（优先级高于继续取材；如果包含 message_for_agent，请逐条照做）：\n"
        f"{_json(feedback)}\n\n"
        "如果本轮必须修复的问题为空，按当前材料质量自主决定 submit 或取材；如果问题只要求补齐 materials 结构或 section_briefs，"
        "不要调用工具，直接基于已有工具结果修复后 submit。\n\n"
        "请输出一个 JSON object。"
    )


def _agent_feedback_from_validation(validation: Dict[str, Any]) -> List[Dict[str, Any]]:
    feedback = _list(validation.get("agent_feedback"))
    if feedback:
        return [item for item in feedback if isinstance(item, dict)]
    return [
        {
            "code": "validation_failed",
            "severity": "blocking",
            "message_for_agent": "materials 未通过结构校验。下一轮请优先修复 draft materials 中的 schema、source_ids、exact_fact_text 或核心覆盖问题；除非确实缺 source，否则不要调用工具。",
            "suggested_next_action": "submit_repaired_materials",
        }
    ]


def _compact_report_plan_for_prompt(report_plan: Dict[str, Any]) -> Dict[str, Any]:
    plan = _dict(report_plan)
    sections: List[Dict[str, Any]] = []
    for raw_section in _list(plan.get("sections")):
        section = _dict(raw_section)
        section_type = _text(section.get("section_type"))
        if not section_type:
            continue
        sections.append(
            {
                "section_type": section_type,
                "secondary_section_types": _list(section.get("secondary_section_types"))[:3],
                "title": _text(section.get("title")),
                "source_ids": _list(section.get("source_ids"))[:6],
                "boundary_notes": _list(section.get("boundary_notes"))[:2],
            }
        )
    return {
        "schema_version": _text(plan.get("schema_version")),
        "title": _text(plan.get("title")),
        "planning_rationale": _text(plan.get("planning_rationale"))[:500],
        "sections": sections,
    }


def _compact_section_briefs_for_prompt(
    section_briefs: List[Any],
    *,
    key_fact_limit: int = 4,
    paragraph_group_limit: int = 4,
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for raw_brief in section_briefs:
        brief = _dict(raw_brief)
        section_type = _text(brief.get("section_type"))
        if not section_type:
            continue
        key_facts: List[Dict[str, Any]] = []
        for raw_fact in _list(brief.get("key_facts"))[:key_fact_limit]:
            fact = _dict(raw_fact)
            key_facts.append(
                {
                    "fact_ids": _list(fact.get("fact_ids"))[:4] or ([_text(fact.get("fact_id"))] if _text(fact.get("fact_id")) else []),
                    "source_ids": _list(fact.get("source_ids"))[:4],
                    "fact_role": _text(fact.get("fact_role")),
                    "use_for": _text(fact.get("use_for"))[:120],
                    "why_it_matters": _text(fact.get("why_it_matters"))[:120],
                    "limitation": _text(fact.get("limitation"))[:120],
                }
            )
        paragraph_groups: List[Dict[str, Any]] = []
        for raw_group in _list(brief.get("paragraph_groups"))[:paragraph_group_limit]:
            group = _dict(raw_group)
            paragraph_groups.append(
                {
                    "group_id": _text(group.get("group_id")),
                    "paragraph_role": _text(group.get("paragraph_role"))[:80],
                    "paragraph_claim": _text(group.get("paragraph_claim"))[:160],
                    "fact_ids": _list(group.get("fact_ids"))[:6],
                    "source_ids": _list(group.get("source_ids"))[:6],
                    "write_focus": _text(group.get("write_focus"))[:120],
                    "contrast_or_boundary": _text(group.get("contrast_or_boundary"))[:160],
                    "must_not_repeat": _text(group.get("must_not_repeat"))[:120],
                }
            )
        rows.append(
            {
                "section_type": section_type,
                "source_ids": _list(brief.get("source_ids"))[:6],
                "key_fact_count": len(_list(brief.get("key_facts"))),
                "paragraph_group_count": len(_list(brief.get("paragraph_groups"))),
                "key_facts": key_facts,
                "paragraph_groups": paragraph_groups,
            }
        )
    return rows


def _compact_fact_hint(fact: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "fact_id": _text(fact.get("fact_id")),
        "source_id": _text(fact.get("source_id")),
        "fact_type": _text(fact.get("fact_type")),
        "status": _text(fact.get("status")),
        "time": _text(fact.get("time")),
        "asset": _text(fact.get("asset")),
        "objects": _list(fact.get("objects"))[:4],
        "reporting_focus": _text(fact.get("reporting_focus")),
        "boundary_note": _text(fact.get("boundary_note"))[:120],
        "candidate_or_boundary": bool(fact.get("candidate_or_boundary")),
    }


def _compact_section_routes_for_patch_prompt(
    section_briefs: List[Any],
    source_fact_catalog: List[Any] | None = None,
) -> List[Dict[str, Any]]:
    fact_by_id, fact_by_source_id = source_fact_indexes([_dict(item) for item in _list(source_fact_catalog)])

    def fact_hints_for(item: Dict[str, Any]) -> List[Dict[str, Any]]:
        hints: List[Dict[str, Any]] = []
        for fact_id in _list(item.get("fact_ids")) + ([_text(item.get("fact_id"))] if _text(item.get("fact_id")) else []):
            fact = _dict(fact_by_id.get(_text(fact_id)))
            if fact:
                hints.append(_compact_fact_hint(fact))
        for source_id in _source_ids_from_item(item):
            fact = _dict(fact_by_source_id.get(_text(source_id)))
            if fact:
                hints.append(_compact_fact_hint(fact))
        seen: set[str] = set()
        deduped: List[Dict[str, Any]] = []
        for hint in hints:
            key = _text(hint.get("fact_id")) or _text(hint.get("source_id"))
            if not key or key in seen:
                continue
            seen.add(key)
            deduped.append(hint)
        return deduped[:4]

    rows: List[Dict[str, Any]] = []
    for raw_brief in section_briefs:
        brief = _dict(raw_brief)
        section_type = _text(brief.get("section_type"))
        if not section_type:
            continue
        key_facts: List[Dict[str, Any]] = []
        for raw_fact in _list(brief.get("key_facts"))[:12]:
            fact = _dict(raw_fact)
            key_facts.append(
                {
                    "fact_ids": _list(fact.get("fact_ids"))[:4] or ([_text(fact.get("fact_id"))] if _text(fact.get("fact_id")) else []),
                    "source_ids": _list(fact.get("source_ids"))[:4],
                    "fact_role": _text(fact.get("fact_role")),
                    "fact_hints": fact_hints_for(fact),
                }
            )
        paragraph_groups: List[Dict[str, Any]] = []
        for raw_group in _list(brief.get("paragraph_groups"))[:6]:
            group = _dict(raw_group)
            paragraph_groups.append(
                {
                    "group_id": _text(group.get("group_id")),
                    "paragraph_role": _text(group.get("paragraph_role"))[:60],
                    "paragraph_claim": _text(group.get("paragraph_claim"))[:120],
                    "fact_ids": _list(group.get("fact_ids"))[:6],
                    "source_ids": _list(group.get("source_ids"))[:6],
                    "fact_hints": fact_hints_for(group),
                }
            )
        rows.append(
            {
                "section_type": section_type,
                "source_ids": _list(brief.get("source_ids"))[:6],
                "key_facts": key_facts,
                "paragraph_groups": paragraph_groups,
            }
        )
    return rows


def _compact_tool_results_for_prompt(tool_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for raw in tool_results:
        item = _dict(raw)
        tool_name = _text(item.get("tool_name"))
        result = _dict(item.get("result"))
        compact_result: Dict[str, Any] = {}
        if tool_name == "get_case_overview":
            header = _dict(result.get("case_header"))
            compact_result = {
                "case_header": {
                    "title": _text(header.get("title")),
                    "delivery_status_label": _text(header.get("delivery_status_label")),
                    "severity_normalized": _text(header.get("severity_normalized") or header.get("severity")),
                    "confidence_normalized": _text(header.get("confidence_normalized") or header.get("confidence")),
                    "final_verdict_summary": _dict(header.get("final_verdict_summary")),
                },
                "confirmed_scope": _list(result.get("confirmed_scope")),
                "candidate_scope": _list(result.get("candidate_scope")),
                "external_infrastructure": _list(result.get("external_infrastructure")),
                "source_counts": _dict(result.get("source_counts")),
            }
        elif tool_name == "get_scope_roles":
            compact_result = {
                "scope": _dict(result.get("scope")),
                "objects": [
                    {
                        "source_id": _text(row.get("source_id")),
                        "object": _text(row.get("object")),
                        "object_type": _text(row.get("object_type")),
                        "investigation_role": _text(row.get("investigation_role")),
                        "report_scope_role": _text(row.get("report_scope_role")),
                        "may_be_written_as_affected": bool(row.get("may_be_written_as_affected")),
                    }
                    for row in [_dict(value) for value in _list(result.get("objects"))]
                ][:20],
            }
        elif tool_name == "get_gaps_and_boundaries":
            compact_result = {
                "gaps": [
                    {
                        "source_id": _text(row.get("source_id")),
                        "question": _text(row.get("question"))[:180],
                        "status": _text(row.get("status")),
                        "delivery_blocking": bool(row.get("delivery_blocking")),
                        "actionable_now": bool(row.get("actionable_now")),
                    }
                    for row in [_dict(value) for value in _list(result.get("gaps"))]
                ][:12],
                "counterevidence_count": len(_list(result.get("counterevidence"))),
            }
        elif tool_name == "get_timeline":
            compact_result = {
                "mode": _text(result.get("mode")),
                "events": [
                    {
                        "source_id": _text(row.get("source_id")),
                        "time": _text(row.get("time")),
                        "status": _text(row.get("status")),
                        "classification": _text(row.get("classification")),
                        "asset": _text(row.get("asset")),
                    }
                    for row in [_dict(value) for value in _list(result.get("events"))]
                ][:30],
            }
        elif tool_name == "list_source_items":
            compact_result = {
                "item_type": _text(result.get("item_type")),
                "status": _text(result.get("status")),
                "items": [
                    {
                        "source_id": _text(row.get("source_id")),
                        "status": _text(row.get("status")),
                        "time": _text(row.get("time")),
                        "object": _text(row.get("object")),
                        "summary": _text(row.get("summary"))[:180],
                    }
                    for row in [_dict(value) for value in _list(result.get("items"))]
                ][:12],
            }
        else:
            compact_result = result
        rows.append(
            {
                "round": item.get("round"),
                "tool_name": tool_name,
                "params": _dict(item.get("params")),
                "result": compact_result,
            }
        )
    return rows


def _compact_draft_materials_for_prompt(materials: Dict[str, Any]) -> Dict[str, Any]:
    if not materials:
        return {}
    compact: Dict[str, Any] = {
        "schema_version": _text(materials.get("schema_version")),
        "case_thesis": _dict(materials.get("case_thesis")),
        "report_plan": _compact_report_plan_for_prompt(_dict(materials.get("report_plan"))),
        "section_briefs": _compact_section_briefs_for_prompt(_list(materials.get("section_briefs"))),
        "reportable_limits": _list(materials.get("reportable_limits")),
        "material_counts": {
            "narrative_spine": len(_list(materials.get("narrative_spine"))),
            "evidence_argument_map": len(_list(materials.get("evidence_argument_map"))),
            "scope_role_matrix": len(_list(materials.get("scope_role_matrix"))),
            "counterarguments_and_boundaries": len(_list(materials.get("counterarguments_and_boundaries"))),
            "action_rationale": len(_list(materials.get("action_rationale"))),
            "section_briefs": len(_list(materials.get("section_briefs"))),
            "source_inventory": len(_list(materials.get("source_inventory"))),
        },
    }
    return {key: value for key, value in compact.items() if value not in ["", {}, []]}


def _invoke_report_agent_json(llm: Any, messages: Any, *, role: str) -> Dict[str, Any]:
    response = invoke_llm_with_trace(llm, messages, role=role)
    return _parse_json_object(str(getattr(response, "content", "") or ""))


def _bind_report_agent_llm(llm: Any, *, json_mode: bool = True) -> Any:
    if not hasattr(llm, "bind"):
        return llm
    # The agent now submits route patches instead of fact prose. Keeping the
    # cap moderate prevents JSON-mode calls from trying to emit a full copy of
    # the deterministic materials.
    bind_kwargs: Dict[str, Any] = {"max_tokens": 4200, "temperature": 0}
    # Some compatible OpenAI-style backends become extremely slow when
    # response_format=json_object is combined with a large patch prompt. The
    # loop already parses and validates JSON itself, so keep provider JSON mode
    # off and enforce the contract in prompt + validator instead.
    try:
        return llm.bind(**bind_kwargs)
    except TypeError:
        bind_kwargs.pop("response_format", None)
        return llm.bind(**bind_kwargs)


def _looks_like_json_mode_unsupported(exc: Exception) -> bool:
    text = f"{type(exc).__name__}: {exc}".lower()
    return "response_format" in text or "json_object" in text or "json mode" in text


def _looks_like_length_limit(exc: Exception) -> bool:
    text = f"{type(exc).__name__}: {exc}".lower()
    return "length limit" in text or "max_tokens" in text or "finish_reason" in text or "completion_tokens" in text


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


def _dedupe_texts(values: List[Any]) -> List[str]:
    seen: set[str] = set()
    out: List[str] = []
    for value in values:
        text = _text(value)
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def _complexity_hints_from_tool_results(tool_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    hints: Dict[str, Any] = {
        "confirmed_scope_count": 0,
        "candidate_scope_count": 0,
        "external_infrastructure_count": 0,
        "confirmed_event_count": 0,
        "candidate_event_count": 0,
        "background_event_count": 0,
        "candidate_claim_count": 0,
        "open_gap_count": 0,
        "recommendation_count": 0,
        "relationship_source_ids": [],
        "gap_source_ids": [],
        "action_source_ids": [],
        "suggested_attention": [],
    }
    relationship_source_ids: List[str] = []
    gap_source_ids: List[str] = []
    action_source_ids: List[str] = []
    suggested_attention: List[str] = []
    for item in tool_results:
        tool_name = _text(item.get("tool_name"))
        params = _dict(item.get("params"))
        result = _dict(item.get("result"))
        if tool_name == "get_case_overview":
            hints["confirmed_scope_count"] = len(_list(result.get("confirmed_scope")))
            hints["candidate_scope_count"] = len(_list(result.get("candidate_scope")))
            hints["external_infrastructure_count"] = len(_list(result.get("external_infrastructure")))
        elif tool_name == "get_scope_roles":
            for row in _list(result.get("objects")):
                if not isinstance(row, dict):
                    continue
                role = _text(row.get("report_scope_role"))
                source_id = _text(row.get("source_id"))
                if source_id and (role == "external_infrastructure" or "candidate" in role):
                    relationship_source_ids.append(source_id)
        elif tool_name == "get_timeline":
            for row in _list(result.get("events")):
                if not isinstance(row, dict):
                    continue
                status = _text(row.get("status"))
                source_id = _text(row.get("source_id"))
                if status == "confirmed":
                    hints["confirmed_event_count"] = int(hints["confirmed_event_count"]) + 1
                elif status == "candidate":
                    hints["candidate_event_count"] = int(hints["candidate_event_count"]) + 1
                    if source_id:
                        relationship_source_ids.append(source_id)
                elif status == "background":
                    hints["background_event_count"] = int(hints["background_event_count"]) + 1
        elif tool_name == "get_gaps_and_boundaries":
            for row in _list(result.get("gaps")):
                if not isinstance(row, dict):
                    continue
                status = _text(row.get("status"))
                source_id = _text(row.get("source_id"))
                if status != "closed":
                    hints["open_gap_count"] = int(hints["open_gap_count"]) + 1
                    if source_id:
                        gap_source_ids.append(source_id)
        elif tool_name == "list_source_items" and _text(params.get("item_type")) == "claim":
            for row in _list(result.get("items")):
                if not isinstance(row, dict):
                    continue
                status = _text(row.get("status"))
                source_id = _text(row.get("source_id"))
                if status == "candidate":
                    hints["candidate_claim_count"] = int(hints["candidate_claim_count"]) + 1
                    if source_id:
                        relationship_source_ids.append(source_id)
        elif tool_name == "list_source_items" and _text(params.get("item_type")) == "recommendation":
            for row in _list(result.get("items")):
                if not isinstance(row, dict):
                    continue
                source_id = _text(row.get("source_id"))
                if source_id:
                    action_source_ids.append(source_id)
            hints["recommendation_count"] = len(action_source_ids)

    if int(hints["candidate_scope_count"]) or int(hints["candidate_event_count"]) or int(hints["candidate_claim_count"]):
        suggested_attention.append("存在候选范围、候选事件或候选 claim：report_plan 需要承接 relationship_scope 或在相邻章节明确合并该职责。")
    if int(hints["external_infrastructure_count"]):
        suggested_attention.append("存在核心外部基础设施：relationship_scope 应说明它与已确认资产、候选对象的边界关系。")
    if int(hints["confirmed_scope_count"]) >= 2 or int(hints["candidate_event_count"]) or int(hints["confirmed_event_count"]) >= 4:
        suggested_attention.append("存在多资产或时序推进：timeline_process 和 evidence_judgment 的 section_briefs 不应过薄。")
    if int(hints["open_gap_count"]) or int(hints["background_event_count"]):
        suggested_attention.append("存在未闭合 gap 或背景事件：counterevidence_limits 应说明这些材料限制了哪些更强结论。")
    if int(hints["recommendation_count"]):
        suggested_attention.append("存在 recommendation/action source：conclusion_actions 或 action_rationale 应引用并解释行动理由。")

    hints["relationship_source_ids"] = _dedupe_texts(relationship_source_ids)[:12]
    hints["gap_source_ids"] = _dedupe_texts(gap_source_ids)[:12]
    hints["action_source_ids"] = _dedupe_texts(action_source_ids)[:12]
    hints["suggested_attention"] = _dedupe_texts(suggested_attention)
    hints["is_complex"] = bool(hints["suggested_attention"])
    return hints


def _compact_source_fact_catalog_for_prompt(bundle: Dict[str, Any], *, limit: int = 80) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for fact in build_source_fact_catalog(bundle)[:limit]:
        rows.append(
            {
                "fact_id": _text(fact.get("fact_id")),
                "source_id": _text(fact.get("source_id")),
                "fact_type": _text(fact.get("fact_type")),
                "status": _text(fact.get("status")),
                "time": _text(fact.get("time")),
                "asset": _text(fact.get("asset")),
                "objects": _list(fact.get("objects"))[:2],
                "reporting_focus": _text(fact.get("reporting_focus")),
                "boundary_note": _text(fact.get("boundary_note")),
                "candidate_or_boundary": bool(fact.get("candidate_or_boundary")),
                "summary_line": _text(fact.get("summary_line"))[:96],
            }
        )
    return rows


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


def _sort_event_source_ids_by_time(index: Dict[str, Dict[str, Any]], source_ids: List[str], *, limit: int = 20) -> List[str]:
    rows: List[Tuple[str, str]] = []
    for source_id in _dedupe_texts(source_ids):
        item = _dict(index.get(source_id))
        if not item or (not source_id.startswith("event:") and _text(item.get("source_type")) != "event"):
            continue
        rows.append((_text(item.get("time") or item.get("ts") or item.get("event_time") or item.get("timestamp")), source_id))
    rows.sort(key=lambda row: (row[0] or "9999", row[1]))
    return [source_id for _, source_id in rows[:limit]]


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
    def ids_where(namespace: str, predicate: Any, *, limit: int = 8) -> List[str]:
        prefix = f"{namespace}:"
        out: List[str] = []
        for source_id, item in index.items():
            if not source_id.startswith(prefix):
                continue
            if predicate(_dict(item)):
                out.append(source_id)
                if len(out) >= limit:
                    break
        return out

    verdict_ids = _first_existing_source_ids(index, ["verdict:delivery"], limit=1)
    event_ids = _first_existing_source_ids(
        index,
        _material_source_ids_by_namespace(materials, "event", limit=6),
        _available_source_ids(index, "event", limit=6),
        limit=6,
    )
    confirmed_event_ids = ids_where("event", lambda item: _text(item.get("status")) == "confirmed", limit=8)
    candidate_event_ids = ids_where("event", lambda item: _text(item.get("status")) == "candidate", limit=6)
    background_event_ids = ids_where("event", lambda item: _text(item.get("status")) == "background", limit=6)
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
    external_object_ids = ids_where("object", lambda item: _text(item.get("report_scope_role")) == "external_infrastructure", limit=6)
    candidate_object_ids = ids_where("object", lambda item: "candidate" in _text(item.get("report_scope_role")), limit=6)
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
            "scope_hypothesis",
            _first_existing_source_ids(index, object_ids, verdict_ids, limit=6),
            secondary_section_types=["entity_roles"],
            must_include=["调查锚点", "已确认受影响对象", "待确认对象或核心外部基础设施"],
            must_not_repeat=["不要评价证据强度或重复时间线"],
        ),
    ]
    if confirmed_event_ids:
        sections.append(
            _plan_section(
                "timeline_process",
                _sort_event_source_ids_by_time(
                    index,
                    _first_existing_source_ids(
                        index,
                        confirmed_event_ids,
                        candidate_event_ids,
                        background_event_ids,
                        limit=20,
                    ),
                    limit=14,
                ),
                must_include=["按时间说明关键节点如何推进", "保留候选和背景事件边界"],
                must_not_repeat=["不要在本节评价证据强度；证据判断留给下一节"],
            )
        )
    sections.append(
        _plan_section(
            "evidence_judgment",
            _first_existing_source_ids(index, confirmed_event_ids, claim_ids, verdict_ids, limit=8),
            must_include=["关键事实", "为什么改变判断", "证据边界"],
            must_not_repeat=["不要写成完整流水账；结论边界留给缺口章节"],
        )
    )
    relationship_ids = _first_existing_source_ids(
        index,
        candidate_object_ids,
        external_object_ids,
        candidate_event_ids,
        object_ids,
        claim_ids,
        gap_ids,
        limit=10,
    )
    if relationship_ids:
        sections.append(
            _plan_section(
                "relationship_scope",
                relationship_ids,
                must_include=["已确认对象", "候选对象", "核心外部基础设施", "不能并入已确认范围的边界"],
                must_not_repeat=["不要重复事件过程；只解释对象关系和范围边界"],
            )
        )
    if gap_ids:
        sections.append(
            _plan_section(
                "counterevidence_limits",
                _first_existing_source_ids(index, gap_ids, background_event_ids, candidate_event_ids, verdict_ids, limit=10),
                must_include=["当前最关键缺口", "背景或替代解释", "缺口限制的更强结论", "当前判断上限"],
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
                "must_include": [
                    _text(item)
                    for item in _list(raw_section.get("must_include"))
                    if _text(item) and not _is_placeholder_text(item)
                ][:4],
                "must_not_repeat": [
                    _text(item)
                    for item in _list(raw_section.get("must_not_repeat"))
                    if _text(item) and not _is_placeholder_text(item)
                ][:4],
                "source_ids": source_ids,
                "boundary_notes": [
                    _text(item)
                    for item in _list(raw_section.get("boundary_notes"))
                    if _text(item) and not _is_placeholder_text(item)
                ][:4],
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
    source_fact_catalog = build_source_fact_catalog(bundle or {}) if bundle else []
    reportable_limits = [
        _text(item.get("exact_fact_text") or item.get("status_reason") or item.get("question"))
        for item in gaps
        if _text(item.get("exact_fact_text") or item.get("status_reason") or item.get("question"))
    ][:4]
    if not reportable_limits and candidates:
        reportable_limits = ["候选范围尚未独立验证，不能直接并入已确认受影响范围。"]
    why_this_judgment_holds = _source_derived_verdict_text(header)
    why_not_stronger_or_broader = _fallback_scope_boundary_text(candidates, gaps)
    materials = {
        "schema_version": "report-writer-materials-v2",
        "source_inventory": [],
        "source_fact_catalog": source_fact_catalog,
        "case_thesis": {
            "conclusion": _text(header.get("delivery_status_label") or header.get("delivery_status")),
            "severity": _text(header.get("severity_normalized") or header.get("severity")),
            "confidence": _text(header.get("confidence_normalized") or header.get("confidence")),
            "confirmed_scope": confirmed,
            "candidate_scope": candidates,
            "why_this_judgment_holds": why_this_judgment_holds,
            "why_not_stronger_or_broader": why_not_stronger_or_broader,
            "source_ids": ["verdict:delivery"],
            "exact_fact_text": why_this_judgment_holds
            or _text(header.get("delivery_status_label") or header.get("delivery_status")),
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
                "claim": _fallback_event_claim(item),
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
        "reportable_limits": reportable_limits,
    }
    if bundle:
        materials["report_plan"] = _fallback_report_plan(materials, bundle, title=_text(header.get("title")))
        materials["section_briefs"] = _section_briefs_from_plan(materials, bundle)
        _materialize_section_fact_routes(materials, source_fact_catalog)
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


def _drop_unknown_source_ids(value: Any, index: Dict[str, Dict[str, Any]]) -> Any:
    if isinstance(value, list):
        return [_drop_unknown_source_ids(item, index) for item in value]
    if not isinstance(value, dict):
        return value
    cleaned: Dict[str, Any] = {}
    for key, item in value.items():
        if key == "source_ids":
            cleaned[key] = [source_id for source_id in _source_ids_from_item({"source_ids": item}) if source_id in index]
            continue
        if key == "source_id":
            source_id = _text(item)
            if source_id in index:
                cleaned[key] = source_id
            continue
        cleaned[key] = _drop_unknown_source_ids(item, index)
    return cleaned


def _source_ids_from_item(item: Dict[str, Any]) -> List[str]:
    source_ids = _list(item.get("source_ids"))
    source_id = _text(item.get("source_id"))
    if source_id:
        source_ids.append(source_id)
    return [_text(source_id).replace(" ", "") for source_id in source_ids if _text(source_id)]


def _fact_ids_from_item(item: Dict[str, Any]) -> List[str]:
    fact_ids = _list(item.get("fact_ids"))
    fact_id = _text(item.get("fact_id"))
    if fact_id:
        fact_ids.append(fact_id)
    return [_text(fact_id).replace(" ", "") for fact_id in fact_ids if _text(fact_id)]


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


def _route_fact_role(section_type: str, source_fact: Dict[str, Any]) -> str:
    fact_type = _text(source_fact.get("fact_type"))
    focus = _text(source_fact.get("reporting_focus"))
    if section_type == "timeline_process" and fact_type == "event":
        return "事件推进节点"
    if section_type == "evidence_judgment" and fact_type == "event":
        return "判断支撑事件"
    if section_type == "relationship_scope":
        if "外部基础设施" in focus:
            return "核心外部基础设施"
        if "待确认" in focus or "候选" in focus:
            return "候选范围边界"
        if "已确认受影响" in focus:
            return "已确认范围"
    if section_type == "counterevidence_limits":
        if fact_type == "gap":
            return "未闭合缺口"
        if _text(source_fact.get("status")) == "background":
            return "背景或替代解释"
        if bool(source_fact.get("candidate_or_boundary")):
            return "结论边界"
    if section_type == "conclusion_actions" and fact_type == "action":
        return "行动建议"
    return focus or "章节事实"


def _route_use_for(section_type: str) -> str:
    mapping = {
        "investigation_entry": "说明调查起点、初始线索和为什么需要继续研判。",
        "scope_hypothesis": "说明确认范围、候选范围和对象角色边界。",
        "entity_roles": "说明对象角色，避免把候选或外部对象写成已确认受影响。",
        "timeline_process": "按 source_fact_catalog 的时间和对象展开事件推进，不评价证据强度。",
        "evidence_judgment": "解释该原子事实如何支撑当前判断，以及它不能推出什么更强结论。",
        "relationship_scope": "说明已确认对象、候选对象、外部基础设施和扩线边界。",
        "counterevidence_limits": "说明缺口、背景事件或候选事实如何限制更强结论。",
        "conclusion_actions": "说明行动建议如何对应当前证据和边界。",
    }
    return mapping.get(section_type, "使用对应原子事实展开本节，不要写成泛化摘要。")


def _route_key_facts_from_sources(
    source_fact_catalog: List[Dict[str, Any]],
    source_ids: List[str],
    *,
    section_type: str,
    limit: int = 6,
) -> List[Dict[str, Any]]:
    _, fact_by_source_id = source_fact_indexes(source_fact_catalog)
    rows: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for source_id in source_ids:
        normalized_id = _text(source_id)
        if not normalized_id or normalized_id in seen:
            continue
        fact = _dict(fact_by_source_id.get(normalized_id))
        if not fact:
            continue
        seen.add(normalized_id)
        fact_id = _text(fact.get("fact_id"))
        boundary_note = _text(fact.get("boundary_note"))
        rows.append(
            {
                "fact_ids": [fact_id] if fact_id else [],
                "source_ids": [normalized_id],
                "fact_role": _route_fact_role(section_type, fact),
                "why_it_matters": _text(fact.get("reporting_focus")) or "该原子事实用于支撑本节判断或边界。",
                "limitation": boundary_note or "该事实需要结合其他证据使用，不能单独推出更强结论。",
                "use_for": _route_use_for(section_type),
            }
        )
        if len(rows) >= limit:
            break
    return rows


def _fact_refs_from_group_item(
    item: Dict[str, Any],
    fact_by_id: Dict[str, Dict[str, Any]],
    fact_by_source_id: Dict[str, Dict[str, Any]],
) -> Tuple[List[str], List[str], List[Dict[str, Any]]]:
    fact_ids = _fact_ids_from_item(item)
    source_ids = _source_ids_from_item(item)
    for fact_id in list(fact_ids):
        source_id = _text(_dict(fact_by_id.get(_text(fact_id))).get("source_id"))
        if source_id and source_id not in source_ids:
            source_ids.append(source_id)
    for source_id in list(source_ids):
        fact_id = _text(_dict(fact_by_source_id.get(_text(source_id))).get("fact_id"))
        if fact_id and fact_id not in fact_ids:
            fact_ids.append(fact_id)
    fact_ids = [fact_id for fact_id in _dedupe_texts(fact_ids) if fact_id in fact_by_id]
    source_ids = [source_id for source_id in _dedupe_texts(source_ids) if source_id in fact_by_source_id]
    facts = [_dict(fact_by_id.get(fact_id)) for fact_id in fact_ids if _dict(fact_by_id.get(fact_id))]
    return fact_ids, source_ids, facts


HIGH_RISK_ACTIVITY_MARKERS = {
    "rundll32",
    "powershell",
    "cmd.exe",
    "psexec",
    "wmi",
    "remote service",
    "web shell",
    "web-shell",
    "loader",
    "dll",
    "archive",
    "exfil",
    "credential",
    "执行",
    "远程服务",
    "横向",
    "外传",
    "压缩",
    "凭据",
}

NETWORK_ACTIVITY_MARKERS = {
    "tls",
    "dns",
    "http",
    "ja3",
    "ja4",
    "beacon",
    "c2",
    "domain",
    "external",
    "通信",
    "连接",
    "解析",
    "外联",
    "信标",
    "基础设施",
}


def _fact_search_text(fact: Dict[str, Any]) -> str:
    parts = [
        fact.get("summary_line"),
        fact.get("exact_fact_text"),
        fact.get("reporting_focus"),
        fact.get("boundary_note"),
        fact.get("classification"),
        fact.get("status"),
        fact.get("asset"),
    ]
    parts.extend(_list(fact.get("objects")))
    return "；".join(_text(item) for item in parts if _text(item))


def _facts_text(facts: List[Dict[str, Any]]) -> str:
    return "；".join(_fact_search_text(fact) for fact in facts if _fact_search_text(fact))


def _contains_any_marker(text: str, markers: set[str]) -> bool:
    lowered = text.lower()
    return any(marker.lower() in lowered for marker in markers)


def _facts_contain_any_marker(facts: List[Dict[str, Any]], markers: set[str]) -> bool:
    return _contains_any_marker(_facts_text(facts), markers)


def _row_facts(row: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [_dict(fact) for fact in _list(row.get("facts")) if isinstance(fact, dict)]


def _row_has_status(row: Dict[str, Any], status: str) -> bool:
    return any(_text(fact.get("status")) == status for fact in _row_facts(row))


def _row_has_fact_type(row: Dict[str, Any], fact_type: str) -> bool:
    return any(_text(fact.get("fact_type")) == fact_type for fact in _row_facts(row))


def _row_has_marker(row: Dict[str, Any], markers: set[str]) -> bool:
    return _facts_contain_any_marker(_row_facts(row), markers)


def _paragraph_role_for_group(section_type: str, facts: List[Dict[str, Any]], index: int) -> str:
    statuses = {_text(fact.get("status")) for fact in facts}
    fact_types = {_text(fact.get("fact_type")) for fact in facts}
    focus_text = "；".join(_text(fact.get("reporting_focus")) for fact in facts)
    if section_type == "timeline_process":
        if "candidate" in statuses:
            return "候选扩线节点"
        if "background" in statuses:
            return "背景或替代解释节点"
        if _facts_contain_any_marker(facts, HIGH_RISK_ACTIVITY_MARKERS):
            return "执行与跨主机推进"
        if index == 1:
            return "调查起点与初始外联"
        return "持续通信与范围推进"
    if section_type == "evidence_judgment":
        if _facts_contain_any_marker(facts, HIGH_RISK_ACTIVITY_MARKERS):
            return "高风险行为支撑"
        if "claim" in fact_types:
            return "归纳判断支撑"
        if _facts_contain_any_marker(facts, NETWORK_ACTIVITY_MARKERS):
            return "通信连续性支撑"
        return "范围扩大支撑"
    if section_type in {"scope_hypothesis", "relationship_scope"}:
        if any("外部基础设施" in _text(fact.get("boundary_note") or fact.get("reporting_focus")) for fact in facts):
            return "外部基础设施边界"
        if "candidate" in statuses or "待确认" in focus_text or "候选" in focus_text:
            return "候选范围边界"
        if "已确认受影响" in focus_text or "种子资产" in focus_text:
            return "已确认范围"
        return "对象关系说明"
    if section_type == "counterevidence_limits":
        if "gap" in fact_types:
            return "未闭合缺口"
        if "candidate" in statuses:
            return "候选未验证边界"
        if "background" in statuses:
            return "背景或替代解释"
        return "结论上限"
    if section_type == "conclusion_actions":
        if "action" in fact_types:
            return "行动建议"
        return "结论与边界"
    if section_type == "investigation_entry":
        return "调查起点"
    return "章节论证段"


def _fact_anchor(fact: Dict[str, Any]) -> str:
    time = _text(fact.get("time"))
    asset = _text(fact.get("asset"))
    objects = [item for item in _list(fact.get("objects")) if _text(item)][:2]
    focus = _text(fact.get("reporting_focus"))
    parts = [item for item in [time, asset, " / ".join(_text(item) for item in objects), focus] if item]
    return "，".join(parts[:3])


def _group_anchor(facts: List[Dict[str, Any]], *, limit: int = 3) -> str:
    anchors = [_fact_anchor(fact) for fact in facts if _fact_anchor(fact)]
    return "；".join(_dedupe_texts(anchors)[:limit])


def _paragraph_claim_for_group(section_type: str, role: str, facts: List[Dict[str, Any]]) -> str:
    fact_text = "；".join(_text(fact.get("summary_line") or fact.get("exact_fact_text")) for fact in facts)
    anchor = _group_anchor(facts)
    if section_type == "timeline_process":
        if "候选" in role:
            return (f"{anchor} 属于扩线后的待验证阶段，只能作为候选推进线索。" if anchor else "扩线阶段只能写成待验证线索。")
        if "背景" in role:
            return (f"{anchor} 提供维护、更新或共享基础设施背景，用于限定时间线解释。" if anchor else "背景节点用于限定时间线解释。")
        if "执行" in role:
            return (f"{anchor} 把网络外联推进到执行或跨主机动作阶段。" if anchor else "通信后的执行或跨主机动作提高事件级复核价值。")
        return (f"{anchor} 构成种子告警前后的连续外联阶段。" if anchor else "种子告警前后存在连续外联和同基础设施复现。")
    if section_type == "evidence_judgment":
        if "高风险" in role:
            return (f"{anchor} 支撑高风险行为判断，但不能直接推出完全控制或恶意载荷已确认。" if anchor else "执行与远程服务线索提高判断权重，但不等于确认控制。")
        if "通信" in role:
            return (f"{anchor} 支撑通信连续性判断，使单点告警具备事件级复核价值。" if anchor else "重复外联和同基础设施复现使单点告警具备事件级复核价值。")
        if "范围" in role:
            return (f"{anchor} 支撑范围不止种子资产的判断。" if anchor else "第二资产上的复现支撑范围不止种子资产。")
        return (f"{anchor} 只能作为归纳观察辅助解释证据链。" if anchor else "归纳判断只能辅助解释证据链，不能替代关键事件事实。")
    if section_type in {"scope_hypothesis", "relationship_scope"}:
        if "已确认" in role:
            return (f"{anchor} 可作为确认范围或主链锚点说明。" if anchor else "已确认对象可写入确认范围或主链锚点。")
        if "候选" in role:
            return (f"{anchor} 只能进入候选范围，不能并入已确认受影响资产。" if anchor else "候选对象或事件不能并入已确认受影响资产。")
        if "外部" in role:
            return (f"{anchor} 是外联和封禁排查对象，不是内部受影响资产。" if anchor else "外部基础设施不是内部受影响资产。")
        return (f"{anchor} 用于说明调查锚点、候选范围和外联基础设施之间的关系。" if anchor else "对象关系用于区分调查锚点、候选范围和外联基础设施。")
    if section_type == "counterevidence_limits":
        if "缺口" in role:
            return (f"{anchor} 限制更强结论和更宽范围写法。" if anchor else "未闭合问题限制更强结论和更宽范围写法。")
        if "候选" in role:
            return (f"{anchor} 尚未独立验证，只能解释为何范围需要保守。" if anchor else "候选事实尚未独立验证，只能解释为何范围需要保守。")
        if "背景" in role:
            return (f"{anchor} 提供替代解释或共享基础设施边界，但不能单独推翻主链。" if anchor else "背景事件提供替代解释或共享基础设施边界，但不能单独推翻主链。")
        return "当前报告应维持复核结论，而不是写成完全确认或完全排除。"
    if section_type == "conclusion_actions":
        if "行动" in role:
            return (f"{anchor} 对应后续核查和处置动作。" if anchor else "建议动作应按当前证据边界保守执行。")
        return "当前结论应保守表达为需要继续复核。"
    if section_type == "investigation_entry" and anchor:
        return f"{anchor} 构成本次调查的入口线索。"
    if fact_text:
        return f"{anchor or role} 用于回答本节核心问题。"
    return "本段用于回答该章节的核心问题。"


def _group_fact_rows(
    key_facts: List[Dict[str, Any]],
    fact_by_id: Dict[str, Dict[str, Any]],
    fact_by_source_id: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for raw_fact in key_facts:
        fact = _dict(raw_fact)
        fact_ids, source_ids, facts = _fact_refs_from_group_item(fact, fact_by_id, fact_by_source_id)
        if not fact_ids and not source_ids:
            continue
        rows.append({"fact_ids": fact_ids, "source_ids": source_ids, "facts": facts, "raw": fact})
    return rows


def _chunk_rows(rows: List[Dict[str, Any]], size: int = 3) -> List[List[Dict[str, Any]]]:
    return [rows[idx : idx + size] for idx in range(0, len(rows), size)]


def _select_rows_for_group(section_type: str, rows: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
    if not rows:
        return []
    if section_type in {"investigation_entry", "scope_hypothesis", "conclusion_actions"}:
        return _chunk_rows(rows, size=3)
    groups: List[List[Dict[str, Any]]] = []
    used: set[int] = set()

    def take(predicate: Any, *, limit: int = 4) -> None:
        selected: List[Dict[str, Any]] = []
        for idx, row in enumerate(rows):
            if idx in used:
                continue
            if predicate(row):
                selected.append(row)
                used.add(idx)
                if len(selected) >= limit:
                    break
        if selected:
            groups.append(selected)

    if section_type == "timeline_process":
        take(lambda row: _row_has_status(row, "confirmed"), limit=4)
        take(lambda row: _row_has_marker(row, HIGH_RISK_ACTIVITY_MARKERS), limit=4)
        take(lambda row: _row_has_status(row, "candidate"), limit=4)
        take(lambda row: _row_has_status(row, "background"), limit=4)
    elif section_type == "evidence_judgment":
        take(lambda row: _row_has_marker(row, NETWORK_ACTIVITY_MARKERS), limit=3)
        take(lambda row: _row_has_marker(row, HIGH_RISK_ACTIVITY_MARKERS), limit=3)
        take(lambda row: _row_has_status(row, "candidate") or _row_has_fact_type(row, "claim"), limit=3)
        take(lambda row: True, limit=3)
    elif section_type in {"relationship_scope", "scope_hypothesis"}:
        take(lambda row: any("已确认受影响" in _text(fact.get("reporting_focus")) or "种子资产" in _text(fact.get("reporting_focus")) for fact in _list(row.get("facts"))), limit=3)
        take(lambda row: any("候选" in _text(fact.get("reporting_focus")) or "待确认" in _text(fact.get("reporting_focus")) or _text(fact.get("status")) == "candidate" for fact in _list(row.get("facts"))), limit=4)
        take(lambda row: any("外部基础设施" in _text(fact.get("reporting_focus") or fact.get("boundary_note")) for fact in _list(row.get("facts"))), limit=3)
        take(lambda row: True, limit=3)
    elif section_type == "counterevidence_limits":
        take(lambda row: any(_text(fact.get("fact_type")) == "gap" for fact in _list(row.get("facts"))), limit=4)
        take(lambda row: any(_text(fact.get("status")) == "background" for fact in _list(row.get("facts"))), limit=4)
        take(lambda row: any(_text(fact.get("status")) == "candidate" for fact in _list(row.get("facts"))), limit=3)
        take(lambda row: True, limit=3)
    else:
        groups = _chunk_rows(rows, size=3)
    for idx, row in enumerate(rows):
        if idx not in used:
            if groups and len(groups[-1]) < 3:
                groups[-1].append(row)
            else:
                groups.append([row])
    return groups[:6]


def _paragraph_groups_from_key_facts(
    section_type: str,
    key_facts: List[Dict[str, Any]],
    source_fact_catalog: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    fact_by_id, fact_by_source_id = source_fact_indexes(source_fact_catalog)
    rows = _group_fact_rows(key_facts, fact_by_id, fact_by_source_id)
    groups: List[Dict[str, Any]] = []
    for idx, row_group in enumerate(_select_rows_for_group(section_type, rows), start=1):
        fact_ids = _dedupe_texts([fact_id for row in row_group for fact_id in _list(row.get("fact_ids"))])
        source_ids = _dedupe_texts([source_id for row in row_group for source_id in _list(row.get("source_ids"))])
        facts = [fact for row in row_group for fact in _list(row.get("facts"))]
        role = _paragraph_role_for_group(section_type, facts, idx)
        groups.append(
            {
                "group_id": f"{section_type}-g{idx}",
                "paragraph_role": role,
                "paragraph_claim": _paragraph_claim_for_group(section_type, role, facts),
                "fact_ids": fact_ids,
                "source_ids": source_ids,
                "write_focus": _route_use_for(section_type),
                "contrast_or_boundary": _paragraph_claim_for_group("counterevidence_limits", role, facts)
                if section_type in {"relationship_scope", "counterevidence_limits"}
                else "本段只承担当前章节的论证任务，不要重复其他章节的完整事实链。",
                "must_not_repeat": "不要把本段事实改写成其他章节的结论，也不要新增未在 source_fact_catalog 中出现的事实。",
            }
        )
    return groups


def _section_briefs_from_plan(materials: Dict[str, Any], bundle: Dict[str, Any]) -> List[Dict[str, Any]]:
    source_fact_catalog = build_source_fact_catalog(bundle)
    briefs: List[Dict[str, Any]] = []
    for raw_section in _list(_dict(materials.get("report_plan")).get("sections")):
        section = _dict(raw_section)
        section_type = _text(section.get("section_type"))
        source_ids = _source_ids_from_item(section)
        if not section_type or not source_ids:
            continue
        if section_type == "timeline_process":
            key_fact_limit = 14
        elif section_type in {"relationship_scope", "counterevidence_limits"}:
            key_fact_limit = 10
        elif section_type == "evidence_judgment":
            key_fact_limit = 8
        else:
            key_fact_limit = 5
        key_facts = _route_key_facts_from_sources(
            source_fact_catalog,
            source_ids,
            section_type=section_type,
            limit=key_fact_limit,
        )
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
                "key_facts": key_facts,
                "paragraph_groups": _paragraph_groups_from_key_facts(section_type, key_facts, source_fact_catalog),
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


def _merge_previous_section_briefs(
    materials: Dict[str, Any],
    previous_materials: Dict[str, Any],
) -> None:
    plan_sections = _list(_dict(materials.get("report_plan")).get("sections"))
    if not plan_sections or not previous_materials:
        return
    current_by_type = {
        _text(item.get("section_type")): item
        for item in _list(materials.get("section_briefs"))
        if isinstance(item, dict) and _text(item.get("section_type"))
    }
    previous_by_type = {
        _text(item.get("section_type")): item
        for item in _list(previous_materials.get("section_briefs"))
        if isinstance(item, dict) and _text(item.get("section_type"))
    }
    if not current_by_type and not previous_by_type:
        return
    merged: List[Dict[str, Any]] = []
    for section in plan_sections:
        section_type = _text(_dict(section).get("section_type"))
        if not section_type:
            continue
        # Preserve agent-authored briefs from an earlier repair round when the
        # current round fixes another issue but accidentally omits a section.
        brief = current_by_type.get(section_type) or previous_by_type.get(section_type)
        if isinstance(brief, dict):
            merged.append(brief)
    if merged:
        materials["section_briefs"] = merged


def _preserve_previous_material_lists(materials: Dict[str, Any], previous_materials: Dict[str, Any]) -> None:
    if not previous_materials:
        return
    for key in [
        "narrative_spine",
        "evidence_argument_map",
        "scope_role_matrix",
        "counterarguments_and_boundaries",
        "action_rationale",
    ]:
        if not _list(materials.get(key)) and _list(previous_materials.get(key)):
            materials[key] = _list(previous_materials.get(key))


def _materialize_section_fact_routes(materials: Dict[str, Any], source_fact_catalog: List[Dict[str, Any]]) -> None:
    fact_by_id, fact_by_source_id = source_fact_indexes(source_fact_catalog)
    for raw_brief in _list(materials.get("section_briefs")):
        if not isinstance(raw_brief, dict):
            continue
        brief = raw_brief
        section_type = _text(brief.get("section_type"))
        brief_source_ids = _source_ids_from_item(brief)
        routed_key_facts: List[Dict[str, Any]] = []
        for raw_fact in _list(brief.get("key_facts")):
            if not isinstance(raw_fact, dict):
                continue
            fact = dict(raw_fact)
            fact_ids = _list(fact.get("fact_ids"))
            if _text(fact.get("fact_id")):
                fact_ids.append(_text(fact.get("fact_id")))
            source_ids = _source_ids_from_item(fact)
            for fact_id in list(fact_ids):
                source_id = _text(_dict(fact_by_id.get(_text(fact_id))).get("source_id"))
                if source_id and source_id not in source_ids:
                    source_ids.append(source_id)
            for source_id in list(source_ids):
                fact_id = _text(_dict(fact_by_source_id.get(_text(source_id))).get("fact_id"))
                if fact_id and fact_id not in fact_ids:
                    fact_ids.append(fact_id)
            fact_ids = [fact_id for fact_id in _dedupe_texts(fact_ids) if fact_id in fact_by_id]
            source_ids = [source_id for source_id in _dedupe_texts(source_ids) if source_id in fact_by_source_id]
            if not fact_ids and not source_ids:
                continue
            routed = {
                "fact_ids": fact_ids,
                "source_ids": source_ids,
                "fact_role": _text(fact.get("fact_role") or fact.get("role") or fact.get("claim") or "章节事实"),
            }
            for field in ["why_it_matters", "limitation", "use_for"]:
                value = _text(fact.get(field))
                if value:
                    routed[field] = value
            if not _text(routed.get("use_for")) and _text(fact.get("reader_fact_text")):
                routed["use_for"] = "使用对应 source_fact_catalog 的原子事实展开本节，不要复述为泛化摘要。"
            routed_key_facts.append(routed)
            brief_source_ids.extend(routed["source_ids"])
        brief["source_ids"] = _dedupe_texts(brief_source_ids)
        brief["key_facts"] = routed_key_facts
        routed_groups: List[Dict[str, Any]] = []
        for group_idx, raw_group in enumerate(_list(brief.get("paragraph_groups")), start=1):
            if not isinstance(raw_group, dict):
                continue
            group = dict(raw_group)
            fact_ids, source_ids, facts = _fact_refs_from_group_item(group, fact_by_id, fact_by_source_id)
            if not fact_ids and not source_ids:
                continue
            paragraph_role = _text(group.get("paragraph_role")) or _paragraph_role_for_group(section_type, facts, group_idx)
            routed_group = {
                "group_id": _text(group.get("group_id")) or f"{section_type or 'section'}-g{group_idx}",
                "paragraph_role": paragraph_role,
                "paragraph_claim": _text(group.get("paragraph_claim"))
                or _paragraph_claim_for_group(section_type, paragraph_role, facts),
                "fact_ids": fact_ids,
                "source_ids": source_ids,
                "write_focus": _text(group.get("write_focus")) or _route_use_for(section_type),
                "contrast_or_boundary": _text(group.get("contrast_or_boundary"))
                or "本段只承担当前章节的论证任务，不要重复其他章节的完整事实链。",
                "must_not_repeat": _text(group.get("must_not_repeat"))
                or "不要新增未在 source_fact_catalog 中出现的事实，不要把候选事实写成确认结论。",
            }
            routed_groups.append(routed_group)
            brief_source_ids.extend(source_ids)
        if not routed_groups and routed_key_facts:
            routed_groups = _paragraph_groups_from_key_facts(section_type, routed_key_facts, source_fact_catalog)
            for group in routed_groups:
                brief_source_ids.extend(_source_ids_from_item(group))
        brief["source_ids"] = _dedupe_texts(brief_source_ids)
        brief["paragraph_groups"] = routed_groups


def _key_fact_identity(fact: Dict[str, Any]) -> Tuple[str, ...]:
    fact_ids = tuple(_dedupe_texts(_list(fact.get("fact_ids")) + ([_text(fact.get("fact_id"))] if _text(fact.get("fact_id")) else [])))
    source_ids = tuple(_source_ids_from_item(fact))
    return fact_ids or source_ids


def _paragraph_group_identity(group: Dict[str, Any]) -> Tuple[str, ...]:
    group_id = _text(group.get("group_id"))
    if group_id:
        return ("group_id", group_id)
    fact_ids = tuple(_dedupe_texts(_list(group.get("fact_ids")) + ([_text(group.get("fact_id"))] if _text(group.get("fact_id")) else [])))
    source_ids = tuple(_source_ids_from_item(group))
    return fact_ids or source_ids


def _merge_section_brief_patch(value: List[Any], previous_value: List[Any]) -> List[Dict[str, Any]]:
    previous_by_type = {
        _text(item.get("section_type")): item
        for item in previous_value
        if isinstance(item, dict) and _text(item.get("section_type"))
    }
    merged: List[Dict[str, Any]] = []
    seen_types: set[str] = set()
    for raw_brief in value:
        if not isinstance(raw_brief, dict):
            continue
        brief = dict(raw_brief)
        section_type = _text(brief.get("section_type"))
        if not section_type:
            continue
        seen_types.add(section_type)
        previous = _dict(previous_by_type.get(section_type))
        previous_facts = [_dict(item) for item in _list(previous.get("key_facts"))]
        patch_facts = [_dict(item) for item in _list(brief.get("key_facts"))]
        previous_groups = [_dict(item) for item in _list(previous.get("paragraph_groups"))]
        patch_groups = [_dict(item) for item in _list(brief.get("paragraph_groups"))]
        merged_facts: List[Dict[str, Any]] = []
        seen_fact_keys: set[Tuple[str, ...]] = set()
        for fact in patch_facts + previous_facts:
            identity = _key_fact_identity(fact)
            if not identity or identity in seen_fact_keys:
                continue
            seen_fact_keys.add(identity)
            merged_facts.append(fact)
        merged_groups: List[Dict[str, Any]] = []
        seen_group_keys: set[Tuple[str, ...]] = set()
        # A paragraph-group patch is the agent-authored argument route for this
        # section. Do not silently mix in deterministic groups for the same
        # section; otherwise validation can pass while the agent missed a
        # candidate/gap/external boundary route.
        groups_to_merge = patch_groups if patch_groups else previous_groups
        for group in groups_to_merge:
            identity = _paragraph_group_identity(group)
            if not identity or identity in seen_group_keys:
                continue
            seen_group_keys.add(identity)
            merged_groups.append(group)
        if previous:
            for key in ["title", "question_to_answer", "mode", "must_include", "must_not_repeat", "boundary_notes"]:
                if key not in brief and key in previous:
                    brief[key] = previous[key]
        brief["source_ids"] = _dedupe_texts(_source_ids_from_item(brief) + _source_ids_from_item(previous))
        brief["key_facts"] = merged_facts[:10]
        if merged_groups:
            brief["paragraph_groups"] = merged_groups[:8]
        merged.append(brief)
    for raw_previous in previous_value:
        if not isinstance(raw_previous, dict):
            continue
        section_type = _text(raw_previous.get("section_type"))
        if section_type and section_type not in seen_types:
            merged.append(dict(raw_previous))
    return merged


def _merge_material_patch(materials: Dict[str, Any], previous_materials: Dict[str, Any]) -> Dict[str, Any]:
    if not previous_materials:
        return dict(materials)
    merged = dict(previous_materials)
    for key, value in materials.items():
        if key in {"source_fact_catalog", "source_inventory"}:
            continue
        if value is None or value == "" or value == {}:
            continue
        if isinstance(value, list) and not value and key not in {"reportable_limits"}:
            continue
        if key == "section_briefs" and isinstance(value, list):
            merged[key] = _merge_section_brief_patch(value, _list(previous_materials.get("section_briefs")))
            continue
        merged[key] = value
    return merged


def _repair_materials_contract(
    materials: Dict[str, Any],
    tool_results: List[Dict[str, Any]],
    bundle: Dict[str, Any],
    previous_materials: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    repaired = _normalize_source_ids_in_material(_merge_material_patch(_dict(materials), _dict(previous_materials)))
    source_index = source_index_for_materials(bundle)
    source_fact_catalog = build_source_fact_catalog(bundle)
    repaired = _drop_unknown_source_ids(repaired, source_index)
    repaired["source_fact_catalog"] = source_fact_catalog
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
    if not _text(thesis.get("why_this_judgment_holds")) or _is_meta_material_text(thesis.get("why_this_judgment_holds")):
        thesis["why_this_judgment_holds"] = (
            _source_derived_verdict_text(header)
            or _text(thesis.get("why_it_matters"))
            or "当前判断来自已收集证据链与交付范围判断的综合结果。"
        )
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
    repaired["schema_version"] = "report-writer-materials-v2"
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
    _preserve_previous_material_lists(repaired, _dict(previous_materials))
    _merge_previous_section_briefs(repaired, _dict(previous_materials))
    _materialize_section_fact_routes(repaired, source_fact_catalog)
    repaired["source_inventory"] = _source_inventory_from_materials(bundle, repaired)
    return repaired


def _submitted_patch_has_paragraph_groups(action_materials: Dict[str, Any], materials: Dict[str, Any]) -> bool:
    submitted_briefs = {
        _text(item.get("section_type")): item
        for item in _list(action_materials.get("section_briefs"))
        if isinstance(item, dict) and _text(item.get("section_type"))
    }
    plan_sections = [
        _text(section.get("section_type"))
        for section in _list(_dict(materials.get("report_plan")).get("sections"))
        if isinstance(section, dict) and _text(section.get("section_type"))
    ]
    required_sections = [
        section_type
        for section_type in plan_sections
        if section_type in AGENT_PARAGRAPH_GROUP_SECTION_TYPES
    ] or plan_sections[:3]
    if not plan_sections or not submitted_briefs:
        return False
    for section_type in required_sections:
        brief = _dict(submitted_briefs.get(section_type))
        groups = _list(brief.get("paragraph_groups"))
        if not groups:
            return False
        for group in groups:
            group_dict = _dict(group)
            if not _text(group_dict.get("paragraph_role")) or not _text(group_dict.get("paragraph_claim")):
                return False
            if not _fact_ids_from_item(group_dict) and not _source_ids_from_item(group_dict):
                return False
    return True


def _submitted_paragraph_group_section_types(action_materials: Dict[str, Any]) -> List[str]:
    section_types: List[str] = []
    for raw_brief in _list(action_materials.get("section_briefs")):
        brief = _dict(raw_brief)
        section_type = _text(brief.get("section_type"))
        if not section_type or not _list(brief.get("paragraph_groups")):
            continue
        section_types.append(section_type)
    return _dedupe_texts(section_types)


def _required_paragraph_group_section_types(materials: Dict[str, Any]) -> List[str]:
    plan_sections = [
        _text(section.get("section_type"))
        for section in _list(_dict(materials.get("report_plan")).get("sections"))
        if isinstance(section, dict) and _text(section.get("section_type"))
    ]
    return [
        section_type
        for section_type in plan_sections
        if section_type in AGENT_PARAGRAPH_GROUP_SECTION_TYPES
    ] or plan_sections[:3]


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
    # source_ids and short rationales. Paragraph groups add a small structured
    # layer, so keep enough output room to avoid truncating valid route patches.
    agent_llm = _bind_report_agent_llm(llm, json_mode=True)
    json_mode_enabled = True
    tool_results = _preload_results(bundle)
    draft_materials: Dict[str, Any] = _fallback_materials_from_preload(tool_results, bundle)
    agent_paragraph_group_sections: set[str] = set()
    feedback: List[Any] = [
        {
            "code": "patch_route_from_deterministic_draft",
            "severity": "instruction",
            "message_for_agent": "系统已给出 deterministic base materials。下一轮优先提交 route patch：为复杂章节 timeline_process/evidence_judgment/relationship_scope/counterevidence_limits 补充 paragraph_groups，说明每段的 paragraph_role、paragraph_claim、fact_ids/source_ids、write_focus、contrast_or_boundary、must_not_repeat；简单章节可由系统沿用 conservative groups；不要重吐完整 source_fact_catalog 或事实文本。如果无法稳定补强 route，提交空 materials 接受 deterministic route 也可以。",
            "suggested_next_action": "submit_route_patch",
        }
    ]
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
                            bundle=bundle,
                            tool_results=tool_results,
                            draft_materials=_compact_draft_materials_for_prompt(draft_materials),
                            feedback=feedback,
                            force_submit=force_submit,
                        )
                    ),
                ],
                role="report_material_loop",
            )
        except Exception as exc:
            if json_mode_enabled and _looks_like_json_mode_unsupported(exc):
                agent_llm = _bind_report_agent_llm(llm, json_mode=False)
                json_mode_enabled = False
                feedback.append("json mode unsupported by current LLM; retried with plain JSON prompt")
                try:
                    action = _invoke_report_agent_json(
                        agent_llm,
                        [
                            SystemMessage(content=REPORT_AGENT_SYSTEM_PROMPT),
                            HumanMessage(
                                content=_build_round_user_prompt(
                                    round_index=round_index,
                                    max_rounds=max_rounds,
                                    bundle=bundle,
                                    tool_results=tool_results,
                                    draft_materials=_compact_draft_materials_for_prompt(draft_materials),
                                    feedback=feedback,
                                    force_submit=force_submit,
                                )
                            ),
                        ],
                        role="report_material_loop",
                    )
                except Exception as retry_exc:
                    if _looks_like_length_limit(retry_exc):
                        error_message = (
                            "round "
                            + str(round_index)
                            + " output length limit reached after plain JSON retry: 下一轮必须提交更短的 route-only JSON。"
                        )
                        draft_validation = validate_report_writer_materials(bundle, draft_materials)
                        trace["rounds"].append(
                            {"round": round_index, "error": error_message, "draft_validation": draft_validation}
                        )
                        if draft_validation.get("ok"):
                            trace["status"] = "deterministic_base_after_agent_length_limit"
                            trace["validation"] = draft_validation
                            trace["submitted_materials"] = draft_materials
                            return draft_materials, trace
                        feedback.append(error_message)
                    else:
                        feedback.append(f"round {round_index} parse/invoke error: {type(retry_exc).__name__}: {retry_exc}")
                        trace["rounds"].append({"round": round_index, "error": feedback[-1]})
                    continue
            else:
                if _looks_like_length_limit(exc):
                    error_message = (
                        "round "
                        + str(round_index)
                        + " output length limit reached: 下一轮必须压缩 submit JSON。只输出 v2 路由字段；source_inventory=[]；不要输出 source_fact_catalog、reader_fact_text、exact_fact_text、title/question/mode/must_include 的重复副本；每节 paragraph_groups 控制在 2 到 5 组。"
                    )
                    draft_validation = validate_report_writer_materials(bundle, draft_materials)
                    trace["rounds"].append(
                        {"round": round_index, "error": error_message, "draft_validation": draft_validation}
                    )
                    if draft_validation.get("ok"):
                        trace["status"] = "deterministic_base_after_agent_length_limit"
                        trace["validation"] = draft_validation
                        trace["submitted_materials"] = draft_materials
                        return draft_materials, trace
                    feedback.append(error_message)
                else:
                    feedback.append(f"round {round_index} parse/invoke error: {type(exc).__name__}: {exc}")
                    trace["rounds"].append({"round": round_index, "error": feedback[-1]})
                continue

        trace["rounds"].append({"round": round_index, "action": action})
        action_type = _text(action.get("action"))
        if action_type == "submit":
            raw_action_materials = _dict(action.get("materials"))
            agent_paragraph_group_sections.update(_submitted_paragraph_group_section_types(raw_action_materials))
            materials = _repair_materials_contract(
                raw_action_materials,
                tool_results,
                bundle,
                previous_materials=draft_materials,
            )
            validation = validate_report_writer_materials(bundle, materials)
            trace["validation"] = validation
            trace["rounds"][-1]["validation"] = validation
            if validation.get("ok"):
                required_group_sections = set(_required_paragraph_group_section_types(materials))
                cumulative_has_groups = bool(required_group_sections) and required_group_sections.issubset(
                    agent_paragraph_group_sections
                )
                raw_has_groups = _submitted_patch_has_paragraph_groups(raw_action_materials, materials) or cumulative_has_groups
                trace["rounds"][-1]["raw_agent_paragraph_groups"] = raw_has_groups
                trace["rounds"][-1]["agent_paragraph_group_sections"] = sorted(agent_paragraph_group_sections)
                if not raw_has_groups:
                    trace["rounds"][-1]["agent_feedback"] = [
                        {
                            "code": "missing_agent_paragraph_groups",
                            "severity": "advisory",
                            "message_for_agent": "raw submit 没有为复杂章节提交完整 paragraph_groups；系统将沿用 deterministic conservative route。后续可优化 agent route patch，但不应因此阻塞报告生成。",
                            "suggested_next_action": "submit_route_patch_when_improving_material_quality",
                        }
                    ]
                trace["status"] = "submitted" if raw_has_groups else "submitted_with_conservative_paragraph_groups"
                trace["submitted_materials"] = materials
                return materials or _fallback_materials_from_preload(tool_results, bundle), trace
            draft_validation = validate_report_writer_materials(bundle, draft_materials)
            if draft_validation.get("ok") and (force_submit or round_index >= max_rounds):
                trace["status"] = "deterministic_base_after_invalid_agent_patch"
                trace["validation"] = draft_validation
                trace["rounds"][-1]["discarded_patch_validation"] = validation
                trace["submitted_materials"] = draft_materials
                return draft_materials, trace
            feedback = _agent_feedback_from_validation(validation)
            if draft_validation.get("ok"):
                trace["rounds"][-1]["deterministic_base_available"] = True
            trace["rounds"][-1]["agent_feedback"] = feedback
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
