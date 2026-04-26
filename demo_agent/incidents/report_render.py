from __future__ import annotations

from typing import Any, Dict, List


def _format_time(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return "unknown"
    return text.replace("T", " ").replace("Z", " UTC")


def _join_or_fallback(values: List[str], fallback: str = "当前未获取") -> str:
    cleaned = [str(value or "").strip() for value in values if str(value or "").strip()]
    return "、".join(cleaned) if cleaned else fallback


def _format_obs_refs(observation_ids: List[str]) -> str:
    refs = [str(item or "").strip() for item in observation_ids if str(item or "").strip()]
    if not refs:
        return "未引用"
    return ", ".join(refs)


def render_appendix_report(appendix_contract: Dict[str, Any]) -> str:
    appendix = appendix_contract or {}
    lines: List[str] = [
        "# 事件调查技术附录",
        "",
        "以下内容主要供分析、复盘和技术排查使用，不直接替代主报告结论。",
        "",
        "## 1. IOC / IOA 清单",
        "",
        "| 类型 | 值 | 角色 | 状态 |",
        "| -- | -- | -- | -- |",
    ]
    for row in list(appendix.get("ioc_rows") or []):
        lines.append(
            f"| {str(row.get('type') or '').replace('|', '/')} | {str(row.get('value') or '').replace('|', '/')} | {str(row.get('role') or '').replace('|', '/')} | {str(row.get('status') or '').replace('|', '/')} |"
        )
    if not list(appendix.get("ioc_rows") or []):
        lines.append("| 暂无 | 暂无 | 暂无 | 暂无 |")

    lines.extend(["", "## 2. 关键对象清单", "", "| 对象 | 类型 | 当前角色 | 是否已纳入证据链 | 备注 |", "| -- | -- | -- | -- | -- |"])
    for row in list(appendix.get("key_object_rows") or []):
        lines.append(
            f"| {str(row.get('object') or '').replace('|', '/')} | {str(row.get('type') or '').replace('|', '/')} | {str(row.get('current_role') or '').replace('|', '/')} | {str(row.get('in_evidence_chain') or '').replace('|', '/')} | {str(row.get('note') or '').replace('|', '/')} |"
        )
    if not list(appendix.get("key_object_rows") or []):
        lines.append("| 暂无 | 暂无 | 暂无 | 否 | 暂无 |")

    lines.extend(["", "## 3. 关键证据细目"])
    evidence_details = list(appendix.get("evidence_details") or [])
    if not evidence_details:
        lines.append("")
        lines.append("- 当前没有可直接展开的关键证据细目。")
    for entry in evidence_details:
        lines.extend(
            [
                "",
                f"### 证据 {entry.get('id')}",
                f"- **证据类型**：{'主支撑证据' if str(entry.get('kind') or '').strip() == 'supporting' else '反证或替代解释'}",
                f"- **证据类别**：{entry.get('category')}",
                f"- **证据强度**：{entry.get('strength')}",
                f"- **事实描述**：{entry.get('fact_description')}",
                f"- **为什么重要**：{entry.get('reason_text')}",
                f"- **边界与限制**：{entry.get('limitation_text')}",
                f"- **主要依据来源**：{entry.get('source_text')}",
                f"- **观测引用**：`{_format_obs_refs(list(entry.get('observation_ids') or []))}`",
            ]
        )

    lines.extend(["", "## 4. 观测引用对照", "", "| 观测编号 | 来源工具 | 事实摘要 | 关系 |", "| -- | -- | -- | -- |"])
    for row in list(appendix.get("observation_rows") or []):
        lines.append(
            f"| `{row.get('observation_id')}` | `{row.get('tool_name')}` | {str(row.get('summary') or '').replace('|', '/')} | `{row.get('relation')}` |"
        )
    if not list(appendix.get("observation_rows") or []):
        lines.append("| `obs-none` | `n/a` | 当前没有可展示的 observation 摘要。 | `context` |")

    lines.extend(["", "## 5. 正文章节引用映射", "", "| 正文章节 | 主要 evidence / observation | 用途 |", "| -- | -- | -- |"])
    for row in list(appendix.get("section_reference_rows") or []):
        refs = _join_or_fallback([str(item or "").strip() for item in list(row.get("references") or []) if str(item or "").strip()], "暂无")
        lines.append(
            f"| {str(row.get('section') or '').replace('|', '/')} | {refs.replace('|', '/')} | {str(row.get('purpose') or '').replace('|', '/')} |"
        )
    if not list(appendix.get("section_reference_rows") or []):
        lines.append("| 暂无 | 暂无 | 暂无 |")

    lines.extend(["", "## 6. 证据来源与参考资料", "", "| 来源类型 | 来源名称 | 用途 | 边界 |", "| -- | -- | -- | -- |"])
    for row in list(appendix.get("source_rows") or []):
        lines.append(
            f"| {str(row.get('source_type') or '').replace('|', '/')} | {str(row.get('source_name') or '').replace('|', '/')} | {str(row.get('usage') or '').replace('|', '/')} | {str(row.get('boundary') or '').replace('|', '/')} |"
        )
    if not list(appendix.get("source_rows") or []):
        lines.append("| 暂无 | 暂无 | 暂无 | 暂无 |")

    lines.extend(["", "## 7. 证据缺口与待补查询", "", "| 缺口 | 限制的结论 | 当前是否可补 | 最值得补的查询 |", "| -- | -- | -- | -- |"])
    for row in list(appendix.get("gap_rows") or []):
        lines.append(
            f"| {str(row.get('gap') or '').replace('|', '/')} | {str(row.get('limited_conclusion') or '').replace('|', '/')} | {str(row.get('actionable') or '').replace('|', '/')} | {str(row.get('best_query') or '').replace('|', '/')} |"
        )
    if not list(appendix.get("gap_rows") or []):
        lines.append("| 当前没有仍需单列的关键缺口 | 当前没有仍需单列的关键结论限制 | 否 | 当前暂无补查项 |")

    return "\n".join(lines).strip() + "\n"


def render_ops_report(ops_report_contract: Dict[str, Any]) -> str:
    main_report = ops_report_contract or {}
    header = main_report.get("report_header") or {}
    background = main_report.get("background_and_leads") or {}
    scope_definition = main_report.get("scope_definition") or {}
    coverage_plan = main_report.get("coverage_plan") or {}
    mechanism = main_report.get("mechanism_breakdown") or {}
    evidence_blocks = main_report.get("evidence_blocks") or {}
    timeline = main_report.get("timeline") or {}
    relationship = main_report.get("relationship_analysis") or {}
    impact = main_report.get("impact_assessment") or {}
    gap_summary = main_report.get("evidence_gap_summary") or {}
    recommended = main_report.get("recommended_actions") or {}

    lines: List[str] = [
        "# 事件调查报告",
        "",
        "## 首页摘要",
        f"- **事件标题**：{header.get('event_title')}",
        f"- **分析窗口**：{header.get('analysis_window')}",
        f"- **当前状态**：`{header.get('current_status')}` / {header.get('current_status_label')}",
        f"- **严重度**：{header.get('severity')}",
        f"- **研判把握**：{header.get('confidence')}",
        f"- **已确认影响范围**：{header.get('confirmed_scope')}",
        f"- **当前最强证据**：{header.get('strongest_evidence')}",
        f"- **当前最关键缺口**：{header.get('key_gap')}",
        f"- **建议立即动作**：{header.get('immediate_action')}",
        f"- **一句话结论**：{header.get('one_sentence_summary')}",
        "",
        "## 1. 事件背景与已知线索",
        f"- **事件标题**：{background.get('event_title')}",
        f"- **分析窗口**：{background.get('analysis_window')}",
        f"- **Seed alert / 调查起点**：{background.get('seed_alert')}",
        f"- **初始命中线索（规则 / 指纹 / 模型）**：{_join_or_fallback(list(background.get('initial_hits') or []), '当前未单列初始命中线索')}",
        f"- **上游检测或已知背景**：{background.get('upstream_context')}",
        f"- **本次调查关注点**：{background.get('investigation_focus')}",
        f"- **本节主要依据来源**：{background.get('source_text')}",
        "",
        "## 2. 范围界定与调查假设",
        f"- **本次调查范围**：{scope_definition.get('investigation_scope')}",
        f"- **主假设**：{scope_definition.get('primary_hypothesis')}",
        f"- **备选解释**：{scope_definition.get('alternative_hypothesis')}",
        f"- **本轮不覆盖的范围**：{scope_definition.get('out_of_scope')}",
        f"- **主假设成立所需条件**：{scope_definition.get('primary_hypothesis_requirements')}",
        f"- **主假设失效条件**：{scope_definition.get('primary_hypothesis_failure_conditions')}",
        f"- **本节主要依据来源**：{scope_definition.get('source_text')}",
        "",
        "## 3. 对象覆盖策略与关键实体",
        f"- **已纳入证据链的对象**：{coverage_plan.get('in_chain_objects')}",
        f"- **当前核心观测对象**：{coverage_plan.get('core_objects')}",
        f"- **横向对比对象**：{coverage_plan.get('comparison_objects')}",
        f"- **扩展查询候选**：{coverage_plan.get('expansion_candidates')}",
        f"- **种子资产**：{coverage_plan.get('seed_asset')}",
        f"- **已确认受影响资产**：{coverage_plan.get('confirmed_assets')}",
        f"- **待确认关联资产**：{coverage_plan.get('related_assets')}",
        f"- **核心外部基础设施**：{coverage_plan.get('core_external_indicators')}",
        f"- **关键指示物**：{coverage_plan.get('key_indicators')}",
        f"- **对象覆盖边界**：{coverage_plan.get('coverage_boundary')}",
        f"- **本节主要依据来源**：{coverage_plan.get('source_text')}",
        "",
        "## 4. 事件机制分解",
        f"- **触发因素 / 起点**：{mechanism.get('trigger_or_start')}",
        f"- **事件主链**：{mechanism.get('main_chain')}",
        f"- **影响放大器 / 传播机制**：{mechanism.get('amplifier')}",
        f"- **当前不能确认的机制环节**：{_join_or_fallback(list(mechanism.get('unconfirmed_links') or []), '当前没有额外未确认机制环节')}",
        f"- **本节主要依据来源**：{mechanism.get('source_text')}",
        "",
        "## 5. 关键证据与异常事实",
        "",
        "### 5.1 主支撑证据",
    ]

    supporting = list((evidence_blocks.get("supporting") or []))
    if not supporting:
        lines.append("- 当前没有足够的主支撑证据可供自动展开。")
    for entry in supporting:
        lines.extend(
            [
                "",
                f"#### 证据 {entry.get('id')}",
                f"- **证据类别**：{entry.get('category')}",
                f"- **证据强度**：{entry.get('strength')}",
                f"- **事实描述**：{entry.get('fact_text')}",
                f"- **为什么支持当前主假设**：{entry.get('reason_text')}",
                f"- **局限性与边界**：{entry.get('limitation_text')}",
                f"- **本节主要依据来源**：{entry.get('source_text')}",
            ]
        )

    lines.extend(["", "### 5.2 反证与替代解释"])
    counter_blocks = list((evidence_blocks.get("counterevidence") or []))
    if not counter_blocks:
        lines.append("- 当前没有足以单独改变结论方向的强反证，但这并不意味着后续可以省略背景核查。")
    for entry in counter_blocks:
        lines.extend(
            [
                "",
                f"#### 证据 {entry.get('id')}",
                f"- **反证或替代解释**：{entry.get('category')}",
                f"- **相关事实**：{entry.get('fact_text')}",
                f"- **为什么它不足以推翻主结论，或为什么它足以让我们降级**：{entry.get('reason_text')}",
                f"- **主要依据来源**：{entry.get('source_text')}",
            ]
        )

    background_block = evidence_blocks.get("background") or {}
    if background_block:
        lines.extend(
            [
                "",
                "### 5.3 辅助背景与解释（可选）",
                f"- **相关背景**：{background_block.get('hint')}",
                f"- **它如何帮助理解本案**：{background_block.get('summary')}",
                f"- **不能据此直接推出的结论**：{background_block.get('limits')}",
                f"- **主要依据来源**：{background_block.get('source_text')}",
            ]
        )

    lines.extend(
        [
            "",
            "## 6. 时序特征与行为模式",
            "",
            "### 6.1 核心时间线",
            "",
            "| 时间 | 事件 | 作用 |",
            "| -- | -- | -- |",
        ]
    )
    timeline_entries = list(timeline.get("entries") or [])
    for entry in timeline_entries:
        lines.append(
            f"| {_format_time(entry.get('ts'))} | {str(entry.get('summary') or '').replace('|', '/')} | `{str(entry.get('role') or '').replace('|', '/')}` |"
        )
    if not timeline_entries:
        lines.append("| 当前未获取 | 当前没有足够时间线事实 | `context` |")

    lines.extend(["", "### 6.2 模式总结"])
    for item in list(timeline.get("pattern_lines") or []):
        lines.append(f"- {item}")
    if not list(timeline.get("pattern_lines") or []):
        lines.append("- 当前没有足够的时序模式可供自动总结。")
    lines.append(f"- **本节主要依据来源**：{timeline.get('source_text')}")

    lines.extend(
        [
            "",
            "## 7. 传播与关联分析",
            f"- **扩线 pivot**：{relationship.get('pivot_text')}",
            f"- **已确认关联**：{_join_or_fallback(list(relationship.get('confirmed_relationships') or []), '当前没有单列的已确认关联')}",
            f"- **候选关联**：{_join_or_fallback(list(relationship.get('candidate_relationships') or []), '当前没有额外候选关联')}",
            f"- **未完成独立验证的对象**：{relationship.get('unverified_objects')}",
            f"- **当前关联边界**：{relationship.get('relationship_boundary')}",
            f"- **本节主要依据来源**：{relationship.get('source_text')}",
            "",
            "## 8. 影响分析",
            f"- **当前已确认影响**：{impact.get('confirmed_impact')}",
            f"- **当前疑似影响**：{impact.get('suspected_impact')}",
            f"- **时间范围**：{impact.get('time_range')}",
            f"- **资产范围**：{impact.get('asset_range')}",
            f"- **外部基础设施范围**：{impact.get('external_range')}",
            f"- **当前攻击阶段**：{impact.get('attack_stage')}",
            f"- **仍未确认的影响**：{_join_or_fallback(list(impact.get('unresolved_impact') or []), '当前没有额外未确认影响')}",
            f"- **本节主要依据来源**：{impact.get('source_text')}",
            "",
            "## 9. 证据链摘要与观测缺口",
            f"- **当前判断主要建立在**：{gap_summary.get('judgment_basis')}",
            f"- **当前最强证据**：{gap_summary.get('strongest_evidence')}",
            f"- **当前最关键缺口**：{gap_summary.get('key_gap')}",
            f"- **当前最多只能走到的判断层级**：{gap_summary.get('judgment_ceiling')}",
            f"- **因缺口而不能写出的结论**：{_join_or_fallback(list(gap_summary.get('cannot_conclude') or []), '当前没有额外不能写出的结论')}",
            f"- **下一轮最值得补的证据**：{_join_or_fallback(list(gap_summary.get('next_best_evidence') or []), '当前暂无额外补证重点')}",
            f"- **本节主要依据来源**：{gap_summary.get('source_text')}",
            "",
            "## 10. 结论与后续建议",
            f"- **当前结论**：{recommended.get('current_conclusion')}",
            f"- **当前状态**：`{recommended.get('current_status')}`",
            f"- **严重度**：{recommended.get('severity')}",
            f"- **研判把握**：{recommended.get('confidence')}",
            f"- **一句话概括**：{recommended.get('one_sentence_summary')}",
            f"- **为什么当前结论成立**：{recommended.get('why_current_conclusion')}",
            f"- **为什么不是相邻状态**：{recommended.get('why_not_other_status')}",
        ]
    )

    immediate_actions = list(recommended.get("immediate_actions") or [])
    short_term_actions = list(recommended.get("short_term_actions") or [])
    follow_up_actions = list(recommended.get("follow_up_actions") or [])

    lines.extend(["", "### 10.1 建议立即动作"])
    if immediate_actions:
        for item in immediate_actions:
            lines.append(f"- {item}")
    else:
        lines.append("- 当前暂无需要单列的立即动作。")

    lines.extend(["", "### 10.2 短期排查动作"])
    if short_term_actions:
        for item in short_term_actions:
            lines.append(f"- {item}")
    else:
        lines.append("- 当前暂无需要单列的短期排查动作。")

    lines.extend(["", "### 10.3 持续监控或复核动作"])
    if follow_up_actions:
        for item in follow_up_actions:
            lines.append(f"- {item}")
    else:
        lines.append("- 当前暂无需要单列的持续监控或复核动作。")
    lines.append(f"- **下一次复核最值得补的证据**：{_join_or_fallback(list(recommended.get('next_best_evidence') or []), '当前暂无额外复核重点')}")

    lines.extend(
        [
            "",
            "## 11. 技术附录提示",
            "- 技术细节、IOC/IOA、关键对象清单、观测对照、引用来源、证据缺口与待补查询请见《事件调查技术附录》。",
        ]
    )

    return "\n".join(lines).strip() + "\n"
