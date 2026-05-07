# Plan13: Report Agent 材料整理 loop 与无损 source bundle

## 0. 目标

本计划只处理“调查结果到最终 polished report 之间”的材料组织与报告生成，不改调查 while loop。

核心目标：

- 让代码中间层只做无损整理，不做报告级语义判断。
- 让 report agent 通过受控工具从统一材料包中取材、整理材料，再开始写完整报告。
- 避免同时暴露 `incident.json`、`evidence_store`、`report_outline`、`report_fact_cards`、`report_polish_brief` 等多个半重叠入口。
- 让最终报告更接近 `report_reference` 的分析师交付风格：有判断、有证据作用、有范围边界、有反证解释、有运维动作依据。

一句话原则：

```text
代码中间层只做无损案卷整理；LLM report agent 负责语义组织；writer 只基于整理后的 materials 写报告。
```

## 1. 当前问题

### 1.1 中间层既压缩又判断，边界不清

当前报告链路大致是：

```text
incident / incident_state
  -> evidence_store
  -> reviewer_input
  -> delivery_decision
  -> report_outline
  -> report_fact_cards
  -> report_polish_input
  -> report_polish_brief
  -> LLM polished report
```

问题不是层数本身，而是部分层已经开始做语义压缩和报告级判断，但又做得不够完整：

- `fact_cards` 会把丰富事件压成短句，例如“出现执行迹象”，导致 writer 拿不到更具体的进程、路径、行为细节。
- `section_fact_map` 能告诉 writer 每节可用哪些事实，但不能充分说明“这些事实如何构成论证”。
- `scope_packet`、`fact card`、`delivery_decision` 之间可能出现对象角色冲突，例如同一资产既像调查锚点，又像已确认受影响资产。
- `report_polish_brief` 已经比原始 JSON 好，但仍偏“事实清单 + 章节映射”，不是“分析师写作前的论证笔记”。

### 1.2 直接给原始产物也不理想

如果 report agent 直接读取完整 `incident.json`，会遇到：

- 字段太多，包含调查控制状态、历史、缓存、派生视图。
- 很多字段重复表达同一事实，LLM 难以判断权威来源。
- 噪声大，报告质量容易受 prompt 选择和上下文长度影响。

所以不应直接暴露完整原始产物给 writer。

### 1.3 需要区分无损整理与语义整理

后续应该拆成两种材料：

| 层 | 生成者 | 责任 | 是否允许压缩事实 | 是否允许语义判断 |
|---|---|---|---:|---:|
| `report_source_bundle` | 代码 | 无损整理调查产物，统一索引和引用 | 否 | 否 |
| `report_writer_materials` | report agent / LLM | 从 source bundle 中选择、组织、解释证据 | 是，但必须引用 source id | 是，但必须可追溯 |

## 2. 目标链路

目标报告链路：

```text
investigation output
  -> report_source_bundle        # 代码生成，无损案卷整理
  -> report agent tools          # 只读 bundle，按需取材
  -> report_writer_materials     # LLM 生成，结构化分析材料
  -> report writer               # LLM 写完整 polished report
  -> report_reviewer(optional)   # 只做一轮质量审查或修订建议
```

第一版先实现到：

```text
report_source_bundle
  -> bounded report material loop
  -> report_writer_materials
  -> polished report
```

本计划第一版就做 bounded material loop，不做单轮 materializer demo。这里优化的核心就是让 report agent 自己按需取材、整理到可写报告的程度，因此不能退化成一次性摘要生成。

但第一版只替换 `report_polished.md` 的生成路径，不影响确定性 `report.md` 和 `report_appendix.md`。旧 polished 链路保留为 feature flag fallback，用于对比和回滚。

不先做复杂 reviewer 修订 loop，避免一开始就把“材料整理 loop”和“报告修订 loop”混在一起。

## 3. `report_source_bundle` 设计

### 3.1 定位

`report_source_bundle` 是调查结束后的统一案卷包。它不是摘要，不是 brief，不是报告材料判断，而是“报告 agent 可查询的事实仓库”。

它需要满足：

- 无信息丢失：不因为正文暂时不用就丢弃原始证据细节。
- 单一入口：report agent 的工具默认只读它，不再混读多个中间层。
- 可追溯：每个 event、claim、object、gap 都能回到 observation/tool/source reference。
- 稳定 schema：后续 writer prompt 和 report agent tools 都依赖这份契约。

### 3.1.1 Source of Truth 与来源边界

`report_source_bundle` 不是从某一个旧中间层简单复制而来。第一版按以下优先级取数：

| Bundle 内容 | 权威来源 | 可辅助来源 | 说明 |
|---|---|---|---|
| seed / case 基础信息 | `incident.seed`、`incident_state.seed` | `report_outline.report_header` | 只做字段归一，不改写事实 |
| observations | `incident_state.observations` | `evidence_store.observations` | observation 是证据引用基础，必须尽量保留完整 tool result 摘要和 source refs |
| events / timeline | `incident_state.timeline`、`incident.cluster.events` | `evidence_store.confirmed_events/candidate_events` | 事件细节优先保留原始字段，派生 status 只作为附加字段 |
| objects / entities / scope | `incident_state.entities`、`incident_state.scope` | `evidence_store.objects`、`delivery_decision.confirmed_scope/candidate_scope` | 对象允许多角色，但报告范围角色必须单独标注 |
| claims / evidence ledger | `incident_state.evidence_ledger` | `evidence_store.claims` | claim 文本、relation、why/limit 若已有则保留，不新增 |
| gaps | `incident_state.gap_ledger` | `delivery_decision.blocking_gaps/non_blocking_gaps` | gap 原始问题来自 ledger，delivery 只补是否阻塞交付 |
| verdict / delivery | `analysis_verdict`、`delivery_verdict`、`delivery_decision` | `report_outline` | bundle 可以承载既有判断，但不得新增判断 |
| recommendations | `incident.recommendations` | `delivery_decision.next_best_questions`、旧 report contract | 只保留已有动作建议，不新编处置动作 |

重要边界：

- Bundle 可以承载调查阶段或交付阶段已经产生的判断，但每个判断字段都要带 `source_layer` 或能回到原字段。
- `delivery_decision` 是报告范围和交付状态的权威输入之一，可以用于确定 `confirmed_scope`、`candidate_scope`、delivery status、blocking/non-blocking gaps；这不是 bundle 新增判断，而是承载调查结束后的交付判断。
- Bundle builder 不新增“为什么重要”“意味着什么”“应怎么写”这类报告级分析。
- 如果同一事实在多个来源中表述不同，bundle 不直接合并成一个新结论，而是保留来源并在 `source_conflicts` 中记录。

### 3.2 建议字段

```json
{
  "schema_version": "report-source-bundle-v1",
  "case_header": {
    "title": "",
    "analysis_window": "",
    "seed_alert": {},
    "final_verdict": {},
    "delivery_status": "",
    "severity": "",
    "confidence": ""
  },
  "observations": [],
  "events": [],
  "claims": [],
  "objects": [],
  "scope": {
    "confirmed_assets": [],
    "candidate_assets": [],
    "seed_assets": [],
    "external_infrastructure": [],
    "background_objects": []
  },
  "timeline": [],
  "gaps": [],
  "counterevidence": [],
  "recommendations": [],
  "citations": {
    "observation_index": {},
    "event_to_observations": {},
    "claim_to_observations": {},
    "object_to_observations": {}
  },
  "appendix_inventory": {
    "ioc_available": true,
    "object_table_available": true,
    "observation_mapping_available": true
  },
  "source_conflicts": []
}
```

### 3.3 无损要求

代码生成 `report_source_bundle` 时：

- 不删除原始事件中的关键字段，例如 process、command、path、domain、ip、asset、classification、stage、description。
- 不把多个事件合并成一句不可回溯摘要。
- 不把候选对象升级为确认对象。
- 不写“为什么重要”“意味着什么”“应如何叙述”等报告判断。
- 可以做字段归一、索引、去重、排序、引用映射。

无损验收不是要求字段字节级完全一样，而是要求报告可能需要的事实细节不丢失。第一版用以下检查：

- `observations` 数量不低于 `incident_state.observations` 和 `evidence_store.observations` 中可用数量的较大者。
- confirmed/candidate/background event 的总数不低于现有 `evidence_store.confirmed_events + candidate_events`，且保留完整事件 id、时间、资产、对象、classification、stage、原始描述字段。
- object 数量不低于现有 `evidence_store.objects`，并保留 object value、type、所有已知 roles。
- gap 数量不低于 `incident_state.gap_ledger` 中非空 gap 数量，并保留 question/status/actionable/delivery 标记。
- 每条 event/claim/gap 若原先有 observation/source refs，bundle 中必须保留对应引用。

### 3.3.1 Source ID Namespace

`report_source_bundle` 必须使用稳定 ID 命名空间，避免 writer materials 里混用不可解释的 id。

建议：

```text
obs:<observation_id>
event:<event_id>
claim:<claim_id>
object:<object_id_or_value_hash>
gap:<gap_id>
action:<action_id>
verdict:<analysis|delivery>
```

规则：

- `source_ids` 可以混合多个 namespace，但每个 id 必须带 namespace 前缀。
- `report_writer_materials` 中推荐按用途拆分为 `supporting_event_ids`、`supporting_claim_ids`、`observation_ids`、`gap_ids`；通用 `source_ids` 只作为兼容字段。
- `submit_report_writer_materials` 只检查引用存在性和 namespace 合法性，不做语义硬编码判断。

### 3.3.2 对象角色表示

对象角色必须区分两类：

```json
{
  "object": "ws-eng-02",
  "all_observed_roles": ["seed_asset", "confirmed_asset"],
  "investigation_role": "seed_asset",
  "report_scope_role": "confirmed_affected_asset",
  "role_sources": ["object:...", "verdict:delivery"]
}
```

解释：

- `investigation_role` 描述它在调查流程里的角色，例如 seed asset、pivot candidate。
- `report_scope_role` 描述最终报告能如何写它，例如 confirmed affected asset、candidate asset、external infrastructure、background object。
- 同一对象可以既是调查锚点，又是已确认受影响资产；这不应视为冲突，但必须在字段上分开。
- 真正冲突是同一对象同时被标成 `confirmed_affected_asset` 和 `candidate_asset` 且来源无法解释，此时写入 `source_conflicts`。

### 3.4 与现有层的关系

第一版不需要立刻删除旧层。

- `incident_state` 仍是调查事实源。
- `evidence_store` 可以作为构造 `report_source_bundle` 的输入之一，但不是 report agent 直接入口。
- `delivery_decision` 可以进入 `case_header/scope/gaps`，但不单独暴露给 report agent。
- `report_fact_cards/report_polish_input/report_polish_brief` 暂时保留用于对比和回退。
- 新链路跑通并确认质量后，再考虑逐步替换旧 polished brief。

## 4. Report Agent 工具设计

### 4.1 工具原则

工具只做读取、切片和提交，不做语义判断。

允许工具：

- 返回 case overview。
- 按条件列出事件、claim、object、gap。
- 按 id 取详细证据。
- 返回对象角色矩阵。
- 返回核心或完整时间线。
- 提交 LLM 整理出的最终 materials。

禁止工具：

- 自动判断“这条证据最重要”。
- 硬编码攻击阶段含义。
- 根据关键词把事实升级为结论。
- 修改 `report_source_bundle`。

### 4.2 第一版工具清单

#### `get_case_overview`

返回：

- 标题、时间窗、seed alert 摘要。
- 最终结论、严重度、把握度。
- 已确认范围、待确认范围。
- 当前缺口和交付边界。

用途：

- 让 report agent 先理解本案大框架。

#### `list_source_items`

参数：

```json
{
  "item_type": "event|claim|object|gap|counterevidence|recommendation",
  "status": "confirmed|candidate|background|any",
  "limit": 20
}
```

返回：

- id、短摘要、状态、时间、对象、引用数量。

用途：

- 让 agent 判断还需要取哪类材料。

#### `get_source_details`

参数：

```json
{
  "ids": ["..."]
}
```

返回：

- 对应 item 的完整字段。
- 关联 observation/source refs。
- 原始事件细节。

用途：

- 给 agent 细读关键证据，整理 `evidence_argument_map`。

#### `get_scope_roles`

返回：

- seed asset。
- confirmed affected asset。
- candidate asset。
- core external infrastructure。
- related internal address。
- background object。

用途：

- 防止报告混淆调查锚点、受影响范围、外部基础设施和背景对象。

#### `get_timeline`

参数：

```json
{
  "mode": "core|with_candidates|full"
}
```

返回：

- 按时间排序的事件。
- 保留 status、classification、stage、asset、object、source refs。

用途：

- 让 agent 整理 narrative spine。

#### `get_gaps_and_boundaries`

返回：

- blocking gaps。
- non-blocking/reportable gaps。
- counterevidence。
- 每个 gap 关联的对象、问题、当前状态、是否影响交付。

用途：

- 让 agent 解释边界，而不是把缺口写成结论失败。

#### `submit_report_writer_materials`

参数：

```json
{
  "materials": {}
}
```

要求：

- 每个 claim/argument/action rationale 必须引用 source ids。
- 不允许引用 bundle 中不存在的 id。
- 不允许空 materials。

用途：

- 结束材料整理 loop，进入 writer。

## 5. Report Material Loop

### 5.1 Loop 定位

这个 loop 不继续调查，不查新日志，不改事实源。

它只回答：

```text
现有调查材料是否已经整理到足以写一份完整、可读、有判断力的 report？
如果没有，还需要从 source bundle 中取哪些材料？
```

### 5.2 每轮输入

每轮给 report agent：

- 当前 round index。
- 已收集的 `draft_materials`。
- 已调用工具历史。
- 可用工具列表。
- 固定写作目标和边界。

不直接给完整 `report_source_bundle`。

第一轮可以预加载最小上下文，避免把 loop 浪费在必需信息上：

- `get_case_overview`
- `get_scope_roles`
- `get_gaps_and_boundaries`

这些预加载结果计入 trace，但不计入 3 轮取材预算。

### 5.3 每轮输出

Report agent 每轮只能输出两类动作：

```json
{
  "action": "tool",
  "tool_name": "get_source_details",
  "params": {"ids": ["evt-1"]}
}
```

或：

```json
{
  "action": "submit",
  "materials": {}
}
```

### 5.4 停止条件

硬停止：

- 最多 3 个 reasoning rounds。
- 每个 reasoning round 最多 3 个只读工具调用。
- 最多 1 次 submit。
- 工具参数非法时最多重试 1 次。

语义停止：

- 已形成 `case_thesis`。
- 已形成 `narrative_spine`。
- 已形成 `evidence_argument_map`。
- 已形成 `scope_role_matrix`。
- 已形成 `counterarguments_and_boundaries`。
- 已形成 `action_rationale`。
- 每个判断都绑定 source ids。

如果材料不足，也必须 submit，但在 materials 中写明：

```json
{
  "reportable_limits": [
    "当前证据不足以支持完整说明具体载荷。"
  ]
}
```

## 6. `report_writer_materials` Schema

第一版 materials 建议：

```json
{
  "schema_version": "report-writer-materials-v1",
  "case_thesis": {
    "conclusion": "",
    "severity": "",
    "confidence": "",
    "confirmed_scope": [],
    "candidate_scope": [],
    "why_this_judgment_holds": "",
    "why_not_stronger_or_broader": "",
    "source_ids": [],
    "exact_fact_text": ""
  },
  "narrative_spine": [
    {
      "step_label": "",
      "summary": "",
      "source_ids": [],
      "reporting_role": "background|trigger|continuity|execution|lateral|scope|boundary",
      "exact_fact_text": ""
    }
  ],
  "evidence_argument_map": [
    {
      "claim": "",
      "supporting_event_ids": [],
      "supporting_claim_ids": [],
      "observation_ids": [],
      "source_ids": [],
      "exact_fact_text": "",
      "why_it_matters": "",
      "limitation": "",
      "recommended_sections": []
    }
  ],
  "scope_role_matrix": [
    {
      "object": "",
      "role": "",
      "may_be_written_as_affected": false,
      "how_to_write": "",
      "exact_fact_text": "",
      "source_ids": []
    }
  ],
  "counterarguments_and_boundaries": [
    {
      "point": "",
      "effect_on_judgment": "does_not_overturn|limits_scope|blocks_delivery|unknown",
      "explanation": "",
      "exact_fact_text": "",
      "source_ids": []
    }
  ],
  "action_rationale": [
    {
      "action": "",
      "why_this_action": "",
      "priority": "immediate|next|monitoring",
      "exact_fact_text": "",
      "source_ids": []
    }
  ],
  "section_briefs": [
    {
      "section_title": "",
      "writing_goal": "",
      "must_use_source_ids": [],
      "must_not_claim": []
    }
  ],
  "reportable_limits": []
}
```

材料要求：

- `exact_fact_text` 必须包含 writer 可直接使用的精确事实，例如时间、资产、域名/IP、进程、路径、动作等；不能只写“见 source id”。
- `exact_fact_text` 可以由 report agent 轻微中文化，但只能从 `get_source_details` 返回的 source detail 中抽取或拼接，不允许引入 source detail 外的新实体、新时间、新动作或新结论。
- `why_it_matters` 和 `explanation` 可以由 LLM 生成，但必须围绕 `exact_fact_text` 和 source ids，不得引入新事实。
- 如果 source bundle 里没有足够细节，materials 必须在 `reportable_limits` 说明，不允许靠泛化术语补齐。

## 7. Writer 生成逻辑

Writer 输入只包括：

- `report_writer_materials`
- 固定 Markdown 章节模板
- 风格与事实边界规则

Writer 不再直接读取：

- 完整 `incident.json`
- 完整 `evidence_store`
- 旧 `report_fact_cards`
- 旧 `report_polish_brief`

Writer 责任：

- 写成面向运维人员的中文 Markdown 报告。
- 保留判断、证据作用、范围边界、反证说明、后续动作。
- 不暴露内部工具名、workflow、reviewer、selector、readiness 等内部词。
- 不重复附录对象表和 IOC 表。

Writer 不负责再查证据，也不读取 source bundle。若 materials 缺少精确事实，writer 必须保守写边界，而不是自行补细节。

## 8. 验收方式

### 8.1 功能验收

跑当前 5 个复杂度足够的 case，输出：

- `report_source_bundle.json`
- `report_material_loop_trace.json`
- `report_writer_materials.json`
- `report_polished.md`

### 8.2 质量验收

人工对比旧 polished report，重点看：

- 是否更像分析师报告，而不是 fact card 改写。
- 是否解释了“为什么确认/为什么降级/为什么边界停在这里”。
- 是否保留关键证据细节。
- 是否减少对象角色混淆。
- 是否把反证写成边界解释，而不是简单一句“不足以推翻”。
- 是否能给出更具体的运维动作依据。

### 8.3 回归验收

至少检查：

- 不新增源材料中不存在的 IOC、资产、时间。
- `source_ids` 都能在 `report_source_bundle` 中找到。
- 候选对象不会被写成已确认受影响范围。
- 外部基础设施不会被写成受影响资产。
- 没有把 report agent 的 loop 过程写进最终报告。

## 9. 分阶段落地

### Phase 1: Source Bundle

新增 `report_source_bundle` builder。

任务：

- 新增模块，例如 `demo_agent/incidents/report_source_bundle.py`。
- 从 `incident_state` 优先取事实字段，并用 `evidence_store/delivery_decision` 补索引和交付判断。
- 输出 `report_source_bundle.json`。
- 不接入 writer，只先检查 bundle 是否包含现有 report 所需所有细节。

验收：

- 五个 case 都能生成 bundle。
- bundle 中事件、对象、gap、observation 引用数量不低于现有 `evidence_store`。

### Phase 2: Report Agent Tools

实现只读工具层。

任务：

- 新增模块，例如 `demo_agent/incidents/report_agent_tools.py`。
- `get_case_overview`
- `list_source_items`
- `get_source_details`
- `get_scope_roles`
- `get_timeline`
- `get_gaps_and_boundaries`
- `submit_report_writer_materials`

验收：

- 工具只读 bundle。
- 工具返回可控切片，不直接泄露完整大 JSON。
- submit 时检查 source id 是否存在。

### Phase 3: Material Loop

实现最多 3 轮的材料整理 loop。

任务：

- 新增模块，例如 `demo_agent/incidents/report_agent.py`。
- 写 report agent system prompt。
- 定义 JSON action schema。
- 保存 `report_material_loop_trace.json`。
- 生成 `report_writer_materials.json`。

验收：

- 五个 case 都能生成 materials。
- 每个 argument/action/scope role 都有 source ids。
- loop 不调用调查工具，不修改 source bundle。

### Phase 4: Writer 接入

让 polished writer 改为读取 `report_writer_materials`。

任务：

- 在 `render_incident_report_with_llm` 中通过 feature flag 接入新链路，例如 `use_report_agent_materials=True`；默认先关闭，专门用于新链路对比跑，不直接影响旧输出。
- 新 writer prompt。
- 保留旧 polished 路径作为 fallback。
- 输出新版 `report_polished.md`。
- 第一版只替换 polished report，不改变 deterministic `report.md` 和 `report_appendix.md`。

验收：

- 五个 case 都能生成 polished report。
- 与旧版相比，至少 3 个 case 在证据论证和范围边界上明显更好。

### Phase 5: 清理旧链路

在新链路稳定后再清理。

候选清理对象：

- `report_polish_input` 旧字段。
- `report_polish_brief` 旧 fact-card 入口。
- 与旧 writer 强绑定的 section fact map。

不在 Phase 1-4 清理，避免影响对比和回退。

## 10. 风险与约束

### 10.1 主要风险

- report agent loop 可能空转，只是不停取材料。
- LLM 可能在 materials 中做无引用判断。
- source bundle 可能名义无损，但实际遗漏某些旧 report 依赖字段。
- writer 可能过度相信 materials，把候选范围写成已确认范围。

### 10.2 控制方式

- loop 限制 3 轮。
- materials 必须带 source ids。
- source id 校验只做引用存在性，不做硬编码语义 validator。
- 保留旧链路作为 fallback。
- 每轮保存 trace，方便看 agent 为什么认为材料够了。

## 11. 不做什么

本计划明确不做：

- 不改调查 while loop。
- 不引入新的证据调查工具。
- 不让 report agent 访问网络或外部情报。
- 不用代码硬编码“某类行为一定代表某攻击阶段”。
- 不靠 validator 兜底报告质量。
- 不在第一版删除旧 report polished 链路。
- 不做单轮 materializer 作为替代路线；本计划的核心交付就是 bounded report material loop。
- 不在第一版引入 report reviewer 修订 loop，避免与材料整理 loop 混杂。

## 12. 预期效果

如果该方案成立，报告质量提升应该来自：

- writer 不再从半压缩 fact list 中自己拼报告。
- report agent 会先整理“证据如何支撑判断”的材料。
- 代码层保证材料可追溯，但不假装自己会做语义分析。
- 最终报告能更自然地解释判断过程，而不是只列事实。

最终目标不是让报告更长，而是让报告更像一个分析师对运维说：

```text
我们为什么认为这是事件；
哪些证据最关键；
影响范围为什么到这里为止；
哪些东西只是候选；
你现在应该先做什么。
```
