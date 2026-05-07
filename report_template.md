# Incident-Agent 调查型报告模板（V8）

## 1. 模板定位

这份模板把 `report.md` 定位为一份面向运维人员、安全运营分析人员和协同负责人的调查交付报告，而不是单条告警结果卡片，也不是调试日志。

V8 的核心变化是：**主报告不再由固定目录驱动，而由 `report_plan` 驱动，并由明确的 plan selection policy 收敛章节选择**。

也就是说，模板不规定每个 case 都必须输出完全相同的章节标题；模板规定：

- 一份合格报告必须回答哪些核心问题。
- 可使用哪些受控的 `section_type`。
- 每个 `section_type` 的职责边界是什么。
- report agent 如何基于调查材料生成 `report_plan`。
- writer 如何严格按照 `report_plan` 成文。
- plan check 如何约束结构稳定性，而不把 case-specific 语义判断写死在代码里。

这样做的原因是：`reference/report_reference` 的稳定性来自分析任务稳定，而不是标题完全固定。不同参考报告会根据 case 类型选择不同章节，例如路径拓扑、候选 ASN、公开背景或影响分析；它们真正一致的是每节都在回答一个不重叠的问题。

## 2. 交付产物分层

推荐保留四层产物：

- `report.md`：面向协同处置的主报告，强调结论、范围、证据判断、边界和动作。
- `report_appendix.md`：面向分析员的技术附录，承载 IOC/IOA、对象清单、观测引用、证据细目、缺口表和查询轨迹摘要。
- `report_source_bundle.json`：无损材料层，由代码从调查产物构建，只做索引、归档、去重和 source_id 绑定，不做语义判断。
- `report_writer_materials.json`：语义组织层，由 report material agent 基于 `report_source_bundle` 生成，包含 `report_plan` 和写作材料。

必须明确分工：

- 代码中间层只负责 `source_bundle` 的无损组织和引用校验。
- LLM report material agent 负责从 source bundle 中选择、组织、解释材料，并生成 `report_plan`。
- writer 只基于 `report_plan` 与 `report_writer_materials` 成文。
- validator 只做结构、引用存在性、对象角色越权和新增事实边界检查，不做 case-specific 语义硬编码。

## 3. 主报告必须回答的问题

无论章节如何动态实例化，主报告必须覆盖五类问题：

- 当前判断是什么。
- 为什么这起告警值得按事件调查。
- 已确认影响到哪里，哪些仍只是候选或背景。
- 当前判断主要站在哪些证据上，又被哪些缺口限制。
- 现在最值得先做什么。

首页摘要负责快速回答这些问题；正文负责让分析员能复核“事实 -> 解释 -> 边界”的证据链。

## 4. 设计原则

### 4.1 每个章节只回答一个问题

如果两个标题会迫使 writer 复述同一条事件链，就应该合并或删去其中一个。

每个计划章节必须有一个明确的 `question_to_answer`。writer 写作时只回答这个问题，不把相邻章节的任务顺手写进来。

### 4.2 事实、解释、边界必须分离

每条关键证据至少拆成三层：

- 事实：看到了什么。
- 解释：它为什么会改变判断。
- 边界：它不能单独证明什么。

报告最常见的问题不是缺事实，而是只列事实，不解释它对结论的作用。

### 4.3 对象角色必须显式交付

安全事件报告必须明确区分：

- 调查锚点 / seed asset。
- 已确认受影响资产。
- 待确认关联资产。
- 核心外部基础设施。
- 内部横向目标。
- 背景指标或替代解释对象。
- 扩展查询候选。

对象角色不清楚时，报告很容易把候选对象误写成已确认范围，或者把外部基础设施和内部横向目标混成一类。

### 4.4 正文承载判断，附录承载细节

主报告只保留能驱动判断和动作的信息。下列内容默认不直接写进 `report.md`：

- tool 名、workflow、prompt、reviewer、selector、readiness gate 等内部实现词。
- `observation_id`、source JSON、长日志、长网页正文。
- 大段 IOC 表、对象表、原始查询结果。
- 反复试错的查询过程。
- 过细的 JA3 / JA4 / DNS answers / 五元组字段。

这些内容应下沉到 `report_appendix.md`、`incident.json`、`evidence_store.json` 或 `investigation_trace.json`。

### 4.5 缺信息时保守，不补写

没有的数据直接省略，或显式写成：

- `当前未获取`
- `当前未观察到`
- `当前证据不足以支持`
- `当前只能作为候选线索保留`

不要为了填满章节而补写不存在的事实、动作、阶段或归因。

### 4.6 建议动作必须和结论状态匹配

不同状态下的建议语气不同：

- `confirmed_incident`：应给出处置、隔离、阻断、补采和复核动作。
- `needs_review`：应优先补强关键证据、验证候选、检查反证，避免直接定性过强。
- `monitor_only`：应偏向保留样本、监控复发、核实背景，不应一律隔离。

## 5. 首页摘要

首页摘要必须存在，建议固定为 8 行。它不是正文导语，而是处置入口。

```markdown
# 首页摘要
- **结论**：
- **严重度**：
- **研判把握**：
- **已确认范围**：
- **最强证据**：
- **关键缺口**：
- **立即动作**：
- **一句话结论**：
```

写作要求：

- 严重度和研判把握统一枚举：`高 / 中 / 低 / 未评估`。
- 已确认范围只写已确认受影响对象，不混入候选对象、外部基础设施或背景指标。
- 最强证据与关键缺口必须同时出现，避免只有结论没有边界。
- 立即动作必须可执行，避免写成“继续关注”“加强排查”这类空泛口号。

## 6. `report_plan` 设计

`report_plan` 是主报告的章节规划，由 **report material agent** 生成。它不是 deterministic renderer 硬编码出来的，也不是 writer 自己临场决定的。

### 6.1 为什么由 report material agent 生成

原因有三点：

- 章节选择是语义判断，需要理解 case 是否存在时序模式、传播范围、外部情报、反证或影响评估，代码硬编码很难泛化。
- writer 不应该同时负责选章节和写章节，否则很容易为了成文顺手增删标题或重复相邻章节。
- report material agent 已经负责整理材料，让它同时输出 `report_plan`，可以保证“材料组织”和“章节规划”一致。

### 6.2 生成流程

推荐流程如下：

```text
调查产物
  │
  ▼
代码构建 report_source_bundle
  │  只做无损索引、source_id、对象表、观测表、证据表、原始摘要
  ▼
report material agent loop
  │  通过只读工具查看 source_bundle
  │  判断哪些 section_type 必要
  │  整理 report_writer_materials
  │  生成 report_plan
  ▼
deterministic plan check
  │  只检查 schema、section_type 白名单、source_id 是否存在、章节数量上限
  │  不判断“这个 case 应不应该有某节”
  ▼
writer
  │  严格按 report_plan 输出 Markdown
  ▼
appendix appender / validation
```

### 6.3 `report_plan` schema

```json
{
  "schema_version": "report-plan-v1",
  "title": "面向读者的报告标题",
  "planning_rationale": "为什么本案采用这些章节，不写给最终读者",
  "sections": [
    {
      "section_type": "investigation_entry",
      "secondary_section_types": [],
      "title": "调查起点与已知线索",
      "question_to_answer": "为什么这起告警值得调查？",
      "mode": "full",
      "must_include": [],
      "must_not_repeat": [],
      "source_ids": [],
      "boundary_notes": []
    }
  ],
  "appendix_note": "技术细节、IOC/IOA、关键对象清单、观测引用、证据细目和待补缺口详见技术附录。"
}
```

字段说明：

- `section_type`：受控枚举，决定章节职责。
- `secondary_section_types`：可选字段，用于说明本节同时覆盖了哪些相邻职责；只允许在合并章节时使用。
- `title`：面向读者的标题，可根据 case 类型自然命名，但必须与 `section_type` 职责一致。
- `question_to_answer`：本节唯一要回答的问题。
- `mode`：`full / compact / boundary_only`。
- `must_include`：本节必须覆盖的 1 到 4 个事实或判断。
- `must_not_repeat`：本节不得重复的相邻章节内容。
- `source_ids`：本节可引用的材料来源。
- `boundary_notes`：必须保守表达的边界。

标题命名约束：

- 标题可以自然化，但必须保留 `section_type` 的分析职责。
- 标题不得把未确认结论写成已确认事实，例如不能把 `relationship_scope` 写成“已确认传播路径”。
- 标题应尽量包含职责关键词，例如“起点”“范围”“对象”“证据”“过程”“关联”“影响”“缺口”“结论”。

### 6.4 章节数量约束

建议主报告正文为 5 到 9 个章节，不含首页摘要。

允许少于 5 个章节的情况：

- case 极简单，且只有单点弱信号或 monitor_only 结论。
- 多个核心问题已经在同一章节中自然覆盖，强行拆分会重复。

不建议超过 9 个章节，除非本案同时具备复杂时间线、复杂传播、多类反证、拓扑或公开情报背景。

### 6.5 Plan selection policy

`report_plan` 的目标不是让标题尽量多，而是让核心问题被完整覆盖且不重复。report material agent 生成 plan 时应先判断当前结论状态，再决定章节组合。

#### `confirmed_incident` 默认 plan

确认事件通常需要解释闭环如何成立，以及处置动作为什么有必要。默认覆盖：

- `investigation_entry`
- `entity_roles`
- `evidence_judgment`
- `timeline_process`，仅当时间顺序能解释事件推进时使用。
- `relationship_scope`，仅当存在多资产、多指标或候选扩线时使用。
- `impact_assessment`，仅当已确认影响范围、业务风险或处置风险足够独立时使用。
- `counterevidence_limits`
- `conclusion_actions`

如果没有复杂扩线，`relationship_scope` 可不选；如果影响评估只是“确认资产 + 当前风险阶段”，可并入 `conclusion_actions` 或 `counterevidence_limits`，不必独立成章。

#### `needs_review` 默认 plan

待复核事件的核心是解释“为什么仍然可疑”和“哪个缺口会改变结论”。默认覆盖：

- `investigation_entry`
- `scope_hypothesis`
- `entity_roles`
- `evidence_judgment`
- `counterevidence_limits`
- `conclusion_actions`

只有在确实存在多对象扩线时才添加 `relationship_scope`；只有在时间顺序本身支持判断时才添加 `timeline_process`；只有在处置风险或业务风险需要单独解释时才添加 `impact_assessment`。

#### `monitor_only` 默认 plan

监控观察类报告应避免写得像已经成立的攻击事件。默认覆盖：

- `investigation_entry`
- `scope_hypothesis`
- `entity_roles`，可使用 `compact` 或与 `scope_hypothesis` 合并。
- `evidence_judgment`
- `counterevidence_limits`
- `conclusion_actions`

通常不选择 `impact_assessment`，除非需要说明为什么当前影响有限或为什么不建议处置升级。通常不选择 `timeline_process`，除非时序能明确支持“更像背景活动或弱信号”。

#### 核心问题覆盖，不等于核心章节全选

核心问题必须覆盖，但不要求每个核心 `section_type` 都独立成章。简单 case 可以用一个章节同时覆盖相邻职责，例如：

- `scope_hypothesis` 可通过 `secondary_section_types=["entity_roles"]` 同时交代简单对象角色。
- `counterevidence_limits` 可通过 `secondary_section_types=["impact_assessment"]` 说明“当前影响无法进一步确认”。
- `conclusion_actions` 可通过 `secondary_section_types=["impact_assessment"]` 写明处置影响和动作优先级。

### 6.6 条件章节互斥与合并规则

为避免重复，report material agent 应遵守以下选择规则：

- `relationship_scope` 与 `impact_assessment`：只有当“关联范围”和“影响/风险”都足够复杂时才拆成两节；如果只是说明已确认资产和候选资产，应优先使用 `relationship_scope`，把影响写成该节结尾或 `conclusion_actions` 的一部分。
- `timeline_process` 与 `evidence_judgment`：如果时间顺序只是证据事实的一部分，不单独选择 `timeline_process`；只有时序本身改变判断时才独立成章。
- `external_context_intel` 与 `investigation_entry`：如果外部情报只是 seed 背景或家族提示，放入 `investigation_entry`；只有外部情报会影响假设、反证或归因边界时才独立成章。
- `topology_path_analysis` 与 `relationship_scope`：如果只是简单 pivot 关联，使用 `relationship_scope`；只有存在路径、拓扑、AS、海缆、云/CDN 互联等结构性分析时才使用 `topology_path_analysis`。
- `scope_hypothesis` 与 `entity_roles`：简单单资产 case 可以合并；多资产、多基础设施、候选对象较多时应拆开。

### 6.7 Source id 粒度要求

`report_plan.sections[*].source_ids` 不应只引用一个过大的 bundle。为了减少泛写，每节应优先引用细粒度 source：

- 事实级 source，例如 `event:*`、`evidence:*`、`fact:*`。
- 对象级 source，例如 `object:*`。
- 缺口级 source，例如 `gap:*`。
- 判断级 source，例如 `verdict:*`。
- 动作级 source，例如 `action:*`。

只有在章节确实需要总览信息时，才引用 case overview 或 source bundle summary。writer 不应因为拿到一个大 source 就泛泛重写整案。

### 6.8 Plan 修订与 fallback 策略

如果 `report_plan` 没通过 deterministic plan check，应优先让 report material agent 修订，而不是直接 fallback。

推荐修订上限：

- 第 1 次失败：把 plan check 错误反馈给 report material agent，只允许修 schema、source_id、section_type 和明显重复章节。
- 第 2 次失败：要求压缩到稳定 plan，保留已通过校验且信息价值最高的章节。
- 第 3 次仍失败：使用最小安全 fallback plan。

fallback plan 应尽量保留原 plan 中已经通过校验的 high-value 条件章节。例如原 plan 中 `relationship_scope` 已通过 source_id 校验且本案存在多资产候选，不应无条件丢弃。

## 7. 受控 `section_type` 目录

### 7.1 核心 section_type

这些类型覆盖主报告必须回答的问题。核心问题必须被覆盖，但不要求每个核心类型都独立成章；简单 case 可通过 `secondary_section_types` 合并相邻职责。

#### `investigation_entry`

回答：为什么会有这份报告。

应写内容：

- Seed alert / 调查起点是什么。
- 初始异常命中了哪个资产、指标、规则、指纹或上游线索。
- 为什么这个命中值得继续调查。
- 公开背景或家族提示只能写成已知线索，不能写成最终归因。

不得写：

- 不展开完整事件链。
- 不列全量对象清单。
- 不提前写最终影响范围。

#### `scope_hypothesis`

回答：这轮调查准备证明什么、排除什么。

应写内容：

- 本轮调查范围，包括资产范围、时间窗口和核心 pivot。
- 主假设，例如异常外联是否与主机侧执行或横向动作构成同一事件链。
- 备选解释，例如共享基础设施、计划内维护、补丁窗口、正常组件、单点弱命中。
- 本轮不覆盖或尚不能确认的范围。

不得写：

- 不把假设写成已经确认的事实。
- 不把候选对象并入已确认范围。

#### `entity_roles`

回答：关键对象各自是什么角色，为什么调查到这些对象先停。

应写内容：

- 调查锚点。
- 已确认受影响对象。
- 待确认关联对象。
- 核心外部基础设施。
- 背景或替代解释对象。
- 当前覆盖边界。

不得写：

- 不只堆 IP / 域名 / 资产名。
- 不把待确认对象写入已确认范围。

#### `evidence_judgment`

回答：当前判断主要站在哪些证据上。

这是主报告最重要的章节。建议写成 2 到 4 个“厚证据块”，每块包含：

- 事实：具体看到什么。
- 判断作用：为什么它支持或削弱当前主假设。
- 边界：它不能单独证明什么。

证据块可覆盖：

- 调查触发证据。
- 持续性或复现证据。
- 主机侧执行、横向移动、外传等风险升级证据。
- 会直接改变判断的反向事实。

注意：这里只评价证据本身。不要在本节综合展开“因此最终只能到哪个结论边界”，结论边界交给 `counterevidence_limits` 或 `conclusion_actions`。

#### `conclusion_actions`

回答：最终判断是什么，接下来怎么做。

应写内容：

- 当前结论与状态。
- 为什么是这个状态，而不是相邻状态。
- 立即处置动作。
- 短期核查动作。
- 持续复核或监控动作。
- 下一轮最值得补的证据。

建议动作分层：

- **立即处置**：隔离、阻断、补采、账号/主机保护等高优先级动作。
- **短期核查**：验证候选对象、补主机侧证据、扩大时间窗、检查反证。
- **持续复核**：监控复发、复查同指标、沉淀检测规则。

### 7.2 条件 section_type

这些类型只有在材料确实支撑时才选择。不要为了“报告看起来完整”而硬写。

#### `timeline_process`

回答：事件如何推进，是否形成可解释的行为模式。

适用条件：

- 有至少 3 个决定性时间节点。
- 时间顺序本身会改变判断，例如先外联后执行、先利用后回连、先归档后上传。

应写内容：

- 起点。
- 推进。
- 模式。
- 未确认机制节点。

不得写：

- 不重复 `evidence_judgment` 的证据强度评价。
- 不把全部日志写成流水账。

#### `relationship_scope`

回答：事件如何扩线，哪些关联已经确认，哪些仍是候选。

适用条件：

- 存在多资产、多域名、多 IP、多 JA3/JA4、同证书、同基础设施或同账号扩线。
- 需要向读者解释为什么一些对象没有进入已确认范围。

应写内容：

- 扩线 pivot。
- 已确认关联。
- 待确认关联。
- 当前关联边界。

不得写：

- 不把共享 pivot 的弱关联写成已确认传播。

#### `impact_assessment`

回答：当前确认影响到哪里，风险体现在哪里。

适用条件：

- 已经存在可解释的影响范围、业务风险、数据风险、处置风险或攻击阶段判断。
- 对 `confirmed_incident` 或较复杂的 `needs_review` case 通常建议保留。

应写内容：

- 已确认受影响范围。
- 待确认影响范围。
- 核心外部基础设施范围。
- 当前已观测阶段或异常阶段。
- 当前不能确认的影响。

不得写：

- 没有执行、横向、外传等证据时，不得写成攻击阶段。
- 不把外部基础设施写成受影响资产。

#### `counterevidence_limits`

回答：当前结论被什么限制，哪些更强结论暂时不能写。

适用条件：

- 存在明显反证、替代解释、未闭合 gap，或当前状态是 `needs_review` / `monitor_only`。
- 对边界敏感的 case 应优先保留。

应写内容：

- 当前最强证据是什么。
- 是否存在反证或替代解释。
- 当前最关键缺口是什么。
- 缺口限制了哪条更强结论。
- 当前最多只能走到哪一层判断。

不得写：

- 不重新复述完整证据链。
- 不把“仍需进一步验证”复制到多个章节。

#### `external_context_intel`

回答：公开情报、内部情报或家族/基础设施背景如何帮助理解本案。

适用条件：

- 本案依赖公开报告、外部情报、家族提示、基础设施声誉或页面证据。
- 背景信息能解释风险，但不能替代本地事实。

应写内容：

- 背景来源类型。
- 它如何帮助解释本案。
- 它不能直接推出什么。

不得写：

- 不把家族提示写成强归因。
- 不把外部公开事件直接写成本案直接证据。

#### `topology_path_analysis`

回答：路径、拓扑、网络关系或基础设施结构如何支撑判断。

适用条件：

- case 涉及 AS 路径、拓扑关系、海缆、云/CDN 互联、网络路径或复杂基础设施结构。
- 有图、路径样本、关系图或结构化网络证据。

应写内容：

- 拓扑或路径观察。
- 它能支撑什么。
- 它不能直接推出什么。

不得写：

- 没有路径样本时，不得把结构关系写成实际流量路径。

## 8. `report_writer_materials` contract

`report_writer_materials` 至少包含：

- `case_header`：标题、分析窗口、事件标签、当前状态。
- `executive_summary`：结论、严重度、把握、已确认范围、最强证据、关键缺口、立即动作。
- `report_plan`：章节规划。
- `case_thesis`：主判断、为什么成立、为什么需要保守。
- `source_inventory`：本次可用 source_id 摘要。
- `entity_role_map`：对象、类型、角色、是否可写入已确认范围。
- `evidence_argument_map`：事实、解释、边界、source_ids。
- `timeline_spine`：决定性节点和判断作用。
- `relationship_scope`：已确认关联、候选关联、扩线边界。
- `impact_assessment`：已确认影响、疑似影响、当前已观测阶段或异常阶段。
- `counterevidence_and_limits`：反证、替代解释、缺口、判断上限。
- `recommended_actions`：立即、短期、持续动作。

`report_plan.sections[*].source_ids` 必须引用这些材料中的 source_id，而不能引用不存在的内部字段。

## 9. Plan check 与 validator 边界

### 9.1 可以做的 deterministic check

这些检查是合理的，因为它们不是 case-specific 语义硬编码：

- `report_plan.schema_version` 是否匹配。
- `section_type` 是否在白名单中。
- `secondary_section_types` 是否在白名单中，且没有和 primary `section_type` 冲突。
- `sections` 数量是否在合理范围内。
- `source_ids` 是否存在于 `source_inventory`。
- 是否至少覆盖核心问题：起点、范围或对象、证据、结论动作。
- 同一 `section_type` 是否重复。
- 是否存在明显可合并的重复章节，例如同一 section_type 被换标题写两次。
- 首页摘要字段是否齐全。
- 严重度 / 把握度是否使用固定枚举。
- 已确认范围是否只使用允许写入 confirmed scope 的对象。

### 9.2 不应该做的硬编码 check

这些判断应交给 report material agent 或人工 review，不应写成固定规则：

- 某个 case 名必须包含某个章节。
- 某个域名/IP 出现就必须定性为 C2。
- 某个工具调用次数达到阈值就必须写某个结论。
- 某个关键字出现就判定报告质量好或坏。
- 某个具体资产必须在第几节出现。

### 9.3 校验失败后的处理

如果 `report_plan` 校验失败，优先让 report material agent 在同一 loop 内修订 plan，修订策略遵循第 6.8 节。

如果多次修订仍失败，可以 fallback 到最小安全 plan：

- `investigation_entry`
- `entity_roles`
- `evidence_judgment`
- `counterevidence_limits`
- `conclusion_actions`

fallback plan 只保证报告可交付，不代表最佳结构。

## 10. Writer 规则

writer 只负责成文，不负责重新规划报告。

writer 必须遵守：

- 严格按 `report_plan.sections` 的顺序、标题和 section_type 输出。
- 不新增 `report_plan` 之外的正文标题。
- 不删除 `report_plan` 中已有章节。
- 每节只回答 `question_to_answer`。
- 优先使用 `must_include`，避免 `must_not_repeat`。
- 只能使用对应章节允许的 `source_ids` 和全局 materials。
- 不暴露 source_id、tool、workflow、reviewer、selector、material loop 等内部术语。
- 如果某节材料不足，按 `boundary_notes` 保守写，不补事实。

## 11. 附录模板

`report_appendix.md` 建议承载以下内容。

### 11.1 IOC / IOA 清单

| 类型 | 值 | 角色 | 状态 |
| -- | -- | -- | -- |
| IP |  | 核心外部基础设施 / 候选基础设施 / 背景指标 | 已确认 / 待确认 |
| 域名 |  |  |  |
| JA3 / JA4 |  |  |  |
| Hash / 文件 / 进程 |  |  |  |

### 11.2 关键对象清单

| 对象 | 类型 | 当前角色 | 是否已纳入证据链 | 备注 |
| -- | -- | -- | -- | -- |
|  | 资产 / 域名 / IP / 指纹 / 文件 / 账号 | 种子 / 已确认 / 待确认 / 背景 / 扩展候选 | 是 / 否 |  |

### 11.3 关键证据细目

每条证据保留：

- 证据编号。
- 证据类型。
- 证据类别。
- 证据强度。
- 事实描述。
- 为什么重要。
- 边界与限制。
- 主要依据来源。
- 观测引用。

### 11.4 观测引用对照

| 观测编号 | 来源 | 事实摘要 | 关系 |
| -- | -- | -- | -- |
| `obs-001` |  |  | `supporting` / `counterevidence` / `context` / `candidate` |

### 11.5 正文章节引用映射

| 正文章节 | section_type | 主要 evidence / observation | 用途 |
| -- | -- | -- | -- |
| 首页摘要 | summary |  | 当前状态 / 最强证据 / 关键缺口 |
|  | evidence_judgment |  | 主支撑证据 / 反证 |
|  | counterevidence_limits |  | 缺口 / 边界 |
|  | conclusion_actions |  | 结论 / 动作 |

### 11.6 证据来源与参考资料

| 来源类型 | 来源名称 | 用途 | 边界 |
| -- | -- | -- | -- |
| 上游检测 |  | 说明规则 / 指纹 / 模型为何触发 | 命中本身不自动等于事件成立 |
| 内部观测 |  | 支撑事实 | 仅覆盖本地可见范围 |
| 本地情报库 |  | 验证 IOC / 指纹 | 依赖库覆盖度 |
| 外部结构化情报 |  | 基础设施或家族补充 | 不能单独替代本地事实 |
| 外部网页 / 报告 |  | 背景解释 | 不等于本案直接证据 |

### 11.7 证据缺口与待补查询

| 缺口 | 限制的结论 | 当前是否可补 | 最值得补的查询 |
| -- | -- | -- | -- |
|  |  | 是 / 否 |  |

## 12. 生成约束

自动生成报告时必须遵守：

1. 只能基于已给材料，不得在成文阶段引入新事实、新对象、新时间、新动作、新阶段或新结论。
2. 首页摘要、正文判断和后续建议必须一致。
3. 每条关键判断都应能映射到 evidence / observation / source。
4. 证据必须同时包含事实、解释、边界三层。
5. `confirmed_incident`、`needs_review`、`monitor_only` 必须使用不同语气和动作类型。
6. 关键对象必须带角色，不允许只列值不说明角色。
7. 观测缺口必须显式交付，不允许只在结尾含糊说“仍有不确定性”。
8. 如果正文用了图、时间线、拓扑或统计图，必须给出“图示要点”和“不能直接推出什么”。
9. 如果某节没有可靠输入，可以短写边界，但不能补写。
10. 外部情报和公开报告只能作为背景、验证或解释，不能越权替代本地事件证据。
11. 建议动作必须可执行，且要与当前状态相匹配。
12. 严禁暴露 agent、tool、prompt、workflow、reviewer、selector、material loop 等内部实现细节。

## 13. 交付验收清单

交付前至少检查：

1. 首页摘要是否能快速看到当前状态、影响范围、最强证据、关键缺口和立即动作。
2. `report_plan` 中每个章节是否只回答一个问题。
3. 主报告是否明确区分已确认、疑似、待确认、背景指标和当前未获取。
4. 对象章节是否解释对象角色，而不是只列 IP / 域名 / 资产。
5. 证据章节是否写出了事实、解释、边界，而不是证据清单。
6. 过程、关联、影响章节是否只有在材料支持时才出现。
7. 反证与缺口是否说明限制了哪些更强结论。
8. 结论章节是否解释为什么是当前状态，而不是相邻状态。
9. 正文是否避免了内部实现词和调试轨迹。
10. 附录是否能把正文关键结论追溯到 observation / evidence / source。
11. 报告整体是否更像面向运维协同的调查交付，而不是面向开发调试的系统日志。

## 14. 从固定标题模板到 V8 的迁移建议

V6/V7 的固定或半固定标题可迁移为受控 `section_type`：

| 旧标题 | V8 section_type |
| -- | -- |
| 调查起点与已知线索 | `investigation_entry` |
| 调查范围与研判假设 | `scope_hypothesis` |
| 关键对象与角色边界 | `entity_roles` |
| 关键事实与证据判断 | `evidence_judgment` |
| 事件过程与行为模式 | `timeline_process` |
| 关联范围与候选边界 | `relationship_scope` |
| 影响分析与处置风险 | `impact_assessment` |
| 反证、缺口与结论边界 | `counterevidence_limits` |
| 结论与后续动作 | `conclusion_actions` |

最小可交付 plan 不追求标题多，而追求问题覆盖完整。复杂 case 再按材料添加条件章节。
