# Plan 11: Polished Report 交付层重构方案

## 0. 任务类型

按 `agent-development` 的分类，这一轮主要属于：

- `retrofit`
- `hardening`

重点不是继续改调查主循环，而是：

> **在不破坏调查部分正常运行的前提下，重构 polished report 的输入链路，让 LLM 更接近“基于事实写报告”，而不是“基于多轮摘要再写一次摘要”。**

---

## 1. 这一轮要解决什么问题

当前 `report_polished.md` 相比 deterministic `report.md`，可读性已经明显提升，但仍然存在两个根本问题：

1. **事实漂移**
   - 报告文风变好了，但偶尔会把时间、资产、IP、域名、动作关系重新拼错。
   - 这说明问题已经不主要是 prompt 不会写，而是上游写作输入已经被多轮 prose 加工。

2. **polish 输入链路过厚**
   - 当前链路大致是：
     - `evidence_store`
     - `report_inputs`
     - `ops_report_contract`
     - `report_polish_input`
     - `report_polish_brief`
     - `LLM`
   - 中间多层都在把事实重新组织成自然语言总结，导致 LLM 实际上吃到的是“总结过一次的话”，而不是统一的事实源。

这会带来：

- 报告主文容易写偏
- brief 过长、重复、token 浪费
- 难以区分“调查没查到”和“报告写歪了”
- 难以对 report 输出做自动校验

---

## 2. 这一轮的核心原则

### 2.1 只动交付层，不动调查层

这一轮默认不改：

- `incidents/agent.py` 的主调查 loop
- 工具执行与 observation 写回
- `reviewer.py` 的核心交付判断语义
- `evidence_store.py` 的主 schema 语义

即：

> **调查怎么跑先不动，只改调查结束后“如何组织成 polished report 输入”。**

### 2.2 引入单一写作事实源

polished report 不再优先吃多层 prose contract，而是优先吃一层统一的：

- `canonical fact cards`
- `verdict packet`
- `scope packet`
- `constraint packet`
- `action packet`

### 2.3 先保证稳定，再考虑更复杂的写作流程

先做：

- 更薄的写作输入
- 生成后校验
- fallback

再决定是否需要：

- 分节生成
- 多轮 rewrite
- 更复杂的 writer/reviewer 写作链

### 2.4 单一事实源必须有明确优先级

polished report 的事实优先级固定为：

1. `report_fact_cards.json` + packets
2. deterministic `report_outline` / appendix（仅用于 fallback 渲染）
3. 旧版 `report_polish_input / brief`（仅用于回滚，不再与 v2 混用）

约束：

- 同一次 polished render 只能基于一套事实源生成正文
- 旧 prose contract 可以保留作对照，但不得再回流进 brief v2
- 任何 fallback 都必须显式记录来源，避免“新链路写一半、旧链路补一半”

---

## 3. 当前问题定位

### 3.1 当前不是 prompt 不够强

当前 prompt 已经足够接近生产级，问题不在“不会约束结构”，而在：

- 输入里已经有太多被解释过的 prose
- 同一事实在 `Narrative Spine`、`Evidence Anchors`、`Scope Packet`、`Ops Packet` 里重复出现
- LLM 需要在多份总结之间重新组织正文

### 3.2 当前不是字段不够多

继续加字段只会让 `report_polish_input` 更厚。

真正的问题是：

> **缺少一层统一、最小、可校验的写作事实卡片。**

### 3.3 当前最需要优化的是 `render.py` 后半段

这轮的主战场是：

- `build_report_polish_input()`
- `build_report_polish_brief()`
- `render_incident_report_with_llm()`

而不是调查 loop 本身。

---

## 4. 改动边界

### 4.1 本轮优先修改的文件

- `demo_agent/incidents/render.py`
- `demo_agent/entrypoints/langchain_agent.py`
- 新增 `demo_agent/incidents/report_fact_cards.py`
- 新增 `demo_agent/incidents/report_polish_validator.py`（如需要）

### 4.2 本轮默认不动的文件

- `demo_agent/incidents/agent.py`
- `demo_agent/incidents/reviewer.py`
- `demo_agent/incidents/evidence_store.py`
- `demo_agent/incidents/report_inputs.py`
- `demo_agent/incidents/report_render.py`

只有在实现 fact cards 时发现 `evidence_store` 缺少某些关键原子事实，才考虑最小补充。

### 4.3 最小补充升级规则

为避免这轮又演变成“顺手重构调查层”，补一条明确规则：

1. 优先从 `evidence_store + delivery_decision` 做只读派生
2. 若某事实已存在于现有运行产物中，但 `evidence_store` 没有显式暴露，允许在 `report_fact_cards.py` 内做 deterministic 派生
3. 若某关键事实根本不存在，只能在 `constraint_packet` / gap card 中标记为未确认，不能在 report 层补写
4. 只有当同类缺口在多个保留 case 中反复阻塞 polished report，才回头最小补充 `evidence_store` schema

---

## 5. 目标架构

### 5.1 当前链路

```text
evidence_store
  -> report_inputs
  -> ops_report_contract / report_outline
  -> report_polish_input
  -> report_polish_brief
  -> LLM
  -> report_polished
```

问题：

- 中间多层都在把事实写成 prose
- 同一事实被重复展开
- 没有一层统一事实源供 writer / validator / appendix 共用

### 5.2 目标链路

```text
evidence_store + delivery_decision
  -> canonical fact cards
  -> concise writer brief v2
  -> LLM
  -> post-polish validator
  -> report_polished
```

这意味着：

- `fact cards` 成为 polished 的唯一事实输入
- `brief v2` 只负责写作编排，不再承担事实层表达
- validator 负责拦截细节漂移

### 5.3 canonical fact cards 契约

`fact cards` 的职责是承载“可核对事实”，而不是再生成一层 narrative prose。

公共必填字段：

- `fact_id`
- `fact_type`: `event` / `scope` / `gap` / `counterevidence` / `action_basis`
- `status`: `confirmed` / `candidate` / `blocked` / `background`
- `summary_line`: 单行 deterministic 事实陈述，不写段落
- `evidence_refs`: 关联的 `observation_id` / `evidence_id`

按类型负载的最小字段：

- `event`
  - `time`
  - `subject`
  - `action`
  - `object`
  - `qualifiers`（可选）
- `scope`
  - `entity`
  - `role`
  - `scope_status`
- `gap`
  - `question`
  - `blocking_effect`
- `counterevidence`
  - `claim`
  - `impact`
- `action_basis`
  - `recommended_action`
  - `priority`

禁止事项：

- 不在卡片里写整段解释性 prose
- 不把同一事实换说法重复写多次
- 不把未确认推断升级成 `confirmed`
- 不让 `why_it_matters` 之类的大段解释重新变成新的 summary 层

### 5.4 packet 契约

为了让 writer 既能写结论，也知道“为什么只能写到这里”，packet 至少分为：

- `verdict_packet`
  - `severity`
  - `confidence`
  - `conclusion_statement`
  - `supporting_fact_ids`
- `scope_packet`
  - `confirmed_entities`
  - `candidate_entities`
  - `supporting_fact_ids`
- `constraint_packet`
  - `blocking_gaps`
  - `counterevidence`
  - `boundary_statement`
  - `supporting_fact_ids`
- `action_packet`
  - `immediate_actions`
  - `next_steps`
  - `supporting_fact_ids`

packet 允许有简短解释，但所有判断都必须能回指到 `fact_id`，不能脱离卡片自成一套 prose 事实源。

---

## 6. 执行步骤

### Phase 1: 新增 canonical fact cards

目标：

- 不改变现有 report 产物
- 先把 polished 所需事实统一抽成一层新产物

计划：

1. 新增 `demo_agent/incidents/report_fact_cards.py`
2. 从 `evidence_store + delivery_decision` 构建：
   - `report_fact_cards.json`
   - `verdict_packet`
   - `scope_packet`
   - `constraint_packet`
   - `action_packet`
3. 明确区分：
   - 原子事实卡：给 writer / validator / appendix 共用
   - packet：给 writer 提供结论边界、范围边界、行动边界
4. 在 `entrypoints/langchain_agent.py` 中把这份新产物落盘
5. Phase 1 结束标准：
   - 不改现有 `report.md`
   - 只新增事实产物
   - 至少 1 个复杂 case 上人工检查：可以仅靠 fact cards + packets 解释“发生了什么、确认到哪、为什么停在这”

本阶段不替换现有 polished 流程。

### Phase 2: 重写 polished brief v2

目标：

- 去掉多层 prose 重复
- 让 LLM 优先基于 fact cards 写正文

计划：

1. 改 `build_report_polish_input()`
   - 不再优先从 `ops_report_contract` 摘大量 prose
   - 改为围绕 fact cards + packets 组 brief
   - 生成 `section_fact_map`，为每个章节提供允许引用的 `fact_id` 子集
2. 改 `build_report_polish_brief()`
   - 缩短长度
   - 去重
   - 保留结构约束，但尽量减少重复事实
   - 明确把“固定写作指令”和“本次 case 事实材料”分层
3. `brief v2` 只保留三类内容：
   - 固定写作约束
   - packet 摘要
   - 分章节 `fact_id` 引用列表与少量必要说明
4. 不再保留 `Narrative Spine` 这种长段事实转述作为主输入
5. 文件名默认仍沿用 `report_polish_input.json` / `report_polish_brief.md`，但内部加 `schema_version`

### Phase 3: 增加 post-polish validator

目标：

- 拦截正文里的事实错配
- 把“文风问题”和“事实问题”分开

计划：

1. 新增 `report_polish_validator.py`
2. 对 LLM 输出做 lightweight 校验：
   - 时间是否存在
   - 资产是否存在
   - IP / 域名是否存在
   - 动作关系是否属于允许事实集
   - confirmed / candidate 是否越界
3. validator 输出分级结果：
   - `hard_fail`
     - 不存在的实体 / 时间 / IP / 域名
     - 不存在的 `时间-主体-动作-对象` 组合
     - 把 `candidate` 写成 `confirmed`
     - 超出 `scope_packet` / `constraint_packet` 的确定性结论
   - `soft_warn`
     - 表达偏笼统
     - 轻度重复
     - 某节信息偏薄但未引入新事实
4. 恢复策略固定为：
   - 先做 1 次定向 section rewrite，只喂该节允许的 `fact_id`
   - 若仍 `hard_fail`，只回退该 section 到 deterministic 段落
   - 仅当多个核心章节连续 `hard_fail` 或模型调用失败时，才整篇回退
5. validator 默认先以 `warn + artifact` 方式上线，稳定后再打开强制 section fallback

### Phase 4: 评估是否需要 section-wise generation

目标：

- 仅当单次整篇生成仍然不稳时，再增加生成控制

计划：

1. 观察 Phase 1-3 后的稳定性
2. 若仍然频繁串线，再改为：
   - 第 1~10 节按节喂不同 fact card 子集
   - 附录继续 deterministic

这一步不是默认立即做。

---

## 7. 输出产物变化

### 7.1 新增产物

- `report_fact_cards.json`
- `report_polish_validation.json`

### 7.2 保留的旧产物

- `report.md`
- `report_appendix.md`
- `report_polish_input.json`
- `report_polish_brief.md`
- `report_polished.md`
- `report_polish_error.txt`

### 7.3 schema 与迁移策略

- `report_polish_input.json` 保留原文件名，但升级为 v2 schema
- v2 输入必须显式记录：
  - `schema_version`
  - `source_mode`（`fact_cards_v2` / `legacy_fallback`）
  - `fact_card_count`
  - `packet_refs`
- 旧版 builder 保留在代码里作为回滚路径，但默认不再额外落一份 legacy artifact，避免产物膨胀

### 7.4 兼容策略

- deterministic report 继续保持现状
- polished report 新链路若失败，可回退到：
  - section 级 deterministic 内容
  - 或旧链路整体回滚
- 但同一次生成中不得混用新旧 prose 输入

---

## 8. 验收标准

### 8.1 功能层

- 调查主循环行为不变
- `report.md` 继续正常生成
- `report_polished.md` 继续可以生成
- 新增 `report_fact_cards.json`

### 8.2 质量层

- polished report 在 5 个 case 上 `hard_fail` 为 0
- unsupported 的 `时间-主体-动作-对象` 组合数为 0
- brief token 规模相对当前基线至少下降 30%
- 同一 canonical fact 在 brief 中的重复引用显著减少
- 附录与主报告的事实一致性提升
- 若触发 fallback，优先局部 section fallback，而不是整篇退回

### 8.3 验证层

- 至少在当前保留的 5 个 case 上重跑验证
- 对比：
  - `report.md`
  - `report_polished.md`
  - `report_fact_cards.json`
  - `report_polish_validation.json`
  - validator 命中情况
- 人工抽查重点看：
  - 首页摘要是否闭合
  - 事件机制分解是否真正引用了关键事实
  - 影响分析与范围边界是否没有越界
  - 证据链摘要是否能说明“为何确认 / 为何未确认”

---

## 9. 风险与回滚

### 风险

1. fact cards 抽取得过薄，导致 writer 信息不够
2. brief v2 太短，导致主报告变得空泛
3. validator 规则过严，误伤正常表达
4. packet 解释过长，重新长成新的 prose summary 层

### 回滚策略

1. 保留现有 deterministic report 链路不动
2. 保留旧的 `report_polish_input / brief` 构建逻辑，必要时切回
3. validator 先只做 warning / log，确认稳定后再做强约束 fallback
4. 若 `fact cards` 无法覆盖关键 case，再先补契约而不是立刻增加更多 summary 字段

---

## 10. 实际落地顺序

1. 先实现 `report_fact_cards.json`
2. 跑一个 case，人工检查 fact cards 是否覆盖够用
3. 再接入 polished brief v2
4. 再加 validator
5. 跑 5 个保留 case 横向对比
6. 只有当 `hard_fail` 已基本清零后，再决定是否继续推进 section-wise generation
7. 若 Phase 1-3 已明显改善，则优先继续打磨 brief / prompt，而不是立刻增加更复杂生成工作流

---

## 11. 一句话目标

这一轮不是“继续靠 prompt 打补丁”，而是：

> **把 polished report 从“基于多轮摘要写作”改成“基于统一事实卡写作”，并用 validator 兜住事实一致性。**
