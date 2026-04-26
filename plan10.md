# Plan 10: Incident-Agent 架构重整方案

## 0. 任务类型

按 `agent-development` 的分类，这一轮主要属于：

- `retrofit`
- `hardening`
- `review`

这不是继续补模板、补字段、补 case 的局部修修补补，而是先处理当前系统最根本的架构问题：

> **控制循环、证据真相源、交付判断、报告生成被混在了一起。**

---

## 1. 为什么现在必须先做架构优化

过去几轮里我们已经做过：

- 调查流程优化
- LLM 决策接入
- 双 agent 思路讨论
- 报告模板优化
- case 扩充
- report 可读性优化

但问题还是反复出现，原因不是“还差一条规则”，而是系统底层边界没有切干净。

当前最典型的症状有 4 个：

1. `agent.py` 和 `render.py` 过大，主循环、策略、状态、渲染全部耦合。
2. `incident` 大对象承载了过多职责，既是调查态，又是交付态，还是报告态。
3. 为了解决局部问题，系统越来越依赖补字段、补 contract、补 reader-facing 文案兜底。
4. 看起来 report 在变好，但其中一部分改善来自 renderer 的补救，而不是调查链本身真的更健康。

所以这一轮的目标不是“继续让输出更像参考报告”，而是：

> **先把内部运行架构整理到一个可持续优化的状态。**

---

## 2. 这一轮遵循的架构原则

这里直接吸收 `agent-development` skill 中最相关的思路。

### 2.1 一个显式主循环

保留一个清晰的主循环：

`state snapshot -> model decision -> tool call -> write-back -> continue/stop`

不要把主转移逻辑隐藏到多个不相关的大函数和 fallback contract 中。

### 2.2 工具面与业务编排分离

工具层只负责：

- 明确 schema
- 执行确定性逻辑
- 返回结构化结果

不要让工具 hint、gap hint、reader hint、报告 hint 一起演化成半硬编码 workflow。

### 2.3 单一真相源

调查阶段只能有一个主要事实存储层。

不能再长期并存：

- `report_outline`
- `report_contract`
- `main_report_contract`
- 其他 reader-facing 派生层

否则任何一个层都可能重新长成“第二真相源”。

### 2.4 接受判断与执行分离

“是否可以交付”不应该由调查 agent 在调查过程中顺手决定，更不应该由 report renderer 反向补出。

要把：

- 调查推进
- 交付审查
- 主报告生成

分成三个不同责任层。

### 2.5 先稳住边界，再增加 autonomy

在架构没整理干净之前，不继续：

- 扩大 LLM 决策范围
- 引入更复杂的双 agent 互相调用
- 增加更多字段和流程开关

---

## 3. 当前系统的核心问题

### 3.1 调查、交付、报告三种语义混杂

当前系统至少混了三种本应分开的语义：

- 调查语义：当前查到了什么，还缺什么，下一步查什么
- 交付语义：现有证据是否足以稳定交付
- 报告语义：运维/SOC 读者应该看到什么、不应该看到什么

这会直接导致：

- 调查态字段渗透到主报告
- 交付态结论和分析态结论互相打架
- renderer 被迫承担大量补救工作

### 3.2 多头真相源

现在同一份事件信息会在多个层里重复出现：

- `incident`
- `report_outline`
- `main_report_contract`
- `analysis`
- `delivery_readiness`
- appendix/reader 相关派生层

这样的问题不是“字段多”本身，而是：

> **任何一层都可能重新变成逻辑入口。**

### 3.3 代码主导的 workflow 痕迹过强

尽管已经引入了 LLM 决策，但目前系统里仍有大量“先定义 gap，再映射 capability，再筛工具，再跑默认动作”的代码控制痕迹。

这不是说这些逻辑都错，而是说明：

> 当前 LLM 更多是在一个被代码高度约束的轨道里选动作，而不是在一个边界清晰的 agent loop 中推进调查。

### 3.4 renderer 承担了过多“修复上游”的职责

当前报告层存在很多 reader-facing 文本清洗、改写、语义补丁，这对主报告可读性有帮助，但也带来一个副作用：

如果上游状态设计不干净，renderer 会不断变成“最后一道补洞层”。

这会让问题看起来被修好了，实际上只是被下游掩盖了。

---

## 4. 总体目标

Plan 10 的总目标是把 incident-agent 重新整理成一个**四层主链路 + 一层基础工具面**的结构。

### 4.1 基础工具面

负责：

- 工具注册
- schema
- 参数校验
- 权限
- 结果整形
- provenance 注入

### 4.2 调查层 `investigator`

负责：

- 读取当前调查状态
- 判断下一步应该做什么
- 调用工具
- 把结果写回证据层
- 在预算内推进或停止

不负责：

- 决定最终是否可交付
- 直接生成读者报告

### 4.3 证据层 `evidence store`

这是单一真相源。

只保存：

- observations
- entities / objects
- claims
- hypotheses
- gaps
- provenance
- confirmed / candidate boundary

不保存：

- 主报告文案
- reader-facing 兜底文本
- 多份平行 report contract

### 4.4 审查层 `reviewer / acceptance`

负责：

- 判断是否可交付
- 判断当前最合适的交付级别
- 判断哪些对象可写入 confirmed scope
- 判断哪些 gap 阻塞交付
- 判断 investigator 是否进入重复、低价值、无进展循环

### 4.5 报告层 `report pipeline`

负责：

- 从审查通过后的交付结果中提取可对外表达的内容
- 生成主报告 contract
- 生成技术附录 contract
- 渲染 Markdown

主报告和技术附录彻底分层，不再共享一份混杂对象。

### 4.6 第一阶段的唯一硬目标

为了避免方案看起来很完整，但落地时再次发散，第一阶段先只冻结一个硬目标：

> **主报告渲染链不再直接读取大 `incident` 对象，而只读取 `EvidenceStore + DeliveryDecision`。**

这条边界成立之前，其他优化都不算真正进入新架构。

---

## 5. 目标架构草图

```text
entrypoint
  -> run session
  -> investigator loop
       -> tool plane
       -> evidence store write-back
  -> reviewer / acceptance
  -> report contract builder
  -> render main report + appendix
```

### 5.1 Investigator 的输入

- seed alert
- runtime budget
- current evidence store snapshot
- current open gaps
- allowed tool registry
- session history summary

### 5.2 Investigator 的输出

不是 report，也不是最终结论，而是：

- updated evidence store
- session event log
- tool call log
- progress markers
- stop reason

### 5.3 Reviewer 的输入

- evidence store
- session trace summary
- stop reason
- current runtime budget usage

### 5.4 Reviewer 的输出

建议冻结成一个独立结构，例如：

`DeliveryDecision`

包含：

- `approved: bool`
- `delivery_status`
- `confidence_band`
- `confirmed_scope`
- `candidate_scope`
- `blocking_gaps`
- `non_blocking_gaps`
- `next_best_questions`
- `reviewer_rationale`
- `insufficient_progress_signals`

### 5.5 Report pipeline 的输入

只允许读取：

- `EvidenceStore`
- `DeliveryDecision`

不允许直接从 investigator runtime 中抽取任意字段拼 report。

---

## 6. 推荐的数据边界

我建议把当前的大 `incident` 对象拆成 4 个核心对象。

## 6.1 `SessionLog`

用途：

- append-only 记录运行过程
- 支持 replay / debug / eval
- 记录为什么继续、为什么停止

包含：

- user intent / seed
- model decision
- tool call
- tool result
- permission decision
- state transition
- retry / stop / reviewer verdict

## 6.2 `RuntimeState`

用途：

- 当前运行时控制
- 当前预算
- 当前轮次
- 当前可见工具集
- 去重与重复动作检测

这是运行时态，不是事实真相源。

## 6.3 `EvidenceStore`

用途：

- 唯一事实真相源

推荐字段：

- `observations`
- `objects`
- `claims`
- `hypotheses`
- `gaps`
- `coverage`
- `candidate_events`
- `confirmed_events`
- `provenance_index`

### 6.3.1 `EvidenceStore` 的严格约束

为了避免 `EvidenceStore` 变成新的大杂烩，需要提前冻结语义边界。

#### A. 原始事实层

只能包含：

- 工具直接返回的 observation
- 事件/对象归并结果
- 时间、实体、指示物、来源、引用关系

禁止包含：

- reader-facing 文案
- 主报告句子
- “建议立即动作”这类交付表述

#### B. 派生判断层

可以包含：

- `claims`
- `hypotheses`
- `open_gaps`
- `candidate_scope_signals`

但必须满足：

- 每条派生判断都有 provenance
- 能回溯到 observation / claim
- 允许被 reviewer 驳回或降级

#### C. 禁止直接写入的交付语义

以下内容不应由 investigator 直接写进 `EvidenceStore` 作为最终真相：

- `approved`
- `delivery_status`
- `confirmed_scope`
- 最终主报告结论

这些必须来自 reviewer 的 `DeliveryDecision`。

## 6.4 `DeliveryDecision`

用途：

- 交付判断单据

它是 reviewer 的产物，不是 investigation loop 在调查中途随手写出来的附属字段。

### 6.4.1 `DeliveryDecision` 的严格约束

`DeliveryDecision` 必须满足下面三条：

1. investigator 可以提出候选判断，但不能直接写最终 `approved` 结果。
2. `confirmed_scope` 只记录已批准可对外交付的范围，不承载“可能受影响但仍待查”的对象。
3. `blocking_gaps` / `non_blocking_gaps` 必须能回溯到 `EvidenceStore.gaps`，不能是纯文案层凭空生成。

---

## 7. 推荐的模块拆分

这一部分直接对应 repo。

### 7.1 当前建议保留并复用的模块

以下模块是比较适合保留并继续承接职责的：

- [demo_agent/incidents/store.py](/home/estar0x/project/maltrail_test/Trace-Agent/demo_agent/incidents/store.py)
  适合作为 trace/evidence 输入层继续复用
- [demo_agent/incidents/contracts.py](/home/estar0x/project/maltrail_test/Trace-Agent/demo_agent/incidents/contracts.py)
  适合作为基础 contract/utility 层
- [demo_agent/incidents/pipeline.py](/home/estar0x/project/maltrail_test/Trace-Agent/demo_agent/incidents/pipeline.py)
  可以保留一部分通用事件整形能力

### 7.2 当前建议拆解的模块

以下两个文件是当前最大的耦合源：

- [demo_agent/incidents/agent.py](/home/estar0x/project/maltrail_test/Trace-Agent/demo_agent/incidents/agent.py)
- [demo_agent/incidents/render.py](/home/estar0x/project/maltrail_test/Trace-Agent/demo_agent/incidents/render.py)

目标不是“马上完全删掉”，而是把职责往外迁。

### 7.3 建议新增的模块边界

建议逐步引入以下文件：

- `demo_agent/incidents/runtime.py`
  运行时预算、重复检测、loop 控制

- `demo_agent/incidents/evidence_store.py`
  单一真相源定义与 write-back

- `demo_agent/incidents/investigator.py`
  investigator loop 与 action selection

- `demo_agent/incidents/reviewer.py`
  交付审查与 acceptance

- `demo_agent/incidents/report_contracts.py`
  从 `EvidenceStore + DeliveryDecision` 派生 `ops_report_contract` 与 `appendix_contract`

- `demo_agent/incidents/report_render.py`
  只做 Markdown 渲染，不再做调查态推理和大量补洞

### 7.3.1 模块引入顺序

这里要明确：

> **先拆状态边界，再拆文件边界。**

第一阶段不追求把所有目标文件一次性建齐。

更合理的顺序是：

1. 先引入 `evidence_store.py`
2. 再引入 `reviewer.py`
3. 再引入 `report_contracts.py`
4. 最后再拆 `investigator.py` / `runtime.py`

这样做的原因是：

- 如果先拆很多文件，但底层仍共用旧 `incident` 大对象，只是“搬家”，不是重构
- 先把主状态边界冻结，后续文件拆分才不会继续复制旧复杂度

### 7.4 入口层保持轻量

[demo_agent/entrypoints/langchain_agent.py](/home/estar0x/project/maltrail_test/Trace-Agent/demo_agent/entrypoints/langchain_agent.py)

未来应该只负责：

- 读取输入
- 初始化依赖
- 启动 session
- 调 investigator
- 调 reviewer
- 调 report pipeline
- 写出 artifacts

不要继续把复杂控制塞回 entrypoint。

---

## 8. 程序与模型的职责边界

这一部分必须提前写清楚，否则后面 investigator 很容易重新变成“代码 workflow”或“完全放飞”。

### 8.1 程序负责什么

程序层负责稳定性与边界控制：

- 工具注册与 schema 校验
- 参数标准化
- permission / budget / step limit
- 结果 write-back
- provenance 记录
- 重复动作检测
- 明确的 hard stop 条件
- reviewer 调用时机

### 8.2 模型负责什么

模型层负责真正需要判断的部分：

- 当前最值得推进的问题是什么
- 在可用工具中下一步应该查什么
- 如何解释多条证据之间的关系
- 当前哪些 gap 更值得优先补查
- 在多个合理动作中如何排序

### 8.3 第一阶段不交给模型的内容

第一阶段明确不把下面这些交给模型自由决定：

- budget 扣减规则
- 工具权限
- 重复动作 hard stop
- artifact 写出逻辑
- 最终 report 输入边界

### 8.4 Reviewer 也不能变成隐藏 workflow engine

reviewer 可以提出：

- 阻塞点
- 缺口优先级
- 低价值重复动作信号

但不能在第一阶段直接演化成：

- 一套新的工具编排器
- 第二个自由调查 agent
- 用大量 case-specific 规则强行约束 investigator

---

## 9. 关于双 agent 的明确方案

这一轮不建议做“两个都能自由查”的松散双 agent。

更稳的方案是：

### 9.1 主体形态

- `Investigator`: 负责调查推进
- `Reviewer`: 负责交付审查

### 9.2 交互方式

优先采用 `manager + evaluator-as-tool` 结构，而不是 handoff。

原因：

- 最终还是需要一个统一主控来生成最终交付
- reviewer 不应该接管用户交互
- reviewer 更像 acceptance layer，而不是第二个主调查者

### 9.3 Reviewer 的权限边界

第一阶段 reviewer 建议默认只读，不直接调用调查工具。

它只输出：

- 是否批准交付
- 是否存在阻塞 gap
- 是否存在重复动作/无效推进
- 最值得继续追问的问题

这样可以先把“判断边界”立住，避免系统复杂度再次爆炸。

### 9.4 后续演进

只有在第一阶段稳定后，才考虑 reviewer 是否可以建议更细粒度的 tool suppression 或 action veto。

即使后面加，也应该是：

- reviewer 提建议
- manager 决定是否执行

而不是 reviewer 自己变成第二个自由 agent。

---

## 10. 分阶段迁移方案

这一轮不做大爆炸重写，分 4 步迁移。

## 10.0 迁移前的基线冻结

在进入正式重构前，先冻结一组最小基线：

- 当前 fixture 集
- 当前主报告输出
- 当前附录输出
- 当前 open-loop trace

目的不是把今天的结果当“完美真相”，而是为了保证：

- 后续架构改动时能对比行为是否退化
- 不会因为重构而悄悄失去已有能力

## 10.1 第一阶段：冻结边界与 contract

目标：

- 冻结 `EvidenceStore`
- 冻结 `DeliveryDecision`
- 冻结 `ops_report_contract`
- 冻结 `appendix_contract`

这一阶段不追求外观效果提升，重点是先停止 contract 膨胀。

### 10.1.1 第一阶段的 cut line

第一阶段只有一个必须达成的 cut line：

> `render main report` 不能再直接读旧 `incident` 的混杂字段，只能读 `EvidenceStore + DeliveryDecision` 的受控投影。

如果这条还没达成，就说明我们还停留在旧架构里。

交付物：

- 新 contract 定义文档
- 新模块骨架
- 旧代码与新 contract 的映射表

### 10.1.2 第一阶段通过标准

第一阶段完成时，至少要同时满足：

1. `report.md` 的主渲染链只吃新 contract
2. 旧 `incident` 大对象不再是主报告真相源
3. reviewer 已经能输出最小 `DeliveryDecision`
4. 至少一个代表性 fixture 能完整跑通

### 10.1.3 第一阶段明确不做

第一阶段不做：

- investigator 自治增强
- reviewer 更复杂的 veto 机制
- 工具目录重构
- LLM prompt 大改

先把状态边界钉死，再谈能力提升。

## 10.2 第二阶段：把 report 从 investigation state 中脱钩

目标：

- render 层不再从大 `incident` 对象里随意取字段
- report 只吃批准后的交付 contract

交付物：

- `report_contracts.py`
- `report_render.py`
- 旧 `render.py` 逐步降级为兼容层

## 10.3 第三阶段：把交付判断移出 investigator

目标：

- `delivery_readiness` 不再混在 investigation 主链里直接驱动报告
- reviewer 成为正式的 acceptance 层

交付物：

- `reviewer.py`
- `DeliveryDecision`
- reviewer smoke eval

## 10.4 第四阶段：收敛 investigator loop

目标：

- 减少当前大量 capability hint / workflow hint 的代码编排痕迹
- investigator 真正围绕 state 和 tool result 推进

交付物：

- 更干净的 action selection contract
- 循环停止/重复动作检测
- open-loop transcript eval

### 10.5 迁移期间的兼容策略

这是当前方案里必须补充的一条，否则很容易再次形成双写长期并存。

#### A. 新 contract 为主，旧字段为兼容输出

迁移期内允许继续产出：

- `report_outline.json`
- `incident.json` 中的旧字段

但语义必须改成：

> **旧字段只允许由新 contract 派生，不允许反向驱动新 contract。**

#### B. 禁止双向同步

迁移期间只能：

- `EvidenceStore + DeliveryDecision -> legacy compatibility view`

不能继续：

- `legacy incident/report fields -> main report truth source`

#### C. 分阶段退役

建议节奏：

1. Phase 1: 旧字段继续写出，但只作兼容层
2. Phase 2: 主链完全切新 contract
3. Phase 3: 逐步停止维护不再被消费的 legacy 字段

---

## 11. Reviewer 的判断依据

reviewer 如果没有清晰依据，后面最容易再次滑回硬编码。

### 11.1 reviewer 的输入依据

reviewer 只能基于：

- `EvidenceStore`
- `SessionLog`
- investigator 的 stop reason
- runtime progress summary

不能直接基于：

- 某个 fixture 名
- 某个域名/IP/JA4 的特殊规则
- 某类 case 的手工 shortcut

### 11.2 reviewer 的最小判断框架

reviewer 至少要回答下面几个问题：

1. 当前是否已经有可交付的主证据链？
2. 当前是否还有阻塞交付的关键 gap？
3. 当前 scope 中哪些对象已经足以 confirmed，哪些仍只能保留为 candidate？
4. investigator 最近几轮是否真的有新增信息，还是只是在重复低价值动作？

### 11.3 `insufficient_progress_signals` 的来源

`insufficient_progress_signals` 不应是随意文案，而应来自通用、可解释的运行信号，例如：

- 连续多轮没有新增 observation / claim / scope 变化
- 连续多轮只重复访问同一类工具且结果新颖度极低
- gap 状态长期未发生变化
- 预算显著下降但主证据链没有增强

这里的重点不是写 case-specific 规则，而是用**通用运行信号**做 reviewer 判断依据。

### 11.4 `blocking_gaps` 的来源

`blocking_gaps` 只能来自已经显式建模的 gap，并满足：

- gap 能说清楚限制了哪个结论
- gap 能说清楚为什么当前仍阻塞交付
- gap 能区分“当前不可解”与“当前值得继续补查”

---

## 12. 第一阶段建议优先落地的内容

如果只做第一步，我建议是下面这组最小可落地改造：

1. 引入 `EvidenceStore` 数据结构
2. 引入 `DeliveryDecision` 数据结构
3. 让报告层只消费 `EvidenceStore + DeliveryDecision`
4. 停止在 investigator 主状态中维护多份 report truth source

这一阶段先不追求：

- investigator 更聪明
- reviewer 更复杂
- LLM 决策范围更大

因为边界没整理好之前，这些优化都会继续返工。

---

## 13. 每阶段都要带 eval gate

除了最终成功标准，迁移过程中每一阶段都需要自己的 gate。

### 13.1 Phase 0 基线 gate

- 基线 fixture 可以完整跑通
- 当前输出已归档，可做回归对比

### 13.2 Phase 1 gate

- 主报告只依赖新 contract
- 代表性 fixture 至少 1 个可跑通
- 主报告中不再暴露内部 workflow 字段

### 13.3 Phase 2 gate

- render 层已经不再从旧 `incident` 混杂取字段
- appendix 与主报告 contract 明确分层

### 13.4 Phase 3 gate

- reviewer 的 `DeliveryDecision` 已进入主链
- 至少有 smoke eval 证明 reviewer 不会无理由放行或无理由阻塞

### 13.5 Phase 4 gate

- investigator 的重复动作控制已生效
- open-loop transcript 可解释每次继续/停止原因

---

## 14. 成功标准

Plan 10 完成后，至少要满足以下标准。

### 14.1 架构层面

- 主循环只有一个清晰入口和停止条件
- 调查态、交付态、报告态边界清晰
- 不再存在长期并行维护的多份主报告真相源

### 14.2 工程层面

- `agent.py` 和 `render.py` 明显缩小职责
- 新模块具备明确单责
- 运行链路可以被 smoke test 覆盖

### 14.3 行为层面

- 主报告不再暴露内部 workflow 字段
- 可交付判断来自 reviewer，而不是 renderer 补洞
- 调查不足时，系统能明确说“阻塞在哪里”，而不是继续堆模糊字段

### 14.4 评估层面

- 至少有一组 fixture 能证明 investigator + reviewer + report pipeline 的分层有效
- 能解释每次继续、停止、交付失败的原因

---

## 15. 本轮明确不做什么

为避免再次滑回“修一个问题加一个字段”，这一轮明确不做：

- 不做 case-specific hardcode
- 不继续给 report 叠更多 reader-facing patch 字段
- 不先做复杂群聊式 multi-agent
- 不先做更多模板外观打磨
- 不把 reviewer 做成第二个自由调用工具的 agent

---

## 16. 风险与注意事项

### 16.1 风险一：表面拆模块，实际仍然共享混杂状态

如果只是把代码复制到新文件里，但底层仍然共用原来的大 `incident` 结构，那么复杂度并不会真的下降。

所以第一优先级不是“拆文件”，而是“拆状态边界”。

### 16.2 风险二：过早引入复杂双 agent

如果在 `EvidenceStore` 和 `DeliveryDecision` 还没稳定前就强行上复杂双 agent，只会把状态同步问题放大。

### 16.3 风险三：为了短期效果再次增加 renderer 兜底

renderer 可以保持必要的读者表达优化，但不能继续承担“修正上游调查逻辑”的职责。

### 16.4 风险四：`EvidenceStore` 重新长成新的大 `incident`

如果后续继续把：

- reader-facing 文案
- 交付态结论
- 临时 runtime 变量

都塞进 `EvidenceStore`，那只是换了个名字继续膨胀。

所以 `EvidenceStore` 的语义边界必须长期守住。

---

## 17. 结论

Plan 10 的核心不是“把 incident-agent 再做复杂一点”，而是：

> **把它从一个混杂的调查 workflow + report compiler，整理成一个边界清晰的 agent system。**

这轮真正最值得先做的不是再加字段，而是先完成：

- 单一证据真相源
- 独立交付审查层
- 报告输入 contract 化
- 调查、交付、报告三层解耦

只有这样，后面无论继续优化：

- LLM 调查 autonomy
- reviewer 能力
- report 质量
- case 泛化能力

才不会继续在同一套混杂结构上反复返工。
