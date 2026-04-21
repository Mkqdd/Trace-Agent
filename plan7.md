# Plan 7: 从单告警归因器升级为事件级溯源 Agent

## 当前判断

经过 `plan5` 和 `plan6` 的优化，当前主线已经能稳定产出更像样的 `analysis.json -> report.md`，而且正文证据也不再只是“标题 + 链接”。

但我们已经碰到一个更本质的上限：

> **只要输入单元仍然是一条孤立 alert，报告再怎么优化，也很难真正变成“溯源报告”。**

当前主线最擅长回答的是：

- 这条 alert 命中了什么指标
- 这个指标更像哪个家族
- 公开情报如何支持这个归因
- 基于这个判断应该做哪些基础处置

这类输出本质上是：

> **告警研判卡片**

而不是真正意义上的：

> **事件级溯源报告**

真正的溯源报告需要讲清楚的内容包括：

- 这起事件是如何开始的
- 关联到哪些主机、账号、端口、域名、IP、证书、样本、下载链
- 同一批活动里哪些 alert 属于同一个 incident
- 时间线如何展开
- 攻击链已经走到了哪个阶段
- 哪些结论是已证实的，哪些只是高概率假设

只靠单条 alert，很难稳定回答这些问题。

因此 Plan 7 的目标不是继续抠单条报告的措辞，而是：

> **把当前系统从“单 alert 归因 Agent”重构为“事件级溯源 Agent”。**

---

## 这次为什么允许大改

当前架构的核心假设是：

- 输入是一条命中后告警
- 主问题是“这个指标更像哪个家族”
- 主执行链围绕 `build_analysis(...)` 聚合归因和补查结果
- 最终报告围绕一份面向单 alert 的 `analysis` 渲染

这个假设在做“告警解释”和“家族归因”时是成立的；
但在做“溯源报告”时，这个假设会反过来束缚系统。

也就是说，当前主线的问题不是简单的“报告不够好”，而是：

> **核心状态模型和控制流，天生不是为 incident-centric 调查设计的。**

因此 Plan 7 明确允许：

- 大规模重构
- 旧链路降级为兼容模式
- 新增事件级主状态对象
- 新增查询存储层
- 新增事件型测试体系
- 必要时重写主 pipeline

我们不再默认“旧主链必须保留”，而是只保留真正有复用价值的部件。

---

## 参考论文与可迁移结论

参考论文：

- [Incident Response Planning Using a Lightweight Large Language Model with Reduced Hallucination](/home/estar0x/project/maltrail_test/Trace-Agent/reference/2508.05188v1(1).pdf)

论文本身的目标是：

- incident response planning
- 不是 threat tracing / attribution reporting

但它对我们最有价值的不是 finetune，而是它的数据与任务组织方式：

1. 输入单元是 **incident context**，而不是单条 alert  
2. 任务被拆成多步，而不是一次性生成整篇输出  
3. 系统里存在显式状态，而不是只靠长上下文隐式推进  
4. 评估的是“流程是否推进”和“结果是否闭环”，而不是只看文案好不好看

其公开数据集也强化了这个结论：

- `incident_examples.json`
  - 做 incident 判断、ATT&CK 映射、实体抽取
- `action_examples.json`
  - 在某个状态下生成下一步动作
- `states_examples.json`
  - 判断某个动作会如何推进状态

这启发我们：

> **Plan 7 的核心不应是“让 LLM 更会写报告”，而应是“让系统具备事件级调查状态机”。**

---

## Plan 7 的新目标

Plan 7 的最终目标不是：

- 输入一条 alert，输出一篇更长的家族背景报告

而是：

- 输入一条 seed alert
- 自动拉取与其相关的背景流量、相关 alert、相关实体
- 聚合出一个 incident
- 在 incident 级别进行补查和证据组织
- 最终输出一份真正围绕事件展开的报告

一句话概括：

> **从 alert-centric，升级到 incident-centric。**

---

## 新的 Agent Contract

### 用户目标

用户给出一条种子 alert，希望系统自动补齐其事件级上下文，并生成可交付的溯源报告。

### 输入

支持两种输入模式：

1. `seed alert`
   - 用户只给一条 alert
   - 系统需要自行查询事件背景

2. `incident fixture`
   - 用户给一个测试用例或事件包
   - 内含种子 alert、背景流量、相关实体与期望输出

### 成功条件

系统能够稳定回答：

- 这是一个什么事件
- 与之相关的流量和告警有哪些
- 关键实体有哪些
- 时间线如何展开
- 事件当前处于哪个攻击阶段
- 哪些证据强、哪些证据弱
- 哪些问题仍待确认

### 停止条件

满足以下任一条件即可结束：

- 事件已达到 `report_ready`
- 查询预算耗尽
- 再补查也不会显著提升事件解释力
- 关键不确定性已经明确记录，可带风险交付

### 核心输出

- `incident.json`
- `report.md`
- `topology.json`
- `topology.html`
- `investigation_trace.json`

其中：

- `incident.json` 是新的单一事实源
- `report.md` 和拓扑都从 `incident.json` 生成
- `investigation_trace.json` 用于解释系统为什么继续查、查了什么、为什么停下

---

## 为什么不能继续以 `analysis.json` 为核心

当前 `analysis.json` 的职责过于混合：

- 事件事实
- 家族归因
- 证据集合
- gap 判断
- 展示相关视图输入

这在单 alert 模式下还能工作，但在 incident 模式下会出现两个问题：

1. 它没有显式表达“事件聚合”的概念
2. 它没有显式表达“调查状态推进”的概念

因此 Plan 7 建议：

- 不再把当前 `analysis.json` 作为核心状态对象
- 引入新的 `incident.json`
- 旧 `analysis` 只保留为兼容层，或在后续阶段废弃

---

## 新的核心状态模型

Plan 7 不采用论文里的 recovery state 原样建模，因为我们当前目标不是“恢复动作推荐”，而是“调查推进与事件收敛”。

我们需要的是 **investigation state**。

这里需要吸收一个很关键的约束：

> **不能在零上下文下先过滤 seed alert。**

因为很多真实 incident 的入口本来就是弱信号。  
如果系统在没有聚合相邻流量、同资产告警、同时间窗事件之前，就先把 seed 判成“价值不大”，那它会系统性漏掉高级攻击的早期阶段。

建议初版状态字段如下：

- `context_built`
- `entry_assessed`
- `cluster_built`
- `entities_grounded`
- `timeline_built`
- `scope_assessed`
- `intrusion_hypothesis_grounded`
- `external_infra_grounded`
- `counterevidence_checked`
- `report_ready`

字段解释：

- `context_built`
  - 是否已经围绕 seed 建出最小上下文包，可用于做上下文化判断
- `entry_assessed`
  - 是否已经基于上下文判断“继续调查 / 降级观察 / 关闭为噪声”
- `cluster_built`
  - 是否已经从最小上下文扩成更完整的 incident 事件簇
- `entities_grounded`
  - 是否已抽出关键主机、IP、域名、证书、账号等实体
- `timeline_built`
  - 是否形成基础事件时间线
- `scope_assessed`
  - 是否知道影响范围和潜在受害对象
- `intrusion_hypothesis_grounded`
  - 是否形成了有证据支撑的攻击链解释
- `external_infra_grounded`
  - 是否明确了外部基础设施或家族支撑
- `counterevidence_checked`
  - 是否检查过与主假设相冲突的信号
- `report_ready`
  - 是否已具备可交付条件

---

## 新的数据对象

### 1. `SeedAlert`

保留当前 alert 标准化逻辑，但它不再是终态事实源，只是调查起点。

### 2. `TraceStore`

这是 Plan 7 的关键新增层。

职责：

- 接收一条 seed alert
- 提供“查背景流量 / 查相关 alert / 查相邻时间窗事件”的统一接口

它可以有两种实现：

1. `FixtureTraceStore`
   - 用于本地测试
   - 从静态 JSON / NDJSON / CSV 中查询

2. `LiveTraceStore`
   - 用于真实环境
   - 对接流量、告警、资产、日志系统

### 3. `IncidentBundle`

用于承载与种子 alert 相关的一组原始事件：

- seed alert
- related alerts
- related flows
- related entity observations
- baseline external intel

它建议拆成两个层次理解：

- `minimal context bundle`
  - 只聚合同资产、同时间窗、同基础设施的近邻事件，用于避免弱信号被过早过滤
- `expanded incident bundle`
  - 在确认值得继续后，再扩成更完整的事件簇

### 4. `IncidentState`

系统运行中的显式调查状态：

- 当前聚合结果
- 当前关键实体
- 当前时间线
- 当前假设
- 当前 gaps
- 当前 investigation state

### 5. `IncidentReportModel`

这是渲染层对象，不是事实源。

它从 `incident.json` 派生，专门服务于：

- `report.md`
- `topology`

---

## 新的主执行链

建议将主链改为：

`seed alert`
-> `context assemble`
-> `context-aware verify`
-> `incident expand`
-> `incident summarize`
-> `investigation planner`
-> `evidence queries / enrichment`
-> `state update`
-> `incident finalize`
-> `report render`

### 阶段说明

#### 1. Context Assemble

先围绕 seed 做**最小上下文聚合**，至少拿到：

- 同资产 / 同主机 / 同账号的相邻告警
- 同时间窗相邻流量
- 同目标 / 同域名 / 同证书 / 同 JA3 / JA4 的近邻事件
- 必要的资产与环境基线

这一步的目标不是一次性完成全量 incident 聚合，而是：

- 让 seed 不再是孤立告警
- 给后续判断提供最小可用上下文
- 避免把真实攻击的早期弱信号直接过滤掉

#### 2. Context-Aware Verify

基于最小上下文判断：

- 这条 seed 是否值得继续作为 incident 入口
- 当前更像：
  - 高置信安全事件
  - 弱信号但值得继续扩查
  - 暂无足够证据，降级观察
  - 明显误报 / 噪声

也就是说，`verify` 不能发生在 `assemble` 之前，而必须建立在最小 bundle 之上。

#### 3. Incident Expand

一旦确认值得继续，再围绕上下文化后的 seed 扩展 incident：

- 同一 src / dst
- 同时间窗相邻流量
- 同证书 / JA3 / JA4 / 域名
- 同资产相关告警
- 同家族或同基础设施线索

输出 `IncidentBundle`。

#### 4. Incident Summarize

基于 bundle 抽出：

- 关键实体
- 基础时间线
- 初始攻击假设
- 待补查问题

#### 5. Investigation Planner

不再规划“补哪条网页情报”，而是规划：

- 下一步该查哪类事件证据
- 例如：
  - 初始访问证据
  - 横向移动证据
  - C2 证据
  - 数据外传证据
  - 受害范围证据
  - 反证线索

#### 6. Evidence Queries / Enrichment

执行补查动作：

- 查背景流量
- 查相关 alerts
- 查时间窗前后事件
- 查外部情报
- 查实体聚合关系

#### 7. State Update

每次补查之后明确更新：

- 哪些 state 变成 `true`
- 哪些 gaps 仍未解决
- 为什么继续查 / 为什么可以停

#### 8. Incident Finalize

输出新的 `incident.json`，成为系统唯一事实源。

#### 9. Report Render

报告从 `incident.json` 渲染，而不是从当前单 alert 导向的 `analysis` 渲染。

---

## 当前可复用与应废弃的部分

### 可复用

- CLI 入口与批处理机制
- 部分 baseline source clients
- 外部高质量页面抓取与 claim 提取能力
- topology 渲染基础能力
- 本地 renderer 优先的设计原则

### 建议降级为兼容层

- `normalize_alert(...)`
- 当前 `build_analysis(...)`
- 当前 `gap_planner.py`
- 当前 deterministic/react gap fill 路径

### 建议从主线中移除

- 以单 alert 家族归因为中心的主 pipeline
- 把 `analysis.json` 继续当成 incident 事实源
- 继续围绕“直接证据 / 家族背景”组织全部报告

---

## 代码结构调整建议

建议新增一个新的主域：

- `demo_agent/incidents/`

初版模块如下：

- `contracts.py`
  - `SeedAlert`
  - `IncidentBundle`
  - `IncidentState`
  - `InvestigationAction`
  - `InvestigationTrace`
- `store.py`
  - `TraceStore`
  - `FixtureTraceStore`
  - `LiveTraceStore`
- `assembler.py`
  - 事件聚合逻辑
- `state.py`
  - 调查状态推进逻辑
- `planner.py`
  - 下一步补查动作规划
- `executor.py`
  - 执行补查动作
- `render.py`
  - 从 `incident.json` 到 `report.md`
- `fixtures.py`
  - 事件型测试夹具读取工具

同时保留当前：

- `demo_agent/query/`

但把它逐步降级为 legacy 路径。

---

## 新的测试策略

Plan 7 必须把测试体系一起重做，否则事件级 agent 很容易退化成“看起来会查，但不可验证”。

### 测试目标

测试不再只是：

- 输入一条 alert
- 看能不能生成一份 report

而应该验证：

- 能否从单条 seed alert 聚合到正确的 incident
- 能否查到背景流量
- 能否构建时间线
- 能否识别关键实体
- 能否产生合理的调查推进
- 能否在证据不足时保留不确定性

### 两类测试

#### 1. Incident Fixture Tests

每个 fixture 至少包含：

- `seed_alert.json`
- `trace_events.ndjson` 或 `background_flows.json`
- `expected_incident.json`
- `acceptance.yaml`

输入仍可是一条 seed alert，但系统必须从 fixture 的背景数据中查出事件上下文。

#### 2. Live Query Simulation Tests

使用 `FixtureTraceStore` 模拟查询环境：

- 让 agent 像真实查询一样读取背景流量
- 但所有数据都来自本地夹具

这样可以验证：

- 查询规划是否合理
- 聚合逻辑是否正确
- 控制流是否稳定

---

## 建议新增的事件型测试用例

### Case 1: 误报 / 正常运维流量

目标：

- 确认不会把背景扫描、备份、健康检查误聚成 incident

### Case 2: 单主机恶意外联 + 重复 C2

目标：

- 从一条命中告警扩出多个相关外联事件
- 形成单主机感染型 incident

### Case 3: Web 初始入侵 + 下载载荷 + 持续 beacon

目标：

- 形成包含初始访问、执行、C2 的时间线

### Case 4: 暴露服务 RCE + 数据外传

目标：

- 验证系统能把 exploit、内部执行、外传流量串起来

### Case 5: Redis / Kafka 误配暴露 + 恶意命令 + persistence 尝试

目标：

- 验证配置暴露型事件的聚合与阶段判断

### Case 6: 恶意家族命中 + 横向移动 hint

目标：

- 验证系统不会只停留在家族背景，而会继续查范围与扩散

---

## 每条 fixture 的验收项

每条测试至少定义：

- 是否识别为真实 incident
- 是否聚合出正确的事件簇
- 是否抽出关键实体
- 是否构建出基础时间线
- 是否给出主要攻击假设
- 是否列出关键不确定性
- 是否引用了真实存在的证据
- 是否从背景流量中补足了单条 alert 没有的信息

建议验收方式采用：

- 严格字段断言
- 关键短语断言
- 时间线片段断言
- 证据引用数量断言

而不是只做整篇报告全文比对。

---

## 与论文数据集的关系

Plan 7 不直接照搬论文的 fine-tuning 路线，但会借用它的任务拆分思想。

我们新的任务拆分建议为：

### 任务 A: `incident_examples` 对应层

目标：

- 输入 seed alert + background events
- 输出：
  - incident 是否成立
  - 事件摘要
  - ATT&CK 阶段
  - 关键实体

### 任务 B: `action_examples` 对应层

目标：

- 输入当前 `IncidentState`
- 输出下一步该查什么

但这里的 action 不再是“恢复动作”，而是：

- `InvestigationAction`

例如：

- 查同时间窗目标 IP 的其他连接
- 查该主机上一小时内的异常 DNS
- 查同证书指纹的其他资产命中

### 任务 C: `states_examples` 对应层

目标：

- 输入某个补查动作和查询结果
- 更新调查状态

这相当于把论文的：

- `recovery state`

改写成：

- `investigation state`

---

## 迁移策略

Plan 7 不建议一步删光旧链路，而是分阶段迁移。

### Phase 1: 引入事件级数据契约与测试夹具

交付：

- `TraceStore`
- `IncidentState`
- fixture 格式
- 第一批事件型用例

### Phase 2: 做新的 incident assembler

交付：

- 从 seed alert 查询最小上下文
- 先产出 `minimal context bundle`
- 做 `context-aware verify`
- 再扩成完整 incident bundle
- 输出 `incident.json` 初版

### Phase 3: 用 incident.json 驱动新 renderer

交付：

- 新版 report renderer
- 事件时间线
- 关键证据簇
- 不确定性区块

### Phase 4: 引入 investigation planner

交付：

- 新版 planner / executor / state updater
- 替代旧 gap planner 主地位

### Phase 5: 旧主链降级为 legacy

交付：

- 旧单 alert pipeline 改为兼容模式
- 新 incident pipeline 成为默认主线

---

## 明确的非目标

Plan 7 当前不做：

- 立即接入多 agent
- 立即做 durable task graph
- 立即做 MCP
- 立即做 finetune
- 立即接入真实 SOC 平台生产系统

原因是：

- 当前最大的收益来自输入单元升级与状态模型升级
- 不是来自更多系统复杂度

---

## 风险与约束

### 风险 1

如果系统仍在零上下文下先过滤 seed，真实攻击的弱信号入口会被提前丢弃。

### 风险 2

如果没有背景流量查询层，所谓“事件级 agent”会退化成“换皮的单 alert agent”。

### 风险 3

如果没有显式状态，系统仍然会退化成：

- 反复补网页情报
- 但没有调查闭环

### 风险 4

如果没有事件型 fixture，后续任何“效果提升”都无法稳定验证。

---

## Plan 7 的验收标准

Plan 7 完成后，应至少满足：

1. 输入一条 seed alert，系统能查询并聚合背景事件
2. 系统不会因为 seed 是弱信号就提前结束，而是会先做最小上下文化判断
3. 输出 `incident.json`，而不再只依赖单 alert `analysis.json`
4. 报告能体现：
   - 时间线
   - 关键实体
   - 关键证据簇
   - 攻击阶段
   - 不确定性
5. 至少有一组事件型测试夹具能稳定通过
6. 当前主线中“只会讲指纹命中 + 家族背景”的上限被打破

---

## 最终结论

Plan 7 的核心不是再优化一次报告，而是：

> **重写系统的主问题定义。**

从：

- “这条 alert 更像哪个家族？”

转成：

- “这条 alert 所在的 incident 到底发生了什么？”

因此，Plan 7 的本质是一次：

> **从单告警归因器，到事件级溯源 Agent 的架构升级。**
