# Plan 9: 证据契约先行的 Agent 调查与交付重构

## 当前判断

经过前几轮迭代，当前系统已经具备一个值得继续打磨的骨架：

- 有显式调查循环
- 有 `session_state / incident_state`
- 有 `investigation_trace.json`
- 有 investigator / reviewer 的雏形
- 有 `incident.json -> report` 的基本交付链路

但现在最核心的问题已经非常明确：

> 当前系统还没有形成一个稳定的“证据级调查契约”。

这会直接带来三类连锁问题：

1. agent 虽然在查，但查出来的结果没有被稳定沉淀成模板可消费的结构
2. report 虽然能生成，但很多章节是在消费零散字段，而不是消费真正的调查产物
3. case 虽然能跑通，但很难验证“是 agent 调查得好”，还是“事件本身就已经把答案写在 fixture 里了”

所以 Plan 9 的目标不是继续优化文案，也不是直接继续堆工具，而是：

> **先冻结一套证据级契约，再让 agent 围绕它补证据，再让 report_template 消费它。**

换句话说，Plan 9 要解决的是：

- agent 到底应该补什么
- 补到什么程度算可以交付
- 报告到底应该基于什么事实结构生成
- case 到底应该怎样设计，才能真正测出 agent 的作用

---

## 为什么 Plan 9 不能直接从 report_template 倒推 agent

`report_template.md` 现在已经足够清楚，也已经接近“交付模板”的稳定版本。

但如果我们直接让 agent 围着章节去工作，就会出现一个新的风险：

> agent 不是在调查，而是在“为了填章节而表演调查”。

这会让系统重新滑回另一种硬编码 workflow：

- 为了写“机制分解”而去凑机制
- 为了写“对象覆盖策略”而去凑对象
- 为了写“证据链摘要”而去凑总结

这不符合你想要的“真正能自己循环调用工具、依据状态推进的 agent”。

所以 Plan 9 明确采用以下顺序：

1. 先定义**证据级 contract**
2. 再把证据 contract 映射成**报告级 contract**
3. 最后再按模板生成 `report.md / report_appendix.md`

核心原则是：

> **agent 直接面向证据和缺口工作，不直接面向章节工作。**

---

## 当前计划里已经识别出的主要问题

### 1. 不能搞“大爆炸重构”

如果一次性同时重做：

- 证据结构
- reviewer 逻辑
- 工具面
- renderer
- fixture
- acceptance

那么一旦效果变差，我们将很难判断到底是哪一层出了问题。

Plan 9 必须拆成多个可验证阶段，每个阶段都能单独跑 smoke / eval。

### 2. 不能把 report_contract 直接做成章节镜像

如果 `report_contract` 只是 `report_template` 的字段翻版，那本质上还是把 workflow 写死。

更稳的方式是：

- 先有底层 `evidence_contract`
- 再由 adapter 生成 `report_contract`

这样以后模板再改，也不会逼着 agent 重写调查逻辑。

### 3. 工具不能过度“写作化”

像下面这种工具方向要避免：

- `synthesize_mechanism_chain`
- `assemble_evidence_block`
- `write_scope_summary`

因为这类工具已经太靠近“下结论”和“写报告”。

Plan 9 中，工具仍然应该主要聚焦于：

- retrieve
- pivot
- ground
- compare
- check_counterevidence
- structure_result

也就是说：

> tool 应该帮 agent 补证据，不应该帮 agent 写结论。

### 4. 证据 provenance 现在还不够清晰

当前系统还没有稳定地区分以下几类东西：

- 本地直接观测事实
- 由程序归并/推导出的关系
- 外部情报或指纹库命中
- 良性背景或反证
- 尚未证实的推断

如果 provenance 不分清，报告里就很容易混淆：

- “我们看到了什么”
- “我们推断了什么”
- “外部资料说了什么”

这会直接伤害交付可信度。

### 5. case 不能只是“变厚”，还要“变分散”

如果 fixture 只是把事件条数从 6 条变成 20 条，但所有关键线索都已经直接躺在 `trace_events.ndjson` 里，那 agent 的作用仍然不明显。

要想真正展示 agent 的价值，case 必须让关键证据分散在多个平面：

- seed 事件流
- 扩线事件流
- 本地情报库
- 外部指纹库 / 结构化情报
- 反证 / 背景上下文

这样 agent 必须主动调用工具，才能把事件补齐。

### 6. acceptance 不能只查 verdict 和关键词

现在的 acceptance 更多是在验证：

- verdict 对不对
- 资产在不在
- 时间线片段在不在
- report 有没有几个关键词

这不足以证明：

- agent 是否真的完成了独立 grounding
- agent 是否真的检查了反证
- 新发现指标是否被再次验证
- report 是否真的建立在可追溯证据上

Plan 9 必须升级 acceptance，使其能测“调查质量”，而不只是“输出结果看起来像对”。

---

## Plan 9 的总目标

Plan 9 只做一件事：

> **把 incident-agent 从“能跑出报告”提升为“能围绕证据缺口补齐调查，并稳定生成可交付报告”。**

具体目标分成四层：

1. 冻结一套稳定的 `evidence_contract`
2. 让 agent 围绕证据缺口而不是章节缺口推进
3. 让 `report_contract` 成为 `evidence_contract -> report_template` 的映射层
4. 设计一组真正能体现 agent 作用的 flagship case 与 acceptance

---

## Plan 9 的设计原则

### 1. 单控制循环不变

仍然保持当前显式 while loop，不引入第二条隐藏主循环。

### 2. 单一真相源与 ownership 必须明确

Plan 9 不允许出现四套并行真相源：

- 一套在 `incident_state`
- 一套在 `decision_basis`
- 一套在 `gap_ledger`
- 一套在 `report_contract`

必须明确：

- 谁生产原始事实
- 谁生产派生结构
- 谁只读
- 谁可以写回

否则系统会在迁移过程中出现字段漂移、状态冲突和“同一结论来源不一致”的问题。

### 3. agent 面向证据缺口，而不是面向章节

agent 不直接思考“我要补第几章”，而是思考：

- 哪条关键结论还缺证据
- 哪个对象还没有角色
- 哪个 pivot 还没有 grounding
- 哪个反证还没有检查
- 哪个边界还没有收敛

### 4. reviewer 只做交付审查，不做第二个调查员

reviewer 的角色必须被严格限制为：

- 判断当前是否可交付
- 标出还缺哪些关键证据
- 阻止重复、低价值或越界工具调用

reviewer 不负责：

- 发起新的独立调查路径
- 自己补证据
- 代替 investigator 下结论

### 5. 程序做结构约束，LLM 做模糊判断

程序适合负责：

- 证据归并
- provenance typing
- citation 绑定
- 缺口同步
- contract adapter
- acceptance 校验

LLM 适合负责：

- 在多个可行动作间做选择
- 判断当前最值得补哪个 gap
- 在证据不完美时给出保守表达
- 把 contract 重写成面向运维人员的报告语言

### 6. 兼容迁移要显式设计，不能边改边赌

Plan 9 不是绿地重写，而是对现有系统做 retrofit。

所以每一层改造都必须回答：

- 旧字段是否继续保留
- 新旧字段谁是 canonical source
- 旧 renderer / smoke / fixture 在什么窗口内继续兼容
- 何时可以删除 bridge layer

如果没有兼容迁移策略，后续每个阶段都会被链路断裂拖慢。

### 7. 每个阶段都必须有可验证产物

Plan 9 不接受“先大改完再看效果”。

每一阶段都必须有：

- 明确代码变更边界
- 可运行产物
- 可比较前后结果的 smoke / eval

---

## 首轮范围冻结（M1）

为了避免再次滑向“大爆炸重构”，Plan 9 首轮实施范围必须冻结。

M1 只允许覆盖下面这些内容：

- 一套最小 `evidence_contract`
- 一套最小 `report_contract` adapter skeleton
- 2 到 3 个最高优先级 gap 类型
- 2 个优先 flagship case
- 一层兼容 bridge，使旧链路暂时不断

M1 明确不做：

- 全量工具面重写
- 全量 fixture 重写
- 全量 acceptance 重写
- 大规模 prompt 重写
- 多 agent 主架构再改一轮

M1 的目标不是“把 Plan 9 全做完”，而是：

> **用最小代价证明 contract-first 这条路线能稳定接管现有系统。**

---

## Phase 1: 冻结 Evidence Contract

### 目标

先定义系统内部最重要的一层：

> agent 最终到底应该产出哪些“证据级对象”。

这一层不是报告模板，也不是最终文案，而是调查中间态。

### 最小 evidence contract

建议至少包含以下结构：

- `observations`
  - 原始工具调用返回的结构化结果
- `claims`
  - 从 observation 沉淀出来、可引用的证据性命题
- `object_registry`
  - 资产、域名、IP、JA3/JA4、家族提示等对象及其角色
- `pivots`
  - 当前扩线使用过或待扩线的 pivot
- `counterevidence`
  - 已检查到的良性背景、共享基础设施、计划内活动等
- `evidence_gaps`
  - 当前阻塞交付或影响判断层级的缺口
- `citation_map`
  - 关键 claim 和 observation/source 的映射

### canonical ownership 与唯一真相源

Phase 1 必须先把 ownership 写死。

建议按下面的规则冻结：

- `observations`
  - 唯一来源：tool executor / tool handler 输出
  - 允许写入方：工具执行层
  - renderer / reviewer 只读
- `claims`
  - 唯一来源：contract builder 从 observations 和事件事实中归并得到
  - investigator 不直接手写 claim 文本
- `object_registry`
  - 唯一来源：entity extractor + contract builder
- `pivots`
  - 唯一来源：调查循环显式记录的扩线对象
- `counterevidence`
  - 唯一来源：反证工具、背景核查工具和 contract builder 归类
- `evidence_gaps`
  - 唯一来源：gap builder / reducer
  - reviewer 只能返回审查意见，不能直接改写 gap 状态
- `citation_map`
  - 唯一来源：contract builder
- `report_contract`
  - 唯一来源：adapter
- `report.md / report_appendix.md`
  - 唯一来源：renderer

这意味着：

- `report_contract` 不是新真相源
- `report.md` 更不是新真相源
- 旧 `incident_state` 字段在迁移期只是兼容层，不应继续无限膨胀
- 动作建议不属于 evidence truth layer，而属于后续 decision / report layer

### 必须额外增加的一层：provenance typing

每条 claim / observation 至少要带上以下 provenance 类型之一：

- `local_observation`
- `derived_relation`
- `external_intel`
- `counterevidence`
- `analyst_note`
- `unverified_inference`

### 最小 schema 约束

Phase 1 不只是列字段名，还要冻结最小 schema 约束。

至少要保证：

- 每条 `observation` 有稳定 `id`
- 每条 `claim` 至少关联一个 observation 或原始事件
- 每个 object 都有 `type + value + role + status`
- 每个 gap 都有 `type + status + delivery_blocking + closure_criteria`
- 每条 citation 都能单向追到 source，反向追到 claim

### evidence layer 与 decision layer 必须分开

Phase 1 还必须明确：

- `evidence_contract`
  - 只承载事实、归并结果、对象角色、缺口和引用关系
- `decision / report layer`
  - 才承载 `recommended_actions`、交付措辞、摘要与状态化建议

也就是说：

- `recommended_actions` 不应作为 evidence truth source 存在
- 它应该由 `report_contract` 或单独的 decision adapter 从证据与状态派生
- reviewer 也不应该直接把动作建议写回 evidence layer

如果 schema 不冻结，后续所有 smoke 和 acceptance 都无法稳定校验。

### Phase 1 的完成定义

- 可以从当前 `incident_state` 稳定导出一份 `evidence_contract`
- 新结构不依赖报告文案存在
- claim / gap / object / citation 可以被独立检查
- 已明确 canonical ownership，避免多套真相源并行

---

## Phase 2: 从 Evidence Contract 映射到 Report Contract

### 目标

在不让 agent 直接面向章节的前提下，让模板真正吃到稳定输入。

### 做法

新增一层 adapter：

- `evidence_contract`
  - 面向调查
- `report_contract`
  - 面向交付

`report_contract` 负责承载：

- `report_header`
- `executive_summary`
- `scope_definition`
- `coverage_plan`
- `mechanism_breakdown`
- `evidence_blocks`
- `counterevidence_blocks`
- `impact_assessment`
- `evidence_gap_summary`
- `recommended_actions`
- `section_presence`
- `appendix_payload`

### 关键约束

- `report_contract` 不能引入新事实
- 它只能重组 `evidence_contract`
- 模板变更只影响 adapter 和 renderer，不直接影响 investigator 行为

### 兼容迁移策略

Phase 2 必须显式引入 bridge layer，而不是一次性切断旧链路。

迁移规则建议如下：

- 旧 `incident.json` 顶层字段暂时继续保留
- 新 `evidence_contract` 成为 canonical source
- `report_contract` 只从 `evidence_contract` 读取
- 旧 renderer 需要的字段由 adapter 回填，直到 deterministic renderer 完成切换
- smoke / acceptance 在过渡期同时支持新旧字段，但必须记录当前测试究竟验证的是哪一层

bridge layer 的目标不是长期存在，而是为了：

- 保证输出链不断
- 让每次阶段性改造都可单独回归
- 避免“contract 刚改，整条链全红”

### bridge layer 的退出条件

bridge layer 不能无限期存在，必须有明确移除条件。

建议至少同时满足以下条件后，才允许删除：

- `report.md / report_appendix.md / report_outline.json` 已全部切换到新 contract 链路
- 旧 renderer 不再被 smoke、eval 或默认入口依赖
- 至少 2 个 flagship case 和 1 组回归 case 在新链路上稳定通过
- 旧字段只剩兼容映射价值，不再被任何 canonical reducer 直接读取
- baseline / ablation 已证明删除 bridge 不会改变既有能力判断

如果这些条件没有同时满足，就不能宣称迁移完成。

### Phase 2 的完成定义

- `report_template.md` 的核心章节都能在 `report_contract` 找到对应槽位
- renderer 不再直接从零散 incident 字段拼报告
- 没有 LLM 时也能用 deterministic renderer 输出稳定结构
- bridge layer 存在且边界明确，知道何时可以移除

---

## Phase 3: 用证据缺口重构 Agent 推进逻辑

### 目标

把 agent 从“查几个预设动作”推进到：

> 基于当前证据状态，判断最值得补哪个 gap。

### 当前需要替换的旧思路

现在的 `open_questions` 还是偏流程型，比如：

- 还没补最小上下文
- 还没做反证检查
- 还没做扩线

这还不够贴近交付需求。

### 新的 gap 分类建议

建议逐步替换成以下更稳定的 gap 类型：

- `missing_seed_hit_context`
- `missing_object_roles`
- `missing_indicator_grounding`
- `missing_counterevidence`
- `missing_scope_boundary`
- `missing_mechanism_chain`
- `missing_impact_statement`
- `missing_citation_support`
- `missing_candidate_validation`

### gap 生命周期必须冻结

Phase 3 不能只定义 gap 类型，还要冻结 gap 生命周期。

建议至少使用下面四种状态：

- `open`
  - 当前明确缺失，且尚未采取有效补证动作
- `partially_closed`
  - 已获得部分证据，但还不足以支撑交付级判断
- `closed`
  - 已满足 closure criteria，不再阻塞当前结论
- `unresolved_but_deliverable`
  - 仍然存在，但已经被明确下沉为边界/缺口，不再阻塞当前交付

每个 gap 还必须明确：

- `delivery_blocking`
- `actionable_now`
- `closure_criteria`
- `reportable_if_unresolved`

### reviewer 与 gap builder 的边界

为了避免双写源，Phase 3 需要明确：

- `gap builder / reducer`
  - 负责生成和更新 canonical gap state
- `reviewer`
  - 只返回 `review_assessment`
  - 可以指出“这个 gap 仍未关闭”或“该动作不能关闭此 gap”
  - 但不能直接把 canonical gap 状态写成 `closed` 或 `delivery_blocking=false`

换句话说：

- reviewer 是审查信号源
- 不是 gap state 的直接写入者

### reducer 合并优先级必须固定

既然 canonical state 通过 reducer 归并，就必须明确冲突处理顺序。

建议至少冻结以下优先级：

1. `local_observation`
   - 对是否真实观测到某事实拥有最高优先级
2. `counterevidence`
   - 对背景解释、降级信号和边界收敛拥有高优先级
3. `external_intel`
   - 可增强解释与 grounding，但不能覆盖本地事实
4. `derived_relation`
   - 只能在上游事实成立时生效，不能反向覆盖上游事实
5. `analyst_note / unverified_inference`
   - 只能作为弱提示或待确认内容

此外还要明确：

- 同类型冲突时，优先保留来源更具体、引用更完整、时间更接近当前对象的记录
- 若冲突不能自动收敛，则必须转化为显式 gap 或 counterevidence，而不是静默覆盖
- reducer 必须保留冲突痕迹，方便 trace 和 eval 回放

### 新的推进逻辑

investigator 每一轮都应该围绕：

1. 当前有哪些 gap
2. 哪些 gap 是 delivery-blocking
3. 哪个 gap 现在最值得补
4. 当前有哪些工具最可能补上它

### reviewer 的新职责

reviewer 只回答三件事：

1. 当前是否可交付
2. 当前动作是否真的能补 gap
3. 当前动作是否重复、低价值或越界

### Phase 3 的完成定义

- `open_questions / gap_ledger` 可以直接映射到 `evidence_gaps`
- reviewer 的决策语义收敛为“交付审查”而不是“第二调查员”
- trace 中能清楚看出每一轮是在补哪个 gap
- gap 的状态转移规则明确，reviewer 不再凭感觉判断“差不多可以交付了”

---

## Phase 4: 重整工具面，但不把写报告变成工具

### 目标

让工具面更贴合证据补齐，而不是只贴合 seed alert。

### 应保留的原则

- 一切皆 tools
- LLM 决定是否调用
- 代码不替 agent 偷跑完整 workflow

### 工具面优化方向

不是新增“写报告工具”，而是增强以下能力：

- `retrieve_*`
  - 取回事件、页面、情报、上下文
- `ground_*`
  - 对新发现对象做独立验证
- `pivot_*`
  - 基于对象扩线
- `compare_*`
  - 比较候选对象与已知对象的关系
- `check_counterevidence`
  - 显式检查良性背景
- `structure_*`
  - 只做结构化，不做新结论

### 工具 I/O schema 必须统一

Phase 4 不能只讨论工具名字，还要冻结工具输出如何接入主循环。

每个工具输出至少要能回答：

- 它新增了哪些事实
- 它影响了哪些 object / pivot
- 它的 provenance 类型是什么

这里要特别避免让工具直接承担“推理写回”职责。

也就是说：

- tool 可以返回 `structured_facts`
- tool 可以返回 `entities`
- tool 可以返回 `source_refs`
- 但 tool 不应直接产出 canonical `claim`
- 也不应直接产出 canonical `gap` 状态转移

claim 归并、gap impact 判断、状态更新，应由统一的 contract builder / reducer 完成。

建议统一最小字段：

- `observation_id`
- `tool_name`
- `query`
- `summary`
- `structured_facts`
- `entities`
- `counterevidence_facts`
- `source_refs`
- `provenance`
- `raw_result_ref`

### 工具失败形态也必须标准化

工具 schema 不能只覆盖成功路径，还必须覆盖失败路径。

至少要区分：

- `no_hit`
  - 查了，但没有命中
- `transient_error`
  - 网络、速率限制、临时 API 故障
- `permission_denied`
  - 被权限或策略阻止
- `invalid_query`
  - 参数不合法或对象类型不支持
- `source_unavailable`
  - 外部源或本地源当前不可用

并且失败结果也必须结构化返回，至少包含：

- `status`
- `error_type`
- `retryable`
- `summary`
- `source_refs`

这样 reducer 才能区分：

- “没有证据”
- “没有命中”
- “没查成”

### 特别强调

如果 agent 通过扩线发现了新的：

- IP
- 域名
- JA3 / JA4
- 证书
- 主机

那么这些新对象必须允许被再次独立 grounding。

不能只因为它们是从 seed 扩出来的，就默认沿用 seed 的结论。

### Phase 4 的完成定义

- 新发现指标可被独立验证
- tool output 能直接沉淀到 evidence contract
- 没有“假装在查，实则在写”的工具
- 工具输出 schema 统一，主循环可以稳定消费

---

## Phase 5: 升级 Case 设计，做真正能体现 Agent 价值的评测集

### 当前问题

现在很多 fixture 太薄，主要风险有两种：

1. 事件本身太简单，agent 做不出层次
2. 关键答案已经直接躺在 `trace_events.ndjson` 里，agent 只是在读答案

### 新的 case 设计原则

一个好的 flagship case 不只是事件更多，而是要满足：

- 有明确 seed
- 有至少一个需要扩线才会发现的新对象
- 新对象需要独立 grounding
- 有至少一个强反证或背景解释
- 有至少一个不可完全消除的 gap
- 有干扰事件，避免最短路径猜中
- 证据分散在多个来源平面，而不是只在 `trace_events.ndjson`

### fixture authoring 规范

Plan 9 不只需要“更多 fixture”，还需要一套写 fixture 的规范。

建议至少明确以下分层：

- `trace_events.ndjson`
  - 放 seed 与最小主链，不直接把全部答案平铺
- 本地情报 / 指纹库 mock
  - 放需要独立 grounding 的补充证据
- 外部情报 mock 或可替代源
  - 放结构化 reputation / 家族 / 基础设施补充
- 背景与反证平面
  - 放共享基础设施、补丁窗口、计划任务、备份等信息
- 故意缺失层
  - 明确本案哪些关键证据就是拿不到，从而迫使 report 交付边界

此外必须增加一条硬约束：

- eval / fixture 默认使用冻结快照、本地 mock 或可重放数据
- 不把实时外部响应当作验收真相源
- 任何 live external dependency 都只能作为开发辅助，不进入稳定评测基线

fixture 不应该让 agent 只靠读取一个事件流文件就得出全部答案。

### 建议优先建设的 5 个 flagship case

1. `single_host_c2_beacon_plus`
   - 展示从 seed 到闭环的完整补证据能力
2. `multi_host_confirmed_spread_plus`
   - 展示扩线、二次 grounding、范围确认能力
3. `shared_infra_needs_review_plus`
   - 展示边界收敛与防误报能力
4. `benign_patch_window_plus`
   - 展示显式降级与反证能力
5. `execution_to_possible_exfil_needs_review`
   - 展示链条不完整时的保守交付能力

### 每个 flagship case 的最低标准

- 事件数建议 12 到 25 条
- 至少 1 条强反证
- 至少 1 个需要工具扩线才能出现的新对象
- 至少 1 个新对象需要独立 grounding
- 至少 1 个 unresolved gap
- 至少 2 到 3 条干扰事件

### Phase 5 的完成定义

- 至少 3 个 flagship case 落地
- 每个 case 都能明确说明“agent 的价值体现在哪里”
- case 不再只是 demo，而是可用来区分 capability / regression 的 eval 资产
- 已形成 fixture authoring 规范，后续新增 case 不再靠临场拼凑

---

## Phase 6: 升级 Acceptance，从“输出像不像”变成“调查对不对”

### 当前 acceptance 的不足

现在 acceptance 主要检查：

- verdict
- assets
- domains
- stages
- timeline fragment
- report fragment

这更像输出验收，而不是调查验收。

### 新 acceptance 需要新增的维度

- `must_fill_report_slots`
- `min_supporting_evidence_blocks`
- `min_counterevidence_blocks`
- `must_have_coverage_roles`
- `must_have_mechanism_breakdown`
- `must_have_key_gap`
- `must_ground_discovered_indicator`
- `must_have_citation_support`
- `must_not_promote_candidate_without_grounding`

### 额外建议

对旗舰 case，要把以下内容也纳入验收：

- trace 中是否出现高价值扩线动作
- trace 中是否出现对新对象的二次 grounding
- reviewer 是否阻止了冗余动作
- report 是否显式交付边界和 gap

### baseline 与 ablation 必须补上

如果没有 baseline / ablation，后续即使效果变好了，也很难说明到底是：

- agent 真的更会调查了
- renderer 更会写了
- fixture 更容易了
- acceptance 更松了

所以 Phase 6 至少要补三类对照：

1. `old renderer + old contract`
2. `new contract + deterministic renderer`
3. `new contract + LLM renderer`

必要时再增加：

- `without reviewer`
- `without second grounding`
- `without counterevidence check`

这样才能区分 capability improvement 和 presentation improvement。

### Phase 6 的完成定义

- acceptance 不再只奖励“关键词命中”
- 可以更稳定地区分：
  - report 写得更像
  - 和 agent 真正调查得更好
- 已有 baseline / ablation，能解释改进到底来自哪一层

---

## 每个 Phase 的最低验证要求

为了避免“实现完成”只停留在主观判断，Plan 9 每个 phase 至少都要补三类验证：

### 1. success path

- 新结构能被正常产出
- 主链路能在代表性 case 上跑通
- 输出能被下游层稳定消费

### 2. failure path

- 工具失败、无命中、权限拒绝、源不可用时不会污染 canonical state
- contract / adapter / reducer 不会把“失败”误判成“无风险”
- reviewer / acceptance 能识别关键缺口仍未关闭

### 3. recovery path

- 在阶段性失败后可以继续使用兼容链路或 bridge layer 回退
- 失败不会破坏 trace、citation、gap state 的一致性
- 后续轮次仍可恢复推进，而不是进入不可解释状态

对于实现顺序靠前的 Phase 1 到 Phase 3，这三类验证必须作为完成定义的一部分，而不是附加项。

---

## 实施顺序

Plan 9 的推荐实施顺序如下：

1. Phase 1：冻结 `evidence_contract`
2. Phase 2：建立 `evidence_contract -> report_contract` adapter
3. Phase 3：用证据缺口重构 gap / reviewer
4. Phase 4：优化工具面和新对象 grounding
5. Phase 5：升级 flagship case
6. Phase 6：升级 acceptance 与 smoke/eval

这个顺序不能反。

特别是：

- **不要先重写 renderer**
- **不要先大改 fixture**
- **不要先往 agent 里塞更多工具**

因为如果证据契约没冻结，这些工作都会反复返工。

### 首轮实施冻结

首轮实际编码时，建议再收紧为：

1. Phase 1：最小 `evidence_contract` + provenance typing
2. Phase 2：最小 `report_contract` adapter + bridge layer
3. Phase 3：先只落 2 到 3 个 gap 类型
4. Phase 5：先只升级 2 个 flagship case

先证明这条路线能稳定跑通，再继续扩面。

---

## 非目标

为了避免本轮继续发散，以下内容明确不是 Plan 9 的主目标：

- 不引入新的多 investigator 并行系统
- 不引入 team system / durable task graph / MCP
- 不引入 memory
- 不重写主控制循环
- 不把 report_template 再大改一轮
- 不把“更强模型”当主解法
- 不用硬编码规则去对单个 fixture 过拟合

Plan 9 是一次：

- `retrofit`
- `hardening`
- `contract-first`

而不是下一轮全盘推倒重来。

---

## 实时清单

下面这份清单用于后续执行时持续更新。

### A. 证据契约

- [ ] 冻结 `evidence_contract` 的最小字段集合
- [ ] 明确 canonical ownership，避免多套真相源并行
- [ ] 给 claim / observation 增加 provenance typing
- [ ] 明确哪些字段属于 `local_observation / derived_relation / external_intel / counterevidence / unverified_inference`
- [ ] 让 citation 能从 claim 追到 observation / source
- [ ] 冻结最小 schema 约束，保证后续可测

### B. 报告适配层

- [ ] 新增 `report_contract` adapter
- [ ] 让 `report_contract` 只消费 `evidence_contract`
- [ ] 让 renderer 不再直接拼零散 incident 字段
- [ ] 让 deterministic renderer 先跑通新模板
- [ ] 增加 bridge layer，明确兼容窗口与移除时机

### C. Agent 推进逻辑

- [ ] 把 `open_questions` 从流程型改成证据缺口型
- [ ] 给每个 gap 标出是否 delivery-blocking
- [ ] 冻结 gap lifecycle：`open / partially_closed / closed / unresolved_but_deliverable`
- [ ] 让 trace 显示“本轮补的是哪个 gap”
- [ ] 限制 reviewer 只做交付审查，不做第二调查员

### D. 工具系统

- [ ] 梳理现有工具的真实职责
- [ ] 去掉或避免新增“写作型工具”
- [ ] 让新发现指标可以独立 grounding
- [ ] 让工具输出直接沉淀到 evidence contract
- [ ] 冻结工具 I/O schema，保证主循环能稳定消费

### E. Case 设计

- [ ] 选定 3 个优先 flagship case
- [ ] 为每个 case 设计“agent 价值点”
- [ ] 增加反证、干扰事件和 unresolved gap
- [ ] 把关键证据分散到多个可查询平面
- [ ] 形成 fixture authoring 规范，明确各类证据放哪一层

### F. Acceptance / Eval

- [ ] 升级 acceptance，检查调查质量而不只是输出像不像
- [ ] 增加对二次 grounding 的验收
- [ ] 增加对 gap / 边界 / counterevidence 的验收
- [ ] 增加 trace 级别的 agent 行为验收
- [ ] 增加 baseline / ablation，区分能力提升和文案提升

### G. 风险控制

- [ ] 每个 phase 完成后都跑 smoke
- [ ] 每次只改一层主逻辑，避免大爆炸重构
- [ ] 首轮范围冻结：只落最小 contract、最小 adapter、少量 gap、少量 case
- [ ] 不为单个 fixture 写硬编码补丁
- [ ] 保持“程序做结构、LLM 做判断”的边界

---

## 当前建议的第一步

如果按 Plan 9 正式开始实施，我建议第一步不是动 renderer，也不是动 fixture，而是：

> **先在当前 incident finalize 阶段新增 `evidence_contract` 导出，并把 provenance typing 立起来。**

原因很简单：

- 这是后续 gap 重构的基础
- 这是后续 report_contract 的基础
- 这是后续 acceptance 升级的基础
- 也是最容易单独验证的一步

Plan 9 的本质不是“让报告更漂亮”，而是：

> **让 agent 真正围绕证据缺口工作，并把调查过程沉淀为稳定交付结构。**
