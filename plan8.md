# Plan 8: 调查收敛校准与交付门槛加固

## 当前判断

经过 Plan 7 的重构，当前主线已经完成了一个很重要的跃迁：

- 从 `alert-centric` 走到了 `incident-centric`
- 从 `analysis.json` 主导走到了 `incident.json` 主导
- 从“单次告警解释”走到了“事件级调查 + 报告生成”

这一层转向本身是正确的，而且当前代码已经具备一个值得继续打磨的骨架：

- 有显式控制循环
- 有显式的 `session_state / incident_state`
- 有可追踪的 `investigation_trace.json`
- 有独立的 `TraceStore`
- 有从事实源派生报告和拓扑的渲染层

但现在最值得优化的问题，已经不再是：

> “这个 agent 能不能查出东西”

而是：

> “它会不会过早下结论，以及它停下来的时机是不是足够可信”

换句话说，Plan 8 的目标不是继续让报告“更像报告”，而是让系统的：

- 调查收敛过程
- 证据边界
- 结论置信度
- 停止条件

变得更稳、更可解释、更可验证。

---

## 当前最主要的 4 个问题

### 1. 结论下得太快，置信度校准偏激进

当前在某些强信号 fixture 中，系统在只做完最小上下文后，就已经把 verdict 拉到：

- `confirmed_incident`
- 高置信度

这说明当前系统已经具备“快速形成方向”的能力；
但它还没有很好地区分：

- **方向性判断**
- **交付级结论**

也就是说，系统现在更像是在做：

> “我已经大致知道这是怎么回事了”

而不是：

> “我已经满足了可以对外稳定交付的结论门槛”

这两者不能混为一谈。

### 2. `report_ready` 条件过薄

当前 `report_ready` 更接近一种“流程完成信号”，而不是“交付质量信号”。

目前的停机逻辑更偏向：

- 查过事件上下文
- 查过至少一个 intel / page 工具
- 形成了 verdict

但真实的交付门槛应该更接近：

- 主支撑证据是否已经成链
- 反证是否真的检查过
- 关键 open question 是否已经被解决或明确保留
- 关键时间线节点是否能映射到 observation
- 当前结论为什么可以停，而不是为什么还可以继续查

如果 `report_ready` 过薄，就会导致系统虽然“能交付”，但交付时机仍然带有偶然性。

### 3. 证据来源混合，新增证据与内部整理没有清晰边界

当前 agent 已经有：

- `technical_source_search`
- `fetch_page_content`
- `extract_claim_candidates_from_page`
- `extract_entities_from_page`

但当前存在一个结构性问题：

> 系统有时是在抽取“外部正文证据”，有时其实只是把当前内部 digest 再结构化一遍。

这会导致：

- 看上去 observation 数量变多了
- 报告里的论据变丰富了
- 但事实层并没有真正新增多少外部支撑

系统需要更清晰地区分：

- **原始事件事实**
- **外部正文证据**
- **结构化情报**
- **内部摘要整理**

否则报告很容易进入“写得越来越完整，但事实没有同比增强”的状态。

### 4. 当前测试更偏冒烟与验收，缺少驱动校准的评测

现有 incident smoke 已经很好地覆盖了：

- verdict 是否匹配预期
- 时间线和阶段是否存在
- trace 是否生成
- 是否到达 `report_ready`

但 Plan 8 需要的评测重点不再只是“能不能跑通”，而是：

- 是否过早确认
- 是否在该保守时仍然保守
- 是否真的检查过反证
- 是否把关键证据和 observation 正确绑定

也就是说，当前测试体系足以验“功能完整”，但还不足以验“判断稳健”。

---

## Plan 8 的目标

Plan 8 的目标不是继续大改主架构，也不是引入更多复杂能力。

Plan 8 只做一件事：

> **把当前 incident-agent 的“调查收敛和交付时机”校准到更可信的水平。**

具体来说，要做到：

1. 系统可以继续快速形成内部方向，但不会把方向性判断过早当成交付级结论
2. `report_ready` 变成一组明确的 readiness checks，而不是一个薄布尔表达式
3. 报告中每条关键证据都能回答“它到底来自哪里”
4. 反证检查成为显式动作，而不是隐含副产物
5. 报告生成从事实组织与语言表达中解耦，保证没 LLM 也能稳定交付
6. 评测体系能真正压住“过早确认”和“虚假闭环”

---

## 为什么 Plan 8 不优先做“换更强模型”

当前阶段最主要的问题不是：

- 模型不会写
- 模型不会总结
- 模型不会查网页

而是：

- verdict 规则太容易把强方向感放大成强结论
- `report_ready` 过早宣布闭环
- 证据 provenance 不够清楚
- 评测没有把这些问题卡死

如果这几个结构性问题不先解决，那么即使换更强模型，也大概率只会得到：

- 更自然的报告
- 更顺滑的推理文本
- 更会自信表达的 agent

但不一定会得到更可信的交付。

Plan 8 明确采用的原则是：

> **先校准 runtime，再优化模型表现。**

---

## Plan 8 的非目标

为了避免本轮工作发散，以下内容明确不在 Plan 8 的主目标内：

- 不引入“两个 investigator 并行查工具”的多 agent 主执行链
- 不把 reviewer-style second agent 作为 Plan 8 的必做实现项
- 不引入完整 team system
- 不引入 durable task graph
- 不引入 memory
- 不引入 MCP
- 不重写 `TraceStore` 抽象
- 不重做报告版式和措辞风格
- 不以“切换模型供应商”作为主解法

Plan 8 是一次：

- `retrofit`
- `hardening`

而不是下一轮大重构。

---

## 设计原则

### 1. 保持单控制循环，不引入第二条隐藏判断链

所有新的判断逻辑仍然收敛在当前显式循环中，不新增一个“报告前再偷偷判断一次”的旁路。

### 2. 把“方向性判断”和“交付级判断”拆开

系统可以在内部快速形成：

- 当前更像恶意
- 当前更像正常背景
- 当前更像待复核

但只有在 readiness checks 满足后，才能把它提升为：

- 最终对外 verdict
- 最终交付信号

### 3. 把 tool 产物当成状态回写，而不是单纯日志

每一次 observation 都必须回答：

- 它增加了什么证据
- 它削弱了什么假设
- 它是否推进了 readiness

### 4. 让“未解决问题”成为一等输出，而不是失败残留

对于 `needs_review` 场景，最重要的不是把语言写得更像确认事件，而是明确：

- 现在还缺什么
- 为什么不能升级
- 下一步最值得补什么

### 5. 用 eval 驱动校准，而不是靠主观阅读修 prompt

Plan 8 的每一项关键优化，都必须对应一个可检验的 acceptance 或 smoke 指标。

---

## 关于双 agent 的设计判断

### 结论

Plan 8 不建议引入“两个 investigator 并行调查”的双 agent 主链；
但可以考虑一种**克制的双 agent 形态**：

- `Investigator`
  - 负责调查、扩上下文、更新 `incident_state`
- `Reviewer`
  - 不查新工具
  - 不写回主状态
  - 只审查当前快照是否满足交付门槛

也就是说，适合你们的不是：

> “两个人一起查”

而是：

> “一个人查，一个人验”

### 为什么不建议“双 investigator”

如果两个 agent 都具备：

- 工具调用权限
- 事件扩查能力
- verdict 修改能力

那么当前系统很容易出现以下问题：

1. 状态边界混乱
   - 谁对最终 verdict 负责会不清楚
2. 工具调用重复
   - 两个 agent 很容易围绕同一 gap 重复查询
3. trace 可解释性下降
   - 最终很难还原“为什么停”“谁推动了升级”
4. 主循环失焦
   - 当前最需要的是把单循环的收敛逻辑打稳，而不是再引入协商层

因此 Plan 8 明确不把“双 investigator”作为主方案。

### 适合的第二个 agent：Reviewer / Delivery Gate

如果要引入第二个 agent，最合理的职责是：

- 输入：
  - 冻结后的 `incident.json`
  - `investigation_trace.json`
  - `report_outline`
- 输出：
  - 一个结构化审查结果

例如：

```json
{
  "approve_delivery": false,
  "suggested_status": "needs_review",
  "blocking_checks": ["counterevidence_checked", "boundary_explained"],
  "overclaims": ["execution evidence is still weak"],
  "missing_references": ["timeline event evt-305 has no observation link"],
  "next_best_actions": ["check counterevidence", "ground boundary before delivery"]
}
```

### Reviewer 的关键约束

为了不让第二个 agent 重新把系统搞复杂，Reviewer 必须满足以下约束：

1. 不调用外部工具
2. 不直接修改 `incident_state`
3. 只输出 schema 化审查结果，不输出一篇新的自由发挥报告
4. 一旦与主 agent 冲突，系统默认取更保守的一侧

### 双 agent 在 Plan 8 中的位置

Plan 8 不把 reviewer agent 作为第一阶段必做项。

更明确地说：

> **Reviewer agent 不属于 Plan 8 的主交付范围，除非单 agent 的 readiness、delivery verdict 与 deterministic report 已经稳定。**

建议顺序是：

1. 先把单 agent 的：
   - `delivery_verdict`
   - `readiness checks`
   - `counterevidence gate`
   做稳定
2. 再引入 reviewer agent，作为**交付验收层**
3. 由确定性逻辑统一合并：
   - investigator 的 `delivery_verdict`
   - reviewer 的 `approve_delivery`
   - readiness checks

也就是说，Reviewer 不是替代主循环，而是补在主循环之后的**acceptance layer**。

### 对 Plan 8 的影响

这意味着 Plan 8 对双 agent 的正式判断是：

- 不做多 investigator 主链
- 可预留 reviewer-style second agent 作为下一步扩展
- 第二个 agent 的作用是“卡交付”，不是“代替调查”
- Reviewer 更像 CI/CD 里的 gatekeeper，而不是调查主循环里的平行参与者

---

## 核心改造一：Verdict 从单层判定改为双层判定

### 当前问题

当前 `_build_runtime_verdict(...)` 直接输出：

- `status`
- `confidence`
- `severity`
- `rationale`

这让系统在“还在收敛”的时候，也被迫直接给出“最终结论口径”。

### 改造目标

把 verdict 拆成两层：

1. `provisional_verdict`
   - 当前调查方向
   - 当前证据更像什么
   - 可以更敏感、更早形成

2. `delivery_verdict`
   - 当前是否满足交付级结论条件
   - 对外展示的最终状态
   - 必须受 readiness checks 约束

### 建议数据结构

在 `incident_state` 或 `finalized` 结构中新增：

```json
{
  "provisional_verdict": {
    "status": "confirmed_incident | needs_review | monitor_only",
    "confidence": 0,
    "rationale": []
  },
  "delivery_verdict": {
    "status": "confirmed_incident | needs_review | monitor_only",
    "confidence": 0,
    "rationale": [],
    "gating_reasons": []
  }
}
```

其中：

- `provisional_verdict` 可以较早收敛
- `delivery_verdict` 需要经过 readiness checks 升格

同时需要明确顶层 contract：

- `incident.json.verdict` = `delivery_verdict`
- `incident.json.provisional_verdict` 单独保留
- 报告首页和对外展示一律使用 `delivery_verdict`

也就是说：

> **顶层 verdict 不能表示“仍在收敛中的方向判断”，它必须表示“当前可对外交付的结论”。**

### 实施策略

当前 `_build_runtime_verdict(...)` 不直接返回最终 verdict，而是拆成：

- `_build_provisional_verdict(...)`
- `_upgrade_delivery_verdict(...)`

前者负责“基于当前事实判断趋势”，后者负责“判断能否作为对外交付结论”。

### 预期收益

- 避免第一步上下文就直接把最终 verdict 锁死
- 为 trace 增加“内部方向变化”提供天然位置
- 为 `needs_review` 场景保留更自然的渐进收敛过程

---

## 核心改造二：Verdict 增加证据维度门禁，而不是只看总分

### 当前问题

当前 verdict 主要由：

- `primary_score`
- `benign_score`
- `execution_seen / lateral_seen / exfil_seen`
- `supporting_obs` 数量

组合得出。

这个逻辑的优点是简单直接；
缺点是它很容易把：

- 同一批事件簇的强信号

放大成：

- 足够支撑交付级结论的多维证据

但两者并不等价。

### 改造目标

对 `confirmed_incident` 引入显式的证据维度判定，而不是只靠分数。

建议的维度：

- `seed_direct_evidence`
  - seed 本身是否为高风险直接命中
- `repeat_or_cluster`
  - 是否已观察到重复通信或连续事件簇
- `progression_evidence`
  - 是否已延伸到执行 / lateral / exfil / 明确主机线索
- `scope_grounded`
  - 影响资产或边界是否已经基本收敛
- `counterevidence_checked`
  - 是否已经主动检查过替代解释

### 建议规则

`confirmed_incident` 不再只看 `primary_score`，而是至少满足：

1. `seed_direct_evidence = true`
2. `repeat_or_cluster = true`
3. 以下至少一个为真：
   - `progression_evidence = true`
   - `scope_grounded = true` 且 `counterevidence_checked = true`

`needs_review` 的典型情况：

- seed 和重复通信都已存在
- 但 progression 尚弱
- 或边界未收敛
- 或反证未检查

`monitor_only` 的典型情况：

- 反证强于正证
- 或同类信号更像维护 / 更新 / 共享基线

### 预期收益

- `confirmed_incident` 不会再被单一高分路径轻易触发
- `needs_review` 会更像一个稳定中间态，而不是“差一点确认”
- 反证检查会变成真正影响 verdict 的门槛

---

## 核心改造三：把 `report_ready` 改为显式 readiness checklist

### 当前问题

当前 `report_ready` 逻辑更像“流程走到了末端”，而不是“交付条件已经满足”。

### 改造目标

把 `report_ready` 改成一组带原因的 checklist。

建议至少包含：

1. `context_built`
   - 最小上下文已经建立
2. `cluster_built`
   - 事件簇已形成，非孤立告警
3. `decision_basis_grounded`
   - 已有可引用的正证据或反证
4. `counterevidence_checked`
   - 已进行反证检查，而不是仅仅“没看到反证”
5. `boundary_explained`
   - 当前事件边界已能说明为什么止于此
6. `observation_links_complete`
   - 核心证据和时间线节点能映射到 observation
7. `open_questions_within_budget`
   - 高优问题要么解决，要么明确保留并解释为何仍可交付

### 建议数据结构

新增：

```json
{
  "readiness": {
    "checks": [
      {"id": "context_built", "passed": true, "reason": "..."},
      {"id": "counterevidence_checked", "passed": false, "reason": "..."}
    ],
    "ready": false,
    "blocking_checks": ["counterevidence_checked"]
  }
}
```

建议在实现上把 readiness 组织成一个单独的 evaluator，而不是把各项判断散落在主循环中。

例如：

- `ReadinessEvaluator`
- 或一组 `_evaluate_*` / `_readiness_checks(...)` 函数

其职责是：

- 接收冻结后的 `incident_state / finalized state`
- 输出结构化 checks
- 给出 `ready` 与 `blocking_checks`
- 为每个未通过项提供明确 `reason`

同时需要强调：

- `seed_direct_evidence`
- `repeat_or_cluster`
- `counterevidence_checked`
- `boundary_explained`

这类门槛必须基于结构化状态与事件事实在代码层硬校验，而不是只在 prompt 中作为软提示。

### Stop 逻辑改造

当前 stop 决策可以继续保留预算逻辑，但 `report_ready` 分支要改成：

- `readiness.ready = true`
- 且已经过最少轮数

如果高优 check 未通过，即使当前没有高价值动作，也不直接宣告“稳定交付”，而是：

- 进入保守停机
- 输出 `needs_review`
- 在 trace 中写明未满足的 readiness checks

### 预期收益

- 停止条件变得可解释
- `needs_review` 交付会更自然
- 后续 smoke/eval 可以直接卡每条 readiness check

---

## 核心改造四：把 counterevidence 检查变成显式动作

### 当前问题

当前系统在一些 benign fixture 中能正确降级，这是优点；
但从 runtime 角度看，反证更多是“查出来了就算”，而不是“系统明确知道自己正在做反证检查”。

这会导致：

- `counterevidence_checked` 的含义偏弱
- 某些 case 只是没碰巧查到 benign，就会显得像没问题

### 改造目标

新增显式的 counterevidence action，例如：

- `check_counterevidence`
- `review_shared_baseline`
- `review_maintenance_context`

这些动作不一定需要新工具；
可以继续复用：

- `search_related_events`
- `expand_asset_scope`
- `TraceStore` 查询

关键是让系统在 trace 和 state 里明确记录：

- 这一步是在找替代解释
- 找到了什么
- 没找到什么

这里的关键不是新增底层工具，而是新增高阶意图层。

也就是说，系统可以显式产生类似：

- `Intention.CHECK_COUNTEREVIDENCE`
- `Intention.REVIEW_SHARED_BASELINE`

然后再把这些高阶意图映射到：

- `search_related_events`
- `expand_asset_scope`
- 本地基线查询

这样做的好处是：

- trace 能明确表明“当前正在做反证检查”
- readiness 可以基于“是否执行过显式反证动作”做硬判断
- 不会把 counterevidence 退化成“碰巧查到了 benign event”

### 触发时机

当出现以下任一情况时，counterevidence 检查优先级上升：

- `confirmed_incident` 候选但 progression 仍弱
- 出现共享基础设施 / 兄弟资产
- 命中像更新 / patch / backup 这类弱信号背景
- 当前边界难以收敛

### 预期收益

- 降级场景更稳
- `needs_review` 不再只是“证据不够”，而是真正“正反都查过仍不足”
- 结论更像调查产物，而不是单向证据堆叠

### 语义约束

`counterevidence_checked = true` 的条件需要被写死为：

- **系统显式执行过反证检查动作**

而不是：

- 只是碰巧出现了一条 benign 事件
- 或在普通扩查中顺带看见了背景信息

否则这个字段仍然会缺乏约束力。

---

## 核心改造五：给每类 observation 增加 provenance 与证据等级

### 当前问题

当前 observation 已经区分了：

- `event`
- `intel`
- `page`

但对于报告与最终判定来说，这个粒度还不够。

我们还需要知道：

- 它是不是原始事件事实
- 它是不是外部正文直接证据
- 它是不是结构化情报
- 它是不是内部 digest 的再整理

### 改造目标

给 observation 和 claim 增加更明确的 provenance：

- `trace_event`
- `structured_intel`
- `page_content`
- `internal_digest`
- `search_result_only`

同时新增一个“证据等级”层：

- `direct`
- `supporting`
- `contextual`
- `derived`

### 规则建议

- 来自 fixture 事件的 observation：
  - provenance = `trace_event`
  - evidence_level = `direct` 或 `supporting`
- 来自 ThreatFox / URLhaus / structured intel：
  - provenance = `structured_intel`
  - evidence_level = `supporting`
- 来自真实页面正文抽取：
  - provenance = `page_content`
  - evidence_level = `supporting` 或 `contextual`
- 来自 `_compose_digest()` 再压缩出的 claim：
  - provenance = `internal_digest`
  - evidence_level = `derived`

### 报告使用原则

- `derived` 不作为“新增外部证据”使用
- `direct + supporting` 决定 verdict 权重
- `contextual + derived` 主要用于解释性文字和背景说明

### 预期收益

- 报告会更诚实
- verdict 会更稳
- 后续模型再润色时，不容易把内部整理误当外部证据

---

## 核心改造五点五：报告生成采用“确定性事实组织 + 可选 LLM 润色”的分层策略

### 当前问题

当前系统已经具备：

- 从 `incident.json` 生成结构化 outline
- 从 outline / incident 确定性生成 `report.md`
- 可选地让 LLM 对报告进行一次润色

这条路线本身是对的，但 Plan 8 需要把它明确成一个设计选择，而不是保留为“先这样凑合”。

当前真正需要回答的问题不是：

- 报告到底要不要用 LLM

而是：

- 哪一层必须确定性
- 哪一层允许 LLM 参与
- 哪一层绝不能交给 LLM 决定

### 结论

Plan 8 采用**分层混合方案**，而不是二选一：

1. `incident.json`
   - 唯一事实源
2. `report_outline.json`
   - 由代码从 `incident.json` 派生的交付视图模型
3. `report.md`
   - 必须存在确定性版本
   - 可以存在可选的 LLM 润色版本

换句话说：

- **事实抽取与组织必须用代码做**
- **语言质量优化可以交给 LLM**
- **是否可交付绝不能由写报告的 LLM 决定**

同时需要明确 artifact contract：

- `report_outline.json` 是 renderer、smoke、reviewer 的 canonical input
- `report.md` 永远表示 deterministic 报告
- 如果启用润色，输出单独的 `report_polished.md`

也就是说：

> **不能让 `report.md` 在 deterministic 与 polished 两种含义之间摇摆。**

### 为什么不建议“完全让 LLM 写最终报告”

如果当前阶段直接把最终报告端到端交给 LLM，会带来几个问题：

1. 事实问题和表达问题会混在一起
2. 很难判断错误到底出在：
   - 调查逻辑
   - 交付门槛
   - 还是写作模型
3. 后续 regression 很难做稳定 diff
4. 模型更容易把：
   - 内部 digest
   - 背景上下文
   - 推断性语言
   混写成“像事实一样的报告句子”

因此，Plan 8 明确不采用“LLM 直接从 incident 写整篇报告”作为主路径。

### 为什么也不建议“先完全不考虑报告模块”

虽然 Plan 8 的重点不是文风优化，但报告模块不能完全后置。

原因是报告并不只是展示层，它本身也是验收面的一部分。

至少需要一个稳定的、可回放的、可 diff 的确定性输出，用来支撑：

- smoke
- acceptance
- reviewer agent
- 回归对比

所以正确的取舍不是：

- 现在不管报告

而是：

- 现在先把报告的事实组织层稳定下来
- 之后再单独优化语言表达层

### 建议的报告分层

建议把报告链条明确写成：

```text
incident.json
-> report_outline.json
-> deterministic report.md
-> optional polished report.md
```

其中：

- `incident.json`
  - 保存事实、状态、结论、边界、observation 关系
- `report_outline.json`
  - 保存可交付报告视图：
    - 章节
    - 证据链
    - 时间线
    - 未决问题
    - 处置建议
- `deterministic report.md`
  - 保证无 LLM 也能交付
- `optional polished report.md`
  - 只在事实不变的前提下优化：
    - 可读性
    - 去重复
    - 行文自然度

对应产物建议固定为：

- `report_outline.json`
- `report.md`
- `report_polished.md`（可选）

### LLM 在报告中的职责边界

LLM 只允许做：

- 句子压缩
- 段落衔接
- 减少模板感
- 把重复信息合并成更自然的中文表达

LLM 不允许做：

- 新增 IOC
- 新增资产
- 新增阶段
- 修改 verdict
- 修改 readiness 结论
- 发明不存在的证据来源

### 报告模块在 Plan 8 中的实施策略

Plan 8 对报告模块采取“先稳事实组织，后优语言表达”的策略。

本轮优先级如下：

1. 固化 `incident.json -> report_outline`
2. 固化确定性 renderer
3. 把 observation 引用、边界说明、未决问题写稳定
4. 保留 LLM polish 作为可选覆盖层
5. 把语言风格优化留到后续独立模块再做

这意味着：

- 报告模块现在不能不管
- 但也不应该抢在 runtime 校准之前成为主战场

### 对双 agent 的影响

如果后续引入 reviewer agent，那么 reviewer 的输入不应是最终自由文本报告，而应优先是：

- `incident.json`
- `report_outline.json`

因为 reviewer 判断“是否可交付”时，最不应该依赖的就是一篇已经被润色过的 prose。

---

## 核心改造六：动作选择从“普遍可让 LLM 参与”改成“只有歧义时才让 LLM 介入”

### 当前问题

当前 `_choose_action(...)` 的设计是合理的，但仍然偏“模型可选地参与全阶段动作排序”。

这在规模较小的循环里不是问题，但当 Plan 8 重点转向收敛校准后，更合适的策略应该是：

- obvious phase 用规则
- ambiguous phase 用 LLM

### 改造目标

明确区分三类阶段：

1. `bootstrap phase`
   - 必做动作
   - 规则直走
   - 例如：
     - `search_seed_context`
     - `search_related_events`

2. `ambiguity phase`
   - 候选动作之间存在明显 tradeoff
   - 才让 LLM 选
   - 例如：
     - 是先查反证还是先补外部基础设施
     - 是先扩范围还是先收边界

3. `closing phase`
   - 以 readiness gap 为导向
   - 规则优先补齐缺口

### 实施策略

给 candidate 增加更明确的元信息：

- `phase`
- `gated_by`
- `improves_checks`
- `risk_if_skipped`

LLM 不再在所有场景中都“从头决定下一步”，而是在歧义阶段里做有限选择。

### 预期收益

- 行为更稳定
- trace 更容易解释
- 模型的作用更集中在高价值分歧上

---

## 核心改造七：让 `needs_review` 成为稳定交付态，而不是失败过渡态

### 当前问题

现在系统已经会输出 `needs_review`，这很好；
但很多 `needs_review` case 仍然有一种感觉：

> “好像已经很像 confirmed，只是语言上稍微保守一点”

这会带来两个问题：

- 用户难以理解为什么没升级
- 系统自己也容易在后续版本中继续往激进方向漂移

### 改造目标

把 `needs_review` 设计成一个稳定、可信、可交付的终态。

它应该明确回答：

- 目前最强的主支撑是什么
- 为什么这些支撑仍不足以升级
- 哪些边界已收敛
- 哪些边界仍未收敛
- 下一步最值得补什么

### 实施点

- `open_questions` 的生成逻辑继续保留，但要区分优先级
- `analysis` 与 `scope_and_boundary` 渲染时，要显式强调：
  - 未确认项
  - 阻断升级的关键缺口

### 预期收益

- `needs_review` 会更像真正的 IR 交付
- 系统不会为了追求“看起来聪明”而一味升级结论

---

## 代码改造建议

Plan 8 主要集中在以下文件：

### 1. `demo_agent/incidents/agent.py`

重点修改：

- `_build_runtime_verdict(...)`
- `_open_questions(...)`
- `_finalize_runtime_state(...)`
- `_stop_decision(...)`
- `_choose_action(...)`

新增建议：

- `_build_provisional_verdict(...)`
- `_upgrade_delivery_verdict(...)`
- `_readiness_checks(...)`
- `_counterevidence_needed(...)`
- `_decision_dimensions(...)`
- `ReadinessEvaluator` 或等价函数群

### 2. `demo_agent/incidents/render.py`

重点修改：

- `build_incident_report_outline(...)`
- `render_incident_report(...)`
- `render_incident_report_with_llm(...)`

目标：

- 明确 `incident.json -> report_outline -> report.md` 的分层
- 确保确定性报告始终可交付
- 把 LLM 的职责收缩到 polish，而不是事实生成

新增展示：

- readiness 状态摘要
- 保守停机原因
- 未满足的关键检查项
- 证据 provenance 的选择性暴露

### 3. `demo_agent/tools/exploration.py`

重点修改：

- `extract_claim_candidates_from_page(...)`

目标：

- 区分真实页面正文抽取与内部 digest 抽取
- 为 claim 增加 provenance 和 evidence level

### 4. `demo_agent/incidents/reviewer.py` 或等价模块

如果后续引入 reviewer-style second agent，建议新增一个单独模块负责：

- 冻结交付快照
- 执行 delivery review
- 输出 schema 化审查结果

这个模块不应持有事件扩查工具。

这个模块不属于 Plan 8 主实现范围，只保留为后续扩展位。

### 5. `tools/run_incident_smoke.py`

重点修改：

- acceptance 检查项扩展
- trace 质量检查
- readiness 检查

新增重点：

- early-confirm guard
- counterevidence check guard
- observation-reference coverage

---

## 评测与验收策略

### 新增 3 类质量指标

#### 1. `early_confirm_rate`

定义：

- 在达到最少 readiness checks 前，就把最终 verdict 输出为 `confirmed_incident` 的比例

目标：

- 显著下降

#### 2. `readiness_precision`

定义：

- 被标为 `report_ready` 的 case 中，真正满足交付门槛的比例

目标：

- 显著上升

#### 3. `evidence_reference_coverage`

定义：

- 报告核心时间线与核心证据中，能映射到 observation 的比例

目标：

- 保持高覆盖，避免“看起来像证据但无来源”

### Fixture acceptance 扩展建议

每个 fixture 的 acceptance 除了现有字段外，可新增：

- `must_check_counterevidence`
- `must_leave_open_questions`
- `max_delivery_confidence_before_step`
- `must_reference_observations_for_fragments`
- `must_not_upgrade_without_progression`

### 保守停机 acceptance

新增一类 acceptance：

- 允许系统停止
- 但不允许它把当前状态渲染成“已经稳定确认”

这类 acceptance 对 `needs_review` 和边界不清场景尤其重要。

---

## 分阶段落地顺序

### Phase 0: 先补可观测性

目标：

- 在不大改判定逻辑前，先让 trace 能够展示：
  - provisional vs delivery
  - readiness checks
  - candidate 决策依据

产出：

- 更强的 `investigation_trace.json`

### Phase 1: 改 verdict 和 readiness

目标：

- 把“方向性判断”和“交付级判断”拆开
- 把 `report_ready` 改成 checklist

这是 Plan 8 最核心的一步。

### Phase 2: 改 provenance 和 counterevidence

目标：

- 补齐证据边界
- 让反证检查变成显式调查动作

### Phase 3: 固化报告生成分层

目标：

- 固化 `incident.json -> report_outline -> deterministic report.md`
- 明确 LLM polish 的职责边界
- 让报告成为稳定验收面，而不是自由文本产物

### Phase 4: 补 smoke 和 acceptance

目标：

- 用评测把前面三步固定下来
- 防止后续回归到“过早确认”

### Phase 5: 可选引入 reviewer-style second agent

目标：

- 在单 agent runtime 足够稳定后
- 为交付环节增加一个只读、保守的 acceptance layer
- 不改变调查主循环的单控制面结构

这个阶段明确不属于 Plan 8 主交付。

---

## 通过标准

Plan 8 完成后，至少应满足：

1. 强信号 case 不再在第一轮上下文后直接稳定给出高置信 delivery verdict，除非 readiness checks 已满足
2. `needs_review` case 能稳定保留关键未决问题，而不是只是语气保守
3. `monitor_only` case 的降级理由中，必须能看到明确的反证或背景解释
4. `report_ready` 不再只是“查过足够多工具”，而是“交付门槛通过”
5. 报告中的关键证据与 observation 引用绑定更完整
6. 确定性报告在无 LLM 情况下也能稳定交付，且与 `report_outline` 一致
7. 如引入 reviewer agent，其结论与 readiness gate 的冲突会默认向更保守一侧收敛
8. smoke 能直接识别：
   - 过早确认
   - 未检查反证
   - readiness 伪通过

---

## 风险与注意事项

### 1. 不要把系统调得过于保守

Plan 8 的目标是“更稳”，不是“永远不确认”。

如果把门槛加得过高，系统可能退化为：

- 大量输出 `needs_review`
- 很少敢输出 `confirmed_incident`

这会损失 incident-agent 的实际价值。

### 2. 不要把 readiness 变成展示层假动作

readiness 必须真正影响：

- delivery verdict
- stop decision
- trace 说明

而不能只是多输出一个漂亮字段。

### 3. 不要把 provenance 做成只为报告服务的标签

provenance 应该同时影响：

- verdict 权重
- evidence ledger
- report rendering

否则它只会变成一个注释层。

### 4. 不要让“反证检查”沦为工具名字替换

只有当系统明确知道：

- 自己正在寻找替代解释
- 找到了什么
- 为什么这些反证不足或足够

counterevidence check 才算真正成立。

### 5. 不要让 report polish 反向污染事实层

如果引入 LLM polish，必须保证：

- polish 输入是冻结后的 outline
- polish 失败可直接回退
- polish 不会修改：
  - verdict
  - observation 引用
  - IOC / 资产 / 阶段

否则报告模块会重新成为幻觉入口。

### 6. 不要让第二个 agent 重新变成第二条调查主链

如果后续引入 reviewer-style second agent，必须坚持：

- 它是 acceptance layer
- 不是 parallel investigator
- 不负责扩查工具
- 不负责重写主状态

否则 Plan 8 本来想解决的是“单循环交付不稳”，结果会退化成“多循环协调更难”。

---

## 一句话概括 Plan 8

如果只用一句话概括 Plan 8：

> **Plan 8 不再扩展 agent 会查什么，而是重点校准 agent 什么时候可以下结论、为什么可以停、以及这些结论到底有多可信。**

如果只用两句话概括：

- Plan 7 解决的是“把单告警系统升级为事件级调查系统”。  
- Plan 8 解决的是“让这个事件级调查系统的收敛过程和交付时机真正可信”。  
