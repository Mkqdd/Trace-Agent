# 调查层 Hypothesis Graph 优化计划

## Summary

当前 evidence-graph writer 实验证明了报告层可以更稳定、更可审计，但也暴露出一个更上游的问题：如果调查层只产出 1 个 observation 和 6 条主链事件，writer 只能生成一篇边界正确但信息密度不足的报告。下一步优化目标不是继续打磨 writer prompt，而是把 evidence graph / hypothesis board 前移到调查循环中，让调查层在主链确认后仍能有纪律地追踪候选扩线、共享基础设施、反证背景和未闭合缺口。

本方案参考 ReAct、Tree of Thoughts、Graph of Thoughts、Toolformer、CyberSleuth、Cyber Defense Benchmark 和 autonomous incident response agent 相关论文，建立一个轻量但可执行的调查架构：

```text
Observation -> Investigation Evidence Graph -> Hypothesis Board
  -> Information-Gain Planner -> Tool Call -> Delta Reviewer
  -> Stop / Continue
```

## Research Basis

- ReAct 说明推理和行动应交替发生，工具结果要持续更新计划，而不是一次查到主链就停止。Source: https://arxiv.org/abs/2210.03629
- Toolformer 强调模型需要学习何时调用工具、传什么参数、如何把工具输出吸收到后续推理。Source: https://arxiv.org/abs/2302.04761
- Tree of Thoughts 和 Graph of Thoughts 支持多条候选推理路径的保留、评分和回溯，适合把 confirmed chain、candidate spread、benign/shared infra alternative 等假设并行维护。Sources: https://arxiv.org/abs/2305.10601 and https://arxiv.org/abs/2308.09687
- CyberSleuth 的经验是：网络取证 agent 需要 long-term reasoning、contextual memory 和 consistent evidence correlation；多 agent 专门化有价值，但简单编排通常比复杂层级更稳。Source: https://arxiv.org/abs/2508.20643
- Cyber Defense Benchmark 显示当前 LLM 在开放式 threat hunting 中仍然很弱，不能指望更强模型自己补齐搜索策略；必须显式设计 investigation state、tool feedback 和 eval。Source: https://arxiv.org/abs/2604.19533
- In-Context Autonomous Network Incident Response 把 IR agent 拆成 perception、reasoning、planning、action，并用真实观察反复修正 conjecture；这与本计划的 hypothesis graph loop 对齐。Source: https://arxiv.org/abs/2602.13156

## Problem Statement

在 `outputs/plan13_v53_task9_evidence_graph_all_ds_v4_live/` 中，5-case 机器验证 clean，但 `multi_host_confirmed_spread_plus` 的报告明显比 `v47_direct_source_current_branch_live` 薄。根因不是 writer 单独退化，而是调查层只执行了 1 轮 `search_seed_context`：

- v47: 5 个 observations，14 条 timeline events，覆盖 `cdn-notify-edge.net`、`198.51.100.44`、`ws-eng-09`、SCCM、Windows Update、QA telemetry/shared infra。
- v53: 1 个 observation，6 条 timeline events，只覆盖 seed 主链。

因此下一步必须解决调查层的 premature stop / shallow search，而不是继续把 writer 写厚。

## Design Principles

- 不做 case-specific hardcoding。禁止针对 fixture 名、event id、时间戳、资产名、域名或期望措辞写规则。
- confirmed main chain 和 candidate boundary 可以共存。主链可交付不代表调查必须立即停止。
- stop gate 应基于 value-of-information，而不是只看 deliverable_now。
- deterministic code 负责状态编译、证据图更新、id 校验、工具结果 delta 统计和安全停止条件。
- LLM investigator 负责在多个开放假设之间选择最能区分它们的下一步工具调用。
- reviewer 只评价本轮工具结果是否产生有效 delta，不接管工具规划，不把自然语言质量偏好变成 blocking failure。
- 所有 fallback、budget stop、runtime stop 必须在 trace 中可见，不能伪装成正常完成。

## Target Architecture

### 1. Investigation Evidence Graph

在每次工具调用后，确定性更新一个调查期 evidence graph。它不同于 report-time graph：它服务于下一轮调查，而不是最终写作。

核心节点：

- `event`: seed、confirmed、candidate、background、counterevidence。
- `asset`: confirmed affected、candidate affected、background asset。
- `indicator`: IP、domain、JA4、process、file、service、internal IP。
- `hypothesis`: confirmed main chain、candidate spread、benign/shared infra alternative、insufficient evidence limits、false positive/noise。
- `gap`: host artifact missing、candidate not grounded、shared infra ambiguity、counterevidence missing、scope not exhausted。
- `action`: available tool actions and expected discriminating value。

核心边：

- `supports`: fact supports hypothesis。
- `refutes`: fact weakens hypothesis。
- `limits`: fact/gap limits stronger conclusion。
- `suggests_next`: gap suggests action。
- `same_infra_as`: entities share infrastructure。
- `candidate_extension_of`: candidate chain extends confirmed chain。
- `background_for`: background event may explain or constrain suspicious interpretation。

### 2. Real Hypothesis Board

当前 `hypothesis_board` 只是空状态和 prompt 可见字段。新版本必须由工具结果驱动更新。

默认假设集合：

- `confirmed_main_chain`: 当前是否足以支撑事件级交付。
- `candidate_spread`: 是否存在额外资产或第二跳传播。
- `benign_or_shared_infra_alternative`: 是否存在共享基础设施、补丁、SCCM、Windows Update、QA telemetry、维护窗口等替代解释。
- `insufficient_evidence_limits`: 哪些更强结论不能写，例如完整控制、持久化、恶意软件家族归属。
- `false_positive_or_noise`: seed 是否可能只是孤立误报或背景噪声。

每个 hypothesis 维护：

- `status`: open / supported / weakened / closed。
- `support_fact_ids`
- `refute_fact_ids`
- `gap_ids`
- `candidate_action_ids`
- `last_updated_step`
- `priority`
- `why_next`

### 3. Information-Gain Planner

planner 输入 hypothesis board、gap ledger、tool catalog、budgets 和 recent tool deltas，输出下一步工具调用或 finish。

工具选择优先级：

1. 能关闭 hard blocking gap 的工具。
2. 能区分高优先级竞争假设的工具。
3. 能显著改变 confirmed scope / candidate boundary / counterevidence boundary 的工具。
4. 能补足报告必要行动建议字段的工具。
5. 低收益、重复、只会增加背景噪声的工具降级。

planner 输出必须包含：

- `target_hypothesis_ids`
- `target_gap_ids`
- `expected_information_gain`
- `expected_report_impact`
- `why_this_tool`
- `why_not_finish`

### 4. Delta Reviewer

post-action reviewer 只判断工具结果增量，不规划下一步工具。

delta 类型：

- `new_confirmed_event`
- `new_candidate_event`
- `new_background_or_counterevidence`
- `candidate_grounded`
- `candidate_weakened`
- `scope_changed`
- `actionability_improved`
- `no_material_delta`

reviewer 产物进入下一轮 planner，但不能硬编码工具路线。

### 5. Value-Of-Information Stop Gate

停止条件应同时考虑交付门槛和继续调查收益。

允许停止：

- 当前 confirmed main chain 足以交付。
- 没有 hard blocking gap。
- 剩余 hypothesis 都是 reportable boundary，或可用工具预期信息增益低。
- 近期工具结果低收益，且没有新候选、新反证、新范围变化。

不应停止：

- 主链已确认，但出现未验证候选扩线，且有可用低成本工具能验证。
- 存在共享基础设施/维护窗口背景，但尚未查询或尚未写成边界。
- candidate asset / second-hop infra 会显著改变报告范围或行动建议。
- 工具 budget 充足且上一轮有 material delta。

## Implementation Plan

### Task 1: Add Investigation Graph State

- 新增 `demo_agent/incidents/investigation_graph.py`。
- 从现有 `incident_state`、`evidence_ledger`、`annotated_events`、`gap_ledger`、`tool_history` 编译 `investigation_graph`。
- 每个节点和边必须保留 source id / observation id / event id。
- 添加 unit tests，验证不发明实体、不丢 candidate/background 状态。

### Task 2: Make Hypothesis Board Stateful

- 用 deterministic compiler 从 investigation graph 生成或更新 `session_state.hypothesis_board`。
- 替换当前只初始化空 board 的实现。
- active hypothesis 必须能反映 confirmed chain、candidate spread、benign/shared infra、open limits。
- 添加 tests 覆盖：主链确认后仍保留 candidate spread；共享基础设施进入 alternative hypothesis；缺命令行进入 insufficient evidence limits。

### Task 3: Add Information-Gain Planner Contract

- 扩展 investigator prompt 和 action schema，让 investigator 输出 target hypotheses、expected information gain、expected report impact。
- 不强制具体工具顺序；只要求解释工具如何区分假设。
- preflight 只校验 schema、tool id、params 来源和 cooldown，不校验自然语言措辞。

### Task 4: Rework Stop Gate

- 把 `deliverable_now` 和 `preferred_stop` 分离。
- 新增 `value_of_information` summary：high / medium / low / exhausted。
- 如果主链 confirmed 但 candidate spread 或 shared infra hypothesis 仍 high value，继续调查。
- runtime budget stop 必须标明是 budget stop，不应被写成调查自然完成。

### Task 5: Improve Delta Review

- post-action reviewer 输出标准化 delta labels。
- 低收益判断必须基于本轮 observation delta，而不是工具名或 case 预期。
- delta labels 进入 run metrics，方便比较 v47/v53 这类差异。

### Task 6: Feed Investigation Graph Into Report Source Bundle

- `report_source_bundle` 应能完整吸收 investigation graph 中的 candidate/background/counterevidence facts。
- 确保 report-time evidence graph 不会因为调查层 shallow state 只看到 seed main chain。

### Task 7: Evaluation And Regression

- 固定保留 v47 作为 multi-host 深度基准。
- 对每个 live run 输出：
  - tool round count
  - observation count
  - confirmed/candidate/background event count
  - hypothesis board status count
  - stop reason
  - value-of-information at stop
  - report validation
  - manual quality rubric
- 先跑 `multi_host_confirmed_spread_plus`，再跑 5-case。

## Acceptance Criteria

- `multi_host_confirmed_spread_plus` 不再在只执行 `search_seed_context` 后停止，除非没有任何 high/medium value action。
- 新输出应恢复或超过 v47 的复杂边界覆盖：`cdn-notify-edge.net`、`198.51.100.44`、`ws-eng-09`、SCCM、Windows Update、QA telemetry/shared infra。
- 报告仍不能把 candidate chain 写成 confirmed spread。
- 5-case 不出现 case-specific hardcoded validators。
- 所有 runs 明确记录 stop reason 和 value-of-information。
- `py_compile`、`tools/test_llm_agent_protocol.py`、新增 investigation graph tests 通过。

## Non-Goals

- 不引入 Neo4j、networkx、vector database 或复杂 MCTS。
- 不新增第二个 investigator agent。
- 不把 reviewer 变成 planner。
- 不用硬编码规则强制某 case 必须调用某工具。
- 不把 report writer 回退到旧 material agent。

## First Experiment

先做最小闭环：

1. 编译 investigation graph。
2. 真实更新 hypothesis board。
3. 在 planner context 中暴露高价值 hypothesis / gap。
4. 调整 stop gate，避免 confirmed main chain 后过早停止。
5. 跑 `multi_host_confirmed_spread_plus` live，对比 v47、v53。

如果单 case 证明能恢复候选链和反证边界，再跑 5-case live。
