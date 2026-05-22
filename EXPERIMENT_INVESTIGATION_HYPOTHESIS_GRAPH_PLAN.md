# 调查层 Hypothesis Graph 优化计划

## Summary

当前 evidence-graph writer 实验证明了报告层可以更稳定、更可审计，但也暴露出一个更上游的问题：如果调查层只产出 1 个 observation 和 6 条主链事件，writer 只能生成一篇边界正确但信息密度不足的报告。下一步优化目标不是继续打磨 writer prompt，而是把 evidence graph / hypothesis board 前移到调查循环中，让调查层在主链确认后仍能有纪律地追踪候选扩线、共享基础设施、反证背景和未闭合缺口。

本方案参考 ReAct、Tree of Thoughts、Graph of Thoughts、Toolformer、GraphRAG、Cyber Defense Benchmark，以及近期的自动化网络事件响应 / 蓝队取证 agent 研究，建立一个轻量但可执行的调查架构。这里的关键不是再堆一个更复杂的 planner，而是把调查状态显式化，让工具调用、假设更新和停止判断都能被审计。

```text
Observation -> Investigation Evidence Graph -> Hypothesis Board
  -> Deterministic Opportunity Scorer -> Top-k Investigator Choice
  -> Tool Call -> Delta Reviewer
  -> Stop / Continue
```

## Current Execution Status

- 已实现 investigation graph、stateful hypothesis board、deterministic opportunity scorer、VOI-aware stop gate、delta labels，以及 finish reviewer 对 high/medium VOI 的防早停控制。
- 本地验证已覆盖 `tools/test_investigation_graph.py`、`tools/test_investigation_planner.py`、`tools/test_investigation_stop_and_delta.py`、`tools/test_investigation_hypothesis_board.py`、`tools/test_llm_agent_protocol.py` 和相关 `py_compile`。
- `outputs/plan13_v62_finish_gate_live_one/multi_host_confirmed_spread_plus/` 使用 `max-runtime-s 300` 跑通，报告验证 clean；调查层从 v53 的 1 轮提升到 4 轮，恢复 candidate/background 覆盖，但最终因 runtime budget 停止，停止时 VOI 仍为 medium。
- `outputs/plan13_v63_finish_gate_runtime600_live_one/multi_host_confirmed_spread_plus/` 使用 `max-runtime-s 600` 跑通，报告验证 clean；最终 `stop_reason=agent_finish`，`value_of_information_at_stop.level=exhausted`，覆盖 `cdn-notify-edge.net`、`198.51.100.44`、`ws-eng-09`、SCCM、`download.windowsupdate.com`、`rundll32.exe`、DLL 和 `10.70.3.90`。
- `outputs/plan13_v64_investigation_hypothesis_5case_live/` 使用 `max-runtime-s 600` 跑完 5-case live；5 个 case 均 `rc=0`，报告漂移验证均为 clean，未出现 hard fail 或 fallback 隐藏为正常输出。
- v64 停止语义仍有两个待优化点：`shared_infra_multi_asset_needs_review` 以 `preflight_block_loop` 停止且停机 VOI 仍为 high，说明高价值动作被预算/重复/预检层压住；`web_initial_access_without_execution` 以 `runtime_budget_exhausted` 停止，虽然 VOI 已降到 low，但仍说明简单 case 的自然收敛还不够干净。
- 当前判断：hypothesis graph / VOI stop gate 已明显改善复杂 case 的过早结束问题，但还不能认为调查层完成；下一步应聚焦停止控制面，把 high-VOI preflight loop 和 low-VOI runtime stop 转化为可解释的 `agent_finish` 或明确预算止损。

## Research Basis

- ReAct (arXiv:2210.03629) 说明推理和行动应交替发生，工具结果要持续更新计划，而不是一次查到主链就停止。
- Toolformer (arXiv:2302.04761) 强调模型需要学习何时调用工具、传什么参数、如何把工具输出吸收到后续推理。
- Tree of Thoughts (arXiv:2305.10601) 和 Graph of Thoughts (arXiv:2308.09687) 支持多条候选推理路径的保留、评分和回溯，适合把 confirmed chain、candidate spread、benign/shared infra alternative 等假设并行维护。
- GraphRAG (arXiv:2404.16130) 支持先构建显式图，再做全局汇总；这比直接把长材料塞给 writer 更适合 Trace-Agent 的证据组织方式。
- 近期蓝队取证 agent 研究（arXiv:2508.20643）强调 long-term reasoning、contextual memory 和 consistent evidence correlation；这支持把调查状态显式保存，而不是只靠下一轮 prompt 记忆。
- Cyber Defense Benchmark (arXiv:2604.19533) 在其评测设置下显示当前 LLM 在开放式 threat hunting 中仍然很弱，不能指望更强模型自己补齐搜索策略，必须显式设计 investigation state、tool feedback 和 eval。
- In-Context Autonomous Network Incident Response (arXiv:2602.13156) 把 IR agent 拆成 perception、reasoning、planning、action，并用真实观察反复修正 conjecture；这与本计划的 hypothesis graph loop 对齐。

## Approaches Considered

### 方案 A: 证据图 + 假设板 + 确定性机会评分

推荐方案。调查层先把观测编译成 evidence graph 和 hypothesis board，再用 deterministic opportunity scorer 为下一步工具打分。LLM 负责解释和在 top-k 候选之间做轻量选择，不负责自由发挥式规划。优点是可审计、容易回放、最不容易重新长出一个新的 prompt-only 控制层。缺点是前期需要把状态和评分维度定义清楚。

### 方案 B: 证据图 + 假设板 + LLM planner

保留更多模型弹性，但风险是 planner 会重新变成一个难以调试的黑箱，最后又要靠 prompt 和 validator 补洞。适合后续在方案 A 已经证明有效后再考虑。

### 方案 C: 继续只调 prompt / reviewer

成本最低，但 v53 已经证明这条路大概率只能得到“更稳的薄报告”，很难稳定恢复 candidate / counterevidence / shared infra 深度。这个方向不建议作为下一轮主线。

**推荐结论：先做方案 A。**

## Problem Statement

在 `outputs/plan13_v53_task9_evidence_graph_all_ds_v4_live/` 中，5-case 机器验证 clean，但 `multi_host_confirmed_spread_plus` 的报告明显比 `v47_direct_source_current_branch_live` 薄。根因不是 writer 单独退化，而是调查层只执行了 1 轮 `search_seed_context`：

- v47: 5 个 observations，14 条 timeline events，覆盖 `cdn-notify-edge.net`、`198.51.100.44`、`ws-eng-09`、SCCM、Windows Update、QA telemetry/shared infra。
- v53: 1 个 observation，6 条 timeline events，只覆盖 seed 主链。

因此下一步必须解决调查层的 premature stop / shallow search，而不是继续把 writer 写厚。

## Design Principles

- 不做 case-specific hardcoding。禁止针对 fixture 名、event id、时间戳、资产名、域名或期望措辞写规则。
- confirmed main chain 和 candidate boundary 可以共存。主链可交付不代表调查必须立即停止。
- stop gate 应基于 value-of-information，而不是只看 deliverable_now。
- 保持单一可见控制环，不要把计划逻辑拆成多个互相隐藏的循环。
- deterministic code 负责状态编译、证据图更新、id 校验、工具结果 delta 统计和安全停止条件。
- LLM investigator 只在 scorer 给出的 top-k 安全动作中选择或解释，不能绕过工具白名单、参数来源、cooldown 和低收益约束。
- reviewer 只评价本轮工具结果是否产生有效 delta，不接管工具规划，不把自然语言质量偏好变成 blocking failure。
- 所有 fallback、budget stop、runtime stop 必须在 trace 中可见，不能伪装成正常完成。
- 结构化字段优先于自然语言关键词。文本关键词只能作为 advisory signal，不能成为 blocking validator 或 case-specific 控制规则。

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

初始更新规则：

- `confirmed_main_chain` 从 delivery verdict、confirmed events、confirmed scope 和 supporting observations 更新。
- `candidate_spread` 从 candidate events、candidate assets、candidate indicators 和 ungrounded expansion gaps 更新。
- `benign_or_shared_infra_alternative` 从 background events、counterevidence facts、maintenance/shared-infra gaps 更新。
- `insufficient_evidence_limits` 从 open gaps、missing host artifacts、missing command line、missing persistence / attribution / scope evidence 更新。
- `false_positive_or_noise` 只有在 seed context 弱、缺少 confirmed follow-up、或出现明确 benign/background 支撑时才升高优先级。

这些规则只能使用结构化字段、状态、fact type、source type 和 graph relation。不得通过匹配具体资产名、域名、event id 或固定时间戳来更新 hypothesis。

### 3. Deterministic Opportunity Scorer

本层先对候选工具做可解释打分，再把 top-k 候选交给 investigator LLM 进行最终选择或 tie-break。不要把“信息增益”完全交给模型自由发挥，也不要把它写成针对某个 case 的规则树。

输入：

- hypothesis board
- gap ledger
- tool catalog
- budgets
- recent tool deltas

输出：

- ranked candidate actions
- `target_hypothesis_ids`
- `target_gap_ids`
- `expected_information_gain`
- `expected_report_impact`
- `why_this_tool`
- `why_not_finish`

评分维度：

1. 是否能关闭 hard blocking gap。
2. 是否能区分高优先级竞争假设。
3. 是否能显著改变 confirmed scope / candidate boundary / counterevidence boundary。
4. 是否能补足报告必要行动建议字段。
5. 是否重复、低收益、或只是继续加噪声。

LLM 只在 top-2 / top-3 候选非常接近时参与解释，不承担全局规划。

初始评分契约：

| Signal | Score |
| --- | ---: |
| 关闭当前 hard blocking gap | +5 |
| 区分两个以上 active high-priority hypotheses | +4 |
| 可能改变 confirmed scope 或 candidate boundary | +4 |
| 可能补充 counterevidence / benign shared-infra boundary | +3 |
| 可能补足行动建议所需对象、日志源或验证目标 | +2 |
| 只处理 reportable boundary 且不改变报告行动 | -2 |
| 与最近同输入工具重复且无新状态 | -4 |
| 触发 budget / cooldown / forbidden repeat | ineligible |

默认 `top_k=3`。如果最高分动作低于 `+3`，且无 hard blocking gap，则 stop gate 可以把剩余问题标为 reportable boundary。

这些分数是通用初始默认值，不是 fixture-specific 规则。测试应验证通用相对排序，例如“能区分高优先级假设的动作高于重复低收益动作”，而不是验证某个 case 的具体 event id、域名或时间戳。

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

reviewer 产物进入下一轮 scorer / investigator context，但不能硬编码工具路线。

### 5. Value-Of-Information Stop Gate

停止条件应同时考虑交付门槛和继续调查收益。

允许停止：

- 当前 confirmed main chain 足以交付。
- 没有 hard blocking gap。
- 剩余 hypothesis 都是 reportable boundary，或可用工具预期信息增益低。
- 近期工具结果低收益，且没有新候选、新反证、新范围变化。
- 已达到明确的步数 / 工具 / 时间预算上限，且预算止损在 trace 中清晰可见。

不应停止：

- 主链已确认，但出现未验证候选扩线，且有可用低成本工具能验证。
- 存在共享基础设施/维护窗口背景，但尚未查询或尚未写成边界。
- candidate asset / second-hop infra 会显著改变报告范围或行动建议。
- 工具 budget 充足且上一轮有 material delta。
- 仅仅因为 `deliverable_now=true` 就停止，而没有检查 `candidate_spread`、`benign/shared infra` 或 `counterevidence` 的信息增益。

## File Map

- Create `demo_agent/incidents/investigation_graph.py`: deterministic investigation graph compiler and hypothesis-board updater.
- Create `demo_agent/incidents/investigation_planner.py`: opportunity scorer, top-k action ranking, and VOI stop summary.
- Modify `demo_agent/incidents/agent.py`: expose the new investigation graph state, wire the scorer into investigator/reviewer context, and separate deliverable vs preferred-stop.
- Modify `demo_agent/incidents/render.py`: persist investigation graph artifacts into run outputs and keep report-side graph data in sync with the investigation graph.
- Modify `demo_agent/incidents/report_agent_tools.py`: add graph-to-fact and graph-to-gap projection helpers for `report_source_bundle`.
- Modify `demo_agent/incidents/report_agent_writer.py`: keep writer inputs graph-grounded, but do not let investigation-layer candidates become confirmed facts.
- Modify `tools/test_investigation_hypothesis_board.py`: replace the current visibility-only checks with state update and ranking checks.
- Create `tools/test_investigation_graph.py`: verify graph construction, hypothesis updates, and no invented facts.
- Create `tools/test_investigation_planner.py`: verify opportunity scoring, top-k tie-breaking, and stop-gate outputs.
- Modify `tools/evaluate_report_quality.py`: add a benchmark comparison mode for v47 vs new investigation-layer runs.
- Modify `demo_agent/docs/README.md`: document the new investigation-layer experiment and its artifacts.

## Target Artifacts

每个 investigation hypothesis graph run 至少应额外保存：

- `investigation_graph.json`: 调查期 evidence graph，不等同于 report-time `report_evidence_graph.json`。
- `investigation_hypothesis_board.json`: 由调查期 graph 更新的 hypothesis board，不等同于 writer 用的 `report_hypothesis_board.json`。
- `investigation_opportunity_trace.json`: 每轮 candidate actions、score、top-k、selected action、why-not-finish。
- `run_metrics.json`: 增加 `value_of_information_at_stop`、`hypothesis_status_counts`、`delta_label_counts`、`candidate_event_count`、`background_event_count`。

这些 artifact 的目标是解释“为什么继续查 / 为什么停止”，而不是给 writer 新增事实来源。writer 仍只能使用 source bundle / fact catalog 中可追溯事实。

## Implementation Plan

### Task 1: Add Investigation Graph State

**Files:**
- Create: `demo_agent/incidents/investigation_graph.py`
- Modify: `demo_agent/incidents/agent.py`
- Test: `tools/test_investigation_graph.py`

- 新增 `demo_agent/incidents/investigation_graph.py`。
- 从现有 `incident_state`、`evidence_ledger`、`annotated_events`、`gap_ledger`、`tool_history` 编译 `investigation_graph`。
- 每个节点和边必须保留 source id / observation id / event id。
- 添加 unit tests，验证不发明实体、不丢 candidate/background 状态。

### Task 2: Make Hypothesis Board Stateful

**Files:**
- Modify: `demo_agent/incidents/agent.py`
- Test: `tools/test_investigation_hypothesis_board.py`

- 用 deterministic compiler 从 investigation graph 生成或更新 `session_state.hypothesis_board`。
- 替换当前只初始化空 board 的实现。
- active hypothesis 必须能反映 confirmed chain、candidate spread、benign/shared infra、open limits。
- 添加 tests 覆盖：主链确认后仍保留 candidate spread；共享基础设施进入 alternative hypothesis；缺命令行进入 insufficient evidence limits。

### Task 3: Add Deterministic Opportunity Scorer Contract

**Files:**
- Create: `demo_agent/incidents/investigation_planner.py`
- Modify: `demo_agent/incidents/agent.py`
- Test: `tools/test_investigation_planner.py`

- 扩展 investigator prompt 和 action schema，让 investigator 输出 target hypotheses、expected information gain、expected report impact。
- 不强制具体工具顺序；只要求解释工具如何区分假设，且只能在 top-k 候选中选择。
- preflight 只校验 schema、tool id、params 来源和 cooldown，不校验自然语言措辞。
- opportunity scorer 必须能解释为什么某个动作比 finish 更值得做，且该解释不能依赖 case-specific 关键词。

### Task 4: Rework Stop Gate

**Files:**
- Modify: `demo_agent/incidents/agent.py`
- Modify: `demo_agent/incidents/render.py`

- 把 `deliverable_now` 和 `preferred_stop` 分离。
- 新增 `value_of_information` summary：high / medium / low / exhausted。
- 如果主链 confirmed 但 candidate spread 或 shared infra hypothesis 仍 high value，继续调查。
- runtime budget stop 必须标明是 budget stop，不应被写成调查自然完成。
- `run_metrics.json` 必须记录 `value_of_information_at_stop` 和触发 stop 的主要 hypothesis/gap。

### Task 5: Improve Delta Review

**Files:**
- Modify: `demo_agent/incidents/agent.py`
- Modify: `tools/evaluate_report_quality.py`

- post-action reviewer 输出标准化 delta labels。
- 低收益判断必须基于本轮 observation delta，而不是工具名或 case 预期。
- delta labels 进入 run metrics，方便比较 v47/v53 这类差异。

### Task 6: Feed Investigation Graph Into Report Source Bundle

**Files:**
- Modify: `demo_agent/incidents/render.py`
- Modify: `demo_agent/incidents/report_agent_tools.py`
- Modify: `demo_agent/incidents/report_agent_writer.py`

- `report_source_bundle` 应能完整吸收 investigation graph 中的 candidate/background/counterevidence facts。
- 确保 report-time evidence graph 不会因为调查层 shallow state 只看到 seed main chain。

### Task 7: Evaluation And Regression

**Files:**
- Create: `tools/test_investigation_graph.py`
- Create: `tools/test_investigation_planner.py`
- Modify: `tools/evaluate_report_quality.py`
- Modify: `demo_agent/docs/README.md`

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
- 评估时区分“主链仍可交付但候选边界更厚”与“报告质量真的变好”，不要只看字符数。

## Acceptance Criteria

- `multi_host_confirmed_spread_plus` 不再在只执行 `search_seed_context` 后停止，除非没有任何 high/medium value action。
- 在 benchmark 回归样本上，新输出应恢复或超过 v47 的复杂边界覆盖：`cdn-notify-edge.net`、`198.51.100.44`、`ws-eng-09`、SCCM、Windows Update、QA telemetry/shared infra。
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
3. 在 scorer / investigator context 中暴露高价值 hypothesis / gap。
4. 调整 stop gate，避免 confirmed main chain 后过早停止。
5. 跑 `multi_host_confirmed_spread_plus` live，对比 v47、v53。

如果单 case 证明能恢复候选链和反证边界，再跑 5-case live。
