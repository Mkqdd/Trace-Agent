# Plan12: 调查 while loop、上下文与 reviewer 职责重构

## 0. 本版修订重点

这版 plan12 的目标不是继续扩写架构愿景，而是把方案收紧成能安全落地的施工单。相比上一版，主要修正：

- 明确 source of truth，避免把 `runtime`、`catalog`、`acceptance_state`、`delivery_decision` 继续互相复制。
- 明确第一版 `AgentContext` 的最小字段集，防止把旧 runtime 原样塞进新壳子。
- 调整 phase 顺序：先补观测与 preflight，再改 reviewer 职责，避免执行前硬约束空窗。
- 明确 reviewer 只能做 post-action feedback，不能提供可执行 next_action，constraints 也只能影响下一轮。
- 增加 preflight block / reviewer finish feedback 的状态机，避免非法输出或 finish 被拒后空转。
- 增加量化验收指标，不只靠“读起来更好”判断。
- 明确 Phase 2 就先禁用 reviewer replacement 执行路径，避免旧 reviewer 在过渡期继续越权。
- 明确 Phase 0 必须先保存五个 case 的 baseline 指标，后续“不高于重构前”才有比较对象。

本计划只处理调查 while loop，不处理报告撰写、不处理 report polish、不处理从调查结果到报告 brief 的中间整理。

## 1. 当前问题判断

### 1.1 reviewer 职责越权

当前 reviewer 是 pre-execution reviewer，它可以 `block`、`redundant`、`deliverable`、`not_deliverable`，还可以给 `next_action`。主循环随后可能通过 `_reviewer_replacement_tool` 执行 reviewer 给出的替代动作。

这会导致两个问题：

- investigator 不再是唯一语义规划者。
- reviewer 在信息不一定更充分的情况下替换动作，trace 很难解释“为什么实际执行的不是 investigator 想查的东西”。

目标状态：

- investigator 负责语义规划。
- preflight gate 负责执行前硬约束。
- reviewer 只在工具执行后审查效果，并给下一轮 feedback。

### 1.2 runtime 与 catalog 混合了事实、建议和控制状态

当前 `_format_llm_session_summary` 同时包含事实、gap、预算、控制摘要、交付判断、历史和模式；`_available_tool_catalog` 同时包含工具说明、推荐参数、历史、冷却、gap 路由和推荐理由。

这会导致两个问题：

- 模型不知道哪些是事实、哪些是程序建议、哪些是硬约束。
- 后续添加字段时容易继续膨胀，最后只是把旧 workflow 换成更大的 prompt。

目标状态：

- `tool_catalog` 只描述工具 API。
- `action_options` 描述当前可执行动作。
- `control_constraints` 描述硬约束。
- `agent_context` 是派生输入，不是事实源。

### 1.3 主循环存在重复执行路径

当前 open-agent branch 和 selector branch 都各自执行：

- 构造 trace。
- 执行 tool。
- 写 observation。
- 更新 budgets。
- finalize runtime。
- 生成 observation_delta。
- 追加 tool_history。
- 计算 stop decision。

这会导致两条路径行为漂移，也增加维护成本。

目标状态：

- 工具执行与写回只有一条共享函数。
- selector 只作为 fallback/baseline，不再继续扩展它的 prompt 能力。

### 1.4 `_finalize_runtime_state` 仍是大黑盒

`_finalize_runtime_state` 同时做分析派生、gap 派生、delivery 派生和 state 写回。短期不适合一刀切拆掉，但必须限制它对 prompt context 的直接暴露。

目标状态：

- 第一阶段不拆函数体，只通过 `AgentContext` adapter 隔离输出。
- 后续再逐步拆成 `derive_analysis_state`、`derive_gap_state`、`derive_delivery_state`、`commit_runtime_state`。

## 2. Source Of Truth

重构前必须先固定字段所有权。否则 `AgentContext` 只是新名字，旧重复字段还会长回来。

| 层 | 责任 | 是否可持久化 | 是否可给模型 | 写入者 | 禁止事项 |
|---|---|---:|---:|---|---|
| `seed_event` | 原始告警事实 | 是 | 是 | `normalize_alert` | 不写入调查派生结论 |
| `TraceStore` / fixture store | 原始日志、资产上下文 | 是 | 否，必须经 observation shaping | store adapter | 不直接塞入 prompt |
| `incident_state` | 事件事实、observation、known_events、entities、evidence_ledger、gap_ledger | 是 | 间接给模型 | tool executor / finalize commit | 不保存模型临时建议 |
| `session_state` | loop 控制、budget、history、preflight/reviewer feedback | 是 | 间接给模型 | loop / preflight / reviewer | 不保存事件事实主副本 |
| `finalized` | 每轮派生快照 | 否，除非 commit 到 `incident_state` | 间接给模型 | `_finalize_runtime_state` | 不作为长期 source of truth |
| `evidence_store` | 从 `incident_state` 派生的报告/分析证据视图 | 是，作为派生缓存 | 间接给模型 | `_refresh_runtime_evidence_store` | 不反向覆盖 raw observation |
| `delivery_decision/readiness` | 交付门槛与停止判断输入 | 是，作为派生判断 | 只给摘要 | delivery reviewer pipeline | 不直接替代 investigator 动作 |
| `AgentContext` | 模型输入视图 | 否 | 是 | `_build_agent_context` | 不写回业务状态 |
| `tool_catalog` | 静态工具 API | 否 | 是 | static registry | 不包含当前推荐、历史、冷却 |
| `action_options` | 当前可执行动作与安全参数 hint | 否 | 是 | action option builder | 不等同于最终动作 |
| `control_constraints` | budget、冷却、重复调用、preflight 限制 | 否 | 是 | control builder / preflight | 不做语义规划 |

单写者原则：

- 事件事实只由 tool executor 和 finalize commit 写入 `incident_state`。
- loop 控制只由 while loop、preflight、post-action reviewer 写入 `session_state`。
- 模型只能输出 proposal 或 feedback，不能直接改任何 state。
- `incident_state.gap_ledger` 是 gap 状态权威源；`acceptance_state.material_gaps`、`delivery_decision.blocking_gaps`、`control_summary.next_focus` 都只能作为 view 或派生判断输入，不允许反向覆盖 `gap_ledger`。
- `delivery_decision/readiness` 可以影响 stop gate，但不能作为 reviewer 或 preflight 替换 action 的依据。

## 3. 目标控制协议

目标 while loop：

```text
while budget remains:
  1. finalized = finalize current state
  2. agent_context = build_agent_context(finalized, incident_state, session_state)
  3. proposal = investigator(agent_context)
  4. preflight = preflight_investigator_action(proposal, agent_context)
  5. if preflight blocks:
       record preflight feedback
       decide retry / continue / stop by block state machine
       continue
  6. step_result = run_approved_tool_step(preflight.normalized_action)
  7. reviewer_feedback = review_executed_step(step_result, finalized_after)
  8. write reviewer_feedback into session_state for next turn
  9. stop = stop_decision(finalized_after, preflight/reviewer counters)
 10. if stop: break
```

权限边界：

| 组件 | 可以做 | 不可以做 |
|---|---|---|
| investigator | 提出一个 tool action 或 finish | 写 state、绕过 preflight、要求 reviewer 替它执行动作 |
| preflight | 校验 schema、tool、params、budget、cooldown、repeat、gap id | 选择更好工具、生成替代 action |
| tool executor | 执行已批准动作、写 observation、更新 budgets/history | 做语义规划 |
| post-action reviewer | 评价刚执行的 step、输出 feedback/constraints/stop recommendation | 输出 next_action、替换动作、单独决定 deliverable |
| stop gate | 统一决定 continue/finish | 依赖模型一句话直接停 |

## 4. AgentContext V1 最小字段集

第一版只允许这些字段进入 investigator prompt。新增字段必须先说明归属层和删除旧字段的位置。

```json
{
  "task_state": {
    "goal": "...",
    "step_index": 3,
    "budgets": {
      "remaining_steps": 5,
      "remaining_tool_calls": 8,
      "remaining_event_queries": 4,
      "remaining_intel_queries": 4
    }
  },
  "evidence_view": {
    "latest_evidence": [],
    "entities": {},
    "candidate_events": []
  },
  "gap_view": {
    "material_gaps": [],
    "primary_focus": {},
    "reportable_unresolved": []
  },
  "tool_catalog": [],
  "action_options": [],
  "control_constraints": {
    "active_tool_cooldowns": [],
    "forbidden_repeats": [],
    "recent_low_value_steps": 0,
    "preflight_block_count": 0
  },
  "reviewer_feedback": {
    "next_round_feedback": [],
    "constraints": [],
    "last_material_delta": ""
  }
}
```

字段上限：

- `latest_evidence` 最多 5 条，只放 observation_id、relation、summary。
- `candidate_events` 最多 6 条，只放 event_id、asset_id、classification、summary、indicators。
- `material_gaps` 只放 id、question、priority、status、actionable_now、delivery_blocking、actionable_tools、closure_criteria。
- `tool_catalog` 只放 tool_name、description、schema、capability_tags、result_shape。
- `action_options` 最多 8 条，只放 tool_name、safe_params_hint、target_gap_ids、expected_gain、input_fingerprint。
- `reviewer_feedback.next_round_feedback` 最多 3 条。
- `reviewer_feedback.constraints` 最多 3 条，只保留最近 2 轮仍有效 constraints。

`action_options` 边界：

- `action_options` 是“当前可安全构造参数的动作入口”，不是 workflow，也不是排序后的强推荐。
- investigator 可以参考 `action_options` 的 `safe_params_hint`，但仍需要用自己的 `reason` 说明为什么该动作能缩小当前不确定性。
- `action_options` 不应携带 `recommended_now`、`why_now`、`preferred_tool` 这类会把 investigator 压成 selector 的字段。
- 如果需要表达硬限制，只能放在 `control_constraints`；如果需要表达当前主焦点，只能放在 `gap_view.primary_focus`。

旧字段迁移表：

| 旧位置 | 新位置 | 处理方式 |
|---|---|---|
| `runtime.latest_evidence` | `evidence_view.latest_evidence` | 裁剪后保留 |
| `runtime.entities` | `evidence_view.entities` | 裁剪后保留 |
| `runtime.candidate_events` | `evidence_view.candidate_events` | 裁剪后保留 |
| `runtime.material_gaps` | `gap_view.material_gaps` | 单一保留 |
| `acceptance_state.material_gaps` | 不直接给模型 | 只作为 `gap_view` builder 输入 |
| `completion_advice.material_gaps` | 删除 | 避免第三份 gap |
| `control_summary.next_focus` | `gap_view.primary_focus` | 只保留主焦点 |
| `tool_catalog[*].description/schema/capability` | `tool_catalog` | 保留为静态 API |
| `tool_catalog[*].recommended_params` | `action_options[*].safe_params_hint` | 改名并迁移 |
| `tool_catalog[*].recommended_now/why_now` | 删除或放 `orchestration_hints` | 默认不进入 V1 |
| `tool_catalog[*].cooldown_*` | `control_constraints.active_tool_cooldowns` | 从工具卡移走 |
| `tool_catalog[*].recent_runs/repeat_risk` | `control_constraints.forbidden_repeats` | 从工具卡移走 |
| `tool_catalog[*].alignment` | `action_options[*].alignment` | V1 可保留精简版，后续再评估 |
| `guardrail_feedback` | `reviewer_feedback.next_round_feedback` | 统一反馈入口 |

## 5. Preflight 状态机

preflight 是程序硬检查，不调用 LLM，不生成替代工具。

检查项：

- JSON/action schema 是否合法。
- tool 是否在 `action_options` 或 `tool_catalog` 中。
- params 是否能通过 `_normalize_open_agent_action`。
- budget 是否允许。
- input_fingerprint 是否命中 forbidden repeat。
- tool 是否在 active cooldown 且缺少 override_reason。
- target_gap_ids 是否存在；若为空，是否允许作为 context/bootstrap 动作。

输出：

```json
{
  "allowed": false,
  "reason": "tool_in_cooldown_without_override",
  "normalized_action": null,
  "feedback_for_next_turn": "该工具同输入仍在冷却中；除非出现新状态变化，否则请选择能缩小其他 gap 的动作。",
  "counts_as_step": false,
  "counts_as_block": true
}
```

block 策略：

- `invalid_json`：不消耗 tool budget；消耗一次 non-tool step retry；写入 feedback。
- `unknown_tool`：不消耗 tool budget；写入 feedback；连续 2 次后 fallback 到 heuristic action 或 stop。
- `params_normalize_error`：不消耗 tool budget；写入具体缺失字段；连续 2 次后 stop 为 `invalid_agent_proposal_loop`。
- `cooldown_without_override`：不消耗 tool budget；写入 cooldown reason；同一 tool 连续 2 次后强制 forbidden repeat。
- `duplicate_deterministic_call`：不消耗 tool budget；写入 repeat reason；同一 fingerprint 不再允许本轮重试。
- `finish_schema_allowed`：preflight 只确认 finish 动作结构合法，不再读取 gap/readiness 做语义拦截；是否接受 finish 交给 reviewer/stop gate。
- `finish_rejected_by_reviewer`：不消耗 tool budget；消耗一次 non-tool step retry；把 reviewer 的自然语言原因写入下一轮 feedback；连续多次仍交给统一 stop gate 收口。
- `llm_unavailable`：如果存在合法 `action_options`，可走 heuristic fallback；如果没有合法 action_options，交给 stop gate 判断为 `no_actionable_path` 或 `delivery_ready`。
- `llm_parse_error`：不消耗 tool budget；消耗一次 non-tool retry；连续 2 次后走 heuristic fallback 或 stop，不能进入 reviewer replacement。

preflight 不做的事：

- 不判断哪个工具“更高价值”。
- 不把被 block 的动作替换为别的工具。
- 不修改 `incident_state`。

## 6. Post-action Reviewer 协议

reviewer 只在工具执行后运行。它看的是已经发生的 step，而不是即将执行的 proposal。

输入：

```json
{
  "executed_action": {},
  "observation": {},
  "observation_delta": {},
  "gap_transition": {},
  "before_focus": {},
  "after_gap_view": {},
  "control_constraints": {}
}
```

输出：

```json
{
  "review_result": "continue",
  "material_delta": "medium",
  "closed_gap_ids": [],
  "remaining_focus": {
    "gap_id": "candidate_grounding",
    "reason": "候选事件仍未获得独立情报支撑。"
  },
  "next_round_feedback": [
    "不要把扩线得到的 candidate 直接写成 confirmed evidence。"
  ],
  "constraints": [
    {
      "type": "avoid_tool",
      "tool_name": "search_related_events",
      "scope": "same_input",
      "reason": "同输入扩线没有带来 material delta。"
    }
  ],
  "stop_recommendation": {
    "should_stop": false,
    "reason": "仍有可行动 candidate grounding gap。"
  }
}
```

权限限制：

- reviewer 不输出 `next_action`。
- reviewer 不输出可执行 params。
- reviewer 不直接 block 下一轮，只能给 `constraints`，由下一轮 preflight 消费。
- reviewer 的 `stop_recommendation` 只是 stop gate 的输入，不是最终停止命令。
- reviewer 不直接改 `incident_state`，只写入 `session_state.reviewer_state.feedback_queue`。
- `remaining_focus` 只能引用已有 `gap_ledger` 中的 gap id；如果没有可引用 gap，只能写为空并说明原因，不能创造新 focus。
- reviewer feedback 不允许建议具体工具名作为下一步动作；如果必须限制工具，只能用 `constraints` 表达“避免/需要 override”，不能表达“下一步应该调用 X”。

## 7. 实施阶段

### Phase 0: 安全基线与观测补齐

目标：

- 不改变 agent 行为，先保证现状可追踪、可回归。

动作：

- 先跑当前五个 case，保存 baseline 指标：
  - stop_reason
  - tool_history 长度
  - reviewer replacement count
  - invalid proposal count
  - duplicate deterministic call count
  - prompt payload bytes
  - preflight/reviewer block count
- 修复 open-agent branch 中 `finalized_before` 先引用后赋值风险。
- 在 trace 中新增并行字段：
  - `agent_context_v1_preview`
  - `investigator_raw_proposal`
  - `normalized_proposal`
  - `preflight_result_preview`
  - `executed_action`
  - `observation_delta`
  - `gap_transition`
  - `reviewer_feedback_preview`
- 记录 prompt payload size，包括 runtime bytes、tool_catalog bytes、agent_context_v1 bytes。

验收：

- 五个 case 能跑完。
- baseline 指标写入当前评估输出或 trace summary，后续 phase 的“不高于重构前”都以它为准。
- `git diff --check` 通过。
- `python -m py_compile demo_agent/incidents/agent.py` 通过。
- trace 能回答：模型看到了什么、提了什么、实际执行什么、执行后状态怎么变。

### Phase 1: 抽出统一 tool step executor

目标：

- 消除 open-agent 和 selector branch 的执行写回重复。

动作：

- 新增 `_run_approved_tool_step(...)`。
- open-agent 与 selector fallback 共用这条执行路径。
- 该函数只负责执行、写 observation、更新 budget/history、计算 delta、返回 step_trace patch。

验收：

- 行为不应有意改变。
- 两条分支不再复制 `_execute_action` 到 `_stop_decision` 的整段逻辑。
- 五个 case 的 stop_reason、tool_history 数量不应出现非预期大幅变化。

### Phase 2: 引入 preflight gate，但暂不移除旧 reviewer

目标：

- 先把执行前硬约束从 reviewer 里抽出来。

动作：

- 新增 `_preflight_investigator_action(...)`。
- 当前 reviewer 仍保留，但 preflight 先运行。
- 如果 preflight block，本轮不进入 reviewer replacement，不执行 tool，只写 feedback 并按 block 状态机处理。
- Phase 2 开始就禁用 reviewer replacement 执行路径：即使旧 reviewer 输出 `next_action`，也只能写入 trace 对照，不能被 `_reviewer_replacement_tool` 执行。
- 先保留旧 reviewer 的 allow/block 输出作为 trace 对照，不再让它覆盖 preflight 硬结果，也不允许它替换 investigator action。

验收：

- preflight 不调用 LLM。
- preflight 不输出替代工具。
- preflight 不判断 finish 是否“语义上过早”；它只允许结构合法的 finish 进入 reviewer feedback 流。
- preflight block 后不会执行 reviewer 替代动作。
- reviewer replacement count 必须从 Phase 2 起为 0。
- trace 中能看到 block reason 和下一轮 feedback。

### Phase 3: 引入 AgentContext adapter，先并行输出

目标：

- 先生成新上下文，人工检查，不立刻切 prompt。

动作：

- 新增 `_build_agent_context(...)`。
- 按第 4 节最小字段集生成 `agent_context_v1`。
- 旧 runtime/catalog 仍用于 prompt。
- trace 同时记录旧输入和新输入大小。

验收：

- `agent_context_v1` 不包含重复 gap 三份拷贝。
- `tool_catalog` 中不包含 cooldown/history/recommended_now。
- `action_options` 中包含当前安全参数 hint。
- `control_constraints` 中包含 active cooldown 和 forbidden repeat。

### Phase 4: 拆分 catalog、action_options、control_constraints，并切 investigator prompt

目标：

- 让 investigator 看到清晰的 API、当前动作、硬约束，而不是混合 runtime。

动作：

- 拆出 `_static_tool_catalog(...)`。
- 拆出 `_available_action_options(...)`。
- 拆出 `_control_constraints(...)`。
- `_choose_open_agent_action` 改为输入 `agent_context_v1`。
- investigator prompt 更新为只理解 `agent_context`，不再同时吃 runtime + bloated tool_catalog。

验收：

- prompt payload 明显减少或至少结构更稳定。
- investigator 仍能选出合法工具。
- invalid proposal 数不高于重构前。
- 五个 case 能跑完。

### Phase 5: reviewer 改为 post-action feedback

目标：

- 让 reviewer 从动作替换者变成执行后审查者。

动作：

- 新增 `_review_executed_step(...)`。
- 废弃或旁路：
  - `_reviewer_replacement_tool`
  - reviewer pre-execution `next_action`
  - fallback reviewer 生成替代动作逻辑
- reviewer feedback 写入 `session_state["reviewer_state"]["feedback_queue"]`。
- 下一轮 `_build_agent_context` 读取 feedback_queue。

验收：

- reviewer action replacement 次数必须为 0。
- reviewer 输出不包含 executable params。
- reviewer constraints 只能影响下一轮 preflight 或 investigator prompt。
- post-action feedback 能在下一轮 prompt 中看到。

### Phase 6: stop decision 收口

目标：

- 结束条件集中在一个地方，不再散在 reviewer、completion_advice、acceptance_state、主循环分支里。

动作：

- 梳理 `_stop_decision` 输入，只依赖：
  - budgets
  - acceptance_state
  - delivery_decision/readiness
  - recent low-value
  - preflight block counters
  - post-action reviewer stop_recommendation
- 固定 stop_reason 枚举。
- 删除 reviewer 直接 deliverable 触发执行结束的路径。

验收：

- stop reason 可枚举、可解释。
- finish 被 reviewer 拒绝后不会空转。
- reviewer 不能单独决定 deliverable。

### Phase 7: 清理旧路径与回归

目标：

- 删除或隔离旧 reviewer replacement 逻辑，保留 selector fallback。

动作：

- 移除主线对 `_reviewer_replacement_tool` 的调用。
- 将旧 `_review_open_agent_proposal` 标记为 deprecated 或仅测试保留。
- 更新 docs/lifecycle，说明新 while loop。
- 跑五个 case，检查 outputs 和 trace。

验收：

- open-agent 主线不再依赖 pre-execution reviewer。
- selector fallback 仍能 smoke 跑通。
- docs 与代码路径一致。

## 8. 量化验收指标

每轮重构后记录这些指标：

| 指标 | 目标 |
|---|---:|
| 五个 case 正常结束 | 5/5 |
| `py_compile` | 通过 |
| `git diff --check` | 通过 |
| reviewer replacement count | 0 |
| invalid proposal count | 不高于 Phase 0 baseline |
| preflight block 后执行工具次数 | 0 |
| duplicate deterministic call | 0 或有明确 override |
| candidate 误升级为 confirmed | 0 |
| 连续低价值工具重复 | 不高于 Phase 0 baseline |
| prompt payload 中重复 gap 拷贝 | 1 份 |
| `tool_catalog` 中 cooldown/history 字段 | 0 |
| stop_reason 是否枚举内 | 100% |

人工阅读重点：

- investigator 是否能解释为什么选该工具。
- preflight 是否只做硬检查。
- reviewer feedback 是否具体但不过度规划。
- stop 是否比之前更清楚，不是被 reviewer 一句话带走。

## 9. 不做事项

- 不在本轮重构报告撰写、polished report、brief/fact card。
- 不新增硬编码语义 validator。
- 不引入新的多 agent 角色。
- 不删除 legacy selector，只保留为 fallback/baseline。
- 不为了当前五个 case 写 case-specific 规则。
- 不把 reviewer feedback 变成新的大 prompt。
- 不让 `AgentContext` 成为新的 durable state。

## 10. 主要风险与缓解

### 风险 1: 去掉 reviewer 替换动作后，调查可能多一轮

缓解：

- preflight block feedback 进入下一轮 investigator prompt。
- block 状态机限制重试次数。
- 只接受多一轮，不接受不可解释的自动替换。

### 风险 2: AgentContext V1 信息不足

缓解：

- Phase 3 先并行输出，不立刻切 prompt。
- 人工读 1-2 个 case 的 context。
- 如果缺字段，必须说明字段归属和旧字段迁移位置。

### 风险 3: reviewer feedback 膨胀

缓解：

- feedback 最多 3 条。
- constraints 最多 3 条。
- 只保留最近 2 轮有效 feedback。
- reviewer 不输出计划，不输出 next_action。

### 风险 4: `_finalize_runtime_state` 继续制造重复字段

缓解：

- 短期不拆函数体，但禁止直接把 finalized 全量塞给模型。
- 只允许 `_build_agent_context` 暴露最小字段。
- 后续单独拆 finalize。

## 11. 推荐执行顺序

建议下一步按这个顺序落：

1. Phase 0：修 `finalized_before` 风险，并补 trace/payload size 观测。
2. Phase 1：抽 `_run_approved_tool_step(...)`，统一执行写回路径。
3. Phase 2：落 `_preflight_investigator_action(...)`，让硬约束先于 reviewer，并禁用 reviewer replacement 执行路径。
4. Phase 3：并行生成 `agent_context_v1`，先不切 prompt。
5. Phase 4：拆 catalog/action_options/control_constraints，并切 investigator prompt。
6. Phase 5：reviewer 改成 post-action feedback，移除替换动作权力。
7. Phase 6/7：收口 stop decision，清理旧路径，跑五个 case。

最小安全落地点：

- 先完成 Phase 0 到 Phase 2，就能解决最危险的执行前硬约束和 reviewer 越权执行问题。
- Phase 3 到 Phase 5 是 prompt/context 与双 agent 协议的真正重构。
- Phase 6 到 Phase 7 是收尾清理和验收。

## 12. 当前执行记录

已完成：

- Phase 0：补充 `run_metrics`、prompt payload 统计、trace 中 investigator raw/normalized proposal 留痕，并修复 open-agent 分支 `finalized_before` 先引用风险。
- Phase 1：新增 `_run_approved_tool_step(...)`，open-agent 和 selector fallback 已共用工具执行、observation 写回、budget 更新、evidence ledger、delta、tool history 和 stop followup 路径。
- Phase 2：新增 `_preflight_investigator_action(...)` 与 preflight history/block 计数；open-agent 主线已禁用 reviewer replacement 执行路径。
- Phase 3：新增 `_build_agent_context_v1(...)`，当前只并行写入 `agent_context_v1_preview` 和 `agent_context_v1_payload`，尚未切换 investigator prompt。
- Phase 4：拆出 `_static_tool_catalog_view(...)`、`_action_options_view(...)`、`_control_constraints_view(...)` 和 `_reviewer_feedback_view(...)`；investigator prompt 已切换为只接收 `seed + agent_context`，不再直接接收旧 `runtime + full tool_catalog`。
- 补充修正：`finish` 不再被 preflight 依据 actionable gap/check 硬编码拦截；结构合法的 finish 会进入 reviewer 审查。reviewer 若不接受 finish，只写自然语言 feedback 给下一轮 investigator，不执行 reviewer 的替代 action。
- Phase 5 局部落地：新增 post-action reviewer prompt 与 `_review_executed_step(...)`；tool action 现在先执行，再由 reviewer 基于 observation_delta / gap_transition 输出 `review_result`、`material_delta`、`next_round_feedback`、`constraints` 和 `stop_recommendation`。主循环不再在 tool 执行前调用 proposal reviewer；`next_action` 仅保留在 finish 审查兼容路径中。
- Phase 6：`_stop_decision(...)` 已收口为统一停止入口，并固定 `STOP_REASON_*` 枚举；open-agent 工具路径现在会先执行 tool、写入 post-action reviewer feedback，再统一调用 stop gate。post-action reviewer 的 `stop_recommendation` 只作为信号，必须结合 `acceptance_state` / `delivery_decision` / budget / low-value counters 才能停。
- Phase 7 局部落地：finish 请求已从旧 proposal reviewer 中拆出，新增轻量 `FINISH_REVIEWER_SYSTEM_PROMPT` 与 `_review_finish_request(...)`；finish reviewer 只能接受或拒绝 finish，不能输出可执行 tool action。旧 proposal reviewer 已重命名为 `_legacy_review_open_agent_proposal(...)`，主线不再调用；`_reviewer_replacement_tool(...)` 已删除，避免 reviewer replacement 被误接回主线。
- LLM 观测补齐：新增 `demo_agent/services/api/llm_observability.py`，所有 investigator / selector / finish reviewer / post-action reviewer / report polish 调用都会通过 `invoke_llm_with_trace(...)` 写入 `llm_calls.jsonl`，记录 start/end/error、role、step_index、prompt bytes、耗时和响应大小。新增 `tools/llm_ping.py` 用于最小 LLM 连通性测试。

已验证：

- `python3 -m py_compile demo_agent/incidents/agent.py demo_agent/incidents/render.py demo_agent/entrypoints/langchain_agent.py demo_agent/services/api/llm_observability.py tools/llm_ping.py tools/test_llm_agent_protocol.py` 通过。
- `conda run -n trail-agent python -m py_compile demo_agent/incidents/agent.py demo_agent/incidents/render.py demo_agent/entrypoints/langchain_agent.py demo_agent/services/api/llm_observability.py tools/llm_ping.py tools/test_llm_agent_protocol.py` 通过。
- `git diff --check` 通过。
- 本地 fake LLM open-agent 小样本通过：preflight block 不执行工具，reviewer replacement count 为 0，trace 已包含 `agent_context_v1_preview`。
- 本地 fake LLM post-action 小样本通过：tool action 执行后触发 `post_action_reviewer`，reviewer feedback 会写入下一轮 `guardrail_feedback`；finish request 被 reviewer 拒绝后仍能继续进入下一轮 investigator。
- 本地 fake LLM agent-context 小样本通过：investigator 输入中只包含 `agent_context`，且上下文包含 `tool_catalog / action_options / control_constraints / reviewer_feedback` 分层。
- heuristic/selector 小样本通过，说明统一 executor 没破坏 legacy fallback 路径。
- `conda run -n trail-agent python tools/run_incident_smoke.py` 通过，当前五个 fixture 的 heuristic smoke 全部通过。
- 新增 `tools/test_llm_agent_protocol.py`，并通过 `conda run -n trail-agent python tools/test_llm_agent_protocol.py`。该测试用 fake LLM 覆盖新协议：investigator 只接收 `agent_context`、tool 后触发 post-action reviewer、finish 走 finish reviewer、reviewer replacement count 为 0、stop_reason 在枚举内。
- 旧协议测试 `tools/test_llm_agent_open_loop.py` 已删除。该脚本依赖不存在的 `single_host_c2_beacon` fixture，并且断言旧的 reviewer replacement 行为，继续保留会误导后续验收。
- CLI 默认 fixture 已从不存在的 `single_host_c2_beacon` 切到当前有效的 `web_initial_access_without_execution`。
- `conda run -n trail-agent python tools/llm_ping.py --trace-path outputs/plan12_live_probe_escalated/llm_ping.jsonl` 在提权网络下通过：`model=chat`、`base_url=https://api.deepshields.com/v1`、总耗时约 510ms。
- 提权重跑单 case `web_initial_access_without_execution` 已完整通过，输出位于 `outputs/plan12_live_probe_escalated/web_initial_access_without_execution/`，生成了 `incident.json`、`run_metrics.json`、`llm_calls.jsonl` 和 `report_polished.md`。
- 本次 live 单 case 指标：`stop_reason=delivery_ready`、`stop_reason_in_enum=true`、`tool_history_length=5`、`reviewer_replacement_count=0`、`invalid_proposal_count=0`、`duplicate_deterministic_call_count=0`、`preflight_block_count=0`。
- `llm_calls.jsonl` 显示本次共 11 次 LLM 调用且全部返回：5 次 investigator 约 4-6s，5 次 post-action reviewer 约 12-19s，1 次 report polish 约 39s。慢点主要在 post-action reviewer 大 prompt（约 56-71KB）和 report polish，而不是 API 不通或沙箱问题。
- 五 case live 回归已完成，输出位于 `outputs/plan12_live_regression_v1/`。五个 case 均产出 `incident.json`、`run_metrics.json`、`llm_calls.jsonl` 和 `report_polished.md`，且 `llm_calls.jsonl` 均为 start/end 成对出现，没有 error 事件。
- 五 case 回归的协议指标均干净：`stop_reason_in_enum=true`、`reviewer_replacement_count=0`、`invalid_proposal_count=0`、`duplicate_deterministic_call_count=0`、`preflight_block_count=0`。
- 五 case stop 结果：`web_initial_access_to_beacon` 与 `web_initial_access_without_execution` 为 `delivery_ready`；`multi_host_confirmed_spread_plus`、`shared_infra_multi_asset_needs_review`、`suspected_exfil_after_execution` 为 `runtime_budget_exhausted`。其中后两者已 `ready_for_delivery=true`，说明流程可交付但 stop reason 仍偏粗，需要后续把 delivery-ready 优先级和 runtime budget 归因再收紧。
- 五 case LLM payload 观测：最大 prompt payload 约 78KB，主要来自 `post_action_reviewer`；最慢调用通常是 `report_polish_initial`，约 41-50s，其次是 `post_action_reviewer`，约 18-24s。
- 清理旧测试后，`conda run -n trail-agent python tools/test_llm_agent_protocol.py`、`conda run -n trail-agent python tools/run_incident_smoke.py`、`git diff --check` 均通过。
- 已继续修复三项控制层债务：
  - `_stop_decision(...)` 已调整为 delivery-ready 优先归因；若同时触发 runtime/step/tool budget，会把预算原因写入 `secondary_stop_reasons`，不再抢占主 `stop_reason`。
  - `investigation_trace` 已补 `execution_source`，`reviewer_replacement_count` 只统计显式 `reviewer_replacement`，避免 preflight block / finish reviewer / fallback 污染指标。
  - post-action reviewer 的 constraints 已收紧为只能约束本轮工具或最近低增量工具，避免 reviewer 通过 constraints 重新变成隐式 tool router。
- `tools/test_llm_agent_protocol.py` 已新增两条回归 smoke：preflight block 不计入 reviewer replacement；delivery ready 与 runtime budget 同时成立时，主 `stop_reason=delivery_ready` 且 `secondary_stop_reasons` 包含 `runtime_budget_exhausted`。
- 修复后三项本地验收通过：`python3 -m py_compile ...`、`conda run -n trail-agent python -m py_compile ...`、`conda run -n trail-agent python tools/test_llm_agent_protocol.py`、`conda run -n trail-agent python tools/run_incident_smoke.py`、`git diff --check`。
- 修复后尝试重跑 `outputs/plan12_live_regression_v2/` 五 case live：前三个 case 已落盘并产出 polished report，其中 `suspected_exfil_after_execution` 验证了新 stop 归因：`stop_reason=delivery_ready` 且 `secondary_stop_reasons=["runtime_budget_exhausted"]`。第四个 case 卡在 `investigator` 第 3 步 LLM 调用 start 后长期没有 end/error，已手动停止。该现象确认了单次 LLM timeout/fallback 仍是下一个必须处理的运行时可靠性问题。
- 补充重跑失败 case：`web_initial_access_to_beacon` 已在 `outputs/plan12_failed_case_rerun_v1/web_initial_access_to_beacon/` 单独重跑通过，完整产出 `incident.json`、`run_metrics.json`、`llm_calls.jsonl`、`report_polished.md`；12 次 LLM 调用 start/end 全部成对、0 error、0 dangling。该结果说明上一次更像 provider/client 偶发挂起，短期不应阻塞 agent 能力优化主线。

Live LLM 验收现状：

- 之前批量 live eval “长时间无输出”的主要原因已初步澄清：不是 LLM API 不通，而是没有中间观测，且 post-action reviewer / report polish 单次调用耗时较长。另有一次卡在单次 investigator LLM 调用 start 后无 end/error；这个缺口应通过统一 LLM 调用边界处理，不能在各调用点继续散落 timeout/watchdog。

下一步建议：

- 不要再额外堆一层分散的 timeout/watchdog。当前已经有三类时间机制：`make_llm(...)` 的 provider/client timeout 与 retry、agent loop 的 `max_runtime_s` 轮间预算、report polish 的局部 retry。真正缺口是单次 LLM 调用 start 后如果 provider/client 没有返回 error，loop 的 runtime budget 无法打断 in-flight invoke。
- 后续若处理该问题，应把策略收口在唯一 LLM 调用边界 `invoke_llm_with_trace(...)` 或其直接上游配置里：保留 `make_llm(...)` 作为传输层 timeout；`invoke_llm_with_trace(...)` 只负责统一记录 attempt / elapsed / surfaced error，并在必要时接受明确的 per-role 调用策略；不要在 investigator、reviewer、report writer 各自再包一套 watchdog。
- report polish 已有 `_invoke_report_writer_with_retry(...)`，如果统一 LLM 边界新增 retry，必须先避免和 report polish 形成双重 retry；更稳妥的第一步是校准 `ChatOpenAI` 的 timeout 参数与观测字段，而不是直接加线程/进程级硬杀。
- 控制 CLI stdout 体积：当前命令会把完整 result JSON 打到终端，回归时虽然不影响落盘，但会造成大量终端噪声。
