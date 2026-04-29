# Incident-Agent 生命周期 / 数据流

这份文档专门说明当前 `incident-agent` 的运行生命周期，以及调查数据如何一步步流到最终报告。

## 1. 总体数据流

```text
用户输入 / fixture case
  │
  ▼
┌──────────────────────────────────────────────────────────────┐
│ CLI 入口 (`python -m demo_agent`)                           │
│ ├── `demo_agent/__main__.py`                                │
│ └── `entrypoints/langchain_agent.py::main()`                │
└──────────────────────┬───────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────┐
│ 输入解析与运行时初始化                                       │
│ ├── `_resolve_incident_paths()`                             │
│ │    - 解析 `--alert` / `--fixture-dir`                     │
│ │    - 定位 `seed_alert.json` 与 fixture 目录               │
│ ├── `load_json()`                                           │
│ └── `_load_optional_llm()`                                  │
│      - 根据 `decision_mode` 与环境变量决定是否加载 LLM      │
└──────────────────────┬───────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────┐
│ 单 case 运行封装                                             │
│ `entrypoints/langchain_agent.py::_run_one_incident_agent()` │
│ ├── `normalize_alert()` -> `event.json`                     │
│ └── `run_incident_agent_case()`                             │
└──────────────────────┬───────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────┐
│ 调查主循环 (`incidents/agent.py::run_incident_agent_case`)  │
│ ├── 初始化                                                   │
│ │    - `seed_event`                                          │
│ │    - `TraceStore` / fixture adapter                        │
│ │    - `session_state`                                       │
│ │    - `incident_state`                                      │
│ │    - `investigation_trace[]`                               │
│ ├── while loop                                               │
│ │    1. `_finalize_runtime_state()`                          │
│ │    2. `_action_candidates()` / `_available_tool_catalog()` │
│ │    3. `_stop_decision()`                                   │
│ │    4. 选择动作                                              │
│ │       - 默认：`llm_agent` + reviewer gate                  │
│ │       - fallback / legacy：`heuristic` / `llm_selector` / `hybrid` │
│ │    5. `_execute_action()`                                  │
│ │    6. observation -> `incident_state` / `evidence_ledger`  │
│ │    7. 记录 `investigation_trace`                           │
│ │    8. 回到步骤 1，直到 stop                                │
│ └── 输出最终 `incident` 视图                                 │
└──────────────────────┬───────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────┐
│ 证据整理与交付判定                                           │
│ ├── `build_runtime_evidence_store()` -> `evidence_store`     │
│ ├── `build_reviewer_input()` -> `reviewer_input`             │
│ └── `build_delivery_decision()` -> `delivery_decision`       │
└──────────────────────┬───────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────┐
│ 报告大纲与报告生成                                           │
│ ├── `build_incident_report_outline()`                        │
│ │    - `evidence_store` + `reviewer_input` +                 │
│ │      `delivery_decision` -> `report_outline`               │
│ ├── deterministic report                                     │
│ │    - `render_incident_report()` -> `report.md`             │
│ │    - `render_incident_report_appendix()`                   │
│ │      -> `report_appendix.md`                               │
│ └── optional polished report                                 │
│      - `build_report_fact_cards()`                           │
│      - `build_report_polish_input_v2()`                      │
│      - `build_report_polish_brief()`                         │
│      - `render_incident_report_with_llm()`                   │
│        -> `report_polished.md`                               │
└──────────────────────┬───────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────┐
│ 结果落盘                                                     │
│ ├── `incident.json`                                          │
│ ├── `investigation_trace.json`                               │
│ ├── `evidence_store.json`                                    │
│ ├── `reviewer_input.json`                                    │
│ ├── `delivery_decision.json`                                 │
│ ├── `report_outline.json`                                    │
│ ├── `report.md` / `report_appendix.md`                       │
│ ├── `report_polish_input.json` / `report_polish_brief.md`    │
│ ├── `report_polished.md` 或 `report_polish_error.txt`        │
│ └── `topology.json` / `topology.html`                        │
└──────────────────────────────────────────────────────────────┘
```

## 2. 主循环里的关键状态

- `seed_event`
  - 由 `seed_alert.json` 规范化得到，是整条调查链的起点。
- `session_state`
  - 控制“怎么调查”的运行时状态。
  - 包含 `decision_mode`、预算、step 计数、tool history、selector / agent / reviewer history 等。
- `incident_state`
  - 控制“已经调查到什么”的运行时状态。
  - 包含 observations、timeline、scope、evidence ledger、gap ledger、counterevidence 等。
- `investigation_trace`
  - 逐 step 的外层审计轨迹。
  - 每一步会记录：控制摘要、候选动作、选中的动作、observation id、状态更新、stop/continue reason。
- `evidence_store`
  - 从运行期 `incident_state` 收敛出的结构化证据层。
  - 后面的 reviewer、delivery decision、report inputs、appendix 都主要吃这层。
- `reviewer_input`
  - 面向“交付审查”的中间视图。
  - 它总结当前运行质量、进展状态、证据充分性和剩余缺口。
- `delivery_decision`
  - 交付层的最终判定。
  - 会给出 `delivery_status`、`confirmed_scope`、`candidate_scope`、`blocking_gaps`、`readiness` 等。
- `report_outline`
  - 报告层统一输入。
  - 它把 `evidence_store`、`reviewer_input`、`delivery_decision` 重新组织成 `ops_report_contract` 和 `appendix_contract`。

## 3. 不同 decision mode 在哪里分叉

默认主线是 `llm_agent`。如果没有可用 LLM，会自动降级到 `heuristic`，用于离线 fallback 和 baseline 对照。

- `heuristic`
  - 代码直接根据候选动作优先级推进，主要作为 fallback / baseline。
- `llm_selector`
  - LLM 只能在代码给出的 `candidate_actions` 里选一个。
- `hybrid`
  - 仍然保留候选动作集合，但优先让 LLM 参与选择。
- `llm_agent`
  - 当前主开发路径。LLM 直接面向开放工具目录提出动作，随后再经过 reviewer gate 决定是否放行、替换或 finish。

## 4. deterministic report 和 polished report 的关系

- `report.md`
  - 完全由代码从 `report_outline` 渲染出来。
  - 更稳定、可复现，适合当作结构化底稿。
- `report_polished.md`
  - 先由代码生成 `report_polish_input.json` 和 `report_polish_brief.md`。
  - 然后把这份 brief 喂给 LLM，让它只写“主报告正文”。
  - 技术附录仍由 deterministic appendix 自动追加。
- 如果 LLM 未启用或调用失败：
  - 仍然会生成 `report.md`
  - 可能只留下 `report_polish_input.json`、`report_polish_brief.md` 和 `report_polish_error.txt`

## 5. 建议怎么顺着数据流看代码

1. 从 `demo_agent/__main__.py` 和 `entrypoints/langchain_agent.py` 看 CLI 如何进入 incident-agent。
2. 从 `incidents/agent.py::run_incident_agent_case()` 看调查 while loop 如何驱动工具调用和 stop。
3. 从 `incidents/reviewer.py` 看 `reviewer_input` 与 `delivery_decision` 如何形成交付判断。
4. 从 `incidents/render.py` 看 `report_outline`、deterministic report、polished report 的生成链路。
5. 从 `incidents/report_inputs.py` 和 `incidents/report_render.py` 看 deterministic 报告正文与附录合同如何被渲染。
