# Incident-Agent 快速开始

当前仓库主线只保留 `incident-agent`。

## 1. 配置 `.env`

配置文件位置：

```text
demo_agent/.env
```

可以参考：

```text
demo_agent/.env.example
```

当前常用配置项有：

- `LLM_API_KEY`
- `LLM_BASE_URL`
- `LLM_MODEL`
- 调查层 `investigator` 默认使用供应商的 `tool` 模型；如需回到通用模型，可设置 `INCIDENT_AGENT_INVESTIGATOR_MODEL=chat`。
- `INCIDENT_AGENT_TOOL_MODEL`：可选，覆盖调查/材料路由类 LLM 调用使用的模型，例如 `tool`。
- `INCIDENT_AGENT_REASONER_MODEL`：可选，覆盖 writer/reviewer 类 LLM 调用使用的模型，例如 `reasoner`。
- `INCIDENT_AGENT_INVESTIGATOR_MODEL`、`INCIDENT_AGENT_REPORT_MATERIAL_MODEL`、`INCIDENT_AGENT_WRITER_MODEL`、`INCIDENT_AGENT_REVIEWER_MODEL`：可选，按具体角色覆盖模型；优先级高于上面的分组模型。
- `INCIDENT_AGENT_ENABLE_LLM`
- `INCIDENT_AGENT_DECISION_MODE`
- `INCIDENT_AGENT_LIVE_INTEL`
- `ABUSECH_AUTH_KEY`

## 2. 运行 incident-agent

在仓库根目录运行：

```bash
python -m demo_agent \
  --alert fixtures/incidents/web_initial_access_to_beacon \
  --out outputs/incident_tests/web_initial_access_to_beacon/agent \
  --mode incident-agent
```

说明：

- `--alert`：可以直接指向 fixture case 目录，也可以指向 `seed_alert.json`
- `--out`：输出目录
- `--decision-mode`：调查模式，默认 `llm_agent`；可选 `heuristic`、`llm_selector`、`llm_agent`、`hybrid`
- `--mode`：当前只保留 `incident-agent`

模式区别：

- `heuristic`：纯代码按既定优先级推进
- `llm_selector`：LLM 只能在代码给出的候选动作中选一个
- `llm_agent`：LLM 在开放工具目录里自行决定下一步工具和参数，并显式决定何时 `finish`
- `hybrid`：保留候选动作模式，但优先让 LLM 选择

如果没有配置可用 LLM，请求 `llm_agent` 时会自动降级到 `heuristic`，以便离线 smoke test 仍能跑通。

如果要快速验证 `llm_agent` 的开放式循环，可运行：

```bash
conda run -n trail-agent python tools/test_llm_agent_protocol.py
```

如果要先确认外部 LLM API 是否可连通，可运行：

```bash
conda run -n trail-agent python tools/llm_ping.py --trace-path outputs/llm_ping.jsonl
```

## 3. 生命周期 / 数据流

详细生命周期说明已单独整理到：

- [lifecycle.md](/home/estar0x/project/maltrail_test/Trace-Agent/demo_agent/docs/lifecycle.md)

## 4. 输出内容

每条 case 通常会生成：

- `input_alert.json`
- `event.json`
- `incident.json`
- `investigation_trace.json`
- `report_outline.json`
- `report.md`
- `report_appendix.md`
- `report_polish_input.json`
- `report_polish_brief.md`
- `report_polished.md` 或 `report_polish_error.txt`
- `topology.json`
- `topology.html`

## 5. 常见查看顺序

建议先看：

1. `report.md`
2. `report_polished.md`（如果存在）
3. `report_outline.json`
4. `delivery_decision.json`
5. `reviewer_input.json`
6. `incident.json`
7. `investigation_trace.json`
8. `topology.html`
