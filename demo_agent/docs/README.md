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
- `INCIDENT_AGENT_ENABLE_LLM`
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
- `--mode`：当前只保留 `incident-agent`

## 3. 输出内容

每条 case 通常会生成：

- `input_alert.json`
- `event.json`
- `incident.json`
- `investigation_trace.json`
- `report_outline.json`
- `report.md`
- `topology.json`
- `topology.html`

## 4. 常见查看顺序

建议先看：

1. `report.md`
2. `incident.json`
3. `investigation_trace.json`
4. `topology.html`
