# Incident-Agent 快速开始

当前仓库主线只保留 `incident-agent`。默认链路是：调查层使用供应商 `tool` 模型做开放式工具决策，report material 和 writer / polish 使用 DeepSeek v4，报告事实仍由 deterministic source bundle / fact catalog 约束，LLM 只负责路由、论证组织和正文展开；如果默认 `tool` / `chat` 上游不稳定，也可以把调查和 review 显式切到 DeepSeek v4。

## 1. 配置 `.env`

配置文件位置：

```text
demo_agent/.env
```

可以参考：

```text
demo_agent/.env.example
```

基础配置：

```env
LLM_API_KEY=<DeepShields key>
LLM_BASE_URL=https://api.deepshields.com/v1
LLM_MODEL=chat
LLM_TEMPERATURE=0.7
```

当前最强报告链路建议加上以下角色级配置：

```env
# If the default tool/chat upstream is unstable, route investigation and review
# roles to the same stable OpenAI-compatible provider used by the writer.
INCIDENT_AGENT_INVESTIGATOR_MODEL=deepseek-v4-pro
INCIDENT_AGENT_INVESTIGATOR_BASE_URL=https://api.deepseek.com
INCIDENT_AGENT_INVESTIGATOR_API_KEY=<DeepSeek key>
INCIDENT_AGENT_INVESTIGATOR_MAX_TOKENS=6000
INCIDENT_AGENT_INVESTIGATOR_TEMPERATURE=0.2
INCIDENT_AGENT_INVESTIGATOR_REASONING_EFFORT=high
INCIDENT_AGENT_INVESTIGATOR_THINKING_ENABLED=1

INCIDENT_AGENT_REVIEWER_MODEL=deepseek-v4-pro
INCIDENT_AGENT_REVIEWER_BASE_URL=https://api.deepseek.com
INCIDENT_AGENT_REVIEWER_API_KEY=<DeepSeek key>
INCIDENT_AGENT_REVIEWER_MAX_TOKENS=6000
INCIDENT_AGENT_REVIEWER_TEMPERATURE=0.2
INCIDENT_AGENT_REVIEWER_REASONING_EFFORT=high
INCIDENT_AGENT_REVIEWER_THINKING_ENABLED=1

INCIDENT_AGENT_REPORT_MATERIAL_MODEL=deepseek-v4-pro
INCIDENT_AGENT_REPORT_MATERIAL_BASE_URL=https://api.deepseek.com
INCIDENT_AGENT_REPORT_MATERIAL_API_KEY=<DeepSeek key>
INCIDENT_AGENT_REPORT_MATERIAL_MAX_TOKENS=16000
INCIDENT_AGENT_REPORT_MATERIAL_TEMPERATURE=0.2
INCIDENT_AGENT_REPORT_MATERIAL_REASONING_EFFORT=high
INCIDENT_AGENT_REPORT_MATERIAL_THINKING_ENABLED=1

INCIDENT_AGENT_WRITER_MODEL=deepseek-v4-pro
INCIDENT_AGENT_WRITER_BASE_URL=https://api.deepseek.com
INCIDENT_AGENT_WRITER_API_KEY=<DeepSeek key>
INCIDENT_AGENT_WRITER_MAX_TOKENS=20000
INCIDENT_AGENT_WRITER_TEMPERATURE=0.2
INCIDENT_AGENT_WRITER_REASONING_EFFORT=high
INCIDENT_AGENT_WRITER_THINKING_ENABLED=1
```

外部情报配置：

```env
SERPAPI_API_KEY=<SerpAPI key>
ABUSECH_AUTH_KEY=<abuse.ch key>
VT_API_KEY=<VirusTotal key>
INCIDENT_AGENT_LIVE_INTEL=1
```

说明：

- `INCIDENT_AGENT_INVESTIGATOR_*` 只影响调查层工具决策。默认 `tool` / `chat` 上游不稳定时，建议显式路由到当前稳定 provider。
- `INCIDENT_AGENT_REVIEWER_*` 只影响 post-action / finish reviewer；它决定是否接受工具动作或交付，不影响 writer 事实边界。
- `INCIDENT_AGENT_REPORT_MATERIAL_*` 只影响 report material agent。
- `INCIDENT_AGENT_WRITER_*` 同时影响 writer 和 polish / repair 相关调用。
- `INCIDENT_AGENT_<ROLE>_BASE_URL` 与 `INCIDENT_AGENT_<ROLE>_API_KEY` 会覆盖默认 OpenAI-compatible endpoint，适合让调查层继续走 DeepShields，而 material / writer 单独走 DeepSeek。
- `INCIDENT_AGENT_LLM_TRACE_PATH` 可记录每次 LLM 调用的模型路由、payload 摘要、生成参数、`finish_reason` 和 token usage，便于排查截断、fallback 或 endpoint 配置错误。
- 不要提交真实 API key。仓库文档和示例只保留占位符。

## 2. 运行单个 case

在仓库根目录运行：

```bash
conda run -n trail-agent python -m demo_agent \
  --alert fixtures/incidents/multi_host_confirmed_spread_plus \
  --out outputs/plan13_manual_check/multi_host_confirmed_spread_plus \
  --mode incident-agent \
  --decision-mode llm_agent \
  --use-report-agent-materials
```

参数说明：

- `--alert` 可以指向 fixture case 目录，也可以指向 `seed_alert.json`。
- `--out` 是输出目录。
- `--decision-mode` 默认是 `llm_agent`；可选 `heuristic`、`llm_selector`、`llm_agent`、`hybrid`。
- `--use-report-agent-materials` 当前默认开启，会走 material agent + writer brief + polished report 链路。

如果没有可用 LLM，请求 `llm_agent` 时会自动降级到 `heuristic`，用于离线 smoke test。

### Evidence Graph Writer Experiment

实验分支可以跳过 LLM material agent，先从 `report_source_bundle` / `source_fact_catalog` 编译确定性证据图和假设板，再交给 writer 写作：

```bash
conda run -n trail-agent python -m demo_agent \
  --alert fixtures/incidents/multi_host_confirmed_spread_plus \
  --out outputs/plan13_v48_evidence_graph_writer_live/multi_host_confirmed_spread_plus \
  --mode incident-agent \
  --decision-mode llm_agent \
  --use-report-agent-materials \
  --report-writer-mode evidence-graph
```

该模式会保留 `report_writer_brief.json`、`report_writer_materials.json`、`report_evidence_graph.json`、`report_hypothesis_board.json`、`report_graph_writer_brief.json` 和 `report_material_loop_trace.json`。`report_material_loop_trace.json` 应明确标记 material agent 被 evidence graph writer bypass，而不是伪装成 agent-authored materials。

## 3. 运行 5-case live eval

当前用于人工看效果的 5 个 fixture 是：

```text
multi_host_confirmed_spread_plus
shared_infra_multi_asset_needs_review
suspected_exfil_after_execution
web_initial_access_to_beacon
web_initial_access_without_execution
```

推荐用一个独立输出目录保存整轮 live eval：

```bash
OUT=outputs/plan13_current_strongest_5case_live
mkdir -p "$OUT"

for CASE in \
  multi_host_confirmed_spread_plus \
  shared_infra_multi_asset_needs_review \
  suspected_exfil_after_execution \
  web_initial_access_to_beacon \
  web_initial_access_without_execution
do
  CASE_OUT="$OUT/$CASE"
  mkdir -p "$CASE_OUT"
  conda run -n trail-agent python -m demo_agent \
    --alert "fixtures/incidents/$CASE" \
    --out "$CASE_OUT" \
    --mode incident-agent \
    --decision-mode llm_agent \
    --use-report-agent-materials \
    > "$CASE_OUT/run_stdout.json" \
    2> "$CASE_OUT/run_stderr.txt"
  printf '%s\n' "$?" > "$CASE_OUT/run_rc.txt"
done
```

Live eval 会调用外部 API，耗时和费用都明显高于 smoke test。宽回归或多轮 live eval 前建议先确认必要性。

## 4. 验证命令

快速验证 `llm_agent` 的开放式循环：

```bash
conda run -n trail-agent python tools/test_llm_agent_protocol.py
```

离线 5-case smoke：

```bash
conda run -n trail-agent python tools/run_incident_smoke.py
```

确认外部 LLM API 连通性：

```bash
conda run -n trail-agent python tools/llm_ping.py --trace-path outputs/llm_ping.jsonl
```

报告链路或 writer 改动后，至少编译相关 Python 文件：

```bash
conda run -n trail-agent python -m py_compile \
  demo_agent/incidents/evidence_graph.py \
  demo_agent/incidents/report_agent.py \
  demo_agent/incidents/report_agent_tools.py \
  demo_agent/incidents/report_agent_writer.py \
  demo_agent/incidents/render.py
```

## 5. 输出内容

每条 case 通常会生成：

- `input_alert.json`
- `event.json`
- `incident.json`
- `investigation_trace.json`
- `evidence_store.json`
- `delivery_decision.json`
- `reviewer_input.json`
- `report_source_bundle.json`
- `report_material_loop_trace.json`
- `report_writer_materials.json`
- `report_writer_brief.json`
- `report_evidence_graph.json`（仅 evidence-graph writer mode）
- `report_hypothesis_board.json`（仅 evidence-graph writer mode）
- `report_graph_writer_brief.json`（仅 evidence-graph writer mode）
- `report_outline.json`
- `report.md`
- `report_appendix.md`
- `report_polish_input.json`
- `report_polish_brief.md`
- `report_polish_validation.json`
- `report_polished.md` 或 `report_polish_error.txt`
- `llm_calls.jsonl`
- `topology.json`
- `topology.html`

建议查看顺序：

1. `report_polished.md`
2. `report_polish_validation.json`
3. `report_material_loop_trace.json`
4. `report_writer_materials.json`
5. `report_writer_brief.json`
6. `incident.json`
7. `delivery_decision.json`
8. `investigation_trace.json`
9. `llm_calls.jsonl`
10. `topology.html`

看报告质量时不要只看命令是否成功。重点确认是否存在 fallback、`finish_reason=length`、material 多轮修复、candidate / confirmed 边界混淆、以及 action guidance 是否足够可执行。

## 6. 当前保留的对比产物

当前 `outputs/` 只保留两组报告产物：

- `outputs/plan13_v38_current_strongest_5case_live_deepseek_v4/`：最新 5-case live eval。调查层为 `tool`，material / writer 为 `deepseek-v4-pro`。
- `outputs/plan13_v36_current_strongest_live/`：上一版最佳单 case 基线，用于和最新链路做人工对比。

最新 v38 的整体结果：5 个 case 均生成 `report_polished.md`，无 LLM error，无 `finish_reason=length`，material 未 fallback。其中 3 个 polish validation 为 `clean`，1 个为 `soft_warn`，`web_initial_access_to_beacon` 当前存在一个已知 validator 误报：`shell.aspx` 文件名被当作未知域名标为 `unknown_domain` hard fail。

## 7. 生命周期 / 数据流

详细生命周期说明见：

- [lifecycle.md](/home/estar0x/project/maltrail_test/Trace-Agent/demo_agent/docs/lifecycle.md)
