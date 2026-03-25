## Threat-Agent Demo（LangChain ReAct 最小闭环）

基于 **告警 JSON（默认 `demo_alert.json`，已是“命中后告警”）**，由 LangChain ReAct Agent 调用工具生成输出：

- `event.json`：归一化后的事件 JSON（保留 `raw_alert`）
- `report.md`：最终报告（由大模型基于 JSON 自由组织结构）
- `agent_output.txt`：agent 最终输出（便于调试）

### 安装依赖

在仓库根目录运行：

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r demo_agent/requirements.txt
```

### 运行

配置 DeepShield（OpenAI 兼容接口，见文档 `https://model.deepshields.com/apipage`）：

```bash
export LLM_API_KEY="YOUR_API_KEY"
export LLM_BASE_URL="https://api.deepshields.com/v1"
export LLM_MODEL="chat"   # 或 reasoner
```

可选配置 VirusTotal：

```bash
export VT_API_KEY="YOUR_VT_KEY"
```

运行（默认读取仓库根目录的 `demo_alert.json`）：

```bash
python -m demo_agent.langchain_agent --alert demo_alert.json
```

输出默认在 `demo_agent/out_langchain/`：

- 如果输入是 **单个 JSON 对象**：直接在该目录生成 `input_alert.json / event.json / report.md / agent_output.txt`
- 如果输入是 **JSON 数组**：会在 `out_langchain/000/`、`out_langchain/001/`... 下分别生成上述文件（每条告警一套产物）

可选：使用 Plan-and-Solve 模式（更少循环、更强收敛）：

```bash
python -m demo_agent.langchain_agent --alert demo_alert.json --mode plan
```

