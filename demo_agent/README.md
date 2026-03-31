## Threat-Agent Demo（LangChain ReAct 最小闭环）

基于 **告警 JSON（默认 `demo_alert.json`，已是“命中后告警”）**，由 LangChain ReAct Agent 调用工具生成输出：

- `event.json`：归一化后的事件 JSON（保留 `raw_alert`）
- `analysis.json`：agent 富化后的统一分析结果
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

推荐在 `demo_agent/` 下创建 `.env`，集中管理模型、VT 以及后续数据库配置：

```bash
cp demo_agent/.env.example demo_agent/.env
# 然后按需填写 demo_agent/.env
```

当前 agent 会自动加载 `demo_agent/.env`。你也可以继续使用 shell `export`，两者兼容。

配置 DeepShield（OpenAI 兼容接口，见文档 `https://model.deepshields.com/apipage`）：

```bash
LLM_API_KEY="YOUR_API_KEY"
LLM_BASE_URL="https://api.deepshields.com/v1"
LLM_MODEL="chat"   # 或 reasoner
VT_API_KEY="YOUR_VT_KEY"  # 可选
```

`demo_agent/.env.example` 里也预留了数据库相关字段，后续如果要接入数据库或 case 存储，可以继续沿用同一套配置方式。

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

