# demo_agent 生命周期说明

这份文档专门回答一个问题：

> 一条命中后告警，是怎样穿过 Trace-Agent，最终变成 `analysis.json`、`report.md` 和 `topology` 的？

这里不强调目录分层，而强调**运行时生命周期**。

---

## 总体流转

```text
用户输入告警
  │
  ▼
┌──────────────────────────────────────────────────────────────┐
│  CLI 入口 (entrypoints/langchain_agent.py, __main__.py)     │
│  ├── 读取 --alert / --out / --mode                          │
│  ├── 解析单条或批量告警                                     │
│  └── 为每条 case 创建独立输出目录                            │
└──────────────────┬───────────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────────────────┐
│  启动装配层 (main.py)                                        │
│  ├── 加载 config.py                                          │
│  ├── 初始化 LLM client (services/api/llm.py)                │
│  └── 构建 QueryEngine                                        │
└──────────────────┬───────────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────────────────┐
│  QueryEngine (QueryEngine.py)                                │
│  ├── run_case(event, out_dir)                                │
│  ├── 管理单 case 生命周期                                     │
│  └── 调用 query/run_query_pipeline                           │
└──────────────────┬───────────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────────────────┐
│  主执行链 (query/pipeline.py)                                │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  1. Type Router                                       │  │
│  │  2. Baseline Investigators                           │  │
│  │  3. Draft Analysis                                   │  │
│  │  4. Gap Planner                                      │  │
│  │  5. Gap Fill (React / deterministic fallback)        │  │
│  │  6. Final Analysis                                   │  │
│  │  7. Report render                                    │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────┬───────────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────────────────┐
│  工具执行层 (tools/)                                         │
│  ├── baseline tools                                         │
│  ├── exploration tools                                      │
│  ├── sources/ 下游数据源适配                                │
│  └── 返回结构化观察结果给主执行链                            │
└──────────────────┬───────────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────────────────┐
│  最终产物层 (types/ + renderers/)                           │
│  ├── analysis.json                                          │
│  ├── report.md                                              │
│  ├── topology.json                                          │
│  └── topology.html                                          │
└──────────────────────────────────────────────────────────────┘
```

---

## 阶段展开

## 1. CLI 入口

相关文件：

- `demo_agent/__main__.py`
- `demo_agent/entrypoints/langchain_agent.py`

职责：

- 解析命令行参数
- 读取用户给定的告警文件
- 区分单条 case 和批量 case
- 创建输出目录
- 保存 `input_alert.json`

输入：

- `--alert`
- `--out`
- `--mode=plan`

输出：

- 标准化前的原始输入文件落盘
- 对每条 case 调用 `QueryEngine.run_case`

这一层不做：

- baseline 查询
- LLM 调用
- 报告生成

---

## 2. 启动装配层

相关文件：

- `demo_agent/main.py`
- `demo_agent/config.py`
- `demo_agent/services/api/llm.py`

职责：

- 加载 `.env` 和配置对象
- 初始化 LLM client
- 创建 `QueryEngine`

输入：

- 环境变量 / `.env`
- 可选外部注入的 cfg / llm

输出：

- 一个可运行的 `QueryEngine`

这一层的意义是把“系统怎么组起来”和“系统怎么执行一条 case”分开。

---

## 3. QueryEngine

相关文件：

- `demo_agent/QueryEngine.py`

职责：

- 承接单条 case 的执行
- 把 `event + out_dir` 交给主执行链
- 返回结构化结果

输入：

- `event`
- `out_dir`

输出：

- `result`
  - `analysis`
  - `gap_plan`
  - `supplemental`
  - `saved`

这一层是“单 case 生命周期管理器”，不是工具层，也不是渲染层。

---

## 4. Type Router

相关文件：

- `demo_agent/query/baseline/router.py`

职责：

- 根据指标类型选择 baseline investigator

输入：

- `event.trigger_fingerprint.type`

输出：

- 一个 investigator 函数

当前路由：

- `IP` -> `investigate_ip`
- `JA3 / JA4 / SSL_SHA1 / CERT_SHA1` -> `investigate_fingerprint`
- `DOMAIN / URL` -> `investigate_domain_or_url`

这一层是纯代码逻辑，不调用 LLM。

---

## 5. Baseline Investigators

相关文件：

- `demo_agent/query/baseline/ip.py`
- `demo_agent/query/baseline/fingerprint.py`
- `demo_agent/query/baseline/domain_url.py`
- `demo_agent/query/baseline/common.py`

职责：

- 在不依赖 LLM 的前提下，并发收集首轮基础证据

输入：

- `event`

输出：

- `local_obs`
- `obs_fp`
- `obs_context`
- `obs_family`
- `timings`

这一步会调用的工具类型：

- 本地库查询
- VirusTotal enrich
- 标准搜索
- abuse.ch 查询
- 家族背景补充

特点：

- 固定流程
- 可并发
- 可审计
- 不做自由推理

---

## 6. Draft Analysis

相关文件：

- `demo_agent/query/pipeline.py`
- `demo_agent/types/analysis.py`

职责：

- 把 baseline 的离散观察结果汇总成第一版 `analysis`

输入：

- `event`
- `local_obs`
- `obs_fp`
- `obs_context`
- `obs_family`

输出：

- `analysis`
  - `facts`
  - `local_intel`
  - `external_intel`
  - `evidence`
  - `findings`
  - `gaps`
  - `assessment`
  - `corroboration`

这一步的关键意义是：

> 从“工具返回了什么”切换到“系统当前认为什么”。

---

## 7. Gap Planner

相关文件：

- `demo_agent/query/gap_planner.py`

职责：

- 围绕 `analysis.gaps` 生成局部补查计划
- 决定“下一步最值得补查什么”

是否调用 LLM：

- 会
- 但有 deterministic fallback

输入：

- `analysis`

输出：

- `GapPlan`
  - `items[]`
  - 每个 item 含：
    - `gap_type`
    - `goal`
    - `actions[]`

可规划的工具名：

- `advanced_web_search`
  - 通用网页搜索，适合补搜索入口
- `technical_source_search`
  - 面向技术来源的定向搜索，优先 any.run / abuse.ch / Malpedia 等
- `fetch_page_content`
  - 抓取网页正文并清洗
- `extract_claim_candidates_from_page`
  - 从正文提炼可写入证据的 claim / TTP / 归因句子
- `extract_entities_from_page`
  - 从正文提取 IP / 域名 / URL / Hash 等二跳实体
- `pivot_related_indicators`
  - 围绕当前指标做相关 IOC 扩展
- `malware_profile_lookup`
  - 查家族背景页
- `threatfox_ioc_lookup`
  - 查 ThreatFox 结构化 IOC / 家族情报
- `urlhaus_ioc_lookup`
  - 查 URLhaus 结构化主机 / URL / payload 情报

这一层不直接输出报告，也不直接改最终结论。

---

## 8. Gap Fill

相关文件：

- `demo_agent/query/react.py`
- `demo_agent/query/pipeline.py`

职责：

- 根据 `GapPlan` 实际执行补查
- 产出新增证据或明确未解决

这一层有两条路径：

### 8.1 React Gap Fill

是否调用 LLM：

- 会

职责：

- 受限地调用 exploration tools
- 读取网页
- 提取 claim / entity
- 返回结构化 `supplemental_evidence`

输入：

- `analysis`
- `gap_plan`
- `out_dir`

输出：

- `SupplementalResult`
  - `supplemental_evidence`
  - `gap_updates`
  - `candidate_family`
  - `supplemental_summary`

可调用工具：

- `advanced_web_search`
  - 通用网页搜索
- `technical_source_search`
  - 技术来源搜索
- `threatfox_ioc_lookup`
  - ThreatFox 结构化查询
- `urlhaus_ioc_lookup`
  - URLhaus 结构化查询
- `fetch_page_content`
  - 抓网页正文
- `extract_claim_candidates_from_page`
  - 提取正文中的可用论据
- `extract_entities_from_page`
  - 提取正文中的二跳实体
- `pivot_related_indicators`
  - 扩展相关 IOC
- `malware_profile_lookup`
  - 查询家族背景资料

约束：

- 只围绕 gap_plan 行动
- 不重做 baseline
- 不允许编造
- 必须输出结构化 JSON

### 8.2 Deterministic Fallback

是否调用 LLM：

- 否

职责：

- 当某些 gap 适合纯代码补查，或 React 无有效产出时，走确定性补查链

典型动作：

- 读取已有技术页面
- 提取 claim
- 提取实体
- 整理成 `supplemental_evidence`

意义：

- 提高稳定性
- 防止补查整段空转
- 在弱证据 case 上至少尝试回收增量线索

---

## 9. Final Analysis

相关文件：

- `demo_agent/query/pipeline.py`
- `demo_agent/types/analysis.py`

职责：

- 把 baseline 结果与 supplemental 结果再次合并
- 形成最终版 `analysis`

输入：

- baseline observations
- supplemental result

输出：

- final `analysis.json`

这一步是全系统最关键的“单一事实源”收束点。  
后续的报告和拓扑都不应该绕开它。

---

## 10. Report / Topology

相关文件：

- `demo_agent/renderers/report_markdown.py`
- `demo_agent/renderers/artifacts.py`
- `demo_agent/renderers/graph_drawer_pyvis.py`
- `demo_agent/entrypoints/langchain_agent.py`

职责：

- 从 final `analysis` 生成可交付产物

输入：

- final `analysis`

输出：

- `report.md`
- `topology.json`
- `topology.html`

说明：

- `report` 是面向人的自然语言表达
- `topology` 是面向关系展示的结构化视图
- 两者都应该基于同一份 final `analysis`

---

## 11. 工具执行层与数据源层的关系

这一层容易混，所以单独说一下。

### agent 真正“看到”的是 tools

也就是说：

- baseline investigator 调的是 `tools/`
- React gap fill 调的也是 `tools/`

### tools 再去调用 sources

例如：

- `tools/baseline.py` 会调用 `tools/sources/local_intel.py`
- `tools/baseline.py` / `tools/exploration.py` 会调用 `tools/sources/abuse_ch.py`
- `tools/baseline.py` 会调用 `tools/sources/vt_client.py`

所以关系是：

```text
query / react
-> tools/*
-> tools/sources/*
```

而不是让 query 或 React 直接碰底层 client。

---

## 12. 最终记住的 3 句话

1. `QueryEngine` 管生命周期，`query/` 管主执行链，`tools/` 管能力，`renderers/` 管产物。  
2. `analysis.json` 是系统唯一事实源，报告和拓扑都围绕它生成。  
3. LLM 只参与局部规划和局部补查，不接管整条主链。
