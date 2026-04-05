# Trace-Agent

Trace-Agent 是一个面向“命中后恶意流量告警”的自动化研判 Agent。

它**不负责从原始流量中发现恶意行为**，而是接收一条已经命中指纹/规则的告警，围绕该告警做以下事情：

1. 规范化事件
2. 按指标类型执行首轮基线调查
3. 汇总首轮证据形成草稿分析
4. 识别剩余证据缺口
5. 使用 `Gap Planner + Gap Investigators (React)` 做受约束补查
6. 汇总成最终 `analysis.json`
7. 从 `analysis.json` 生成 `report.md` 和 `topology.json/html`

项目当前的核心设计目标不是“让 LLM 自由发挥”，而是构建一条**可审计、可降级、可逐步增强**的 agentic workflow。

## 1. 总体架构

主链如下：

```text
Alert Ingest
-> Type Router
-> Baseline Investigators
-> Draft Analysis
-> Gap Planner
-> Gap Investigators (React)
-> Final Analysis
-> Report / Topology
```

设计原则：

- 首轮基线调查尽量使用**纯代码 + 固定工具链**，因为本地库查询、VT 查询、结构化 IOC 查询、标准搜索本身是高度确定性的。
- LLM 只用在**局部规划**和**受约束补查**，而不是接管整个工作流。
- `analysis.json` 是整个系统的**单一事实源**。报告和拓扑都应从它生成，而不是各自直接读散乱的中间结果。
- 每一层都允许**安全降级**：外部情报失败、LLM 超时、补查无结果时，主链仍然可以完成。

## 2. 输入、输出与核心数据对象

### 2.1 输入

输入是一条或多条“命中后告警” JSON，典型字段包括：

- `event_time`
- `src_ip` / `dst_ip`
- `protocol`
- `trigger_fingerprint.type`
- `trigger_fingerprint.value`
- `enrichment.info` / `reference` / `update_time`

样例见：

- `demo_alert.json`
- `react_gap_probe.json`

### 2.2 输出

每条告警最终会产出一个目录，包含：

- `input_alert.json`
  - 原始输入告警
- `event.json`
  - 归一化后的事件对象
- `analysis.json`
  - 最终结构化分析对象，是全链路核心产物
- `report.md`
  - 面向人的中文报告
- `topology.json`
  - 结构化拓扑数据
- `topology.html`
  - 图可视化页面
- `agent_output.txt`
  - 简单运行标记

### 2.3 最重要的数据对象：`analysis.json`

`analysis.json` 是系统真正的中心对象。它大体包含：

- `event`
  - 归一化后的原始事件
- `facts`
  - 从事件中抽取的关键事实
- `local_intel`
  - 本地 MySQL 情报命中结果
- `external_intel`
  - VT、ThreatFox、URLhaus、网页搜索、家族情报等外部结果
- `supplemental`
  - gap fill 阶段补回的额外证据
- `evidence`
  - 统一整理后的证据列表
- `findings`
  - 系统提炼出的关键发现
- `corroboration`
  - 多源证据之间的支持/冲突关系
- `gaps`
  - 当前仍存在的证据缺口
- `assessment`
  - 最终家族、置信度、严重度、复核标志等
- `timings`
  - 各阶段耗时
- `report`
  - 最终报告路径与内容

## 3. 模块总览

按职责分，模块可以分成两类：

- **纯代码模块**
  - 不直接调用 LLM，负责确定性逻辑、客户端访问、数据整理、渲染与持久化。
- **调用 LLM 的模块**
  - 只承担局部规划、受限补查或可选的报告润色。

下文按模块逐一说明。

## 4. 入口与主控模块

### 4.1 `demo_agent/langchain_agent.py`

类型：纯代码模块

职责：

- 项目 CLI 入口
- 接收单条或批量告警
- 对每条告警执行完整主链
- 统一保存输入、分析结果、报告和拓扑

主要输入：

- `--alert`
  - 告警 JSON 路径
- `--out`
  - 输出目录
- `--mode`
  - 当前只支持 `plan`

主要输出：

- 返回运行结果 JSON
- 每条 case 的输出目录及产物

关键行为：

- 调用 `normalize_alert()` 生成 `event`
- 调用 `run_plan_and_solve()` 执行主链
- 调用 `build_topology_from_analysis()` 和 `draw_graph_pyvis()` 生成拓扑

说明：

- 这里已经移除了“纯 react 主模式”，现在它只承载 `plan` 主链。

### 4.2 `demo_agent/agents/plan_agent.py`

类型：纯代码模块

职责：

- 作为兼容包装层，将“plan-and-solve”入口映射到新的 V2 pipeline coordinator

输入：

- `llm`
- `cfg`
- `event`
- `out_dir`

输出：

- `run_pipeline()` 的完整结果

说明：

- 这个文件本身逻辑很轻，真实主控在 `pipeline/coordinator.py`。

## 5. 事件规范化模块

### 5.1 `demo_agent/event.py`

类型：纯代码模块

职责：

- 把原始告警规范化为系统内部统一事件结构

输入：

- 一条原始告警 `alert: Dict[str, Any]`

输出：

- `event: Dict[str, Any]`

输出字段核心包括：

- `event_time`
- `src`
- `dst`
- `protocol`
- `trigger_fingerprint`
- `enrichment`
- `raw_alert`

说明：

- 该模块明确假设输入已经是“命中后告警”。
- 它不做本地情报查询，也不做归因判断，只做归一化。

## 6. 基线调查模块

这一层全部是纯代码，不调用 LLM。

目标是：根据指标类型，自动并发地收集**首轮基础证据**。

### 6.1 `demo_agent/baseline_investigators/router.py`

类型：纯代码模块

职责：

- 按指标类型选择对应 investigator

输入：

- `indicator_type`

输出：

- 一个 investigator 函数

路由规则：

- `IP` -> `investigate_ip`
- `JA3/JA4/SSL_SHA1/CERT_SHA1` -> `investigate_fingerprint`
- `DOMAIN/URL` -> `investigate_domain_or_url`

### 6.2 `demo_agent/baseline_investigators/common.py`

类型：纯代码模块

职责：

- 提供 baseline investigator 共享的适配函数和辅助逻辑

输入：

- investigator 传入的指标、家族 seed、查询语句等

输出：

- 统一的 JSON/dict 结果

主要函数：

- `lookup_local()`
  - 调本地 MySQL 指纹库
- `enrich_vt()`
  - 调 VirusTotal baseline 工具
- `search_standard()`
  - 标准网页搜索
- `search_abuse()`
  - abuse.ch 聚合搜索
- `lookup_family()`
  - 家族背景搜索
- `merge_searches()`
  - 合并多来源搜索结果
- `timed_call()`
  - 包装调用并记录耗时
- `safe_future_result()`
  - 并发结果安全回收

### 6.3 `demo_agent/baseline_investigators/ip.py`

类型：纯代码模块

职责：

- 处理 `IP` 指标的 baseline 调查

输入：

- `event`

输出：

- `local_obs`
- `obs_fp`
- `obs_context`
- `obs_family`
- `timings`

内部固定动作：

- 本地库查询
- VT IP 富化
- 标准上下文搜索
- abuse.ch 查询
- 家族背景查询

实现特点：

- 使用 `ThreadPoolExecutor` 并发首轮 I/O
- `family_lookup` 会尽量利用 hint/local family 提前并发

### 6.4 `demo_agent/baseline_investigators/fingerprint.py`

类型：纯代码模块

职责：

- 处理 `JA3/JA4/SSL_SHA1/CERT_SHA1` 这类指纹指标的 baseline 调查

输入：

- `event`

输出：

- `local_obs`
- `obs_fp`
- `obs_context`
- `obs_family`
- `timings`

内部固定动作：

- 本地库查询
- 指纹搜索
- 上下文搜索
- abuse.ch 查询
- 家族背景查询

### 6.5 `demo_agent/baseline_investigators/domain_url.py`

类型：纯代码模块

职责：

- 处理 `DOMAIN/URL` 指标的 baseline 调查

输入：

- `event`

输出：

- `local_obs`
- `obs_fp`
- `obs_context`
- `obs_family`
- `timings`

内部固定动作：

- 本地库查询
- VT enrich（当前主要用于兼容接口，非所有类型都真正实现）
- abuse.ch 查询
- 标准搜索
- 家族背景查询

## 7. 基础客户端模块

这一层全部是纯代码模块，负责接外部系统或本地系统。

### 7.1 `demo_agent/config.py`

类型：纯代码模块

职责：

- 从 `demo_agent/.env` 和环境变量加载配置

输入：

- 环境变量 / `.env`

输出：

- `AgentConfig`
- `DatabaseConfig`

核心配置包括：

- LLM API key / base URL / model / temperature
- VT key
- abuse.ch auth key
- DB 连接参数

### 7.2 `demo_agent/clients/llm.py`

类型：LLM 基础设施模块

职责：

- 根据 `AgentConfig` 构造 LangChain `ChatOpenAI` 客户端

输入：

- `AgentConfig`

输出：

- `ChatOpenAI`

说明：

- 它本身不做提示词设计，只负责提供一个统一 LLM 入口。

### 7.3 `demo_agent/clients/local_intel.py`

类型：纯代码模块

职责：

- 查询本地 MySQL `threat_intel.intel` 表

输入：

- `indicator_type`
- `indicator_value`

输出：

- `matched`
- `best_match`
- `matches`
- `query`
- `error`

说明：

- 会做类型映射，例如 `JA3 -> ja3_md5`，`SSL_SHA1 -> ssl_sha1`
- 返回结构化记录而不是自然语言

### 7.4 `demo_agent/clients/vt_client.py`

类型：纯代码模块

职责：

- 调用 VirusTotal IP API，返回结构化 enrich 结果

输入：

- `ip`

输出：

- `stats`
- `country`
- `asn`
- `as_owner`
- `reputation`
- `raw`

说明：

- 当前最成熟的是 IP enrich，其他 IOC 类型仍以 baseline 工具层兼容为主。

### 7.5 `demo_agent/clients/abuse_ch.py`

类型：纯代码模块

职责：

- 封装 ThreatFox 和 URLhaus 的社区 API

输入：

- 指标值
- 指标类型

输出：

- 标准化后的结构化 IOC / 基础设施结果列表

包含两个客户端：

- `ThreatFoxClient`
  - 用于查 IOC、hash、家族关联、标签、样本线索
- `URLhausClient`
  - 用于查恶意 URL、host、payload、投递基础设施

说明：

- 返回结果会被统一整理成 `title/url/snippet/family/confidence/tags/...`
- 这是当前系统最重要的结构化外部情报来源之一

## 8. 工具层模块

工具层分为两类：

- baseline tools
  - 给 baseline investigator 用，也可复用给 deterministic gap fill
- exploration tools
  - 给 React gap fill 或确定性补查用

### 8.1 `demo_agent/tooling/common.py`

类型：纯代码模块

职责：

- 提供工具层共享基础能力

输入：

- 查询文本、网页 URL、原始网页 HTML、文本内容等

输出：

- 标准化搜索结果
- 清洗后的页面正文
- 抽取出的实体

主要函数：

- `search_web()`
  - 统一网页搜索入口，优先走 SerpAPI，再退到 DDGS / DuckDuckGo HTML
- `fetch_page()`
  - 抓网页正文，清理 HTML，并做截断
- `extract_text_entities()`
  - 从文本中提取 IP、域名、URL、hash
- `merge_search_observations()`
  - 合并多路搜索结果

说明：

- 内置缓存 `_CACHE_WEB / _CACHE_PAGE / _CACHE_VT_IP / _CACHE_LOCAL_INTEL`
- 这是整个系统最重要的“轻量搜索与页面抓取”底层

### 8.2 `demo_agent/tooling/baseline.py`

类型：纯代码模块

职责：

- 将本地库、VT、标准搜索、ThreatFox、URLhaus、家族搜索包装成 LangChain Tool

输入：

- `indicator_value`
- `indicator_type`
- `query`
- `family`

输出：

- JSON 字符串，内部是结构化结果

主要工具：

- `local_intel_lookup`
  - 查本地 MySQL 指纹库
- `vt_enrich_ip`
  - VT IP enrich
- `vt_enrich_ioc`
  - VT enrich 统一入口
- `standard_web_search`
  - 标准 baseline 搜索
- `threatfox_ioc_lookup`
  - ThreatFox 结构化 IOC 查询
- `urlhaus_ioc_lookup`
  - URLhaus 结构化基础设施查询
- `abuse_ch_lookup`
  - ThreatFox + URLhaus + abuse.ch 搜索聚合入口
- `family_intel_lookup`
  - 家族背景页面搜索

说明：

- 这里已经做了按指标类型的短路，例如不合适的类型不会去打 URLhaus。

### 8.3 `demo_agent/tooling/exploration.py`

类型：纯代码模块，但服务于 LLM 补查

职责：

- 提供 React gap fill 和 deterministic gap fill 的探索型工具

输入：

- 查询语句
- 网页 URL
- 页面正文

输出：

- 搜索结果
- 页面正文
- claim 列表
- entity 列表

主要工具：

- `advanced_web_search`
  - 支持 constraint 的高级网页搜索
- `technical_source_search`
  - 面向技术来源的搜索模板，优先 any.run / abuse.ch / Malpedia / VT 等
- `fetch_page_content`
  - 抓取并清理页面正文
- `extract_claim_candidates_from_page`
  - 从页面正文中提取可作为证据的句子
- `extract_entities_from_page`
  - 从正文中抽取二跳实体
- `pivot_related_indicators`
  - 围绕指标继续搜相关 IOC / 基础设施
- `malware_profile_lookup`
  - 搜高质量家族背景资料

### 8.4 `demo_agent/tooling/__init__.py`

类型：纯代码模块

职责：

- 聚合并导出项目中对 LLM 可见的工具
- 定义少量额外工具，如保存报告、构造拓扑 JSON

输入：

- 由 LLM 调用时的 tool input

输出：

- 各类 LangChain Tool

额外工具：

- `build_topology_json`
  - 从事件 JSON 直接生成拓扑 JSON
- `save_report_md`
  - 保存 Markdown 报告

## 9. 分析与证据整合模块

### 9.1 `demo_agent/analysis.py`

类型：纯代码模块

职责：

- 从 baseline / supplemental 结果中构造最终 `analysis.json`

输入：

- `event`
- `local_intel`
- `obs_fp`
- `obs_context`
- `obs_family`
- `supplemental`
- `mode`

输出：

- 完整 `analysis` dict

这是系统最复杂的纯代码模块，主要负责：

- 统一 evidence 模型
- 证据清洗、去重、分层、排序
- 家族候选聚合
- 多源归因仲裁
- corroboration 计算
- gap 生成
- gap_fill_needed 判断
- findings / actions / assessment 生成

它实际上承担了“**结构化分析引擎**”的角色。

## 10. LLM 模块：Gap Planner

### 10.1 `demo_agent/pipeline/gap_planner.py`

类型：调用 LLM 的模块

职责：

- 根据当前 `analysis` 中的 gaps 生成**局部补查计划**
- 输出强约束 JSON，而不是自由文本

输入：

- `analysis`

输出：

- `GapPlan`
  - `items[]`
  - 每个 item 包含 `gap_type`、`goal`、`actions[]`

LLM 的职责边界：

- 只规划补查动作
- 不重做 baseline
- 不直接生成最终结论
- 不写报告

可规划的工具名：

- `advanced_web_search`
  - 高级搜索
- `technical_source_search`
  - 技术来源搜索
- `fetch_page_content`
  - 读页面正文
- `extract_claim_candidates_from_page`
  - 抽正文 claim
- `extract_entities_from_page`
  - 抽页面实体
- `pivot_related_indicators`
  - 做二跳 pivot
- `malware_profile_lookup`
  - 查家族背景
- `threatfox_ioc_lookup`
  - 查 ThreatFox 结构化 IOC
- `urlhaus_ioc_lookup`
  - 查 URLhaus 结构化基础设施

说明：

- 这个模块优先使用 `with_structured_output(GapPlan)`。
- 如果 LLM 超时、失败或输出空计划，会退回 `_fallback_actions()` 生成确定性补查计划。

## 11. LLM 模块：Gap Investigators (React)

### 11.1 `demo_agent/agents/react_agent.py`

类型：调用 LLM 的模块

职责：

- 为 gap fill 构建受约束 ReAct 执行器
- 驱动 LLM 通过工具完成一次定向补查

这里实际上有两组执行器：

- `build_react_executor()`
  - 旧的“完整 react 生成报告”执行器
  - 当前主链不再依赖它
- `build_gap_fill_executor()`
  - 当前主链真正使用的受限补查执行器

#### 11.1.1 `build_gap_fill_executor()`

输入：

- `llm`
- `tools`

输出：

- `AgentExecutor`

职责：

- 用严格提示词约束 LLM：
  - 只围绕 `analysis + gap_plan` 补查
  - 最终输出必须是结构化 JSON
  - 证据不足时必须返回 `unresolved` / 空证据
  - 不能编造家族、IOC、TTP

可调用的工具：

- `advanced_web_search`
  - 高级网页搜索
- `technical_source_search`
  - 技术来源搜索
- `threatfox_ioc_lookup`
  - ThreatFox 结构化查询
- `urlhaus_ioc_lookup`
  - URLhaus 结构化查询
- `fetch_page_content`
  - 读取页面正文
- `extract_claim_candidates_from_page`
  - 从正文抽取 claim
- `extract_entities_from_page`
  - 从正文抽取实体
- `pivot_related_indicators`
  - 搜二跳 IOC
- `malware_profile_lookup`
  - 查家族背景页

输出结构：

- `supplemental_evidence`
- `gap_updates`
- `candidate_family`
- `supplemental_summary`

#### 11.1.2 `_extract_json_object()`

类型：纯代码辅助函数

职责：

- 从 LLM 输出中提取 JSON

输入：

- LLM 输出字符串

输出：

- `Dict[str, Any]`

说明：

- 支持 fenced code block
- 支持 `Final Answer:` 前缀
- 尽量从杂乱文本中恢复合法 JSON

## 12. 混合主控模块：Coordinator

### 12.1 `demo_agent/pipeline/coordinator.py`

类型：混合模块

职责：

- 编排整条主链
- 串联 baseline、draft analysis、gap planner、gap fill、final analysis、report render

输入：

- `llm`
- `cfg`
- `event`
- `out_dir`

输出：

- 最终 pipeline 结果 dict

主要步骤：

1. 根据指标类型选择 baseline investigator
2. 跑 baseline，拿到 `local_obs / obs_fp / obs_context / obs_family`
3. 构建 draft analysis
4. 若需要补查：
   - 用 `gap_planner` 规划
   - 按策略决定走：
     - `deterministic_only`
     - `react_then_fallback`
5. 若补查有结果，重建 final analysis
6. 渲染报告
7. 把 timings、report 等信息回写到 final analysis

### 12.2 Coordinator 内的关键机制

#### `_plan_gap_actions_with_timeout()`

类型：LLM 调度辅助

职责：

- 给 Gap Planner 加硬超时

输入：

- `llm`
- `analysis`

输出：

- `GapPlan`

超时策略：

- 超时或失败时自动回退到纯代码 fallback plan

#### `_run_gap_fill_with_timeout()`

类型：LLM 调度辅助

职责：

- 给 React gap fill 加硬超时

输入：

- `gap_executor`
- `analysis`
- `gap_plan`
- `out_dir`

输出：

- `gap_result` 或 `None`

#### `_prefer_deterministic_gap_fill()`

类型：纯代码策略函数

职责：

- 判断某些 gap 是否应该直接走确定性补查，而不是先跑 React

设计意图：

- 避免让 LLM 在低收益场景下重复空转
- 优先用确定性 API 编排解决“已知家族补第二来源”或“Unknown 家族补结构化基础设施”这类问题

#### `_deterministic_gap_fill()`

类型：纯代码补查模块

职责：

- 在不依赖 React 的情况下，根据 `gap_plan` 的动作链直接跑结构化补查

输入：

- `analysis`
- `gap_plan`

输出：

- 与 React 一致的 `supplemental` 结构：
  - `supplemental_evidence`
  - `gap_updates`
  - `candidate_family`
  - `supplemental_summary`

内部动作：

- 调 ThreatFox / URLhaus
- 调技术搜索
- 读取 top result 页面
- 抽 claim / entity
- 生成 supplemental evidence

说明：

- 这是当前项目里非常关键的“半确定性 Agentic Workflow”设计点。

## 13. 渲染模块

### 13.1 `demo_agent/renderers/report_markdown.py`

类型：纯代码模块

职责：

- 将 `analysis` 渲染成对外中文 Markdown 报告

输入：

- `analysis`

输出：

- `report.md` 文本

主要工作：

- 组织事件概述
- 组织研判结论
- 组织归因依据
- 挑选关键证据
- 整理补查发现
- 整理参考链接
- 生成处置建议

说明：

- 当前默认优先走本地渲染器
- `coordinator.py` 中也支持可选的 LLM 报告模式，但主设计仍然是“报告从 analysis 渲染”，而不是让 LLM 自由写事实

### 13.2 `demo_agent/renderers/artifacts.py`

类型：纯代码模块

职责：

- 从 `event` 或 `analysis` 构造拓扑图的结构化 JSON

输入：

- `event`
- 或 `analysis`

输出：

- `topology.json`

说明：

- `build_topology_from_analysis()` 会把最终家族、置信度、目的地址 enrich 等信息回填到图谱输入中。

### 13.3 `demo_agent/renderers/graph_drawer_pyvis.py`

类型：纯代码模块

职责：

- 将 `topology.json` 渲染为 `topology.html`

输入：

- `graph_data`

输出：

- HTML 文件路径

说明：

- 基于 `pyvis`
- 对节点、边、层级布局做了基本约束

## 14. 存储模块

### 14.1 `demo_agent/storage/io.py`

类型：纯代码模块

职责：

- 统一做 JSON / 文本读写

输入：

- 路径
- 对象或文本

输出：

- 文件系统上的 JSON 或文本文件

说明：

- 这是最基础的持久化层，不包含业务逻辑。

## 15. 结构化协议模块

### 15.1 `demo_agent/schemas.py`

类型：纯代码模块

职责：

- 用 Pydantic 定义 LLM 交互协议和补查协议

输入：

- LLM 输出的 JSON 或 Python dict

输出：

- 类型安全的 `GapPlan` / `SupplementalResult`

核心 schema：

- `GapPlanAction`
- `GapPlanItem`
- `GapPlan`
- `SupplementalEvidence`
- `GapUpdate`
- `SupplementalResult`

说明：

- `GapPlanAction` 允许额外字段，目的是提升对 LLM 输出小变体的兼容性。

## 16. 当前设计的关键思想

阅读完上面的模块后，理解这个项目最重要的不是“有哪些文件”，而是以下几个设计原则：

### 16.1 基线调查优先纯代码

因为首轮动作高度固定：

- 查本地库
- 查 VT
- 查 ThreatFox / URLhaus
- 跑标准搜索
- 跑家族背景搜索

这些动作不需要 LLM 规划，用纯代码更稳定、更快、更易审计。

### 16.2 LLM 只负责局部规划和局部探索

LLM 主要只在两处介入：

- `Gap Planner`
  - 决定“补什么缺口”
- `Gap Investigators (React)`
  - 决定“围绕这个缺口如何具体搜/读/提取”

它不负责：

- 路由指标类型
- 跑首轮 baseline
- 直接决定所有最终结论

### 16.3 `analysis.json` 是单一事实源

报告和拓扑不应该各自直接读 baseline 或 react 输出，而应统一从 `analysis` 生成。  
这能保证：

- 图和报告一致
- 证据可追溯
- 后续可继续扩展 memory / DB / evaluation

### 16.4 React 不是唯一补查方式

本项目并没有把所有 gap 都交给 React。  
相反，它引入了：

- `Gap Planner`
- `React gap fill`
- `deterministic fallback`

也就是：

- 能确定性解决的补查，就优先用确定性流
- 只有在值得探索时才让 React 介入

### 16.5 工具层分层

工具不是一锅端给 LLM，而是分成：

- baseline tools
- exploration tools

这样可以避免：

- React 重跑 baseline
- 不合适的指标类型乱用不合适的工具
- 全链路发散

## 17. 设计上最值得关注的阅读顺序

如果你第一次阅读这个项目，推荐按下面顺序看源码：

1. `demo_agent/langchain_agent.py`
2. `demo_agent/event.py`
3. `demo_agent/baseline_investigators/router.py`
4. `demo_agent/baseline_investigators/ip.py`
5. `demo_agent/baseline_investigators/fingerprint.py`
6. `demo_agent/tooling/baseline.py`
7. `demo_agent/analysis.py`
8. `demo_agent/pipeline/gap_planner.py`
9. `demo_agent/agents/react_agent.py`
10. `demo_agent/pipeline/coordinator.py`
11. `demo_agent/renderers/report_markdown.py`
12. `demo_agent/renderers/artifacts.py`

按这个顺序读，最容易把“固定工作流 + 局部 LLM + 单一事实源”的设计理解完整。
