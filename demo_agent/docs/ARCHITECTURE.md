# demo_agent 架构说明

这份文档只回答三件事：

- 这套 agent 的核心设计洞察是什么
- 当前推荐阅读和演化的目录骨架是什么
- 每一层各自负责什么

阅读代码时，建议优先以这里描述的结构视图为准。

---

## 核心洞察

### 1. 一切调查能力尽量 Tool 化

对 Trace-Agent 来说，下面这些都优先视为 `Tool`：

- 本地 MySQL 情报查询
- VirusTotal enrich
- ThreatFox / URLhaus 结构化查询
- 标准网页搜索 / 技术来源搜索
- 抓取网页正文
- claim / entity / IOC 提取
- 指标 pivot / 家族背景补充

它们在抽象上都属于同一类能力：

> 输入查询对象，返回结构化观察结果。

一旦统一成 Tool：

- baseline 可以统一调度
- React 补查可以统一受控调用
- 工具白名单、权限、超时、并发策略更容易集中管理
- 输出更容易统一 merge 到 `analysis`

### 2. LLM 不是 Tool，而是推理基础设施

Gap Planner、React Gap Fill、摘要润色都依赖模型，但“模型本身”不是某个调查动作。  
因此 LLM 更适合作为一层基础设施保留在 `services/api/`，而不是和具体调查能力混放。

### 3. 主流程、工具、状态、展示必须分开

这套系统不是“一个大模型自由探索”，而是：

- 主流程负责阶段编排
- Tool 层负责实际能力
- Types / State 负责结构化状态
- Renderers 负责最终产物

这四层分清楚之后，系统才稳定、可审计、也更容易继续增强。

---

## 目录骨架

```text
demo_agent/
├── docs/                     # 设计与生命周期文档
├── entrypoints/              # 外部入口
├── main.py                   # 启动装配：配置、LLM、engine
├── QueryEngine.py            # 单 case 生命周期管理
├── query/                    # 主执行链 package
│   ├── __init__.py           # 对外导出 run_query_pipeline
│   ├── pipeline.py           # 主执行链定义
│   ├── gap_planner.py        # Gap Planner
│   ├── react.py              # React gap fill 执行器
│   └── baseline/             # baseline 路由与类型化调查器
├── Tool.py                   # Tool 协议与元数据定义
├── tools/                    # 一切 agent 可调用能力
│   ├── __init__.py           # 对外导出常用 tools
│   ├── registry.py           # 工具注册表与阶段工具集合
│   ├── baseline.py           # baseline 常用工具
│   ├── exploration.py        # gap fill / React 常用工具
│   ├── common.py             # 工具共享逻辑
│   └── sources/              # 底层数据源适配（abuse.ch / VT / MySQL）
├── services/
│   └── api/                  # LLM client 与 structured output 封装
├── renderers/                # report / topology 渲染
├── state/                    # 运行时状态与阶段 trace
├── types/                    # event / analysis / schema 定义
├── utils/                    # 纯辅助函数
└── config.py                 # 配置加载
```

说明：

- Python 下不能同时存在 `tools.py` 文件和 `tools/` 目录，所以这里用 `tools/registry.py` 承担“工具注册表”的角色。
- 当前代码已经按这套主骨架完成收薄，后续理解与继续优化时，建议优先以这里描述的结构为准。

---

## 目录介绍

## 1. docs/

职责：

- 放设计说明、生命周期说明、后续重构草案
- 给人看“为什么这样设计”，而不是承载运行时代码

这一层是团队协作和系统理解入口。

---

## 2. entrypoints/

职责：

- 接收 CLI 或外部调用
- 读取输入告警
- 创建输出目录
- 将请求交给 `main.py` / `QueryEngine.py`

这一层只负责“进入系统”，不负责调查、归因或渲染。

典型内容：

- `langchain_agent.py`

---

## 3. main.py

职责：

- 初始化系统依赖
- 加载配置
- 创建 LLM client
- 构建 QueryEngine

这是“把系统组起来”的位置。

---

## 4. QueryEngine.py

职责：

- 管理单个 case 的生命周期
- 接收 `event` 和输出目录
- 调用主执行链
- 返回结构化结果

它比 `query/` 高一层，更偏“case runtime manager”。

---

## 5. query/

职责：

- 承载主执行链 package
- 把 baseline、gap planner、gap fill 拆成清晰子模块
- 作为 `QueryEngine` 调用的统一执行入口

当前主链逻辑可概括为：

```text
Alert Ingest
-> Type Router
-> Baseline
-> Draft Analysis
-> Gap Planner
-> Gap Fill
-> Final Analysis
-> Report / Topology
```

推荐拆分如下：

- `query/pipeline.py`
  - 主执行链编排
  - 串起 baseline、draft analysis、gap planner、gap fill、final analysis、report
- `query/gap_planner.py`
  - 围绕 gaps 生成局部补查计划
- `query/react.py`
  - 负责受限 React 补查执行
- `query/baseline/`
  - baseline 路由与类型化 investigator

也就是说，`query/` 是流程定义层，不是具体工具层。

---

## 6. Tool.py

职责：

- 定义统一的 Tool 协议和元数据

建议每个 Tool 至少显式声明：

- `name`
- `kind`
- `read_only`
- `networked`
- `structured_output`
- `baseline_allowed`
- `react_allowed`
- `supported_indicator_types`
- `supported_gap_types`
- `timeout_seconds`
- `concurrency_safe`

这层是后续做：

- 工具白名单
- 工具路由
- 权限策略
- 并发治理

的共同基础。

---

## 7. tools/

这是整个项目最核心的一层。

原则：

> 凡是 agent 可以显式调用的一项调查能力，都优先放进 `tools/`。

### `tools/registry.py`

职责：

- 注册系统中有哪些 tool
- 定义 baseline 可用工具集合
- 定义 React 可用工具集合
- 后续承载按 indicator type / gap type 的工具路由

### `tools/baseline.py`

职责：

- 提供 baseline 阶段常用的固定工具

典型能力：

- `local_intel_lookup`
- `vt_enrich_ioc`
- `standard_web_search`
- `abuse_ch_lookup`
- `family_intel_lookup`

### `tools/exploration.py`

职责：

- 提供 gap fill / React 阶段的探索型工具

典型能力：

- `advanced_web_search`
- `technical_source_search`
- `fetch_page_content`
- `extract_claim_candidates_from_page`
- `extract_entities_from_page`
- `pivot_related_indicators`
- `malware_profile_lookup`

### `tools/common.py`

职责：

- 提供工具层共享逻辑

例如：

- 文本清洗
- URL 规范化
- HTML 提取
- 搜索结果 merge
- entity 抽取辅助

### `tools/sources/`

职责：

- 承接底层数据源适配

这层不是直接给 agent 用的“高层 Tool”，而是被 `tools/baseline.py`、`tools/exploration.py` 等工具封装调用的底层实现。

当前包括：

- `abuse_ch.py`
- `local_intel.py`
- `vt_client.py`

---

## 8. services/api/

职责：

- 承接 LLM 运行基础设施

包括：

- provider / model 配置
- client 初始化
- structured output 封装
- retry / timeout / parse fallback

这一层只保留真正跨阶段、非工具化的基础设施。  
对当前项目来说，最明确符合这个定义的就是 LLM API 层。

---

## 9. renderers/

职责：

- 根据 `final analysis` 生成最终产物

包括：

- `report.md`
- `topology.json`
- `topology.html`

这一层不做调查，不做 gap 规划，也不直接访问外部数据源。  
它只负责“把结构化分析状态渲染成可交付产物”。

---

## 10. state/

职责：

- 承载运行时状态与阶段 trace

适合放：

- case runtime state
- stage trace
- planner / React 执行轨迹
- session 级状态快照

这层更偏“过程中的状态”。

---

## 11. types/

职责：

- 承载结构化数据模型与 schema

当前最核心的是：

- `event`
- `analysis`
- `GapPlan`
- `SupplementalResult`

这层更偏“数据长什么样”。

简化理解：

- `types/` = 数据结构定义
- `state/` = 运行中的状态与快照

---

## 12. utils/

职责：

- 放纯辅助函数

例如：

- `io.py`
- `url.py`
- `text.py`
- `dedupe.py`
- `timing.py`

这层不承载主业务逻辑，也不承载 Tool 协议。

---

## 推荐阅读顺序

如果第一次读这个项目，推荐按下面顺序看：

1. `entrypoints/langchain_agent.py`
2. `main.py`
3. `QueryEngine.py`
4. `query/pipeline.py`
5. `query/gap_planner.py`
6. `query/react.py`
7. `query/baseline/router.py`
8. `Tool.py`
9. `tools/registry.py`
10. `tools/baseline.py`
11. `tools/exploration.py`
12. `types/analysis.py`
13. `renderers/report_markdown.py`

这样最容易先建立主链认知，再下钻到具体工具和渲染逻辑。
