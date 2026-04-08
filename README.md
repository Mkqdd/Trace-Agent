# Trace-Agent 设计说明

Trace-Agent 是一个面向**命中后恶意流量告警**的自动化研判 Agent。

它不负责从原始流量中发现恶意行为，而是接收一条已经命中指纹/规则的告警，围绕这条告警完成：

- 首轮基线调查
- 缺口识别
- 局部补查
- 结构化分析汇总
- 报告与拓扑生成

整个项目的主设计链路是：

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

---

## 0. 全局设计原则

在看 8 个模块之前，先理解这套系统的 4 个总原则：

### 0.1 首轮调查尽量不用 LLM

像本地库查询、VT enrich、ThreatFox / URLhaus 查询、标准网页搜索这类动作，本质上是固定的 I/O 编排，纯代码更稳定、更快、更可审计。

### 0.2 LLM 只做“局部规划”和“局部探索”

LLM 不负责整条主链，只负责：

- Gap Planner：决定围绕哪些 gap 做补查
- Gap Investigators (React)：围绕 gap 调工具补充证据

### 0.3 `analysis.json` 是单一事实源

所有最终展示层都应该从 `analysis.json` 出发：

- `report.md`
- `topology.json`
- `topology.html`

而不是各自直接读取 baseline / React 的零散结果。

### 0.4 React 不是唯一补查机制

系统不是“全靠 React”。  
Gap 阶段实际有 3 层：

- Gap Planner：局部补查计划
- React Gap Fill：受限补查
- Deterministic Fallback：当补查适合用确定性流或 React 无结果时，走纯代码补查

---

## 1. Alert Ingest

### 模块职责

接收用户提供的告警 JSON，完成输入读取、逐条 case 切分、目录初始化和主链调用。

### 是否调用 LLM

否。

### 输入

- 单条告警对象，或告警对象数组
- CLI 参数：
  - `--alert`
  - `--out`
  - `--mode`

### 输出

- 每条 case 的输出目录
- 每条 case 的：
  - `input_alert.json`
  - `event.json`
  - `analysis.json`
  - `report.md`
  - `topology.json`
  - `topology.html`

### 这一层做什么，不做什么

会做：

- 读取 JSON
- 判断是单条还是批量
- 为每条告警建立独立输出目录
- 调用后续主链

不会做：

- 归因
- 工具调用
- 情报查询

### 相关代码

- `demo_agent/langchain_agent.py`
- `demo_agent/storage/io.py`

---

## 2. Type Router

### 模块职责

根据命中的指标类型，把事件路由到对应的 baseline 调查路径。

### 是否调用 LLM

否。

### 输入

- 归一化后的 `event`
- 核心字段：
  - `trigger_fingerprint.type`
  - `trigger_fingerprint.value`

### 输出

- 一个 investigator 函数

### 路由逻辑

当前按指标类型分成 3 条主线：

- `IP`
  - 路由到 `investigate_ip`
- `JA3 / JA4 / SSL_SHA1 / CERT_SHA1`
  - 路由到 `investigate_fingerprint`
- `DOMAIN / URL`
  - 路由到 `investigate_domain_or_url`

### 设计意图

这一步的目标是把“指标类型差异”前置，避免所有类型都走一条模糊的大流水线。

### 相关代码

- `demo_agent/baseline_investigators/router.py`

---

## 3. Baseline Investigators

### 模块职责

在**不依赖 LLM** 的前提下，自动并发地收集首轮基础证据。

这是整个系统的“确定性调查层”。

### 是否调用 LLM

否。

### 输入

- `event`

### 输出

一个 baseline 结果对象，核心包括：

- `local_obs`
  - 本地 MySQL 情报命中结果
- `obs_fp`
  - 指纹或 IOC 的直接 enrich 结果
- `obs_context`
  - 上下文搜索结果
- `obs_family`
  - 家族背景搜索结果
- `timings`
  - 各 baseline 子步骤耗时

### 子调查器

#### 3.1 IP Investigator

职责：

- 对 IP 指标做首轮固定调查

固定动作：

- 本地库查询
- VirusTotal IP enrich
- 标准上下文搜索
- abuse.ch 查询
- 家族背景查询

对应代码：

- `demo_agent/baseline_investigators/ip.py`

#### 3.2 Fingerprint Investigator

职责：

- 对 JA3 / JA4 / SSL_SHA1 / CERT_SHA1 这类指纹做首轮固定调查

固定动作：

- 本地库查询
- 指纹搜索
- 上下文搜索
- abuse.ch 查询
- 家族背景查询

对应代码：

- `demo_agent/baseline_investigators/fingerprint.py`

#### 3.3 Domain/URL Investigator

职责：

- 对 DOMAIN / URL 做首轮固定调查

固定动作：

- 本地库查询
- VT enrich 统一入口
- abuse.ch 查询
- 标准搜索
- 家族背景查询

对应代码：

- `demo_agent/baseline_investigators/domain_url.py`

### 这一层依赖的底层能力

为了保持 investigator 本身简洁，这一层会通过共享适配层访问底层工具：

- `lookup_local`
- `enrich_vt`
- `search_standard`
- `search_abuse`
- `lookup_family`
- `timed_call`

对应代码：

- `demo_agent/baseline_investigators/common.py`

### 设计意图

Baseline Investigators 的设计重点不是“聪明”，而是：

- 自动
- 类型化
- 并发
- 稳定
- 可重复

---

## 4. Draft Analysis

### 模块职责

把 baseline 阶段收集到的事实和情报，汇总为一份**初版结构化分析对象**。

这是从“零散观察结果”进入“统一分析状态”的关键转换层。

### 是否调用 LLM

否。

### 输入

- `event`
- `local_obs`
- `obs_fp`
- `obs_context`
- `obs_family`
- `mode`

### 输出

- 初版 `analysis` 对象

其中最核心的部分包括：

- `facts`
- `local_intel`
- `external_intel`
- `evidence`
- `findings`
- `corroboration`
- `gaps`
- `assessment`
- `gap_fill_needed`

### Draft Analysis 的关键工作

#### 4.1 证据统一化

不同来源的结果会被整理进统一 evidence 模型：

- event evidence
- local intel evidence
- VT evidence
- search result evidence
- family background evidence

#### 4.2 证据清洗与排序

会做：

- URL 规范化
- 标题/摘要清洗
- 去重
- 按来源权重和证据质量排序
- 标记 `evidence_tier`
- 标记 `page_type`
- 标记 `is_reportable`

#### 4.3 多源归因仲裁

会综合以下来源的家族信号：

- 本地高置信指纹命中
- 结构化外部家族来源
- 家族背景来源
- 告警自带 hint
- 补查阶段补回的家族信号

并形成：

- `primary_source`
- `supporting_sources`
- `conflicting_sources`
- `family_candidates`
- `requires_manual_review`

#### 4.4 gap 生成

会根据当前证据覆盖情况生成 gap，例如：

- `missing_local_match`
- `vt_only_context`
- `single_source_attribution`
- `no_secondary_confirmation`
- `behavior_context_missing`
- `destination_context_missing`
- `conflicting_attribution`

### 相关代码

- `demo_agent/analysis.py`

### 设计意图

这一步的本质是：

**把 baseline 阶段的“观测结果”提升为一份可驱动后续决策的“分析状态”。**

---

## 5. Gap Planner

### 模块职责

只围绕 Draft Analysis 中的 `gaps`，生成一份**局部补查计划**。

### 是否调用 LLM

是。

### 输入

- 初版 `analysis`

### 输出

- `GapPlan`

结构大致为：

```json
{
  "items": [
    {
      "gap_type": "...",
      "goal": "...",
      "actions": [
        {"tool": "...", "query": "...", "notes": "..."}
      ]
    }
  ]
}
```

### LLM 在这里的职责

它只负责回答：

- 这个 gap 最值得怎么补
- 先查什么
- 再读什么页面
- 该抽哪些 claim / entity

它**不负责**：

- 改写最终结论
- 重新跑 baseline
- 自由发散式全局规划

### 可规划的工具

Gap Planner 不直接执行工具，但它必须在计划里只使用允许的工具名。

允许的工具包括：

- `advanced_web_search`
  - 通用高级网页搜索
- `technical_source_search`
  - 面向技术来源的搜索模板
- `fetch_page_content`
  - 读取网页正文
- `extract_claim_candidates_from_page`
  - 从正文抽证据句子
- `extract_entities_from_page`
  - 从正文抽 IP/域名/URL/Hash
- `pivot_related_indicators`
  - 围绕当前指标继续找二跳 IOC
- `malware_profile_lookup`
  - 查高质量家族背景页面
- `threatfox_ioc_lookup`
  - ThreatFox 结构化 IOC 查询
- `urlhaus_ioc_lookup`
  - URLhaus 结构化 URL / host / payload 查询

### 输入输出约束

输入：

- `analysis`

输出：

- 强结构化的 `GapPlan`

### 失败与回退

如果 LLM：

- 超时
- 输出非法 JSON
- 输出空计划

系统会自动回退到纯代码的 `_fallback_actions()`。

### 相关代码

- `demo_agent/pipeline/gap_planner.py`
- `demo_agent/schemas.py`

---

## 6. Gap Investigators (React)

### 模块职责

拿着 Gap Planner 产出的局部计划，用**受限 ReAct** 方式去补查新增证据。

### 是否调用 LLM

是。

### 输入

- Draft Analysis
- `GapPlan`
- `out_dir`

### 输出

- `SupplementalResult`

结构包括：

- `supplemental_evidence`
- `gap_updates`
- `candidate_family`
- `supplemental_summary`

### React 的职责边界

React 在这里的职责是：

- 补新增证据
- 补行为/TTP 线索
- 补二跳 IOC
- 补第二来源支撑

React 不负责：

- 重做 baseline
- 直接写最终报告
- 自由决定系统最终结论

### React 可调用的工具

#### 探索型网页工具

- `advanced_web_search`
  - 根据 query 做高级搜索
- `technical_source_search`
  - 优先搜索 any.run、abuse.ch、Malpedia、VT 等技术来源
- `fetch_page_content`
  - 抓正文、清洗 HTML、截断文本
- `extract_claim_candidates_from_page`
  - 从正文提取家族/TTP/IOC 相关句子
- `extract_entities_from_page`
  - 从正文提取 IP、域名、URL、Hash 等
- `pivot_related_indicators`
  - 围绕已有指标继续扩线
- `malware_profile_lookup`
  - 查家族背景和 TTP 页面

#### 结构化 IOC / 基础设施工具

- `threatfox_ioc_lookup`
  - 查 IOC 到家族/标签/样本的结构化映射
- `urlhaus_ioc_lookup`
  - 查恶意 URL、host、payload 的结构化记录

### 输出约束

React 最终必须输出合法 JSON，而不是 Markdown。

如果没有查到有效新增证据，也必须：

- 返回合法 JSON
- 将 gap 状态标为 `unresolved` 或 `partially_resolved`
- 严禁编造家族、IOC、TTP

### 解析与保护

这层还配套了：

- JSON 提取器
- schema 验证器
- 超时保护
- deterministic fallback

### 相关代码

- `demo_agent/agents/react_agent.py`
- `demo_agent/schemas.py`

---

## 7. Final Analysis

### 模块职责

把补查结果重新并入分析状态，生成最终版 `analysis.json`。

### 是否调用 LLM

否。

### 输入

- `event`
- baseline 结果
- `supplemental`

### 输出

- 最终 `analysis`

### 与 Draft Analysis 的区别

Draft Analysis 的作用是：

- 汇总 baseline
- 判断 gap

Final Analysis 的作用是：

- 吃进 `supplemental`
- 更新 evidence / findings / corroboration / assessment
- 准备最终报告和拓扑输入

### Final Analysis 重点更新哪些内容

- `supplemental` 写入最终分析对象
- `evidence` 合并补查证据
- `corroboration` 感知补查是否提供支持或冲突
- `assessment.rationale` 可吸收 `supplemental_summary`
- `findings` 可增加补查带来的增量发现
- `timings` 记录整条链路的阶段耗时

### 相关代码

- `demo_agent/analysis.py`
- `demo_agent/pipeline/coordinator.py`

---

## 8. Report / Topology

这是最终展示层。

虽然报告和拓扑是两个产物，但在设计上属于同一个模块：  
**它们都只应该读取 Final Analysis。**

### 8.1 Report

#### 模块职责

从最终 `analysis` 生成面向人的中文报告。

#### 是否调用 LLM

默认否。  
可选是。

默认模式：

- 使用本地模板渲染器生成 Markdown

可选模式：

- 在 coordinator 中切到 LLM 报告模式
- 让 LLM 基于 `analysis_json` 写中文报告

#### 输入

- 最终 `analysis`

#### 输出

- `report.md`

#### 设计意图

默认模式下，报告生成不依赖 LLM 自由写事实，而是：

- 结构由代码控制
- 内容尽量从 `analysis` 显式映射

这样更稳、更可审计。

#### 相关代码

- `demo_agent/renderers/report_markdown.py`
- `demo_agent/pipeline/coordinator.py`

### 8.2 Topology

#### 模块职责

从最终 `analysis` 生成结构化图谱和 HTML 图。

#### 是否调用 LLM

否。

#### 输入

- 最终 `analysis`

#### 输出

- `topology.json`
- `topology.html`

#### 分两层

第一层：

- `build_topology_from_analysis()`
  - 把最终家族、置信度、目的地址 enrich 等信息回填到图谱对象

第二层：

- `draw_graph_pyvis()`
  - 把图谱对象渲染成 HTML

#### 相关代码

- `demo_agent/renderers/artifacts.py`
- `demo_agent/renderers/graph_drawer_pyvis.py`

---

## 9. Supporting Layers

上面的 8 个模块是主设计链路。下面这些是支撑层，不直接处于主链顺序里，但所有模块都会依赖它们。

### 9.1 配置层

- `demo_agent/config.py`

职责：

- 读取 `.env`
- 统一构造 `AgentConfig` / `DatabaseConfig`

### 9.2 客户端层

- `demo_agent/clients/local_intel.py`
- `demo_agent/clients/vt_client.py`
- `demo_agent/clients/abuse_ch.py`
- `demo_agent/clients/llm.py`

职责：

- 封装 MySQL、VT、ThreatFox、URLhaus、LLM 的底层访问

### 9.3 工具层

- `demo_agent/tooling/common.py`
- `demo_agent/tooling/baseline.py`
- `demo_agent/tooling/exploration.py`
- `demo_agent/tooling/__init__.py`

职责：

- 对客户端做 Tool 包装
- 统一缓存、搜索、页面抓取、实体提取、结构化 IOC 查询

### 9.4 存储层

- `demo_agent/storage/io.py`

职责：

- 负责 JSON / 文本读写

### 9.5 结构化协议层

- `demo_agent/schemas.py`

职责：

- 用 Pydantic 约束 Gap Planner 和 React Gap Fill 的输入输出协议

---

## 10. 一句话理解整套设计

如果只用一句话概括这个项目的设计：

**Trace-Agent 用纯代码完成首轮稳定调查，用 LLM 只处理局部缺口，再把所有结果统一收敛到 `analysis.json`，最后由 `analysis.json` 生成报告和拓扑。**

如果只用两句话概括：

- 基线调查是确定性工作流。  
- Gap 补查是受约束的 Agent 化探索。  

这就是这套系统最核心的设计思想。
