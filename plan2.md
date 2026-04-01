# Trace-Agent V2 最终稿

## 一、总体判断

基于根目录下 `plan.md` 的最终设计版，并结合当前代码与样例运行情况，Trace-Agent 的下一阶段应采用：

**类型化基线流水线 + 受约束 Gap Planner + 只做深度探索的 React Investigator + analysis 单一事实源**

这是当前最适合“命中后告警自动研判”场景的结构，原因如下：

1. **稳定**
   - 类型路由、首轮富化、基础证据采集由代码完成，避免主链过度依赖 LLM。

2. **可复现**
   - 同一类指标每次都会走相同的 baseline path，便于调试、评测和回归。

3. **可审计**
   - 所有输出最终都收敛到 `analysis.json`，报告和拓扑只读最终版 analysis。

4. **可扩展**
   - 可以按指标类型持续扩展 investigator，也可以独立增强 gap 补查能力。

5. **让 React 真正有增量价值**
   - React 不再重跑首轮流水线，而是专注于“读正文、提细节、补缺口”。

---

## 二、V2 核心原则

### 原则 1：彻底分离“确定性动作”和“探索性动作”

确定性动作：
- 命中 IP 查本地库
- 命中 IOC 查 VT
- 命中 JA3/JA4/SSL 指纹查本地映射
- 按固定模板做首轮公开情报召回

这些动作必须由代码自动完成，不交给 LLM。

探索性动作：
- 阅读高质量情报文章正文
- 提取家族别名、TTP、二跳 IOC
- 判断多个证据之间的冲突与补充价值

这些动作才是 LLM/React 发挥价值的地方。

### 原则 2：拒绝“全局大脑”

LLM 不应作为全局 Planner 主导整个主链。

V2 中，LLM 的角色是：
- **Gap Planner**
- **Gap Investigator（React）**
- **Report Synthesizer**

而不是：
- 全流程总控
- 基线调查决策者
- 无约束自由探索 agent

### 原则 3：工具分层与查询策略分层必须同时成立

仅仅把工具分成 baseline 和 exploration 还不够。

必须同时区分：
- baseline tools
- exploration tools
- baseline queries
- exploration queries

否则即便工具名不同，也可能只是“换个方式重复首轮查询”。

### 原则 4：analysis 必须继续作为单一事实源

无论 V2 如何重构，以下原则不变：
- `report.md` 只从最终版 `analysis.json` 生成
- `topology.json/html` 只从最终版 `analysis.json` 生成
- 工具原始输出不应直接驱动对外报告

---

## 三、V2 核心架构

采用如下八阶段分层闭环：

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

### 1. Alert Ingest

职责：
- 接收命中后告警
- 标准化生成 `event.json`
- 保留原始输入、时间、源/目的、协议、指标类型和值

输出：
- `event.json`

### 2. Type Router

职责：
- 根据 `trigger_fingerprint.type` 做纯代码路由

默认支持：
- `IP`
- `JA3`
- `JA4`
- `SSL_SHA1`
- `DOMAIN`
- `URL`

约束：
- 不引入 LLM
- 路由规则必须稳定可测

### 3. Baseline Investigators

职责：
- 完成首轮确定性调查
- 自动并发收集基础证据
- 为不同类型指标执行不同的调查目标与工具组合

要求：
- 断开 LLM 后，这一层仍然能产出有价值的 `draft analysis`

### 4. Draft Analysis

职责：
- 汇总 baseline evidence
- 形成第一版 `analysis`
- 识别 gaps
- 计算初版 assessment、corroboration、confidence

输出：
- `analysis.json`（draft）

### 5. Gap Planner

职责：
- 仅围绕 gaps 生成局部补查计划
- 输出必须为结构化 JSON

示例：

```json
[
  {
    "gap_type": "vt_only_context",
    "goal": "family_attribution",
    "actions": [
      {"tool": "advanced_web_search", "query": "194.226.121.108 malware family"},
      {"tool": "fetch_page_content", "url_slot": "top_search_result"}
    ]
  }
]
```

约束：
- 不做全局规划
- 不改写最终结论
- 不允许发散式自由探索

### 6. Gap Investigators (React)

职责：
- 严格执行 Gap Planner 的动作
- 只使用 exploration tools
- 只产出补充证据，不重做基线归因

输出：
- `supplemental_evidence`
- `gap_updates`
- `candidate_family`
- `supplemental_summary`

硬约束：
- 如果补查一轮后仍未拿到有效新增证据，必须返回 `unresolved`
- 不允许为了“完成任务”而臆造家族、IOC、TTP 或攻击意图
- React 的 system prompt 与输出解析协议必须明确：
  - “证据不足时返回未解决状态”
  - “绝不编造”

### 7. Final Analysis

职责：
- 合并 baseline evidence 与 supplemental evidence
- 更新：
  - `assessment`
  - `findings`
  - `corroboration`
  - `gaps`
  - `confidence`
- 生成最终版 `analysis.json`

### 8. Output Layer

职责：
- 从最终版 `analysis.json` 生成：
  - `report.md`
  - `topology.json`
  - `topology.html`

约束：
- 不再直接读取零散工具结果

---

## 四、工具分层设计

## A. Baseline Tools

分配给：
- baseline investigators

特点：
- 输入明确
- 输出结构化
- 可并发
- 调用稳定

建议包含：

1. `local_intel_lookup`
   - 查询本地 MySQL `threat_intel.intel`

2. `vt_enrich_ioc`
   - 统一 IOC 富化接口
   - 未来应覆盖：
     - IP
     - Domain
     - URL
     - Hash

3. `abuse_ch_lookup`
   - 整合：
     - ThreatFox
     - URLhaus
     - SSLBL
     - MalwareBazaar

4. `standard_web_search`
   - 固定模板查询
   - 仅做首轮公开情报召回
   - 不读取页面正文

5. `family_intel_lookup`
   - 输入家族名
   - 输出基础家族画像与高质量参考页

## B. Exploration Tools

分配给：
- Gap Investigator（React）

特点：
- 输出通常是非结构化文本
- 依赖 LLM 阅读理解能力
- 用于补深度，而不是补基础覆盖

建议包含：

1. `advanced_web_search(query, constraint)`
   - 支持定向搜索
   - 例如：
     - `site:malpedia.caad.fkie.fraunhofer.de`
     - `site:abuse.ch`
     - `site:any.run`
     - `site:microsoft.com`

2. `fetch_page_content(url)`
   - 读取页面正文
   - 去 HTML
   - 返回可分析纯文本
   - 必须内建正文清洗与长度控制：
     - 去除 HTML / JS / CSS 噪音
     - 提取正文主内容
     - 对输出做最大长度截断，避免长文直接塞满 LLM 上下文窗口
   - 默认建议正文限制在约 `4000-8000` 字符
   - 必须支持失败降级：
     - 合理超时
     - 抓取失败返回结构化错误
     - 必要时伪装 `User-Agent`
   - 需要预期安全博客和情报站点常见的反爬 / Cloudflare 场景

3. `extract_entities_from_page(content)`
   - 从正文提取：
     - 家族别名
     - 关联 IOC
     - TTP
     - 攻击目标
     - 投递方式

4. `pivot_related_indicators(indicator_or_family)`
   - 围绕已有 IOC/家族做二跳扩展

5. `malware_profile_lookup(family)`
   - 深查家族画像与背景资料

## C. React 禁止继承的工具

默认禁止 React 直接使用：
- `local_intel_lookup`
- `vt_enrich_ioc`
- baseline 同模板 `standard_web_search`

原因：
- 这些都是 baseline 已完成动作
- 继续复用只会导致重复输出

如果后续确实需要 React 查询二跳 VT 关系，应单独新增关系型工具，而不是复用 baseline enrich。

---

## 五、按指标类型的 Baseline Path

### 1. IP Investigator

首轮目标：
- 信誉判断
- 基础归属
- 是否存在家族线索
- 是否存在远端上下文

工具组合：
- `local_intel_lookup(IP)`
- `vt_enrich_ioc(IP)`
- `abuse_ch_lookup(IP)`
- `standard_web_search(IP + malware/C2)`

### 2. JA3 Investigator

首轮目标：
- 本地指纹映射
- 家族归因
- 公开情报映射

工具组合：
- `local_intel_lookup(JA3)`
- `standard_web_search(JA3 + family)`
- `family_intel_lookup(family)`
- `abuse_ch_lookup(JA3)`

### 3. JA4 Investigator

首轮目标：
- 命中本地 JA4DB
- 区分“恶意工具标签”和“普通应用标签”
- 获取公开映射页与家族背景

工具组合：
- `local_intel_lookup(JA4)`
- `standard_web_search(JA4 + family)`
- `family_intel_lookup(family)`

建议新增字段：
- `classification`
  - `malware`
  - `tooling`
  - `benign_app`
  - `unknown`

### 4. SSL_SHA1 Investigator

首轮目标：
- 命中本地 SSLBL/证书映射
- 获取家族背景和研究页

工具组合：
- `local_intel_lookup(SSL_SHA1)`
- `abuse_ch_lookup(SSL_SHA1)`
- `standard_web_search(SSL_SHA1 + family)`
- `family_intel_lookup(family)`

### 5. DOMAIN / URL Investigator

首轮目标：
- 判断信誉
- 判断投递/钓鱼/下载行为
- 获取样本或家族上下文

工具组合：
- `local_intel_lookup(DOMAIN/URL)`
- `vt_enrich_ioc(DOMAIN/URL)`
- `abuse_ch_lookup(DOMAIN/URL)`
- `standard_web_search(DOMAIN/URL + malware/phishing)`

---

## 六、Gap Taxonomy 与触发策略

V2 固定使用以下 gap taxonomy：

### 强触发补查

这些 gap 默认进入 Gap Planner：

1. `no_secondary_confirmation`
   - 本地有命中，但缺第二权威来源支撑

2. `conflicting_attribution`
   - 本地与外部线索发生家族冲突

3. `vt_only_context`
   - 只有信誉，没有家族或行为归因

4. `single_source_attribution`
   - 家族判断只有一个有效来源支撑

5. `behavior_context_missing`
   - 已知家族，但缺 TTP/攻击意图/用途描述

### 弱提示，不默认触发补查

6. `missing_local_match`
   - 本地库无直接命中

7. `destination_context_missing`
   - 目标实体缺上下文

说明：
- 不是所有 gap 都值得立即触发 React
- 补查算力应留给高价值缺口
- 即使进入补查，最终 `gap_updates` 也允许返回：
  - `resolved`
  - `partially_resolved`
  - `unresolved`
- `unresolved` 是合法结果，不应被视为异常，而应被视为诚实保留不确定性

---

## 七、analysis 结构要求

V2 中 `analysis.json` 继续作为单一事实源，结构建议如下：

```json
{
  "facts": {},
  "local_intel": {},
  "external_intel": {},
  "evidence": [],
  "findings": [],
  "corroboration": {},
  "gaps": [],
  "supplemental": {},
  "assessment": {},
  "report": {}
}
```

要求：
- `local_intel` 与 `external_intel` 分开
- `supplemental` 单独记录 React 补查结果
- `report` 只是最终表达，不参与调查决策
- `topology` 与 `report` 只读最终版 `analysis`
- 关键中间对象必须有明确 schema，避免 JSON 漂移导致流水线崩溃

强类型约束建议覆盖：
- Gap Planner 输出的补查计划
- React 输出的 `supplemental_evidence`
- React 输出的 `gap_updates`
- Final Analysis 中的 `assessment`
- Final Analysis 中的 `evidence`
- Final Analysis 中的 `findings`

工程实现建议：
- 优先使用 `Pydantic`
- 或在 LangChain 中使用 `with_structured_output`
- 目标不是“更优雅”，而是避免某一步 JSON 失真后把整条链带崩

---

## 八、报告层设计

继续保持“内部版 / 对外版”双视图。

### 内部版

保留：
- `gaps`
- `corroboration`
- `supplemental`
- 证据冲突
- 补查状态

### 对外版

仅展示：
- 事件概述
- 研判结论
- 关键证据与情报
- 家族/威胁背景
- 处置建议
- 参考链接

原则：
- 不直接暴露内部字段名
- 不默认展示“剩余缺口”
- 不展示调试信息

---

## 九、落地路线图

### Phase 1：工具分层打底

目标：
- 真正拆开 baseline tools 与 exploration tools

重点：
- 保留现有 `analysis` 中枢
- 新增：
  - `fetch_page_content`
  - `advanced_web_search`
  - `malware_profile_lookup`
- 同时补上 `fetch_page_content` 的正文清洗、长度截断、超时与失败降级策略

### Phase 2：类型化 baseline investigator

目标：
- 拆掉当前单一 `plan_agent.py`

建议拆分为：
- `router.py`
- `baseline_investigators/ip.py`
- `baseline_investigators/ja3.py`
- `baseline_investigators/ja4.py`
- `baseline_investigators/ssl_sha1.py`
- `baseline_investigators/domain_url.py`

### Phase 3：Gap Planner + React 补查

目标：
- 让第二轮真的有新增价值

重点：
- Gap Planner 输出受约束 JSON
- React 只执行 exploration actions
- 使用 `react_gap_probe` 作为固定回归样例
- React 必须支持返回 `unresolved`
- Gap Planner 与 React 输出都要迁移到强类型 schema 约束

### Phase 4：报告与质量提升

目标：
- 让对外报告更像成品

重点：
- 继续优化中文摘要
- 过滤低质量来源
- 减少重复证据展示
- 为不同类型生成更合适的报告风格

---

## 十、最终结论

Trace-Agent V2 不应该走向：
- 继续扩张当前单一硬编码 workflow
- 或把全流程交给一个自由规划式 LLM Agent

Trace-Agent V2 的最终方向应当是：

**类型化 baseline 流水线 + 受约束 Gap Planner + 只做深度探索的 React Investigator + analysis 单一事实源**

这是在当前场景下兼顾：
- 稳定性
- 可复现性
- 可审计性
- 扩展性
- LLM 增量价值

的最合理设计。
