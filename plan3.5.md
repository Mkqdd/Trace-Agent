# Trace-Agent 下一阶段优化计划（Plan 3.5）

## 一、当前位置判断

截至当前版本，Trace-Agent 已经从 **V2 alpha / 强原型** 进入 **V2 beta 候选阶段**。

当前已经成立的能力包括：

- `plan` 主链稳定，且已正式收敛为唯一产品路径
- `IP / JA3 / JA4 / SSL_SHA1 / DOMAIN / URL` 都具备 baseline 处理能力
- `analysis.json` 作为单一事实源已经站稳
- `gap planner + 受限 React + deterministic fallback` 这条补查链已经能触发、能安全结束、也能补回部分新增证据
- ThreatFox / URLhaus 已接入主链，不再只是网页搜索兜底
- 当前功能 smoke 在主链口径下为 `4/4` 通过

这意味着：

> 架构层面的大方向已经基本确定，下一阶段不应再重做主架构，而应聚焦于“归因融合、补查质量、拓扑扩线、性能治理、报告成品化”。

---

## 二、为什么需要 Plan 3.5

Plan 3 主要解决的是：

- 补查结果能否进入最终报告
- 是否删除纯 `react` 路径
- 是否把报告从“能生成”提升到“能看”

这些目标现在基本都已经落地了。

但随着 ThreatFox / URLhaus 等结构化数据源接入，系统开始暴露出更深一层的问题：

1. **结构化情报已接入，但没有完全制度化地影响最终结论**
   - ThreatFox / URLhaus 已进入 baseline 与 gap fill
   - 但它们对 `family / confidence / severity / rationale` 的提升仍偏保守
   - 一旦与本地库冲突，还缺少明确的仲裁矩阵

2. **补查质量仍不稳定**
   - `gap_fill` 已经能补到东西，但很多时候补回的是“辅助线索”，不是稳定归因证据
   - 当前的页面 claim 提取上限仍受到关键词 / 正则方案限制

3. **拓扑图仍然偏静态**
   - `topology` 仍主要反映原始告警和一跳证据
   - 补查得到的二跳 IOC、关联域名、恶意 URL 等没有稳定进入图谱

4. **时延明显上升**
   - 最新 `batch_plan_full` 已达到 70s+，已经开始影响可用性
   - 结构化 API 接入提高了能力上限，也带来了明显性能压力

5. **报告“像样了”，但还不够“专业”**
   - 已经具备结构和层次
   - 但归因理由仍偏模板化
   - 某些 case 中高价值证据与背景证据的界线仍不够锐利

所以 Plan 3.5 的核心目标是：

> 在不改变主架构的前提下，把 Trace-Agent 从“稳定可跑”推进到“稳定、可信、可扩线、可展示、响应更合理”的 beta 版本。

---

## 三、Plan 3.5 核心原则

### 原则 1：不再继续扩主架构

以下主结构保持不变：

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

Plan 3.5 不再讨论是否要新增 agent 主模式，也不再恢复纯 `react`。

### 原则 2：优先提升“增量价值”，而不是盲目加工具

ThreatFox / URLhaus 已经证明：  
新工具不是接进来就自动变强，关键在于：

- 结果能否影响 `analysis.assessment`
- 结果能否被 `report` 和 `topology` 正确消费
- 结果是否值得为此付出额外时延

因此 Plan 3.5 的重点不是“再接很多 API”，而是：

- 让已有工具产生更高质量的增量
- 让高质量增量稳定体现在最终输出中

### 原则 3：归因必须有明确的冲突仲裁矩阵

从 Plan 3.5 开始，不能再停留在“谁看起来更像谁”的经验融合，而要明确：

- 本地私有情报 > 结构化外部情报 > 泛网页搜索
- ThreatFox / URLhaus 可以增强结论，但不能静默覆盖本地高置信命中
- 当本地与外部出现强冲突时，必须显式记录为 `conflict`，并提升人工复核优先级

### 原则 4：补查阶段升级为“预过滤 + 轻量 LLM 语义抽取”

当前基于关键词 / 正则的 claim 抽取已经起到过渡作用，但它的上限已经很明显：

- 面对长篇技术分析正文，容易漏掉高价值句子
- 对隐含家族归因、行为描述、IOC 关系的把握能力不足
- 难以稳定提炼“可直接上卷到报告”的强 claim

Plan 3.5 采取折中而务实的方案：

- 保留代码级预过滤，避免把整篇长文无控制地丢给 LLM
- 在预过滤后新增一次低成本、强 schema 约束的 LLM 语义抽取
- 让模型输出结构化 `family / ttp_summary / iocs / supporting_claims`

### 原则 5：Topology 不是附属产物，而是调查结果的另一种主视图

Plan 3.5 进一步明确：

- `topology` 不能只画原始告警
- 它必须随调查结果一起生长
- 补查得到的关联域名、二跳 IP、恶意 URL、payload/hash 等扩线实体，应该作为 `expanded_iocs` 进入图谱

### 原则 6：性能问题正式成为一等公民

到 Plan 3 为止，性能还是副问题；  
到 Plan 3.5，性能已经必须进入主优化清单。

以后每个新增情报源都要回答两个问题：

1. 它能否实质提高归因质量？
2. 它是否值得增加这部分时延？

### 原则 7：结构化情报优先于泛搜索结果

当前已经接入：

- 本地 MySQL
- VirusTotal
- ThreatFox
- URLhaus
- SerpAPI / Web Search

Plan 3.5 明确约束：

- 能用结构化数据解决的，不优先丢给网页搜索
- 能直接映射 family / IOC / host / payload 的结构化结果，优先进入关键证据
- 泛搜索结果更多承担背景补充，而不是替代结构化情报

### 原则 8：报告继续走“半结构化渲染”

Plan 3 的“半结构化渲染”方向保留，并进一步收紧：

- 结论、证据、建议由模板稳定渲染
- 如需 LLM，仅允许生成极短摘要
- 不允许 LLM 从零写整篇报告

---

## 四、Plan 3.5 的 4 个 Blocking Issues

## 1. 建立明确的多源情报冲突仲裁矩阵

### 当前问题

ThreatFox / URLhaus 已经能查到结构化结果，例如：

- IOC -> family
- host -> malicious URLs / tags / threat
- URL -> threat / status

但系统还没有明确回答：

- 如果本地库命中 `Family A`，ThreatFox 返回 `Family B`，谁是主结论？
- 哪些来源只算 supporting，哪些来源可以直接上卷到 `assessment`？
- 冲突发生时，如何提升人工复核优先级？

### 目标

建立明确、可审计的 tie-breaker matrix。

### 具体动作

- 在 `analysis.py` 中正式引入 attribution tie-breaker matrix：
  - `local_intel` 高置信命中：Primary
  - ThreatFox 结构化 family：Supporting / Suspected Alias / Conflict
  - URLhaus：Infra Signal，不直接等同于 family
  - 泛网页搜索：Background 或 Supporting
- 当本地命中与 ThreatFox / 外部 family 冲突时：
  - 默认保留本地家族为 Primary
  - 外部家族进入 `conflicts[]` 或 `corroboration.conflicting_candidates`
  - `severity` 或复核优先级上调
  - 报告中明确写出“存在归因冲突，建议人工复核”
- ThreatFox 只有在“本地未命中或本地命中置信不足”时，才允许直接提升 `assessment.family`
- URLhaus 只提升：
  - `verdict`
  - `confidence`
  - `expanded_iocs`
  - `recommended_actions`
- 在 `corroboration` 中新增：
  - `primary_source`
  - `supporting_sources`
  - `conflicting_sources`

### 验收标准

- 冲突 case 不再“静默覆盖”
- ThreatFox 命中的 IOC case 能稳定把家族提升到 `assessment.family`，但不会无声压过本地高置信结论
- URLhaus 命中的 case 即便不归因，也应显著提升 verdict/infra 判断

---

## 2. 将补查提取升级为“轻量 LLM 语义抽取链”

### 当前问题

当前 `extract_claim_candidates_from_page` 主要还是依赖：

- 关键字
- 正则
- 句子切分

这在“短页面 / 简单 IOC 页面”上还能工作，但面对长篇分析报告时：

- 漏掉高价值家族归因句
- 漏掉隐含的 TTP 描述
- 容易抽到断章取义的低价值句子

### 目标

把补查提取从“脆弱的关键字抓句子”提升到“受强 schema 约束的轻量 LLM 语义抽取”。

### 具体动作

- 保留当前代码级预过滤：
  - 去 HTML
  - 截断正文
  - 提取候选句子 / 实体 hint
- 在其后新增一个轻量 LLM extraction step，例如：
  - `ThreatIntelExtraction`
  - `family_name`
  - `ttp_summary`
  - `supporting_claims[]`
  - `iocs[]`
  - `confidence_note`
- 用强 schema / Pydantic 约束输出，避免自由生成
- 将这一步定位为：
  - 成本低于完整 gap React
  - 质量高于纯正则抽取
- 让 gap fill 最终更常补回：
  - `candidate_family`
  - `explicit TTP claim`
  - `secondary IOC / infra pivot`
- 在 supplemental result 中增加更清晰的分级：
  - `strong_supplemental`
  - `supporting_supplemental`
  - `background_supplemental`

### 验收标准

- 长页面 case 中，claim 提取质量明显提升
- `gap_probe_plan` 至少在部分 case 中能把 `family=Unknown` 拉成“倾向于某家族”
- `ip_without_vt` 这类弱证据场景能更稳定补出二跳 IOC 或 infra 线索

---

## 3. 让拓扑图随补查结果动态扩线

### 当前问题

当前 `topology.json/html` 仍然主要反映：

- 原始告警关系
- 一跳命中
- 家族节点

而补查得到的：

- 新域名
- 二跳 IP
- 恶意 URL
- 关联 payload/hash

大多还只停留在文本报告里。

### 目标

让图谱真正体现“溯源扩线”。

### 具体动作

- 在 `analysis.entities` 或 `analysis.derived` 中新增：
  - `expanded_iocs`
  - `expanded_relationships`
- 将以下来源的二跳实体纳入统一结构：
  - ThreatFox `ioc`
  - URLhaus `host/url/payload`
  - gap fill 提取出的 `ips/domains/urls/hash`
- 在 `renderers/artifacts.py` 中：
  - 为这些扩展实体创建 node
  - 以“关联 IOC / 补查发现 / 结构化情报”建立 edge
- 在 topology 中区分：
  - 原始告警实体
  - 家族归因实体
  - 扩线实体
  - 低置信背景实体

### 验收标准

- `gap fill` 得到的二跳 IOC 不再只写进 Markdown
- 拓扑图能直观看到调查过程中新增的基础设施或关联指标
- `topology` 与 `report` 对补查结果的表达保持一致

---

## 4. 做深层并发 / 异步治理，而不仅仅是条件过滤

### 当前问题

最新 smoke 中：

- `batch_plan_full` 已达到 75s+
- `gap_probe_plan` 已达到 50s+

仅靠“按条件少查一些”是不够的。  
当前真正的问题是：外部 I/O 的并发还停留在外层 investigator，客户端内部仍存在串行嵌套。

### 目标

把性能优化从“少发请求”升级为“减少串行阻塞”。

### 具体动作

- 在 `ThreatFoxClient.search_indicator` 内部把多 payload 查询并发化：
  - `exact_match=True`
  - `exact_match=False`
  - hash / IOC 分支
- 在 `URLhausClient` 内部按 endpoint 和 fallback 路径并发化，而不是纯串行
- 若继续增加结构化源，优先考虑：
  - `ThreadPoolExecutor`
  - 或下一步升级为 `asyncio + httpx`
- 继续保留外层按指标类型的条件触发，但不再把它当唯一性能手段
- 为关键阶段加耗时埋点：
  - baseline
  - structured intel
  - gap planner
  - gap fill
  - report render

### 验收标准

- `batch_plan_full` 平均时长明显回落
- 加入结构化源后，不能再无约束拖长所有 case
- 工具实现内部不再存在明显的串行嵌套热点

---

## 五、Plan 3.5 的实施顺序

### Phase 1：归因冲突仲裁矩阵

先做：

- local vs ThreatFox vs URLhaus vs web 的 source precedence
- conflict data model
- assessment / corroboration / report 的冲突表达

这是第一优先级，因为它决定系统结论是否可信。

### Phase 2：轻量 LLM 语义抽取链

先做：

- `extract_claim_candidates_from_page` 的混合改造
- 新 schema
- supplemental evidence 分级

### Phase 3：Topology 动态扩线

先做：

- `expanded_iocs`
- `expanded_relationships`
- topology renderer 增量生长逻辑

### Phase 4：深层并发治理

在前面逻辑稳定后，再压：

- 客户端内部串行 I/O
- 无效调用
- 重复调用
- 高耗时路径

### Phase 5：报告成品化收尾

最后再继续磨：

- 归因依据自然化
- 分层稳定化
- ThreatFox / URLhaus / conflict case 的专业化表达

---

## 六、Plan 3.5 暂不优先做的事

以下方向继续后置：

- 再引入新的大型外部 API（如 ANY.RUN）
- 多告警关联分析
- memory / case retrieval
- 更复杂的数据库 schema 改造
- 大规模自动化测试工程化
- 再次重构 agent 主架构

这些都应该在 Plan 3.5 收口后，再进入下一阶段。

---

## 七、Plan 3.5 的成功标准

如果以下条件基本满足，可以认为 Plan 3.5 完成：

1. 本地 / ThreatFox / URLhaus / 网页结果之间已经有明确的冲突仲裁逻辑
2. 长页面补查不再主要依赖关键字正则，而是升级为轻量 LLM 语义抽取
3. 补查得到的二跳 IOC 能进入拓扑图，而不是只写进报告
4. 主链 smoke 继续稳定通过
5. 时延相较当前版本有明显改善
6. 代表性报告达到“可展示、可解释、可复核”的水平

---

## 八、一句话总结

Plan 3 解决的是：

> “补查结果能不能进最终输出？”

Plan 3.5 要解决的是：

> “补查和结构化情报进来之后，能不能在冲突可控、抽取更聪明、拓扑会扩线、性能更合理的前提下，真正提升归因质量并产出专家级结果？”
