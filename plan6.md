# Plan 6: Baseline 网页正文 Enrichment

## 当前在解决什么问题

当前主线的 report 已经比以前更像一份报警研判报告了，但我们现在碰到的新瓶颈已经不是“会不会写报告”，而是：

> **很多正文证据本身只有搜索摘要（snippet），没有真正读过链接里的正文内容。**

这会导致报告里经常出现下面这种不够满意的表达：

- “某页面提到了传播方式和影响”
- “某研究页概述了某家族的行为”
- “该页面将样本归入某家族”

这些句子方向没错，但信息密度不够。它们更像“搜索结果的改写”，不像“读过网页正文后做出的内容提炼”。

换句话说，当前问题已经从：

- “report 不会写”

转成了：

- “report 想写深一点，但上游 evidence 还停留在 snippet 层”

这也是为什么我们现在最应该优化 baseline，而不是继续只改 renderer 文案。

---

## 根因判断

当前 baseline 的主流程大致是：

`baseline investigator -> 标准搜索/API 查询 -> merge -> build_analysis -> report`

在这条链里：

- `SerpAPI / DDGS / HTML fallback` 返回的核心字段是：
  - `title`
  - `url`
  - `snippet`
- baseline 把这些结果直接收进 observation
- `build_analysis(...)` 再把它们写成 `analysis.evidence`
- 其中很多 evidence 的 `claim` 实际就是：
  - `snippet`
  - 或 `title`

所以当前 `analysis.evidence` 中大量外部网页证据，本质上还是：

> **搜索结果摘要**

而不是：

> **页面正文提炼后的具体事实**

这解释了几个现象：

1. report 虽然已经不再是“只有链接”，但很多段落依然偏泛
2. 微软 / Malpedia / Check Point 这些高价值页面没有被充分消化
3. report 经常只能写“页面提到某家族”，而写不出：
   - 具体传播方式
   - 具体功能/影响
   - 明确 TTP / IOC / 基础设施线索

---

## 为什么不把这一步交给 React

当前主线里，React 的主要定位是：

- gap fill
- 补查
- 缺口场景扩线

但我们已经确认，当前大多数强命中 case 根本不会进入 React。

因此，如果把“读正文”这件事放到 React：

- 主线绝大多数 case 依然只能吃 snippet
- `analysis` 本身仍然是薄的
- report、gap 判断、处置建议都吃不到这层提升

所以这件事应该放在：

> **React 之前**

更准确地说，是在：

`baseline -> draft analysis -> page enrichment -> rebuilt analysis -> gap planner/react`

这条链里。

---

## 与现有 snippet-LMM 优化的关系

Plan 6 还有一个需要明确收口的点：

> **既然我们准备对高优页面做正文 deep-read，就不应该再把“对搜索 snippet 做 LLM 润色”当成主方案。**

之前在 renderer 里加入的那层轻量 LLM 证据摘要，本质上是在补一个上游不足：

- 上游 evidence 只有 `title + snippet + url`
- renderer 只能拿这些信息去尽量写得更自然

这条路线在当时是合理的，因为它确实能让 report 从“空话 + 链接”提升到“稍有内容的段落”。

但在 Plan 6 的目标下，它的定位必须调整：

### 新的优先级

1. **正文 deep-read 后的 claim**
2. **结构化情报自带的具体说明**
3. **原始 snippet**
4. **基于 snippet 的 LLM 润色**

也就是说：

- 如果某条 evidence 已经有正文 claim，就不再对原始 snippet 做额外 LLM 优化
- renderer 优先使用 deep-read 后的 claim 直接生成段落
- 之前那种“只基于 snippet 让 LLM 写两句”的路径，只作为：
  - enrichment 失败时的保底
  - 或没有可抓正文的结构化来源的轻量补充

### 这意味着什么

Plan 6 不是简单“新增一个 enrichment 模块”，还意味着要把现有的摘要策略收口成：

- **正文 claim 驱动**
- 而不是 **snippet 润色驱动**

如果不收这一步，后面即使抓到了正文，report 也仍然可能错误地优先使用老的 snippet 优化路径，导致正文 deep-read 的价值被稀释。

所以 Plan 6 的一个显式约束是：

> **已有正文 claim 的 evidence，不再走 snippet 级 LLM 摘要主路径；旧的 snippet 优化逻辑降级为 fallback。**

---

## Plan 6 的目标

Plan 6 的目标非常聚焦：

1. 让 baseline 生成的不再只是搜索摘要级 evidence
2. 让高优网页来源进入 `analysis` 前，先做一次正文 deep-read
3. 让 report 的正文证据从“snippet 改写”升级成“正文提炼”
4. 保持当前主线稳定，不把 baseline 变成一个失控的小 React

这不是一次大架构重写，而是一次：

> **在主链里补上一层“高价值页面正文提炼”能力**

---

## 设计原则

### 1. enrichment 是 baseline 的一部分，不是 renderer 的一部分

renderer 负责展示，不负责调查。

所以：

- 不在 `report_markdown.py` 里现场抓网页
- 不把正文提取逻辑塞进渲染层

正文 deep-read 必须发生在 analysis 收敛之前。

### 2. enrichment 是受控、少量、可降级的

这一步不是把所有搜索结果都抓一遍。

必须满足：

- 只抓少量高价值页面
- 有总时间预算
- 任意一步失败都能回退到原 snippet
- 失败不影响主链继续跑

### 3. enrichment 的产物应该写回 analysis 输入层

这一步的价值不只是为了 report。

如果正文 deep-read 成功，它应该同时改善：

- `analysis.evidence`
- `assessment` 的支撑质量
- 后续 `gap_fill_needed` 的判断
- report 的正文证据摘要
- threat-hunt 建议

所以 enrichment 结果不能只在 renderer 临时存在。

### 4. 第一版优先 deterministic，不先引入新的 heavy LLM 依赖

Plan 6 第一版优先复用已有能力：

- `fetch_page(...)`
- `extract_claim_candidates_from_page(...)`

先做：

- 网页抓取
- 句子级 claim 提取
- 高信息量 claim 选择

如果第一版之后仍然觉得正文段落太碎，再考虑加一个很轻量的 LLM claim synthesizer。

---

## 新增模块与插入位置

### 新增模块

建议新增：

- `demo_agent/query/baseline/page_enrichment.py`

它的职责是：

> 对 draft analysis 中最值得进入正文的少量网页证据做正文抓取和 claim 提取。

### 插入位置

建议在主链中新增一个阶段：

1. baseline investigator
2. `build_analysis(...)` 生成 draft analysis
3. `page_enrichment.enrich_baseline_pages(...)`
4. 使用 enrichment 结果重新执行 `build_analysis(...)`
5. 再进入 gap planner / React / final report

这样做的好处是：

- 先利用现有 analysis 排序能力选“该读谁”
- 再做 deep-read
- 不需要在 baseline 阶段盲抓所有结果

---

## enrichment 的输入与输出

### 输入

输入建议包括：

- `event`
- baseline observations：
  - `local_obs`
  - `obs_fp`
  - `obs_context`
  - `obs_family`
- `draft_analysis`

其中 `draft_analysis` 的作用很重要：

- 它告诉 enrichment 当前哪些 evidence 权重高
- 哪些条目已经足够进入正文
- 哪些只是低质量背景页

### 输出

建议输出一个结构化 enrichment 结果，例如：

```json
{
  "items": [
    {
      "url": "...",
      "source": "...",
      "page_title": "...",
      "page_fetch_ok": true,
      "page_type": "research_page",
      "summary_hint": "...",
      "claims": [
        {"text": "...", "kind": "capability"},
        {"text": "...", "kind": "delivery"},
        {"text": "...", "kind": "ttp"}
      ],
      "entities": {
        "ips": [],
        "domains": [],
        "hashes": []
      }
    }
  ],
  "timings": {...}
}
```

第一版不要求这个结构非常复杂，但至少要能区分：

- 页面抓取是否成功
- 提取到了哪些具体 claim
- 这些 claim 可以如何回写 evidence

---

## 如何选要抓的页面

这一步必须严格控量。

建议规则如下：

### 1. 候选来源

从 draft analysis 的高优 evidence 中选，不直接从所有原始 observation 里盲抓。

优先考虑：

- `search_result`
- `family_intel`
- 高质量结构化情报页

### 2. 数量限制

第一版建议：

- `event/context` 类最多抓 `Top 2`
- `family/background` 类最多抓 `Top 1-2`
- 总量控制在 `Top 3-4`

### 3. 站点优先级

优先：

- `microsoft.com`
- `malpedia.caad.fkie.fraunhofer.de`
- `checkpoint.com`
- `trendmicro.com`
- `proofpoint.com`
- `abuse.ch`

限制或跳过：

- 索引页
- 黑名单下载页
- 搜索聚合页
- 噪声域名

### 4. 域名去重

默认同域名只抓一条。

对于高价值白名单域名，可放宽到两条，但必须保证它们承载的是不同信息，而不是同类重复文章。

---

## enrichment 如何执行

建议的执行步骤如下：

1. 根据 draft analysis 选出候选 evidence
2. 对每个 evidence 的 `url` 调用 `fetch_page(...)`
3. 如果抓取成功：
   - 获取正文文本
   - 调用 `extract_claim_candidates_from_page(...)`
4. 从 claims 中筛选更高价值的内容：
   - 传播方式
   - 功能/影响
   - 受害对象
   - TTP
   - IOC / 基础设施
5. 把这些结果写成 enrichment item

这一步尽量复用已有工具，不重新写第二套抓取器。

---

## 如何回写到 analysis

Plan 6 的关键不只是“抓到了正文”，而是：

> **怎样把正文内容真正替换掉 snippet 级 evidence。**

建议在 `build_analysis(...)` 中新增一层优先级：

对于某条网页 evidence：

1. 如果存在 `page_enrichment.claims`
   - 优先使用正文提炼后的 claim 作为 evidence `claim`
2. 否则如果存在 `summary_hint`
   - 使用 enrichment 提供的 summary
3. 再否则
   - 回退到原始 `snippet`

也就是说：

`正文 claim > enrichment summary > 原始 snippet`

这样后面 renderer 就不需要自己再猜“是不是要深读网页”，而是直接使用更高质量的 evidence。

---

## 性能与稳定性要求

Plan 6 不允许把主链拖死。

必须加入以下控制：

### 时间预算

- 单页抓取 timeout：`10-15s`
- enrichment 总预算：`20-30s`

### 数量预算

- 最多 `3-4` 个页面

### 错误处理

- 任一页面失败 -> 跳过
- claim 提取失败 -> 回退原 snippet
- enrichment 总超时 -> 整体跳过

### 缓存

正文抓取和 claim 提取结果应缓存，避免重复抓同一页面。

---

## 与现有 React 的关系

Plan 6 并不是削弱 React，而是重新明确分工：

- baseline enrichment：
  - 负责“把主链 Top 证据读深”
- React：
  - 负责“主链还没解决的问题和缺口补查”

也就是说，Plan 6 做完后，React 应该更聚焦于：

- 二跳扩线
- 行为补查
- 特殊 gap
- 目的地址上下文补充

而不是再承担“主链里本来就该读的正文页面”。

---

## 预期收益

如果 Plan 6 做成，最直接的变化应该是：

### analysis 层

- `analysis.evidence.claim` 不再大面积停留在 snippet
- 高优 evidence 会携带更具体的正文事实

### report 层

证据段落会从这种：

- “微软页面概述了传播方式和影响”

提升成这种：

- “微软页面将 QuasarRAT 描述为可由攻击者远程控制受害主机的后门，并指出其能够执行命令、操作文件及实施进一步恶意动作，这为当前证书指纹与家族归因之间的关系提供了更具体的行为背景。”

### 主链整体

- React 触发前的 baseline 就更有解释力
- report 不再主要依赖 snippet 改写
- 事件直接证据和家族背景证据的差异会更清晰

---

## 不在 Plan 6 范围内的内容

为了收住边界，以下内容暂不纳入本次：

1. 不重写 baseline 查询模板生成逻辑
2. 不把 enrichment 做成自由 agent loop
3. 不在第一版引入 heavy LLM 页面总结器
4. 不改 React 主架构
5. 不重做 report 总体章节结构

Plan 6 只聚焦于一件事：

> **让 baseline 生成的高优网页证据，从 snippet 级升级到正文 claim 级。**

---

## 验收标准

Plan 6 完成后，至少应满足：

1. `demo_alert` 能完整跑通，主链不被改坏
2. `analysis.json` 中高优网页 evidence 的 `claim` 明显不再只是搜索 snippet
3. `report.md` 中至少在代表性 case（如 `004`、`005`）里，能看到：
   - 传播方式
   - 功能/影响
   - TTP / IOC / 基础设施
   这类更具体的正文内容
4. enrichment 失败时系统能平稳回退，不影响现有主链产物生成
5. 总时延增长控制在可接受范围内，不出现主链明显卡死

---

## 一句话总结

Plan 6 要解决的核心不是“report 还不够会写”，而是：

> **baseline 现在写进 `analysis` 的很多网页证据还只是 snippet。**

所以我们下一步要做的，是在 React 之前补一层受控的正文 deep-read enrichment，让主链自己的高优证据先读深，再去谈更好的分析摘要和更像样的报警报告。
