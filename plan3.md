# Trace-Agent 下一阶段优化计划（Plan 3）

## 一、当前位置判断

基于当前代码、目录结构以及最新一轮功能测试结果，Trace-Agent 已经从“能跑的 demo”进入了 **V2 alpha / 强原型阶段**。

它已经具备以下能力：

- `plan` 主链可以稳定处理 `IP / JA3 / JA4 / SSL_SHA1`
- baseline 调查、gap planner、gap fill、analysis 中枢、report/topology 这条链已经跑通
- 在弱证据场景下，gap fill 已经可以补回新增 evidence，而不是只会超时或空手而归
- 缺失 VT、本地 MySQL 不可用等场景下，主链具备安全降级能力

但它还没有达到“稳定可交付”的状态，当前最明显的问题是：

1. `gap fill` 补回的证据，并没有稳定地体现在最终 `report.md` 中
2. 报告质量不均衡，有的 case 已经像样，有的 case 仍然偏薄、偏保守、偏重复
3. 证据源过滤还不够严格，弱来源会混入前排
4. 本地 MySQL 情报在实际运行中的可用性和权重利用还不够稳定
5. 对外报告目前仍然偏“证据列表导出”，距离稳定成品化还有一段距离

因此，Plan 3 的核心目标不是重做架构，而是：

**在保留 Plan 2 整体结构不变的前提下，把 V2 alpha 打磨成真正稳定、可展示、可继续扩展的 V2 beta。**

---

## 二、Plan 3 核心原则

### 原则 1：不重构主架构，优先修“最后一公里”

Plan 2 的八阶段结构仍然成立：

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

Plan 3 不再大改骨架，而是优先修：

- `supplemental_evidence -> final analysis -> report`
- 报告成品化与稳定表达
- 报告可读性与证据质量

### 原则 2：继续坚持“analysis 单一事实源”

无论后续怎么优化报告或补查，以下约束不变：

- `report.md` 只能从最终版 `analysis.json` 生成
- `topology.json/html` 只能从最终版 `analysis.json` 生成
- gap fill 的原始返回值不能直接绕过 analysis 驱动对外输出

Plan 3 的重点是：**让 analysis 更完整地承接补查结果，而不是让 report 去猜。**

### 原则 3：区分“主链稳定性问题”和“报告质量问题”

后续优化时要明确区分两类问题：

- **功能问题**
  - 超时
  - 崩溃
  - gap fill 没被触发
  - evidence 没有进入 final analysis

- **质量问题**
  - report 太薄
  - family 没写明
  - 引用了弱来源
  - 语言重复、像模板

Plan 3 优先级应先解决功能问题，再处理质量问题。

### 原则 4：正式移除“纯 React”产品路径

从 Plan 3 开始，项目只保留这一条产品主链：

```text
确定性 plan 主链
-> gaps 识别
-> 受约束 React 补查
-> final analysis
-> report / topology
```

不再把“独立 react 模式”作为对外交付能力、主功能 smoke 项或长期维护目标。

理由：

- 在当前垂直场景下，自由探索式 React 的不确定性明显高于收益
- 真正有价值的 React 角色已经收敛为 `Gap Investigator`
- 删除纯 React 路径有助于收敛测试口径、减少维护负担、集中资源打磨主链

### 原则 5：报告采用“半结构化渲染”而非整篇自由生成

Plan 3 默认不追求让 LLM 每次从零写整份报告。

推荐改为：

- 事件概述、证据分层、处置建议由 Python 模板稳定渲染
- 仅“研判结论/归因理由摘要”允许由 LLM 生成一小段自然语言，且必须严格基于 `analysis`

这样可以同时获得：

- 输出稳定
- 结构可控
- 语言不至于完全生硬
- 降低“写得花但不准”的风险

---

## 三、当前最需要修复的 4 个问题

## 1. Gap Fill 结果没有稳定进入报告

### 现象

在 `gap_probe_plan` 这类 case 中：

- gap fill 已触发
- `supplemental_evidence_count > 0`
- 但最终 `report.md` 仍然很薄
- 新增证据没有被充分写进报告

### 本质问题

当前链路更像是：

```text
gap fill 有结果
-> final analysis 部分接住
-> report renderer 没有充分消费
```

也就是说，补查已经开始“查到东西”，但没有稳定完成“被最终表达出来”这一步。

### 目标

让 `supplemental_evidence` 在以下三个层面真正闭环：

1. 写进最终版 `analysis`
2. 影响 `assessment / findings / confidence / corroboration`
3. 进入 `report.md` 的“关键证据与情报”部分

### 具体动作

- 审查 `final analysis` 合并逻辑，确保 `supplemental_evidence` 不只是挂在 observations 里
- 当 `supplemental` 中存在高置信度（如 `> 70`）且带 `candidate_family` 的证据时，允许它更新保守 assessment
- 为 `supplemental_evidence` 增加“是否可进入对外报告”的明确判断
- 报告渲染时优先消费高价值 supplemental evidence，而不是只消费 baseline evidence
- 若 gap fill 已提供候选家族、二跳 IOC、TTP claim，应允许其更新报告中的结论段，而不是只保留“Unknown”
- 在报告中新增一个明确的小节：`深度关联发现（补查结果）`
- 将 `supplemental_summary` 或高价值 `claim` 上卷为报告中的可读中文结论，而不是只留在 JSON 中

### 验收标准

- `gap_probe_plan` 中若 `supplemental_evidence_count > 0`，报告中必须能看到至少 1 条补查新增证据
- 若补查提供了有效 family clue，报告必须写出“当前线索倾向于 …”而不是仍然完全空白

---

## 2. 删除独立 React 模式，彻底收敛到主链

### 决策

Plan 3 明确做出这个决定：

> 删除纯 `react` 运行路径，只保留 `plan 主链 + React gap fill`。

### 需要同步调整的地方

- CLI 默认与文档只保留 `plan` 入口
- `run_functional_smoke.py` 移除 `react_mode_smoke`
- README、测试文档、说明文档里不再把独立 `react` 作为可用模式介绍
- 相关代码若仍保留，也只能作为开发调试脚手架，而不是主功能路径

### 价值

- 降低维护面
- 收敛用户心智模型
- 避免“两个 agent 并行演进”导致设计漂移
- 让 React 的角色彻底固定为：**只对 gaps 做深度补查**

---

## 3. 报告质量需要从“可运行”提升到“可展示”

### 当前问题

报告当前已经能生成，但质量参差不齐，主要问题有：

- 语言重复，很多句式像模板复读
- `gap fill` 新增价值未被完整体现在报告中
- 家族背景和行为说明有时太少
- 一些 case 过于保守，只输出“可疑恶意流量”
- 弱来源有时会混进关键证据

### Plan 3 目标

把报告分成更稳定的三层：

1. **结论层**
   - 事件是什么
   - 当前更倾向哪个家族
   - 置信度为何是现在这个水平

2. **证据层**
   - baseline evidence
   - supplemental evidence
   - 关键证据和背景参考分开

3. **行动层**
   - 处置建议
   - IOC/TTP 扩线建议

并引入“半结构化渲染”的稳定思路：

- 模板负责结构
- 代码负责事实填充
- LLM 只负责极短的归因摘要润色（可选）

### 具体动作

- 把 `report renderer` 从“平铺 evidence”改成“按结论组织 evidence”
- 区分：
  - `关键证据`
  - `深度关联发现（补查结果）`
  - `背景参考`
  - `低权重补充`
- 增加一段简短、稳定的“为何得出当前归因”的理由摘要
- 避免把内部字段语言直接暴露给用户
- 如果 family 不确定，也应该给出“当前缺的是什么”，但措辞必须是对外友好的
- 报告模板默认由 Python/Jinja2/Markdown 模板稳定拼接
- 如启用 LLM，仅允许其生成 100 字以内的“研判结论摘要”，禁止整篇自由写作

### 验收标准

- `004 / 005 / ip_without_vt / gap_probe_plan` 这 4 条代表性报告都能达到“可给师兄看”的水平
- 报告里不再出现明显重复句式堆叠
- 报告中的关键证据和背景参考能看出层次，而不是一个大列表

---

## 4. 证据源质量与证据排序仍需继续优化

### 当前问题

虽然 evidence 清洗和排序已经做过一轮，但仍然存在：

- `reddit`、泛社区页混入前排
- 同一来源重复性过高
- 页面质量没有被充分区分
- 某些外部文章和当前 indicator 关联其实较弱

### Plan 3 目标

把 evidence 分成更清楚的等级：

- `strong_evidence`
- `supporting_evidence`
- `background_reference`
- `discarded_low_signal`

同时在实现层引入明确的来源分层字典，例如 `DOMAIN_TIERS`：

- Tier 1（Strong）：`virustotal`, `abuse.ch`, `malpedia`, `any.run`
- Tier 2（Supporting）：`microsoft.com`, `trendmicro.com`, `checkpoint.com`, `huntress.com`
- Tier 3（Background）：泛指纹库、一般安全博客、厂商较弱背景页
- Tier 4（Noisy）：`reddit.com`, 泛 `github.com` 搜索页、论坛、机翻农场站

### 具体动作

- 继续加强 page-type 判定：
  - detail
  - family profile
  - sandbox report
  - list/tag
  - forum/community
- 对 `reddit / forum / generic blog / noisy aggregator` 再降权
- 对 `Tier 4` 来源默认不进入关键证据
- 引入更强的去重策略：
  - 同域名多页只保留最强一条进入关键证据
- 对 “与 indicator 弱相关但与 family 强相关” 的文章降级为背景参考，而不是关键证据
- 在 analysis 中显式记录：
  - `evidence_tier`
  - `page_type`
  - `is_reportable`

### 验收标准

- 关键证据区不再出现明显低质量来源
- `reddit` 一类来源最多出现在背景参考，不进入关键证据

---

## 四、Plan 3 的实施优先级

建议严格按下面顺序推进。

### Phase 1：打通 gap fill 到 report 的最后一公里

目标：
- 让补查结果稳定进入 `final analysis` 和 `report`

优先改动：
- `final analysis` 合并逻辑
- `report renderer` 对 supplemental evidence 的消费方式
- `assessment` 更新规则（高质量 supplemental family 如何覆盖保守结果）

完成标志：
- `gap_probe_plan` 从 FAIL 变成 PASS
- 报告中能看到补查新增证据

### Phase 2：删除独立 react 模式并收敛入口

目标：
- 彻底统一用户入口与测试口径

建议：
- CLI、README、smoke、文档全部只围绕 `plan + gap fill react`
- 清理或冻结纯 react 相关代码路径

完成标志：
- 不再存在“是否要维护纯 react 模式”的分歧
- smoke 套件只验证主链

### Phase 3：做报告成品化

目标：
- 让报告从“结构正确”变成“展示效果好”

优先改动：
- 报告段落重组
- 半结构化模板渲染
- 关键证据/背景参考分层
- 深度关联发现单独成节
- 家族归因理由摘要
- 语言去模板化

完成标志：
- 代表性样例报告观感明显提升

### Phase 4：继续提升证据质量

目标：
- 减少噪音来源
- 提高强证据比例

优先改动：
- source/page-type 权重
- 去重
- 弱来源降级

完成标志：
- 关键证据区更“干净”

### Phase 5：再决定是否引入更强外部 API

只有在前面 4 个阶段完成后，再考虑继续引入：

- ANY.RUN API
- ThreatFox / URLhaus 结构化接口
- 更多 sandbox / TI API

理由：

> 当前的主要短板已经不只是“缺更多数据”，而是“已有数据没有被稳定整合和高质量表达”。

---

## 五、Plan 3 暂不优先做的事

以下方向不是没价值，但当前不应优先：

- 重构主架构
- 大规模自动化测试工程化
- 引入数据库 schema 大改
- 多告警关联分析
- 自动处置闭环
- 复杂 memory / case retrieval
- 重新引入或重建“纯 react 主模式”

这些都应该在 Plan 3 收口后再考虑。

---

## 六、Plan 3 的成功标准

若以下条件全部满足，可认为 Plan 3 完成：

1. `plan` 主链功能 smoke 稳定通过
2. `gap_probe_plan` 不再失败，补查价值能体现在报告中
3. 纯 `react` 路径已从产品范围与主测试口径中移除
4. `004 / 005 / ip_without_vt / gap_probe_plan` 的报告都达到可展示水平
5. 关键证据区不再出现明显低质量来源
6. 高价值 supplemental evidence 能影响最终 assessment，而不只是挂在 JSON 中

---

## 七、一句话总结

Plan 2 解决的是：

> “Agent 能不能稳定跑起来？”

Plan 3 要解决的是：

> “Agent 跑起来之后，能不能把补查价值真正写进结果，并产出让人信服的报告？”
