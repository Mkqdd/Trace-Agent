# Claude Code 源码学习笔记（面向 Trace-Agent）

这份笔记是基于网站 `https://nangongwentian-fe.github.io/learn-claude-source/` 的阅读整理，目的不是复述教程内容，而是把其中**对 Trace-Agent 设计最有启发的部分**提炼出来，作为后续演进时的长期上下文。

阅读时间：

- 2026-04-11

核心来源页：

- 概览：<https://nangongwentian-fe.github.io/learn-claude-source/overview.html>
- 架构全景：<https://nangongwentian-fe.github.io/learn-claude-source/architecture.html>
- S01 Agent Loop：<https://nangongwentian-fe.github.io/learn-claude-source/s01-agent-loop.html>
- S02 Tools：<https://nangongwentian-fe.github.io/learn-claude-source/s02-tools.html>
- S03 Permissions：<https://nangongwentian-fe.github.io/learn-claude-source/s03-permissions.html>
- S04 System Prompt：<https://nangongwentian-fe.github.io/learn-claude-source/s04-system-prompt.html>
- S05 Context & Compact：<https://nangongwentian-fe.github.io/learn-claude-source/s05-compact.html>
- S06 Subagents：<https://nangongwentian-fe.github.io/learn-claude-source/s06-subagents.html>
- S07 MCP：<https://nangongwentian-fe.github.io/learn-claude-source/s07-mcp.html>
- S08 Hooks：<https://nangongwentian-fe.github.io/learn-claude-source/s08-hooks.html>
- S10 Skills & CLAUDE.md：<https://nangongwentian-fe.github.io/learn-claude-source/s10-skills.html>
- S11 State & Session：<https://nangongwentian-fe.github.io/learn-claude-source/s11-state.html>
- S12 CLI & Architecture：<https://nangongwentian-fe.github.io/learn-claude-source/s12-cli.html>

---

## 1. 对我们最重要的总启发

从 Claude Code 这套源码学习里，对 Trace-Agent 最重要的启发不是“它有哪些功能”，而是下面这些**架构原则**：

### 1.1 Agent 的本质仍然是 Loop + Tools

最核心的抽象依然非常简单：

- 维护消息历史
- 调 LLM
- 如果模型要用工具，就执行工具
- 把工具结果回灌给模型
- 直到模型不再要求工具

对我们的意义：

- 不要把系统复杂化到忘记主循环本质
- Trace-Agent 的主链可以继续坚持“**确定性工作流 + 局部 Agent Loop**”的组合
- 现在的 `plan 主链 + gap fill` 方向是对的，因为它没有把所有事情都塞进一个大而自由的 loop

### 1.2 工具不只是函数，而是带元数据的执行单元

Claude Code 对 tool 的处理，不只是“提供函数给模型调”，还强调：

- 是否只读
- 是否可并发
- 是否破坏性
- 超大结果如何处理
- 权限检查钩子

对我们的意义：

- 我们现在的工具已经按 `baseline / exploration` 分层，但还没有正式建立“工具元数据层”
- 后续可以考虑给工具增加显式属性：
  - `read_only`
  - `networked`
  - `destructive`
  - `concurrency_safe`
  - `structured_output`
- 这样：
  - baseline 并发更容易控制
  - React 的工具白名单更好做
  - 权限与运行策略更容易收敛

### 1.3 权限必须是工具调用管线的一等公民

Claude Code 一个非常强的点是：权限不是外围补丁，而是每次工具执行前都走裁决。

对我们的意义：

- Trace-Agent 现在更多是“内部研究型 Agent”
- 但如果后面真的要走向更可交付的系统，权限层必须补上
- 至少应该把工具分成：
  - 纯读工具
  - 外网访问工具
  - 本地写入工具
  - 未来可能出现的处置类工具
- 然后对不同运行模式做约束：
  - 只分析模式
  - 可写报告模式
  - 未来可能的半自动处置模式

### 1.4 System Prompt 应该是“动态构建的程序”，而不是一段长字符串

Claude Code 的启发是：系统提示词不是静态文案，而是从多个来源拼装出来的“操作手册”。

对我们的意义：

- 我们现在的 `Gap Planner` 和 `React Gap Fill` prompt 已经比较长了
- 后面继续增强时，不应简单把更多规则堆进一个字符串
- 更合理的做法是按来源拼装：
  - 系统固定规则
  - 当前模式限制
  - 当前 gap 类型
  - 当前允许的工具清单
  - 当前补查目标
  - 项目级约束（例如不能编造 IOC）

这会让提示词更容易演化，也更容易做 A/B 调整。

### 1.5 上下文必须当作稀缺资源治理

Claude Code 强调三层 compact，这一点对 Trace-Agent 非常重要。

对我们的意义：

- 我们现在有：
  - `analysis.json`
  - evidence 列表
  - page content
  - claim/entity 提取
- 但还没有正式的“上下文压缩策略”
- 随着后续接入更多数据源，LLM 输入一定会膨胀

后面值得做的方向：

- baseline -> draft analysis 时就控制 evidence 数量
- gap fill 前只喂必要的 `analysis` 子集
- 对页面内容坚持：
  - HTML 清洗
  - 长度截断
  - claim/entity 先抽取再喂给模型
- 对历史证据做分层，而不是整包塞入 prompt

### 1.6 子代理真正有价值的点是“上下文隔离”，不是“多开几个模型”

Claude Code 关于 Subagents 最重要的启发是：

- 子代理不是为了看起来更智能
- 而是为了让主上下文保持干净
- 子代理跑很多步，父代理只接收摘要

对我们的意义：

- 我们现在已经不准备把系统做成“全自由 React”
- 这个判断是对的
- 如果后面真的再引入子代理，目的应该是：
  - 隔离超重的补查任务
  - 让主分析上下文不要被长页面、长搜索过程污染
- 例如未来可以有：
  - `IOC Pivot Subagent`
  - `Family Background Subagent`
  - `Sandbox Evidence Subagent`

但前提一定是：**只把摘要回传给主链**。

### 1.7 MCP 的真正价值是统一外部能力接入层

Claude Code 把 MCP 作为标准化外部能力接入层，这对我们非常有启发。

对我们的意义：

- 现在 Trace-Agent 的外部能力接入还比较“客户端化”
  - VT client
  - abuse.ch client
  - 搜索
- 如果后面数据源越来越多：
  - ANY.RUN
  - MISP
  - 自建 IOC 平台
  - 沙箱平台
  - 内部资产系统
- 那么靠手写 client 会越来越散

值得考虑的演进方向：

- 中期：先做我们自己的统一数据源接口层
- 长期：如果生态允许，可考虑 MCP 风格的外部能力编排

### 1.8 Hooks 的价值在于“围绕主链插可选的工程能力”

Claude Code 的 Hook 系统说明：

- 不是所有能力都要写进主循环
- 可以在关键生命周期节点挂自定义逻辑

对我们的意义：

- Trace-Agent 很适合做事件级 hook：
  - `PreBaseline`
  - `PostBaseline`
  - `PreGapFill`
  - `PostGapFill`
  - `PreReportRender`
  - `PostCaseComplete`
- 这样后续可以很容易插入：
  - 埋点
  - 指标上报
  - 自动存档
  - 外部告警平台同步
  - 人工审批节点

### 1.9 Skills / CLAUDE.md 的设计给了我们“知识注入分层”的启发

Claude Code 的一个特别好的思路是：

- 持久规范放在 CLAUDE.md
- 大块、任务专用知识按需加载为 Skills

对我们的意义：

- 我们现在的补查知识还比较分散在 prompt 和代码里
- 后面可以把知识注入分成两层：
  - 永久规则：
    - 归因不能编造
    - 证据引用规范
    - 报告结构规范
  - 按需知识：
    - 某家族专题知识
    - 某类 IOC 的专题补查策略
    - 某类基础设施研判手册

这能显著降低 prompt 的臃肿程度。

### 1.10 Session / State 持久化值得我们借鉴

Claude Code 把 session、transcript、state 拆开持久化。

对我们的意义：

- 我们现在已经有：
  - `input_alert.json`
  - `event.json`
  - `analysis.json`
  - `report.md`
- 但如果后面要支持更复杂的调试或恢复，可能还需要：
  - 补查过程日志
  - gap planner 输出快照
  - React 工具调用轨迹
  - 中间版本 analysis

也就是说，我们已经有“结果级持久化”，后面可以再补“过程级持久化”。

### 1.11 CLI 分层和快速路径很值得学习

Claude Code 的 CLI 架构强调：

- 快速路径先返回
- 重型主链延迟加载

对我们的意义：

- 我们现在 CLI 还比较薄，但这个思路值得记住
- 未来如果命令越来越多，可以考虑：
  - `--version`
  - `--print-config`
  - `--dump-system-prompt`
  - `--validate-alert`
  - `--dry-run-gap-plan`

走快路径，不要一上来就初始化整个 Agent 系统。

---

## 2. 对 Trace-Agent 最直接可借鉴的设计点

下面这些是我认为**最值得真正写进我们后续设计/代码**的内容。

### 2.1 给工具增加元数据层

建议后续把工具统一描述成类似：

- `name`
- `read_only`
- `networked`
- `destructive`
- `concurrency_safe`
- `supports_indicator_types`
- `returns_structured_json`

这样能解决我们现在几个长期问题：

- baseline 并发时谁能并发、谁不能并发
- 为什么 `JA3` 不应该去打 `URLhaus`
- React 工具白名单该怎么做
- 未来权限层该怎么挂

### 2.2 把 prompt 构建器正式独立出来

我们现在已经感受到：

- Gap Planner prompt
- React prompt
- 报告模式 prompt

开始变长、变复杂。

建议后面做成：

- `build_gap_planner_prompt(analysis, allowed_tools, rules, mode)`
- `build_gap_fill_prompt(analysis, gap_plan, allowed_tools, rules)`
- `build_report_prompt(analysis, report_policy)`

这样能让系统更像工程系统，而不是 prompt 字符串堆积。

### 2.3 正式设计“上下文预算策略”

建议后面给每一类 LLM 输入显式加预算：

- Draft analysis 之前：不用 LLM
- Gap planner：
  - 只喂摘要版 analysis
- Gap fill：
  - 只喂与 gap 有关的 facts/evidence
- 页面阅读：
  - 永远先 claim/entity 再回给模型

这会让我们后面接更多 API 时不至于 prompt 爆炸。

### 2.4 给主链加 Hook 点

这个对工程化扩展特别有帮助。

建议未来可支持：

- `PreBaseline`
- `PostBaseline`
- `PreGapPlanner`
- `PostGapPlanner`
- `PreGapFill`
- `PostGapFill`
- `PreRender`
- `PostRender`

不一定马上实现，但设计上可以预留。

### 2.5 如果以后引入“子代理”，必须强调摘要回传

如果后面真的要做更复杂的补查：

- 不应该让主链直接承受所有中间细节
- 而应该让子代理只返回：
  - evidence summary
  - family candidate
  - related IOC summary

这个原则非常重要，避免系统逐步演变成“上下文泥潭”。

---

## 3. 对当前 Trace-Agent 的具体映射

把 Claude Code 的这些思想映射到我们项目上，大致是这样：

### 3.1 我们已经对齐的部分

- `plan 主链 + gap fill`，本质上符合“主循环 + 工具 + 局部探索”
- `analysis.json` 已经开始承担“真相源”的角色
- `baseline` 与 `exploration tools` 已经做了初步分层
- gap fill 已经不是纯自由 ReAct，而是：
  - planner
  - react
  - deterministic fallback

### 3.2 我们还明显偏弱的部分

- 工具元数据层还不正式
- prompt 还是字符串为主，没有 builder
- 没有正式的 context budget / compact 策略
- 没有 hook 系统
- 还没有“过程级 state 持久化”

### 3.3 我们后续最值得继续借鉴的方向

优先级我会排成这样：

1. 工具元数据层
2. Prompt Builder
3. Context 预算与轻量 compact
4. 过程级 state 持久化
5. Hook 系统
6. 子代理隔离
7. 更统一的外部能力接入层

---

## 4. 我对这个教程最认同的一句话总结

如果只保留一句最有价值的启发，那就是：

**工业级 Agent 的难点不在“会不会调模型”，而在“如何把工具、权限、上下文、状态和扩展能力组织成一条可控的工作流”。**

对 Trace-Agent 来说，这句话的含义是：

- 我们继续增强系统时，不应该只盯着“补哪个 API、改哪个 prompt”
- 更应该持续把：
  - 工具层
  - 权限层
  - 上下文层
  - 状态层
  - 扩展层

做得更清晰

这套源码学习对我们最大的价值，就在这里。

---

## 5. 以后怎么使用这份笔记

这份目录主要用于后续开发时快速提醒自己：

- 当我们想加一个新工具时，先想“它的元数据是什么”
- 当我们想把 prompt 再写长一点时，先想“要不要做 builder”
- 当我们想加更多补查步骤时，先想“上下文会不会爆”
- 当我们想做更复杂的补查时，先想“是不是应该做子代理隔离”
- 当我们想加更多集成时，先想“是不是该抽统一接入层”

也就是说，这份笔记不是知识收藏，而是**后续设计决策时的参考系**。
