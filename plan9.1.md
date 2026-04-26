# Plan 9.1: 语义解耦、证据角色化与双 Agent 交付控制

## 0. 任务类型

按 `agent-development` 的分类，这一轮属于：

- `retrofit`
- `hardening`

不是绿地重写，也不是继续打磨模板文案，而是对现有 incident-agent 的控制面、证据面和交付面做一次有边界的重构。

---

## 1. 当前最核心的问题到底是什么

经过前几轮调整，我现在更明确地认为：

> 当前系统的主问题不是“再补一点上游结构化事实”，而是“分析语义、交付语义、读者语义被混在了一起”。

这会带来三个直接后果：

1. `analysis/provisional` 已经很强时，正文会开始写得像“事件基本成立”。
2. `delivery/readiness` 还没放行时，首页状态又只能写成 `needs_review`。
3. 结果就是主报告同时出现两套口径，看起来像系统自己在打架。

这也是为什么之前已经修了多轮：

- 结构化事实
- 模板
- case
- LLM 决策

但主报告仍然不够像 `report_reference`。

因为真正没解决的是：

> **谁来定义主报告能说什么，谁来定义不能说什么。**

---

## 2. Plan 9.1 的总目标

Plan 9.1 不再继续做“哪里差就补哪里”的局部修补，而是先把主链路重新冻结成一个清晰的契约：

1. 为 `report.md` 建立单一真相源
2. 明确区分：
   - 内部分析判断
   - 交付放行判断
   - 面向运维/SOC 的外部表达
3. 把主证据从“随便挑几条正向事件”升级成“按通用证据角色组织”
4. 把双 agent 真正放到控制链路里：
   - investigator 负责调查推进
   - reviewer 负责交付审查与低价值动作约束
5. 让主报告和技术附录分层，避免主报告继续暴露开发态/工作流态内容

---

## 3. 本轮明确不做什么

为了避免再次返工，Plan 9.1 明确不做以下事情：

### 3.1 不做 case-specific hardcode

禁止下面这种“看起来效果变好，实际上过拟合”的修改：

- 针对某个 fixture 的域名/IP/JA4 写特殊规则
- 因为某个 case 总是重复调用某个工具，就写死禁用条件
- 因为某个 case 常见 `execution + lateral-movement`，就把它硬编码成固定证据组合

### 3.2 不把 agent 再改回 workflow engine

不能重新滑回：

- “先查 A，再查 B，再查 C”
- “如果是 spread case 就必须查扩散”
- “如果是 exfil case 就必须补外传”

程序可以提供结构约束，但不能重新把调查流程写死。

### 3.3 不先继续堆模板

当前 `report_template.md` 已经足够成熟。

下一轮的重点不是继续改模板，而是让：

- agent 真正补齐模板需要的证据
- renderer 真正只消费合适的语义层

---

## 4. 新的单一真相源设计

## 4.1 `report.md` 的单一真相源

我建议新增并冻结一个新的主报告契约：

- `main_report_contract`

并明确：

> `report.md` 只能由 `main_report_contract` 渲染出来。

不能再让最终渲染时同时混用：

- `delivery_verdict`
- `analysis_summary`
- `decision_basis`
- `focus_statement`
- `positive_summary`
- `reader_report`
- `report_outline`

否则只会继续出现多头口径。

### 4.1.1 `main_report_contract` 的定位

它不是技术全量 contract，也不是模板字段镜像，而是：

> **一个只面向运维/SOC 主报告的“外部表达层 contract”。**

它只保留主报告真正应该说的东西：

- 当前状态
- 一句话结论
- 当前最强证据
- 当前最关键缺口
- 已确认范围
- 待确认范围
- 证据链如何支撑当前结论
- 为什么现在不能说得更多
- 下一步建议动作

### 4.1.2 `main_report_contract` 的唯一上游

`main_report_contract` 只能从以下内容生成：

- `delivery_verdict`
- `readiness`
- `evidence_contract`
- `scope`
- `timeline`
- `recommendations`
- 一个新的“证据角色摘要层”

不能直接吃内部分析措辞。

### 4.1.3 canonical ownership 与迁移关系

为了避免再出现“新加一个 contract，但旧 contract 也没退场”的问题，这里补一个明确的 ownership：

- `evidence_contract`
  - canonical source for: 证据对象、证据 provenance、grounding 状态、对象 registry、引用锚点
  - 不负责: 主报告措辞、交付口径
- `analysis_assessment`
  - canonical source for: 核心事件方向、内部分析强弱、分析侧 rationale
  - 不负责: 对外主状态
- `delivery_assessment`
  - canonical source for: 是否可稳定交付、阻塞 gap、放行原因/不放行原因
  - 不负责: 读者友好措辞
- `main_report_contract`
  - canonical source for: `report.md` 的全部外部表达
  - 不负责: 附录明细、底层 provenance 存档

现有结构的迁移关系建议如下：

- `report.md`
  - 新目标: 只读 `main_report_contract`
- `report_appendix.md`
  - 继续主要读取 `evidence_contract`，必要时补充 `analysis_assessment` / `delivery_assessment`
- `report_contract`
  - 过渡层，仅在兼容窗口内保留
- `report_outline`
  - 过渡层，仅为旧 renderer/LLM polish 兼容使用
- `reader_report`
  - 不再作为独立真相源，只能成为 `main_report_contract` 构造阶段的中间 helper，后续可删除

### 4.1.4 迁移完成的判据

只有同时满足以下条件，才算真正完成“单一真相源”迁移：

1. `render_incident_report()` 不再直接读取 `analysis_summary`、`decision_basis`、`report_outline`
2. `report.md` 的关键段落都可以在 `main_report_contract` 中找到唯一对应字段
3. `reader_report` 不再被最终渲染链直接消费
4. `report_contract`/`report_outline` 即使暂时保留，也只作为兼容产物，不再承载独占语义

---

## 4.2 分析层和交付层如何分开

我建议内部显式保留三层语义：

### A. `analysis_assessment`

回答：

- 从证据强度看，核心事件方向偏向什么

它允许更积极，也允许存在 provisional 的“方向性”。

### B. `delivery_assessment`

回答：

- 现在是否已经满足稳定交付条件
- 哪些 gap 阻止我们把结论写得更实

### C. `main_report_contract`

回答：

- 在当前交付状态下，面向运维/SOC，报告到底应该怎么说

关键原则是：

> 主报告只服从 `delivery_assessment`，不直接服从 `analysis_assessment`。

但主报告仍然要把二者的张力表达出来，只是要用外部语言表达。

例如：

- 不写：“analysis 已 confirmed，但 delivery 未放行”
- 改写成：“核心异常链已具备高风险特征，但扩展范围仍缺少独立核验，因此当前按需复核事件交付”

这样既诚实，又不会把内部工作流术语暴露给读者。

---

## 4.3 是否要改 verdict 体系

我的建议是：

### 4.3.1 外部主状态先不大改

先保留现在外部常用状态：

- `confirmed_incident`
- `needs_review`
- `monitor_only`

避免一次性把整个输出生态都打散。

### 4.3.2 内部新增两个维度

在内部补两个显式维度：

- `core_incident_assessment`
- `scope_completion_assessment`

分别回答：

- 核心事件链是否已经站住
- 扩展范围是否已经补证到可以并入主结论

这样就不会再把“核心事件是否成立”和“扩线范围是否补齐”绑死成一个判断。

这一步非常关键，因为现在很多 case 卡在：

- 核心链已经很强
- 但扩线候选还没完全 grounded
- 最终整个报告只能退回 `needs_review`

这会导致主报告显得过于保守，但又在正文里偷偷写得很像已成立。

---

## 5. 通用证据角色模型

当前 `decision_basis` 的问题是：

- 正向证据基本只是从 seed/supporting 里取前几条
- 反证只是简单挑几条 counter
- 没有明确覆盖“为什么立案”“为什么升级”“为什么收敛范围”“为什么还不能写更多”

所以我建议引入一层通用的证据角色抽象。

## 5.1 证据角色集合

主报告至少需要下面六类角色：

### 1. `trigger_evidence`

回答：

- 这起调查为什么被触发
- seed 告警的直接落点是什么

### 2. `corroborating_evidence`

回答：

- 为什么这不是单点孤立命中
- 哪些观察让异常从“单点”变成“连续链”

### 3. `progression_evidence`

回答：

- 为什么风险等级被拉高
- 哪些事件说明行为出现升级、阶段推进或攻击动作延展

注意：

这里不是硬编码某个 ATT&CK 阶段，而是泛化地表达“风险升级证据”。

### 4. `scope_evidence`

回答：

- 为什么某些资产/基础设施可以被并入当前范围
- 范围判断的依据是什么

### 5. `counterevidence`

回答：

- 当前最强的替代解释是什么
- 为什么它没有推翻主结论，或者为什么它足以让我们降级

### 6. `boundary_gap_evidence`

回答：

- 当前到底缺什么，所以不能把结论写得更满
- 哪些对象还只是候选，不该写成已确认

这六类角色足以支撑主报告大部分关键段落。

如果后续确实需要，再补：

- `impact_evidence`
- `background_context`

但第一轮不宜继续加太多角色。

---

## 5.2 这些角色如何选，不靠硬编码

证据角色的归类不能靠 case-specific 规则，而应该基于通用特征打分。

建议每条事件或证据观察都计算以下通用特征：

- 是否 seed 直接观测
- 是否重复/复现同一对象
- 是否引入新的关键对象
- 是否引入新的受影响资产
- 是否带来更高风险的行为语义
- 是否具备独立 grounding
- 是否来自不同来源平面
  - 网络
  - 主机
  - 本地情报
  - 外部情报
  - 基线/反证
- 是否更适合解释为背景活动
- 是否仍然只是候选/未独立确认

然后由程序做通用打分与归位：

- 不是按 case 类型归位
- 不是按某个域名/IP/JA4 归位
- 不是按固定 stage 名归位

而是按“这条证据在当前结论里扮演什么角色”归位。

---

## 5.3 角色层和证据层的 ownership

ownership 必须清楚：

- 原始事件与情报命中：来自 observation / tool result
- provenance 与 grounding：由 pipeline 程序整理
- evidence role assignment：由程序生成，可让 LLM 辅助排序但不直接裸写
- 主报告措辞：由 renderer 或 LLM polish 基于角色层输出

换句话说：

> LLM 可以帮助“选择当前最值得强调的角色实例”，但不能绕过程序化 provenance 直接创造主证据。

## 5.4 证据角色层的最小 schema

为了避免“角色概念是清楚的，但一落代码又退回随手挑几条”，这里补一个最小数据 schema。

每个 evidence role entry 至少应包含：

- `role`
  - 例如 `trigger_evidence` / `corroborating_evidence`
- `entry_id`
  - role 层自己的稳定 id，不直接复用 observation 原始 id
- `observation_ids`
  - 绑定到哪些原始观测/情报命中
- `object_refs`
  - 涉及哪些资产、IP、domain、fingerprint、host artifact
- `grounding_status`
  - `grounded` / `partially_grounded` / `candidate_only`
- `evidence_strength`
  - `high` / `medium` / `low`
- `why_selected`
  - 为什么它在当前 role 下值得进入主报告
- `reader_fact`
  - 面向主报告的事实句素材
- `reader_limit`
  - 这一项证据本身的边界或局限
- `citation_refs`
  - 供附录或引用映射使用

### 5.4.1 一条证据能否属于多个 role

可以，但要受限：

- 同一 observation 可以被多个 role 引用
- 但每个 role entry 必须明确“它在当前 role 下承担的功能”
- 主报告最终默认每个 role 只选 1 到 2 个 entry

这样可以避免：

- 同一条事件在正文里反复重复出现
- 角色层为了凑满章节而人为复制内容

### 5.4.2 role selection 的基本约束

第一轮建议使用以下简单约束，而不是复杂优化器：

- `trigger_evidence`
  - 选 1 条，优先 seed 直接观测
- `corroborating_evidence`
  - 选 1 到 2 条，优先能证明“不是单点孤立命中”的独立复现
- `progression_evidence`
  - 选 1 到 2 条，优先风险明显升级的观测
- `scope_evidence`
  - 选 1 到 2 条，优先真正能支撑“并入范围”的对象关系
- `counterevidence`
  - 选 1 到 2 条，优先最强替代解释
- `boundary_gap_evidence`
  - 选 1 到 2 条，优先当前真正阻塞交付的 gap

这里的“优先”是通用评分优先，不是 case-specific 规则。

---

## 6. 双 Agent 是否合适，以及怎么落地

我现在的判断是：

> 双 agent 是合适的，但不是 investigator + 第二个调查员，而是 investigator + delivery reviewer。

## 6.1 investigator 的职责

investigator 负责：

- 根据当前 state 和 gap ledger 决定下一步行动
- 自主循环调用工具
- 扩线、补证、查反证、做对象核验
- 把新事实沉淀回 evidence/state

它不负责最终“我要不要放行这份报告”。

## 6.2 reviewer 的职责

reviewer 只负责三件事：

1. 判断当前是否已经可交付
2. 指出还阻塞交付的关键 gap
3. 识别重复、低收益或越界的工具调用，并给出约束建议

它不负责：

- 自己去调查
- 自己生成新事实
- 自己扩线
- 代替 investigator 下最终事实结论

这点必须卡死，否则双 agent 会退化成两个 agent 一起自由发挥，最后更难控。

---

## 6.3 reviewer 如何控制重复调用，而不靠硬编码

reviewer 不应通过这种方式工作：

- “这个 case 里某工具经常重复，所以禁掉”
- “如果看到某类域名就不要再查”

而应当基于通用的“收益变化”判断：

### reviewer 每轮输入应包括

- 当前 gap ledger
- 最近一到两轮新增事实
- 最近一到两轮新增对象
- 最近一到两轮新增 grounded evidence
- 最近几次工具调用及其 query signature
- 每次调用是否带来了新实体 / 新证据 / gap closure

### reviewer 的输出应包括

- `deliverable_now`: 是否建议进入交付
- `blocking_gaps`: 当前阻塞交付的 gap
- `low_value_repeats`: 哪些动作已经重复且收益低
- `tool_cooldown_suggestions`: 哪些工具在什么条件前不应继续调用
- `next_focus`: investigator 下一轮最值得补的 gap

注意：

`tool_cooldown_suggestions` 不是永久禁用，而是：

> **在状态没有新增变化前，暂不值得重复调用。**

这符合“程序做结构约束，LLM 做模糊判断”的原则，也比硬编码泛化得多。

## 6.4 reviewer 建议到底是软约束还是硬约束

这一点必须提前定清楚，不然后面 investigator 很可能继续无视 reviewer。

我的建议是三层执行语义：

### 6.4.1 信息性建议

例如：

- `next_focus`
- `blocking_gaps`

这类输出进入 investigator prompt，作为强提示，但不强制。

### 6.4.2 软门控建议

例如：

- `tool_cooldown_suggestions`
- `low_value_repeats`

这类输出进入一个程序化 pre-check：

- 如果 investigator 再次选择被 cooldown 的同类动作，必须显式给出 `override_reason`
- 没有 `override_reason` 时，动作直接被拒绝并要求重选

这样既不是纯自由发挥，也不是写死禁用。

### 6.4.3 硬阻塞条件

例如：

- 达到最大循环步数
- 连续若干轮无新增 grounded evidence
- reviewer 判断已经 `deliverable_now = true`

这类条件由程序直接终止或切换到交付阶段，不再让 investigator 继续游走。

### 6.4.4 关键点

reviewer 不直接决定“查什么事实”，但它可以决定：

- 什么时候不值得继续某类重复动作
- 什么时候必须切入交付
- 什么时候 investigator 只有在给出合理 override 时才能继续某个动作

这才算真正把 reviewer 放进控制链，而不是只做一个旁观评论员。

---

## 7. 工具暴露原则

用户之前强调“一切皆 tools”，这一点我认同。

但“全部工具都暴露”不等于“没有工具治理”。

真正合理的做法应该是：

- 工具能力尽量完整暴露
- tool description 更清晰
- 工具调用条件更清晰
- 重复低收益调用由 reviewer 约束
- 是否该调用哪类工具，由 investigator 决定

## 7.1 应暴露的工具能力分组

建议至少覆盖以下几组能力：

### A. 种子上下文与时间窗工具

用于：

- 建最小事件窗
- 回看 seed 前后上下文
- 形成调查起点

### B. pivot / 扩线工具

用于围绕以下对象继续扩查：

- asset
- ip
- domain
- ja3/ja4
- internal peer
- process / host artifact

### C. grounding / compare 工具

用于判断新扩出的对象或事件：

- 是否有独立支撑
- 是否只是共享基础设施
- 是否与既有主链存在足够关联

### D. 指纹 / 情报 / 本地库查询工具

用于：

- 本地数据库命中
- 外部情报命中
- ja4db / abuse.ch / 其他信誉库
- 资产背景 / 基线背景

### E. counterevidence / baseline 工具

用于主动找：

- 补丁窗口
- 合法运维
- 正常软件更新
- 共享 CDN / 共享 IP 背景

### F. 结构化写回工具

用于把结果写回统一 state，而不是让 tool output 只当终端噪声。

---

## 7.2 工具说明需要补什么

当前很多问题不只是“LLM 笨”，而是 tool contract 不够清楚。

每个工具描述都应该补上：

- 什么时候该用
- 什么时候不该用
- 它最适合回答什么问题
- 它返回结果后，哪些字段适合沉淀为证据
- 什么算“新信息”
- 什么情况下重复调用大概率没有价值

这一步通常比继续改 system prompt 更有效。

## 7.3 工具暴露策略

Plan 9.1 里不建议“每轮全量暴露所有工具”。

更合理的方式是：

- 底层工具全集仍然存在
- 但每一轮只向 investigator 暴露一个“当前候选工具集”

### 7.3.1 候选工具集如何形成

由程序根据当前状态做通用筛选：

- 当前有哪些 open gaps
- 当前关注对象类型是什么
- 最近哪些工具已经重复且无收益
- 当前处于 seed build-up / expansion / grounding / counterevidence / delivery 哪个阶段

然后形成：

- `recommended_tools`
- `allowed_but_low_priority_tools`
- `cooldown_tools`

### 7.3.2 investigator 看到什么

investigator 每轮默认只重点看到：

- 少量 `recommended_tools`
- 必要的 `allowed_but_low_priority_tools`

`cooldown_tools` 不直接消失，但要明确标注：

- 当前为什么不建议再用
- 在什么状态变化后可以重新考虑

### 7.3.3 为什么这不算硬编码 workflow

因为筛选依据不是：

- 这是 spread case
- 这是 exfil case
- 这是某个特定域名

而是：

- 当前 gap 类型
- 当前对象类型
- 最近信息增益
- 当前控制阶段

它是在做工具治理，不是在写死调查路径。

---

## 8. 主报告与附录的分层

现在主报告最大的问题之一是：

> 它还像给开发者看，不像给运维/SOC 协同读者看。

所以 Plan 9.1 里，报告必须明确分层。

## 8.1 主报告保留什么

主报告保留：

- 当前事件状态
- 结论
- 最强证据
- 关键反证
- 影响范围
- 时间线骨架
- 当前边界与缺口
- 建议动作

主报告尽量不保留：

- 证据编号内部玩法
- selector / reviewer / readiness 术语
- 过细的 JA3/JA4 技术串
- 观测对象 registry 的开发态表达
- 工具名
- source_type / internal_digest / observation_id

## 8.2 技术附录放什么

附录保留：

- IOC/IOA 详细清单
- 证据引用映射
- 指纹命中明细
- 候选对象与未确认对象
- 关键对象 provenance
- gap ledger
- 分析层/交付层差异说明

这样主报告才能更像真正可交付材料，而不是内部调试 dump。

---

## 9. 最推荐的实现顺序

这一轮不能再大爆炸重构，必须按可验证阶段推进。

## Phase 1: 冻结主报告语义 contract

目标：

- 新增 `main_report_contract`
- 明确 `report.md` 只吃它
- 主报告不再直接混吃 analysis 口径

涉及文件：

- `demo_agent/incidents/render.py`
- 可能少量触及 `demo_agent/incidents/agent.py`

验收标准：

- 同一个 case 不再出现“状态是 needs_review，但正文像 confirmed”这种明显自冲突
- `report.md` 与 `report_appendix.md` 分层更清楚

## Phase 2: 引入通用证据角色层

目标：

- 在 pipeline 中新增 evidence role selection
- 取代当前“前 4 条 positive events”式的主证据选取

涉及文件：

- `demo_agent/incidents/pipeline.py`
- 可能补少量 `render.py` adapter

验收标准：

- 主证据不再全是“重复通信”同质化描述
- spread / execution / exfil / benign 混合 case 中，证据类型明显更丰富

## Phase 3: reviewer 真正接管交付约束

目标：

- reviewer 输出 deliverability / blocking gaps / cooldown suggestions
- 调查 loop 可读取 reviewer 建议，减少重复低收益工具调用

涉及文件：

- `demo_agent/incidents/agent.py`
- 可能涉及 prompt / tool gating 相关模块

验收标准：

- trace 中重复工具调用率下降
- reviewer 的阻塞理由能和最终报告的“关键缺口”对齐

## Phase 4: 工具 contract 与新实体补查

目标：

- 对新扩出的关键 IP / domain / fingerprint / host artifact，提供通用 enrichment / grounding / counterevidence 工具路径
- agent 自主决定何时补查，不写死 workflow

涉及文件：

- tool definitions / tool docs / prompt 相关位置

验收标准：

- 当扩线发现新对象时，trace 能看到 agent 自主进行必要的验证与情报补查
- `multi_host_confirmed_spread` 一类 case 中，新对象不再只是“被发现”，而是“被验证”

## Phase 5: case 与 acceptance 升级

目标：

- 设计更能体现 agent 价值的旗舰 case
- acceptance 从“关键词/状态检查”升级为“调查质量检查”

验收标准：

- 能分辨“事件薄导致报告薄”与“agent 没查明白导致报告薄”
- 同时覆盖：
  - 真阳性扩散
  - 需保守收敛的扩线
  - 强反证降级
  - 新对象需要二次指纹/情报验证

---

## 10. case 设计原则

为了真正体现 agent 的作用，新的旗舰 case 不能只是“多加几条事件”。

关键证据必须分散在多个平面：

- seed 流量
- 扩线流量
- 主机侧动作
- 本地数据库命中
- 外部情报/指纹命中
- 反证/维护背景

这样 agent 必须主动调用工具，才能完成：

- 证据补齐
- 范围确认
- 反证排查
- 报告收敛

否则 case 太 demo，永远分不清是 agent 不行，还是材料本身就薄。

---

## 11. 验收指标要怎么改

后续 eval 不能只看：

- verdict 对不对
- 报告有没有关键词

至少要新增下面几类指标：

### 11.1 语义一致性

- 主状态和正文是否一致
- 是否存在“正文比状态说得更满”的冲突

### 11.2 证据角色覆盖

- 是否覆盖 trigger / corroboration / progression / scope / counter / gap

### 11.3 调查质量

- 是否对扩线出来的新关键对象做了独立验证
- 是否主动检查了反证
- 是否把共享基础设施和真实扩散区分开

### 11.4 控制质量

- 重复工具调用率
- 无新增信息的循环次数
- reviewer 建议是否真正改变 investigator 行为

### 11.5 报告可交付性

- 运维/SOC 能否看明白：
  - 发生了什么
  - 为什么这样判断
  - 影响到哪里
  - 还缺什么
  - 下一步该做什么

### 11.6 grader 依赖什么输入

为了让这些验收指标后续真的能实现，trace 和产物层至少要稳定保留：

- investigator 每轮动作选择
- reviewer 每轮输出
- 每轮新增对象/新增证据/关闭的 gap
- evidence role assignment 结果
- `main_report_contract`
- 最终 `report.md` / `report_appendix.md`

后续 grader 建议拆成三类：

- deterministic grader
  - 查字段一致性、role 覆盖率、trace 中是否存在重复低收益循环
- contract-aware grader
  - 查 `main_report_contract` 与最终报告是否一致
- LLM grader
  - 只用于评“报告是否像运维/SOC 可交付材料”这类确实需要主观判断的问题

---

## 12. 我建议的第一落点

如果现在立刻开始做代码，我建议第一刀先切在：

1. `render.py`
2. `pipeline.py`

具体来说先做：

- `main_report_contract`
- 证据角色层
- 主报告/附录分层

而不是先继续修：

- 上游结构化事实
- 模板文案
- 某个 case 的特殊表现

原因很简单：

> 如果主报告的语义 contract 还没冻结，继续补上游和补 case，只会继续把更多内容灌进一个仍然会自相矛盾的出口。

---

## 13. 风险与注意事项

### 13.1 最大风险

新增了 `main_report_contract` 之后，如果旧的 `report_outline`、`reader_report`、`report_contract` 仍长期并存，就会再次形成多头真相源。

所以必须明确迁移路径：

- 先兼容一小段时间
- 然后尽快让 `report.md` 只吃一个 contract

### 13.2 第二个风险

双 agent 如果边界不清，会重新变成：

- investigator 一套判断
- reviewer 另一套判断
- 报告第三套判断

所以 reviewer 必须只做交付审查，不做第二调查员。

### 13.3 第三个风险

如果证据角色层做得太贴模板，也会再次滑回“为了写章节而调查”。

所以角色层必须是：

- 面向结论支撑关系
- 不是面向章节字段补空

---

## 14. 当前结论

Plan 9.1 的核心不再是“再补一点事实”或“再改一点模板”，而是：

> **先把主报告的语义出口收敛成单一 contract，再让证据选择和 reviewer 控制围绕这个出口服务。**

只有这样，后续我们再去优化：

- investigator 的循环质量
- 工具暴露质量
- 新 case
- 指纹/情报补查

才不会继续陷入“改了一堆上游，最后还是从一个语义混乱的主报告里漏出来”的循环。

---

## 15. 实时清单

当前我认为最应该按顺序执行的是：

1. 冻结 `main_report_contract`，统一主报告真相源
2. 引入通用证据角色层，替换当前 top-positive 选证逻辑
3. 让 reviewer 产出可执行的交付阻塞与工具冷却建议
4. 升级工具 contract，让 agent 能对新扩线对象自主补查
5. 用升级后的 case 和 acceptance 验证整条链路

这五步里，前两步是现在最值得先做的。
