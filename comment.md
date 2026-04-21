我对 Plan 8 的整体思路非常认同。Plan 7 实现了架构从单告警向事件级的跃迁，而 Plan 8 精准地抓住了当前系统最核心的痛点：**结论下得太快，交付门槛（readiness）不够严谨，证据来源（provenance）模糊，以及缺乏显式的反证检查**。

以下是我对 Plan 8 几个核心改造点的具体意见和建议，主要集中在落地细节和代码结构的调整上：

### 1. 核心改造一：Verdict 从单层判定改为双层判定
*   **意见：** 非常赞同。将 `provisional_verdict`（内部方向）和 `delivery_verdict`（对外结论）拆分，是解决“过早下定论”的关键。
*   **建议：** 在 `demo_agent/incidents/agent.py` 中，现有的 `_build_runtime_verdict` 确实容易导致状态过早锁定。我们需要在 `IncidentState` 中明确定义这两个字段。`provisional_verdict` 可以在每个事件循环的末尾更新，而 `delivery_verdict` 的状态提升必须严格依赖于 `readiness` 检查的结果。

### 2. 核心改造二与三：引入证据维度门禁与显式的 Readiness Checklist
*   **意见：** 这是 Plan 8 最具操作性的部分。目前的 `report_ready` 只是一个布尔值，缺乏可解释性。将其改造为 Checklist 能够极大地增强系统的稳健性。
*   **建议：** 
    *   在代码实现上，可以设计一个单独的 `ReadinessEvaluator` 类或函数群。
    *   **关于维度门禁**：像 `seed_direct_evidence`、`repeat_or_cluster` 这样的条件，不应仅仅是 Prompt 里的提示，而应在代码层面根据 `TraceStore` 中的结构化数据进行硬编码校验。
    *   **关于 Checklist**：在 `incident.json` 中，`readiness.checks` 必须详细记录每项检查未通过的 `reason`，这对于生成 `needs_review` 的报告至关重要。

### 3. 核心改造四：将 Counterevidence 检查变成显式动作
*   **意见：** 这是提升系统专业度的关键。很多误报（如备份流量、扫描器）正是因为缺乏反证检查而被误判为真实攻击。
*   **建议：** 
    *   在 Agent 的动作空间（Tool/Action Space）中，不需要新增底层工具，而是需要新增高阶意图（Intent）。例如，当 LLM 规划下一步时，它可以选择一个名为 `Intention.CHECK_COUNTEREVIDENCE` 的动作，然后映射到具体的搜索或本地库查询工具。
    *   在 Trace 日志中，必须显式记录“开始反证检查”阶段，即使没有找到反证，也要记录“检查过但未发现”，以满足 Readiness 的条件。

### 4. 核心改造五：证据的 Provenance 与等级
*   **意见：** 解决报告“虚胖”和“幻觉”的核心。目前混淆了外部事实和内部总结。
*   **建议：** 
    *   对于 `Observation` 模型，必须增加 `provenance` 和 `evidence_level` 字段。
    *   这会影响到 `demo_agent/tools/exploration.py` 中的 `extract_claim...` 函数族。当我们从网页提取 claim 时，必须打上 `page_content` 标签；当我们对事件进行总结时，打上 `internal_digest` 标签。
    *   在最终渲染报告（特别是确定性渲染层）时，必须过滤或降权 `internal_digest` 类型的证据，不能将其作为“直接证据”列出。

### 5. 核心改造五点五：报告生成分层
*   **意见：** 极其重要。彻底将**事实组织**与**语言润色**解耦，是保证安全产品交付质量的红线。
*   **建议：**
    *   目前的 `demo_agent/incidents/render.py` 需要重构。
    *   链路必须是：`incident.json` -> 纯代码生成的 `report_outline.json` -> 纯代码渲染的 `deterministic_report.md`。
    *   如果需要 LLM 润色，必须明确 Prompt 约束：“你只能调整句式、合并冗余，绝不能修改、增加或删除任何实体（IP、域名、恶意软件家族）和定性结论”。

### 6. 关于 Reviewer Agent 的看法
*   **意见：** 同意 Plan 8 的保守策略，先做好单 Agent 的收敛，将 Reviewer 作为未来的扩展。
*   **建议：** 如果未来引入 Reviewer，它应该更像一个 CI/CD 里的 Lint/Gatekeeper 节点，而不是一个并行的参与者。它只做 Yes/No 的判断，并给出具体的 Block 理由（基于 Readiness Checklist），由主 Agent 根据理由决定是否继续查或直接输出 `needs_review`。

### 总结
Plan 8 的核心是 **“收敛、校准与可解释性”**。我建议我们的重构路径（分阶段落地顺序）非常合理，第一步（Phase 1: 改 verdict 和 readiness）和第二步（Phase 2: 改 provenance 和 counterevidence）是当务之急，可以先从修改 `IncidentState` 模型和 `agent.py` 的核心循环逻辑开始。
