# 事件调查技术附录

## 1. 技术时间线

| 时间 | 事件 | 作用 | 观测引用 |
| -- | -- | -- | -- |
| 2026-05-18 08:55:00 UTC | The seed workstation resolved a rare domain later reused by the beacon alert. | `主证据` | obs-001, obs-002, obs-003 |
| 2026-05-18 09:00:00 UTC | Seed JA4 alert matched a beacon against the same rare external infrastructure. | `种子告警` | obs-001, obs-002, obs-003 |
| 2026-05-18 09:06:20 UTC | The seed workstation reconnected to the same C2 infrastructure after the alert. | `主证据` | obs-001, obs-002, obs-003 |
| 2026-05-18 09:11:30 UTC | PsExec remote service creation from ws-eng-02 to ws-eng-05 was observed after beaconing started. | `主证据` | obs-001, obs-002, obs-003 |
| 2026-05-18 09:18:00 UTC | A second workstation contacted the same external C2 infrastructure using the same pattern. | `主证据` | 未引用 |
| 2026-05-18 09:24:00 UTC | WMI lateral movement from ws-eng-05 to ws-eng-09 followed the shared beacon traffic. | `主证据` | 未引用 |
| 2026-05-18 09:31:00 UTC | A third workstation contacted the same C2 after the lateral movement chain. | `主证据` | 未引用 |

## 2. 证据细目

### 2.1 主支撑证据

#### 证据 E-01
- **证据类别**：网络
- **证据强度**：高
- **事实描述**：在 2026-05-18 09:00:00 UTC，资产 `ws-eng-02` 出现了一条告警观测，关联的核心指示物为 203.0.113.77 / sync-cdn-notify.net / JA4 t13d1516h2_2ba4190accc0_13fe129f5abc。 原始摘要显示：Seed JA4 alert matched a beacon against the same rare external infrastructure.
- **为什么支持当前主假设**：这是种子命中的直接落点，说明告警并不是孤立的指纹命中。
- **局限性与边界**：单条种子命中本身不能独立证明事件成立，仍需要结合重复通信、资产背景或主机侧线索共同定性。
- **观测引用**：`obs-001, obs-002, obs-003`

#### 证据 E-02
- **证据类别**：网络
- **证据强度**：高
- **事实描述**：在 2026-05-18 08:55:00 UTC，资产 `ws-eng-02` 出现了一条DNS观测，关联的核心指示物为 sync-cdn-notify.net / DNS answers 203.0.113.77。 原始摘要显示：The seed workstation resolved a rare domain later reused by the beacon alert.
- **为什么支持当前主假设**：它给出了可疑外联之前的解析准备动作，说明相关基础设施不是只在告警瞬间出现。
- **局限性与边界**：仅凭网络侧重复通信仍可能在少数情况下被正常组件、同步组件或运维脚本解释，因此仍需要结合资产背景或主机侧结果。
- **观测引用**：`obs-001, obs-002, obs-003`

#### 证据 E-03
- **证据类别**：网络
- **证据强度**：高
- **事实描述**：在 2026-05-18 09:06:20 UTC，资产 `ws-eng-02` 出现了一条网络流量观测，关联的核心指示物为 203.0.113.77 / sync-cdn-notify.net。 原始摘要显示：The seed workstation reconnected to the same C2 infrastructure after the alert.
- **为什么支持当前主假设**：同一资产围绕同一批外部基础设施再次通信，单条告警已经扩展成连续事件链。
- **局限性与边界**：仅凭网络侧重复通信仍可能在少数情况下被正常组件、同步组件或运维脚本解释，因此仍需要结合资产背景或主机侧结果。
- **观测引用**：`obs-001, obs-002, obs-003`

#### 证据 E-04
- **证据类别**：网络
- **证据强度**：高
- **事实描述**：在 2026-05-18 09:11:30 UTC，资产 `ws-eng-02` 出现了一条告警观测，关联的核心指示物为 10.70.3.45。 原始摘要显示：PsExec remote service creation from ws-eng-02 to ws-eng-05 was observed after beaconing started.
- **为什么支持当前主假设**：同一资产围绕同一批外部基础设施再次通信，单条告警已经扩展成连续事件链。
- **局限性与边界**：仅凭网络侧重复通信仍可能在少数情况下被正常组件、同步组件或运维脚本解释，因此仍需要结合资产背景或主机侧结果。
- **观测引用**：`obs-001, obs-002, obs-003`

### 2.2 反证与替代解释
- 当前没有足以改变结论方向的强反证，但这并不意味着后续可以省略背景核查。

### 2.3 背景情报与家族上下文（可选）
- **相关家族/工具提示**：Possible internal spread beacon
- **背景情报摘要**：当前可获得的背景提示主要来自 seed 告警自带的家族/工具描述：Possible internal spread beacon。它与本案已经观察到的阶段形态 命令与控制、横向移动 基本一致，更适合作为解释当前事件链的辅助背景。
- **不能据此直接推出的结论**：这类背景提示的价值在于帮助理解攻击链或工具形态，而不是直接完成家族归因、攻击团伙归因或样本级确认。
- **观测引用 / 来源引用**：`obs-003, obs-005`

## 3. IOC / IOA 清单

| 类型 | 值 | 与本案关系 |
| -- | -- | -- |
| IP | 203.0.113.77 | 事件中的核心外部基础设施 |
| IP | 10.70.3.45 | 事件中的核心外部基础设施 |
| IP | 10.70.3.90 | 事件中的核心外部基础设施 |
| 域名 | sync-cdn-notify.net | 种子告警前后持续出现的关联域名 |
| JA4 | t13d1516h2_2ba4190accc0_13fe129f5abc | 种子告警命中的关键指纹 |

## 4. 观测引用对照

| 观测编号 | 来源工具 | 来源类型 | 摘要 |
| -- | -- | -- | -- |
| `obs-001` | `search_seed_context` | `trace_store.seed_context` | 检索到 5 条偏可疑事件，围绕 sync-cdn-notify.net、203.0.113.77、10.70.3.45 展开。 |
| `obs-002` | `search_related_events` | `trace_store.related_events` | 检索到 7 条偏可疑事件，围绕 sync-cdn-notify.net、203.0.113.77、10.70.3.45 展开。 |
| `obs-003` | `check_counterevidence` | `trace_store.asset_context` | 显式反证检查覆盖了 7 条同资产上下文，未发现足以降级当前判断的明确背景解释。 |
| `obs-004` | `expand_asset_scope` | `trace_store.asset_context` | 检索到 3 条偏可疑事件，围绕 sync-cdn-notify.net、203.0.113.77、10.70.3.90 展开。 |
| `obs-005` | `extract_claim_candidates_from_page` | `internal_digest` | 从内部调查摘要中整理出 8 条 claim，用于结构化报告而不是新增外部证据。 |
