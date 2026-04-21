# 事件调查技术附录

## 1. 技术时间线

| 时间 | 事件 | 作用 | 观测引用 |
| -- | -- | -- | -- |
| 2026-04-07 11:17:00 UTC | The seed workstation resolved a rare domain shortly before the JA4 alert fired. | `上下文` | 未引用 |
| 2026-04-07 11:20:00 UTC | Seed JA4 alert observed a suspicious TLS session to the same rare external infrastructure. | `种子告警` | obs-001, obs-002, obs-003 |
| 2026-04-07 11:24:00 UTC | The same workstation reconnected to the same external IP a few minutes after the seed alert. | `主证据` | obs-001, obs-002, obs-003 |
| 2026-04-07 11:46:00 UTC | A second workstation contacted a sibling domain on the same external IP, but there is still no endpoint corroboration. | `上下文` | 未引用 |
| 2026-04-07 11:50:00 UTC | The second workstation resolved another rare domain pointing to the same shared infrastructure. | `上下文` | 未引用 |

## 2. 证据细目

### 2.1 主支撑证据

#### 证据 E-01
- **证据类别**：网络
- **证据强度**：高
- **事实描述**：在 2026-04-07 11:20:00 UTC，资产 `ws-design-07` 出现了一条告警观测，关联的核心指示物为 198.51.100.66 / auth-sync-edge.net / JA4 t13d190900_44ae3120b3c1_909fe43ab981。 原始摘要显示：Seed JA4 alert observed a suspicious TLS session to the same rare external infrastructure.
- **为什么支持当前主假设**：这是种子命中的直接落点，说明告警并不是孤立的指纹命中。
- **局限性与边界**：单条种子命中本身不能独立证明事件成立，仍需要结合重复通信、资产背景或主机侧线索共同定性。
- **观测引用**：`obs-001, obs-002, obs-003`

#### 证据 E-02
- **证据类别**：网络
- **证据强度**：高
- **事实描述**：在 2026-04-07 11:24:00 UTC，资产 `ws-design-07` 出现了一条网络流量观测，关联的核心指示物为 198.51.100.66 / auth-sync-edge.net。 原始摘要显示：The same workstation reconnected to the same external IP a few minutes after the seed alert.
- **为什么支持当前主假设**：同一资产围绕同一批外部基础设施再次通信，单条告警已经扩展成连续事件链。
- **局限性与边界**：仅凭网络侧重复通信仍可能在少数情况下被正常组件、同步组件或运维脚本解释，因此仍需要结合资产背景或主机侧结果。
- **观测引用**：`obs-001, obs-002, obs-003`

### 2.2 反证与替代解释
- 当前没有足以改变结论方向的强反证，但这并不意味着后续可以省略背景核查。

## 3. IOC / IOA 清单

| 类型 | 值 | 与本案关系 |
| -- | -- | -- |
| IP | 198.51.100.66 | 事件中的核心外部基础设施 |
| 域名 | auth-sync-edge.net | 种子告警前后持续出现的关联域名 |
| 域名 | cdn-auth-sync.net | 事件中的关联域名 |
| JA4 | t13d190900_44ae3120b3c1_909fe43ab981 | 种子告警命中的关键指纹 |

## 4. 观测引用对照

| 观测编号 | 来源工具 | 来源类型 | 摘要 |
| -- | -- | -- | -- |
| `obs-001` | `search_seed_context` | `trace_store.seed_context` | 检索到 2 条偏可疑事件，围绕 auth-sync-edge.net、198.51.100.66 展开。 |
| `obs-002` | `search_related_events` | `trace_store.related_events` | 检索到 2 条偏可疑事件，围绕 auth-sync-edge.net、198.51.100.66 展开。 |
| `obs-003` | `check_counterevidence` | `trace_store.asset_context` | 显式反证检查覆盖了 5 条同资产上下文，未发现足以降级当前判断的明确背景解释。 |
| `obs-004` | `expand_asset_scope` | `trace_store.asset_context` | 检索到 2 条上下文事件，当前主要用于扩边界和补足范围。 |
| `obs-005` | `extract_claim_candidates_from_page` | `internal_digest` | 从内部调查摘要中整理出 4 条 claim，用于结构化报告而不是新增外部证据。 |
