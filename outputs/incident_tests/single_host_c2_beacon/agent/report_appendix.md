# 事件调查技术附录

## 1. 技术时间线

| 时间 | 事件 | 作用 | 观测引用 |
| -- | -- | -- | -- |
| 2026-03-29 09:12:10 UTC | Rare DNS lookup for domain later reused by the seed alert. | `主证据` | obs-001, obs-002, obs-003 |
| 2026-03-29 09:14:40 UTC | Outbound TLS session to rare external infra using the same JA4 fingerprint as the seed event. | `主证据` | obs-001, obs-002, obs-003 |
| 2026-03-29 09:15:00 UTC | Seed JA4 alert matched a known beacon-style fingerprint. | `种子告警` | obs-001, obs-002, obs-003 |
| 2026-03-29 09:21:05 UTC | Second outbound TLS session to the same external infrastructure after the seed alert. | `主证据` | obs-001, obs-002, obs-003 |
| 2026-03-29 09:27:20 UTC | Another periodic outbound connection to a sibling domain on the same external IP. | `主证据` | 未引用 |
| 2026-03-29 09:30:00 UTC | Follow-up DNS resolution for a second suspicious domain on the same infrastructure. | `主证据` | 未引用 |
| 2026-03-29 09:45:10 UTC | Suspicious post-beacon process activity appeared on the same workstation after external communications started. | `执行线索` | 未引用 |
| 2026-03-29 09:48:00 UTC | Scheduled package update traffic during the same hour. | `反证` | obs-002, obs-003 |

## 2. 证据细目

### 2.1 主支撑证据

#### 证据 E-01
- **证据类别**：网络
- **证据强度**：高
- **事实描述**：在 2026-03-29 09:15:00 UTC，资产 `ws-finance-23` 出现了一条告警观测，关联的核心指示物为 198.51.100.24 / cdn-sync-update.com / JA4 t12i190700_d83cc789557e_16bbda4055b2。 原始摘要显示：Seed JA4 alert matched a known beacon-style fingerprint.
- **为什么支持当前主假设**：这是种子命中的直接落点，说明告警并不是孤立的指纹命中。
- **局限性与边界**：单条种子命中本身不能独立证明事件成立，仍需要结合重复通信、资产背景或主机侧线索共同定性。
- **观测引用**：`obs-001, obs-002, obs-003`

#### 证据 E-02
- **证据类别**：网络
- **证据强度**：高
- **事实描述**：在 2026-03-29 09:12:10 UTC，资产 `ws-finance-23` 出现了一条DNS观测，关联的核心指示物为 cdn-sync-update.com / DNS answers 198.51.100.24。 原始摘要显示：Rare DNS lookup for domain later reused by the seed alert.
- **为什么支持当前主假设**：它给出了可疑外联之前的解析准备动作，说明相关基础设施不是只在告警瞬间出现。
- **局限性与边界**：仅凭网络侧重复通信仍可能在少数情况下被正常组件、同步组件或运维脚本解释，因此仍需要结合资产背景或主机侧结果。
- **观测引用**：`obs-001, obs-002, obs-003`

#### 证据 E-03
- **证据类别**：网络
- **证据强度**：高
- **事实描述**：在 2026-03-29 09:14:40 UTC，资产 `ws-finance-23` 出现了一条网络流量观测，关联的核心指示物为 198.51.100.24 / cdn-sync-update.com / JA4 t12i190700_d83cc789557e_16bbda4055b2。 原始摘要显示：Outbound TLS session to rare external infra using the same JA4 fingerprint as the seed event.
- **为什么支持当前主假设**：同一资产围绕同一批外部基础设施再次通信，单条告警已经扩展成连续事件链。
- **局限性与边界**：仅凭网络侧重复通信仍可能在少数情况下被正常组件、同步组件或运维脚本解释，因此仍需要结合资产背景或主机侧结果。
- **观测引用**：`obs-001, obs-002, obs-003`

#### 证据 E-04
- **证据类别**：网络
- **证据强度**：高
- **事实描述**：在 2026-03-29 09:21:05 UTC，资产 `ws-finance-23` 出现了一条网络流量观测，关联的核心指示物为 198.51.100.24 / cdn-sync-update.com。 原始摘要显示：Second outbound TLS session to the same external infrastructure after the seed alert.
- **为什么支持当前主假设**：同一资产围绕同一批外部基础设施再次通信，单条告警已经扩展成连续事件链。
- **局限性与边界**：仅凭网络侧重复通信仍可能在少数情况下被正常组件、同步组件或运维脚本解释，因此仍需要结合资产背景或主机侧结果。
- **观测引用**：`obs-001, obs-002, obs-003`

### 2.2 反证与替代解释

#### 证据 C-01
- **反证或替代解释类别**：网络
- **证据强度**：高
- **相关事实**：在 2026-03-29 09:48:00 UTC，资产 `ws-finance-23` 出现了一条网络流量观测，关联的核心指示物为 203.0.113.10 / packages.vendor.example。 原始摘要显示：Scheduled package update traffic during the same hour.
- **为什么它提示了替代解释，或为什么它不足以推翻主结论**：这条记录更接近计划内维护或正常更新背景，是当前能够降级或收窄判断的重要原因。
- **边界与后续关注点**：这类背景解释能够帮助收窄判断，但如果后续出现脱离基线的重复通信、执行线索或跨资产异常，它本身并不能永久关闭事件。
- **观测引用**：`obs-002, obs-003`

### 2.3 背景情报与家族上下文（可选）
- **相关家族/工具提示**：Possible Cobalt Strike beacon
- **背景情报摘要**：当前可获得的背景提示主要来自 seed 告警自带的家族/工具描述：Possible Cobalt Strike beacon。它与本案已经观察到的阶段形态 命令与控制、执行 基本一致，更适合作为解释当前事件链的辅助背景。
- **不能据此直接推出的结论**：这类背景提示的价值在于帮助理解攻击链或工具形态，而不是直接完成家族归因、攻击团伙归因或样本级确认。
- **观测引用 / 来源引用**：`obs-003, obs-004`

## 3. IOC / IOA 清单

| 类型 | 值 | 与本案关系 |
| -- | -- | -- |
| IP | 198.51.100.24 | 事件中的核心外部基础设施 |
| IP | 203.0.113.10 | 事件中的关联外部地址 |
| 域名 | cdn-sync-update.com | 种子告警前后持续出现的关联域名 |
| 域名 | api.telemetry-sync.net | 种子告警前后持续出现的关联域名 |
| 域名 | packages.vendor.example | 事件中的关联域名 |
| JA4 | t12i190700_d83cc789557e_16bbda4055b2 | 种子告警命中的关键指纹 |

## 4. 观测引用对照

| 观测编号 | 来源工具 | 来源类型 | 摘要 |
| -- | -- | -- | -- |
| `obs-001` | `search_seed_context` | `trace_store.seed_context` | 检索到 6 条偏可疑事件，围绕 cdn-sync-update.com、api.telemetry-sync.net、198.51.100.24 展开。 |
| `obs-002` | `search_related_events` | `trace_store.related_events` | 检索到 7 条偏可疑事件，围绕 cdn-sync-update.com、api.telemetry-sync.net、198.51.100.24 展开。 |
| `obs-003` | `check_counterevidence` | `trace_store.asset_context` | 显式反证检查发现 1 条更接近维护、更新、补丁或备份背景的事件。 |
| `obs-004` | `extract_claim_candidates_from_page` | `internal_digest` | 从内部调查摘要中整理出 8 条 claim，用于结构化报告而不是新增外部证据。 |
