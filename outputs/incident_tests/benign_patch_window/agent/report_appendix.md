# 事件调查技术附录

## 1. 技术时间线

| 时间 | 事件 | 作用 | 观测引用 |
| -- | -- | -- | -- |
| 2026-04-02 01:55:00 UTC | Host entered the scheduled monthly patch window controlled by the operations team. | `反证` | obs-001, obs-002, obs-003 |
| 2026-04-02 01:57:10 UTC | DNS query resolved the vendor update endpoint used during the patch window. | `反证` | obs-001, obs-002, obs-003 |
| 2026-04-02 02:00:00 UTC | Seed heuristic JA4 alert fired on update traffic during the patch window. | `种子告警` | obs-001, obs-002, obs-003 |
| 2026-04-02 02:01:30 UTC | Host downloaded a signed package manifest from the same vendor endpoint. | `反证` | obs-001, obs-002, obs-003 |
| 2026-04-02 02:05:00 UTC | Follow-up TLS session transferred the expected patch package. | `反证` | obs-001, obs-002, obs-003 |
| 2026-04-02 02:06:20 UTC | A sibling server contacted the same update endpoint in the same maintenance window. | `反证` | 未引用 |

## 2. 证据细目

### 2.1 主支撑证据

#### 证据 E-01
- **证据类别**：网络
- **证据强度**：高
- **事实描述**：在 2026-04-02 02:00:00 UTC，资产 `srv-ops-01` 出现了一条告警观测，关联的核心指示物为 203.0.113.50 / updates.vendor.example / JA4 t13d1516h2_1f8c0d19a111_39bb8eb7d001。 原始摘要显示：Seed heuristic JA4 alert fired on update traffic during the patch window.
- **为什么支持当前主假设**：这是种子命中的直接落点，说明告警并不是孤立的指纹命中。
- **局限性与边界**：单条种子命中本身不能独立证明事件成立，仍需要结合重复通信、资产背景或主机侧线索共同定性。
- **观测引用**：`obs-001, obs-002, obs-003`

### 2.2 反证与替代解释

#### 证据 C-01
- **反证或替代解释类别**：资产背景
- **证据强度**：高
- **相关事实**：在 2026-04-02 01:55:00 UTC，资产 `srv-ops-01` 出现了一条资产背景观测。 原始摘要显示：Host entered the scheduled monthly patch window controlled by the operations team.
- **为什么它提示了替代解释，或为什么它不足以推翻主结论**：这条记录更接近计划内维护或正常更新背景，是当前能够降级或收窄判断的重要原因。
- **边界与后续关注点**：这类背景解释能够帮助收窄判断，但如果后续出现脱离基线的重复通信、执行线索或跨资产异常，它本身并不能永久关闭事件。
- **观测引用**：`obs-001, obs-002, obs-003`

#### 证据 C-02
- **反证或替代解释类别**：网络
- **证据强度**：高
- **相关事实**：在 2026-04-02 01:57:10 UTC，资产 `srv-ops-01` 出现了一条DNS观测，关联的核心指示物为 updates.vendor.example / DNS answers 203.0.113.50。 原始摘要显示：DNS query resolved the vendor update endpoint used during the patch window.
- **为什么它提示了替代解释，或为什么它不足以推翻主结论**：这条记录更接近计划内维护或正常更新背景，是当前能够降级或收窄判断的重要原因。
- **边界与后续关注点**：这类背景解释能够帮助收窄判断，但如果后续出现脱离基线的重复通信、执行线索或跨资产异常，它本身并不能永久关闭事件。
- **观测引用**：`obs-001, obs-002, obs-003`

#### 证据 C-03
- **反证或替代解释类别**：网络
- **证据强度**：高
- **相关事实**：在 2026-04-02 02:01:30 UTC，资产 `srv-ops-01` 出现了一条HTTP观测，关联的核心指示物为 203.0.113.50 / updates.vendor.example。 原始摘要显示：Host downloaded a signed package manifest from the same vendor endpoint.
- **为什么它提示了替代解释，或为什么它不足以推翻主结论**：这条记录更接近计划内维护或正常更新背景，是当前能够降级或收窄判断的重要原因。
- **边界与后续关注点**：这类背景解释能够帮助收窄判断，但如果后续出现脱离基线的重复通信、执行线索或跨资产异常，它本身并不能永久关闭事件。
- **观测引用**：`obs-001, obs-002, obs-003`

#### 证据 C-04
- **反证或替代解释类别**：网络
- **证据强度**：高
- **相关事实**：在 2026-04-02 02:05:00 UTC，资产 `srv-ops-01` 出现了一条网络流量观测，关联的核心指示物为 203.0.113.50 / updates.vendor.example。 原始摘要显示：Follow-up TLS session transferred the expected patch package.
- **为什么它提示了替代解释，或为什么它不足以推翻主结论**：这条记录更接近计划内维护或正常更新背景，是当前能够降级或收窄判断的重要原因。
- **边界与后续关注点**：这类背景解释能够帮助收窄判断，但如果后续出现脱离基线的重复通信、执行线索或跨资产异常，它本身并不能永久关闭事件。
- **观测引用**：`obs-001, obs-002, obs-003`

## 3. IOC / IOA 清单

| 类型 | 值 | 与本案关系 |
| -- | -- | -- |
| IP | 203.0.113.50 | 事件中的核心外部基础设施 |
| 域名 | updates.vendor.example | 种子告警前后持续出现的关联域名 |
| JA4 | t13d1516h2_1f8c0d19a111_39bb8eb7d001 | 种子告警命中的关键指纹 |

## 4. 观测引用对照

| 观测编号 | 来源工具 | 来源类型 | 摘要 |
| -- | -- | -- | -- |
| `obs-001` | `search_seed_context` | `trace_store.seed_context` | 检索到 1 条偏可疑事件，围绕 updates.vendor.example、203.0.113.50 展开。 |
| `obs-002` | `search_related_events` | `trace_store.related_events` | 检索到 1 条偏可疑事件，围绕 updates.vendor.example、203.0.113.50 展开。 |
| `obs-003` | `check_counterevidence` | `trace_store.asset_context` | 显式反证检查发现 5 条更接近维护、更新、补丁或备份背景的事件。 |
| `obs-004` | `expand_asset_scope` | `trace_store.asset_context` | 检索到 1 条更接近维护、更新或正常基线的事件。 |
| `obs-005` | `extract_claim_candidates_from_page` | `internal_digest` | 从内部调查摘要中整理出 5 条 claim，用于结构化报告而不是新增外部证据。 |
