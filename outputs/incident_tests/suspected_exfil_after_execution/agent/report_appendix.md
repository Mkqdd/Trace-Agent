# 事件调查技术附录

## 1. 技术时间线

| 时间 | 事件 | 作用 | 观测引用 |
| -- | -- | -- | -- |
| 2026-06-03 16:34:00 UTC | The workstation resolved a rare storage domain shortly before the seed alert fired. | `上下文` | 未引用 |
| 2026-06-03 16:40:00 UTC | Seed JA4 alert observed a suspicious TLS session to a rare storage edge. | `种子告警` | obs-001, obs-002, obs-003 |
| 2026-06-03 16:44:00 UTC | Archive utility spawned on the workstation shortly before the outbound transfer. | `执行线索` | obs-001, obs-002, obs-003 |
| 2026-06-03 16:47:00 UTC | A large outbound HTTPS upload followed the archive creation, but DLP visibility is incomplete. | `支撑证据` | obs-001, obs-002, obs-003 |
| 2026-06-03 17:05:00 UTC | A second workstation briefly connected to the same storage edge, but only once and without host evidence. | `上下文` | 未引用 |

## 2. 证据细目

### 2.1 主支撑证据

#### 证据 E-01
- **证据类别**：网络
- **证据强度**：高
- **事实描述**：在 2026-06-03 16:40:00 UTC，资产 `ws-rnd-04` 出现了一条告警观测，关联的核心指示物为 198.51.100.144 / files-sync-share.net / JA4 t13d190900_44ac2200b3c1_ab11cd22ee44。 原始摘要显示：Seed JA4 alert observed a suspicious TLS session to a rare storage edge.
- **为什么支持当前主假设**：这是种子命中的直接落点，说明告警并不是孤立的指纹命中。
- **局限性与边界**：单条种子命中本身不能独立证明事件成立，仍需要结合重复通信、资产背景或主机侧线索共同定性。
- **观测引用**：`obs-001, obs-002, obs-003`

#### 证据 E-02
- **证据类别**：主机
- **证据强度**：高
- **事实描述**：在 2026-06-03 16:44:00 UTC，资产 `ws-rnd-04` 出现了一条告警观测。 原始摘要显示：Archive utility spawned on the workstation shortly before the outbound transfer.
- **为什么支持当前主假设**：这条记录把可疑外联推进到了主机侧执行层，显著提高了事件成立概率。
- **局限性与边界**：当前仍缺少更细的命令行、落地文件、持久化或内存证据，因此可以确认存在执行线索，但还不能完整描述具体载荷。
- **观测引用**：`obs-001, obs-002, obs-003`

#### 证据 E-03
- **证据类别**：网络
- **证据强度**：中
- **事实描述**：在 2026-06-03 16:47:00 UTC，资产 `ws-rnd-04` 出现了一条网络流量观测，关联的核心指示物为 198.51.100.144 / files-sync-share.net。 原始摘要显示：A large outbound HTTPS upload followed the archive creation, but DLP visibility is incomplete.
- **为什么支持当前主假设**：它强调了这批外部基础设施在当前环境中的稀有性。
- **局限性与边界**：这条观测本身更适合用来补足上下文，而不是单独承担最终结论。
- **观测引用**：`obs-001, obs-002, obs-003`

### 2.2 反证与替代解释
- 当前没有足以改变结论方向的强反证，但这并不意味着后续可以省略背景核查。

### 2.3 背景情报与家族上下文（可选）
- **相关家族/工具提示**：Possible cloud-storage exfil candidate
- **背景情报摘要**：当前可获得的背景提示主要来自 seed 告警自带的家族/工具描述：Possible cloud-storage exfil candidate。它与本案已经观察到的阶段形态 执行、数据外传 基本一致，更适合作为解释当前事件链的辅助背景。
- **不能据此直接推出的结论**：这类背景提示的价值在于帮助理解攻击链或工具形态，而不是直接完成家族归因、攻击团伙归因或样本级确认。
- **观测引用 / 来源引用**：`obs-003, obs-005`

## 3. IOC / IOA 清单

| 类型 | 值 | 与本案关系 |
| -- | -- | -- |
| IP | 198.51.100.144 | 事件中的核心外部基础设施 |
| 域名 | files-sync-share.net | 种子告警前后持续出现的关联域名 |
| JA4 | t13d190900_44ac2200b3c1_ab11cd22ee44 | 种子告警命中的关键指纹 |
| 行为线索 | Archive utility spawned on the workstation shortly before the outbound transfer. | 执行阶段的重要主机侧线索 |

## 4. 观测引用对照

| 观测编号 | 来源工具 | 来源类型 | 摘要 |
| -- | -- | -- | -- |
| `obs-001` | `search_seed_context` | `trace_store.seed_context` | 检索到 3 条偏可疑事件，围绕 files-sync-share.net、198.51.100.144 展开。 |
| `obs-002` | `search_related_events` | `trace_store.related_events` | 检索到 3 条偏可疑事件，围绕 files-sync-share.net、198.51.100.144 展开。 |
| `obs-003` | `check_counterevidence` | `trace_store.asset_context` | 显式反证检查覆盖了 5 条同资产上下文，未发现足以降级当前判断的明确背景解释。 |
| `obs-004` | `expand_asset_scope` | `trace_store.asset_context` | 检索到 1 条上下文事件，当前主要用于扩边界和补足范围。 |
| `obs-005` | `extract_claim_candidates_from_page` | `internal_digest` | 从内部调查摘要中整理出 6 条 claim，用于结构化报告而不是新增外部证据。 |
