# 事件调查技术附录

以下内容主要供分析、复盘和技术排查使用，不直接替代主报告结论。

## 1. 技术时间线

| 时间 | 事件 | 作用 | 观测引用 |
| -- | -- | -- | -- |
| 2026-04-02 01:55:00 UTC | Host entered the scheduled monthly patch window controlled by the operations team. | `支撑证据` | 未引用 |
| 2026-04-02 01:57:10 UTC | DNS query resolved the vendor update endpoint used during the patch window. | `支撑证据` | 未引用 |
| 2026-04-02 02:00:00 UTC | Seed heuristic JA4 alert fired on update traffic during the patch window. | `种子告警` | obs-001, obs-002, obs-003 |
| 2026-04-02 02:01:30 UTC | Host downloaded a signed package manifest from the same vendor endpoint. | `支撑证据` | 未引用 |
| 2026-04-02 02:05:00 UTC | Follow-up TLS session transferred the expected patch package. | `支撑证据` | 未引用 |
| 2026-04-02 02:06:20 UTC | A sibling server contacted the same update endpoint in the same maintenance window. | `支撑证据` | 未引用 |

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
- 当前没有足以改变结论方向的强反证，但这并不意味着后续可以省略背景核查。

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
| `obs-002` | `search_related_events` | `trace_store.related_events` | 扩线检索到 1 条可疑关联事件，围绕 updates.vendor.example、203.0.113.50 展开；当前先作为待验证候选线索。 |
| `obs-003` | `check_counterevidence` | `trace_store.asset_context` | 显式反证检查发现 5 条更接近维护、更新、补丁或备份背景的事件。 |
| `obs-004` | `expand_asset_scope` | `trace_store.asset_context` | 检索到 1 条更接近维护、更新或正常基线的事件。 |
| `obs-005` | `local_intel_lookup` | `intel_tool` | 本地情报库未命中该指示物。 |
| `obs-006` | `vt_enrich_ioc` | `intel_tool` | VirusTotal 已查询该外部 IP，但未返回正向恶意检测。 |
| `obs-007` | `abuse_ch_lookup` | `intel_tool` | abuse.ch 聚合查询未命中结构化情报。 |
