# 事件调查技术附录

## 1. 技术时间线

| 时间 | 事件 | 作用 | 观测引用 |
| -- | -- | -- | -- |
| 2026-05-11 14:02:00 UTC | Public-facing web server received suspicious exploit requests against the login endpoint before external TLS traffic began. | `支撑证据` | obs-001, obs-002, obs-003 |
| 2026-05-11 14:07:30 UTC | The web server resolved a rare domain shortly after the exploit attempts. | `主证据` | obs-001, obs-002, obs-003 |
| 2026-05-11 14:12:00 UTC | Seed JA4 alert matched a possible web-shell beacon over TLS. | `种子告警` | obs-001, obs-002, obs-003 |
| 2026-05-11 14:18:10 UTC | The same web server reconnected to the same external infrastructure after the seed alert. | `主证据` | obs-001, obs-002, obs-003 |
| 2026-05-11 14:23:00 UTC | PowerShell launcher executed under w3wp after suspicious outbound TLS traffic began. | `执行线索` | 未引用 |

## 2. 证据细目

### 2.1 主支撑证据

#### 证据 E-01
- **证据类别**：网络
- **证据强度**：高
- **事实描述**：在 2026-05-11 14:12:00 UTC，资产 `web-app-01` 出现了一条告警观测，关联的核心指示物为 198.51.100.88 / cdn-auth-check.net / JA4 t13d1517h2_91adbe210bc1_7cae1281e991。 原始摘要显示：Seed JA4 alert matched a possible web-shell beacon over TLS.
- **为什么支持当前主假设**：这是种子命中的直接落点，说明告警并不是孤立的指纹命中。
- **局限性与边界**：单条种子命中本身不能独立证明事件成立，仍需要结合重复通信、资产背景或主机侧线索共同定性。
- **观测引用**：`obs-001, obs-002, obs-003`

#### 证据 E-02
- **证据类别**：网络
- **证据强度**：高
- **事实描述**：在 2026-05-11 14:07:30 UTC，资产 `web-app-01` 出现了一条DNS观测，关联的核心指示物为 cdn-auth-check.net / DNS answers 198.51.100.88。 原始摘要显示：The web server resolved a rare domain shortly after the exploit attempts.
- **为什么支持当前主假设**：它给出了可疑外联之前的解析准备动作，说明相关基础设施不是只在告警瞬间出现。
- **局限性与边界**：仅凭网络侧重复通信仍可能在少数情况下被正常组件、同步组件或运维脚本解释，因此仍需要结合资产背景或主机侧结果。
- **观测引用**：`obs-001, obs-002, obs-003`

#### 证据 E-03
- **证据类别**：网络
- **证据强度**：高
- **事实描述**：在 2026-05-11 14:18:10 UTC，资产 `web-app-01` 出现了一条网络流量观测，关联的核心指示物为 198.51.100.88 / cdn-auth-check.net。 原始摘要显示：The same web server reconnected to the same external infrastructure after the seed alert.
- **为什么支持当前主假设**：同一资产围绕同一批外部基础设施再次通信，单条告警已经扩展成连续事件链。
- **局限性与边界**：仅凭网络侧重复通信仍可能在少数情况下被正常组件、同步组件或运维脚本解释，因此仍需要结合资产背景或主机侧结果。
- **观测引用**：`obs-001, obs-002, obs-003`

#### 证据 E-04
- **证据类别**：网络
- **证据强度**：高
- **事实描述**：在 2026-05-11 14:02:00 UTC，资产 `web-app-01` 出现了一条告警观测。 原始摘要显示：Public-facing web server received suspicious exploit requests against the login endpoint before external TLS traffic began.
- **为什么支持当前主假设**：它补足了种子告警周围的上下文。
- **局限性与边界**：它解释了事件为何进入高风险状态，但单独仍不能证明漏洞利用已经成功执行。
- **观测引用**：`obs-001, obs-002, obs-003`

### 2.2 反证与替代解释
- 当前没有足以改变结论方向的强反证，但这并不意味着后续可以省略背景核查。

### 2.3 背景情报与家族上下文（可选）
- **相关家族/工具提示**：Possible web-shell beacon
- **背景情报摘要**：当前可获得的背景提示主要来自 seed 告警自带的家族/工具描述：Possible web-shell beacon。它与本案已经观察到的阶段形态 初始访问、命令与控制、执行 基本一致，更适合作为解释当前事件链的辅助背景。
- **不能据此直接推出的结论**：这类背景提示的价值在于帮助理解攻击链或工具形态，而不是直接完成家族归因、攻击团伙归因或样本级确认。
- **观测引用 / 来源引用**：`obs-003, obs-004`

## 3. IOC / IOA 清单

| 类型 | 值 | 与本案关系 |
| -- | -- | -- |
| IP | 198.51.100.88 | 事件中的核心外部基础设施 |
| 域名 | cdn-auth-check.net | 种子告警前后持续出现的关联域名 |
| JA4 | t13d1517h2_91adbe210bc1_7cae1281e991 | 种子告警命中的关键指纹 |

## 4. 观测引用对照

| 观测编号 | 来源工具 | 来源类型 | 摘要 |
| -- | -- | -- | -- |
| `obs-001` | `search_seed_context` | `trace_store.seed_context` | 检索到 5 条偏可疑事件，围绕 cdn-auth-check.net、198.51.100.88 展开。 |
| `obs-002` | `search_related_events` | `trace_store.related_events` | 检索到 5 条偏可疑事件，围绕 cdn-auth-check.net、198.51.100.88 展开。 |
| `obs-003` | `check_counterevidence` | `trace_store.asset_context` | 显式反证检查覆盖了 5 条同资产上下文，未发现足以降级当前判断的明确背景解释。 |
| `obs-004` | `extract_claim_candidates_from_page` | `internal_digest` | 从内部调查摘要中整理出 7 条 claim，用于结构化报告而不是新增外部证据。 |
