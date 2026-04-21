# 事件级溯源报告

## 1. 执行摘要
- **事件结论**：确认事件
- **当前状态**：`confirmed`
- **严重度**：高危
- **置信度**：94
- **一句话摘要**：最小上下文和扩展事件簇都显示该资产与同一批外部基础设施发生重复通信，已经具备 C2 / beacon 事件特征。
- **建议立即执行的动作**：优先隔离或重点监控资产：web-app-01。

## 2. 事件范围与边界
- **Seed alert / 起点**：2026-05-11 14:12:00，web-app-01 命中 Possible web-shell beacon JA4 规则。
- **时间窗口**：2026-05-11 14:02:00 UTC 至 2026-05-11 14:23:00 UTC
- **种子资产**：web-app-01
- **疑似受影响资产**：web-app-01
- **内部 IP**：10.60.1.14
- **外部 IP**：198.51.100.88
- **域名**：cdn-auth-check.net
- **当前攻击阶段**：initial-access、command-and-control、execution
- **事件规模**：事件簇 5 条，主支撑事件 5 条，待解释关联事件 0 条，反证/背景事件 0 条。
- **核心外部指示物**：198.51.100.88、cdn-auth-check.net
- **当前事件边界**：当前自动化判断把事件边界收敛在 web-app-01 上，已经足以把本案从单条告警提升为已成立事件，但尚未确认存在更大范围扩散。

## 3. 核心时间线

| 时间 | 事件 | 作用 | 观测引用 |
| -- | -- | -- | -- |
| 2026-05-11 14:02:00 UTC | Public-facing web server received suspicious exploit requests against the login endpoint before external TLS traffic began. | `支撑证据` | obs-001, obs-002 |
| 2026-05-11 14:07:30 UTC | The web server resolved a rare domain shortly after the exploit attempts. | `主证据` | obs-001, obs-002 |
| 2026-05-11 14:12:00 UTC | Seed JA4 alert matched a possible web-shell beacon over TLS. | `种子告警` | obs-001, obs-002 |
| 2026-05-11 14:18:10 UTC | The same web server reconnected to the same external infrastructure after the seed alert. | `主证据` | obs-001, obs-002 |
| 2026-05-11 14:23:00 UTC | PowerShell launcher executed under w3wp after suspicious outbound TLS traffic began. | `执行线索` | 未引用 |

## 4. 核心证据链

### 4.1 主支撑证据

#### 证据 E-01
- **证据类别**：网络
- **证据强度**：高
- **事实描述**：在 2026-05-11 14:12:00 UTC，资产 `web-app-01` 出现了一条告警观测，关联的核心指示物为 198.51.100.88 / cdn-auth-check.net / JA4 t13d1517h2_91adbe210bc1_7cae1281e991。 原始摘要显示：Seed JA4 alert matched a possible web-shell beacon over TLS.
- **为什么支持当前主假设**：这是种子命中的直接落点，说明告警并不是孤立的指纹命中。
- **局限性与边界**：单条种子命中本身不能独立证明事件成立，仍需要结合重复通信、资产背景或主机侧线索共同定性。
- **观测引用**：`obs-001, obs-002`

#### 证据 E-02
- **证据类别**：网络
- **证据强度**：高
- **事实描述**：在 2026-05-11 14:07:30 UTC，资产 `web-app-01` 出现了一条DNS观测，关联的核心指示物为 cdn-auth-check.net / DNS answers 198.51.100.88。 原始摘要显示：The web server resolved a rare domain shortly after the exploit attempts.
- **为什么支持当前主假设**：它给出了可疑外联之前的解析准备动作，说明相关基础设施不是只在告警瞬间出现。
- **局限性与边界**：仅凭网络侧重复通信仍可能在少数情况下被正常组件、同步组件或运维脚本解释，因此仍需要结合资产背景或主机侧结果。
- **观测引用**：`obs-001, obs-002`

#### 证据 E-03
- **证据类别**：网络
- **证据强度**：高
- **事实描述**：在 2026-05-11 14:18:10 UTC，资产 `web-app-01` 出现了一条网络流量观测，关联的核心指示物为 198.51.100.88 / cdn-auth-check.net。 原始摘要显示：The same web server reconnected to the same external infrastructure after the seed alert.
- **为什么支持当前主假设**：同一资产围绕同一批外部基础设施再次通信，单条告警已经扩展成连续事件链。
- **局限性与边界**：仅凭网络侧重复通信仍可能在少数情况下被正常组件、同步组件或运维脚本解释，因此仍需要结合资产背景或主机侧结果。
- **观测引用**：`obs-001, obs-002`

#### 证据 E-04
- **证据类别**：网络
- **证据强度**：高
- **事实描述**：在 2026-05-11 14:02:00 UTC，资产 `web-app-01` 出现了一条告警观测。 原始摘要显示：Public-facing web server received suspicious exploit requests against the login endpoint before external TLS traffic began.
- **为什么支持当前主假设**：它补足了种子告警周围的上下文。
- **局限性与边界**：它解释了事件为何进入高风险状态，但单独仍不能证明漏洞利用已经成功执行。
- **观测引用**：`obs-001, obs-002`

### 4.2 反证与替代解释
- 当前没有足以改变结论方向的强反证，但这并不意味着后续可以省略背景核查。

### 4.3 背景情报与家族上下文（可选）
- **相关家族/工具提示**：Possible web-shell beacon
- **背景情报摘要**：当前可获得的背景提示主要来自 seed 告警自带的家族/工具描述：Possible web-shell beacon。它与本案已经观察到的阶段形态 initial-access、command-and-control、execution 基本一致，更适合作为解释当前事件链的辅助背景。
- **不能据此直接推出的结论**：这类背景提示的价值在于帮助理解攻击链或工具形态，而不是直接完成家族归因、攻击团伙归因或样本级确认。
- **观测引用 / 来源引用**：`obs-003`

## 5. 综合研判
- **主假设**：web-app-01 疑似 Possible web-shell beacon 相关事件
- **备选解释**：围绕 198.51.100.88、cdn-auth-check.net 的通信可能存在正常背景解释
- **为什么当前结论成立**：决策主要建立在种子告警后的重复外联、同基础设施复现以及后续执行线索之上。 web-app-01 先围绕 198.51.100.88、cdn-auth-check.net 形成重复外联，随后又出现主机侧执行痕迹，因此判断已经超过单点命中。 事件簇已经出现连续恶意外联或主机侧异常，足以支撑事件成立。 seed alert 自带家族/工具提示：Possible web-shell beacon。
- **为什么没有升级或为什么没有降级**：当前已经足够升级为确认事件，但还没有证据支持把事件范围直接扩大到明确扩散或明确数据外传。

## 6. 处置建议

### 6.1 立即动作（0 到 2 小时）
- [HIGH] 优先隔离或重点监控资产：web-app-01。
- [HIGH] 在边界和代理设备上排查并封禁外部基础设施：198.51.100.88、cdn-auth-check.net。

### 6.2 短期排查（24 小时内）
- [MEDIUM] 以 seed 指标和事件簇中的域名 / IP 为 pivot，继续检索同时间窗内的重复通信。

## 7. 附录

### 7.1 IOC / IOA 清单

| 类型 | 值 | 与本案关系 |
| -- | -- | -- |
| IP | 198.51.100.88 | 事件中的核心外部基础设施 |
| 域名 | cdn-auth-check.net | 种子告警前后持续出现的关联域名 |
| JA4 | t13d1517h2_91adbe210bc1_7cae1281e991 | 种子告警命中的关键指纹 |

### 7.2 观测引用对照

| 观测编号 | 来源工具 | 摘要 |
| -- | -- | -- |
| `obs-001` | `search_seed_context` | 检索到 5 条偏可疑事件，围绕 cdn-auth-check.net、198.51.100.88 展开。 |
| `obs-002` | `search_related_events` | 检索到 5 条偏可疑事件，围绕 cdn-auth-check.net、198.51.100.88 展开。 |
| `obs-003` | `extract_claim_candidates_from_page` | 从当前事件摘要中抽取出 7 条可直接引用的 claim。 |
