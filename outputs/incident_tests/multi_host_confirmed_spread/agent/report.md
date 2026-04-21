# 事件级溯源报告

## 1. 执行摘要
- **事件结论**：确认事件
- **当前状态**：`confirmed`
- **严重度**：高危
- **置信度**：94
- **一句话摘要**：最小上下文和扩展事件簇都显示该资产与同一批外部基础设施发生重复通信，已经具备 C2 / beacon 事件特征。
- **建议立即执行的动作**：优先隔离或重点监控资产：ws-eng-02、ws-eng-05、ws-eng-09。

## 2. 事件范围与边界
- **Seed alert / 起点**：2026-05-18 09:00:00，ws-eng-02 命中 Possible internal spread beacon JA4 规则。
- **时间窗口**：2026-05-18 08:55:00 UTC 至 2026-05-18 09:31:00 UTC
- **种子资产**：ws-eng-02
- **疑似受影响资产**：ws-eng-02、ws-eng-05、ws-eng-09
- **内部 IP**：10.70.3.12、10.70.3.45、10.70.3.90
- **外部 IP**：203.0.113.77、10.70.3.45、10.70.3.90
- **域名**：sync-cdn-notify.net
- **当前攻击阶段**：command-and-control、lateral-movement
- **事件规模**：事件簇 7 条，主支撑事件 7 条，待解释关联事件 0 条，反证/背景事件 0 条。
- **核心外部指示物**：203.0.113.77、10.70.3.45、10.70.3.90、sync-cdn-notify.net
- **当前事件边界**：当前自动化判断把事件边界收敛在 ws-eng-02、ws-eng-05、ws-eng-09 上，已经足以把本案从单条告警提升为已成立事件，但尚未确认存在更大范围扩散。
- **尚未确认的范围**：
  - 当前事件链主要从外联和执行阶段收敛，初始入侵入口仍未识别。
  - 是否存在主机侧执行、持久化或横向移动证据？

## 3. 核心时间线

| 时间 | 事件 | 作用 | 观测引用 |
| -- | -- | -- | -- |
| 2026-05-18 08:55:00 UTC | The seed workstation resolved a rare domain later reused by the beacon alert. | `主证据` | obs-001, obs-002 |
| 2026-05-18 09:00:00 UTC | Seed JA4 alert matched a beacon against the same rare external infrastructure. | `种子告警` | obs-001, obs-002 |
| 2026-05-18 09:06:20 UTC | The seed workstation reconnected to the same C2 infrastructure after the alert. | `主证据` | obs-001, obs-002 |
| 2026-05-18 09:11:30 UTC | PsExec remote service creation from ws-eng-02 to ws-eng-05 was observed after beaconing started. | `主证据` | obs-001, obs-002 |
| 2026-05-18 09:18:00 UTC | A second workstation contacted the same external C2 infrastructure using the same pattern. | `主证据` | 未引用 |
| 2026-05-18 09:24:00 UTC | WMI lateral movement from ws-eng-05 to ws-eng-09 followed the shared beacon traffic. | `主证据` | 未引用 |
| 2026-05-18 09:31:00 UTC | A third workstation contacted the same C2 after the lateral movement chain. | `主证据` | 未引用 |

## 4. 核心证据链

### 4.1 主支撑证据

#### 证据 E-01
- **证据类别**：网络
- **证据强度**：高
- **事实描述**：在 2026-05-18 09:00:00 UTC，资产 `ws-eng-02` 出现了一条告警观测，关联的核心指示物为 203.0.113.77 / sync-cdn-notify.net / JA4 t13d1516h2_2ba4190accc0_13fe129f5abc。 原始摘要显示：Seed JA4 alert matched a beacon against the same rare external infrastructure.
- **为什么支持当前主假设**：这是种子命中的直接落点，说明告警并不是孤立的指纹命中。
- **局限性与边界**：单条种子命中本身不能独立证明事件成立，仍需要结合重复通信、资产背景或主机侧线索共同定性。
- **观测引用**：`obs-001, obs-002`

#### 证据 E-02
- **证据类别**：网络
- **证据强度**：高
- **事实描述**：在 2026-05-18 08:55:00 UTC，资产 `ws-eng-02` 出现了一条DNS观测，关联的核心指示物为 sync-cdn-notify.net / DNS answers 203.0.113.77。 原始摘要显示：The seed workstation resolved a rare domain later reused by the beacon alert.
- **为什么支持当前主假设**：它给出了可疑外联之前的解析准备动作，说明相关基础设施不是只在告警瞬间出现。
- **局限性与边界**：仅凭网络侧重复通信仍可能在少数情况下被正常组件、同步组件或运维脚本解释，因此仍需要结合资产背景或主机侧结果。
- **观测引用**：`obs-001, obs-002`

#### 证据 E-03
- **证据类别**：网络
- **证据强度**：高
- **事实描述**：在 2026-05-18 09:06:20 UTC，资产 `ws-eng-02` 出现了一条网络流量观测，关联的核心指示物为 203.0.113.77 / sync-cdn-notify.net。 原始摘要显示：The seed workstation reconnected to the same C2 infrastructure after the alert.
- **为什么支持当前主假设**：同一资产围绕同一批外部基础设施再次通信，单条告警已经扩展成连续事件链。
- **局限性与边界**：仅凭网络侧重复通信仍可能在少数情况下被正常组件、同步组件或运维脚本解释，因此仍需要结合资产背景或主机侧结果。
- **观测引用**：`obs-001, obs-002`

#### 证据 E-04
- **证据类别**：网络
- **证据强度**：高
- **事实描述**：在 2026-05-18 09:11:30 UTC，资产 `ws-eng-02` 出现了一条告警观测，关联的核心指示物为 10.70.3.45。 原始摘要显示：PsExec remote service creation from ws-eng-02 to ws-eng-05 was observed after beaconing started.
- **为什么支持当前主假设**：同一资产围绕同一批外部基础设施再次通信，单条告警已经扩展成连续事件链。
- **局限性与边界**：仅凭网络侧重复通信仍可能在少数情况下被正常组件、同步组件或运维脚本解释，因此仍需要结合资产背景或主机侧结果。
- **观测引用**：`obs-001, obs-002`

### 4.2 反证与替代解释
- 当前没有足以改变结论方向的强反证，但这并不意味着后续可以省略背景核查。

### 4.3 背景情报与家族上下文（可选）
- **相关家族/工具提示**：Possible internal spread beacon
- **背景情报摘要**：当前可获得的背景提示主要来自 seed 告警自带的家族/工具描述：Possible internal spread beacon。它与本案已经观察到的阶段形态 command-and-control、lateral-movement 基本一致，更适合作为解释当前事件链的辅助背景。
- **不能据此直接推出的结论**：这类背景提示的价值在于帮助理解攻击链或工具形态，而不是直接完成家族归因、攻击团伙归因或样本级确认。
- **观测引用 / 来源引用**：`obs-004`

## 5. 综合研判
- **主假设**：ws-eng-02、ws-eng-05、ws-eng-09 疑似 Possible internal spread beacon 相关事件
- **备选解释**：围绕 203.0.113.77、10.70.3.45 的通信可能存在正常背景解释
- **为什么当前结论成立**：决策主要建立在种子告警后的重复外联、同基础设施复现以及后续执行线索之上。 ws-eng-02、ws-eng-05、ws-eng-09 围绕 203.0.113.77、10.70.3.45、10.70.3.90 形成了重复通信链，已经能够支撑事件成立。 事件簇已经出现连续恶意外联或主机侧异常，足以支撑事件成立。 seed alert 自带家族/工具提示：Possible internal spread beacon。
- **为什么没有升级或为什么没有降级**：当前已经足够升级为确认事件，但还没有证据支持把事件范围直接扩大到明确扩散或明确数据外传。
- **仍未解决的问题**：
  - 当前事件链主要从外联和执行阶段收敛，初始入侵入口仍未识别。
  - 是否存在主机侧执行、持久化或横向移动证据？
- **下一次复核时最值得补的证据**：
  - 当前事件链主要从外联和执行阶段收敛，初始入侵入口仍未识别。
  - 是否存在主机侧执行、持久化或横向移动证据？

## 6. 处置建议

### 6.1 立即动作（0 到 2 小时）
- [HIGH] 优先隔离或重点监控资产：ws-eng-02、ws-eng-05、ws-eng-09。
- [HIGH] 在边界和代理设备上排查并封禁外部基础设施：203.0.113.77、10.70.3.45、10.70.3.90、sync-cdn-notify.net。

### 6.2 短期排查（24 小时内）
- [MEDIUM] 以 seed 指标和事件簇中的域名 / IP 为 pivot，继续检索同时间窗内的重复通信。

## 7. 附录

### 7.1 IOC / IOA 清单

| 类型 | 值 | 与本案关系 |
| -- | -- | -- |
| IP | 203.0.113.77 | 事件中的核心外部基础设施 |
| IP | 10.70.3.45 | 事件中的核心外部基础设施 |
| IP | 10.70.3.90 | 事件中的核心外部基础设施 |
| 域名 | sync-cdn-notify.net | 种子告警前后持续出现的关联域名 |
| JA4 | t13d1516h2_2ba4190accc0_13fe129f5abc | 种子告警命中的关键指纹 |

### 7.2 观测引用对照

| 观测编号 | 来源工具 | 摘要 |
| -- | -- | -- |
| `obs-001` | `search_seed_context` | 检索到 5 条偏可疑事件，围绕 sync-cdn-notify.net、203.0.113.77、10.70.3.45 展开。 |
| `obs-002` | `search_related_events` | 检索到 7 条偏可疑事件，围绕 sync-cdn-notify.net、203.0.113.77、10.70.3.45 展开。 |
| `obs-003` | `expand_asset_scope` | 检索到 3 条偏可疑事件，围绕 sync-cdn-notify.net、203.0.113.77、10.70.3.90 展开。 |
| `obs-004` | `extract_claim_candidates_from_page` | 从当前事件摘要中抽取出 8 条可直接引用的 claim。 |
