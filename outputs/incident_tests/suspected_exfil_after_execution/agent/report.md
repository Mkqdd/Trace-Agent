# 事件级溯源报告

## 1. 执行摘要
- **事件结论**：待人工复核
- **当前状态**：`needs_review`
- **严重度**：中危
- **置信度**：66
- **一句话摘要**：自动聚合已经找到可关联的上下文，不过现阶段仍缺少足够强的执行或持续控制证据。
- **建议立即执行的动作**：对重点资产补采主机侧日志，确认是否存在执行、持久化或横向移动证据。

## 2. 事件范围与边界
- **Seed alert / 起点**：2026-06-03 16:40:00，ws-rnd-04 命中 Possible cloud-storage exfil candidate JA4 规则。
- **时间窗口**：2026-06-03 16:34:00 UTC 至 2026-06-03 17:05:00 UTC
- **种子资产**：ws-rnd-04
- **重点观察资产**：ws-rnd-04
- **待排查关联资产**：ws-rnd-09
- **内部 IP**：10.90.2.44、10.90.2.49
- **外部 IP**：198.51.100.144
- **域名**：files-sync-share.net
- **当前攻击阶段**：execution、exfiltration
- **事件规模**：事件簇 5 条，主支撑事件 3 条，待解释关联事件 2 条，反证/背景事件 0 条。
- **核心外部指示物**：198.51.100.144、files-sync-share.net
- **当前事件边界**：当前已经形成可关联的事件簇，但主要支撑信号仍不足以把结论稳定推进到确认事件。
- **尚未确认的范围**：
  - 当前仍缺少足够强的主机侧执行或扩散证据，自动结论需要结合人工复核。
  - 主支撑信号目前仍集中在单个重点资产上，尚未确认存在更大范围扩散。
  - 其他关联资产目前更多体现为共享基础设施上的弱关联，仍需逐台确认是否真正受影响。
  - 关联资产 ws-rnd-09 是否真正受影响？

## 3. 核心时间线

| 时间 | 事件 | 作用 | 观测引用 |
| -- | -- | -- | -- |
| 2026-06-03 16:34:00 UTC | The workstation resolved a rare storage domain shortly before the seed alert fired. | `上下文` | 未引用 |
| 2026-06-03 16:40:00 UTC | Seed JA4 alert observed a suspicious TLS session to a rare storage edge. | `种子告警` | obs-001, obs-002 |
| 2026-06-03 16:44:00 UTC | Archive utility spawned on the workstation shortly before the outbound transfer. | `执行线索` | obs-001, obs-002 |
| 2026-06-03 16:47:00 UTC | A large outbound HTTPS upload followed the archive creation, but DLP visibility is incomplete. | `支撑证据` | obs-001, obs-002 |
| 2026-06-03 17:05:00 UTC | A second workstation briefly connected to the same storage edge, but only once and without host evidence. | `上下文` | 未引用 |

## 4. 核心证据链

### 4.1 主支撑证据

#### 证据 E-01
- **证据类别**：网络
- **证据强度**：高
- **事实描述**：在 2026-06-03 16:40:00 UTC，资产 `ws-rnd-04` 出现了一条告警观测，关联的核心指示物为 198.51.100.144 / files-sync-share.net / JA4 t13d190900_44ac2200b3c1_ab11cd22ee44。 原始摘要显示：Seed JA4 alert observed a suspicious TLS session to a rare storage edge.
- **为什么支持当前主假设**：这是种子命中的直接落点，说明告警并不是孤立的指纹命中。
- **局限性与边界**：单条种子命中本身不能独立证明事件成立，仍需要结合重复通信、资产背景或主机侧线索共同定性。
- **观测引用**：`obs-001, obs-002`

#### 证据 E-02
- **证据类别**：主机
- **证据强度**：高
- **事实描述**：在 2026-06-03 16:44:00 UTC，资产 `ws-rnd-04` 出现了一条告警观测。 原始摘要显示：Archive utility spawned on the workstation shortly before the outbound transfer.
- **为什么支持当前主假设**：这条记录把可疑外联推进到了主机侧执行层，显著提高了事件成立概率。
- **局限性与边界**：当前仍缺少更细的命令行、落地文件、持久化或内存证据，因此可以确认存在执行线索，但还不能完整描述具体载荷。
- **观测引用**：`obs-001, obs-002`

#### 证据 E-03
- **证据类别**：网络
- **证据强度**：中
- **事实描述**：在 2026-06-03 16:47:00 UTC，资产 `ws-rnd-04` 出现了一条网络流量观测，关联的核心指示物为 198.51.100.144 / files-sync-share.net。 原始摘要显示：A large outbound HTTPS upload followed the archive creation, but DLP visibility is incomplete.
- **为什么支持当前主假设**：它强调了这批外部基础设施在当前环境中的稀有性。
- **局限性与边界**：这条观测本身更适合用来补足上下文，而不是单独承担最终结论。
- **观测引用**：`obs-001, obs-002`

### 4.2 反证与替代解释
- 当前没有足以改变结论方向的强反证，但这并不意味着后续可以省略背景核查。

### 4.3 背景情报与家族上下文（可选）
- **相关家族/工具提示**：Possible cloud-storage exfil candidate
- **背景情报摘要**：当前可获得的背景提示主要来自 seed 告警自带的家族/工具描述：Possible cloud-storage exfil candidate。它与本案已经观察到的阶段形态 execution、exfiltration 基本一致，更适合作为解释当前事件链的辅助背景。
- **不能据此直接推出的结论**：这类背景提示的价值在于帮助理解攻击链或工具形态，而不是直接完成家族归因、攻击团伙归因或样本级确认。
- **观测引用 / 来源引用**：`obs-004`

## 5. 综合研判
- **主假设**：ws-rnd-04 疑似 Possible cloud-storage exfil candidate 相关事件
- **备选解释**：围绕 198.51.100.144、files-sync-share.net 的通信可能存在正常背景解释
- **为什么当前结论成立**：当前已有可疑关联，但支撑证据还不足以推进为确认事件。 目前最强的支撑来自 ws-rnd-04 围绕 198.51.100.144、files-sync-share.net 的重复通信，但这条链还没有延伸到执行或扩散层。 当前已形成可疑事件簇，但关键阶段或影响范围仍需人工复核。 seed alert 自带家族/工具提示：Possible cloud-storage exfil candidate。 已观察到关联资产或共享基础设施上的扩展信号，但尚需继续确认是否属于同一事件。
- **为什么没有升级或为什么没有降级**：其余关联资产目前更多体现为范围参考，而不是已经受影响的直接证据。
- **仍未解决的问题**：
  - 当前仍缺少足够强的主机侧执行或扩散证据，自动结论需要结合人工复核。
  - 主支撑信号目前仍集中在单个重点资产上，尚未确认存在更大范围扩散。
  - 其他关联资产目前更多体现为共享基础设施上的弱关联，仍需逐台确认是否真正受影响。
  - 关联资产 ws-rnd-09 是否真正受影响？
  - seed 自带的家族提示 Possible cloud-storage exfil candidate 是否有更多外部证据支撑？
- **下一次复核时最值得补的证据**：
  - 当前仍缺少足够强的主机侧执行或扩散证据，自动结论需要结合人工复核。
  - 主支撑信号目前仍集中在单个重点资产上，尚未确认存在更大范围扩散。
  - 其他关联资产目前更多体现为共享基础设施上的弱关联，仍需逐台确认是否真正受影响。

## 6. 处置建议

### 6.1 立即动作（0 到 2 小时）
- [HIGH] 对重点资产补采主机侧日志，确认是否存在执行、持久化或横向移动证据。

### 6.2 短期排查（24 小时内）
- [MEDIUM] 继续围绕同域名 / 同 dst_ip / 同 JA4 搜索更宽时间窗内的关联事件。
- [MEDIUM] 把关联资产 ws-rnd-09 纳入复核清单，确认它们是共享基础设施背景还是真实受影响对象。

## 7. 附录

### 7.1 IOC / IOA 清单

| 类型 | 值 | 与本案关系 |
| -- | -- | -- |
| IP | 198.51.100.144 | 事件中的核心外部基础设施 |
| 域名 | files-sync-share.net | 种子告警前后持续出现的关联域名 |
| JA4 | t13d190900_44ac2200b3c1_ab11cd22ee44 | 种子告警命中的关键指纹 |
| 行为线索 | Archive utility spawned on the workstation shortly before the outbound transfer. | 执行阶段的重要主机侧线索 |

### 7.2 观测引用对照

| 观测编号 | 来源工具 | 摘要 |
| -- | -- | -- |
| `obs-001` | `search_seed_context` | 检索到 3 条偏可疑事件，围绕 files-sync-share.net、198.51.100.144 展开。 |
| `obs-002` | `search_related_events` | 检索到 3 条偏可疑事件，围绕 files-sync-share.net、198.51.100.144 展开。 |
| `obs-003` | `expand_asset_scope` | 检索到 1 条上下文事件，当前主要用于扩边界和补足范围。 |
| `obs-004` | `extract_claim_candidates_from_page` | 从当前事件摘要中抽取出 6 条可直接引用的 claim。 |
