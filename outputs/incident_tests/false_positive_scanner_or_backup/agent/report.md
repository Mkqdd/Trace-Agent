# 事件级溯源报告

## 1. 执行摘要
- **事件结论**：降级观察
- **当前状态**：`monitor_only`
- **严重度**：低危
- **置信度**：55
- **一句话摘要**：当前看到的告警与补充背景更接近计划内活动或正常变更，建议继续观察而不是立即定性为入侵。
- **建议立即执行的动作**：保留当前告警与上下文，作为后续相似行为的基线样本。

## 2. 事件范围与边界
- **Seed alert / 起点**：2026-05-26 01:12:00，backup-srv-01 命中 Backup traffic outlier candidate JA4 规则。
- **时间窗口**：2026-05-26 01:05:00 UTC 至 2026-05-26 01:18:40 UTC
- **种子资产**：backup-srv-01
- **重点观察资产**：backup-srv-01
- **关联资产**：backup-srv-02
- **内部 IP**：10.80.9.20、10.80.9.21
- **外部 IP**：203.0.113.210
- **域名**：backup.vendor.example
- **当前攻击阶段**：尚未稳定识别
- **事件规模**：事件簇 6 条，主支撑事件 1 条，待解释关联事件 0 条，反证/背景事件 5 条。
- **核心外部指示物**：203.0.113.210、backup.vendor.example
- **当前事件边界**：当前更倾向于把这起告警解释为计划内活动中的弱信号，而不是已经成立的入侵事件。
- **尚未确认的范围**：
  - 当前降级依赖于维护窗口和更新背景；如果后续在相同指示物上出现脱离基线的重复通信，需要重新升级研判。
  - 关联资产出现的同类访问目前更像共享基线，而不是扩散迹象。

## 3. 核心时间线

| 时间 | 事件 | 作用 | 观测引用 |
| -- | -- | -- | -- |
| 2026-05-26 01:05:00 UTC | Nightly backup window started on backup-srv-01 under the approved operations schedule. | `反证` | obs-001, obs-002 |
| 2026-05-26 01:08:00 UTC | The backup server resolved the approved vendor backup endpoint before the transfer began. | `反证` | obs-001, obs-002 |
| 2026-05-26 01:12:00 UTC | Heuristic JA4 alert fired on backup traffic to the vendor repository. | `种子告警` | obs-001, obs-002 |
| 2026-05-26 01:14:30 UTC | Backup agent uploaded an encrypted archive to the approved vendor endpoint. | `反证` | obs-001, obs-002 |
| 2026-05-26 01:17:00 UTC | Backup manifest and retention metadata were exchanged with the same service. | `反证` | obs-001, obs-002 |
| 2026-05-26 01:18:40 UTC | A sibling backup node contacted the same endpoint during the same backup window. | `反证` | 未引用 |

## 4. 核心证据链

### 4.1 主支撑证据

#### 证据 E-01
- **证据类别**：网络
- **证据强度**：高
- **事实描述**：在 2026-05-26 01:12:00 UTC，资产 `backup-srv-01` 出现了一条告警观测，关联的核心指示物为 203.0.113.210 / backup.vendor.example / JA4 t13d1516h2_9f7710a0ab12_0011ab22cd33。 原始摘要显示：Heuristic JA4 alert fired on backup traffic to the vendor repository.
- **为什么支持当前主假设**：这是种子命中的直接落点，说明告警并不是孤立的指纹命中。
- **局限性与边界**：单条种子命中本身不能独立证明事件成立，仍需要结合重复通信、资产背景或主机侧线索共同定性。
- **观测引用**：`obs-001, obs-002`

### 4.2 反证与替代解释

#### 证据 C-01
- **反证或替代解释类别**：资产背景
- **证据强度**：高
- **相关事实**：在 2026-05-26 01:05:00 UTC，资产 `backup-srv-01` 出现了一条资产背景观测。 原始摘要显示：Nightly backup window started on backup-srv-01 under the approved operations schedule.
- **为什么它提示了替代解释，或为什么它不足以推翻主结论**：这条记录更接近计划内维护或正常更新背景，是当前能够降级或收窄判断的重要原因。
- **边界与后续关注点**：这类背景解释能够帮助收窄判断，但如果后续出现脱离基线的重复通信、执行线索或跨资产异常，它本身并不能永久关闭事件。
- **观测引用**：`obs-001, obs-002`

#### 证据 C-02
- **反证或替代解释类别**：网络
- **证据强度**：高
- **相关事实**：在 2026-05-26 01:08:00 UTC，资产 `backup-srv-01` 出现了一条DNS观测，关联的核心指示物为 backup.vendor.example / DNS answers 203.0.113.210。 原始摘要显示：The backup server resolved the approved vendor backup endpoint before the transfer began.
- **为什么它提示了替代解释，或为什么它不足以推翻主结论**：这条记录更接近计划内维护或正常更新背景，是当前能够降级或收窄判断的重要原因。
- **边界与后续关注点**：这类背景解释能够帮助收窄判断，但如果后续出现脱离基线的重复通信、执行线索或跨资产异常，它本身并不能永久关闭事件。
- **观测引用**：`obs-001, obs-002`

#### 证据 C-03
- **反证或替代解释类别**：网络
- **证据强度**：高
- **相关事实**：在 2026-05-26 01:14:30 UTC，资产 `backup-srv-01` 出现了一条网络流量观测，关联的核心指示物为 203.0.113.210 / backup.vendor.example。 原始摘要显示：Backup agent uploaded an encrypted archive to the approved vendor endpoint.
- **为什么它提示了替代解释，或为什么它不足以推翻主结论**：这条记录更接近计划内维护或正常更新背景，是当前能够降级或收窄判断的重要原因。
- **边界与后续关注点**：这类背景解释能够帮助收窄判断，但如果后续出现脱离基线的重复通信、执行线索或跨资产异常，它本身并不能永久关闭事件。
- **观测引用**：`obs-001, obs-002`

#### 证据 C-04
- **反证或替代解释类别**：网络
- **证据强度**：高
- **相关事实**：在 2026-05-26 01:17:00 UTC，资产 `backup-srv-01` 出现了一条HTTP观测，关联的核心指示物为 203.0.113.210 / backup.vendor.example。 原始摘要显示：Backup manifest and retention metadata were exchanged with the same service.
- **为什么它提示了替代解释，或为什么它不足以推翻主结论**：这条记录更接近计划内维护或正常更新背景，是当前能够降级或收窄判断的重要原因。
- **边界与后续关注点**：这类背景解释能够帮助收窄判断，但如果后续出现脱离基线的重复通信、执行线索或跨资产异常，它本身并不能永久关闭事件。
- **观测引用**：`obs-001, obs-002`

## 5. 综合研判
- **主假设**：backup-srv-01 疑似恶意外联事件
- **备选解释**：围绕 203.0.113.210、backup.vendor.example 的通信可能存在正常背景解释
- **为什么当前结论成立**：决策主要建立在明确的维护窗口、重复的正常更新流量和可解释的背景证据之上。 唯一的主支撑仍然是 seed alert 本身，它没有得到更多恶意侧信号的放大。 当前证据更容易被维护窗口、补丁、备份或共享基线解释。
- **为什么没有升级或为什么没有降级**：反证主要来自维护窗口、签名更新以及兄弟资产同步访问，这些背景足以解释为什么不能只凭 seed alert 直接定性。
- **仍未解决的问题**：
  - 当前降级依赖于维护窗口和更新背景；如果后续在相同指示物上出现脱离基线的重复通信，需要重新升级研判。
  - 关联资产出现的同类访问目前更像共享基线，而不是扩散迹象。
- **下一次复核时最值得补的证据**：
  - 当前降级依赖于维护窗口和更新背景；如果后续在相同指示物上出现脱离基线的重复通信，需要重新升级研判。
  - 关联资产出现的同类访问目前更像共享基线，而不是扩散迹象。

## 6. 处置建议

### 6.3 后续改进（可选）
- [LOW] 保留当前告警与上下文，作为后续相似行为的基线样本。
- [LOW] 结合变更窗口、补丁任务和资产画像确认是否需要做白名单或检测规则收敛。

## 7. 附录

### 7.1 IOC / IOA 清单

| 类型 | 值 | 与本案关系 |
| -- | -- | -- |
| IP | 203.0.113.210 | 事件中的核心外部基础设施 |
| 域名 | backup.vendor.example | 种子告警前后持续出现的关联域名 |
| JA4 | t13d1516h2_9f7710a0ab12_0011ab22cd33 | 种子告警命中的关键指纹 |

### 7.2 观测引用对照

| 观测编号 | 来源工具 | 摘要 |
| -- | -- | -- |
| `obs-001` | `search_seed_context` | 检索到 1 条偏可疑事件，围绕 backup.vendor.example、203.0.113.210 展开。 |
| `obs-002` | `search_related_events` | 检索到 1 条偏可疑事件，围绕 backup.vendor.example、203.0.113.210 展开。 |
| `obs-003` | `expand_asset_scope` | 检索到 1 条更接近维护、更新或正常基线的事件。 |
| `obs-004` | `extract_claim_candidates_from_page` | 从当前事件摘要中抽取出 5 条可直接引用的 claim。 |
