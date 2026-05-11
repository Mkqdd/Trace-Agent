# 首页摘要

- **结论**：可疑事件，建议继续复核。
- **严重度**：中
- **研判把握**：未评估
- **已确认范围**：`ws-legal-03`
- **最强证据**：
  - 2026-06-20 10:12:00 UTC，资产 `ws-legal-03`，关联对象 `auth-queue-sync.net / 198.51.100.131`，Seed JA4 alert observed an unusual TLS session to auth-queue-sync.net on 共享基础设施.
  - 2026-06-20 10:16:20 UTC，资产 `ws-legal-03`，关联对象 `auth-queue-sync.net / 198.51.100.131`，The seed 工作站 reconnected to the same auth-queue-sync.net endpoint after the 种子告警.
  - 2026-06-20 10:21:40 UTC，资产 `ws-legal-03`，关联对象 `auth-queue-sync.net / 198.51.100.131`，A second short TLS session from ws-legal-03 reused the same domain and JA4-adjacent shared hosting path.
- **关键缺口**：
  - 是否存在主机侧执行、持久化或横向移动证据？
  - 关联资产 `ws-legal-09`、`ws-legal-12` 是否真正受影响？
  - 仍需显式检查维护窗口、补丁、备份或共享基线等反证。
- **立即动作**：
  - 对重点资产补采主机侧日志，确认是否存在执行、持久化或横向移动证据。
  - 继续围绕相同域名、目标 IP 和 JA4 通信指纹搜索更宽时间窗内的关联事件。
  - 把关联资产 `ws-legal-09`、`ws-legal-12` 纳入复核清单，确认它们是共享基础设施背景还是真实受影响对象。
- **一句话结论**：可疑事件，建议继续复核；当前已形成可疑事件簇，但关键阶段或影响范围仍需人工复核。

## 调查起点与已知线索

可疑事件，建议继续复核；当前已形成可疑事件簇，但关键阶段或影响范围仍需人工复核。种子告警自带家族/工具提示：Suspicious shared-infra 信标 requiring review。已观察到关联资产或共享基础设施上的扩展信号，但尚需继续确认是否属于同一事件。同时也存在可解释为背景活动的信号，因此暂未自动推进为确认事件。最小事件链已达到待复核报告门槛；剩余问题应按未决边界呈现。

2026-06-20 10:04:30 UTC，资产 `ws-legal-03`，关联对象 `auth-queue-sync.net`，The seed 工作站 resolved auth-queue-sync.net, a 罕见域名 mapped to a shared hosting IP, before the alert.，源地址 `10.44.1.18`。

2026-06-20 10:12:00 UTC，资产 `ws-legal-03`，关联对象 `auth-queue-sync.net / 198.51.100.131`，Seed JA4 alert observed an unusual TLS session to auth-queue-sync.net on 共享基础设施.，源地址 `10.44.1.18`。

2026-06-20 10:16:20 UTC，资产 `ws-legal-03`，关联对象 `auth-queue-sync.net / 198.51.100.131`，The seed 工作站 reconnected to the same auth-queue-sync.net endpoint after the 种子告警.，源地址 `10.44.1.18`。

## 调查范围与研判假设

本次调查的锚点是资产 `ws-legal-03`，已确认受影响对象。此外，还有两个待确认对象：`ws-legal-09` 和 `ws-legal-12`，当前仍需独立验证是否真正受影响。这些对象只能进入候选范围，不能并入已确认受影响资产。

核心外部基础设施包括 IP 地址 `198.51.100.131` 和域名 `auth-queue-sync.net`，它们是外联和封禁排查对象，而不是内部受影响资产。

## 事件过程与行为模式

2026-06-20 10:12:00 UTC，资产 `ws-legal-03`，关联对象 `auth-queue-sync.net / 198.51.100.131`，Seed JA4 alert observed an unusual TLS session to auth-queue-sync.net on 共享基础设施.，源地址 `10.44.1.18`。

2026-06-20 10:16:20 UTC，资产 `ws-legal-03`，关联对象 `auth-queue-sync.net / 198.51.100.131`，The seed 工作站 reconnected to the same auth-queue-sync.net endpoint after the 种子告警.，源地址 `10.44.1.18`。

2026-06-20 10:21:40 UTC，资产 `ws-legal-03`，关联对象 `auth-queue-sync.net / 198.51.100.131`，A second short TLS session from ws-legal-03 reused the same domain and JA4-adjacent shared hosting path.，源地址 `10.44.1.18`。

2026-06-20 10:04:30 UTC，资产 `ws-legal-03`，关联对象 `auth-queue-sync.net`，The seed 工作站 resolved auth-queue-sync.net, a 罕见域名 mapped to a shared hosting IP, before the alert.，源地址 `10.44.1.18`。

2026-06-20 10:24:00 UTC，资产 `ws-legal-03`，Endpoint coverage for ws-legal-03 did not include command-line telemetry during the relevant window.，源地址 `10.44.1.18`。

2026-06-20 10:39:00 UTC，资产 `ws-legal-09`，关联对象 `cdn-auth-queue.net / 198.51.100.131`，A second 工作站 contacted cdn-auth-queue.net on the same shared IP, but only through one weak network signal.，源地址 `10.44.1.29`。

2026-06-20 10:42:00 UTC，资产 `ws-legal-09`，关联对象 `cdn-auth-queue.net`，The second 工作站 resolved a sibling domain pointing to the same 共享基础设施.，源地址 `10.44.1.29`。

2026-06-20 10:46:10 UTC，资产 `ws-legal-09`，关联对象 `identity-cache.vendor.example / 198.51.100.131`，The same 工作站 also used a sanctioned identity-cache vendor domain on the shared hosting IP.，源地址 `10.44.1.29`。

2026-06-20 10:49:30 UTC，资产 `ws-legal-12`，关联对象 `legal-docs-cdn.example / 198.51.100.131`，A legal-document review 工作站 touched the same IP through a different business SaaS domain, suggesting 共享基础设施.，源地址 `10.44.1.42`。

## 关键事实与证据判断

2026-06-20 10:12:00 UTC，资产 `ws-legal-03`，关联对象 `auth-queue-sync.net / 198.51.100.131`，Seed JA4 alert observed an unusual TLS session to auth-queue-sync.net on 共享基础设施.，源地址 `10.44.1.18`。

2026-06-20 10:21:40 UTC，资产 `ws-legal-03`，关联对象 `auth-queue-sync.net / 198.51.100.131`，A second short TLS session from ws-legal-03 reused the same domain and JA4-adjacent shared hosting path.，源地址 `10.44.1.18`。

可疑事件，建议继续复核；当前已形成可疑事件簇，但关键阶段或影响范围仍需人工复核。种子告警自带家族/工具提示：Suspicious shared-infra 信标 requiring review。已观察到关联资产或共享基础设施上的扩展信号，但尚需继续确认是否属于同一事件。同时也存在可解释为背景活动的信号，因此暂未自动推进为确认事件。最小事件链已达到待复核报告门槛；剩余问题应按未决边界呈现。

检索到 3 条偏可疑事件，围绕 `auth-queue-sync.net`、`198.51.100.131` 展开。扩线检索到 3 条可疑关联事件，围绕 `auth-queue-sync.net`、`198.51.100.131` 展开；当前先作为待验证候选线索。

2026-06-20 10:16:20 UTC，资产 `ws-legal-03`，关联对象 `auth-queue-sync.net / 198.51.100.131`，The seed 工作站 reconnected to the same auth-queue-sync.net endpoint after the 种子告警.，源地址 `10.44.1.18`。

检索到 1 条更接近维护、更新或正常基线的事件。

## 关联范围与候选边界

对象 `ws-legal-03`，类型为资产，当前角色为种子资产，种子告警首先落在该资产上。当前已纳入主证据链的资产。

对象 `ws-legal-09`，类型为资产，当前角色为待确认关联资产，当前仍需独立验证是否真正受影响。事件中出现过的资产对象。当前关键关联指标里出现的扩线候选资产。

对象 `ws-legal-12`，类型为资产，当前角色为待确认关联资产，当前仍需独立验证是否真正受影响。事件中出现过的资产对象。当前关键关联指标里出现的扩线候选资产。

对象 `203.0.113.131`，类型为 IP，当前角色为扩展查询候选，当前关键关联指标里出现的扩线候选地址。

对象 `cdn-auth-queue.net`，类型为域名，当前角色为扩展查询候选，当前关键关联指标里出现的扩线候选域名。

对象 `198.51.100.131`，类型为 IP，当前角色为核心外部基础设施，当前主证据链中反复出现的关键对象。用于补充边界或背景解释的对象。当前关键关联指标里出现的扩线候选地址。

对象 `auth-queue-sync.net`，类型为域名，当前角色为核心外部基础设施，当前主证据链中反复出现的关键对象。用于补充边界或背景解释的对象。当前关键关联指标里出现的扩线候选域名。

对象 `legal-docs-cdn.example`，类型为域名，当前角色为扩展查询候选，当前关键关联指标里出现的扩线候选域名。

对象 `login-queue-cdn.net`，类型为

---

# 事件调查技术附录

以下内容主要供分析、复盘和技术排查使用，不直接替代主报告结论。

## 1. IOC / IOA 清单

| 类型 | 值 | 角色 | 状态 |
| -- | -- | -- | -- |
| IP | 198.51.100.131 | 核心外部基础设施 | 已确认 |
| 域名 | auth-queue-sync.net | 核心外部基础设施 | 已确认 |
| IP | 20.190.160.22 | 背景/上下文指标 | 已确认 |
| 域名 | identity-cache.vendor.example | 背景/上下文指标 | 已确认 |
| 域名 | login.microsoftonline.com | 背景/上下文指标 | 已确认 |
| 指纹 | t13d190900_7711aa22bb33_9911ccddee77 | 扩展查询候选 | 待确认 |
| 内网 IP | 10.44.1.18 | 关联内部地址 | 已确认 |
| 内网 IP | 10.44.1.29 | 关联内部地址 | 已确认 |
| 内网 IP | 10.44.1.42 | 关联内部地址 | 已确认 |
| IP | 203.0.113.131 | 扩展查询候选 | 待确认 |
| 域名 | cdn-auth-queue.net | 扩展查询候选 | 待确认 |
| 域名 | legal-docs-cdn.example | 扩展查询候选 | 待确认 |
| 域名 | login-queue-cdn.net | 扩展查询候选 | 待确认 |

## 2. 关键对象清单

| 对象 | 类型 | 当前角色 | 是否已纳入证据链 | 备注 |
| -- | -- | -- | -- | -- |
| ws-legal-03 | 资产 | 种子资产 | 是 | 种子告警首先落在该资产上。；当前已纳入主证据链的资产。；事件中出现过的资产对象。；当前 pivot 里出现的扩线候选资产。 |
| ws-legal-09 | 资产 | 待确认关联资产 | 否 | 当前仍需独立验证是否真正受影响。；事件中出现过的资产对象。；当前 pivot 里出现的扩线候选资产。 |
| ws-legal-12 | 资产 | 待确认关联资产 | 否 | 当前仍需独立验证是否真正受影响。；事件中出现过的资产对象。；当前 pivot 里出现的扩线候选资产。 |
| 198.51.100.131 | IP | 核心外部基础设施 | 是 | 当前主证据链中反复出现的关键对象。；用于补充边界或背景解释的对象。；当前 pivot 里出现的扩线候选地址。 |
| auth-queue-sync.net | 域名 | 核心外部基础设施 | 是 | 当前主证据链中反复出现的关键对象。；用于补充边界或背景解释的对象。；当前 pivot 里出现的扩线候选域名。 |
| 20.190.160.22 | IP | 背景/上下文指标 | 是 | 用于补充边界或背景解释的对象。；当前 pivot 里出现的扩线候选地址。 |
| identity-cache.vendor.example | 域名 | 背景/上下文指标 | 是 | 用于补充边界或背景解释的对象。；当前 pivot 里出现的扩线候选域名。 |
| login.microsoftonline.com | 域名 | 背景/上下文指标 | 是 | 用于补充边界或背景解释的对象。；当前 pivot 里出现的扩线候选域名。 |
| t13d190900_7711aa22bb33_9911ccddee77 | JA4 | 种子命中指纹 | 是 | 种子告警命中的关键通信指纹。 |
| Suspicious shared-infra beacon requiring review | 家族提示 | 家族/工具提示 | 是 | 辅助解释本案的家族或工具背景，不直接等于强归因。 |
| 10.44.1.18 | 内网 IP | 关联内部地址 | 是 | 事件链中出现的内部地址。 |
| 10.44.1.29 | 内网 IP | 关联内部地址 | 是 | 事件链中出现的内部地址。 |
| 10.44.1.42 | 内网 IP | 关联内部地址 | 是 | 事件链中出现的内部地址。 |
| 203.0.113.131 | IP | 扩展查询候选 | 否 | 当前 pivot 里出现的扩线候选地址。 |
| cdn-auth-queue.net | 域名 | 扩展查询候选 | 否 | 当前 pivot 里出现的扩线候选域名。 |
| legal-docs-cdn.example | 域名 | 扩展查询候选 | 否 | 当前 pivot 里出现的扩线候选域名。 |
| login-queue-cdn.net | 域名 | 扩展查询候选 | 否 | 当前 pivot 里出现的扩线候选域名。 |
| t13d190900_7711aa22bb33_9911ccddee77 | 指纹 | 扩展查询候选 | 否 | 当前 pivot 里出现的扩线候选指纹。 |

## 3. 关键证据细目

### 证据 E-01
- **证据类型**：主支撑证据
- **证据类别**：调查触发证据（网络）
- **证据强度**：高
- **事实描述**：在 2026-06-20 10:12:00 UTC，资产 `ws-legal-03` 出现了一条与 198.51.100.131 / auth-queue-sync.net 相关的关键观测。
- **为什么重要**：这是种子命中的直接落点，说明调查起点并不是孤立的指纹命中。
- **边界与限制**：单条种子命中本身不能独立证明事件成立，仍需要结合重复通信、资产背景或主机侧线索共同定性。
- **主要依据来源**：种子事件窗观测、关联事件扩查
- **观测引用**：`obs-001, obs-002, obs-003`

### 证据 E-02
- **证据类型**：主支撑证据
- **证据类别**：连续性支撑证据（网络）
- **证据强度**：高
- **事实描述**：在 2026-06-20 10:21:40 UTC，资产 `ws-legal-03` 再次与 198.51.100.131 / auth-queue-sync.net 通信，说明同一基础设施上的异常仍在持续。
- **为什么重要**：同一基础设施在种子资产或关联资产上再次出现，使单点告警扩展成可复核的连续事件链。
- **边界与限制**：仅凭网络侧重复通信仍可能在少数情况下被正常组件、同步组件或运维脚本解释，因此仍需要结合资产背景或主机侧结果。
- **主要依据来源**：种子事件窗观测、关联事件扩查
- **观测引用**：`obs-001, obs-002, obs-003`

### 证据 E-03
- **证据类型**：主支撑证据
- **证据类别**：连续性支撑证据（网络）
- **证据强度**：高
- **事实描述**：在 2026-06-20 10:16:20 UTC，资产 `ws-legal-03` 再次与 198.51.100.131 / auth-queue-sync.net 通信，说明同一基础设施上的异常仍在持续。
- **为什么重要**：同一基础设施在种子资产或关联资产上再次出现，使单点告警扩展成可复核的连续事件链。
- **边界与限制**：仅凭网络侧重复通信仍可能在少数情况下被正常组件、同步组件或运维脚本解释，因此仍需要结合资产背景或主机侧结果。
- **主要依据来源**：种子事件窗观测、关联事件扩查
- **观测引用**：`obs-001, obs-002, obs-003`

### 证据 E-04
- **证据类型**：主支撑证据
- **证据类别**：范围确认依据（网络）
- **证据强度**：中
- **事实描述**：在 2026-06-20 10:42:00 UTC，资产 `ws-legal-09` 先解析了少见域名 `cdn-auth-queue.net`。
- **为什么重要**：它把事件范围从种子资产推进到其他资产，使当前结论不再只停留在单点异常。
- **边界与限制**：这条观测本身更适合用来补足上下文，而不是单独承担最终结论。
- **主要依据来源**：关联事件扩查、显式反证检查
- **观测引用**：`obs-002, obs-003, obs-004`

### 证据 E-05
- **证据类型**：主支撑证据
- **证据类别**：范围确认依据（网络）
- **证据强度**：中
- **事实描述**：在 2026-06-20 10:49:30 UTC，资产 `ws-legal-12` 出现了一条与 198.51.100.131 / legal-docs-cdn.example 相关的关键观测。
- **为什么重要**：它把事件范围从种子资产推进到其他资产，使当前结论不再只停留在单点异常。
- **边界与限制**：这条观测本身更适合用来补足上下文，而不是单独承担最终结论。
- **主要依据来源**：关联事件扩查、显式反证检查
- **观测引用**：`obs-002, obs-003, obs-004`

### 证据 C-01
- **证据类型**：反证或替代解释
- **证据类别**：反证与替代解释（网络）
- **证据强度**：高
- **事实描述**：在 2026-06-20 10:46:10 UTC，资产 `ws-legal-09` 与 198.51.100.131 / identity-cache.vendor.example 的访问更接近计划内更新、维护或共享基础设施背景。
- **为什么重要**：这条观测更支持背景解释或替代解释，而不是继续放大当前主假设。
- **边界与限制**：这类背景解释能够帮助收窄判断，但如果后续出现脱离基线的重复通信、执行线索或跨资产异常，它本身并不能永久关闭事件。
- **主要依据来源**：关联事件扩查、显式反证检查
- **观测引用**：`obs-002, obs-003, obs-004`

### 证据 C-02
- **证据类型**：反证或替代解释
- **证据类别**：反证与替代解释（上下文）
- **证据强度**：高
- **事实描述**：在 2026-06-20 10:52:00 UTC，资产 `相关资产` 与 198.51.100.131 / auth-queue-sync.net 的访问更接近计划内更新、维护或共享基础设施背景。
- **为什么重要**：这条观测更支持背景解释或替代解释，而不是继续放大当前主假设。
- **边界与限制**：这类背景解释能够帮助收窄判断，但如果后续出现脱离基线的重复通信、执行线索或跨资产异常，它本身并不能永久关闭事件。
- **主要依据来源**：关联事件扩查
- **观测引用**：`obs-002, obs-003`

## 4. 观测引用对照

| 观测编号 | 来源工具 | 事实摘要 | 关系 |
| -- | -- | -- | -- |
| `obs-001` | `search_seed_context` | 检索到 3 条偏可疑事件，围绕 auth-queue-sync.net、198.51.100.131 展开。 | `supporting` |
| `obs-002` | `search_related_events` | 扩线检索到 3 条可疑关联事件，围绕 auth-queue-sync.net、198.51.100.131 展开；当前先作为待验证候选线索。 | `candidate` |
| `obs-003` | `search_related_events` | 扩线检索到 3 条可疑关联事件，围绕 auth-queue-sync.net、198.51.100.131 展开；当前先作为待验证候选线索。 | `candidate` |
| `obs-004` | `expand_asset_scope` | 检索到 1 条更接近维护、更新或正常基线的事件。 | `counterevidence` |

## 5. 正文章节引用映射

| 正文章节 | 主要 evidence / observation | 用途 |
| -- | -- | -- |
| 首页摘要 | E-01、E-02、check_counterevidence | 当前状态 / 当前最强证据 / 当前最关键缺口 |
| 第 5 节 | E-01、E-02、E-03、E-04、E-05、C-01、C-02 | 主支撑证据 / 反证与替代解释 |
| 第 9 节 | check_counterevidence、structure_evidence、execution_gap | 证据链摘要 / 缺口说明 |
| 第 10 节 | E-01、E-02 | 结论 / 动作 / 复核重点 |

## 6. 证据来源与参考资料

| 来源类型 | 来源名称 | 用途 | 边界 |
| -- | -- | -- | -- |
| 上游检测 | t13d190900_7711aa22bb33_9911ccddee77 / Suspicious shared-infra beacon requiring review | 提供本案的调查起点与初始命中线索。 | 命中本身并不自动等于事件成立，仍需要后续本地事实补强。 |
| 内部观测 | trace_store.seed_context | 支撑时间线、范围和关键事实。 | 仅覆盖当前调查纳入的本地流量与上下文数据。 |
| 内部观测 | trace_store.related_events | 支撑时间线、范围和关键事实。 | 仅覆盖当前调查纳入的本地流量与上下文数据。 |
| 背景核查 | trace_store.asset_context | 验证维护窗口、补丁、备份或共享基线等替代解释。 | 反证核查只能说明是否存在降级解释，不能替代主证据链。 |

## 7. 证据缺口与待补查询

| 缺口 | 限制的结论 | 当前是否可补 | 最值得补的查询 |
| -- | -- | -- | -- |
| 是否存在主机侧执行、持久化或横向移动证据？ | 当前尚未观测到稳定的执行阶段证据，因此还不能确认主机侧执行、持久化或横向移动是否已经成立。 | 否 | 当前缺少继续缩小该缺口的有效手段，更适合作为报告边界说明。 |
| 关联资产 ws-legal-09、ws-legal-12 是否真正受影响？ | 当前仍缺少对“关联资产 ws-legal-09、ws-legal-12 是否真正受影响？”的直接补证。 | 否 | 当前缺少继续缩小该缺口的有效手段，更适合作为报告边界说明。 |
| 仍需显式检查维护窗口、补丁、备份或共享基线等反证。 | 当前不能完全排除维护窗口、共享基础设施或正常组件造成的替代解释。 | 是 | 仍需显式检查维护窗口、补丁、备份或共享基线等反证。 |
| 仍需把当前事件事实沉淀为 claim 或可引用实体，避免报告只剩原始事件聚合。 | 当前仍缺少对“仍需把当前事件事实沉淀为 claim 或可引用实体，避免报告只剩原始事件聚合。”的直接补证。 | 是 | 仍需把当前事件事实沉淀为 claim 或可引用实体，避免报告只剩原始事件聚合。 |
| seed 自带的家族提示 Suspicious shared-infra beacon requiring review 是否有更多外部证据支撑？ | 当前仍缺少对“seed 自带的家族提示 Suspicious shared-infra beacon requiring review 是否有更多外部证据支撑？”的直接补证。 | 否 | 当前缺少继续缩小该缺口的有效手段，更适合作为报告边界说明。 |
