# 事件调查报告

## 首页摘要
- **事件标题**：ws-legal-03 Suspicious shared-infra beacon requiring review 调查报告
- **分析窗口**：2026-06-20 10:04:30 UTC 至 2026-06-20 11:18:00 UTC
- **当前状态**：可疑事件，建议继续复核
- **严重度**：中
- **研判把握**：高
- **已确认影响范围**：当前尚无已确认受影响资产
- **当前最强证据**：在 2026-06-20 10:42:00 UTC，资产 `ws-legal-09` 先解析了少见域名 `cdn-auth-queue.net`，说明把事件范围从种子资产推进到其他资产，使当前结论不再只停留在单点异常。
- **当前最关键缺口**：是否存在主机侧执行、持久化或横向移动证据？
- **建议立即动作**：优先隔离或重点监控资产：ws-legal-03。
- **一句话结论**：ws-legal-03 围绕 198.51.100.131、auth-queue-sync.net 已出现连续异常迹象，但由于还需要进一步确认主机侧是否已经出现能够直接支撑执行、持久化或横向移动的证据，当前仍按待人工复核事件交付。

## 1. 事件背景与已知线索
- **事件标题**：ws-legal-03 Suspicious shared-infra beacon requiring review 调查报告
- **分析窗口**：2026-06-20 10:04:30 UTC 至 2026-06-20 11:18:00 UTC
- **调查起点**：2026-06-20 10:12:00 UTC，最先在 `ws-legal-03` 的告警中触发调查，当时关联对象为 auth-queue-sync.net、198.51.100.131。
- **初始命中线索（规则 / 指纹 / 模型）**：命中了种子通信指纹：t13d190900_7711aa22bb33_9911ccddee77、当前已有家族/工具背景提示：Suspicious shared-infra beacon requiring review、当前已知关键对象包括 198.51.100.131、auth-queue-sync.net、种子事件直接表现为：Seed JA4 alert observed an unusual TLS session to auth-queue-sync.net on shared infrastructure.
- **上游检测或已知背景**：当前可获得的背景提示主要来自家族/工具线索：Suspicious shared-infra beacon requiring review，与当前观察到的阶段形态 命令与控制 基本一致。
- **本次调查关注点**：在 2026-06-20 10:42:00 UTC，资产 `ws-legal-09` 先解析了少见域名 `cdn-auth-queue.net`，说明把事件范围从种子资产推进到其他资产，使当前结论不再只停留在单点异常。
- **本节主要依据来源**：种子事件窗观测、关联事件扩查、显式反证检查

## 2. 范围界定与调查假设
- **本次调查范围**：本轮调查覆盖 2026-06-20 10:04:30 UTC 至 2026-06-20 11:18:00 UTC 内围绕 ws-legal-03 与 198.51.100.131、auth-queue-sync.net 的关键事件窗。
- **主假设**：围绕 ws-legal-03 与 198.51.100.131、auth-queue-sync.net 的异常通信及后续高风险迹象，当前应按“可疑事件，建议继续复核”收敛交付。
- **备选解释**：在 2026-06-20 10:46:10 UTC，资产 `ws-legal-09` 与 198.51.100.131 / identity-cache.vendor.example 的访问更接近计划内更新、维护或共享基础设施背景。
- **本轮不覆盖的范围**：本轮不把未经过独立验证的候选对象 ws-legal-09、ws-legal-12、203.0.113.131、cdn-auth-queue.net、legal-docs-cdn.example、login-queue-cdn.net 直接写成已确认范围，也不把背景情报直接写成已确认事实。
- **主假设成立所需条件**：当前主假设至少需要同时满足：种子告警需要能够对应到明确异常起点；同一基础设施的异常通信需要在同资产或关联资产上被再次观察到；已核查的维护或更新背景不足以解释整条主链；未独立验证的候选对象只能作为边界线索保留，不能直接写成确认影响范围。
- **主假设失效条件**：这条观测更支持背景解释或替代解释，而不是继续放大当前主假设。
- **本节主要依据来源**：种子事件窗观测、关联事件扩查、显式反证检查

## 3. 对象覆盖策略与关键实体
- **已纳入证据链的对象**：ws-legal-03、198.51.100.131、auth-queue-sync.net、t13d190900_7711aa22bb33_9911ccddee77
- **当前核心观测对象**：ws-legal-03、198.51.100.131、auth-queue-sync.net
- **横向对比对象**：198.51.100.131、auth-queue-sync.net、20.190.160.22、identity-cache.vendor.example、login.microsoftonline.com、10.44.1.18
- **扩展查询候选**：ws-legal-09、ws-legal-12、203.0.113.131、cdn-auth-queue.net、legal-docs-cdn.example、login-queue-cdn.net
- **种子资产**：ws-legal-03
- **待确认关联资产**：ws-legal-09、ws-legal-12
- **核心外部基础设施**：198.51.100.131、auth-queue-sync.net
- **关键指示物**：198.51.100.131、auth-queue-sync.net、t13d190900_7711aa22bb33_9911ccddee77
- **对象覆盖边界**：当前调查重点仍围绕 `ws-legal-03` 收敛，但还没有资产可以写成已确认受影响范围；候选对象 ws-legal-09、ws-legal-12、203.0.113.131、cdn-auth-queue.net、legal-docs-cdn.example、login-queue-cdn.net 继续作为边界线索保留。
- **本节主要依据来源**：显式反证检查、关联事件扩查、种子事件窗观测

## 4. 事件机制分解
- **触发因素 / 起点**：在 2026-06-20 10:12:00 UTC，资产 `ws-legal-03` 出现了一条与 198.51.100.131 / auth-queue-sync.net 相关的关键观测。
- **事件主链**：事件链以资产 `ws-legal-03` 出现了一条与 198.51.100.131 / auth-queue-sync.net 相关的关键观测 为起点。 其后，资产 `ws-legal-09` 先解析了少见域名 `cdn-auth-queue.net`，说明相同基础设施上的异常已经扩展到其他资产。
- **影响放大器 / 传播机制**：同一基础设施上的异常已经出现在 ws-legal-09、ws-legal-12 等资产上，说明当前结论不再局限于单点告警。
- **当前不能确认的机制环节**：是否存在主机侧执行、持久化或横向移动证据？、关联资产 ws-legal-09、ws-legal-12 是否真正受影响？、seed 自带的家族提示 Suspicious shared-infra beacon requiring review 是否有更多外部证据支撑？
- **本节主要依据来源**：种子事件窗观测、关联事件扩查、显式反证检查

## 5. 关键证据与异常事实

### 5.1 主支撑证据

#### 证据 E-01
- **证据类别**：调查触发证据（网络）
- **证据强度**：高
- **事实描述**：在 2026-06-20 10:12:00 UTC，资产 `ws-legal-03` 出现了一条与 198.51.100.131 / auth-queue-sync.net 相关的关键观测。
- **为什么支持当前主假设**：这是种子命中的直接落点，说明调查起点并不是孤立的指纹命中。
- **局限性与边界**：单条种子命中本身不能独立证明事件成立，仍需要结合重复通信、资产背景或主机侧线索共同定性。
- **本节主要依据来源**：种子事件窗观测、关联事件扩查、显式反证检查

#### 证据 E-02
- **证据类别**：连续性支撑证据（网络）
- **证据强度**：高
- **事实描述**：在 2026-06-20 10:21:40 UTC，资产 `ws-legal-03` 再次与 198.51.100.131 / auth-queue-sync.net 通信，说明同一基础设施上的异常仍在持续。
- **为什么支持当前主假设**：同一基础设施在种子资产或关联资产上再次出现，使单点告警扩展成可复核的连续事件链。
- **局限性与边界**：仅凭网络侧重复通信仍可能在少数情况下被正常组件、同步组件或运维脚本解释，因此仍需要结合资产背景或主机侧结果。
- **本节主要依据来源**：种子事件窗观测、关联事件扩查、显式反证检查

#### 证据 E-03
- **证据类别**：连续性支撑证据（网络）
- **证据强度**：高
- **事实描述**：在 2026-06-20 10:16:20 UTC，资产 `ws-legal-03` 再次与 198.51.100.131 / auth-queue-sync.net 通信，说明同一基础设施上的异常仍在持续。
- **为什么支持当前主假设**：同一基础设施在种子资产或关联资产上再次出现，使单点告警扩展成可复核的连续事件链。
- **局限性与边界**：仅凭网络侧重复通信仍可能在少数情况下被正常组件、同步组件或运维脚本解释，因此仍需要结合资产背景或主机侧结果。
- **本节主要依据来源**：种子事件窗观测、关联事件扩查、显式反证检查

#### 证据 E-04
- **证据类别**：范围确认依据（网络）
- **证据强度**：中
- **事实描述**：在 2026-06-20 10:42:00 UTC，资产 `ws-legal-09` 先解析了少见域名 `cdn-auth-queue.net`。
- **为什么支持当前主假设**：它把事件范围从种子资产推进到其他资产，使当前结论不再只停留在单点异常。
- **局限性与边界**：这条观测本身更适合用来补足上下文，而不是单独承担最终结论。
- **本节主要依据来源**：显式反证检查、关联事件扩查

#### 证据 E-05
- **证据类别**：范围确认依据（网络）
- **证据强度**：中
- **事实描述**：在 2026-06-20 10:49:30 UTC，资产 `ws-legal-12` 出现了一条与 198.51.100.131 / legal-docs-cdn.example 相关的关键观测。
- **为什么支持当前主假设**：它把事件范围从种子资产推进到其他资产，使当前结论不再只停留在单点异常。
- **局限性与边界**：这条观测本身更适合用来补足上下文，而不是单独承担最终结论。
- **本节主要依据来源**：关联事件扩查、显式反证检查

### 5.2 反证与替代解释

#### 证据 C-01
- **反证或替代解释**：反证与替代解释（网络）
- **相关事实**：在 2026-06-20 10:46:10 UTC，资产 `ws-legal-09` 与 198.51.100.131 / identity-cache.vendor.example 的访问更接近计划内更新、维护或共享基础设施背景。
- **为什么它不足以推翻主结论，或为什么它足以让我们降级**：这条观测更支持背景解释或替代解释，而不是继续放大当前主假设。
- **主要依据来源**：显式反证检查、关联事件扩查

#### 证据 C-02
- **反证或替代解释**：反证与替代解释（上下文）
- **相关事实**：在 2026-06-20 10:52:00 UTC，资产 `相关资产` 与 198.51.100.131 / auth-queue-sync.net 的访问更接近计划内更新、维护或共享基础设施背景。
- **为什么它不足以推翻主结论，或为什么它足以让我们降级**：这条观测更支持背景解释或替代解释，而不是继续放大当前主假设。
- **主要依据来源**：关联事件扩查

### 5.3 辅助背景与解释（可选）
- **相关背景**：Suspicious shared-infra beacon requiring review
- **它如何帮助理解本案**：当前可获得的背景提示主要来自家族/工具线索：Suspicious shared-infra beacon requiring review，与当前观察到的阶段形态 命令与控制 基本一致。
- **不能据此直接推出的结论**：这类背景提示更适合帮助理解攻击链或工具形态，不应直接当作样本级确认或强归因结论。
- **主要依据来源**：上游检测

## 6. 时序特征与行为模式

### 6.1 核心时间线

| 时间 | 事件 | 作用 |
| -- | -- | -- |
| 2026-06-20 10:04:30 UTC | 资产 `ws-legal-03`：先解析了少见域名 `auth-queue-sync.net` | 背景观测 |
| 2026-06-20 10:12:00 UTC | 资产 `ws-legal-03`：Seed JA4 alert observed an unusual TLS session to auth-queue-sync.net on shared infrastructure. | 调查起点 |
| 2026-06-20 10:16:20 UTC | 资产 `ws-legal-03`：再次与 auth-queue-sync.net、198.51.100.131 通信，说明同一基础设施上的异常仍在持续 | 主证据 |
| 2026-06-20 10:21:40 UTC | 资产 `ws-legal-03`：与 auth-queue-sync.net、198.51.100.131 建立了可疑通信 | 主证据 |
| 2026-06-20 10:24:00 UTC | 资产 `ws-legal-03`：Endpoint coverage for ws-legal-03 did not include command-line telemetry during the relevant window. | 背景观测 |
| 2026-06-20 10:39:00 UTC | 资产 `ws-legal-09`：A second workstation contacted cdn-auth-queue.net on the same shared IP, but only through one weak network signal. | 背景观测 |
| 2026-06-20 10:42:00 UTC | 资产 `ws-legal-09`：先解析了少见域名 `cdn-auth-queue.net` | 背景观测 |
| 2026-06-20 10:46:10 UTC | 资产 `ws-legal-09`：The same workstation also used a sanctioned identity-cache vendor domain on the shared hosting IP. | 反证检查 |
| 2026-06-20 10:49:30 UTC | 资产 `ws-legal-12`：A legal-document review workstation touched the same IP through a different business SaaS domain, suggesting shared infrastructure. | 背景观测 |
| 2026-06-20 10:52:00 UTC | Passive infrastructure context showed the IP hosted multiple unrelated customer domains during the same week. | 反证检查 |
| 2026-06-20 10:55:00 UTC | 资产 `ws-legal-03`：An approved SSO browser extension update on ws-legal-03 overlapped the first suspicious TLS session. | 反证检查 |
| 2026-06-20 11:01:20 UTC | 资产 `ws-legal-03`：Normal Microsoft identity traffic from ws-legal-03 appeared in the same SSO workflow window. | 反证检查 |
| 2026-06-20 11:08:30 UTC | 资产 `ws-legal-03`：先解析了少见域名 `login-queue-cdn.net` | 背景观测 |
| 2026-06-20 11:11:00 UTC | 资产 `ws-legal-03`：A single TLS connection to the second queue-themed domain remained an unresolved follow-on indicator without host corroboration. | 背景观测 |
| 2026-06-20 11:18:00 UTC | 资产 `ws-legal-09`：EDR coverage for ws-legal-09 did not include command-line telemetry in this window, limiting scope confirmation. | 背景观测 |

### 6.2 模式总结
- 当前尚未识别明确的初始入侵入口，现有证据主要从异常外联及后续行为开始收敛。
- 告警前后已经出现了解析或访问准备动作，说明异常不是完全孤立的单点命中。
- 告警后存在复现或持续性通信，说明相关行为具有连续性。
- 同时间窗也完成了替代解释检查，但现有反证不足以完全推翻主链。
- **本节主要依据来源**：种子事件窗观测、关联事件扩查、显式反证检查

## 7. 传播与关联分析
- **关联扩查主轴**：auth-queue-sync.net、cdn-auth-queue.net、identity-cache.vendor.example、legal-docs-cdn.example、login.microsoftonline.com、login-queue-cdn.net、198.51.100.131、20.190.160.22、203.0.113.131、10.44.1.18、t13d190900_7711aa22bb33_9911ccddee77
- **已确认关联**：在 2026-06-20 10:42:00 UTC，资产 `ws-legal-09` 先解析了少见域名 `cdn-auth-queue.net`。、在 2026-06-20 10:49:30 UTC，资产 `ws-legal-12` 出现了一条与 198.51.100.131 / legal-docs-cdn.example 相关的关键观测。、当前调查一共纳入了 15 条关键事件，当前调查重点仍围绕 `ws-legal-03`。
- **候选关联**：是否存在主机侧执行、持久化或横向移动证据？、关联资产 ws-legal-09、ws-legal-12 是否真正受影响？、seed 自带的家族提示 Suspicious shared-infra beacon requiring review 是否有更多外部证据支撑？
- **未完成独立验证的对象**：ws-legal-09、ws-legal-12、203.0.113.131、cdn-auth-queue.net、legal-docs-cdn.example、login-queue-cdn.net
- **当前关联边界**：当前还没有可写入已确认影响范围的资产；调查重点仍围绕 `ws-legal-03`，其余候选对象保持待确认状态。
- **本节主要依据来源**：显式反证检查、关联事件扩查

## 8. 影响分析
- **当前已确认影响**：当前已确认的事实主要收敛在 ws-legal-03 与 198.51.100.131、auth-queue-sync.net 之间的异常通信及后续高风险迹象。
- **当前疑似影响**：仍需继续核实的对象包括 ws-legal-09、ws-legal-12、203.0.113.131、cdn-auth-queue.net、legal-docs-cdn.example。
- **时间范围**：2026-06-20 10:04:30 UTC 至 2026-06-20 11:18:00 UTC
- **资产范围**：ws-legal-03
- **外部基础设施范围**：198.51.100.131、auth-queue-sync.net
- **当前攻击阶段**：命令与控制
- **仍未确认的影响**：当前尚未观测到稳定的执行阶段证据，因此还不能确认主机侧执行、持久化或横向移动是否已经成立。、当前仍缺少对“关联资产 ws-legal-09、ws-legal-12 是否真正受影响？”的直接补证。、当前仍缺少对“seed 自带的家族提示 Suspicious shared-infra beacon requiring review 是否有更多外部证据支撑？”的直接补证。
- **本节主要依据来源**：显式反证检查、关联事件扩查

## 9. 证据链摘要与观测缺口
- **当前判断主要建立在**：种子告警已经和明确异常起点对齐；同一基础设施的连续通信已在同资产或关联资产上被复现；异常范围已经不再局限于种子资产；已核查的维护或更新背景不足以解释整条主链。
- **当前最强证据**：在 2026-06-20 10:42:00 UTC，资产 `ws-legal-09` 先解析了少见域名 `cdn-auth-queue.net`，说明把事件范围从种子资产推进到其他资产，使当前结论不再只停留在单点异常。
- **当前最关键缺口**：是否存在主机侧执行、持久化或横向移动证据？
- **当前最多只能走到的判断层级**：当前最多适合稳定交付为 `可疑事件，建议继续复核`，尚不足以直接升级为 `确认安全事件`。
- **因缺口而不能写出的结论**：当前尚未观测到稳定的执行阶段证据，因此还不能确认主机侧执行、持久化或横向移动是否已经成立。、当前仍缺少对“关联资产 ws-legal-09、ws-legal-12 是否真正受影响？”的直接补证。、当前仍缺少对“seed 自带的家族提示 Suspicious shared-infra beacon requiring review 是否有更多外部证据支撑？”的直接补证。
- **下一轮最值得补的证据**：当前缺少继续缩小该缺口的有效手段，更适合作为报告边界说明。
- **本节主要依据来源**：种子事件窗观测、关联事件扩查、显式反证检查

## 10. 结论与后续建议
- **当前结论**：可疑事件，建议继续复核
- **当前状态**：可疑事件，建议继续复核
- **严重度**：中
- **研判把握**：高
- **一句话概括**：ws-legal-03 围绕 198.51.100.131、auth-queue-sync.net 已出现连续异常迹象，但由于还需要进一步确认主机侧是否已经出现能够直接支撑执行、持久化或横向移动的证据，当前仍按待人工复核事件交付。
- **为什么当前结论成立**：当前已经形成：种子告警已经和明确异常起点对齐；同一基础设施的连续通信已在同资产或关联资产上被复现；异常范围已经不再局限于种子资产；已核查的维护或更新背景不足以解释整条主链；但由于还需要进一步确认主机侧是否已经掌握能够直接支撑执行、持久化或横向移动的证据，本案仍需要按待人工复核结论交付。
- **为什么不是相邻状态**：当前主链已经超过单点命中，但还需要进一步确认主机侧是否已经掌握能够直接支撑执行、持久化或横向移动的证据，因此暂不直接升级为确认事件。

### 10.1 建议立即动作
- 优先隔离或重点监控资产：ws-legal-03。
- 在边界和代理设备上排查并封禁外部基础设施：198.51.100.131、auth-queue-sync.net。

### 10.2 短期排查动作
- 继续核实待复核关联资产 ws-legal-09、ws-legal-12。
- 优先补查：是否存在主机侧执行、持久化或横向移动证据？。

### 10.3 持续监控或复核动作
- 当前暂无需要单列的持续监控或复核动作。
- **下一次复核最值得补的证据**：当前缺少继续缩小该缺口的有效手段，更适合作为报告边界说明。

## 11. 技术附录提示
- 技术细节、IOC/IOA、关键对象清单、观测对照、引用来源、证据缺口与待补查询请见《事件调查技术附录》。
