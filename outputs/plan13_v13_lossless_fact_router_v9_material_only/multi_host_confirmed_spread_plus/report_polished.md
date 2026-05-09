# 首页摘要

- **结论**：可疑事件，建议继续复核。
- **严重度**：中
- **研判把握**：中
- **已确认范围**：`ws-eng-02` 和 `ws-eng-05`
- **最强证据**：`ws-eng-02` 在 `2026-07-14 01:10:00 UTC` 发送了一个可疑的 TLS 信标到罕见的外部基础设施。
- **关键缺口**：仍需围绕当前关键关联指标做一次显式扩线，确认是否存在同指标的更大范围复现。
- **立即动作**：对重点资产补采主机侧日志，确认是否存在执行、持久化或横向移动证据。
- **一句话结论**：当前只能依据已整理的交付判断和证据包保守生成报告材料。

## 调查起点与已知线索

可疑事件，建议继续复核；事件簇已经从单点异常推进到高风险阶段或保守收敛后的多资产范围，足以支撑事件成立。种子告警自带家族/工具提示：Suspected multi-host beacon spread。已观察到关联资产或共享基础设施上的扩展信号，但尚需继续确认是否属于同一事件。交付门槛尚未满足：仍有 5 条候选扩线事件没有完成独立验证。尚未执行显式反证检查。仍缺少情报或结构化整理动作，报告材料尚未收束。仍需围绕当前关键关联指标做一次显式扩线，确认是否存在同指标的更大范围复现。

2026-07-14 01:04:00 UTC，资产 `ws-eng-02` 关联对象 `sync-cdn-notify.net`，The seed workstation resolved a rare domain shortly before the suspicious TLS session。源地址 `10.70.3.12`。这一事实表明，在可疑TLS会话之前，种子工作站解析了一个罕见的域名，这可能是事件的起点。

2026-07-14 01:10:00 UTC，资产 `ws-eng-02` 关联对象 `sync-cdn-notify.net / 203.0.113.77`，Seed JA4 alert matched a suspicious TLS beacon to rare external infrastructure。源地址 `10.70.3.12`。这一事实进一步支持了可疑TLS会话的存在，并且与罕见的外部基础设施相关联，这是事件的主要支撑证据之一。

2026-07-14 01:14:20 UTC，资产 `ws-eng-02` 关联对象 `sync-cdn-notify.net / 203.0.113.77`，The seed workstation reconnected to the same C2 infrastructure after the alert。源地址 `10.70.3.12`。这一事实表明，种子工作站重新连接到了相同的C2基础设施，这进一步支持了事件的持续性和复杂性。

## 调查范围与研判假设

对象 `ws-eng-02`，类型为资产，当前角色为种子资产，种子告警首先落在该资产上。当前已纳入主证据链的资产。事件中出现过的资产对象。当前关键关联指标里出现的扩线候选资产。这表明 `ws-eng-02` 是事件的核心资产，其行为模式和网络活动是事件的重要线索。

对象 `ws-eng-05`，类型为资产，当前角色为已确认受影响资产，当前已纳入主证据链的资产。事件中出现过的资产对象。当前关键关联指标里出现的扩线候选资产。事件聚类中仍需独立验证的候选资产。这表明 `ws-eng-05` 也受到了影响，其行为模式和网络活动也是事件的重要线索。

对象 `ws-eng-09`，类型为资产，当前角色为待确认关联资产，当前仍需独立验证是否真正受影响。事件中出现过的资产对象。当前关键关联指标里出现的扩线候选资产。事件聚类中仍需独立验证的候选资产。这表明 `ws-eng-09` 是一个待确认的候选资产，需要进一步验证其是否真正受到影响。

对象 `203.0.113.77`，类型为IP，当前角色为核心外部基础设施，当前主证据链中反复出现的关键对象。当前关键关联指标里出现的扩线候选地址。这表明 `203.0.113.77` 是一个重要的外部基础设施，其在网络活动中扮演着关键角色。

对象 `sync-cdn-notify.net`，类型为域名，当前角色为核心外部基础设施，当前主证据链中反复出现的关键对象。当前关键关联指标里出现的扩线候选域名。这表明 `sync-cdn-notify.net` 是一个重要的外部基础设施，其在网络活动中扮演着关键角色。

## 事件过程与行为模式

2026-07-14 01:04:00 UTC，资产 `ws-eng-02` 关联对象 `sync-cdn-notify.net`，The seed workstation resolved a rare domain shortly before the suspicious TLS session。源地址 `10.70.3.12`。这一事实表明，在可疑TLS会话之前，种子工作站解析了一个罕见的域名，这可能是事件的起点。

2026-07-14 01:10:00 UTC，资产 `ws-eng-02` 关联对象 `sync-cdn-notify.net / 203.0.113.77`，Seed JA4 alert matched a suspicious TLS beacon to rare external infrastructure。源地址 `10.70.3.12`。这一事实进一步支持了可疑TLS会话的存在，并且与罕见的外部基础设施相关联，这是事件的主要支撑证据之一。

2026-07-14 01:14:20 UTC，资产 `ws-eng-02` 关联对象 `sync-cdn-notify.net / 203.0.113.77`，The seed workstation reconnected to the same C2 infrastructure after the alert。源地址 `10.70.3.12`。这一事实表明，种子工作站重新连接到了相同的C2基础设施，这进一步支持了事件的持续性和复杂性。

2026-07-14 01:18:00 UTC，资产 `ws-eng-02`，Suspicious rundll32.exe launched a loader DLL from a user-writable path shortly after the beacon sequence。源地址 `10.70.3.12`。这一事实表明，可疑的rundll32.exe进程在beacon序列之后从用户可写的路径启动了一个loader DLL，这可能是可疑执行线索。

2026-07-14 01:21:10 UTC，资产 `ws-eng-02` 关联对象 `10.70.3.45`，PsExec remote service creation from ws-eng-02 to ws-eng-05 followed the seed beacon traffic。源地址 `10.70.3.12`。这一事实表明，PsExec远程服务创建从 `ws-eng-02` 到 `ws-eng-05`，这可能是潜在的横向移动线索。

2026-07-14 01:28:40 UTC，资产 `ws-eng-05` 关联对象 `sync-cdn-notify.net / 203.0.113.77`，A second workstation contacted the original beacon infrastructure minutes after the remote-service event。源地址 `10.70.3.45`。这一事实表明，第二台工作站几分钟后联系了原始的beacon基础设施，这进一步支持了事件的持续性和复杂性。

2026-07-14 01:32:10 UTC，资产 `ws-eng-05` 关联对象 `cdn-notify-edge.net`，The second workstation resolved a secondary rare domain that did not appear in the种子告警。源地址 `10.70.3.45`。这一事实表明，第二台工作站解析了一个次要的罕见域名，这可能是待确认扩线或边界线索。

2026-07-14 01:36:00 UTC，资产 `ws-eng-05` 关联对象 `cdn-notify-edge.net / 198.51.100.44`，The second workstation pivoted to a second external IP over TLS after reaching the original beacon host。源地址 `10.70.3.45`。这一事实表明，第二台工作站通过TLS切换到第二个外部IP，这可能是待确认扩线或边界线索。

## 关键事实与证据判断

2026-07-14 01:04:00 UTC，资产 `ws-eng-02` 关联对象 `sync-cdn-notify.net`，The seed workstation resolved a rare domain shortly before the suspicious TLS session。源地址 `10.70.3.12`。这一事实表明，在可疑TLS会话之前，种子工作站解析了一个罕见的域名，这可能是事件的起点。

2026-07-14 01:10:00 UTC，资产 `ws-eng-02` 关联对象 `sync-cdn-notify.net / 203.0.113.77`，Seed JA4 alert matched a suspicious TLS beacon to rare external infrastructure。源地址 `10.70.3.12`。这一事实进一步支持了可疑TLS会话的存在，并且与罕见的外部基础设施相关联，这是事件的主要支撑证据之一。

2026-07-14 01:14:20 UTC，资产 `ws-eng-02` 关联对象 `sync-cdn-notify.net / 203.0.113.77`，The seed workstation reconnected to the same C2 infrastructure after the alert。源地址 `10.70.3.12`。这一事实表明，种子工作站重新连接到了相同的C2基础设施，这进一步支持了事件的持续性和复杂性。

2026-07-14 01:18:00 UTC，资产 `ws-eng-02`，Suspicious rundll32.exe launched a loader DLL from a user-writable path shortly after the beacon sequence。源地址 `10.70.3.12`。这一事实表明，可疑的rundll32.exe进程在beacon序列之后从用户可写的路径启动了一个loader DLL，这可能是可疑执行线索。

2026-07-14 01:28:40 UTC，资产 `ws-eng-05` 关联对象 `sync-cdn-notify.net / 203.0.113.77`，A second workstation contacted the original beacon infrastructure minutes after the remote-service event。源地址 `10.70.3.45`。这一事实表明，第二台工作站几分钟后联系了原始的beacon基础设施，这进一步支持了事件的持续性和复杂性。

检索到 6 条偏可疑事件，围绕 `sync-cdn-notify.net`、`203.0.113.77`、`10.70.3.45` 展开。这一事实表明，这些事件围绕特定的域名和IP展开，进一步支持了事件的复杂性和持续性。

扩线检索到 9 条可疑关联事件，围绕 `sync-cdn-notify.net`、`cdn-notify-edge.net`、`203.0.113.77` 展开；当前先作为待验证候选线索。这一事实表明，这些事件需要进一步验证，以确认是否属于同一事件。

## 关联范围与候选边界

对象 `ws-eng-02`，类型为资产，当前角色为种子资产，种子告警首先落在该资产上。当前已纳入主证据链的资产。事件中出现过的资产对象。当前关键关联指标里出现的扩线候选资产。这表明 `ws-eng-02` 是事件的核心资产，其行为模式和网络活动是事件的重要线索。

对象 `ws-eng-05`，类型为资产，当前角色为已确认受影响资产，当前已纳入主证据链的资产。事件中出现过的资产对象。当前关键关联指标里出现的扩线候选资产。事件聚类中仍需独立验证的候选资产。这表明 `ws-eng-05` 也受到了影响，其行为模式和网络活动也是事件的重要线索。

对象 `ws-eng-09`，类型为资产，当前角色为待确认关联资产，当前仍需独立验证是否真正受影响。事件中出现过的资产对象。当前关键关联指标里出现的扩线候选资产。事件聚类中仍需独立验证的候选资产。这表明 `ws-eng-09` 是一个待确认的候选资产，需要进一步验证其是否真正受到影响。

对象 `203.0.113.77`，类型为IP，当前角色为核心外部基础设施，当前主证据链中反复出现的关键对象。当前关键关联指标里出现的扩线候选地址。这表明 `203.0.113.77` 是一个重要的外部基础设施，其在网络活动中扮演着关键角色。

对象 `sync-cdn-notify.net`，类型为域名，当前角色为核心外部基础设施，当前主证据链中反复出现的关键对象。当前关键关联指标里出现的扩线候选域名。这表明 `sync-cdn-notify.net` 是一个重要的外部基础设施，其在网络活动中扮演着关键角色。

对象 `13.107.246.45`，类型为IP，当前角色为背景/上下文指标，用于补充边界或背景解释的对象。当前关键关联指标里出现的扩线候选地址。这表明 `13.107.246.45` 是一个背景对象，用于补充事件的边界或背景解释。

对象 `ws-lab-02`，类型为资产，当前角色为扩展查询候选，当前关键关联指标里出现的扩线候选资产。这表明 `ws-lab-02` 是一个待确认的候选资产，需要进一步验证其是否真正受到影响。

对象 `cdn-notify-edge.net`，类型为域名，当前角色为扩展查询候选，当前关键关联指标里出现的扩线候选域名。候选事件涉及的域名，尚未进入已确认主链。这表明 `cdn-notify-edge.net` 是一个待确认的候选域名，需要进一步验证其是否真正受到影响。

## 反证、缺口与结论边界

仍需围绕当前关键关联指标做一次显式扩线，确认是否存在同指标的更大范围复现。这一缺口限制了更强结论或范围扩展，但不等于否定当前已支撑事实。

扩线得到的 5 条关联事件尚未完成独立验证，是否应并入主事件范围？这一缺口限制了更强结论或范围扩展，但不等于否定当前已支撑事实。

仍需显式检查维护窗口、补丁、备份或共享基线等反证。这一缺口限制了更强结论或范围扩展，但不等于否定当前已支撑事实。

仍需把当前事件事实沉淀为 claim 或可引用实体，避免报告只剩原始事件聚合。这一缺口限制了更强结论或范围扩展，但不等于否定当前已支撑事实。

背景/替代解释事件：2026-07-14 01:24:00 UTC，资产 `ws-eng-05`，Approved SCCM patch staging began on ws-eng-05 in the same hour and could explain some routine admin activity。源地址 `10.70.3.45`。这一事实表明，批准的SCCM补丁部署可能解释了一些常规管理活动，这可能是背景或替代解释事件。

背景/替代解释事件：2026-07-14 01:26:00 UTC，资产 `ws-eng-05` 关联对象 `download.windowsupdate.com / 13.107.246.45`，Windows update content was downloaded from an approved Microsoft endpoint during the maintenance window。源地址 `10.70.3.45`。这一事实表明，Windows更新内容在维护窗口期间从一个批准的Microsoft端点下载，这可能是背景或替代解释事件。

背景/替代解释事件：2026-07-14 01:44:10 UTC，资产 `ws-eng-09` 关联对象 `cdn-notify-edge.net`，A third workstation later resolved the secondary domain that emerged only after expansion。源地址 `10.70.3.90`。这一事实表明，第三台工作站后来解析了在扩展后才出现的二级域名，这可能是背景或替代解释事件。

背景/替代解释事件：2026-07-14 01:46:20 UTC，资产 `ws-lab-02` 关联对象 `telemetry-collector.example / 198.51.100.44`，A QA telemetry job also touched the same hosting IP through a different vendor domain, indicating the secondary IP is shared infrastructure。源地址 `10.70.8.22`。这一事实表明，QA遥测作业通过不同的供应商域接触了相同的托管IP，这可能是背景或替代解释事件。

## 结论与后续动作

可疑事件，建议继续复核；事件簇已经从单点异常推进到高风险阶段或保守收敛后的多资产范围，足以支撑事件成立。种子告警自带家族/工具提示：Suspected multi-host beacon spread。已观察到关联资产或共享基础设施上的扩展信号，但尚需继续确认是否属于同一事件。交付门槛尚未满足：仍有 5 条候选扩线事件没有完成独立验证。尚未执行显式反证检查。仍缺少情报或结构化整理动作，报告材料尚未收束。仍需围绕当前关键关联指标做一次显式扩线，确认是否存在同指标的更大范围复现。

对重点资产补采主机侧日志，确认是否存在执行、持久化或横向移动证据。这一行动建议是为了进一步验证事件的复杂性和持续性，确保没有遗漏任何重要线索。

继续围绕相同域名、目标IP和JA4通信指纹搜索更宽时间窗内的关联事件。这一行动建议是为了扩大搜索范围，确保没有遗漏任何相关事件。

优先核验新扩出的关联事件是否存在独立命中，不要只因为共享基础设施就直接并入主证据链。这一行动建议是为了确保新扩出的关联事件具有独立性，避免误判。

把关联资产 `ws-eng-09` 纳入复核清单，确认它们是共享基础设施背景还是真实受影响对象。这一行动建议是为了进一步验证 `ws-eng-09` 是否真正受到影响，确保没有遗漏任何重要线索。

技术细节、IOC/IOA、关键对象清单、观测引用、证据细目和待补缺口详见技术附录。