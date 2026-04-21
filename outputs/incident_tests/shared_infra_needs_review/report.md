# 事件级溯源报告

## 研判结论
- 结论：待人工复核
- 严重度：中危
- 置信度：58
- 核心判断：上下文已形成，但仍需人工复核
- 结论摘要：自动聚合已经找到可关联的上下文，不过现阶段仍缺少足够强的执行或持续控制证据。

## 资产与范围
- 种子资产：ws-design-07
- 重点观察资产：ws-design-07
- 待排查关联资产：ws-design-11
- 内部 IP：10.55.4.19、10.55.4.21
- 外部 IP：198.51.100.66
- 域名：auth-sync-edge.net、cdn-auth-sync.net
- 时间窗口：2026-04-07 11:17:00 UTC 至 2026-04-07 11:50:00 UTC
- 核心支撑事件数：2，待解释关联事件数：3，反证/背景事件数：0

## 事件边界
- 事件簇大小：5 条事件。
- 当前攻击阶段：command-and-control。
- 主要外部指示物：198.51.100.66、auth-sync-edge.net
- 当前待重点复核的关联资产：ws-design-11

## 当前判断依据
- 当前已有可疑关联，但支撑证据还不足以推进为确认事件。
- 当前主支撑信号仍集中在 ws-design-07；ws-design-11 仅表现出共享基础设施上的弱关联，暂时不能按扩散处理。
- 核心支撑链：目前最强的支撑来自 ws-design-07 围绕 198.51.100.66、auth-sync-edge.net 的重复通信，但这条链还没有延伸到执行或扩散层。
- 背景/反证：其余关联资产目前更多体现为范围参考，而不是已经受影响的直接证据。

## 主支撑证据
- 2026-04-07 11:20:00 UTC | ws-design-07 | alert | 指示物：198.51.100.66 / auth-sync-edge.net / JA4 t13d190900_44ae3120b3c1_909fe43ab981；Seed JA4 alert observed a suspicious TLS session to the same rare external infrastructure.；这是种子命中的直接落点，说明告警并不是孤立的指纹命中。
- 2026-04-07 11:24:00 UTC | ws-design-07 | flow | 指示物：198.51.100.66 / auth-sync-edge.net；The same workstation reconnected to the same external IP a few minutes after the seed alert.；同一资产围绕同一批外部基础设施再次通信，单条告警已经扩展成连续事件链。

## 时间线
- 2026-04-07 11:17:00 UTC [上下文] The seed workstation resolved a rare domain shortly before the JA4 alert fired.
- 2026-04-07 11:20:00 UTC [种子告警] Seed JA4 alert observed a suspicious TLS session to the same rare external infrastructure.
- 2026-04-07 11:24:00 UTC [主证据] The same workstation reconnected to the same external IP a few minutes after the seed alert.
- 2026-04-07 11:46:00 UTC [上下文] A second workstation contacted a sibling domain on the same external IP, but there is still no endpoint corroboration.
- 2026-04-07 11:50:00 UTC [上下文] The second workstation resolved another rare domain pointing to the same shared infrastructure.

## 当前判断边界
- 当前已经形成可关联的事件簇，但证据还不足以把结论稳定推进到确认事件。
- 当前仍缺少足够强的主机侧执行或扩散证据，自动结论需要结合人工复核。
- 主支撑信号目前仍集中在单个重点资产上，尚未确认存在更大范围扩散。
- 其他关联资产目前更多体现为共享基础设施上的弱关联，仍需逐台确认是否真正受影响。
- 事件簇中尚未观测到稳定的执行阶段证据。

## 建议动作
- 对重点资产补采主机侧日志，确认是否存在执行、持久化或横向移动证据。
- 继续围绕同域名 / 同 dst_ip / 同 JA4 搜索更宽时间窗内的关联事件。
- 把关联资产 ws-design-11 纳入复核清单，确认它们是共享基础设施背景还是真实受影响对象。
