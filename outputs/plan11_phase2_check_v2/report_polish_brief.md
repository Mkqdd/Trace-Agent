# Report Writer Brief

## Writing Task
- 目标读者：运维人员与安全运营协同对象。
- 正文必须只基于下方 packets 与各章节允许引用的 fact cards 写作，不要使用这些材料之外的事实。
- 正文只负责解释判断、范围和动作；完整技术细节会在正文后自动追加，不要在正文重复 IOC 表、对象表和观测映射表。
- 如果某节材料不足，请保留标题并用保守表述说明当前证据不足，不得补写。
- Fact Catalog 会把全部可用事实只列一次；各章节仅围绕 Section Fact Map 中给出的 fact ID 取材。

## Header Packet
- 事件标题：ws-eng-02 Suspected multi-host beacon spread 调查报告
- 分析窗口：2026-07-14 01:04:00 UTC 至 2026-07-14 01:49:00 UTC
- 最终结论：确认安全事件
- 严重度：高
- 研判把握：高
- 已确认范围：ws-eng-02、ws-eng-05
- 一句话结论：ws-eng-02、ws-eng-05 围绕 203.0.113.77、sync-cdn-notify.net 已形成可以稳定交付的异常链。

## Verdict Packet
- 结论陈述：ws-eng-02、ws-eng-05 围绕 203.0.113.77、sync-cdn-notify.net 已形成可以稳定交付的异常链。

## Scope Packet
- 已确认对象：ws-eng-02；ws-eng-05
- 待确认对象：ws-eng-09

## Constraint Packet
- 边界陈述：当前确认范围收敛在 ws-eng-02、ws-eng-05；ws-eng-09 保持待确认状态。
- 未闭合问题：扩线得到的 3 条关联事件尚未完成独立验证，是否应并入主事件范围？
- 反证与替代解释：显式反证检查发现 2 条更接近维护、更新、补丁或备份背景的事件。

## Action Packet
- 立即动作：优先隔离或重点监控资产：ws-eng-02、ws-eng-05。；在边界和代理设备上排查并封禁外部基础设施：203.0.113.77、sync-cdn-notify.net。
- 下一步动作：继续核实待确认关联资产 ws-eng-09。；优先补查：扩线得到的 3 条关联事件尚未完成独立验证，是否应并入主事件范围。

## Fact Catalog
### 已确认事件事实
- `fact-event-evt-801`：2026-07-14 01:04:00 UTC 资产 `ws-eng-02` 解析域名 `sync-cdn-notify.net`。
- `fact-event-evt-802`：2026-07-14 01:10:00 UTC 资产 `ws-eng-02` 对外通信 `sync-cdn-notify.net / 203.0.113.77`。
- `fact-event-evt-803`：2026-07-14 01:14:20 UTC 资产 `ws-eng-02` 对外通信 `sync-cdn-notify.net / 203.0.113.77`。
- `fact-event-evt-804`：2026-07-14 01:18:00 UTC 资产 `ws-eng-02` 出现执行迹象 `相关主机执行活动`。
- `fact-event-evt-805`：2026-07-14 01:21:10 UTC 资产 `ws-eng-02` 访问内网目标 `10.70.3.45`。
- `fact-event-evt-808`：2026-07-14 01:28:40 UTC 资产 `ws-eng-05` 对外通信 `sync-cdn-notify.net / 203.0.113.77`。
- `fact-event-evt-810`：2026-07-14 01:36:00 UTC 资产 `ws-eng-05` 对外通信 `cdn-notify-edge.net / 198.51.100.44`。
- `fact-event-evt-811`：2026-07-14 01:39:20 UTC 资产 `ws-eng-05` 访问内网目标 `10.70.3.90`。
### 待确认事件事实
- `fact-event-evt-812`：2026-07-14 01:44:10 UTC 资产 `ws-eng-09` 与 `cdn-notify-edge.net` 出现待确认关联命中。
- `fact-event-evt-809`：2026-07-14 01:32:10 UTC 资产 `ws-eng-05` 与 `cdn-notify-edge.net` 出现待确认关联命中。
- `fact-event-evt-813`：2026-07-14 01:47:30 UTC 资产 `ws-eng-09` 与 `cdn-notify-edge.net / 198.51.100.44` 出现待确认关联命中。
- `fact-event-evt-814`：2026-07-14 01:49:00 UTC 资产 `ws-eng-09` 与 `主机侧上下文线索` 出现待确认关联命中。
### 背景事件事实
- `fact-event-evt-806`：2026-07-14 01:24:00 UTC 资产 `ws-eng-05` 当前出现仅用于边界说明的背景事件 `维护或计划内背景活动`。
- `fact-event-evt-807`：2026-07-14 01:26:00 UTC 资产 `ws-eng-05` 当前出现仅用于边界说明的背景事件 `download.windowsupdate.com / 13.107.246.45`。
- `fact-event-evt-815`：2026-07-14 01:46:20 UTC 资产 `ws-lab-02` 当前出现仅用于边界说明的背景事件 `telemetry-collector.example / 198.51.100.44`。
### 已确认范围对象
- `fact-scope-obj-01`：对象 `ws-eng-02` 当前作为种子资产纳入已确认范围。
- `fact-scope-obj-02`：对象 `ws-eng-05` 当前作为已确认受影响资产纳入已确认范围。
- `fact-scope-obj-04`：对象 `203.0.113.77` 当前作为核心外部基础设施纳入已确认范围。
- `fact-scope-obj-05`：对象 `sync-cdn-notify.net` 当前作为核心外部基础设施纳入已确认范围。
- `fact-scope-obj-12`：对象 `10.70.3.12` 当前作为关联内部地址纳入已确认范围。
- `fact-scope-obj-13`：对象 `10.70.3.45` 当前作为关联内部地址纳入已确认范围。
- `fact-scope-obj-14`：对象 `10.70.3.90` 当前作为关联内部地址纳入已确认范围。
- `fact-scope-obj-15`：对象 `10.70.8.22` 当前作为关联内部地址纳入已确认范围。
### 待确认范围对象
- `fact-scope-obj-03`：对象 `ws-eng-09` 当前作为待确认关联资产保留为待确认范围。
- `fact-scope-obj-17`：对象 `cdn-notify-edge.net` 当前作为扩展查询候选保留为待确认范围。
- `fact-scope-obj-18`：对象 `t13d1516h2_2ba4190accc0_13fe129f5abc` 当前作为扩展查询候选保留为待确认范围。
- `fact-scope-obj-16`：对象 `ws-lab-02` 当前作为扩展查询候选保留为待确认范围。
### 背景指标对象
- `fact-scope-obj-06`：对象 `13.107.246.45` 当前只作为背景/上下文指标保留为背景指标。
- `fact-scope-obj-07`：对象 `198.51.100.44` 当前只作为背景/上下文指标保留为背景指标。
- `fact-scope-obj-08`：对象 `download.windowsupdate.com` 当前只作为背景/上下文指标保留为背景指标。
- `fact-scope-obj-09`：对象 `telemetry-collector.example` 当前只作为背景/上下文指标保留为背景指标。
- `fact-scope-obj-11`：对象 `Suspected multi-host beacon spread` 当前只作为家族/工具提示保留为背景指标。
- `fact-scope-obj-10`：对象 `t13d1516h2_2ba4190accc0_13fe129f5abc` 当前只作为种子命中指纹保留为背景指标。
### 反证事实
- `fact-counter-cl-08`：显式反证检查发现 2 条更接近维护、更新、补丁或备份背景的事件。
### 缺口事实
- `fact-gap-validate_candidate_events`：当前仍需对“扩线得到的 3 条关联事件尚未完成独立验证，是否应并入主事件范围？”补充独立确认。
### 动作依据事实
- `fact-action-01`：优先隔离或重点监控资产：ws-eng-02、ws-eng-05。
- `fact-action-02`：在边界和代理设备上排查并封禁外部基础设施：203.0.113.77、sync-cdn-notify.net。
- `fact-action-03`：继续核实待确认关联资产 ws-eng-09。
- `fact-action-04`：优先补查：扩线得到的 3 条关联事件尚未完成独立验证，是否应并入主事件范围。

## Section Fact Map
### 首页摘要
- 本节目标：只收敛结论、严重度、把握度、已确认范围和立即动作，不展开附录型对象清单。
- 可引用 packets：verdict_packet；scope_packet；action_packet
- 优先引用事实 ID（按顺序）：fact-event-evt-801；fact-event-evt-802；fact-event-evt-803；fact-scope-obj-01；fact-scope-obj-02
### 1. 事件背景与已知线索
- 本节目标：说明事件为什么进入调查、初始异常是什么、当前最关键的外部基础设施是什么。
- 可引用 packets：verdict_packet；scope_packet
- 优先引用事实 ID（按顺序）：fact-event-evt-801；fact-event-evt-802；fact-scope-obj-01；fact-scope-obj-04；fact-scope-obj-05
### 2. 范围界定与调查假设
- 本节目标：说明本轮判断覆盖到哪里、哪些对象仍待确认、为什么边界停在这里。
- 可引用 packets：scope_packet；constraint_packet
- 优先引用事实 ID（按顺序）：fact-scope-obj-01；fact-scope-obj-02；fact-scope-obj-04；fact-scope-obj-05；fact-scope-obj-03；fact-gap-validate_candidate_events；fact-counter-cl-08
### 3. 对象覆盖策略与关键实体
- 本节目标：区分已确认资产、待确认对象、核心外部基础设施和背景指标，只点关键对象。
- 可引用 packets：scope_packet
- 优先引用事实 ID（按顺序）：fact-scope-obj-01；fact-scope-obj-02；fact-scope-obj-03；fact-scope-obj-04；fact-scope-obj-05
### 4. 事件机制分解
- 本节目标：按推进关系解释事件从异常通信到执行/横向的主链，不逐条重放所有时间点。
- 可引用 packets：verdict_packet；scope_packet
- 优先引用事实 ID（按顺序）：fact-event-evt-801；fact-event-evt-802；fact-event-evt-803；fact-event-evt-804；fact-event-evt-805
### 5. 关键证据与异常事实
- 本节目标：只抓最关键的支撑事实与反证边界，写清它们为什么改变判断。
- 可引用 packets：verdict_packet；constraint_packet
- 优先引用事实 ID（按顺序）：fact-event-evt-801；fact-event-evt-802；fact-event-evt-803；fact-scope-obj-01；fact-scope-obj-02；fact-counter-cl-08
### 6. 时序特征与行为模式
- 本节目标：只保留少量关键时间节点，并说明这些节点对判断意味着什么。
- 可引用 packets：verdict_packet；constraint_packet
- 优先引用事实 ID（按顺序）：fact-event-evt-801；fact-event-evt-802；fact-event-evt-803；fact-event-evt-811；fact-event-evt-806
### 7. 传播与关联分析
- 本节目标：说明哪些关联已经进入主判断，哪些扩线结果仍只是候选或边界说明。
- 可引用 packets：scope_packet；constraint_packet
- 优先引用事实 ID（按顺序）：fact-event-evt-804；fact-event-evt-805；fact-event-evt-812；fact-event-evt-809；fact-event-evt-813；fact-scope-obj-03
### 8. 影响分析
- 本节目标：说明已经确认的影响范围、仍待确认的部分，以及这对运维处置意味着什么。
- 可引用 packets：verdict_packet；scope_packet；action_packet
- 优先引用事实 ID（按顺序）：fact-scope-obj-01；fact-scope-obj-02；fact-scope-obj-03；fact-scope-obj-04；fact-scope-obj-05；fact-event-evt-801；fact-event-evt-802；fact-event-evt-806
### 9. 证据链摘要与观测缺口
- 本节目标：说明判断上限、当前仍未闭合的缺口，以及为什么这些缺口没有推翻主判断。
- 可引用 packets：constraint_packet
- 优先引用事实 ID（按顺序）：fact-gap-validate_candidate_events；fact-counter-cl-08；fact-event-evt-812；fact-event-evt-809
### 10. 结论与后续建议
- 本节目标：按立即处置、短期核查、持续复核三类写动作建议，并回扣前文证据边界。
- 可引用 packets：verdict_packet；action_packet；constraint_packet
- 优先引用事实 ID（按顺序）：fact-scope-obj-01；fact-scope-obj-02；fact-scope-obj-04；fact-scope-obj-05；fact-gap-validate_candidate_events；fact-action-01；fact-action-02；fact-action-03；fact-action-04
### 11. 技术附录提示
- 本节目标：只提示附录里有哪些技术明细可以进一步查阅，不重复附录内容。
- 可引用 packets：scope_packet；constraint_packet
- 优先引用事实 ID（按顺序）：fact-counter-cl-08；fact-gap-validate_candidate_events

## Writing Priorities
- 第1、2、4、5、7、8、9节默认写成连续短段落，不要把正文写成 fact card 清单。
- 已确认对象、待确认对象、背景指标必须分开表述，不能混写。
- 反证只说明为什么它不足以推翻主判断，不要把背景流量写成主结论。
