# Report Writer Brief

## Writing Task
- 目标读者：运维人员与安全运营协同对象。
- 正文必须只基于下方 packets 与各章节允许引用的 fact cards 写作，不要使用这些材料之外的事实。
- 正文只负责解释判断、范围和动作；完整技术细节会在正文后自动追加，不要在正文重复 IOC 表、对象表和观测映射表。
- 如果某节材料不足，请保留标题并用保守表述说明当前证据不足，不得补写。
- Fact Catalog 会把全部可用事实只列一次；各章节仅围绕 Section Fact Map 中给出的 fact ID 取材。
- 如果某条 fact 带有“判断作用 / 书写边界”，正文应先解释它为什么改变判断，再交代边界，不要只复述事件发生。

## Header Packet
- 事件标题：web-app-02 Possible web-shell beacon 调查报告
- 分析窗口：2026-06-24 14:54:00 UTC 至 2026-06-24 15:10:00 UTC
- 最终结论：可疑事件，建议继续复核
- 严重度：中
- 研判把握：高
- 已确认范围：当前尚无已确认受影响资产
- 一句话结论：web-app-02 围绕 198.51.100.177、auth-edge-panel.net 已形成需要继续收敛的异常事件链。

## Verdict Packet
- 结论陈述：web-app-02 围绕 198.51.100.177、auth-edge-panel.net 已形成需要继续收敛的异常事件链。

## Scope Packet

## Constraint Packet
- 边界陈述：该缺口已多轮核查但仍未获得新的有效信息，更适合作为报告未决事项。
- 未闭合问题：是否存在主机侧执行、持久化或横向移动证据？；仍需围绕当前关键关联指标开展一轮扩线核查，确认是否存在同指标的更大范围复现。；seed 自带的家族提示 Possible web-shell beacon 是否有更多外部证据支撑？

## Action Packet
- 立即动作：优先隔离或重点监控资产：web-app-02；在边界和代理设备上排查并封禁外部基础设施：198.51.100.177、auth-edge-panel.net
- 下一步动作：优先补查：是否存在主机侧执行、持久化或横向移动证据

## Fact Catalog
### 已确认事件事实
- `fact-event-evt-801` [关键事件]：2026-06-24 14:54:00 UTC 资产 `web-app-02` 出现关联事件 `Public-facing web server received suspicious exploit requests against the admin portal before outbound TLS traffic began.`。；书写边界：不要脱离上下文单独放大这条事实
- `fact-event-evt-802` [异常起点]：2026-06-24 14:58:30 UTC 资产 `web-app-02` 解析域名 `auth-edge-panel.net`。；书写边界：单次解析不足以独立定性
- `fact-event-evt-803` [落地外联]：2026-06-24 15:02:00 UTC 资产 `web-app-02` 对外通信 `auth-edge-panel.net / 198.51.100.177`。；书写边界：仍需结合复现或主机侧线索共同定性
### 背景事件事实
- `fact-event-evt-805` [背景反证]：2026-06-24 15:10:00 UTC 资产 `web-app-02` 当前出现仅用于边界说明的背景事件 `cdn-auth-edge.net`。；书写边界：只能帮助收窄边界，不能单独推翻主结论
### 已确认范围对象
- `fact-scope-obj-01` [调查锚点]：对象 `web-app-02` 当前作为种子资产纳入已确认范围。；书写边界：作为起点表述，不等于单点即可完成定性
- `fact-scope-obj-02` [核心外部基础设施]：对象 `198.51.100.177` 当前作为核心外部基础设施纳入已确认范围。；书写边界：只应写入外联判断或边界封禁动作
- `fact-scope-obj-03` [核心外部基础设施]：对象 `auth-edge-panel.net` 当前作为核心外部基础设施纳入已确认范围。；书写边界：只应写入外联判断或边界封禁动作
### 缺口事实
- `fact-gap-execution_gap` [交付边界]：当前仍需对“是否存在主机侧执行、持久化或横向移动证据？”补充独立确认。；书写边界：限制范围继续扩大，但不否定当前主结论
- `fact-gap-expand_cluster_scope` [交付边界]：当前仍需对“仍需围绕当前关键关联指标开展一轮扩线核查，确认是否存在同指标的更大范围复现。”补充独立确认。；书写边界：限制范围继续扩大，但不否定当前主结论
- `fact-gap-validate_family_hint` [交付边界]：当前仍需对“seed 自带的家族提示 Possible web-shell beacon 是否有更多外部证据支撑？”补充独立确认。；书写边界：限制范围继续扩大，但不否定当前主结论
### 动作依据事实
- `fact-action-01` [处置动作]：优先隔离或重点监控资产：web-app-02；书写边界：动作需回扣前文证据或边界判断
- `fact-action-02` [处置动作]：在边界和代理设备上排查并封禁外部基础设施：198.51.100.177、auth-edge-panel.net；书写边界：动作需回扣前文证据或边界判断
- `fact-action-03` [处置动作]：优先补查：是否存在主机侧执行、持久化或横向移动证据；书写边界：动作需回扣前文证据或边界判断

## Section Fact Map
### 首页摘要
- 本节目标：只收敛结论、严重度、把握度、已确认范围和立即动作，不展开附录型对象清单。
- 可引用 packets：verdict_packet；scope_packet；action_packet
- 优先引用事实 ID（按顺序）：fact-event-evt-801；fact-event-evt-802；fact-event-evt-803；fact-scope-obj-01；fact-scope-obj-02
### 1. 事件背景与已知线索
- 本节目标：说明事件为什么进入调查、初始异常是什么、当前最关键的外部基础设施是什么。
- 可引用 packets：verdict_packet；scope_packet
- 优先引用事实 ID（按顺序）：fact-event-evt-802；fact-event-evt-803；fact-scope-obj-01；fact-scope-obj-02；fact-scope-obj-03
### 2. 范围界定与调查假设
- 本节目标：说明本轮判断覆盖到哪里、哪些对象仍待确认、为什么边界停在这里。
- 可引用 packets：scope_packet；constraint_packet
- 优先引用事实 ID（按顺序）：fact-scope-obj-01；fact-scope-obj-02；fact-scope-obj-03；fact-gap-execution_gap
### 3. 对象覆盖策略与关键实体
- 本节目标：区分已确认资产、待确认对象、核心外部基础设施和背景指标，只点关键对象。
- 可引用 packets：scope_packet
- 优先引用事实 ID（按顺序）：fact-scope-obj-01；fact-scope-obj-02；fact-scope-obj-03
### 4. 事件机制分解
- 本节目标：按推进关系解释事件从异常通信到执行/横向的主链，不逐条重放所有时间点。
- 可引用 packets：verdict_packet；scope_packet
- 优先引用事实 ID（按顺序）：fact-event-evt-802；fact-event-evt-803
### 5. 关键证据与异常事实
- 本节目标：只抓最关键的支撑事实与反证边界，写清它们为什么改变判断。
- 可引用 packets：verdict_packet；constraint_packet
- 优先引用事实 ID（按顺序）：fact-event-evt-803
### 6. 时序特征与行为模式
- 本节目标：只保留少量关键时间节点，并说明这些节点对判断意味着什么。
- 可引用 packets：verdict_packet；constraint_packet
- 优先引用事实 ID（按顺序）：fact-event-evt-802；fact-event-evt-803；fact-event-evt-805
### 7. 传播与关联分析
- 本节目标：说明哪些关联已经进入主判断，哪些扩线结果仍只是候选或边界说明。
- 可引用 packets：scope_packet；constraint_packet
- 优先引用事实 ID（按顺序）：fact-scope-obj-03
### 8. 影响分析
- 本节目标：说明已经确认的影响范围、仍待确认的部分，以及这对运维处置意味着什么。
- 可引用 packets：verdict_packet；scope_packet；action_packet
- 优先引用事实 ID（按顺序）：fact-scope-obj-01；fact-scope-obj-02；fact-scope-obj-03
### 9. 证据链摘要与观测缺口
- 本节目标：说明判断上限、当前仍未闭合的缺口，以及为什么这些缺口没有推翻主判断。
- 可引用 packets：constraint_packet
- 优先引用事实 ID（按顺序）：fact-gap-execution_gap；fact-gap-expand_cluster_scope；fact-gap-validate_family_hint
### 10. 结论与后续建议
- 本节目标：按立即处置、短期核查、持续复核三类写动作建议，并回扣前文证据边界。
- 可引用 packets：verdict_packet；action_packet；constraint_packet
- 优先引用事实 ID（按顺序）：fact-scope-obj-01；fact-scope-obj-02；fact-scope-obj-03；fact-gap-execution_gap；fact-gap-expand_cluster_scope；fact-action-01；fact-action-02；fact-action-03
### 11. 技术附录提示
- 本节目标：只提示附录里有哪些技术明细可以进一步查阅，不重复附录内容。
- 可引用 packets：scope_packet；constraint_packet
- 优先引用事实 ID（按顺序）：fact-gap-execution_gap

## Writing Priorities
- 第1、2、4、5、7、8、9节默认写成连续短段落，不要把正文写成 fact card 清单。
- 已确认对象、待确认对象、背景指标必须分开表述，不能混写。
- 反证只说明为什么它不足以推翻主判断，不要把背景流量写成主结论。
