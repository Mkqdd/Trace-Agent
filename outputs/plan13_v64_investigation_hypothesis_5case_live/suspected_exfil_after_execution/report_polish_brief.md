# Report Writer Brief

## Writing Task
- 目标读者：运维人员与安全运营协同对象。
- 正文必须只基于下方 packets 与各章节允许引用的 fact cards 写作，不要使用这些材料之外的事实。
- 正文只负责解释判断、范围和动作；完整技术细节会在正文后自动追加，不要在正文重复 IOC 表、对象表和观测映射表。
- 如果某节材料不足，请保留标题并用保守表述说明当前证据不足，不得补写。
- Fact Catalog 会把全部可用事实只列一次；各章节仅围绕 Section Fact Map 中给出的 fact ID 取材。
- 如果某条 fact 带有“判断作用 / 书写边界”，正文应先解释它为什么改变判断，再交代边界，不要只复述事件发生。
- 调查锚点、已确认受影响对象、核心外部基础设施是三类不同角色，必须分开表述。
- 如果当前没有已确认受影响资产，可以写调查锚点和处置焦点，但不要把调查起点改写成已确认影响范围。

## Header Packet
- 事件标题：ws-rnd-04 Suspected cloud-storage exfil chain 调查报告
- 分析窗口：2026-06-03 16:28:00 UTC 至 2026-06-03 17:24:40 UTC
- 最终结论：确认安全事件
- 严重度：高
- 研判把握：高
- 已确认受影响范围：ws-rnd-04
- 一句话结论：ws-rnd-04 围绕 198.51.100.144、files-sync-share.net 已形成可以稳定交付的异常链。

## Verdict Packet
- 结论陈述：ws-rnd-04 围绕 198.51.100.144、files-sync-share.net 已形成可以稳定交付的异常链。

## Scope Packet
- 已确认受影响对象：ws-rnd-04
- 待确认对象：ws-rnd-09

## Constraint Packet
- 边界陈述：当前确认范围收敛在 ws-rnd-04；ws-rnd-09 保持待确认状态。
- 未闭合问题：仍需围绕当前关键关联指标开展一轮扩线核查，确认是否存在同指标的更大范围复现。；补充 seed 家族、指纹或外部基础设施的公开技术背景，明确它只能作为背景还是能支撑基础设施解释。；仍需显式检查维护窗口、补丁、备份或共享基线等反证。

## Action Packet
- 立即动作：优先隔离或重点监控已确认受影响资产：ws-rnd-04；在边界和代理设备上排查并封禁外部基础设施：198.51.100.144、files-sync-share.net、api.files-sync-share.net
- 下一步动作：继续核实待确认关联资产 ws-rnd-09；优先补查：仍需围绕当前关键关联指标开展一轮扩线核查，确认是否存在同指标的更大范围复现

## Fact Catalog
### 已确认事件事实
- `fact-event-evt-602` [落地外联]：2026-06-03 16:34:20 UTC 资产 `ws-rnd-04` 对外通信 `files-sync-share.net / 198.51.100.144`。；书写边界：仍需结合复现或主机侧线索共同定性
- `fact-event-evt-603` [落地外联]：2026-06-03 16:40:00 UTC 资产 `ws-rnd-04` 对外通信 `files-sync-share.net / 198.51.100.144`。；书写边界：仍需结合复现或主机侧线索共同定性
- `fact-event-evt-604` [主机升级]：2026-06-03 16:42:30 UTC 资产 `ws-rnd-04` 出现执行迹象 `相关主机执行活动`。；书写边界：可确认风险升级，但仍缺少更细载荷细节
- `fact-event-evt-609` [异常起点]：2026-06-03 16:52:30 UTC 资产 `ws-rnd-04` 解析域名 `api.files-sync-share.net`。；书写边界：单次解析不足以独立定性
### 待确认事件事实
- `fact-event-evt-611` [待确认扩展]：2026-06-03 17:05:00 UTC 资产 `ws-rnd-09` 与 `files-sync-share.net / 198.51.100.144` 出现待确认关联命中。；书写边界：未独立验证，不能并入已确认范围
### 背景事件事实
- `fact-event-evt-601` [背景反证]：2026-06-03 16:28:00 UTC 资产 `ws-rnd-04` 当前出现仅用于边界说明的背景事件 `files-sync-share.net`。；书写边界：只能帮助收窄边界，不能单独推翻主结论
### 调查锚点对象
- `fact-scope-obj-01` [调查锚点]：对象 `ws-rnd-04` 当前作为调查锚点保留在主调查链中。；书写边界：作为起点表述，不等于单点即可完成定性，也不要写成已确认受影响范围
### 待确认范围对象
- `fact-scope-obj-02` [待确认对象]：对象 `ws-rnd-09` 当前作为待确认关联资产保留为待确认范围。；书写边界：保持待确认，不写成已确认受影响
- `fact-scope-obj-15` [待确认对象]：对象 `t13d190900_44ac2200b3c1_ab11cd22ee44` 当前作为候选扩展对象保留为待确认范围。；书写边界：仍需独立验证，不能直接升格
- `fact-scope-obj-14` [待确认对象]：对象 `ws-rnd-12` 当前作为候选扩展对象保留为待确认范围。；书写边界：仍需独立验证，不能直接升格
### 已确认关联基础设施
- `fact-scope-obj-03` [已确认关联基础设施]：对象 `198.51.100.144` 当前作为已确认关联基础设施纳入主证据链。；书写边界：只应写入外联判断或边界封禁动作，不写成已确认受影响范围
- `fact-scope-obj-04` [已确认关联基础设施]：对象 `api.files-sync-share.net` 当前作为已确认关联基础设施纳入主证据链。；书写边界：只应写入外联判断或边界封禁动作，不写成已确认受影响范围
- `fact-scope-obj-05` [已确认关联基础设施]：对象 `files-sync-share.net` 当前作为已确认关联基础设施纳入主证据链。；书写边界：只应写入外联判断或边界封禁动作，不写成已确认受影响范围
### 缺口事实
- `fact-gap-expand_cluster_scope` [交付边界]：当前仍需对“仍需围绕当前关键关联指标开展一轮扩线核查，确认是否存在同指标的更大范围复现。”补充独立确认。；书写边界：限制范围继续扩大，但不否定当前主结论
- `fact-gap-ground_external_context` [交付边界]：当前仍需对“补充 seed 家族、指纹或外部基础设施的公开技术背景，明确它只能作为背景还是能支撑基础设施解释。”补充独立确认。；书写边界：限制范围继续扩大，但不否定当前主结论
- `fact-gap-check_counterevidence` [交付边界]：当前仍需对“仍需显式检查维护窗口、补丁、备份或共享基线等反证。”补充独立确认。；书写边界：限制范围继续扩大，但不否定当前主结论
### 动作依据事实
- `fact-action-01` [处置动作]：优先隔离或重点监控已确认受影响资产：ws-rnd-04；书写边界：动作需回扣前文证据或边界判断
- `fact-action-02` [处置动作]：在边界和代理设备上排查并封禁外部基础设施：198.51.100.144、files-sync-share.net、api.files-sync-share.net；书写边界：动作需回扣前文证据或边界判断
- `fact-action-03` [处置动作]：继续核实待确认关联资产 ws-rnd-09；书写边界：动作需回扣前文证据或边界判断
- `fact-action-04` [处置动作]：优先补查：仍需围绕当前关键关联指标开展一轮扩线核查，确认是否存在同指标的更大范围复现；书写边界：动作需回扣前文证据或边界判断

## Section Fact Map
### 首页摘要
- 本节目标：只收敛结论、严重度、把握度、已确认受影响范围和立即动作，不展开附录型对象清单；如果当前只有调查锚点而没有已确认受影响资产，不要把调查锚点改写成已确认影响范围。
- 可引用 packets：verdict_packet；scope_packet；action_packet
- 优先引用事实 ID（按顺序）：fact-event-evt-602；fact-event-evt-603；fact-event-evt-604；fact-scope-obj-01；fact-scope-obj-03
### 1. 事件背景与已知线索
- 本节目标：说明事件为什么进入调查、调查起点资产是什么、初始异常是什么，以及当前最关键的外部基础设施是什么。
- 可引用 packets：verdict_packet；scope_packet
- 优先引用事实 ID（按顺序）：fact-event-evt-609；fact-event-evt-602；fact-scope-obj-01；fact-scope-obj-03；fact-scope-obj-04
### 2. 范围界定与调查假设
- 本节目标：说明调查锚点、已确认受影响范围和待确认对象各落在哪里，以及为什么边界停在这里。
- 可引用 packets：scope_packet；constraint_packet
- 优先引用事实 ID（按顺序）：fact-scope-obj-01；fact-scope-obj-03；fact-scope-obj-04；fact-scope-obj-02；fact-gap-expand_cluster_scope
### 3. 对象覆盖策略与关键实体
- 本节目标：区分调查锚点、已确认受影响对象、待确认对象、核心外部基础设施和背景指标，只点关键对象。
- 可引用 packets：scope_packet
- 优先引用事实 ID（按顺序）：fact-scope-obj-01；fact-scope-obj-02；fact-scope-obj-03；fact-scope-obj-04
### 4. 事件机制分解
- 本节目标：按推进关系解释事件从异常通信到执行/横向的主链，不逐条重放所有时间点。
- 可引用 packets：verdict_packet；scope_packet
- 优先引用事实 ID（按顺序）：fact-event-evt-609；fact-event-evt-602；fact-event-evt-604
### 5. 关键证据与异常事实
- 本节目标：只抓最关键的支撑事实与反证边界，写清它们为什么改变判断。
- 可引用 packets：verdict_packet；constraint_packet
- 优先引用事实 ID（按顺序）：fact-event-evt-602；fact-event-evt-604
### 6. 时序特征与行为模式
- 本节目标：只保留少量关键时间节点，并说明这些节点对判断意味着什么。
- 可引用 packets：verdict_packet；constraint_packet
- 优先引用事实 ID（按顺序）：fact-event-evt-609；fact-event-evt-602；fact-event-evt-604；fact-event-evt-601
### 7. 传播与关联分析
- 本节目标：说明哪些关联已经进入主判断，哪些扩线结果仍只是候选或边界说明，不要把调查锚点直接写成范围扩大。
- 可引用 packets：scope_packet；constraint_packet
- 优先引用事实 ID（按顺序）：fact-event-evt-611；fact-scope-obj-02
### 8. 影响分析
- 本节目标：说明已确认受影响范围、已确认异常行为和仍待确认部分之间的区别；如果没有已确认受影响资产，必须写成“当前尚无已确认受影响资产；已观察到的异常行为主要落在调查锚点”，不要使用“影响范围仅限于调查锚点”这类表述。
- 可引用 packets：verdict_packet；scope_packet；action_packet
- 优先引用事实 ID（按顺序）：fact-scope-obj-01；fact-scope-obj-02；fact-scope-obj-03；fact-scope-obj-04；fact-event-evt-604
### 9. 证据链摘要与观测缺口
- 本节目标：说明判断上限、当前仍未闭合的缺口，以及为什么这些缺口没有推翻主判断。
- 可引用 packets：constraint_packet
- 优先引用事实 ID（按顺序）：fact-gap-expand_cluster_scope；fact-gap-ground_external_context；fact-gap-check_counterevidence；fact-event-evt-611
### 10. 结论与后续建议
- 本节目标：按立即处置、短期核查、持续复核三类写动作建议，并回扣前文证据边界。
- 可引用 packets：verdict_packet；action_packet；constraint_packet
- 优先引用事实 ID（按顺序）：fact-scope-obj-01；fact-scope-obj-03；fact-scope-obj-04；fact-gap-expand_cluster_scope；fact-gap-ground_external_context；fact-action-01；fact-action-02；fact-action-03；fact-action-04
### 11. 技术附录提示
- 本节目标：只提示附录里有哪些技术明细可以进一步查阅，不重复附录内容。
- 可引用 packets：scope_packet；constraint_packet
- 优先引用事实 ID（按顺序）：fact-gap-expand_cluster_scope

## Writing Priorities
- 第1、2、4、5、7、8、9节默认写成连续短段落，不要把正文写成 fact card 清单。
- 调查锚点、已确认受影响对象、待确认对象、背景指标必须分开表述，不能混写。
- 调查起点资产只写成调查锚点或调查焦点，不写成已确认受影响资产。
- 核心外部基础设施只写成已确认关联基础设施或关键外联对象，不写成已确认受影响范围。
- 第8节如果没有已确认受影响对象，使用“当前尚无已确认受影响资产；已观察到的异常行为主要落在调查锚点”这类句式，不要使用任何“影响范围仅限于调查锚点”的变体。
- 反证只说明为什么它不足以推翻主判断，不要把背景流量写成主结论。
