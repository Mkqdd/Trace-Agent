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
- 事件标题：ws-legal-03 Suspicious shared-infra beacon requiring review 调查报告
- 分析窗口：2026-06-20 10:04:30 UTC 至 2026-06-20 11:18:00 UTC
- 最终结论：可疑事件，建议继续复核
- 严重度：中
- 研判把握：高
- 已确认受影响范围：当前尚无已确认受影响资产
- 一句话结论：ws-legal-03 围绕 198.51.100.131、auth-queue-sync.net 已出现连续异常迹象，但 ws-legal-09 仍需独立确认。

## Verdict Packet
- 结论陈述：ws-legal-03 围绕 198.51.100.131、auth-queue-sync.net 已出现连续异常迹象，但 ws-legal-09 仍需独立确认。

## Scope Packet
- 已确认受影响对象：当前尚无已确认受影响资产
- 待确认对象：ws-legal-09

## Constraint Packet
- 边界陈述：是否存在主机侧执行、持久化或横向移动证据？
- 未闭合问题：是否存在主机侧执行、持久化或横向移动证据？；仍需围绕当前关键关联指标开展一轮扩线核查，确认是否存在同指标的更大范围复现。；关联资产 ws-legal-09 是否真正受影响？；补充 seed 家族、指纹或外部基础设施的公开技术背景，明确它只能作为背景还是能支撑基础设施解释。；仍需显式检查维护窗口、补丁、备份或共享基线等反证。；仍需把当前事件事实沉淀为 claim 或可引用实体，避免报告只剩原始事件聚合。；seed 自带的家族提示 Suspicious shared-infra beacon requiring review 是否有更多外部证据支撑？
- 反证与替代解释：检索到 1 条更接近维护、更新或正常基线的事件。

## Action Packet
- 立即动作：优先隔离或重点监控资产：ws-legal-03；在边界和代理设备上排查并封禁外部基础设施：198.51.100.131、auth-queue-sync.net
- 下一步动作：继续核实待确认关联资产 ws-legal-09；优先补查：是否存在主机侧执行、持久化或横向移动证据

## Fact Catalog
### 已确认事件事实
- `fact-event-evt-702` [落地外联]：2026-06-20 10:12:00 UTC 资产 `ws-legal-03` 对外通信 `auth-queue-sync.net / 198.51.100.131`。；书写边界：仍需结合复现或主机侧线索共同定性
- `fact-event-evt-703` [落地外联]：2026-06-20 10:16:20 UTC 资产 `ws-legal-03` 对外通信 `auth-queue-sync.net / 198.51.100.131`。；书写边界：仍需结合复现或主机侧线索共同定性
- `fact-event-evt-704` [落地外联]：2026-06-20 10:21:40 UTC 资产 `ws-legal-03` 对外通信 `auth-queue-sync.net / 198.51.100.131`。；书写边界：仍需结合复现或主机侧线索共同定性
### 待确认事件事实
- `fact-event-evt-706` [待确认扩展]：2026-06-20 10:39:00 UTC 资产 `ws-legal-09` 与 `cdn-auth-queue.net / 198.51.100.131` 出现待确认关联命中。；书写边界：未独立验证，不能并入已确认范围
- `fact-event-evt-707` [待确认扩展]：2026-06-20 10:42:00 UTC 资产 `ws-legal-09` 与 `cdn-auth-queue.net` 出现待确认关联命中。；书写边界：未独立验证，不能并入已确认范围
- `fact-event-evt-715` [待确认扩展]：2026-06-20 11:18:00 UTC 资产 `ws-legal-09` 与 `主机侧上下文线索` 出现待确认关联命中。；书写边界：未独立验证，不能并入已确认范围
### 背景事件事实
- `fact-event-evt-701` [背景反证]：2026-06-20 10:04:30 UTC 资产 `ws-legal-03` 当前出现仅用于边界说明的背景事件 `auth-queue-sync.net`。；书写边界：只能帮助收窄边界，不能单独推翻主结论
### 调查锚点对象
- `fact-scope-obj-01` [调查锚点]：对象 `ws-legal-03` 当前作为调查锚点保留在主调查链中。；书写边界：作为起点表述，不等于单点即可完成定性，也不要写成已确认受影响范围
### 待确认范围对象
- `fact-scope-obj-02` [待确认对象]：对象 `ws-legal-09` 当前作为待确认关联资产保留为待确认范围。；书写边界：保持待确认，不写成已确认受影响
- `fact-scope-obj-10` [待确认对象]：对象 `cdn-auth-queue.net` 当前作为候选扩展对象保留为待确认范围。；书写边界：仍需独立验证，不能直接升格
- `fact-scope-obj-11` [待确认对象]：对象 `t13d190900_7711aa22bb33_9911ccddee77` 当前作为候选扩展对象保留为待确认范围。；书写边界：仍需独立验证，不能直接升格
### 已确认关联基础设施
- `fact-scope-obj-03` [已确认关联基础设施]：对象 `198.51.100.131` 当前作为已确认关联基础设施纳入主证据链。；书写边界：只应写入外联判断或边界封禁动作，不写成已确认受影响范围
- `fact-scope-obj-04` [已确认关联基础设施]：对象 `auth-queue-sync.net` 当前作为已确认关联基础设施纳入主证据链。；书写边界：只应写入外联判断或边界封禁动作，不写成已确认受影响范围
### 反证事实
- `fact-counter-cl-02` [替代解释]：检索到 1 条更接近维护、更新或正常基线的事件。；书写边界：要解释为何不足以推翻主判断，而不是只罗列背景事件
### 缺口事实
- `fact-gap-execution_gap` [交付边界]：当前仍需对“是否存在主机侧执行、持久化或横向移动证据？”补充独立确认。；书写边界：限制范围继续扩大，但不否定当前主结论
- `fact-gap-expand_cluster_scope` [交付边界]：当前仍需对“仍需围绕当前关键关联指标开展一轮扩线核查，确认是否存在同指标的更大范围复现。”补充独立确认。；书写边界：限制范围继续扩大，但不否定当前主结论
- `fact-gap-related_assets_review` [交付边界]：当前仍需对“关联资产 ws-legal-09 是否真正受影响？”补充独立确认。；书写边界：限制范围继续扩大，但不否定当前主结论
- `fact-gap-ground_external_context` [交付边界]：当前仍需对“补充 seed 家族、指纹或外部基础设施的公开技术背景，明确它只能作为背景还是能支撑基础设施解释。”补充独立确认。；书写边界：限制范围继续扩大，但不否定当前主结论
- `fact-gap-check_counterevidence` [交付边界]：当前仍需对“仍需显式检查维护窗口、补丁、备份或共享基线等反证。”补充独立确认。；书写边界：限制范围继续扩大，但不否定当前主结论
- `fact-gap-structure_evidence` [交付边界]：当前仍需对“仍需把当前事件事实沉淀为 claim 或可引用实体，避免报告只剩原始事件聚合。”补充独立确认。；书写边界：限制范围继续扩大，但不否定当前主结论
- `fact-gap-validate_family_hint` [交付边界]：当前仍需对“seed 自带的家族提示 Suspicious shared-infra beacon requiring review 是否有更多外部证据支撑？”补充独立确认。；书写边界：限制范围继续扩大，但不否定当前主结论
### 动作依据事实
- `fact-action-01` [处置动作]：优先隔离或重点监控资产：ws-legal-03；书写边界：动作需回扣前文证据或边界判断
- `fact-action-02` [处置动作]：在边界和代理设备上排查并封禁外部基础设施：198.51.100.131、auth-queue-sync.net；书写边界：动作需回扣前文证据或边界判断
- `fact-action-03` [处置动作]：继续核实待确认关联资产 ws-legal-09；书写边界：动作需回扣前文证据或边界判断
- `fact-action-04` [处置动作]：优先补查：是否存在主机侧执行、持久化或横向移动证据；书写边界：动作需回扣前文证据或边界判断

## Section Fact Map
### 首页摘要
- 本节目标：只收敛结论、严重度、把握度、已确认受影响范围和立即动作，不展开附录型对象清单；如果当前只有调查锚点而没有已确认受影响资产，不要把调查锚点改写成已确认影响范围。
- 可引用 packets：verdict_packet；scope_packet；action_packet
- 优先引用事实 ID（按顺序）：fact-event-evt-702；fact-event-evt-703；fact-event-evt-704；fact-scope-obj-01；fact-scope-obj-03
### 1. 事件背景与已知线索
- 本节目标：说明事件为什么进入调查、调查起点资产是什么、初始异常是什么，以及当前最关键的外部基础设施是什么。
- 可引用 packets：verdict_packet；scope_packet
- 优先引用事实 ID（按顺序）：fact-event-evt-702；fact-scope-obj-01；fact-scope-obj-03；fact-scope-obj-04
### 2. 范围界定与调查假设
- 本节目标：说明调查锚点、已确认受影响范围和待确认对象各落在哪里，以及为什么边界停在这里。
- 可引用 packets：scope_packet；constraint_packet
- 优先引用事实 ID（按顺序）：fact-scope-obj-01；fact-scope-obj-03；fact-scope-obj-04；fact-scope-obj-02；fact-gap-execution_gap；fact-counter-cl-02
### 3. 对象覆盖策略与关键实体
- 本节目标：区分调查锚点、已确认受影响对象、待确认对象、核心外部基础设施和背景指标，只点关键对象。
- 可引用 packets：scope_packet
- 优先引用事实 ID（按顺序）：fact-scope-obj-01；fact-scope-obj-02；fact-scope-obj-03；fact-scope-obj-04
### 4. 事件机制分解
- 本节目标：按推进关系解释事件从异常通信到执行/横向的主链，不逐条重放所有时间点。
- 可引用 packets：verdict_packet；scope_packet
- 优先引用事实 ID（按顺序）：fact-event-evt-702
### 5. 关键证据与异常事实
- 本节目标：只抓最关键的支撑事实与反证边界，写清它们为什么改变判断。
- 可引用 packets：verdict_packet；constraint_packet
- 优先引用事实 ID（按顺序）：fact-event-evt-702；fact-counter-cl-02
### 6. 时序特征与行为模式
- 本节目标：只保留少量关键时间节点，并说明这些节点对判断意味着什么。
- 可引用 packets：verdict_packet；constraint_packet
- 优先引用事实 ID（按顺序）：fact-event-evt-702；fact-event-evt-701
### 7. 传播与关联分析
- 本节目标：说明哪些关联已经进入主判断，哪些扩线结果仍只是候选或边界说明，不要把调查锚点直接写成范围扩大。
- 可引用 packets：scope_packet；constraint_packet
- 优先引用事实 ID（按顺序）：fact-event-evt-706；fact-event-evt-707；fact-event-evt-715；fact-scope-obj-02
### 8. 影响分析
- 本节目标：说明已确认受影响范围、已确认异常行为和仍待确认部分之间的区别；如果没有已确认受影响资产，必须写成“当前尚无已确认受影响资产；已观察到的异常行为主要落在调查锚点”，不要使用“影响范围仅限于调查锚点”这类表述。
- 可引用 packets：verdict_packet；scope_packet；action_packet
- 优先引用事实 ID（按顺序）：fact-scope-obj-01；fact-scope-obj-02；fact-scope-obj-03；fact-scope-obj-04；fact-event-evt-702
### 9. 证据链摘要与观测缺口
- 本节目标：说明判断上限、当前仍未闭合的缺口，以及为什么这些缺口没有推翻主判断。
- 可引用 packets：constraint_packet
- 优先引用事实 ID（按顺序）：fact-gap-execution_gap；fact-gap-expand_cluster_scope；fact-gap-related_assets_review；fact-gap-ground_external_context；fact-gap-check_counterevidence；fact-gap-structure_evidence；fact-gap-validate_family_hint；fact-counter-cl-02；fact-event-evt-706；fact-event-evt-707
### 10. 结论与后续建议
- 本节目标：按立即处置、短期核查、持续复核三类写动作建议，并回扣前文证据边界。
- 可引用 packets：verdict_packet；action_packet；constraint_packet
- 优先引用事实 ID（按顺序）：fact-scope-obj-01；fact-scope-obj-03；fact-scope-obj-04；fact-gap-execution_gap；fact-gap-expand_cluster_scope；fact-action-01；fact-action-02；fact-action-03；fact-action-04
### 11. 技术附录提示
- 本节目标：只提示附录里有哪些技术明细可以进一步查阅，不重复附录内容。
- 可引用 packets：scope_packet；constraint_packet
- 优先引用事实 ID（按顺序）：fact-counter-cl-02；fact-gap-execution_gap

## Writing Priorities
- 第1、2、4、5、7、8、9节默认写成连续短段落，不要把正文写成 fact card 清单。
- 调查锚点、已确认受影响对象、待确认对象、背景指标必须分开表述，不能混写。
- 调查起点资产只写成调查锚点或调查焦点，不写成已确认受影响资产。
- 核心外部基础设施只写成已确认关联基础设施或关键外联对象，不写成已确认受影响范围。
- 第8节如果没有已确认受影响对象，使用“当前尚无已确认受影响资产；已观察到的异常行为主要落在调查锚点”这类句式，不要使用任何“影响范围仅限于调查锚点”的变体。
- 反证只说明为什么它不足以推翻主判断，不要把背景流量写成主结论。
