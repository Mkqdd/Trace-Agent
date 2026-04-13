# 网络安全事件分析报告

## 事件概述
- 事件时间：2026-03-29 15:05:00
- 通信关系：`10.10.14.33` -> `203.0.113.19`
- 协议：TLS
- 命中指标：SSL_SHA1 `01fca6410fefef1530ac71c5e34d6985a6e23643`
- 当前研判：QuasarRAT
- 置信度：95
- 严重度：高危

## 研判结论
在 2026-03-29 15:05:00，检测到 10.10.14.33 与 203.0.113.19 之间存在 TLS 流量，该流量命中 SSL_SHA1 指标 `01fca6410fefef1530ac71c5e34d6985a6e23643`。

结合本地指纹情报与外部公开情报，当前将该事件关联到 `QuasarRAT` 的把握为较高。

## 归因依据
当前归因结果为 `QuasarRAT`，置信度为 95。 主依据来自 `SSLBL`。 另有 `SSLBL、家族背景情报` 提供补充支持。 当前主结论以本地指纹情报 `QuasarRAT` 为主，并获得外部结构化情报的补充支持。

当前结论并非仅来自单一标签，而是由结构化命中和外部公开情报共同支撑。 其中 `本地指纹情报命中` 等 4 条高优证据从本地指纹、公开研究和基础设施线索多个角度支持该事件与 `QuasarRAT` 的关联。

## 事件直接证据
### 本地指纹情报命中
来源：SSLBL
证据等级：高
本地情报库将 ssl_sha1 01fca6410fefef1530ac71c5e34d6985a6e23643 关联到家族/标签 QuasarRAT，来源 SSLBL。
参考：[https://sslbl.abuse.ch/ssl-certificates/sha1/01fca6410fefef1530ac71c5e34d6985a6e23643/](https://sslbl.abuse.ch/ssl-certificates/sha1/01fca6410fefef1530ac71c5e34d6985a6e23643/)

### MalwareBazaar Database - Abuse.ch
来源：bazaar.abuse.ch
证据等级：中
QuasarRAT的恶意软件样本（SHA256 760900c54d8de9c15d683400c4c1969c386f22b2dbbecd4163b93dd0112af4a6）在MalwareBazaar数据库中被记录。这一信息支持了QuasarRAT家族的身份和活动模式。
参考：[https://bazaar.abuse.ch/sample/760900c54d8de9c15d683400c4c1969c386f22b2dbbecd4163b93dd0112af4a6/](https://bazaar.abuse.ch/sample/760900c54d8de9c15d683400c4c1969c386f22b2dbbecd4163b93dd0112af4a6/)

### Backdoor:Win32/QuasarRAT.A threat description
来源：microsoft.com
证据等级：中
Microsoft提供了关于QuasarRAT.A的威胁描述，包括其传播方式和对计算机的影响。这有助于理解QuasarRAT.A的特征和行为，并为防范这种恶意软件提供指导。
参考：[https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Backdoor:Win32/QuasarRAT.A&ThreatID=2147731545](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Backdoor:Win32/QuasarRAT.A&ThreatID=2147731545)

### Quasar RAT (Malware Family)
来源：malpedia.caad.fkie.fraunhofer.de
证据等级：中
Quasar RAT 是一个由各种攻击者使用的 .NET 编写的恶意软件家族。该恶意软件功能齐全且开源，通常被包装……
参考：[https://malpedia.caad.fkie.fraunhofer.de/details/win.quasar_rat](https://malpedia.caad.fkie.fraunhofer.de/details/win.quasar_rat)

## 处置建议
### 基础响应
- [HIGH] 排查并视情况隔离源主机 10.10.14.33。 理由：源主机产生了命中后恶意流量，需要确认是否存在持续外联或二次投递行为。
- [HIGH] 在边界侧监控或阻断与 203.0.113.19 相关的后续通信。 理由：当前告警中的网络目的地址是最直接的外联对象，应优先纳入监测范围。
- [MEDIUM] 基于 SSL_SHA1 指纹 01fca6410fefef1530ac71c5e34d6985a6e23643 在历史流量中做横向检索。 理由：可以快速判断是否存在相同指纹的历史通信或更多受影响资产。
- [MEDIUM] 结合 QuasarRAT 相关 TTP 做主机侧排查与 IOC 扩线。 理由：已有家族线索时，可以更有针对性地检查样本行为、持久化方式和额外外联特征。

### 建议追加的威胁猎捕动作
- 基于当前外联目标、同证书指纹或同类 TLS 特征继续扩线，排查是否存在持续 C2 通信或其他受影响资产。
- 在历史流量中进一步检索相同 SSL_SHA1 指标 `01fca6410fefef1530ac71c5e34d6985a6e23643`，确认是否存在横向复用、批量投递或多资产命中。
