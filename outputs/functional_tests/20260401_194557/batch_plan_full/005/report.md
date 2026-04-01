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

## 关键证据与情报
### 本地指纹情报命中
来源：SSLBL
说明：本地情报库将 ssl_sha1 01fca6410fefef1530ac71c5e34d6985a6e23643 关联到家族/标签 QuasarRAT，来源 SSLBL。
证据等级：高

### Trojan:MSIL/QuasarRat.NE!MTB threat description
来源：microsoft.com
说明：Microsoft 威胁百科页面给出了与 `QuasarRAT` 相关的检测说明和威胁描述。
证据等级：中
参考：[https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Trojan:MSIL/QuasarRat.NE!MTB&ThreatID=2147828113](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Trojan:MSIL/QuasarRat.NE!MTB&ThreatID=2147828113)

### MalwareBazaar Database - Abuse.ch
来源：bazaar.abuse.ch
说明：MalwareBazaar 页面展示了与 `QuasarRAT` 相关的恶意软件家族归类信息。
证据等级：中
参考：[https://bazaar.abuse.ch/sample/d93f7cb5d7e03bdc168bcf05ca7e1fdeb46f6c9d56c1b7508912db0e4ac0f45f/](https://bazaar.abuse.ch/sample/d93f7cb5d7e03bdc168bcf05ca7e1fdeb46f6c9d56c1b7508912db0e4ac0f45f/)

### Quasar RAT (Malware Family)
来源：malpedia.caad.fkie.fraunhofer.de
说明：Malpedia 将 `QuasarRAT` 描述为已知恶意软件家族，并提供了相应家族背景信息。
证据等级：中
参考：[https://malpedia.caad.fkie.fraunhofer.de/details/win.quasar_rat](https://malpedia.caad.fkie.fraunhofer.de/details/win.quasar_rat)

### Backdoor:Win32/QuasarRAT.A threat description
来源：microsoft.com
说明：Microsoft 威胁百科页面给出了与 `QuasarRAT` 相关的检测说明和威胁描述。
证据等级：中
参考：[https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Backdoor:Win32/QuasarRAT.A&ThreatID=2147731545](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Backdoor:Win32/QuasarRAT.A&ThreatID=2147731545)

## 本地指纹情报
本地情报库命中 `ssl_sha1` 指标 `01fca6410fefef1530ac71c5e34d6985a6e23643`，关联家族为 `QuasarRAT`，来源 `SSLBL`。
该记录最近更新时间为 2026-03-26T07:46:12。

## 相关情报参考
- [Trojan:MSIL/QuasarRat.NE!MTB threat description](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Trojan:MSIL/QuasarRat.NE!MTB&ThreatID=2147828113)：Microsoft 威胁百科页面给出了与 `QuasarRAT` 相关的检测说明和威胁描述。
- [MalwareBazaar Database - Abuse.ch](https://bazaar.abuse.ch/sample/d93f7cb5d7e03bdc168bcf05ca7e1fdeb46f6c9d56c1b7508912db0e4ac0f45f/)：MalwareBazaar 页面展示了与 `QuasarRAT` 相关的恶意软件家族归类信息。
- [Quasar RAT (Malware Family)](https://malpedia.caad.fkie.fraunhofer.de/details/win.quasar_rat)：Malpedia 将 `QuasarRAT` 描述为已知恶意软件家族，并提供了相应家族背景信息。

## 处置建议
- [HIGH] 排查并视情况隔离源主机 10.10.14.33。 理由：源主机产生了命中后恶意流量，需要确认是否存在持续外联或二次投递行为。
- [HIGH] 在边界侧监控或阻断与 203.0.113.19 相关的后续通信。 理由：当前告警中的网络目的地址是最直接的外联对象，应优先纳入监测范围。
- [MEDIUM] 基于 SSL_SHA1 指纹 01fca6410fefef1530ac71c5e34d6985a6e23643 在历史流量中做横向检索。 理由：可以快速判断是否存在相同指纹的历史通信或更多受影响资产。
- [MEDIUM] 结合 QuasarRAT 相关 TTP 做主机侧排查与 IOC 扩线。 理由：已有家族线索时，可以更有针对性地检查样本行为、持久化方式和额外外联特征。

## 参考链接
- 本地指纹情报命中
  摘要：本地情报库将 ssl_sha1 01fca6410fefef1530ac71c5e34d6985a6e23643 关联到家族/标签 QuasarRAT，来源 SSLBL。
- [Trojan:MSIL/QuasarRat.NE!MTB threat description](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Trojan:MSIL/QuasarRat.NE!MTB&ThreatID=2147828113)
  摘要：Microsoft 威胁百科页面给出了与 `QuasarRAT` 相关的检测说明和威胁描述。
- [MalwareBazaar Database - Abuse.ch](https://bazaar.abuse.ch/sample/d93f7cb5d7e03bdc168bcf05ca7e1fdeb46f6c9d56c1b7508912db0e4ac0f45f/)
  摘要：MalwareBazaar 页面展示了与 `QuasarRAT` 相关的恶意软件家族归类信息。
- [Quasar RAT (Malware Family)](https://malpedia.caad.fkie.fraunhofer.de/details/win.quasar_rat)
  摘要：Malpedia 将 `QuasarRAT` 描述为已知恶意软件家族，并提供了相应家族背景信息。
- [Backdoor:Win32/QuasarRAT.A threat description](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Backdoor:Win32/QuasarRAT.A&ThreatID=2147731545)
  摘要：Microsoft 威胁百科页面给出了与 `QuasarRAT` 相关的检测说明和威胁描述。
- [Found a "Quasar" folder in my software folder, and I don't ...](https://www.reddit.com/r/techsupport/comments/1khzp0m/found_a_quasar_folder_in_my_software_folder_and_i/)
  摘要：社区讨论中提到了与 `QuasarRAT` 相关的感染或处置经历，仅适合作为低权重参考。
