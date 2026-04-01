# 网络安全事件分析报告

## 事件概述
- 事件时间：2026-03-29 10:40:00
- 通信关系：`10.20.8.41` -> `203.0.113.77`
- 协议：TLS
- 命中指标：JA4 `t13d201100_2b729b4bf6f3_9e7b989ebec8`
- 当前研判：IcedID
- 置信度：95
- 严重度：高危

## 研判结论
在 2026-03-29 10:40:00，检测到 10.20.8.41 与 203.0.113.77 之间存在 TLS 流量，该流量命中 JA4 指标 `t13d201100_2b729b4bf6f3_9e7b989ebec8`。

结合本地指纹情报与外部公开情报，当前将该事件关联到 `IcedID` 的把握为较高。

## 关键证据与情报
### 本地指纹情报命中
来源：JA4DB
说明：本地情报库将 ja4 t13d201100_2b729b4bf6f3_9e7b989ebec8 关联到家族/标签 IcedID，来源 JA4DB。
证据等级：高

### IcedID (Malware Family)
来源：malpedia.caad.fkie.fraunhofer.de
说明：Malpedia 将 `IcedID` 描述为已知恶意软件家族，并提供了相应家族背景信息。
证据等级：中
参考：[https://malpedia.caad.fkie.fraunhofer.de/details/win.icedid](https://malpedia.caad.fkie.fraunhofer.de/details/win.icedid)

### Fork in the Ice: IcedID Malware Analysis
来源：proofpoint.com
说明：Proofpoint 的研究内容提供了与 `IcedID` 相关的威胁活动线索。
证据等级：中
参考：[https://www.proofpoint.com/us/blog/threat-insight/fork-ice-new-era-icedid](https://www.proofpoint.com/us/blog/threat-insight/fork-ice-new-era-icedid)

### IcedID, Software S0483
来源：attack.mitre.org
说明：该来源页面《IcedID, Software S0483》提到了与 `IcedID` 或指标 `t13d201100_2b729b4bf6f3_9e7b989ebec8` 相关的信息：IcedID is a modular banking malware designed to steal financial information that has been observe...
证据等级：中
参考：[https://attack.mitre.org/software/S0483/](https://attack.mitre.org/software/S0483/)

### Melting UNC2198 ICEDID to Ransomware Operations
来源：cloud.google.com
说明：该来源页面《Melting UNC2198 ICEDID to Ransomware Operations》提到了与 `IcedID` 或指标 `t13d201100_2b729b4bf6f3_9e7b989ebec8` 相关的信息：Although analysis is always ongoing, at the time of publishing this blog post, Mandiant tracks mu...
证据等级：中
参考：[https://cloud.google.com/blog/topics/threat-intelligence/melting-unc2198-icedid-to-ransomware-operations](https://cloud.google.com/blog/topics/threat-intelligence/melting-unc2198-icedid-to-ransomware-operations)

## 本地指纹情报
本地情报库命中 `ja4` 指标 `t13d201100_2b729b4bf6f3_9e7b989ebec8`，关联家族为 `IcedID`，来源 `JA4DB`。
该记录最近更新时间为 2026-03-28T23:16:27。

## 相关情报参考
- [IcedID (Malware Family)](https://malpedia.caad.fkie.fraunhofer.de/details/win.icedid)：Malpedia 将 `IcedID` 描述为已知恶意软件家族，并提供了相应家族背景信息。
- [Fork in the Ice: IcedID Malware Analysis](https://www.proofpoint.com/us/blog/threat-insight/fork-ice-new-era-icedid)：Proofpoint 的研究内容提供了与 `IcedID` 相关的威胁活动线索。
- [IcedID, Software S0483](https://attack.mitre.org/software/S0483/)：该来源页面《IcedID, Software S0483》提到了与 `IcedID` 或指标 `t13d201100_2b729b4bf6f3_9e7b989ebec8` 相关的信息：IcedID is a modular banking malware designed to steal financial information that has been observe...

## 处置建议
- [HIGH] 排查并视情况隔离源主机 10.20.8.41。 理由：源主机产生了命中后恶意流量，需要确认是否存在持续外联或二次投递行为。
- [HIGH] 在边界侧监控或阻断与 203.0.113.77 相关的后续通信。 理由：当前告警中的网络目的地址是最直接的外联对象，应优先纳入监测范围。
- [MEDIUM] 基于 JA4 指纹 t13d201100_2b729b4bf6f3_9e7b989ebec8 在历史流量中做横向检索。 理由：可以快速判断是否存在相同指纹的历史通信或更多受影响资产。
- [MEDIUM] 结合 IcedID 相关 TTP 做主机侧排查与 IOC 扩线。 理由：已有家族线索时，可以更有针对性地检查样本行为、持久化方式和额外外联特征。

## 参考链接
- 本地指纹情报命中
  摘要：本地情报库将 ja4 t13d201100_2b729b4bf6f3_9e7b989ebec8 关联到家族/标签 IcedID，来源 JA4DB。
- [IcedID (Malware Family)](https://malpedia.caad.fkie.fraunhofer.de/details/win.icedid)
  摘要：Malpedia 将 `IcedID` 描述为已知恶意软件家族，并提供了相应家族背景信息。
- [Fork in the Ice: IcedID Malware Analysis](https://www.proofpoint.com/us/blog/threat-insight/fork-ice-new-era-icedid)
  摘要：Proofpoint 的研究内容提供了与 `IcedID` 相关的威胁活动线索。
- [IcedID, Software S0483](https://attack.mitre.org/software/S0483/)
  摘要：该来源页面《IcedID, Software S0483》提到了与 `IcedID` 或指标 `t13d201100_2b729b4bf6f3_9e7b989ebec8` 相关的信息：IcedID is a modular banking malware designed to steal financial information that has been observe...
- [Melting UNC2198 ICEDID to Ransomware Operations](https://cloud.google.com/blog/topics/threat-intelligence/melting-unc2198-icedid-to-ransomware-operations)
  摘要：该来源页面《Melting UNC2198 ICEDID to Ransomware Operations》提到了与 `IcedID` 或指标 `t13d201100_2b729b4bf6f3_9e7b989ebec8` 相关的信息：Although analysis is always ongoing, at the time of publishing this blog post, Mandiant tracks mu...
- [Security Primer – IcedID](https://www.cisecurity.org/insights/white-papers/security-primer-icedid)
  摘要：该来源页面《Security Primer – IcedID》提到了与 `IcedID` 或指标 `t13d201100_2b729b4bf6f3_9e7b989ebec8` 相关的信息：IcedID, also known as BokBot, is a modular banking trojan that targets user financial information...
