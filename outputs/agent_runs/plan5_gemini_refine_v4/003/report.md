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

## 归因依据
当前归因结果为 `IcedID`，置信度为 95。 主依据来自 `JA4DB`。 另有 `JA4DB、家族背景情报` 提供补充支持。 当前主结论以本地指纹情报 `IcedID` 为主，并获得外部结构化情报的补充支持。

当前结论并非仅来自单一标签，而是由结构化命中和外部公开情报共同支撑。 其中 `本地指纹情报命中` 等 4 条高优证据从本地指纹、公开研究和基础设施线索多个角度支持该事件与 `IcedID` 的关联。

## 事件直接证据
### 本地指纹情报命中
来源：JA4DB
证据等级：高
本地情报库将 ja4 t13d201100_2b729b4bf6f3_9e7b989ebec8 关联到家族/标签 IcedID，来源 JA4DB。这表明该本地情报库可以提供关于特定家族/标签的信息，并且这些信息是可靠的。

### IcedID Malware: Analysis, Detection, Removal
来源：huntress.com
证据等级：中
IcedID是一种银行木马，旨在窃取敏感信息，特别是金融凭证。它通过网络钓鱼活动传播，一旦感染系统，就会建立持久性并进行恶意活动。
参考：[https://www.huntress.com/threat-library/malware/icedid](https://www.huntress.com/threat-library/malware/icedid)

### Breaking the Ice: A Deep Dive Into the IcedID Banking ...
来源：ibm.com
证据等级：低
该文章深入分析了IcedID银行木马的新主要版本发布，提供了关于其传播机制、内部版本号提取方法等方面的详细信息。
参考：[https://www.ibm.com/think/x-force/breaking-the-ice-a-deep-dive-into-the-icedid-banking-trojans-new-major-version-release](https://www.ibm.com/think/x-force/breaking-the-ice-a-deep-dive-into-the-icedid-banking-trojans-new-major-version-release)

### IcedID (Malware Family)
来源：malpedia.caad.fkie.fraunhofer.de
证据等级：中
IcedID（又称BokBot）是一种最初被分类为银行木马的恶意软件，于2017年首次被发现。它还充当...
参考：[https://malpedia.caad.fkie.fraunhofer.de/details/win.icedid](https://malpedia.caad.fkie.fraunhofer.de/details/win.icedid)

## 家族背景与补充参考
### IcedID - Red Canary Threat Detection Report
来源：redcanary.com
证据等级：低
红罐子公司的威胁检测报告提供了关于IcedID银行木马的详细信息。该报告指出，IcedID通过钓鱼邮件和其他恶意软件进行传播，并针对金融机构的用户实施攻击。
参考：[https://redcanary.com/threat-detection-report/threats/icedid/](https://redcanary.com/threat-detection-report/threats/icedid/)

### YiBackdoor: Linked to IcedID and Latrodectus | ThreatLabz
来源：zscaler.com
证据等级：低
ZScaler威胁实验室发现了一个新的恶意软件家族，命名为YiBackdoor。该恶意软件与IcedID和Latrodectus存在关联。YiBackdoor最早在2025年6月被观察到，表明它是一个相对较新的威胁。
参考：[https://www.zscaler.com/blogs/security-research/yibackdoor-new-malware-family-links-icedid-and-latrodectus](https://www.zscaler.com/blogs/security-research/yibackdoor-new-malware-family-links-icedid-and-latrodectus)

## 处置建议
### 基础响应
- [HIGH] 排查并视情况隔离源主机 10.20.8.41。 理由：源主机产生了命中后恶意流量，需要确认是否存在持续外联或二次投递行为。
- [HIGH] 在边界侧监控或阻断与 203.0.113.77 相关的后续通信。 理由：当前告警中的网络目的地址是最直接的外联对象，应优先纳入监测范围。
- [MEDIUM] 基于 JA4 指纹 t13d201100_2b729b4bf6f3_9e7b989ebec8 在历史流量中做横向检索。 理由：可以快速判断是否存在相同指纹的历史通信或更多受影响资产。
- [MEDIUM] 结合 IcedID 相关 TTP 做主机侧排查与 IOC 扩线。 理由：已有家族线索时，可以更有针对性地检查样本行为、持久化方式和额外外联特征。

### 建议追加的威胁猎捕动作
- 围绕浏览器凭据、Cookie、钱包插件和本地敏感配置文件开展主机侧排查，确认是否存在信息窃取后的残留痕迹。
- 基于当前外联目标、同证书指纹或同类 TLS 特征继续扩线，排查是否存在持续 C2 通信或其他受影响资产。
- 在历史流量中进一步检索相同 JA4 指标 `t13d201100_2b729b4bf6f3_9e7b989ebec8`，确认是否存在横向复用、批量投递或多资产命中。
