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

此次事件中，IcedID恶意软件通过TLS协议进行了通信，并且其行为与已知的IcedID活动特征相符。IcedID不仅作为其他恶意软件的加载器，还曾导致过人为操作的勒索软件攻击。

## 事件直接证据
### 本地指纹情报命中
来源：JA4DB
证据等级：高
本地情报数据库JA4DB将特定的JA4指纹关联到IcedID恶意软件家族。这种匹配有助于确认此次事件中的恶意软件身份。

### IcedID (Malware Family)
来源：malpedia.caad.fkie.fraunhofer.de
证据等级：中
IcedID不仅是一种恶意软件，还充当其他恶意软件（包括勒索软件）的加载器。在2022年11月，Proofpoint研究人员观察到了IcedID的新变种IcedID Lite，这表明该家族仍在活跃并不断进化。
参考：[https://malpedia.caad.fkie.fraunhofer.de/details/win.icedid](https://malpedia.caad.fkie.fraunhofer.de/details/win.icedid)

### Trojan:Win32/IcedId threat description
来源：microsoft.com
证据等级：中
微软的安全威胁描述指出，IcedID在极端情况下可能导致人为操作的勒索软件攻击。这一描述进一步验证了IcedID的危害性和复杂性。
参考：[https://www.microsoft.com/wdsi/threats/malware-encyclopedia-description?Name=Trojan:Win32/IcedId](https://www.microsoft.com/wdsi/threats/malware-encyclopedia-description?Name=Trojan:Win32/IcedId)

### IcedID Malware: Analysis, Detection, Removal
来源：huntress.com
证据等级：中
Huntress公司提供的关于IcedID的分析和检测方法显示，该恶意软件具备多种危害能力。这些信息有助于更全面地理解IcedID的行为特征。
参考：[https://www.huntress.com/threat-library/malware/icedid](https://www.huntress.com/threat-library/malware/icedid)

## 家族背景与补充参考
### IcedID, Software S0483
来源：attack.mitre.org
证据等级：低
MITRE ATT&CK 矩阵提供了关于 IcedID 软件的详细信息，包括其战术和技术手段。该资源强调了 IcedID 在企业环境中的活动模式，有助于识别和防御相关攻击。
参考：[https://attack.mitre.org/software/S0483/](https://attack.mitre.org/software/S0483/)

### IcedID • Application • JA4+ Database
来源：ja4db.com
证据等级：低
JA4+ 数据库是一个社区维护的指纹库，记录了来自互联网网络的 JA4+ 指纹。该数据库包含有关 IcedID 的传播和检测信息，有助于识别特定的攻击活动。
参考：[https://ja4db.com/application/IcedID%20](https://ja4db.com/application/IcedID%20)

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
