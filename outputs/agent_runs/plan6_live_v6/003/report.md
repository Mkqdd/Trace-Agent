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

本次事件涉及IcedID银行木马，该木马通过多种方式进行传播，并具有窃取金融凭证和部署勒索软件的能力。多个来源证实了该家族的活动及其传播方式，包括钓鱼邮件和利用工具包。

## 事件直接证据
### 本地指纹情报命中
来源：JA4DB
证据等级：高
本地情报库将ja4 t13d201100_2b729b4bf6f3_9e7b989ebec8关联到IcedID家族，这进一步确认了当前事件中的恶意软件属于IcedID。

### IcedID (Malware Family)
来源：malpedia.caad.fkie.fraunhofer.de
证据等级：中
Malpedia提供了关于IcedID的详细背景信息，指出这是一种自2017年起活跃的银行木马，还充当其他恶意软件的加载器，包括勒索软件。
参考：[https://malpedia.caad.fkie.fraunhofer.de/details/win.icedid](https://malpedia.caad.fkie.fraunhofer.de/details/win.icedid)

### Trojan:Win32/IcedId threat description
来源：microsoft.com
证据等级：中
微软的安全报告确认了IcedID是一种模块化的银行木马，自2017年起被观察到，微软的防御系统可以检测并移除这种威胁。
参考：[https://www.microsoft.com/wdsi/threats/malware-encyclopedia-description?Name=Trojan:Win32/IcedId](https://www.microsoft.com/wdsi/threats/malware-encyclopedia-description?Name=Trojan:Win32/IcedId)

### IcedID Malware: Analysis, Detection, Removal
来源：huntress.com
证据等级：中
Huntress.com提供的情报显示，IcedID主要通过钓鱼邮件、驱动下载和利用工具包进行传播，其采用Web注入技术窃取用户数据，并通过DLL注入和加密等高级规避技术维持持久性。
参考：[https://www.huntress.com/threat-library/malware/icedid](https://www.huntress.com/threat-library/malware/icedid)

## 家族背景与补充参考
### IcedID, Software S0483
来源：attack.mitre.org
证据等级：低
IcedID利用COVID-19和FMLA相关主题进行钓鱼攻击，以安装银行木马。这表明攻击者可能通过社会工程学手段诱骗受害者点击恶意链接或附件，从而感染系统。
参考：[https://attack.mitre.org/software/S0483/](https://attack.mitre.org/software/S0483/)

### YiBackdoor: Linked to IcedID and Latrodectus | ThreatLabz
来源：zscaler.com
证据等级：低
Zscaler ThreatLabz发现了一种新的恶意软件家族YiBackdoor，该家族首次在2025年6月被观察到，并且与IcedID有关联。这表明IcedID家族正在不断发展新的恶意软件变种来扩大其威胁能力。
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
