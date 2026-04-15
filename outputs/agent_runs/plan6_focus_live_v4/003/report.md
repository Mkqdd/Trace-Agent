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

当前事件涉及IcedID银行木马，该木马通过与C2服务器通信获取恶意载荷并注入到svchost.exe进程中，同时能够执行网络钓鱼和web注入攻击。本地情报库中的JA4指标进一步确认了该事件与IcedID相关。

## 事件直接证据
### 本地指纹情报命中
来源：JA4DB
证据等级：高
本地情报库 `JA4DB` 直接将当前命中的 JA4 指标 `t13d201100_2b729b4bf6f3_9e7b989ebec8` 关联到 `IcedID`，这不是泛化的家族背景描述，而是直接落在本次告警触发项上的结构化命中，因此应视为本轮归因的核心证据。 该记录最近更新时间为 2026-03-28T23:16:27，说明这条映射并非孤立的历史残留，仍可以作为当前事件研判的高权重依据。 这意味着当前告警并不是仅凭标题或模糊标签做出的猜测，而是已经拿到了可以与历史情报库稳定对应的指纹线索，因此后续外部页面证据的主要作用是补充 `IcedID` 的能力画像和行为细节，而不是替代这条直接映射。 从落地排查角度看，可以优先围绕 `t13d201100_2b729b4bf6f3_9e7b989ebec8` 做历史流量横向检索，确认是否存在同指纹复用、持续外联或多资产同时命中的情况。

### Breaking the Ice: A Deep Dive Into the IcedID Banking ...
来源：ibm.com
证据等级：中
`Breaking the Ice: A Deep Dive Into the IcedID Banking ...` 的正文对 `IcedID` 给出了更完整的能力画像：The loader communicates with the C2 to fetch the IcedID payload The downloader downloads the malicious payload – a file named photo.png* The loader runs photo.png The loader creates a new instance of svchost.exe Loader injects the malicious payload into the new svchost.exe process The browser hooking will allow IcedID to detect targeted URLs and deploy web-injections accordingly. Next, the loader creates a new process, svchost, and injects the decrypted IcedID payload into it. 从页面正文能直接抽出的关键技术点包括：The loader communicates with the C2 to fetch the IcedID payload The downloader downloads the malicious payload – a file named photo.png* The loader runs photo.png The loader creates a new instance of svchost.exe Loader injects the malicious payload into the new svchost.exe process；The browser hooking will allow IcedID to detect targeted URLs and deploy web-injections accordingly.；Next, the loader creates a new process, svchost, and injects the decrypted IcedID payload into it.。 放回当前告警语境里看，这些信息的价值不只是补充背景，而是说明 `IcedID` 已知的传播、持久化、模块加载或窃密特征，与当前流量命中后的家族判断能够互相支撑。 从研判与处置角度看，这类正文型来源能够帮助我们把“命中某个家族”进一步展开为“该家族通常如何传播、落地后会做什么、后续还该排查哪些痕迹”，因此比单纯标签更有分析价值。
参考：[https://www.ibm.com/think/x-force/breaking-the-ice-a-deep-dive-into-the-icedid-banking-trojans-new-major-version-release](https://www.ibm.com/think/x-force/breaking-the-ice-a-deep-dive-into-the-icedid-banking-trojans-new-major-version-release)

### IcedID Malware: Analysis, Detection, Removal
来源：huntress.com
证据等级：中
IcedID是一种银行木马，通过网络钓鱼邮件、驱动下载和利用工具包传播，能够窃取金融凭证并部署勒索软件。这一信息提供了关于IcedID的背景补充，有助于理解其传播方式和潜在威胁。
参考：[https://www.huntress.com/threat-library/malware/icedid](https://www.huntress.com/threat-library/malware/icedid)

## 家族背景与补充参考
### Latrodectus Malware Analysis: IcedID 2.0
来源：proofpoint.com
证据等级：中
IcedID 2.0能够通过隐秘手段外泄敏感数据并导致电子邮件被误导向。这些技术特点有助于理解当前事件中的威胁行为。
参考：[https://www.proofpoint.com/us/blog/threat-insight/latrodectus-spider-bytes-ice](https://www.proofpoint.com/us/blog/threat-insight/latrodectus-spider-bytes-ice)

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
