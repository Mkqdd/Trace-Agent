# 网络安全事件分析报告

## 事件概述
- 事件时间：2026-03-20 10:00:00
- 通信关系：`11.22.33.44` -> `44.33.22.11`
- 协议：TLS
- 命中指标：JA3 `4d7a28d6f2263ed61de88ca66eb011e3`
- 当前研判：Tofsee
- 置信度：95
- 严重度：高危

## 研判结论
在 2026-03-20 10:00:00，检测到 11.22.33.44 与 44.33.22.11 之间存在 TLS 流量，该流量命中 JA3 指标 `4d7a28d6f2263ed61de88ca66eb011e3`。

结合本地指纹情报与外部公开情报，当前将该事件关联到 `Tofsee` 的把握为较高。

## 归因依据
当前归因结果为 `Tofsee`，置信度为 95。 主依据来自 `SSLBL`。 另有 `abuse.ch、家族背景情报` 提供补充支持。 当前主结论以本地指纹情报 `Tofsee` 为主，并获得外部结构化情报的补充支持。

当前事件中，通信流命中了与Tofsee恶意软件相关的JA3指纹。Tofsee是一种可由其他恶意软件下载并安装的恶意软件，它可以通过漏洞利用或钓鱼攻击传播，并在受感染计算机上创建注册表项以保存配置信息。此外，Tofsee还具有模块化特性，能够下载并执行额外的恶意功能。这些信息有助于进一步识别和防范Tofsee的感染。

## 事件直接证据
### 本地指纹情报命中
来源：SSLBL
证据等级：高
本地情报库 `SSLBL` 直接将当前命中的 JA3 指标 `4d7a28d6f2263ed61de88ca66eb011e3` 关联到 `Tofsee`，这不是泛化的家族背景描述，而是直接落在本次告警触发项上的结构化命中，因此应视为本轮归因的核心证据。 该记录最近更新时间为 2020-12-08T18:10:55，说明这条映射并非孤立的历史残留，仍可以作为当前事件研判的高权重依据。 这意味着当前告警并不是仅凭标题或模糊标签做出的猜测，而是已经拿到了可以与历史情报库稳定对应的指纹线索，因此后续外部页面证据的主要作用是补充 `Tofsee` 的能力画像和行为细节，而不是替代这条直接映射。 从落地排查角度看，可以优先围绕 `4d7a28d6f2263ed61de88ca66eb011e3` 做历史流量横向检索，确认是否存在同指纹复用、持续外联或多资产同时命中的情况。
参考：[https://sslbl.abuse.ch/ja3-fingerprints/4d7a28d6f2263ed61de88ca66eb011e3/](https://sslbl.abuse.ch/ja3-fingerprints/4d7a28d6f2263ed61de88ca66eb011e3/)

### Win32/Tofsee threat description
来源：microsoft.com
证据等级：中
Tofsee恶意软件可通过其他恶意软件下载，例如TrojanDownloader:Win32/Tofsee，并通过漏洞利用或钓鱼攻击传播。Tofsee会在注册表中创建HKCU\Software\Microsoft\DeviceControl子键，并设置"DevData"值来保存加密配置信息。这种配置机制使得Tofsee能够在受感染系统中持久存在并执行恶意操作。此信息表明当前通信流可能涉及此类恶意活动，需进一步检查相关注册表项和配置文件。
参考：[https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Win32/Tofsee](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Win32/Tofsee)

### Tofsee Malware
来源：checkpoint.com
证据等级：中
Tofsee是一种模块化恶意软件，能够下载并执行额外的恶意功能，增加了其危害性。被感染的计算机可能会成为DDoS僵尸网络的一部分。这些信息表明，Tofsee不仅可以通过特定的网络行为特征进行识别，还能通过其在网络中的活动模式进一步确认。这有助于采取更全面的安全措施来防止Tofsee的感染和扩散。
参考：[https://www.checkpoint.com/cyber-hub/threat-prevention/what-is-malware/tofsee-malware/](https://www.checkpoint.com/cyber-hub/threat-prevention/what-is-malware/tofsee-malware/)

## 家族背景与补充参考
### Tofsee (Malware Family)
来源：malpedia.caad.fkie.fraunhofer.de
证据等级：中
Tofsee（也称为Gheg）是一种能够执行DDoS攻击、挖矿、发送邮件、窃取账户凭证和自我更新的恶意程序。它还与垃圾邮件活动有关，并使用.ch域名生成算法。这些信息有助于理解当前事件中Tofsee的潜在行为。
参考：[https://malpedia.caad.fkie.fraunhofer.de/details/win.tofsee](https://malpedia.caad.fkie.fraunhofer.de/details/win.tofsee)

## 处置建议
### 基础响应
- [HIGH] 排查并视情况隔离源主机 11.22.33.44。 理由：源主机产生了命中后恶意流量，需要确认是否存在持续外联或二次投递行为。
- [HIGH] 在边界侧监控或阻断与 44.33.22.11 相关的后续通信。 理由：当前告警中的网络目的地址是最直接的外联对象，应优先纳入监测范围。
- [MEDIUM] 基于 JA3 指纹 4d7a28d6f2263ed61de88ca66eb011e3 在历史流量中做横向检索。 理由：可以快速判断是否存在相同指纹的历史通信或更多受影响资产。
- [MEDIUM] 结合 Tofsee 相关 TTP 做主机侧排查与 IOC 扩线。 理由：已有家族线索时，可以更有针对性地检查样本行为、持久化方式和额外外联特征。

### 建议追加的威胁猎捕动作
- 围绕浏览器凭据、Cookie、钱包插件和本地敏感配置文件开展主机侧排查，确认是否存在信息窃取后的残留痕迹。
- 基于当前外联目标、同证书指纹或同类 TLS 特征继续扩线，排查是否存在持续 C2 通信或其他受影响资产。
- 在历史流量中进一步检索相同 JA3 指标 `4d7a28d6f2263ed61de88ca66eb011e3`，确认是否存在横向复用、批量投递或多资产命中。
