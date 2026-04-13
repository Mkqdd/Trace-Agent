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

当前事件涉及Tofsee恶意软件家族，其特征包括使用受感染计算机进行DDoS攻击、加密货币挖掘以及电子邮件发送等功能。本地情报数据库通过ja3_md5标识符关联到Tofsee家族，这进一步证实了该事件的性质和威胁。此外，该恶意软件还具有收集用户信息的功能，使其成为一种多功能且具有高度威胁性的恶意软件。总之，当前事件涉及Tofsee恶意软件家族，并且该恶意软件具有多种功能和高度威胁性。

## 事件直接证据
### 本地指纹情报命中
来源：SSLBL
证据等级：高
本地情报数据库将ja3_md5标识符4d7a28d6f2263ed61de88ca66eb011e3关联到了Tofsee恶意软件家族，这表明该恶意软件可能具有与Tofsee相关的功能和威胁性。
参考：[https://sslbl.abuse.ch/ja3-fingerprints/4d7a28d6f2263ed61de88ca66eb011e3/](https://sslbl.abuse.ch/ja3-fingerprints/4d7a28d6f2263ed61de88ca66eb011e3/)

### Tofsee (Malware Family)
来源：malpedia.caad.fkie.fraunhofer.de
证据等级：中
Tofsee（又称Gheg）是一种恶意的特洛伊木马类型的程序，能够执行DDoS攻击、加密货币挖掘、发送电子邮件、窃取信息等操作。这些功能使得Tofsee成为了一种多功能且具有高度威胁性的恶意软件。
参考：[https://malpedia.caad.fkie.fraunhofer.de/details/win.tofsee](https://malpedia.caad.fkie.fraunhofer.de/details/win.tofsee)

### Tofsee Malware
来源：checkpoint.com
证据等级：中
Tofsee是一种模块化的特洛伊木马类型的恶意软件。一旦安装在被感染的计算机上，它可以用于发送垃圾邮件电子邮件并收集有关计算机用户的计算机的信息。这些功能使得Tofsee成为了一种多功能且具有高度威胁性的恶意软件。
参考：[https://www.checkpoint.com/cyber-hub/threat-prevention/what-is-malware/tofsee-malware/](https://www.checkpoint.com/cyber-hub/threat-prevention/what-is-malware/tofsee-malware/)

### Win32/Tofsee threat description
来源：microsoft.com
证据等级：中
这些后门特洛伊木马可以使用您的PC来发送垃圾邮件电子邮件，进行DDoS攻击和挖掘比特币。它们还可以监视您在PC上的活动。这些功能使得Tofsee成为了一种多功能且具有高度威胁性的恶意软件。
参考：[https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Win32/Tofsee](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Win32/Tofsee)

## 家族背景与补充参考
### Backdoor.Tofsee
来源：malwarebytes.com
证据等级：中
Tofsee被Malwarebytes检测为Backdoor.Tofsee。它是一个具有多态性质的木马后门。这一发现有助于我们了解该家族的技术特点。
参考：[https://www.malwarebytes.com/blog/detections/backdoor-tofsee](https://www.malwarebytes.com/blog/detections/backdoor-tofsee)

### Download JA3 IDS Ruleset (Suricata 4.1.0 or newer)
来源：sslbl.abuse.ch
证据等级：中
通过SSLBL Abuse.ch提供的JA3指纹规则集，我们能够识别出与Tofsee相关的特定JA3哈希值。这表明Tofsee家族正在利用这些哈希值来逃避检测。
参考：[https://sslbl.abuse.ch/blacklist/ja3_fingerprints.rules](https://sslbl.abuse.ch/blacklist/ja3_fingerprints.rules)

## 处置建议
### 基础响应
- [HIGH] 排查并视情况隔离源主机 11.22.33.44。 理由：源主机产生了命中后恶意流量，需要确认是否存在持续外联或二次投递行为。
- [HIGH] 在边界侧监控或阻断与 44.33.22.11 相关的后续通信。 理由：当前告警中的网络目的地址是最直接的外联对象，应优先纳入监测范围。
- [MEDIUM] 基于 JA3 指纹 4d7a28d6f2263ed61de88ca66eb011e3 在历史流量中做横向检索。 理由：可以快速判断是否存在相同指纹的历史通信或更多受影响资产。
- [MEDIUM] 结合 Tofsee 相关 TTP 做主机侧排查与 IOC 扩线。 理由：已有家族线索时，可以更有针对性地检查样本行为、持久化方式和额外外联特征。

### 建议追加的威胁猎捕动作
- 基于当前外联目标、同证书指纹或同类 TLS 特征继续扩线，排查是否存在持续 C2 通信或其他受影响资产。
- 在历史流量中进一步检索相同 JA3 指标 `4d7a28d6f2263ed61de88ca66eb011e3`，确认是否存在横向复用、批量投递或多资产命中。
