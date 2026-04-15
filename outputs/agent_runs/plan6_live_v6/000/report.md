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

本次事件涉及Tofsee恶意软件家族，其具备多种恶意功能，包括DDoS攻击、挖矿、窃取凭证等。通过分析多个来源的信息，确认该恶意软件可以通过邮件附件进行传播，并且能够下载和执行额外的恶意模块。

## 事件直接证据
### 本地指纹情报命中
来源：SSLBL
证据等级：高
本地情报库将JA3指纹4d7a28d6f2263ed61de88ca66eb011e3关联到了Tofsee恶意软件家族。这表明当前网络通信中的恶意活动与Tofsee有关，进一步验证了恶意软件的存在。
参考：[https://sslbl.abuse.ch/ja3-fingerprints/4d7a28d6f2263ed61de88ca66eb011e3/](https://sslbl.abuse.ch/ja3-fingerprints/4d7a28d6f2263ed61de88ca66eb011e3/)

### Tofsee (Malware Family)
来源：malpedia.caad.fkie.fraunhofer.de
证据等级：中
Tofsee是一种具备多种恶意功能的木马程序，能够执行DDoS攻击、挖矿、发送电子邮件和窃取账户凭证。这些功能表明Tofsee具有高度的威胁性，可以对受害者造成多方面的损害。
参考：[https://malpedia.caad.fkie.fraunhofer.de/details/win.tofsee](https://malpedia.caad.fkie.fraunhofer.de/details/win.tofsee)

### Tofsee Malware
来源：checkpoint.com
证据等级：中
Tofsee不仅具备核心恶意功能，还是一种模块化恶意软件，能够在受感染的计算机上下载并执行额外的恶意功能。这种特性使得Tofsee能够持续扩展其危害能力，增加了防护难度。
参考：[https://www.checkpoint.com/cyber-hub/threat-prevention/what-is-malware/tofsee-malware/](https://www.checkpoint.com/cyber-hub/threat-prevention/what-is-malware/tofsee-malware/)

### Backdoor.Tofsee
来源：malwarebytes.com
证据等级：中
Backdoor.Tofsee一旦被执行，能够跟踪用户在线活动，改变浏览器和DNS设置，并窃取个人信息。这种恶意软件可以通过邮件附件进行传播，增加了其传播范围和感染风险。
参考：[https://www.malwarebytes.com/blog/detections/backdoor-tofsee](https://www.malwarebytes.com/blog/detections/backdoor-tofsee)

## 家族背景与补充参考
### Trojan.Win32.TOFSEE.AD - Threat Encyclopedia
来源：trendmicro.com
证据等级：低
Tofsee特洛伊木马通常作为其他恶意软件投放的文件，或当用户访问恶意网站时无意间下载的文件进入系统。这种传播方式有助于理解当前事件中的恶意软件是如何进入系统的。
参考：[https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/trojan.win32.tofsee.ad](https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/trojan.win32.tofsee.ad)

### Tofsee Botnet: Proxying and Mining
来源：bitsight.com
证据等级：中
Bitsight发现，一个名为PrivateLoader的著名恶意软件正在分发Tofsee模块化垃圾邮件机器人。这表明Tofsee可能涉及代理和挖矿活动，进一步支持了当前事件中Tofsee家族的活跃性和复杂性。
参考：[https://www.bitsight.com/blog/tofsee-botnet-proxying-and-mining](https://www.bitsight.com/blog/tofsee-botnet-proxying-and-mining)

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
