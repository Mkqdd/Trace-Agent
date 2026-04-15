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

综合多份情报来源，确认此次事件涉及的恶意软件家族为Tofsee。该家族具有多种传播和攻击手段，包括利用漏洞和钓鱼攻击进行传播，并通过修改Windows注册表确保开机自启动。

## 事件直接证据
### 本地指纹情报命中
来源：SSLBL
证据等级：高
本地情报库将JA3指纹4d7a28d6f2263ed61de88ca66eb011e3与Tofsee恶意软件家族关联起来，这表明该指纹在已知的Tofsee活动中被使用过。该匹配结果增加了对该家族的识别可信度。
参考：[https://sslbl.abuse.ch/ja3-fingerprints/4d7a28d6f2263ed61de88ca66eb011e3/](https://sslbl.abuse.ch/ja3-fingerprints/4d7a28d6f2263ed61de88ca66eb011e3/)

### Tofsee (Malware Family)
来源：malpedia.caad.fkie.fraunhofer.de
证据等级：中
Tofsee恶意软件家族的具体行为描述中提到其采用特定的机器指令序列进行操作，如mov和push等指令。这些技术细节有助于进一步识别和分析该家族的行为特征。
参考：[https://malpedia.caad.fkie.fraunhofer.de/details/win.tofsee](https://malpedia.caad.fkie.fraunhofer.de/details/win.tofsee)

### Tofsee Malware
来源：checkpoint.com
证据等级：中
Tofsee恶意软件会修改Windows注册表以实现开机自启动，确保持续感染目标系统。这种持久性机制使得该恶意软件能够在系统重启后继续运行。
参考：[https://www.checkpoint.com/cyber-hub/threat-prevention/what-is-malware/tofsee-malware/](https://www.checkpoint.com/cyber-hub/threat-prevention/what-is-malware/tofsee-malware/)

### Win32/Tofsee threat description
来源：microsoft.com
证据等级：中
微软安全情报显示，Tofsee变种可以通过漏洞利用或钓鱼攻击进行传播，并能执行发送垃圾邮件、DDoS攻击以及比特币挖掘等活动。这些功能表明该家族具有较强的网络攻击能力。
参考：[https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Win32/Tofsee](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Win32/Tofsee)

## 家族背景与补充参考
### Backdoor.Tofsee
来源：malwarebytes.com
证据等级：中
Malwarebytes将Tofsee检测为一种多态性质的特洛伊木马。这种多态特性使得该恶意软件能够在每次感染时改变自身形态，从而逃避检测。这与当前事件中的恶意软件特征相符。
参考：[https://www.malwarebytes.com/blog/detections/backdoor-tofsee](https://www.malwarebytes.com/blog/detections/backdoor-tofsee)

### Download JA3 IDS Ruleset (Suricata 4.1.0 or newer)
来源：sslbl.abuse.ch
证据等级：中
SSLBL滥用中心记录了Tofsee的JA3指纹，其中包含了与当前事件中匹配的JA3哈希值4d7a28d6f2263ed61de88ca66eb011e3。这一证据进一步确认了当前事件中的恶意软件属于Tofsee家族。
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
