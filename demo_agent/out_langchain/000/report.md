# 网络安全事件分析报告

## 研判结论
- 源 11.22.33.44 与目的 44.33.22.11 的 TLS 流量命中 JA3 指纹 4d7a28d6f2263ed61de88ca66eb011e3。
- 该事件当前更可能与 Tofsee 相关。
- 基于当前证据强度，事件处置优先级可评估为 中危。

## 事件摘要
- 事件时间：2026-03-20 10:00:00
- 源地址：`11.22.33.44`
- 目的地址：`44.33.22.11`
- 协议：TLS
- 命中指纹：JA3 `4d7a28d6f2263ed61de88ca66eb011e3`
- 推断家族：Tofsee
- 置信度：70
- 严重度：中危

## 证据与情报
### e01 命中后告警事件
- 来源：alert
- 说明：在 2026-03-20 10:00:00 观察到 11.22.33.44 -> 44.33.22.11 的 TLS 流量，命中 JA3 指纹 4d7a28d6f2263ed61de88ca66eb011e3。
- 置信度：95
- 证据权重：96（高）；依据：原始告警事实
- 原始引用：`event.raw_alert`

### e02 Tofsee (Malware Family) - Fraunhofer
- 来源：malpedia.caad.fkie.fraunhofer.de
- 域名：`malpedia.caad.fkie.fraunhofer.de`
- 查询：`Tofsee 4d7a28d6f2263ed61de88ca66eb011e3 malware family C2`
- 说明：According to PCrisk, Tofsee (also known as Gheg) is a malicious Trojan-type program that is capable of performing DDoS attacks, mining cryptocurrency, sending emails, stealing various account credentials, updating itself, and more. Cyber criminals mainly use this program as an email-oriented tool (they target users' email accounts), however, having Tofsee installed can also lead to many other ...
- 链接：https://malpedia.caad.fkie.fraunhofer.de/details/win.tofsee
- 置信度：65
- 证据权重：76（中）；依据：权威外部来源 malpedia.caad.fkie.fraunhofer.de
- 原始引用：`observations.family_intel.raw.results[1]`

### e03 Win32/Tofsee threat description - Microsoft Security Intelligence
- 来源：microsoft.com
- 域名：`microsoft.com`
- 查询：`Tofsee 4d7a28d6f2263ed61de88ca66eb011e3 malware family C2`
- 说明：Microsoft security software detects and removes this family of threats. These backdoor trojans can use your PC to send spam emails, conduct DDoS attacks and mine for Bitcoins. They can also monitor what you do on your PC and send the information to a malicious hacker. Find out ways that malware can get on your PC.
- 链接：https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Win32/Tofsee
- 置信度：65
- 证据权重：76（中）；依据：权威外部来源 microsoft.com
- 原始引用：`observations.family_intel.raw.results[0]`

### e04 Malware | Neutralizing Tofsee Spambot #2 | InMemoryConfig store vaccine
- 来源：spamhaus.org
- 域名：`spamhaus.org`
- 查询：`Tofsee 4d7a28d6f2263ed61de88ca66eb011e3 malware family C2`
- 说明：A recap If you're wondering what malware vaccines are and how they can be utilized, or you'd like to read about the first vaccine our researchers have shared relating to Tofsee and its binary file, read this blog post. Alternatively, keep reading to learn about a second vaccine our team has produced, focused on polluting Tofsee's internal configuration store.
- 链接：https://www.spamhaus.org/resource-hub/malware/neutralizing-tofsee-spambot-part-2-inmemoryconfig-store-vaccine/
- 置信度：65
- 证据权重：75（中）；依据：权威外部来源 spamhaus.org
- 原始引用：`observations.family_intel.raw.results[3]`

### e05 SSLBL | JA3 Fingerprint 4d7a28d6f2263ed61de88ca66eb011e3
- 来源：sslbl.abuse.ch
- 域名：`sslbl.abuse.ch`
- 查询：`JA3 4d7a28d6f2263ed61de88ca66eb011e3 Tofsee`
- 说明：The JA3 SSL client fingerprint 4d7a28d6f2263ed61de88ca66eb011e3 has been identified to be associated with a Tofsee
- 链接：https://sslbl.abuse.ch/ja3-fingerprints/4d7a28d6f2263ed61de88ca66eb011e3/
- 置信度：60
- 证据权重：75（中）；依据：权威外部来源 sslbl.abuse.ch
- 原始引用：`observations.fingerprint_enrichment.results[0]`

### e06 告警附带家族提示
- 来源：abuse.ch
- 说明：原始告警将该事件关联到家族/标签 Tofsee。
- 置信度：70
- 证据权重：72（中）；依据：结构化本地信息
- 原始引用：`event.enrichment`

### e07 Detecting Tofsee Malware Communication without False Positives
- 来源：hnull.org
- 域名：`hnull.org`
- 查询：`Tofsee 4d7a28d6f2263ed61de88ca66eb011e3 malware family C2`
- 说明：Detecting Tofsee Malware Communication without False Positives The Tofsee malware family attempts to evade detection by using a custom encryption protocol. Nonetheless, that protocol can be identified efficiently. This post describes the detector that I developed and implemented in mercury.
- 链接：https://hnull.org/2025/09/28/detecting-tofsee-malware-communication-without-false-positives/
- 置信度：65
- 证据权重：65（中）；依据：一般网页来源 hnull.org
- 原始引用：`observations.family_intel.raw.results[4]`

## 不确定性
- 当前未记录明显的不确定性。

## 处置建议
- [HIGH] 排查并视情况隔离源主机 11.22.33.44。 理由：源主机产生了命中后恶意流量，需要确认是否存在持续外联或二次投递行为。
- [HIGH] 在边界侧监控或阻断与 44.33.22.11 相关的后续通信。 理由：当前告警中的网络目的地址是最直接的外联对象，应优先纳入监测范围。
- [MEDIUM] 基于 JA3 指纹 4d7a28d6f2263ed61de88ca66eb011e3 在历史流量中做横向检索。 理由：可以快速判断是否存在相同指纹的历史通信或更多受影响资产。
- [MEDIUM] 结合 Tofsee 相关 TTP 做主机侧排查与 IOC 扩线。 理由：已有家族线索时，可以更有针对性地检查样本行为、持久化方式和额外外联特征。
