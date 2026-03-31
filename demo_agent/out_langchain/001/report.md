# 网络安全事件分析报告

## 研判结论
- 源 194.226.121.108 与目的 44.33.22.11 的 HTTP 流量命中 IP 指纹 194.226.121.108。
- 该事件当前更可能与 discordgrabber 相关。

## 事件摘要
- 事件时间：2026-03-20 10:00:00
- 源地址：`194.226.121.108`
- 目的地址：`44.33.22.11`
- 协议：HTTP
- 命中指纹：IP `194.226.121.108`
- 推断家族：discordgrabber
- 置信度：48
- 严重度：低危

## 证据与情报
### e01 命中后告警事件
- 来源：alert
- 说明：在 2026-03-20 10:00:00 观察到 194.226.121.108 -> 44.33.22.11 的 HTTP 流量，命中 IP 指纹 194.226.121.108。
- 置信度：95
- 证据权重：96（高）；依据：原始告警事实
- 原始引用：`event.raw_alert`

### e02 MalwareBazaar | DiscordGrabber - abuse.ch
- 来源：bazaar.abuse.ch
- 域名：`bazaar.abuse.ch`
- 查询：`discordgrabber 194.226.121.108 malware family C2`
- 说明：Malware samples associated with tag DiscordGrabber MalwareBazaar Database Samples on MalwareBazaar are usually associated with certain tags. Every sample can associated with one or more tags. Using tags, it is easy to navigate through the huge amount of malware samples in the MalwareBazaar corpus. The page below gives you an overview on malware samples that are tagged with DiscordGrabber ...
- 链接：https://bazaar.abuse.ch/browse/tag/DiscordGrabber/
- 置信度：65
- 证据权重：78（中）；依据：权威外部来源 bazaar.abuse.ch
- 原始引用：`observations.family_intel.raw.results[4]`

### e03 VirusTotal IP 富化
- 来源：VirusTotal
- 查询：`194.226.121.108`
- 说明：VirusTotal 返回 IP 194.226.121.108 的信誉/归属信息。VT 分析统计为 {'malicious': 12, 'suspicious': 1, 'undetected': 33, 'harmless': 48, 'timeout': 0}。
- 置信度：48
- 证据权重：75（中）；依据：结构化信誉情报
- 原始引用：`observations.fingerprint_enrichment`

### e04 告警附带家族提示
- 来源：maltrail-static
- 说明：原始告警将该事件关联到家族/标签 discordgrabber。
- 置信度：70
- 证据权重：74（中）；依据：本地静态情报命中
- 原始引用：`event.enrichment`

### e05 Here Comes TroubleGrabber: Stealing Credentials Through Discord
- 来源：netskope.com
- 域名：`netskope.com`
- 查询：`discordgrabber 194.226.121.108 malware family C2`
- 说明：The malware uses Discord and Github to deliver the next stage payloads and uses Discord webhooks as a C2 to send the victims credentials. Such attacks require security solutions with application-layer detections, multiple threat detection solutions, DLP, and machine learning techniques that understand the language and nature of the cloud and web.
- 链接：https://www.netskope.com/blog/here-comes-troublegrabber-stealing-credentials-through-discord
- 置信度：65
- 证据权重：74（中）；依据：权威外部来源 netskope.com
- 原始引用：`observations.family_intel.raw.results[1]`

### e06 New TroubleGrabber malware targets Discord users
- 来源：securityaffairs.com
- 域名：`securityaffairs.com`
- 查询：`discordgrabber 194.226.121.108 malware family C2`
- 说明：The malware the same functionalities used by other malware that target Discord gamers, like AnarchyGrabber, but it appears to be the work of different threat actors. TroubleGrabber was developed by an individual named "Itroublve" and is currently used by multiple threat actors.
- 链接：https://securityaffairs.com/110887/malware/troublegrabber-discord-malware.html
- 置信度：65
- 证据权重：73（中）；依据：权威外部来源 securityaffairs.com
- 原始引用：`observations.family_intel.raw.results[2]`

## 不确定性
- 当前未记录明显的不确定性。

## 处置建议
- [HIGH] 排查并视情况隔离源主机 194.226.121.108。 理由：源主机产生了命中后恶意流量，需要确认是否存在持续外联或二次投递行为。
- [HIGH] 在边界侧监控或阻断与 44.33.22.11 相关的后续通信。 理由：当前告警中的网络目的地址是最直接的外联对象，应优先纳入监测范围。
- [MEDIUM] 基于 IP 指纹 194.226.121.108 在历史流量中做横向检索。 理由：可以快速判断是否存在相同指纹的历史通信或更多受影响资产。
- [MEDIUM] 结合 discordgrabber 相关 TTP 做主机侧排查与 IOC 扩线。 理由：已有家族线索时，可以更有针对性地检查样本行为、持久化方式和额外外联特征。
