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
- 原始引用：`event.raw_alert`

### e02 告警附带家族提示
- 来源：maltrail-static
- 说明：原始告警将该事件关联到家族/标签 discordgrabber。
- 置信度：70
- 原始引用：`event.enrichment`

### e03 VirusTotal IP 富化
- 来源：VirusTotal
- 查询：`194.226.121.108`
- 说明：VirusTotal 返回 IP 194.226.121.108 的信誉/归属信息。VT 分析统计为 {'malicious': 12, 'suspicious': 1, 'undetected': 33, 'harmless': 48, 'timeout': 0}。
- 置信度：48
- 原始引用：`observations.fingerprint_enrichment`

### e04 ThreatFox | Browse IOCs
- 来源：html_fallback
- 查询：`discordgrabber 194.226.121.108 malware family C2`
- 说明：Using the form below, you can search for malware samples by a hash (MD5, SHA256, SHA1), imphash, tlsh hash, ClamAV signature, tag or malware family. Browse Database
- 链接：//duckduckgo.com/l/?uddg=https%3A%2F%2Fthreatfox.abuse.ch%2Fbrowse&amp;rut=bf66d1fd60b5fb2c020014790b472b3d6cff6358253dadb3d8fb0821fc169745
- 置信度：65
- 原始引用：`observations.family_intel.raw.results[0]`

### e05 Here Comes TroubleGrabber: Stealing Credentials Through Discord
- 来源：html_fallback
- 查询：`discordgrabber 194.226.121.108 malware family C2`
- 说明：The malware uses Discord and Github to deliver the next stage payloads and uses Discord webhooks as a C2 to send the victims credentials. Such attacks require security solutions with application-layer detections, multiple threat detection solutions, DLP, and machine learning techniques that understand the language and nature of the cloud and web.
- 链接：//duckduckgo.com/l/?uddg=https%3A%2F%2Fwww.netskope.com%2Fblog%2Fhere%2Dcomes%2Dtroublegrabber%2Dstealing%2Dcredentials%2Dthrough%2Ddiscord&amp;rut=ddd6799fde4b9f17f3260f32fd66e4db41aa469b91cda5a125f3b6e70e4ee461
- 置信度：65
- 原始引用：`observations.family_intel.raw.results[1]`

### e06 Possibility of discord token grabber program on PC - Resolved Malware ...
- 来源：html_fallback
- 查询：`discordgrabber 194.226.121.108 malware family C2`
- 说明：A few hours ago, without warning, a bot had created its own session on my discord account (while I was still logged in) and sent a spam link to several people in my dms. I am thinking that it may have been down to my session token being grabbed off of a bot I had previously authorised and later h...
- 链接：//duckduckgo.com/l/?uddg=https%3A%2F%2Fforums.malwarebytes.com%2Ftopic%2F318319%2Dpossibility%2Dof%2Ddiscord%2Dtoken%2Dgrabber%2Dprogram%2Don%2Dpc%2F&amp;rut=6a72385883e20f8e1d12ce7e15bf5a04e2a7de9e201b743123d1f7fede4a1540
- 置信度：65
- 原始引用：`observations.family_intel.raw.results[2]`

## 不确定性
- 当前未记录明显的不确定性。

## 处置建议
- [HIGH] 排查并视情况隔离源主机 194.226.121.108。 理由：源主机产生了命中后恶意流量，需要确认是否存在持续外联或二次投递行为。
- [HIGH] 在边界侧监控或阻断与 44.33.22.11 相关的后续通信。 理由：当前告警中的网络目的地址是最直接的外联对象，应优先纳入监测范围。
- [MEDIUM] 基于 IP 指纹 194.226.121.108 在历史流量中做横向检索。 理由：可以快速判断是否存在相同指纹的历史通信或更多受影响资产。
- [MEDIUM] 结合 discordgrabber 相关 TTP 做主机侧排查与 IOC 扩线。 理由：已有家族线索时，可以更有针对性地检查样本行为、持久化方式和额外外联特征。
