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
- 原始引用：`event.raw_alert`

### e02 告警附带家族提示
- 来源：abuse.ch
- 说明：原始告警将该事件关联到家族/标签 Tofsee。
- 置信度：70
- 原始引用：`event.enrichment`

### e03 SSLBL | JA3 Fingerprint 4d7a28d6f2263ed61de88ca66eb011e3
- 来源：html_fallback
- 查询：`JA3 4d7a28d6f2263ed61de88ca66eb011e3 Tofsee`
- 说明：The JA3 SSL client fingerprint 4d7a28d6f2263ed61de88ca66eb011e3 has been identified to be associated with a Tofsee
- 链接：//duckduckgo.com/l/?uddg=https%3A%2F%2Fsslbl.abuse.ch%2Fja3%2Dfingerprints%2F4d7a28d6f2263ed61de88ca66eb011e3%2F&amp;rut=e12da2595d56c2742df2e0170603f27a6c4e7fe9d79df426d66e9852cfcc91c2
- 置信度：60
- 原始引用：`observations.fingerprint_enrichment.results[0]`

### e04 ja3.me | Free JA3 database
- 来源：html_fallback
- 查询：`JA3 4d7a28d6f2263ed61de88ca66eb011e3 Tofsee`
- 说明：Freely available database of JA3 data, including hashes, user agents, and TLS cipher data.
- 链接：//duckduckgo.com/l/?uddg=https%3A%2F%2Fja3.me%2F&amp;rut=91df37573eb2b4f4972c35d688168e3ae15c9710cdd096879ac5490e222eafe1
- 置信度：60
- 原始引用：`observations.fingerprint_enrichment.results[1]`

### e05 JA3 Fingerprint Lookup - Free TLS &amp; SSL Fingerprinting Tool | TrustMyIP
- 来源：html_fallback
- 查询：`JA3 4d7a28d6f2263ed61de88ca66eb011e3 Tofsee`
- 说明：Free JA3 fingerprint lookup tool to check your TLS Client Hello fingerprint. Detect your browser JA3 hash, cipher suites, &amp; SSL extensions instantly.
- 链接：//duckduckgo.com/l/?uddg=https%3A%2F%2Ftrustmyip.com%2Fja3%2Dfingerprint&amp;rut=d444da673370fd46ffc0f05aa895b67b6add6fd79e4d122777ed8a0bde166ba0
- 置信度：60
- 原始引用：`observations.fingerprint_enrichment.results[2]`

### e06 Tofsee (Malware Family) - Fraunhofer
- 来源：html_fallback
- 查询：`Tofsee 4d7a28d6f2263ed61de88ca66eb011e3 malware family C2`
- 说明：According to PCrisk, Tofsee (also known as Gheg) is a malicious Trojan-type program that is capable of performing DDoS attacks, mining cryptocurrency, sending emails, stealing various account credentials, updating itself, and more. Cyber criminals mainly use this program as an email-oriented tool (they target users&#x27; email accounts), however, having Tofsee installed can also lead to many other ...
- 链接：//duckduckgo.com/l/?uddg=https%3A%2F%2Fmalpedia.caad.fkie.fraunhofer.de%2Fdetails%2Fwin.tofsee&amp;rut=174365d0497de30732a43065efa4d3ca8374c704b8cf3ac498d4f8fc19f9e478
- 置信度：65
- 原始引用：`observations.family_intel.raw.results[0]`

### e07 Win32/Tofsee threat description - Microsoft Security Intelligence
- 来源：html_fallback
- 查询：`Tofsee 4d7a28d6f2263ed61de88ca66eb011e3 malware family C2`
- 说明：Microsoft security software detects and removes this family of threats. These backdoor trojans can use your PC to send spam emails, conduct DDoS attacks and mine for Bitcoins. They can also monitor what you do on your PC and send the information to a malicious hacker. Find out ways that malware can get on your PC.
- 链接：//duckduckgo.com/l/?uddg=https%3A%2F%2Fwww.microsoft.com%2Fen%2Dus%2Fwdsi%2Fthreats%2Fmalware%2Dencyclopedia%2Ddescription%3FName%3DWin32%2FTofsee&amp;rut=67efe557d2768d320e803aa431e1ac68bea5ff472aa933094ef67753e55e37e9
- 置信度：65
- 原始引用：`observations.family_intel.raw.results[1]`

### e08 Detecting Tofsee Malware Communication without False Positives
- 来源：html_fallback
- 查询：`Tofsee 4d7a28d6f2263ed61de88ca66eb011e3 malware family C2`
- 说明：Detecting Tofsee Malware Communication without False Positives The Tofsee malware family attempts to evade detection by using a custom encryption protocol. Nonetheless, that protocol can be identified efficiently. This post describes the detector that I developed and implemented in mercury.
- 链接：//duckduckgo.com/l/?uddg=https%3A%2F%2Fhnull.org%2F2025%2F09%2F28%2Fdetecting%2Dtofsee%2Dmalware%2Dcommunication%2Dwithout%2Dfalse%2Dpositives%2F&amp;rut=cd73b4ada232fed59350f5a63ad0f9a6ab76365fc3feb2b1ef409bde740d2a6a
- 置信度：65
- 原始引用：`observations.family_intel.raw.results[2]`

## 不确定性
- 当前未记录明显的不确定性。

## 处置建议
- [HIGH] 排查并视情况隔离源主机 11.22.33.44。 理由：源主机产生了命中后恶意流量，需要确认是否存在持续外联或二次投递行为。
- [HIGH] 在边界侧监控或阻断与 44.33.22.11 相关的后续通信。 理由：当前告警中的网络目的地址是最直接的外联对象，应优先纳入监测范围。
- [MEDIUM] 基于 JA3 指纹 4d7a28d6f2263ed61de88ca66eb011e3 在历史流量中做横向检索。 理由：可以快速判断是否存在相同指纹的历史通信或更多受影响资产。
- [MEDIUM] 结合 Tofsee 相关 TTP 做主机侧排查与 IOC 扩线。 理由：已有家族线索时，可以更有针对性地检查样本行为、持久化方式和额外外联特征。
