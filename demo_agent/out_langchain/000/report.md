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

## 关键证据与情报
### 本地指纹情报命中
来源：SSLBL
说明：本地情报库将 ja3_md5 4d7a28d6f2263ed61de88ca66eb011e3 关联到家族/标签 Tofsee，来源 SSLBL。
证据等级：高
参考：[https://sslbl.abuse.ch/ja3-fingerprints/4d7a28d6f2263ed61de88ca66eb011e3/](https://sslbl.abuse.ch/ja3-fingerprints/4d7a28d6f2263ed61de88ca66eb011e3/)

### Tofsee (Malware Family)
来源：malpedia.caad.fkie.fraunhofer.de
说明：Malpedia 将 `Tofsee` 描述为已知恶意软件家族，并提供了相应家族背景信息。
证据等级：中
参考：[https://malpedia.caad.fkie.fraunhofer.de/details/win.tofsee](https://malpedia.caad.fkie.fraunhofer.de/details/win.tofsee)

### Tofsee Botnet: Proxying and Mining
来源：bitsight.com
说明：Bitsight 的研究内容提到了 `Tofsee` 的传播或运营活动。
证据等级：中
参考：[https://www.bitsight.com/blog/tofsee-botnet-proxying-and-mining](https://www.bitsight.com/blog/tofsee-botnet-proxying-and-mining)

### Tofsee Malware
来源：checkpoint.com
说明：Check Point 的公开资料对 `Tofsee` 的功能和危害进行了概述。
证据等级：中
参考：[https://www.checkpoint.com/cyber-hub/threat-prevention/what-is-malware/tofsee-malware/](https://www.checkpoint.com/cyber-hub/threat-prevention/what-is-malware/tofsee-malware/)

### Download JA3 IDS Ruleset (Suricata 4.1.0 or newer) - SSLBL
来源：sslbl.abuse.ch
说明：该来源页面《Download JA3 IDS Ruleset (Suricata 4.1.0 or newer) - SSLBL》提到了与 `Tofsee` 或指标 `4d7a28d6f2263ed61de88ca66eb011e3` 相关的信息：... (Tofsee)"; ja3_hash; content:"906004246f3ba5e755b043c057254a29"; reference ... 4d7a28d6f2263e...
证据等级：中
参考：[https://sslbl.abuse.ch/blacklist/ja3_fingerprints.rules](https://sslbl.abuse.ch/blacklist/ja3_fingerprints.rules)

## 本地指纹情报
本地情报库命中 `ja3_md5` 指标 `4d7a28d6f2263ed61de88ca66eb011e3`，关联家族为 `Tofsee`，来源 `SSLBL`。
该记录最近更新时间为 2020-12-08T18:10:55。
可参考：[https://sslbl.abuse.ch/ja3-fingerprints/4d7a28d6f2263ed61de88ca66eb011e3/](https://sslbl.abuse.ch/ja3-fingerprints/4d7a28d6f2263ed61de88ca66eb011e3/)

## 相关情报参考
- [Tofsee (Malware Family)](https://malpedia.caad.fkie.fraunhofer.de/details/win.tofsee)：Malpedia 将 `Tofsee` 描述为已知恶意软件家族，并提供了相应家族背景信息。
- [Download JA3 IDS Ruleset (Suricata 4.1.0 or newer) - SSLBL](https://sslbl.abuse.ch/blacklist/ja3_fingerprints.rules)：该来源页面《Download JA3 IDS Ruleset (Suricata 4.1.0 or newer) - SSLBL》提到了与 `Tofsee` 或指标 `4d7a28d6f2263ed61de88ca66eb011e3` 相关的信息：... (Tofsee)"; ja3_hash; content:"906004246f3ba5e755b043c057254a29"; reference ... 4d7a28d6f2263e...
- [JA3 Fingerprint 4d7a28d6f2263ed61de88ca66eb011e3](https://sslbl.abuse.ch/ja3-fingerprints/4d7a28d6f2263ed61de88ca66eb011e3/)：该来源页面《JA3 Fingerprint 4d7a28d6f2263ed61de88ca66eb011e3》提到了与 `Tofsee` 或指标 `4d7a28d6f2263ed61de88ca66eb011e3` 相关的信息：The JA3 SSL client fingerprint 4d7a28d6f2263ed61de88ca66eb011e3 has been identified to be associa...

## 处置建议
- [HIGH] 排查并视情况隔离源主机 11.22.33.44。 理由：源主机产生了命中后恶意流量，需要确认是否存在持续外联或二次投递行为。
- [HIGH] 在边界侧监控或阻断与 44.33.22.11 相关的后续通信。 理由：当前告警中的网络目的地址是最直接的外联对象，应优先纳入监测范围。
- [MEDIUM] 基于 JA3 指纹 4d7a28d6f2263ed61de88ca66eb011e3 在历史流量中做横向检索。 理由：可以快速判断是否存在相同指纹的历史通信或更多受影响资产。
- [MEDIUM] 结合 Tofsee 相关 TTP 做主机侧排查与 IOC 扩线。 理由：已有家族线索时，可以更有针对性地检查样本行为、持久化方式和额外外联特征。

## 参考链接
- [本地指纹情报命中](https://sslbl.abuse.ch/ja3-fingerprints/4d7a28d6f2263ed61de88ca66eb011e3/)
  摘要：本地情报库将 ja3_md5 4d7a28d6f2263ed61de88ca66eb011e3 关联到家族/标签 Tofsee，来源 SSLBL。
- [Tofsee (Malware Family)](https://malpedia.caad.fkie.fraunhofer.de/details/win.tofsee)
  摘要：Malpedia 将 `Tofsee` 描述为已知恶意软件家族，并提供了相应家族背景信息。
- [Tofsee Botnet: Proxying and Mining](https://www.bitsight.com/blog/tofsee-botnet-proxying-and-mining)
  摘要：Bitsight 的研究内容提到了 `Tofsee` 的传播或运营活动。
- [Tofsee Malware](https://www.checkpoint.com/cyber-hub/threat-prevention/what-is-malware/tofsee-malware/)
  摘要：Check Point 的公开资料对 `Tofsee` 的功能和危害进行了概述。
- [Download JA3 IDS Ruleset (Suricata 4.1.0 or newer) - SSLBL](https://sslbl.abuse.ch/blacklist/ja3_fingerprints.rules)
  摘要：该来源页面《Download JA3 IDS Ruleset (Suricata 4.1.0 or newer) - SSLBL》提到了与 `Tofsee` 或指标 `4d7a28d6f2263ed61de88ca66eb011e3` 相关的信息：... (Tofsee)"; ja3_hash; content:"906004246f3ba5e755b043c057254a29"; reference ... 4d7a28d6f2263e...
- [JA3 Fingerprint 4d7a28d6f2263ed61de88ca66eb011e3](https://sslbl.abuse.ch/ja3-fingerprints/4d7a28d6f2263ed61de88ca66eb011e3/)
  摘要：该来源页面《JA3 Fingerprint 4d7a28d6f2263ed61de88ca66eb011e3》提到了与 `Tofsee` 或指标 `4d7a28d6f2263ed61de88ca66eb011e3` 相关的信息：The JA3 SSL client fingerprint 4d7a28d6f2263ed61de88ca66eb011e3 has been identified to be associa...
