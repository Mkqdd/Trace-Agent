# 网络安全事件分析报告

## 事件概述
- 事件时间：2026-03-31 10:30:00
- 通信关系：`194.226.121.108` -> `44.33.22.11`
- 协议：HTTP
- 命中指标：IP `194.226.121.108`
- 当前研判：可疑恶意流量
- 置信度：45
- 严重度：低危

## 研判结论
在 2026-03-31 10:30:00，检测到 194.226.121.108 与 44.33.22.11 之间存在 HTTP 流量，该流量命中 IP 指标 `194.226.121.108`。

当前已确认该事件具备可疑恶意流量特征，但自动化情报尚不足以稳定归因到明确家族。

## 关键证据与情报
### VirusTotal IP 富化
来源：VirusTotal
说明：VirusTotal 提供了指标 `194.226.121.108` 的信誉与基础归属信息，可作为该事件风险判断的辅助依据。
证据等级：中
参考：[https://www.virustotal.com/gui/ip-address/194.226.121.108](https://www.virustotal.com/gui/ip-address/194.226.121.108)

### ThreatFox | Kaiji
来源：threatfox.abuse.ch
说明：该来源页面《ThreatFox | Kaiji》提到了与 `Unknown` 或指标 `194.226.121.108` 相关的信息：The page below gives you an overview on indicators of compromise associated with elf.kaiji . You...
证据等级：中
参考：[https://threatfox.abuse.ch/browse/malware/elf.kaiji/](https://threatfox.abuse.ch/browse/malware/elf.kaiji/)

### ThreatFox | Orcus RAT
来源：threatfox.abuse.ch
说明：该来源页面《ThreatFox | Orcus RAT》提到了与 `Unknown` 或指标 `194.226.121.108` 相关的信息：The page below gives you an overview on indicators of compromise associated with win.orcus_rat. Y...
证据等级：中
参考：[https://threatfox.abuse.ch/browse/malware/win.orcus_rat/](https://threatfox.abuse.ch/browse/malware/win.orcus_rat/)

## 相关情报参考
- [ThreatFox | Kaiji](https://threatfox.abuse.ch/browse/malware/elf.kaiji/)：该来源页面《ThreatFox | Kaiji》提到了与 `Unknown` 或指标 `194.226.121.108` 相关的信息：The page below gives you an overview on indicators of compromise associated with elf.kaiji . You...
- [ThreatFox | Orcus RAT](https://threatfox.abuse.ch/browse/malware/win.orcus_rat/)：该来源页面《ThreatFox | Orcus RAT》提到了与 `Unknown` 或指标 `194.226.121.108` 相关的信息：The page below gives you an overview on indicators of compromise associated with win.orcus_rat. Y...

## 说明
- 当前自动化情报不足以稳定归因到明确恶意软件家族。

## 处置建议
- [HIGH] 排查并视情况隔离源主机 194.226.121.108。 理由：源主机产生了命中后恶意流量，需要确认是否存在持续外联或二次投递行为。
- [HIGH] 在边界侧监控或阻断与 44.33.22.11 相关的后续通信。 理由：当前告警中的网络目的地址是最直接的外联对象，应优先纳入监测范围。
- [MEDIUM] 基于 IP 指纹 194.226.121.108 在历史流量中做横向检索。 理由：可以快速判断是否存在相同指纹的历史通信或更多受影响资产。

## 参考链接
- [VirusTotal IP 富化](https://www.virustotal.com/gui/ip-address/194.226.121.108)
  摘要：VirusTotal 提供了指标 `194.226.121.108` 的信誉与基础归属信息，可作为该事件风险判断的辅助依据。
- [ThreatFox | Kaiji](https://threatfox.abuse.ch/browse/malware/elf.kaiji/)
  摘要：该来源页面《ThreatFox | Kaiji》提到了与 `Unknown` 或指标 `194.226.121.108` 相关的信息：The page below gives you an overview on indicators of compromise associated with elf.kaiji . You...
- [ThreatFox | Orcus RAT](https://threatfox.abuse.ch/browse/malware/win.orcus_rat/)
  摘要：该来源页面《ThreatFox | Orcus RAT》提到了与 `Unknown` 或指标 `194.226.121.108` 相关的信息：The page below gives you an overview on indicators of compromise associated with win.orcus_rat. Y...
