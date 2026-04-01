# 网络安全事件分析报告

## 事件概述
- 事件时间：2026-03-29 13:20:00
- 通信关系：`10.10.14.9` -> `198.51.100.88`
- 协议：TLS
- 命中指标：SSL_SHA1 `0a95355a64c3fe3f52695f97595037481ca11c4d`
- 当前研判：Vidar
- 置信度：95
- 严重度：高危

## 研判结论
在 2026-03-29 13:20:00，检测到 10.10.14.9 与 198.51.100.88 之间存在 TLS 流量，该流量命中 SSL_SHA1 指标 `0a95355a64c3fe3f52695f97595037481ca11c4d`。

结合本地指纹情报与外部公开情报，当前将该事件关联到 `Vidar` 的把握为较高。

## 关键证据与情报
### 本地指纹情报命中
来源：SSLBL
说明：本地情报库将 ssl_sha1 0a95355a64c3fe3f52695f97595037481ca11c4d 关联到家族/标签 Vidar，来源 SSLBL。
证据等级：高

### infected with vidar infostealer : r/antivirus
来源：reddit.com
说明：社区讨论中提到了与 `Vidar` 相关的感染或处置经历，仅适合作为低权重参考。
证据等级：中
参考：[https://www.reddit.com/r/antivirus/comments/1pgmyi3/infected_with_vidar_infostealer/](https://www.reddit.com/r/antivirus/comments/1pgmyi3/infected_with_vidar_infostealer/)

### Vidar (Malware Family)
来源：malpedia.caad.fkie.fraunhofer.de
说明：Malpedia 将 `Vidar` 描述为已知恶意软件家族，并提供了相应家族背景信息。
证据等级：中
参考：[https://malpedia.caad.fkie.fraunhofer.de/details/win.vidar](https://malpedia.caad.fkie.fraunhofer.de/details/win.vidar)

### Hacked sites deliver Vidar infostealer to Windows users
来源：malwarebytes.com
说明：Malwarebytes 的检测页面将相关样本归入 `Vidar` 并给出简要说明。
证据等级：低
参考：[https://www.malwarebytes.com/blog/threat-intel/2026/03/hacked-sites-deliver-vidar-infostealer-to-windows-users](https://www.malwarebytes.com/blog/threat-intel/2026/03/hacked-sites-deliver-vidar-infostealer-to-windows-users)

### How Vidar Malware Spreads via Malvertising on Google
来源：darktrace.com
说明：该来源页面《How Vidar Malware Spreads via Malvertising on Google》提到了与 `Vidar` 或指标 `0a95355a64c3fe3f52695f97595037481ca11c4d` 相关的信息：Discover how Vidar info stealer malware is distributed through malvertising on Google and the ris...
证据等级：低
参考：[https://www.darktrace.com/blog/vidar-info-stealer-malware-distributed-via-malvertising-on-google](https://www.darktrace.com/blog/vidar-info-stealer-malware-distributed-via-malvertising-on-google)

## 本地指纹情报
本地情报库命中 `ssl_sha1` 指标 `0a95355a64c3fe3f52695f97595037481ca11c4d`，关联家族为 `Vidar`，来源 `SSLBL`。
该记录最近更新时间为 2026-03-27T07:35:42。

## 相关情报参考
- [Vidar (Malware Family)](https://malpedia.caad.fkie.fraunhofer.de/details/win.vidar)：Malpedia 将 `Vidar` 描述为已知恶意软件家族，并提供了相应家族背景信息。
- [infected with vidar infostealer : r/antivirus](https://www.reddit.com/r/antivirus/comments/1pgmyi3/infected_with_vidar_infostealer/)：社区讨论中提到了与 `Vidar` 相关的感染或处置经历，仅适合作为低权重参考。
- [Hacked sites deliver Vidar infostealer to Windows users](https://www.malwarebytes.com/blog/threat-intel/2026/03/hacked-sites-deliver-vidar-infostealer-to-windows-users)：Malwarebytes 的检测页面将相关样本归入 `Vidar` 并给出简要说明。

## 处置建议
- [HIGH] 排查并视情况隔离源主机 10.10.14.9。 理由：源主机产生了命中后恶意流量，需要确认是否存在持续外联或二次投递行为。
- [HIGH] 在边界侧监控或阻断与 198.51.100.88 相关的后续通信。 理由：当前告警中的网络目的地址是最直接的外联对象，应优先纳入监测范围。
- [MEDIUM] 基于 SSL_SHA1 指纹 0a95355a64c3fe3f52695f97595037481ca11c4d 在历史流量中做横向检索。 理由：可以快速判断是否存在相同指纹的历史通信或更多受影响资产。
- [MEDIUM] 结合 Vidar 相关 TTP 做主机侧排查与 IOC 扩线。 理由：已有家族线索时，可以更有针对性地检查样本行为、持久化方式和额外外联特征。

## 参考链接
- 本地指纹情报命中
  摘要：本地情报库将 ssl_sha1 0a95355a64c3fe3f52695f97595037481ca11c4d 关联到家族/标签 Vidar，来源 SSLBL。
- [infected with vidar infostealer : r/antivirus](https://www.reddit.com/r/antivirus/comments/1pgmyi3/infected_with_vidar_infostealer/)
  摘要：社区讨论中提到了与 `Vidar` 相关的感染或处置经历，仅适合作为低权重参考。
- [Vidar (Malware Family)](https://malpedia.caad.fkie.fraunhofer.de/details/win.vidar)
  摘要：Malpedia 将 `Vidar` 描述为已知恶意软件家族，并提供了相应家族背景信息。
- [Hacked sites deliver Vidar infostealer to Windows users](https://www.malwarebytes.com/blog/threat-intel/2026/03/hacked-sites-deliver-vidar-infostealer-to-windows-users)
  摘要：Malwarebytes 的检测页面将相关样本归入 `Vidar` 并给出简要说明。
- [How Vidar Malware Spreads via Malvertising on Google](https://www.darktrace.com/blog/vidar-info-stealer-malware-distributed-via-malvertising-on-google)
  摘要：该来源页面《How Vidar Malware Spreads via Malvertising on Google》提到了与 `Vidar` 或指标 `0a95355a64c3fe3f52695f97595037481ca11c4d` 相关的信息：Discover how Vidar info stealer malware is distributed through malvertising on Google and the ris...
- [Vidar Stealer 2.0 Exploits Fake Game Cheats on GitHub, ...](https://www.infosecurity-magazine.com/news/vidar-stealer-exploits-github/)
  摘要：该资讯文章提到了与 `Vidar` 相关的最新攻击活动或传播方式。
