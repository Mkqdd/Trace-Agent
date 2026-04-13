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

## 归因依据
当前归因结果为 `Vidar`，置信度为 95。 主依据来自 `SSLBL`。 另有 `SSLBL、家族背景情报` 提供补充支持。 当前主结论以本地指纹情报 `Vidar` 为主，并获得外部结构化情报的补充支持。

当前事件中，Vidar家族的恶意软件被检测到。该家族的信息窃取行为主要针对密码、信用卡信息和加密货币等敏感数据。此外，Vidar还特别关注双因素认证（2FA）软件和Tor浏览器的数据收集。当前事件中的证据包括本地指纹情报命中、关于Vidar家族的信息和检测方法以及该家族的详细技术分析。这些证据共同揭示了当前事件中Vidar家族的活动情况及其潜在威胁。

## 事件直接证据
### 本地指纹情报命中
来源：SSLBL
证据等级：高
本地情报库将 ssl_sha1 0a95355a64c3fe3f52695f97595037481ca11c4d 关联到家族/标签 Vidar，来源 SSLBL。这表明Vidar家族的恶意软件正在使用该SSL证书进行通信。这一发现有助于进一步了解Vidar家族的技术特征和活动模式。
参考：[https://sslbl.abuse.ch/ssl-certificates/sha1/0a95355a64c3fe3f52695f97595037481ca11c4d/](https://sslbl.abuse.ch/ssl-certificates/sha1/0a95355a64c3fe3f52695f97595037481ca11c4d/)

### Vidar Malware: Analysis, Detection, Removal
来源：huntress.com
证据等级：中
Vidar malware是信息盗窃木马，旨在外泄敏感数据，如密码、信用卡信息和加密货币。该恶意软件特别关注双因素认证（2FA）软件和Tor浏览器的数据收集。这些信息有助于进一步了解Vidar家族的技术特征和活动模式。
参考：[https://www.huntress.com/threat-library/malware/vidar](https://www.huntress.com/threat-library/malware/vidar)

### What is Vidar Malware?
来源：checkpoint.com
证据等级：中
Vidar是一种信息盗窃恶意软件，作为恶意软件即服务（MaaS）运营。该恶意软件首次于2018年底在野外被发现。Vidar的主要目标是窃取敏感数据，包括密码、信用卡信息和加密货币等。该恶意软件还特别关注双因素认证（2FA）软件和Tor浏览器的数据收集。这些信息有助于进一步了解Vidar家族的技术特征和活动模式。
参考：[https://www.checkpoint.com/cyber-hub/threat-prevention/what-is-malware/what-is-vidar-malware/](https://www.checkpoint.com/cyber-hub/threat-prevention/what-is-malware/what-is-vidar-malware/)

### Vidar (Malware Family)
来源：malpedia.caad.fkie.fraunhofer.de
证据等级：中
Vidar是一个基于Arkei的分叉恶意软件。它似乎是第一个能够抓取2FA软件和Tor浏览器相关信息的窃密器。这些信息有助于进一步了解Vidar家族的技术特征和活动模式。
参考：[https://malpedia.caad.fkie.fraunhofer.de/details/win.vidar](https://malpedia.caad.fkie.fraunhofer.de/details/win.vidar)

## 家族背景与补充参考
### Hacked sites deliver Vidar infostealer to Windows users
来源：malwarebytes.com
证据等级：中
Vidar 恶意软件通过被黑网站和恶意 SSL 证书进行分发，主要针对 Windows 用户。
参考：[https://www.malwarebytes.com/blog/threat-intel/2026/03/hacked-sites-deliver-vidar-infostealer-to-windows-users](https://www.malwarebytes.com/blog/threat-intel/2026/03/hacked-sites-deliver-vidar-infostealer-to-windows-users)

### Malicious SSL Certificates
来源：sslbl.abuse.ch
证据等级：中
Vidar 恶意软件通过被黑网站和恶意 SSL 证书进行分发，主要针对 Windows 用户。
参考：[https://sslbl.abuse.ch/ssl-certificates/](https://sslbl.abuse.ch/ssl-certificates/)

## 处置建议
### 基础响应
- [HIGH] 排查并视情况隔离源主机 10.10.14.9。 理由：源主机产生了命中后恶意流量，需要确认是否存在持续外联或二次投递行为。
- [HIGH] 在边界侧监控或阻断与 198.51.100.88 相关的后续通信。 理由：当前告警中的网络目的地址是最直接的外联对象，应优先纳入监测范围。
- [MEDIUM] 基于 SSL_SHA1 指纹 0a95355a64c3fe3f52695f97595037481ca11c4d 在历史流量中做横向检索。 理由：可以快速判断是否存在相同指纹的历史通信或更多受影响资产。
- [MEDIUM] 结合 Vidar 相关 TTP 做主机侧排查与 IOC 扩线。 理由：已有家族线索时，可以更有针对性地检查样本行为、持久化方式和额外外联特征。

### 建议追加的威胁猎捕动作
- 围绕浏览器凭据、Cookie、钱包插件和本地敏感配置文件开展主机侧排查，确认是否存在信息窃取后的残留痕迹。
- 回溯受害主机近期 Web 访问、下载链和跳转链路，重点排查恶意广告、伪造 CAPTCHA 页面、被入侵站点或第三方托管下载源。
- 基于当前外联目标、同证书指纹或同类 TLS 特征继续扩线，排查是否存在持续 C2 通信或其他受影响资产。
