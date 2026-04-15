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

本次事件涉及Vidar恶意软件家族，其通过多种传播方式如钓鱼邮件和恶意广告进行扩散，并具备窃取敏感数据的能力，包括登录凭证和加密货币钱包信息。本地情报库中的SSL证书SHA1与Vidar相关联，进一步确认了这一判断。

## 事件直接证据
### 本地指纹情报命中
来源：SSLBL
证据等级：高
本地情报库将SSL证书SHA1 0a95355a64c3fe3f52695f97595037481ca11c4d关联到Vidar家族，这表明该证书可能被用于恶意活动，从而支持了当前事件的归因判断。
参考：[https://sslbl.abuse.ch/ssl-certificates/sha1/0a95355a64c3fe3f52695f97595037481ca11c4d/](https://sslbl.abuse.ch/ssl-certificates/sha1/0a95355a64c3fe3f52695f97595037481ca11c4d/)

### Vidar (Malware Family)
来源：malpedia.caad.fkie.fraunhofer.de
证据等级：中
Vidar是一种基于Arkei的恶意软件，能够从2FA软件和Tor浏览器中窃取信息，其传播方式包括Google搜索广告和恶意广告，这与当前事件中发现的传播方式相符。
参考：[https://malpedia.caad.fkie.fraunhofer.de/details/win.vidar](https://malpedia.caad.fkie.fraunhofer.de/details/win.vidar)

### What is Vidar Malware?
来源：checkpoint.com
证据等级：中
Vidar作为信息窃取者，可通过钓鱼邮件或假冒合法软件的下载来传播，这些传播方式在当前事件中得到了验证，进一步证实了恶意软件的身份。
参考：[https://www.checkpoint.com/cyber-hub/threat-prevention/what-is-malware/what-is-vidar-malware/](https://www.checkpoint.com/cyber-hub/threat-prevention/what-is-malware/what-is-vidar-malware/)

### Vidar Malware: Analysis, Detection, Removal
来源：huntress.com
证据等级：中
Vidar恶意软件专门针对敏感数据，如登录凭证和加密货币钱包信息进行窃取，其传播途径包括钓鱼邮件和捆绑软件下载，这些信息有助于识别当前事件中的攻击手段。
参考：[https://www.huntress.com/threat-library/malware/vidar](https://www.huntress.com/threat-library/malware/vidar)

## 家族背景与补充参考
### Don't Be Fooled Into Downloading Vidar | Latest Alerts and ...
来源：cyber.nj.gov
证据等级：中
新泽西州网络协调中心（NJCCIC）观察到越来越多的攻击在分发Vidar Stealer。Vidar作为恶意软件即服务（MaaS），在攻击中扮演着重要角色。这表明Vidar的使用正在增加，并可能成为未来攻击的主要威胁源。
参考：[https://www.cyber.nj.gov/Home/Components/News/News/2002/214](https://www.cyber.nj.gov/Home/Components/News/News/2002/214)

### Hacked sites deliver Vidar infostealer to Windows users
来源：malwarebytes.com
证据等级：中
Vidar加载在内存中并通过与远程命令服务器通信，能够悄悄地收集和外泄数据，而不会显示出明显的感染迹象。研究人员最近检测到一个利用多个不同感染链最终交付Vidar的信息窃取器的活动。这种隐蔽的传播方式使得Vidar成为难以发现的威胁。
参考：[https://www.malwarebytes.com/blog/threat-intel/2026/03/hacked-sites-deliver-vidar-infostealer-to-windows-users](https://www.malwarebytes.com/blog/threat-intel/2026/03/hacked-sites-deliver-vidar-infostealer-to-windows-users)

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
