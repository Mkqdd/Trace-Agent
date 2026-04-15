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

本次事件涉及到了Vidar恶意软件家族，并通过多个来源验证了其活动。本地情报库和多个安全厂商的信息均表明Vidar具有窃取用户信息的能力，并且通过多种手段进行传播和隐藏。

## 事件直接证据
### 本地指纹情报命中
来源：SSLBL
证据等级：高
本地情报库将SSL证书的SHA1哈希值与Vidar恶意软件家族关联起来，这表明此次通信中使用的SSL证书属于已知的恶意软件相关证书。这种关联有助于确认此次事件中的恶意软件身份。
参考：[https://sslbl.abuse.ch/ssl-certificates/sha1/0a95355a64c3fe3f52695f97595037481ca11c4d/](https://sslbl.abuse.ch/ssl-certificates/sha1/0a95355a64c3fe3f52695f97595037481ca11c4d/)

### Vidar Malware: Analysis, Detection, Removal
来源：huntress.com
证据等级：中
Huntress提供的文档详细介绍了Vidar恶意软件的分析、检测和移除方法，强调了该恶意软件可以通过单个控制面板进行实时保护部署和管理。这些信息有助于进一步了解Vidar的特性及其防护措施。
参考：[https://www.huntress.com/threat-library/malware/vidar](https://www.huntress.com/threat-library/malware/vidar)

### What is Vidar Malware?
来源：checkpoint.com
证据等级：中
Check Point的报告指出，Vidar是全球第四大常见的信息窃取型恶意软件。这一统计数据揭示了Vidar在全球范围内的广泛影响及其对用户的潜在威胁。
参考：[https://www.checkpoint.com/cyber-hub/threat-prevention/what-is-malware/what-is-vidar-malware/](https://www.checkpoint.com/cyber-hub/threat-prevention/what-is-malware/what-is-vidar-malware/)

### Hacked sites deliver Vidar infostealer to Windows users
来源：malwarebytes.com
证据等级：中
Malwarebytes的报道描述了Vidar恶意软件通过被黑网站向Windows用户传播的过程，包括HTA脚本和MSI安装程序等隐蔽手段。这些技术细节揭示了Vidar的传播机制和隐蔽策略。
参考：[https://www.malwarebytes.com/blog/threat-intel/2026/03/hacked-sites-deliver-vidar-infostealer-to-windows-users](https://www.malwarebytes.com/blog/threat-intel/2026/03/hacked-sites-deliver-vidar-infostealer-to-windows-users)

## 家族背景与补充参考
### Don't Be Fooled Into Downloading Vidar | Latest Alerts and ...
来源：cyber.nj.gov
证据等级：中
新泽西州网络犯罪调查中心（NJCCIC）观察到Vidar Stealer攻击有所增加，该恶意软件作为Malware-as-a-Service（MaaS）进行分发。这表明Vidar Stealer正在广泛传播，并可能影响多个受害者。
参考：[https://www.cyber.nj.gov/Home/Components/News/News/2002/214](https://www.cyber.nj.gov/Home/Components/News/News/2002/214)

### Vidar Stealer 2.0 Exploits Fake Game Cheats on GitHub, ...
来源：infosecurity-magazine.com
证据等级：低
Vidar Stealer 2.0利用GitHub上的虚假游戏作弊工具进行传播，这些工具实际上包含恶意软件。这种传播方式使得恶意软件能够迅速扩散并感染大量用户。
参考：[https://www.infosecurity-magazine.com/news/vidar-stealer-exploits-github/](https://www.infosecurity-magazine.com/news/vidar-stealer-exploits-github/)

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
