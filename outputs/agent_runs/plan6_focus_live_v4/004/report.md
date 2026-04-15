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

当前事件涉及Vidar恶意软件家族，通过TLS通信中的SSL证书指纹（SSL_SHA1 0a95355a64c3fe3f52695f97595037481ca11c4d）关联到该家族。Vidar是一种从Arkei派生出的信息窃取器，能够窃取双因素认证软件和Tor浏览器中的信息。其传播方式包括Google搜索广告和恶意广告。此外，Vidar还常通过钓鱼邮件或假冒合法软件的下载来分发。

## 事件直接证据
### 本地指纹情报命中
来源：SSLBL
证据等级：高
本地情报库 `SSLBL` 直接将当前命中的 SSL_SHA1 指标 `0a95355a64c3fe3f52695f97595037481ca11c4d` 关联到 `Vidar`，这不是泛化的家族背景描述，而是直接落在本次告警触发项上的结构化命中，因此应视为本轮归因的核心证据。 该记录最近更新时间为 2026-03-27T07:35:42，说明这条映射并非孤立的历史残留，仍可以作为当前事件研判的高权重依据。 这意味着当前告警并不是仅凭标题或模糊标签做出的猜测，而是已经拿到了可以与历史情报库稳定对应的指纹线索，因此后续外部页面证据的主要作用是补充 `Vidar` 的能力画像和行为细节，而不是替代这条直接映射。 从落地排查角度看，可以优先围绕 `0a95355a64c3fe3f52695f97595037481ca11c4d` 做历史流量横向检索，确认是否存在同指纹复用、持续外联或多资产同时命中的情况。
参考：[https://sslbl.abuse.ch/ssl-certificates/sha1/0a95355a64c3fe3f52695f97595037481ca11c4d/](https://sslbl.abuse.ch/ssl-certificates/sha1/0a95355a64c3fe3f52695f97595037481ca11c4d/)

### Vidar (Malware Family)
来源：malpedia.caad.fkie.fraunhofer.de
证据等级：中
Vidar是一种从Arkei派生出的恶意软件，以其能够窃取双因素认证软件和Tor浏览器中的信息而闻名。其传播方式包括Google搜索广告和恶意广告。这些技术细节有助于理解Vidar的行为模式和传播机制，从而更好地识别和防御此类威胁。当前事件中出现的TLS通信可能正是通过这些途径进行的，这为当前告警提供了关键的技术依据。
参考：[https://malpedia.caad.fkie.fraunhofer.de/details/win.vidar](https://malpedia.caad.fkie.fraunhofer.de/details/win.vidar)

### What is Vidar Malware?
来源：checkpoint.com
证据等级：中
Vidar是一种信息窃取器，能够用于分发其他形式的恶意软件。它通常通过钓鱼邮件或假冒合法软件的下载来传播。这些传播方式对员工培训具有重要意义，有助于提高员工对潜在威胁的认识。虽然这条证据主要提供背景信息，但它对于理解和预防Vidar的传播方式仍然具有重要价值。
参考：[https://www.checkpoint.com/cyber-hub/threat-prevention/what-is-malware/what-is-vidar-malware/](https://www.checkpoint.com/cyber-hub/threat-prevention/what-is-malware/what-is-vidar-malware/)

## 家族背景与补充参考
### Vidar Stealer 2.0 distributed via fake game cheats on ...
来源：acronis.com
证据等级：中
Vidar Stealer 2.0通过假游戏作弊工具在GitHub和Reddit上传播。该恶意软件能够提取多种敏感信息，包括浏览器凭证、Azure令牌等。这些信息有助于理解当前事件中使用的恶意软件及其传播方式。
参考：[https://www.acronis.com/en/tru/posts/vidar-stealer-20-distributed-via-fake-game-cheats-on-github-and-reddit/](https://www.acronis.com/en/tru/posts/vidar-stealer-20-distributed-via-fake-game-cheats-on-github-and-reddit/)

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
