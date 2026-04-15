# 网络安全事件分析报告

## 事件概述
- 事件时间：2026-03-20 10:00:00
- 通信关系：`194.226.121.108` -> `44.33.22.11`
- 协议：HTTP
- 命中指标：IP `194.226.121.108`
- 当前研判：discordgrabber
- 置信度：77
- 严重度：中危

## 研判结论
在 2026-03-20 10:00:00，检测到 194.226.121.108 与 44.33.22.11 之间存在 HTTP 流量，该流量命中 IP 指标 `194.226.121.108`。

当前家族线索主要来自告警附带标签和外部情报，现阶段更倾向于将该事件关联到 `discordgrabber`。

## 归因依据
当前归因结果为 `discordgrabber`，置信度为 77。 主依据来自 `家族背景情报`。 另有 `maltrail-static` 提供补充支持。 当前家族判断主要依赖外部情报线索 `discordgrabber`。

本次事件涉及一个名为TroubleGrabber的新类型凭证窃取器，通过Discord附件进行传播，并利用Discord消息将窃取到的凭证发送给攻击者。IP地址194.226.121.108的信誉评分为高度可疑，进一步支持了该威胁的存在。

## 事件直接证据
### Stealing Credentials Through Discord
来源：netskope.com
证据等级：中
`Stealing Credentials Through Discord` 的正文对 `discordgrabber` 给出了更完整的能力画像：TroubleGrabber is a new credential stealer distributed via Discord attachments and communicates stolen credentials back to attackers using Discord messages. 从页面正文能直接抽出的关键技术点包括：TroubleGrabber is distributed through Discord attachments.；Stolen credentials are communicated back to attackers via Discord messages.。 就当前告警而言，The alert is relevant as it identifies a new threat vector involving the distribution of a credential stealer through Discord. 从研判与处置角度看，这类正文型来源能够帮助我们把“命中某个家族”进一步展开为“该家族通常如何传播、落地后会做什么、后续还该排查哪些痕迹”，因此比单纯标签更有分析价值。
参考：[https://www.netskope.com/blog/here-comes-troublegrabber-stealing-credentials-through-discord](https://www.netskope.com/blog/here-comes-troublegrabber-stealing-credentials-through-discord)

### VirusTotal IP 富化
来源：VirusTotal
证据等级：中
VirusTotal 提供的 IP 地址 194.226.121.108 的信誉报告显示该 IP 具有较高的恶意评分（12 次恶意检测），进一步证实了该 IP 地址与恶意活动相关联。这些信息有助于确认当前告警的有效性。
参考：[https://www.virustotal.com/gui/ip-address/194.226.121.108](https://www.virustotal.com/gui/ip-address/194.226.121.108)

## 处置建议
### 基础响应
- [HIGH] 排查并视情况隔离源主机 194.226.121.108。 理由：源主机产生了命中后恶意流量，需要确认是否存在持续外联或二次投递行为。
- [HIGH] 在边界侧监控或阻断与 44.33.22.11 相关的后续通信。 理由：当前告警中的网络目的地址是最直接的外联对象，应优先纳入监测范围。
- [MEDIUM] 基于 IP 指纹 194.226.121.108 在历史流量中做横向检索。 理由：可以快速判断是否存在相同指纹的历史通信或更多受影响资产。
- [MEDIUM] 结合 discordgrabber 相关 TTP 做主机侧排查与 IOC 扩线。 理由：已有家族线索时，可以更有针对性地检查样本行为、持久化方式和额外外联特征。

### 建议追加的威胁猎捕动作
- 围绕浏览器凭据、Cookie、钱包插件和本地敏感配置文件开展主机侧排查，确认是否存在信息窃取后的残留痕迹。
