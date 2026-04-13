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

VirusTotal 提供了关于恶意 IP 地址的详细信誉信息。该 IP 地址与多个恶意软件样本相关联，表明其可能被用于恶意活动。此外，VirusTotal 还提供了关于该 IP 地址的归属信息，这有助于进一步了解该 IP 地址的背景和潜在用途。总之，VirusTotal 提供的信誉信息和归属信息对于了解该 IP 地址的潜在恶意用途以及进一步采取适当的防护措施具有重要意义。

## 事件直接证据
### VirusTotal IP 富化
来源：VirusTotal
证据等级：中
VirusTotal 提供了关于恶意 IP 地址的详细信誉信息。该 IP 地址与多个恶意软件样本相关联，表明其可能被用于恶意活动。此外，VirusTotal 还提供了关于该 IP 地址的归属信息，这有助于进一步了解该 IP 地址的背景和潜在用途。总之，VirusTotal 提供的信誉信息和归属信息对于了解该 IP 地址的潜在恶意用途以及进一步采取适当的防护措施具有重要意义。
参考：[https://www.virustotal.com/gui/ip-address/194.226.121.108](https://www.virustotal.com/gui/ip-address/194.226.121.108)

### Stealing Credentials Through Discord
来源：netskope.com
证据等级：中
TroubleGrabber 是一种新的凭证窃取器，正在通过 Discord 附件进行传播，并使用 Discord 消息将被盗的凭证发送回。这种新型的凭证窃取器利用了 Discord 平台的流行性和社交属性，使得它能够更容易地传播并获取用户的敏感信息。因此，用户在使用 Discord 平台时应该保持警惕，避免随意下载和打开可疑的附件，以减少被 TroubleGrabber 等恶意软件攻击的风险。总之，TroubleGrabber 利用 Discord 附件和消息进行传播和窃取凭证，这提醒我们在使用 Discord 平台时要保持警惕，避免被恶意软件攻击。
参考：[https://www.netskope.com/blog/here-comes-troublegrabber-stealing-credentials-through-discord](https://www.netskope.com/blog/here-comes-troublegrabber-stealing-credentials-through-discord)

### Using Discord infrastructure for malicious intent
来源：blog.checkpoint.com
证据等级：中
Check Point Research (CPR) 发现了一种多功能性恶意软件，名为 TroubleGrabber，它具有通过 Discord 附件和消息进行传播和窃取凭证的能力。这种新型的凭证窃取器利用了 Discord 平台的流行性和社交属性，使得它能够更容易地传播并获取用户的敏感信息。因此，用户在使用 Discord 平台时应该保持警惕，避免随意下载和打开可疑的附件，以减少被 TroubleGrabber 等恶意软件攻击的风险。总之，TroubleGrabber 利用 Discord 附件和消息进行传播和窃取凭证，这提醒我们在使用 Discord 平台时要保持警惕，避免被恶意软件攻击。
参考：[https://blog.checkpoint.com/security/using-discord-infrastructure-for-malicious-intent/](https://blog.checkpoint.com/security/using-discord-infrastructure-for-malicious-intent/)

## 处置建议
### 基础响应
- [HIGH] 排查并视情况隔离源主机 194.226.121.108。 理由：源主机产生了命中后恶意流量，需要确认是否存在持续外联或二次投递行为。
- [HIGH] 在边界侧监控或阻断与 44.33.22.11 相关的后续通信。 理由：当前告警中的网络目的地址是最直接的外联对象，应优先纳入监测范围。
- [MEDIUM] 基于 IP 指纹 194.226.121.108 在历史流量中做横向检索。 理由：可以快速判断是否存在相同指纹的历史通信或更多受影响资产。
- [MEDIUM] 结合 discordgrabber 相关 TTP 做主机侧排查与 IOC 扩线。 理由：已有家族线索时，可以更有针对性地检查样本行为、持久化方式和额外外联特征。

### 建议追加的威胁猎捕动作
- 围绕浏览器凭据、Cookie、钱包插件和本地敏感配置文件开展主机侧排查，确认是否存在信息窃取后的残留痕迹。
