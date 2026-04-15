# 网络安全事件分析报告

## 事件概述
- 事件时间：2026-03-29 15:05:00
- 通信关系：`10.10.14.33` -> `203.0.113.19`
- 协议：TLS
- 命中指标：SSL_SHA1 `01fca6410fefef1530ac71c5e34d6985a6e23643`
- 当前研判：QuasarRAT
- 置信度：95
- 严重度：高危

## 研判结论
在 2026-03-29 15:05:00，检测到 10.10.14.33 与 203.0.113.19 之间存在 TLS 流量，该流量命中 SSL_SHA1 指标 `01fca6410fefef1530ac71c5e34d6985a6e23643`。

结合本地指纹情报与外部公开情报，当前将该事件关联到 `QuasarRAT` 的把握为较高。

## 归因依据
当前归因结果为 `QuasarRAT`，置信度为 95。 主依据来自 `SSLBL`。 另有 `SSLBL、家族背景情报` 提供补充支持。 当前主结论以本地指纹情报 `QuasarRAT` 为主，并获得外部结构化情报的补充支持。

本次事件涉及QuasarRAT家族的恶意软件活动。本地指纹情报命中显示了与QuasarRAT相关的SSL证书指纹，进一步验证了这一威胁。微软的安全文档详细描述了QuasarRAT的特征和技术细节，包括其使用.NET框架编码，主要通过端口4782进行通信，并具备远程访问功能。这些信息有助于我们更准确地识别和应对当前的恶意软件威胁。

## 事件直接证据
### 本地指纹情报命中
来源：SSLBL
证据等级：高
本地情报库 `SSLBL` 直接将当前命中的 SSL_SHA1 指标 `01fca6410fefef1530ac71c5e34d6985a6e23643` 关联到 `QuasarRAT`，这不是泛化的家族背景描述，而是直接落在本次告警触发项上的结构化命中，因此应视为本轮归因的核心证据。 该记录最近更新时间为 2026-03-26T07:46:12，说明这条映射并非孤立的历史残留，仍可以作为当前事件研判的高权重依据。 这意味着当前告警并不是仅凭标题或模糊标签做出的猜测，而是已经拿到了可以与历史情报库稳定对应的指纹线索，因此后续外部页面证据的主要作用是补充 `QuasarRAT` 的能力画像和行为细节，而不是替代这条直接映射。 从落地排查角度看，可以优先围绕 `01fca6410fefef1530ac71c5e34d6985a6e23643` 做历史流量横向检索，确认是否存在同指纹复用、持续外联或多资产同时命中的情况。
参考：[https://sslbl.abuse.ch/ssl-certificates/sha1/01fca6410fefef1530ac71c5e34d6985a6e23643/](https://sslbl.abuse.ch/ssl-certificates/sha1/01fca6410fefef1530ac71c5e34d6985a6e23643/)

### Backdoor:Win32/QuasarRAT.A threat description
来源：microsoft.com
证据等级：中
Backdoor:Win32/QuasarRAT.A 是一个基于 .NET 的开源远程管理工具，用 C# 编写。感染此恶意软件的设备可能会出现可疑的端口 4782 连接（默认端口，但可能更改）。该威胁行为包括访问任务管理器、创建远程 shell 和监控 TCP 连接等。这些特征与当前告警中的 QuasarRAT 家族一致，表明可能存在 QuasarRAT 活动。
参考：[https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Backdoor:Win32/QuasarRAT.A](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Backdoor:Win32/QuasarRAT.A)

### Quasar RAT (Malware Family)
来源：malpedia.caad.fkie.fraunhofer.de
证据等级：中
Malpedia提供的QuasarRAT相关信息指出，该恶意软件可以通过PowerShell解码和.NET C2提取来分析。此外，QuasarRAT与其他恶意软件如AsyncRAT有相关联，这表明QuasarRAT可能与其他威胁活动有关。这些信息虽然不直接支持当前事件，但提供了QuasarRAT的更多背景知识，有助于全面了解其威胁行为。
参考：[https://malpedia.caad.fkie.fraunhofer.de/details/win.quasar_rat](https://malpedia.caad.fkie.fraunhofer.de/details/win.quasar_rat)

## 处置建议
### 基础响应
- [HIGH] 排查并视情况隔离源主机 10.10.14.33。 理由：源主机产生了命中后恶意流量，需要确认是否存在持续外联或二次投递行为。
- [HIGH] 在边界侧监控或阻断与 203.0.113.19 相关的后续通信。 理由：当前告警中的网络目的地址是最直接的外联对象，应优先纳入监测范围。
- [MEDIUM] 基于 SSL_SHA1 指纹 01fca6410fefef1530ac71c5e34d6985a6e23643 在历史流量中做横向检索。 理由：可以快速判断是否存在相同指纹的历史通信或更多受影响资产。
- [MEDIUM] 结合 QuasarRAT 相关 TTP 做主机侧排查与 IOC 扩线。 理由：已有家族线索时，可以更有针对性地检查样本行为、持久化方式和额外外联特征。

### 建议追加的威胁猎捕动作
- 回溯受害主机近期 Web 访问、下载链和跳转链路，重点排查恶意广告、伪造 CAPTCHA 页面、被入侵站点或第三方托管下载源。
- 基于当前外联目标、同证书指纹或同类 TLS 特征继续扩线，排查是否存在持续 C2 通信或其他受影响资产。
- 在历史流量中进一步检索相同 SSL_SHA1 指标 `01fca6410fefef1530ac71c5e34d6985a6e23643`，确认是否存在横向复用、批量投递或多资产命中。
