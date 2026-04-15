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

综合多个情报源的信息，确认了此次事件中的恶意软件家族为QuasarRAT，并通过SSL证书指纹和相关威胁描述进行了进一步验证。QuasarRAT是一种复杂的后门恶意软件，具有多种传播和控制手段。

## 事件直接证据
### 本地指纹情报命中
来源：SSLBL
证据等级：高
本地情报库将SSL证书的SHA1指纹01fca6410fefef1530ac71c5e34d6985a6e23643关联到了QuasarRAT家族，这表明该证书与QuasarRAT有关联，支持了当前事件的归因判断。
参考：[https://sslbl.abuse.ch/ssl-certificates/sha1/01fca6410fefef1530ac71c5e34d6985a6e23643/](https://sslbl.abuse.ch/ssl-certificates/sha1/01fca6410fefef1530ac71c5e34d6985a6e23643/)

### Malware QuasarRAT - SSLBL
来源：sslbl.abuse.ch
证据等级：中
SSLBL数据库显示，QuasarRAT家族自2019年1月3日首次出现以来，使用特定的SSL证书指纹进行通信。这些指纹被用于识别QuasarRAT的C&C服务器，从而帮助确认了此次事件中的恶意软件家族。
参考：[https://sslbl.abuse.ch/ssl-certificates/signature/QuasarRAT/](https://sslbl.abuse.ch/ssl-certificates/signature/QuasarRAT/)

### Backdoor:Win32/QuasarRAT.A threat description
来源：microsoft.com
证据等级：中
微软的安全更新建议指出，及时安装针对指定漏洞的安全补丁可以有效防止QuasarRAT等恶意软件的攻击。这提示我们，保持系统和应用程序的最新安全更新是防御此类威胁的重要措施。
参考：[https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Backdoor:Win32/QuasarRAT.A](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Backdoor:Win32/QuasarRAT.A)

### Quasar RAT (Malware Family)
来源：malpedia.caad.fkie.fraunhofer.de
证据等级：中
Malpedia数据库提供了关于QuasarRAT的详细信息，包括其别名如CinaRAT和Yggdrasil，以及相关的APT组织如APT33。这些信息有助于确认QuasarRAT的复杂性和潜在的攻击者背景。
参考：[https://malpedia.caad.fkie.fraunhofer.de/details/win.quasar_rat](https://malpedia.caad.fkie.fraunhofer.de/details/win.quasar_rat)

## 家族背景与补充参考
### Backdoor.Quasar
来源：malwarebytes.com
证据等级：中
Backdoor.Quasar 是一款轻量级且公开可用的开源远程访问木马（RAT），主要针对 Windows 系统。这表明 QuasarRAT 的开源性质使其容易被滥用，支持当前事件中的恶意活动判断。
参考：[https://www.malwarebytes.com/blog/detections/backdoor-quasar](https://www.malwarebytes.com/blog/detections/backdoor-quasar)

### QuasarRAT Malware Analysis Report | by psy_maestro
来源：medium.com
证据等级：中
QuasarRAT 虽然是一种开源的远程访问工具/木马，但其合法用途如远程访问计算机也被利用于恶意行为。这进一步验证了当前事件中 QuasarRAT 的恶意使用情况。
参考：[https://medium.com/@psy_maestro/quasarrat-malware-analysis-report-8202c47729b3](https://medium.com/@psy_maestro/quasarrat-malware-analysis-report-8202c47729b3)

## 处置建议
### 基础响应
- [HIGH] 排查并视情况隔离源主机 10.10.14.33。 理由：源主机产生了命中后恶意流量，需要确认是否存在持续外联或二次投递行为。
- [HIGH] 在边界侧监控或阻断与 203.0.113.19 相关的后续通信。 理由：当前告警中的网络目的地址是最直接的外联对象，应优先纳入监测范围。
- [MEDIUM] 基于 SSL_SHA1 指纹 01fca6410fefef1530ac71c5e34d6985a6e23643 在历史流量中做横向检索。 理由：可以快速判断是否存在相同指纹的历史通信或更多受影响资产。
- [MEDIUM] 结合 QuasarRAT 相关 TTP 做主机侧排查与 IOC 扩线。 理由：已有家族线索时，可以更有针对性地检查样本行为、持久化方式和额外外联特征。

### 建议追加的威胁猎捕动作
- 围绕浏览器凭据、Cookie、钱包插件和本地敏感配置文件开展主机侧排查，确认是否存在信息窃取后的残留痕迹。
- 基于当前外联目标、同证书指纹或同类 TLS 特征继续扩线，排查是否存在持续 C2 通信或其他受影响资产。
- 在历史流量中进一步检索相同 SSL_SHA1 指标 `01fca6410fefef1530ac71c5e34d6985a6e23643`，确认是否存在横向复用、批量投递或多资产命中。
