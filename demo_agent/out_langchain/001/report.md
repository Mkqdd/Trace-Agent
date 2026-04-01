# 网络安全事件报告

## 事件概述

在 2026 年 3 月 20 日 10:00:00，观察到了来自 IP 地址 `194.226.121.108` 到 IP 地址 `44.33.22.11` 的 HTTP 流量。此 IP 地址命中了已知的恶意 IP 指纹，且与 `discordgrabber` 家族相关。

## 研判结论

根据外部情报和本地告警，初步判断该事件与 `discordgrabber` 家族相关，存在可疑的恶意活动。当前置信度为 65%，严重程度为中危。

## 关键证据与情报

### 证据 1
**来源**: 告警事件  
**描述**: 在 2026 年 3 月 20 日 10:00:00 观察到 `194.226.121.108` 到 `44.33.22.11` 的 HTTP 流量，命中 IP 指纹 `194.226.121.108`。  
**权重**: 高  
**依据**: 原始告警事实  

### 证据 2
**来源**: VirusTotal  
**描述**: VirusTotal 返回 IP `194.226.121.108` 的信誉/归属信息。分析统计结果为 {'恶意': 12, '可疑': 1, '未检测到': 33, '无害': 48, '超时': 0}。  
**权重**: 中  
**依据**: 结构化信誉情报  

### 证据 3
**来源**: 告警附带家族提示  
**描述**: 原始告警将该事件关联到家族/标签 `discordgrabber`。  
**权重**: 中  
**依据**: 本地静态情报命中  

### 证据 4
**来源**: any.run  
**描述**: 在线沙箱报告指出 `DiscordGrabber.exe` 被标记为窃取者，Python 编写的恶意软件，最终判断为恶意活动。  
**权重**: 低  
**依据**: 一般网页来源 any.run  

## 家族/威胁背景

`discordgrabber` 是一个针对 Discord 用户的恶意软件家族，通过窃取用户的登录凭证、系统信息和其他数据来实施攻击。该家族经常利用 Discord 的消息功能来进行隐蔽的 C2 通信。

## 处置建议

1. **排查并视情况隔离源主机 `194.226.121.108`**。  
   **理由**: 源主机产生了命中后的恶意流量，需确认是否存在持续外联或二次投递行为。

2. **在边界侧监控或阻断与 `44.33.22.11` 相关的后续通信**。  
   **理由**: 当前告警中的网络目的地址是最直接的外联对象，应优先纳入监测范围。

3. **基于 IP 指纹 `194.226.121.108` 在历史流量中做横向检索**。  
   **理由**: 可以快速判断是否存在相同指纹的历史通信或更多受影响资产。

4. **结合 `discordgrabber` 相关 TTP 做主机侧排查与 IOC 扩线**。  
   **理由**: 已有家族线索时，可以更有针对性地检查样本行为、持久化方式和额外外联特征。

## 参考链接

- [Malware analysis DiscordGrabber.exe Malicious activity](https://any.run/report/f10a16a6aa1909a98ad1664fdab9d966fbbbaec518f8e2228d2dad98d4e16161/8c5b369f-e726-4366-80b4-54d0ba99da01)
- [Artstation Scam and Discord Token Grabber “BLENDERX” ...](https://www.reddit.com/r/blender/comments/1ojqlea/warning_artstation_scam_and_discord_token_grabber/)
- [Discord warns users about new malware called ...](https://proprivacy.com/privacy-news/discord-users-warned-of-troublegrabber-malware)
- [Stealing Credentials Through Discord](https://infocon.org/mirrors/vx%20underground%20-%202025%20June/Papers/Malware%20Defense/Malware%20Analysis/2020/2020-11-13%20-%20Here%20Comes%20TroubleGrabber-%20Stealing%20Credentials%20Through%20Discord.pdf)
- [Help with a Discord token grabber! : r/techsupport](https://www.reddit.com/r/techsupport/comments/112dihe/help_with_a_discord_token_grabber/)