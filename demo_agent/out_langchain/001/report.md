# 网络安全报告

## 研判结论

本次事件涉及一个疑似用于窃取Discord凭证和其他敏感信息的恶意软件家族。该事件被标记为低危，但需要进一步监控和调查以确认其影响范围和潜在威胁。

## 事件摘要

在2026年3月20日10:00时，检测到IP地址为194.226.121.108的主机通过HTTP协议向IP地址为44.33.22.11的外部IP发送数据包。触发了恶意软件指纹匹配，标记为`discordgrabber`。该事件被识别为与已知恶意软件家族相关联，但没有进一步的详细信息。

## 证据与情报

以下是一些关于`discordgrabber`恶意软件家族的相关情报：

- **ThreatFox | 浏览IOCs**
  - URL: [https://threatfox.abuse.ch/browse](https://threatfox.abuse.ch/browse)
  - 描述：使用此表单可以按哈希值（MD5、SHA256、SHA1）、imphash、tlsh哈希、ClamAV签名、标签或恶意软件家族搜索恶意软件样本。
  
- **MalwareBazaar | DiscordGrabber - abuse.ch**
  - URL: [https://bazaar.abuse.ch/browse/tag/DiscordGrabber/](https://bazaar.abuse.ch/browse/tag/DiscordGrabber/)
  - 描述：与标签`DiscordGrabber`相关的恶意软件样本。这些样本通常与特定的标签关联，便于导航和查询。

- **discord-malware · GitHub Topics · GitHub**
  - URL: [https://github.com/topics/discord-malware](https://github.com/topics/discord-malware)
  - 描述：一种强大的远程管理工具，利用Discord作为C2通道。

- **Here Comes TroubleGrabber: Stealing Credentials Through Discord**
  - URL: [https://www.netskope.com/blog/here-comes-troublegrabber-stealing-credentials-through-discord](https://www.netskope.com/blog/here-comes-troublegrabber-stealing-credentials-through-discord)
  - 描述：该恶意软件利用Discord和GitHub交付下一阶段的载荷，并使用Discord Webhook作为C2服务器来发送受害者的凭据。这种攻击需要具备应用层检测能力的安全解决方案，以及多种威胁检测方案、DLP和机器学习技术，以理解云和网络的语言及性质。

- **New TroubleGrabber Discord malware steals passwords, system info**
  - URL: [https://csirt.cy/en/notifications/new-troublegrabber-discord-malware-steals-passwords-system-info](https://csirt.cy/en/notifications/new-troublegrabber-discord-malware-steals-passwords-system-info)
  - 描述：该恶意软件还利用Discord Webhook与其命令控制(C2)服务器通信，并发送受害者被盗的信息。TroubleGrabber窃取包括浏览器令牌、Discord Webhook令牌、浏览器密码和系统信息在内的广泛重要信息。

## 处置建议

1. **监控和分析**：持续监控与194.226.121.108相关的活动，并对任何异常行为进行详细分析。
2. **更新防护措施**：确保所有防护措施（如防火墙规则、入侵检测系统等）都已更新并能有效应对此类恶意软件。
3. **用户教育**：加强用户对Discord和其他社交媒体平台上的钓鱼攻击的意识，提醒他们不要轻易分享敏感信息。
4. **定期扫描**：定期使用防病毒工具扫描系统，确保没有新的恶意软件感染。

以上措施有助于降低风险并保护系统的完整性。