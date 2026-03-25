# 网络安全事件分析报告

## 研判结论
本次事件为一起**真实的**（simulated=false）恶意软件活动告警。内部主机 `194.226.121.108` 通过 HTTP 协议向外部 IP `44.33.22.11` 发起了网络连接。该连接触发了基于 IP 的指纹匹配，关联到已知的恶意软件家族 **DiscordGrabber**。综合情报分析，该 IP 地址极有可能是 DiscordGrabber 或相关变种（如 TroubleGrabber）恶意软件的**命令与控制（C2）服务器**或用于窃取凭据的 Webhook 端点。事件整体评估为**低危**，但鉴于其明确的恶意软件关联性，需立即采取阻断和排查措施。

## 事件摘要
- **事件时间**：2026-03-20 10:00:00
- **源地址**：`194.226.121.108` （内部主机）
- **目的地址**：`44.33.22.11`
- **协议**：HTTP
- **触发指纹**：IP `194.226.121.108` 匹配到恶意软件特征。
- **关联恶意软件家族**：DiscordGrabber
- **数据来源**：maltrail-static 威胁情报源
- **严重等级**：低危

## 证据与情报

### 1. 原始告警与指纹匹配
- 安全设备检测到从内部主机 `194.226.121.108` 到外部地址 `44.33.22.11` 的 HTTP 流量。
- 该流量触发了基于 IP (`194.226.121.108`) 的指纹规则，匹配结果为 `true`。
- 关联的威胁情报标签为 **`discordgrabber`**，表明该 IP 地址在威胁情报库中被标记为与 DiscordGrabber 恶意软件相关。

### 2. 恶意软件家族情报分析
针对 `discordgrabber` 家族及关联 IP 的搜索，揭示了以下关键信息：

- **TroubleGrabber 恶意软件分析**：名为 “TroubleGrabber” 的恶意软件利用 Discord 和 GitHub 分发下一阶段载荷，并使用 Discord webhooks 作为 C2 服务器发送窃取的受害者凭据。此类攻击需要具备应用层检测、多重威胁检测、数据防泄漏（DLP）以及理解云和网络语言与性质的机器学习技术的安全解决方案。
  - 来源：[Here Comes TroubleGrabber: Stealing Credentials Through Discord](//duckduckgo.com/l/?uddg=https%3A%2F%2Fwww.netskope.com%2Fblog%2Fhere%2Dcomes%2Dtroublegrabber%2Dstealing%2Dcredentials%2Dthrough%2Ddiscord&amp;rut=3742f61cbb7509ac92425a6eb37b08ce55809eca0fbf7b2afd6b544fffb5288f)

- **针对 Discord 用户的新威胁**：TroubleGrabber 恶意软件具有与其他针对 Discord 游戏玩家的恶意软件（如 AnarchyGrabber）相同的功能，但似乎是不同威胁行为者的作品。该恶意软件由名为 “Itroublve” 的个人开发，目前被多个威胁行为者使用。
  - 来源：[New TroubleGrabber malware targets Discord users](//duckduckgo.com/l/?uddg=https%3A%2F%2Fsecurityaffairs.com%2F110887%2Fmalware%2Ftroublegrabber%2Ddiscord%2Dmalware.html&amp;rut=65624ca22e34fbea9df4ac6a29a095cfafecf3531fac0eecd0ad6a1e4d60ecd5)

- **恶意软件样本库关联**：在 MalwareBazaar 数据库中，存在大量被标记为 `DiscordGrabber` 的恶意软件样本，表明这是一个活跃且被广泛记录的恶意软件家族。
  - 来源：[MalwareBazaar | DiscordGrabber - abuse.ch](//duckduckgo.com/l/?uddg=https%3A%2F%2Fbazaar.abuse.ch%2Fbrowse%2Ftag%2FDiscordGrabber%2F&amp;rut=355d3ead1fd063d11d578003d55551f30d9609754ddaf733f7878d0e93e8744e)

- **窃取信息的范围**：TroubleGrabber 同样使用 Discord webhooks 与其 C2 服务器通信并发送受害者的被盗信息。它窃取广泛的重要信息，包括“网络浏览器令牌、Discord webhook 令牌、网络浏览器密码和系统信息”。
  - 来源：[New TroubleGrabber Discord malware steals passwords, system info](//duckduckgo.com/l/?uddg=https%3A%2F%2Fcsirt.cy%2Fen%2Fnotifications%2Fnew%2Dtroublegrabber%2Ddiscord%2Dmalware%2Dsteals%2Dpasswords%2Dsystem%2Dinfo&amp;rut=09c37104447d77ba1e21fe6a65631fb3d5fd0a5eeb430585f98d8b70b12056cd)

### 3. 关联图谱分析
根据提供的拓扑图，事件关联逻辑如下：
1.  内部主机 `194.226.121.108` 向外部 IP `44.33.22.11` 发起了网络流 (`network_flow`)。
2.  该主机的 IP 地址 (`194.226.121.108`) 被识别为一个恶意指纹 (`fingerprint_ip`)。
3.  此指纹以中等置信度 (`confidence: 50`) 关联到一个恶意软件家族节点。虽然在提供的图谱中该家族标签为 “Unknown”，但根据 `family_intel` 的搜索结果，可以明确其实际关联家族为 **DiscordGrabber**。

### 4. 威胁情报补充说明
- **VirusTotal 情报缺失**：由于未配置 VT_API_KEY，未能获取该 IP 地址在 VirusTotal 上的即时信誉评分和关联样本信息。建议补充此信息以进行更全面的研判。

## 处置建议
1.  **立即阻断与隔离**：
    - 在边界防火墙或入侵防御系统（IPS）上，立即创建规则，阻断内部网络所有主机与 IP `194.226.121.108` 和 `44.33.22.11` 之间的所有通信。
    - 定位并隔离发起连接的主机 `194.226.121.108`，将其从生产网络中断开，防止横向移动或进一步的数据外泄。

2.  **终端深度排查**：
    - 对主机 `194.226.121.108` 进行全面的恶意软件扫描，使用更新的杀毒软件及专杀工具（可参考 MalwareBazaar 等平台样本特征）。
    - 重点检查该主机上的 Discord 客户端、浏览器历史记录、Cookie、密码存储以及近期运行的进程和计划任务，寻找与 TroubleGrabber/DiscordGrabber 相关的痕迹（如异常 Webhook URL、陌生进程、近期下载的可执行文件等）。
    - 检查系统日志、安全日志以及可能的代理/DNS 日志，追溯该恶意连接的起源（如由哪个用户进程发起）。

3.  **影响范围评估**：
    - 调查网络内是否有其他主机与这两个 IOC（`194.226.121.108`, `44.33.22.11`）有过通信记录。
    - 检查是否有其他主机表现出类似异常行为（如向未知地址发送 HTTP POST 请求）。
    - 提醒内部用户，特别是使用 Discord 的员工，注意防范通过 Discord 消息或链接传播的恶意软件，不要点击可疑链接或下载未知文件。

4.  **取证与根除**：
    - 在确认感染后，根据排查结果彻底清除恶意软件。可能需要重置被盗的各类凭证（Discord 令牌、浏览器保存的密码等）。
    - 保留相关日志和样本用于后续分析和上报。

5.  **加固与预防**：
    - 考虑部署或优化能够检测应用层威胁（如滥用 Discord Webhook）的安全解决方案。
    - 加强终端安全教育，提高员工对社交工程和恶意软件传播方式的警惕性。
    - 确保所有终端安全软件（EDR/AV）的威胁情报库为最新状态。