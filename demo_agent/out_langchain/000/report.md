# 网络安全事件报告

## 事件概述

时间：2026年3月20日 10:00:00

事件描述：观察到IP地址为11.22.33.44的源主机与IP地址为44.33.22.11的目的主机之间发生了TLS流量，该流量命中了特定的JA3指纹4d7a28d6f2263ed61de88ca66eb011e3。

## 判研结论

根据本地情报和外部情报的分析结果，本次事件被怀疑涉及Tofsee恶意软件活动，置信度为95%，严重程度为高危。

## 关键证据与情报

### 事件相关证据

- **命中后告警事件**：在2026年3月20日10:00:00观察到11.22.33.44 -> 44.33.22.11的TLS流量，命中JA3指纹4d7a28d6f2263ed61de88ca66eb011e3。
- **本地指纹情报命中**：本地情报库将ja3_md5 4d7a28d6f2263ed61de88ca66eb011e3关联到家族/标签Tofsee，来源SSLBL。
- **告警附带家族提示**：原始告警将该事件关联到家族/标签Tofsee。

### 外部情报佐证

- **权威外部来源**：
  - [sslbl.abuse.ch](https://sslbl.abuse.ch/blacklist/ja3_fingerprints.rules)
  - [malpedia.caad.fkie.fraunhofer.de](https://malpedia.caad.fkie.fraunhofer.de/details/win.tofsee)
  - [microsoft.com](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Win32/Tofsee)

## 家族/威胁背景

Tofsee是一种模块化的木马型恶意软件，能够执行DDoS攻击、挖掘加密货币、发送电子邮件以及窃取信息。它可以通过多种方法感染计算机，并用于多种恶意用途。

## 处置建议

1. 排查并视情况隔离源主机11.22.33.44。
2. 在边界侧监控或阻断与44.33.22.11相关的后续通信。
3. 基于JA3指纹4d7a28d6f2263ed61de88ca66eb011e3在历史流量中做横向检索。
4. 结合Tofsee相关TTP做主机侧排查与IOC扩线。

## 参考链接

- [sslbl.abuse.ch/ja3-fingerprints/4d7a28d6f2263ed61de88ca66eb011e3/](https://sslbl.abuse.ch/ja3-fingerprints/4d7a28d6f2263ed61de88ca66eb011e3/)
- [sslbl.abuse.ch/blacklist/ja3_fingerprints.rules](https://sslbl.abuse.ch/blacklist/ja3_fingerprints.rules)
- [malpedia.caad.fkie.fraunhofer.de/details/win.tofsee](https://malpedia.caad.fkie.fraunhofer.de/details/win.tofsee)
- [microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Win32/Tofsee](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Win3_2fTofsee)
- [bitsight.com/blog/tofsee-botnet-proxying-and-mining](https://www.bitsight.com/blog/tofsee-botnet-proxying-and-mining)
- [malwarebytes.com/blog/detections/backdoor-tofsee](https://www.malwarebytes.com/blog/detections/backdoor-tofsee)
- [checkpoint.com/cyber-hub/threat-prevention/what-is-malware/tofsee-malware/](https://www.checkpoint.com/cyber-hub/threat-prevention/what-is-malware/tofsee-malware/)
- [services.flowmon.com/reputation/ja3malware/list.csv](https://services.flowmon.com/reputation/ja3malware/list.csv)
- [live.paloaltonetworks.com/t5/advanced-threat-prevention/tofsee-tls-fingerprint-detection/td-p/295364](https://live.paloaltonetworks.com/t5/advanced-threat-prevention/tofsee-tls-fingerprint-detection/td-p/295364)
- [spamhaus.org/resource-hub/malware/neutralizing-tofsee-spambot-part-3-network-based-kill-switch/](https://www.spamhaus.org/resource-hub/malware/neutralizing-tofsee-spambot-part-3-network-based-kill-switch/)