# 功能测试结果

- 运行时间：2026-04-01 19:44:53
- 总用例数：5
- 通过用例：5
- 失败用例：0

| case | mode | ok | duration(s) | gap_triggered | notes |
|------|------|----|-------------|---------------|-------|
| batch_plan_full | plan | PASS | 13.54 | False | 主链批量样例，覆盖 JA3/IP/JA4/SSL_SHA1。 |
| gap_probe_plan | plan | PASS | 17.71 | True | 验证 plan 主链中的 gap -> React 补查链路是否触发。 |
| ip_without_vt | plan | PASS | 18.72 | True | 验证 VT 缺失时是否安全降级。 |
| ja4_without_db | plan | PASS | 3.63 | False | 验证本地 MySQL 不可用时是否安全降级。 |
| react_mode_smoke | react | PASS | 15.78 | False | 验证独立 react 模式是否仍可运行。 |

## 逐项结果

### batch_plan_full
- 状态：PASS
- 模式：plan
- 用时：13.54s
- 触发补查：False
- item1: type=JA3 family=Tofsee evidence=12 issues=none
- item2: type=IP family=discordgrabber evidence=4 issues=none
- item3: type=JA4 family=Cobalt Strike v4.9.1 beacon evidence=7 issues=none
- item4: type=JA4 family=IcedID evidence=13 issues=none
- item5: type=SSL_SHA1 family=Vidar evidence=9 issues=none
- item6: type=SSL_SHA1 family=QuasarRAT evidence=9 issues=none

### gap_probe_plan
- 状态：PASS
- 模式：plan
- 用时：17.71s
- 触发补查：True
- item1: type=IP family=Unknown evidence=4 issues=none

### ip_without_vt
- 状态：PASS
- 模式：plan
- 用时：18.72s
- 触发补查：True
- item1: type=IP family=discordgrabber evidence=3 issues=none

### ja4_without_db
- 状态：PASS
- 模式：plan
- 用时：3.63s
- 触发补查：False
- item1: type=JA4 family=Cobalt Strike v4.9.1 beacon evidence=6 issues=none

### react_mode_smoke
- 状态：PASS
- 模式：react
- 用时：15.78s
- 触发补查：False
