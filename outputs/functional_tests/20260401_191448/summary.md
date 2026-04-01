# 功能测试结果

- 运行时间：2026-04-01 19:18:18
- 总用例数：5
- 通过用例：2
- 失败用例：3

| case | mode | ok | duration(s) | gap_triggered | notes |
|------|------|----|-------------|---------------|-------|
| batch_plan_full | plan | PASS | 13.84 | False | 主链批量样例，覆盖 JA3/IP/JA4/SSL_SHA1。 |
| gap_probe_plan | plan | FAIL | 90.09 | False | 验证 plan 主链中的 gap -> React 补查链路是否触发。 |
| ip_without_vt | plan | FAIL | 90.1 | False | 验证 VT 缺失时是否安全降级。 |
| ja4_without_db | plan | PASS | 3.19 | False | 验证本地 MySQL 不可用时是否安全降级。 |
| react_mode_smoke | react | FAIL | 13.31 | False | 验证独立 react 模式是否仍可运行。 |

## 逐项结果

### batch_plan_full
- 状态：PASS
- 模式：plan
- 用时：13.84s
- 触发补查：False
- item1: type=JA3 family=Tofsee evidence=12 issues=none
- item2: type=IP family=discordgrabber evidence=4 issues=none
- item3: type=JA4 family=Cobalt Strike v4.9.1 beacon evidence=7 issues=none
- item4: type=JA4 family=IcedID evidence=13 issues=none
- item5: type=SSL_SHA1 family=Vidar evidence=9 issues=none
- item6: type=SSL_SHA1 family=QuasarRAT evidence=9 issues=none

### gap_probe_plan
- 状态：FAIL
- 模式：plan
- 用时：90.09s
- 触发补查：False
- stderr 摘要：`timeout after 90s`

### ip_without_vt
- 状态：FAIL
- 模式：plan
- 用时：90.1s
- 触发补查：False
- stderr 摘要：`timeout after 90s`

### ja4_without_db
- 状态：PASS
- 模式：plan
- 用时：3.19s
- 触发补查：False
- item1: type=JA4 family=Cobalt Strike v4.9.1 beacon evidence=6 issues=none

### react_mode_smoke
- 状态：FAIL
- 模式：react
- 用时：13.31s
- 触发补查：False
- stderr 摘要：`Traceback (most recent call last):
  File "<frozen runpy>", line 198, in _run_module_as_main
  File "<frozen runpy>", line 88, in _run_code
  File "/home/estar0x/project/maltrail_test/Trace-Agent/demo_agent/langchain_agent.py", line 129, in <module>
    main()
  File "/home/estar0x/project/maltrail_`
