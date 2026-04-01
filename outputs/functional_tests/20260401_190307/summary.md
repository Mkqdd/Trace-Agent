# 功能测试结果

- 运行时间：2026-04-01 19:03:31
- 总用例数：5
- 通过用例：3
- 失败用例：2

| case | mode | ok | duration(s) | gap_triggered | notes |
|------|------|----|-------------|---------------|-------|
| batch_plan_full | plan | PASS | 11.9 | True | 主链批量样例，覆盖 JA3/IP/JA4/SSL_SHA1。 |
| gap_probe_plan | plan | FAIL | 2.11 | False | 验证 plan 主链中的 gap -> React 补查链路是否触发。 |
| ip_without_vt | plan | PASS | 3.49 | True | 验证 VT 缺失时是否安全降级。 |
| ja4_without_db | plan | PASS | 3.18 | True | 验证本地 MySQL 不可用时是否安全降级。 |
| react_mode_smoke | react | FAIL | 3.23 | False | 验证独立 react 模式是否仍可运行。 |

## 逐项结果

### batch_plan_full
- 状态：PASS
- 模式：plan
- 用时：11.9s
- 触发补查：True
- item1: type=JA3 family=Tofsee evidence=2 issues=none
- item2: type=IP family=discordgrabber evidence=2 issues=none
- item3: type=JA4 family=Cobalt Strike v4.9.1 beacon evidence=2 issues=none
- item4: type=JA4 family=IcedID evidence=2 issues=none
- item5: type=SSL_SHA1 family=Vidar evidence=2 issues=none
- item6: type=SSL_SHA1 family=QuasarRAT evidence=2 issues=none

### gap_probe_plan
- 状态：FAIL
- 模式：plan
- 用时：2.11s
- 触发补查：False
- item1: type=IP family=Unknown evidence=1 issues=family not present in report

### ip_without_vt
- 状态：PASS
- 模式：plan
- 用时：3.49s
- 触发补查：True
- item1: type=IP family=discordgrabber evidence=2 issues=none

### ja4_without_db
- 状态：PASS
- 模式：plan
- 用时：3.18s
- 触发补查：True
- item1: type=JA4 family=Cobalt Strike v4.9.1 beacon evidence=2 issues=none

### react_mode_smoke
- 状态：FAIL
- 模式：react
- 用时：3.23s
- 触发补查：False
- stderr 摘要：`", line 164, in invoke
    raise e
  File "/home/estar0x/miniconda3/envs/trail-agent/lib/python3.11/site-packages/langchain/chains/base.py", line 154, in invoke
    self._call(inputs, run_manager=run_manager)
  File "/home/estar0x/miniconda3/envs/trail-agent/lib/python3.11/site-packages/langchain/ag`
