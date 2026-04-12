# 快速开始


## 2. 配置 `.env`

配置文件位置：

```text
demo_agent/.env
```

可以先参考：

```text
demo_agent/.env.example
```

当前最常用的配置项有：

- `LLM_API_KEY`
- `LLM_BASE_URL`
- `LLM_MODEL`
- `VT_API_KEY`
- `SERPAPI_API_KEY`
- `ABUSECH_AUTH_KEY`

## 3. 运行主链

在仓库根目录运行：

```bash
python -m demo_agent \
  --alert demo_alert.json \
  --out outputs/agent_runs/default \
  --mode plan
```

说明：

- `--alert`：输入告警 JSON，可以是单条对象，也可以是对象数组
- `--out`：输出目录
- `--mode`：当前只支持 `plan`

## 4. 输出内容

如果输入是一个告警数组，输出会按 `000/001/002...` 分目录保存。

每条 case 通常会生成：

- `input_alert.json`
- `event.json`
- `analysis.json`
- `report.md`
- `topology.json`
- `topology.html`
- `agent_output.txt`

默认输出目录示例：

```text
outputs/agent_runs/default/004/
```

## 5. 常见查看顺序

建议先看：

1. `report.md`
2. `analysis.json`
3. `topology.html`

## 6. 运行单条样例

如果你只想测一条告警，最简单的方式是先准备一个只包含单条对象的 JSON 文件，再运行：

```bash
python -m demo_agent \
  --alert /tmp/demo_alert_single.json \
  --out outputs/agent_runs/single_check \
  --mode plan
```
