# Threat intel hub（单库、按类型分表）

所有外部源 **fetch** + Maltrail **静态读盘** + **动态 feeds**，统一写入 MySQL 库 **`threat_intel_hub`**，按指标类型落到 **`fp_*`** 表（由 `grouped_intel/schema.sql` 定义）。

唯一入口脚本：**`intel_hub_ingest.py`**。

---

## 一步步构建数据库

### 1. 准备环境

- MySQL 8（或兼容版本）
- Python 3，依赖：

  ```bash
  pip install pymysql requests pandas
  ```

### 2. 创建库与表

在 MySQL 中执行 schema（按你的主机、端口、用户调整）：

```bash
cd /path/to/maltrail
mysql -h 127.0.0.1 -P 3306 -u root -p < Fingerprint/grouped_intel/schema.sql
```

这会创建数据库 **`threat_intel_hub`** 以及 **`fp_domain`、`fp_ip`、`fp_url`** 等表。

### 3. 配置 API 密钥（按需）

- **URLhaus / ThreatFox**：编辑 `Fingerprint/urlhaus/urlhaus_ip_domain_port.py` 与 `Fingerprint/threatfox/treatfox_ip_domain_port.py` 中的 **`AUTH_KEY`**（abuse.ch）。
- 其他源一般无需密钥。

### 4. 全量灌库

在**仓库根目录**执行（连接参数按本机修改）：

```bash
cd /path/to/maltrail
python Fingerprint/intel_hub_ingest.py --host 127.0.0.1 --port 3306 --user root --password YOUR_PASSWORD
```

说明：

- 需要能访问外网（各在线源 + Maltrail 动态 feeds）。
- Maltrail **静态**默认读 `<repo>/trails/static`，若无则使用 **`Fingerprint/maltrail/trails/static`**。
- Maltrail **动态**需要完整 Maltrail 仓库中的 **`trails/feeds`** 与 **`core/common.py`**；否则使用 **`Fingerprint/maltrail/trails/feeds`** 且仍依赖仓库根的 `core`。
- 同时跑静、动时，默认对 **同一 (类型, 指标值)** 做 **静态优先**：已在静态规则里的 IOC 不会再插入对应动态 feed 行（`f_statics` 与 `Sm_*` 重叠会合并）。需要保留两行可加 `--no-maltrail-static-feed-dedupe`。

默认每次运行会先 **清空所有 `fp_*` 表** 再写入（全量替换）。若要保留旧数据、只做 upsert：

```bash
python Fingerprint/intel_hub_ingest.py --incremental ...
```

常用跳过项（调试或省流量）：

```bash
python Fingerprint/intel_hub_ingest.py --skip-maltrail-dynamic
python Fingerprint/intel_hub_ingest.py --skip-urlhaus --skip-threatfox
```

### 5. 验证

```sql
USE threat_intel_hub;
SHOW TABLES LIKE 'fp_%';
SELECT COUNT(*) FROM fp_domain;
SELECT COUNT(*) FROM fp_ip;
```

---

## 目录说明（保留文件）

| 路径 | 作用 |
|------|------|
| `intel_hub_ingest.py` | 总入口：拉取/读取各源并写入 hub |
| `grouped_intel/schema.sql` | hub 库表结构 |
| `grouped_intel/hub_db.py` | 行数据路由到各 `fp_*` 表 |
| `maltrail/maltrail_intel.py` | Maltrail 静/动行收集 |
| `maltrail/static_trails.py` | 解析 `trails/static` |
| `urlhaus/`、`threatfox/`、`SSLBL/`、`ja4_db/` | 各源 fetch/transform（无独立入库入口） |
