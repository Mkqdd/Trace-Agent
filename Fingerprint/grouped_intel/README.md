# grouped_intel — Hub 表结构

- **`schema.sql`**：创建 **`threat_intel_hub`** 及 **`fp_*`** 分表。
- **`hub_db.py`**：将统一行格式写入对应 `fp_*` 表；由 **`../intel_hub_ingest.py`** 调用。

扩展新 `indicator_type`：在 **`schema.sql`** 增加表，在 **`hub_db.py`** 的 **`TYPE_TO_TABLE`** 增加映射；未知类型进 **`fp_other`**。
