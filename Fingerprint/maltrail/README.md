# Maltrail → hub 行数据

本目录为 **`Fingerprint/intel_hub_ingest.py`** 提供 Maltrail 数据，不单独写库。

| 文件 | 作用 |
|------|------|
| `static_trails.py` | 解析 `trails/static`（`.txt` / `.csv`） |
| `maltrail_intel.py` | `collect_static_intel_rows()`、`collect_dynamic_intel_rows()` |

**路径**：优先 `<repo>/trails/static` 与 `<repo>/trails/feeds`；否则使用本目录下 **`trails/static`**、**`trails/feeds`**。动态 feeds 依赖 Maltrail 的 **`core/common.py`**（仓库根须在 `sys.path` 中，由 ingest 脚本 `chdir` 到仓库根保证）。
