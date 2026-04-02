import requests
from datetime import datetime

JA4DB_API = "https://ja4db.com/api/read/"


# ===================== 过滤过长的指纹记录 =====================
MAX_INDICATOR_LEN = 512
def filter_too_long_records(data):
    filtered = []
    skipped = []

    for record in data:
        indicator_type = record[0]
        indicator_value = record[1]

        if indicator_value is None:
            continue

        if len(str(indicator_value)) > MAX_INDICATOR_LEN:
            skipped.append((indicator_type, indicator_value))
            continue

        filtered.append(record)

    print(f"[+] valid records: {len(filtered)}")
    print(f"[+] skipped too long records: {len(skipped)}")

    if skipped:
        print("[+] examples of skipped records:")
        for item in skipped[:5]:
            print(f"    type={item[0]}, len={len(item[1])}")

    return filtered



# ===================== 拉取数据 =====================
def fetch_ja4db():
    print("[+] Fetching JA4DB records...")

    resp = requests.get(JA4DB_API, timeout=60)
    resp.raise_for_status()

    data = resp.json()
    if not isinstance(data, list):
        raise ValueError("JA4DB response is not a list")

    print(f"[+] Fetched {len(data)} records")
    return data


# ===================== 置信度映射 =====================
def map_confidence(verified, observation_count):
    obs = observation_count or 0

    return None
    # if verified:
    #     if obs >= 100:
    #         return 90
    #     if obs >= 10:
    #         return 80
    #     return 70

    # if obs >= 100:
    #     return 65
    # if obs >= 10:
    #     return 55
    # return 40


# ===================== 家族/标签映射 =====================
def build_label(item):
    # JA4DB 不是恶意家族库，这里只是借用 malware_family 字段存“归属标签”
    application = item.get("application")
    library = item.get("library")
    device = item.get("device")
    os_name = item.get("os")

    if application:
        return str(application).strip()

    parts = []
    if library:
        parts.append(str(library).strip())
    if device:
        parts.append(str(device).strip())
    if os_name:
        parts.append(str(os_name).strip())

    if parts:
        return " / ".join(parts)

    return None


# ===================== 指纹字段展开 =====================
def transform(records):
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    fingerprint_field_map = {
        "ja4_fingerprint": "ja4",
        "ja4_fingerprint_string": "ja4_string",
        "ja4s_fingerprint": "ja4s",
        "ja4h_fingerprint": "ja4h",
        "ja4x_fingerprint": "ja4x",
        "ja4t_fingerprint": "ja4t",
        "ja4ts_fingerprint": "ja4ts",
        "ja4tscan_fingerprint": "ja4tscan",
    }

    data = []

    for item in records:
        malware_family = build_label(item)
        verified = bool(item.get("verified"))
        observation_count = item.get("observation_count") or 0

        severity = None
        confidence = map_confidence(verified, observation_count)
        source = "JA4DB"
        last_updated = now_str

        for raw_field, indicator_type in fingerprint_field_map.items():
            value = item.get(raw_field)

            if value is None:
                continue

            value = str(value).strip()
            if not value:
                continue
            if value.lower() == "null":
                continue

            data.append((
                indicator_type,
                value,
                malware_family,
                severity,
                confidence,
                source,
                last_updated
            ))

    return data


# ===================== 脚本层去重 =====================
def deduplicate_records(data):
    merged = {}

    for record in data:
        key = (record[0], record[1])  # indicator_type, indicator_value

        if key not in merged:
            merged[key] = record
            continue

        old = merged[key]

        # 置信度更高的覆盖
        if (record[4] or 0) > (old[4] or 0):
            merged[key] = record

    return list(merged.values())