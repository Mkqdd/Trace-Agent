import os
import requests

AUTH_KEY = "d00864e3dd7f4d72a9db6b2ca85ed156506be2842b0d2863"
LIMIT = 1000

URLHAUS_RECENT_API = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
URLHAUS_RECENT_LIMIT_API = f"https://urlhaus-api.abuse.ch/v1/urls/recent/limit/{LIMIT}/"


# ===================== 工具函数 =====================
def normalize_time_str(s):
    if s is None:
        return None
    s = str(s).strip()
    if not s or s.lower() in {"null", "none", "nan"}:
        return None
    if s.endswith(" UTC"):
        s = s[:-4]
    return s


def map_severity(url_status, threat):
    status = (url_status or "").strip().lower()
    threat = (threat or "").strip().lower()

    return None
    # if threat == "malware_download":
    #     if status == "online":
    #         return "high"
    #     if status == "offline":
    #         return "medium"
    #     return "medium"

    # return "medium"


def map_confidence(url_status, threat):
    status = (url_status or "").strip().lower()
    threat = (threat or "").strip().lower()

    return None
    # if threat == "malware_download":
    #     if status == "online":
    #         return 90
    #     if status == "offline":
    #         return 75
    #     return 70

    # return 70


def normalize_host_type(host_value):
    if not host_value:
        return None
    host_value = str(host_value).strip()
    if not host_value:
        return None

    # 很粗的判断，够你现在用了
    if ":" in host_value and host_value.count(":") >= 2:
        return "ip"
    parts = host_value.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return "ip"
    return "domain"


# ===================== 拉取 recent urls =====================
def fetch_recent_urls():
    print("[+] Fetching URLhaus recent URLs...")

    headers = {
        "Auth-Key": AUTH_KEY
    }

    resp = requests.get(
        URLHAUS_RECENT_LIMIT_API,
        headers=headers,
        timeout=60
    )
    resp.raise_for_status()

    result = resp.json()

    query_status = result.get("query_status")
    if query_status not in {"ok", "no_results"}:
        raise ValueError(f"URLhaus API error: {query_status}")

    urls = result.get("urls", [])
    print(f"[+] Fetched {len(urls)} recent URL records")

    return urls


# ===================== 映射到统一 schema =====================
def transform(records):
    data = []

    for item in records:
        raw_url = item.get("url")
        if not raw_url:
            continue

        raw_url = str(raw_url).strip()
        if not raw_url:
            continue

        url_status = item.get("url_status")
        threat = item.get("threat")
        host = item.get("host")
        date_added = normalize_time_str(item.get("date_added"))

        tags = item.get("tags") or []
        malware_family = None
        if isinstance(tags, list) and tags:
            malware_family = str(tags[0]).strip() if str(tags[0]).strip() else None

        severity = map_severity(url_status, threat)
        confidence = map_confidence(url_status, threat)

        # 1. 插入 URL 指标
        data.append((
            "url",
            raw_url,
            malware_family,
            severity,
            confidence,
            "URLhaus",
            date_added
        ))

        # 2. 插入 host 指标（domain/ip）
        host_type = normalize_host_type(host)
        if host_type:
            data.append((
                host_type,
                str(host).strip(),
                malware_family,
                severity,
                confidence,
                "URLhaus",
                date_added
            ))

    return data


# ===================== 去重 =====================
def deduplicate_records(data):
    merged = {}

    for record in data:
        key = (record[0], record[1])  # indicator_type, indicator_value

        if key not in merged:
            merged[key] = record
            continue

        old = merged[key]

        old_time = old[6] or ""
        new_time = record[6] or ""

        if new_time > old_time:
            merged[key] = record
        elif new_time == old_time and (record[4] or 0) > (old[4] or 0):
            merged[key] = record

    return list(merged.values())