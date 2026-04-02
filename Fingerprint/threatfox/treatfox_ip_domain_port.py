import requests

THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
AUTH_KEY = "d00864e3dd7f4d72a9db6b2ca85ed156506be2842b0d2863"
DAYS = 7   # 取最近几天，文档里最大 7


# ===================== 拉取 ThreatFox 数据 =====================
def fetch_threatfox_iocs():
    print("[+] Fetching ThreatFox IOCs...")

    headers = {
        "Auth-Key": AUTH_KEY,
        "Content-Type": "application/json"
    }

    payload = {
        "query": "get_iocs",
        "days": DAYS
    }

    resp = requests.post(
        THREATFOX_API,
        headers=headers,
        json=payload,
        timeout=60
    )
    resp.raise_for_status()

    result = resp.json()

    if result.get("query_status") != "ok":
        raise ValueError(f"ThreatFox API error: {result.get('query_status')}")

    data = result.get("data", [])
    print(f"[+] Fetched {len(data)} records")
    return data


# ===================== 威胁等级映射 =====================
def map_severity(threat_type: str):
    if not threat_type:
        return "medium"

    threat_type = threat_type.lower()

    return None
    # if "botnet_cc" in threat_type or "c2" in threat_type or "payload" in threat_type:
    #     return "high"
    # if "malware_download" in threat_type or "phishing" in threat_type:
    #     return "medium"
    # return "medium"


# ===================== IOC 类型规范化 =====================
def normalize_indicator_type(ioc_type: str):
    if not ioc_type:
        return "unknown"

    ioc_type = ioc_type.strip().lower()

    mapping = {
        "ip:port": "ip_port",
        "ip-port": "ip_port",
        "url": "url",
        "domain": "domain",
        "ipv4": "ip",
        "ipv6": "ip",
        "ip": "ip",
        "md5_hash": "md5",
        "sha1_hash": "sha1",
        "sha256_hash": "sha256",
        "md5": "md5",
        "sha1": "sha1",
        "sha256": "sha256"
    }

    return mapping.get(ioc_type, ioc_type)


# ===================== 时间清洗 =====================
def normalize_time_str(s: str):
    if not s:
        return None

    s = s.strip()

    # ThreatFox 示例里是 "2020-12-08 13:36:27 UTC"
    if s.endswith(" UTC"):
        s = s[:-4]

    return s


# ===================== 映射到统一 schema =====================
def transform(records):
    data = []

    for item in records:
        indicator_type = normalize_indicator_type(item.get("ioc_type"))
        indicator_value = item.get("ioc")

        if not indicator_value:
            continue

        malware_family = item.get("malware_printable") or item.get("malware")
        severity = map_severity(item.get("threat_type"))
        confidence = item.get("confidence_level") or 0
        source = "ThreatFox"

        # 优先 last_seen，没有就 first_seen
        last_updated = normalize_time_str(item.get("last_seen"))
        if not last_updated:
            last_updated = normalize_time_str(item.get("first_seen"))

        data.append((
            indicator_type,
            indicator_value,
            malware_family,
            severity,
            confidence,
            source,
            last_updated
        ))

    return data