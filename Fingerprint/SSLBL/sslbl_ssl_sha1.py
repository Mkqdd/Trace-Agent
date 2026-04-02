import requests
import pandas as pd

SSLBL_URL = "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"
LOCAL_FILE = "./Fingerprint/SSLBL/data/sslbl_ssl_sha1.csv"


# ===================== 下载 =====================
def download_sslbl():
    print("[+] Downloading SSLBL...")
    r = requests.get(SSLBL_URL, timeout=30)
    r.raise_for_status()

    import os
    os.makedirs(os.path.dirname(LOCAL_FILE), exist_ok=True)
    with open(LOCAL_FILE, "wb") as f:
        f.write(r.content)

    print("[+] Downloaded")


# ===================== 解析 =====================
def load_csv():
    print("[+] Parsing CSV...")

    df = pd.read_csv(
        LOCAL_FILE,
        comment='#',
        header=None   # 没有表头
    )

    # 手动加列名
    df.columns = ["Listingdate", "SHA1", "Listingreason"]

    df = df.dropna(subset=["SHA1"])
    df["SHA1"] = df["SHA1"].str.strip()

    print(f"[+] {len(df)} rows loaded")
    return df


# ===================== 数据映射（核心） =====================
def transform(df):
    data = []

    for _, row in df.iterrows():
        sha1 = row["SHA1"]
        date = row["Listingdate"]
        reason = row["Listingreason"]

        # SSLBL -> 统一schema映射
        indicator_type = "ssl_sha1"
        indicator_value = sha1

        malware_family = reason.split()[0] if isinstance(reason, str) else None

        severity = ""       
        confidence =    None      

        source = "SSLBL"
        last_updated = date

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