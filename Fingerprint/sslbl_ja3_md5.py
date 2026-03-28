import requests
import pandas as pd
import pymysql


# ===================== 配置 =====================
MYSQL_CONFIG = {
    "host": "127.0.0.1",
    "user": "root",
    "password": "123456",
    "database": "threat_intel",
    "charset": "utf8mb4"
}

JA3_URL = "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv"
LOCAL_FILE = "./Fingerprint/data/sslbl_ja3_md5.csv"


# ===================== 下载 =====================
def download_ja3():
    print("[+] Downloading JA3...")
    r = requests.get(JA3_URL, timeout=30)
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
        header=None
    )

    df.columns = ["ja3_md5", "Firstseen", "Lastseen", "Listingreason"]


    df = df.dropna(subset=["ja3_md5"])
    df["ja3_md5"] = df["ja3_md5"].str.strip()

    print(f"[+] {len(df)} rows loaded")
    return df


# ===================== 数据映射 =====================
def transform(df):
    data = []

    for _, row in df.iterrows():
        ja3 = row["ja3_md5"]
        last_seen = row["Lastseen"]
        reason = row["Listingreason"]

        indicator_type = "ja3_md5"
        indicator_value = ja3

        malware_family = reason.split()[0] if isinstance(reason, str) else None

        severity = ""
        confidence = None

        source = "SSLBL"
        last_updated = last_seen

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


# ===================== 入库 =====================
def insert_data(conn, data):
    cursor = conn.cursor()

    print("[+] Inserting...")

    cursor.executemany("""
        INSERT IGNORE INTO intel (
            indicator_type,
            indicator_value,
            malware_family,
            severity,
            confidence,
            source,
            last_updated
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, data)

    conn.commit()

    print(f"[+] Inserted {cursor.rowcount} rows")


# ===================== 主流程 =====================
def main():
    download_ja3()

    df = load_csv()

    conn = pymysql.connect(**MYSQL_CONFIG)

    data = transform(df)

    insert_data(conn, data)

    conn.close()

    print("[+] Done")


if __name__ == "__main__":
    main()