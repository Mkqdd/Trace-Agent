from __future__ import annotations

from datetime import date, datetime
from typing import Any, Dict, List, Optional

from ..config import DatabaseConfig, load_database_config

try:
    import pymysql
except Exception:  # pragma: no cover - optional runtime dependency
    pymysql = None  # type: ignore[assignment]


_TYPE_CANDIDATES = {
    "IP": ["ip"],
    "DOMAIN": ["domain"],
    "URL": ["url"],
    "JA3": ["ja3_md5", "ja3"],
    "JA4": ["ja4"],
    "SSL_SHA1": ["ssl_sha1"],
    "CERT_SHA1": ["ssl_sha1"],
}


def _json_safe(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_json_safe(v) for v in value]
    return value


def indicator_type_candidates(indicator_type: str) -> List[str]:
    normalized = str(indicator_type or "").strip().upper()
    return list(_TYPE_CANDIDATES.get(normalized, [normalized.lower()])) or ["unknown"]


class LocalIntelClient:
    def __init__(self, db_config: Optional[DatabaseConfig] = None) -> None:
        self.db_config = db_config or load_database_config()

    def enabled(self) -> bool:
        return pymysql is not None and bool(self.db_config.host and self.db_config.name and self.db_config.user)

    def lookup(self, *, indicator_type: str, indicator_value: str) -> Dict[str, Any]:
        indicator_value = str(indicator_value or "").strip()
        if not indicator_value:
            return {"enabled": self.enabled(), "matched": False, "error": "empty indicator value"}

        if pymysql is None:
            return {"enabled": False, "matched": False, "error": "pymysql not installed"}

        candidates = indicator_type_candidates(indicator_type)
        rows: List[Dict[str, Any]] = []

        try:
            conn = pymysql.connect(
                host=self.db_config.host,
                port=int(self.db_config.port),
                user=self.db_config.user,
                password=self.db_config.password,
                database=self.db_config.name,
                charset=self.db_config.charset,
                cursorclass=pymysql.cursors.DictCursor,
                connect_timeout=5,
                read_timeout=5,
                write_timeout=5,
            )
            try:
                with conn.cursor() as cursor:
                    for mapped_type in candidates:
                        cursor.execute(
                            """
                            SELECT
                                indicator_type,
                                indicator_value,
                                malware_family,
                                severity,
                                confidence,
                                source,
                                last_updated
                            FROM intel
                            WHERE indicator_type = %s AND indicator_value = %s
                            ORDER BY COALESCE(confidence, 0) DESC, last_updated DESC
                            """,
                            (mapped_type, indicator_value),
                        )
                        for row in cursor.fetchall():
                            row = _json_safe(row)
                            if row not in rows:
                                rows.append(row)
            finally:
                conn.close()
        except Exception as exc:
            return {
                "enabled": True,
                "matched": False,
                "query": {
                    "indicator_type": indicator_type,
                    "indicator_value": indicator_value,
                    "candidates": candidates,
                },
                "error": str(exc),
            }

        best_match = rows[0] if rows else None
        return {
            "enabled": True,
            "matched": bool(rows),
            "query": {
                "indicator_type": indicator_type,
                "indicator_value": indicator_value,
                "candidates": candidates,
            },
            "match_count": len(rows),
            "best_match": best_match,
            "matches": rows,
        }
