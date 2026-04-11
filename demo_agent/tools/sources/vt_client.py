from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests


@dataclass(frozen=True)
class VirusTotalIpEnrichment:
    ip: str
    stats: Dict[str, int]
    country: Optional[str] = None
    asn: Optional[int] = None
    as_owner: Optional[str] = None
    reputation: Optional[int] = None
    raw: Optional[Dict[str, Any]] = None


class VirusTotalClient:
    def __init__(self, api_key: Optional[str] = None, base_url: str = "https://www.virustotal.com/api/v3") -> None:
        self.api_key = api_key or os.getenv("VT_API_KEY") or os.getenv("VIRUSTOTAL_API_KEY")
        self.base_url = base_url.rstrip("/")

    def enabled(self) -> bool:
        return bool(self.api_key)

    def enrich_ip(self, ip: str, timeout_s: float = 20.0) -> VirusTotalIpEnrichment:
        if not self.api_key:
            raise RuntimeError("VirusTotal API key missing. Set VT_API_KEY (or VIRUSTOTAL_API_KEY).")

        url = f"{self.base_url}/ip_addresses/{ip}"
        headers = {"x-apikey": self.api_key}
        r = requests.get(url, headers=headers, timeout=timeout_s)
        r.raise_for_status()
        data = r.json()

        attrs = (data.get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        return VirusTotalIpEnrichment(
            ip=ip,
            stats={k: int(v) for k, v in stats.items()},
            country=attrs.get("country"),
            asn=attrs.get("asn"),
            as_owner=attrs.get("as_owner"),
            reputation=attrs.get("reputation"),
            raw=data,
        )
