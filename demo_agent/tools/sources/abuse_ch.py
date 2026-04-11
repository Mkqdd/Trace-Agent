from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional

import requests


def _strip(value: Any) -> str:
    return str(value or "").strip()


def _infer_indicator_type(value: str) -> str:
    text = _strip(value)
    if text.startswith(("http://", "https://")):
        return "URL"
    if re.fullmatch(r"[a-fA-F0-9]{32}", text):
        return "MD5"
    if re.fullmatch(r"[a-fA-F0-9]{40}", text):
        return "SHA1"
    if re.fullmatch(r"[a-fA-F0-9]{64}", text):
        return "SHA256"
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", text):
        return "IP"
    if "." in text and "/" not in text and " " not in text:
        return "DOMAIN"
    return ""


def _first_non_empty(*values: Any) -> str:
    for value in values:
        text = _strip(value)
        if text:
            return text
    return ""


class ThreatFoxClient:
    def __init__(
        self,
        auth_key: Optional[str] = None,
        base_url: str = "https://threatfox-api.abuse.ch/api/v1/",
    ) -> None:
        self.auth_key = (
            auth_key
            or os.getenv("THREATFOX_AUTH_KEY")
            or os.getenv("ABUSECH_AUTH_KEY")
            or os.getenv("ABUSE_CH_AUTH_KEY")
        )
        self.base_url = base_url

    def enabled(self) -> bool:
        return bool(self.auth_key)

    def _post(self, payload: Dict[str, Any], timeout_s: float = 20.0) -> Dict[str, Any]:
        if not self.auth_key:
            raise RuntimeError("ThreatFox Auth-Key missing.")
        response = requests.post(
            self.base_url,
            headers={"Auth-Key": self.auth_key},
            json=payload,
            timeout=timeout_s,
        )
        response.raise_for_status()
        data = response.json()
        return data if isinstance(data, dict) else {}

    def _normalize_row(self, row: Dict[str, Any]) -> Dict[str, Any]:
        row_id = _strip(row.get("id"))
        family = _first_non_empty(row.get("malware_printable"), row.get("malware"))
        tags = [str(item).strip() for item in list(row.get("tags") or []) if str(item).strip()]
        sample_count = len(list(row.get("malware_samples") or []))
        sample_url = ""
        if sample_count:
            sample_url = _strip((row.get("malware_samples") or [{}])[0].get("malware_bazaar"))
        confidence = int(row.get("confidence_level") or 50)
        threat_desc = _first_non_empty(row.get("threat_type_desc"), row.get("threat_type"))
        ioc = _strip(row.get("ioc"))
        url = _first_non_empty(
            f"https://threatfox.abuse.ch/ioc/{row_id}/" if row_id else "",
            row.get("reference"),
            row.get("malware_malpedia"),
            sample_url,
        )

        claim_parts = [f"ThreatFox 将 IOC `{ioc}` 标记为 `{threat_desc or '恶意 IOC'}`。"]
        if family:
            claim_parts.append(f"关联家族为 `{family}`。")
        if tags:
            claim_parts.append(f"标签包括 `{', '.join(tags[:4])}`。")
        if sample_count:
            claim_parts.append(f"还关联到 {sample_count} 个样本线索。")

        return {
            "id": row_id,
            "ioc": ioc,
            "indicator_type": _strip(row.get("ioc_type")),
            "family": family,
            "malware_label": _strip(row.get("malware")),
            "reference": _strip(row.get("reference")),
            "malpedia_url": _strip(row.get("malware_malpedia")),
            "source": "threatfox.abuse.ch",
            "url": url or None,
            "title": f"ThreatFox IOC {ioc}" if ioc else "ThreatFox IOC",
            "snippet": " ".join(part for part in claim_parts if part).strip(),
            "confidence": confidence,
            "tags": tags,
            "raw": row,
        }

    def search_indicator(self, *, indicator_value: str, indicator_type: str = "", timeout_s: float = 20.0) -> Dict[str, Any]:
        indicator_value = _strip(indicator_value)
        indicator_type = (_strip(indicator_type) or _infer_indicator_type(indicator_value)).upper()
        if not indicator_value:
            return {"enabled": self.enabled(), "ok": False, "error": "empty indicator value"}
        if not self.auth_key:
            return {"enabled": False, "ok": False, "error": "ThreatFox Auth-Key not set"}

        payloads: List[Dict[str, Any]] = []
        if indicator_type in {"MD5", "SHA256"}:
            payloads.append({"query": "search_hash", "hash": indicator_value})
        else:
            payloads.append({"query": "search_ioc", "search_term": indicator_value, "exact_match": True})
            if indicator_type in {"IP", "DOMAIN"}:
                payloads.append({"query": "search_ioc", "search_term": indicator_value, "exact_match": False})

        normalized: List[Dict[str, Any]] = []
        raw_queries: List[Dict[str, Any]] = []
        seen = set()

        import concurrent.futures

        def _fetch_and_parse(payload: Dict[str, Any]) -> Dict[str, Any]:
            raw_response = self._post(payload, timeout_s=timeout_s)
            return {"payload": payload, "response": raw_response}

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(4, len(payloads))) as executor:
                futures = [executor.submit(_fetch_and_parse, p) for p in payloads]
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    raw = result["response"]
                    raw_queries.append(result)
                    
                    if str(raw.get("query_status") or "").lower() != "ok":
                        continue
                    for row in list(raw.get("data") or []):
                        prepared = self._normalize_row(row if isinstance(row, dict) else {})
                        key = (
                            prepared.get("ioc"),
                            prepared.get("family"),
                            prepared.get("url"),
                        )
                        if key in seen:
                            continue
                        seen.add(key)
                        normalized.append(prepared)
        except Exception as exc:
            return {
                "enabled": True,
                "ok": False,
                "indicator_type": indicator_type,
                "indicator_value": indicator_value,
                "error": str(exc),
            }

        return {
            "enabled": True,
            "ok": bool(normalized),
            "indicator_type": indicator_type,
            "indicator_value": indicator_value,
            "mode": "threatfox_api",
            "results": normalized,
            "raw_queries": raw_queries,
            "query_status": "ok" if normalized else "no_result",
        }


class URLhausClient:
    def __init__(
        self,
        auth_key: Optional[str] = None,
        base_url: str = "https://urlhaus-api.abuse.ch/v1",
    ) -> None:
        self.auth_key = (
            auth_key
            or os.getenv("URLHAUS_AUTH_KEY")
            or os.getenv("ABUSECH_AUTH_KEY")
            or os.getenv("ABUSE_CH_AUTH_KEY")
        )
        self.base_url = base_url.rstrip("/")

    def enabled(self) -> bool:
        return bool(self.auth_key)

    def _post_form(self, endpoint: str, data: Dict[str, Any], timeout_s: float = 20.0) -> Dict[str, Any]:
        if not self.auth_key:
            raise RuntimeError("URLhaus Auth-Key missing.")
        response = requests.post(
            f"{self.base_url}/{endpoint.strip('/')}/",
            headers={"Auth-Key": self.auth_key},
            data=data,
            timeout=timeout_s,
        )
        response.raise_for_status()
        payload = response.json()
        return payload if isinstance(payload, dict) else {}

    def _normalize_host_result(self, raw: Dict[str, Any]) -> List[Dict[str, Any]]:
        host = _strip(raw.get("host"))
        reference = _first_non_empty(raw.get("urlhaus_reference"), f"https://urlhaus.abuse.ch/host/{host}/" if host else "")
        urls = list(raw.get("urls") or [])
        tags: List[str] = []
        threats: List[str] = []
        statuses: List[str] = []
        results: List[Dict[str, Any]] = []

        for url_item in urls[:3]:
            if not isinstance(url_item, dict):
                continue
            item_tags = [str(item).strip() for item in list(url_item.get("tags") or []) if str(item).strip()]
            tags.extend(item_tags)
            threats.append(_strip(url_item.get("threat")))
            statuses.append(_strip(url_item.get("url_status")))
            url_ref = _first_non_empty(url_item.get("urlhaus_reference"), raw.get("urlhaus_reference"))
            claim = f"URLhaus 记录 `{url_item.get('url')}` 为 `{_strip(url_item.get('threat')) or '恶意投递 URL'}`，状态 `{_strip(url_item.get('url_status')) or 'unknown'}`。"
            if item_tags:
                claim += f" 标签包括 `{', '.join(item_tags[:4])}`。"
            results.append(
                {
                    "source": "urlhaus.abuse.ch",
                    "url": url_ref or None,
                    "title": f"URLhaus URL {url_item.get('url')}",
                    "snippet": claim,
                    "confidence": 72,
                    "tags": item_tags,
                    "host": host,
                    "raw": url_item,
                }
            )

        if host:
            tags_text = ", ".join(dict.fromkeys([tag for tag in tags if tag])) or "无显式标签"
            threat_text = ", ".join(dict.fromkeys([item for item in threats if item])) or "恶意 URL 投递"
            status_text = ", ".join(dict.fromkeys([item for item in statuses if item])) or "unknown"
            results.insert(
                0,
                {
                    "source": "urlhaus.abuse.ch",
                    "url": reference or None,
                    "title": f"URLhaus Host {host}",
                    "snippet": (
                        f"URLhaus 将主机 `{host}` 关联到 {raw.get('url_count') or len(urls)} 个恶意 URL，"
                        f"常见威胁类型 `{threat_text}`，状态 `{status_text}`，标签 `{tags_text}`。"
                    ),
                    "confidence": 74,
                    "tags": list(dict.fromkeys(tags)),
                    "host": host,
                    "raw": raw,
                }
            )
        return results

    def _normalize_url_result(self, raw: Dict[str, Any]) -> List[Dict[str, Any]]:
        url = _strip(raw.get("url"))
        tags = [str(item).strip() for item in list(raw.get("tags") or []) if str(item).strip()]
        claim = f"URLhaus 记录 URL `{url}` 为 `{_strip(raw.get('threat')) or '恶意投递 URL'}`，状态 `{_strip(raw.get('url_status')) or 'unknown'}`。"
        if tags:
            claim += f" 标签包括 `{', '.join(tags[:4])}`。"
        return [
            {
                "source": "urlhaus.abuse.ch",
                "url": _first_non_empty(raw.get("urlhaus_reference"), f"https://urlhaus.abuse.ch/url/{_strip(raw.get('id'))}/" if raw.get("id") else ""),
                "title": f"URLhaus URL {url}" if url else "URLhaus URL",
                "snippet": claim,
                "confidence": 76,
                "tags": tags,
                "host": _strip(raw.get("host")),
                "raw": raw,
            }
        ]

    def _normalize_payload_result(self, raw: Dict[str, Any]) -> List[Dict[str, Any]]:
        sha256_hash = _strip(raw.get("sha256_hash"))
        file_type = _strip(raw.get("file_type")) or "payload"
        signature = _first_non_empty(raw.get("signature"), raw.get("filename"))
        claim = f"URLhaus 记录 SHA256 `{sha256_hash}` 为已观测载荷，文件类型 `{file_type}`。"
        if signature:
            claim += f" 关联签名/文件名 `{signature}`。"
        return [
            {
                "source": "urlhaus.abuse.ch",
                "url": _first_non_empty(raw.get("urlhaus_download"), raw.get("urlhaus_reference")),
                "title": f"URLhaus Payload {sha256_hash[:12]}..." if sha256_hash else "URLhaus Payload",
                "snippet": claim,
                "confidence": 74,
                "signature": signature,
                "raw": raw,
            }
        ]

    def lookup_indicator(self, *, indicator_value: str, indicator_type: str = "", timeout_s: float = 20.0) -> Dict[str, Any]:
        indicator_value = _strip(indicator_value)
        indicator_type = (_strip(indicator_type) or _infer_indicator_type(indicator_value)).upper()
        if not indicator_value:
            return {"enabled": self.enabled(), "ok": False, "error": "empty indicator value"}
        if not self.auth_key:
            return {"enabled": False, "ok": False, "error": "URLhaus Auth-Key not set"}

        endpoint = ""
        data: Dict[str, Any] = {}
        if indicator_type == "URL":
            endpoint = "url"
            data = {"url": indicator_value}
        elif indicator_type in {"DOMAIN", "IP"}:
            endpoint = "host"
            data = {"host": indicator_value}
        elif indicator_type == "SHA256":
            endpoint = "payload"
            data = {"sha256_hash": indicator_value}
        else:
            return {
                "enabled": True,
                "ok": False,
                "indicator_type": indicator_type,
                "indicator_value": indicator_value,
                "note": f"URLhaus structured lookup does not support {indicator_type} directly.",
            }

        try:
            raw = self._post_form(endpoint, data, timeout_s=timeout_s)
        except Exception as exc:
            return {
                "enabled": True,
                "ok": False,
                "indicator_type": indicator_type,
                "indicator_value": indicator_value,
                "error": str(exc),
            }

        query_status = str(raw.get("query_status") or "").lower()
        if query_status != "ok":
            return {
                "enabled": True,
                "ok": False,
                "indicator_type": indicator_type,
                "indicator_value": indicator_value,
                "mode": "urlhaus_api",
                "query_status": query_status or "no_result",
                "raw": raw,
            }

        if endpoint == "host":
            results = self._normalize_host_result(raw)
        elif endpoint == "url":
            results = self._normalize_url_result(raw)
        else:
            results = self._normalize_payload_result(raw)

        return {
            "enabled": True,
            "ok": bool(results),
            "indicator_type": indicator_type,
            "indicator_value": indicator_value,
            "mode": "urlhaus_api",
            "endpoint": endpoint,
            "results": results,
            "raw": raw,
        }
