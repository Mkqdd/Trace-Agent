from __future__ import annotations

import re
from typing import Any, Dict, List

from langchain_core.tools import tool

from .sources.abuse_ch import ThreatFoxClient, URLhausClient
from .common import dumps_json, is_ip, strip_quotes

_CACHE_THREATFOX: Dict[str, Dict[str, Any]] = {}
_CACHE_URLHAUS: Dict[str, Dict[str, Any]] = {}
_THREATFOX_SUPPORTED_TYPES = {"IP", "DOMAIN", "URL", "MD5", "SHA256"}
_URLHAUS_SUPPORTED_TYPES = {"IP", "DOMAIN", "URL", "SHA256"}


def _infer_indicator_type(value: str) -> str:
    value = strip_quotes(value)
    if is_ip(value):
        return "IP"
    if value.startswith(("http://", "https://")):
        return "URL"
    if re.fullmatch(r"[a-fA-F0-9]{32}", value):
        return "MD5"
    if re.fullmatch(r"[a-fA-F0-9]{40}", value):
        return "SSL_SHA1"
    if re.fullmatch(r"[a-fA-F0-9]{64}", value):
        return "SHA256"
    if "." in value and " " not in value and "/" not in value:
        return "DOMAIN"
    return ""


def _supports_threatfox(indicator_type: str) -> bool:
    return strip_quotes(indicator_type).upper() in _THREATFOX_SUPPORTED_TYPES


def _supports_urlhaus(indicator_type: str) -> bool:
    return strip_quotes(indicator_type).upper() in _URLHAUS_SUPPORTED_TYPES


@tool
def threatfox_ioc_lookup(indicator_value: str, indicator_type: str = "") -> str:
    """Query ThreatFox Community API for an IOC/hash and return structured JSON."""
    indicator_value = strip_quotes(indicator_value)
    indicator_type = strip_quotes(indicator_type).upper() or _infer_indicator_type(indicator_value)
    cache_key = f"{indicator_type}::{indicator_value}"
    if cache_key in _CACHE_THREATFOX:
        cached = dict(_CACHE_THREATFOX[cache_key])
        cached["cache_hit"] = True
        return dumps_json(cached)
    if not _supports_threatfox(indicator_type):
        obs = {
            "enabled": True,
            "ok": False,
            "indicator_type": indicator_type,
            "indicator_value": indicator_value,
            "note": f"ThreatFox structured lookup does not support {indicator_type} directly.",
            "skipped": True,
            "source": "threatfox.abuse.ch",
        }
        _CACHE_THREATFOX[cache_key] = obs
        return dumps_json(obs)

    client = ThreatFoxClient()
    obs = client.search_indicator(indicator_value=indicator_value, indicator_type=indicator_type)
    _CACHE_THREATFOX[cache_key] = obs
    return dumps_json(obs)


@tool
def urlhaus_ioc_lookup(indicator_value: str, indicator_type: str = "") -> str:
    """Query URLhaus Community API for a host/url/hash and return structured JSON."""
    indicator_value = strip_quotes(indicator_value)
    indicator_type = strip_quotes(indicator_type).upper() or _infer_indicator_type(indicator_value)
    cache_key = f"{indicator_type}::{indicator_value}"
    if cache_key in _CACHE_URLHAUS:
        cached = dict(_CACHE_URLHAUS[cache_key])
        cached["cache_hit"] = True
        return dumps_json(cached)
    if not _supports_urlhaus(indicator_type):
        obs = {
            "enabled": True,
            "ok": False,
            "indicator_type": indicator_type,
            "indicator_value": indicator_value,
            "note": f"URLhaus structured lookup does not support {indicator_type} directly.",
            "skipped": True,
            "source": "urlhaus.abuse.ch",
        }
        _CACHE_URLHAUS[cache_key] = obs
        return dumps_json(obs)

    client = URLhausClient()
    obs = client.lookup_indicator(indicator_value=indicator_value, indicator_type=indicator_type)
    _CACHE_URLHAUS[cache_key] = obs
    return dumps_json(obs)
