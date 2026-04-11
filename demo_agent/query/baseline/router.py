from __future__ import annotations

from typing import Any, Callable, Dict

from .domain_url import investigate_domain_or_url
from .fingerprint import investigate_fingerprint
from .ip import investigate_ip


InvestigatorFn = Callable[[Dict[str, Any]], Dict[str, Any]]


def get_investigator(indicator_type: str) -> InvestigatorFn:
    normalized = str(indicator_type or "").strip().upper()
    if normalized == "IP":
        return investigate_ip
    if normalized in {"JA3", "JA4", "SSL_SHA1", "CERT_SHA1"}:
        return investigate_fingerprint
    if normalized in {"DOMAIN", "URL"}:
        return investigate_domain_or_url
    return investigate_domain_or_url
