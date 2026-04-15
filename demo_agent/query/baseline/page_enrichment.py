from __future__ import annotations

import json
import re
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from typing import Any, Dict, List, Optional, Sequence, Set
from urllib.parse import urlparse

from ...tools import extract_claim_candidates_from_page, fetch_page_content

_TRUSTED_MULTI_DOC_DOMAINS = {
    "microsoft.com",
    "malpedia.caad.fkie.fraunhofer.de",
    "checkpoint.com",
    "trendmicro.com",
    "proofpoint.com",
    "abuse.ch",
    "huntress.com",
    "malwarebytes.com",
}
_SKIP_EXACT_URL_SUFFIXES = {
    "/ssl-certificates/",
    "/blacklist/sslblacklist.csv",
    "/blacklist/ja3_fingerprints.rules",
}
_SKIP_TITLE_PARTS = {
    "malicious ssl certificates",
    "download ja3 ids ruleset (suricata 4.1.0 or newer)",
}
_KIND_PRIORITY = {
    "ttp": 0,
    "family_or_indicator": 1,
    "ioc": 2,
    "context": 3,
}
_LOW_SIGNAL_CLAIM_PARTS = (
    "get a demo",
    "start for free",
    "portal login",
    "integrations integrations",
    "support documentation",
    "see huntress in action",
    "meet the team",
    "founded by former",
    "awards awards",
    "contact us",
    "search get a demo",
    "support blog",
    "sign up now",
    "download report",
    "choose your language",
)


def _text(value: Any) -> str:
    return str(value or "").strip()


def _normalize_url(url: Any) -> str:
    text = _text(url)
    return text


def _domain(url: Any) -> str:
    normalized = _normalize_url(url)
    if not normalized:
        return ""
    domain = urlparse(normalized).netloc.lower().strip()
    if domain.startswith("www."):
        domain = domain[4:]
    return domain


def _trusted_domain(domain: str) -> bool:
    return any(domain == item or domain.endswith(f".{item}") for item in _TRUSTED_MULTI_DOC_DOMAINS)


def _skip_candidate(item: Dict[str, Any]) -> bool:
    url = _normalize_url(item.get("url"))
    title = _text(item.get("title")).lower()
    if not url:
        return True
    if any(url.lower().endswith(suffix) for suffix in _SKIP_EXACT_URL_SUFFIXES):
        return True
    if title in _SKIP_TITLE_PARTS:
        return True
    return False


def _candidate_sort_key(item: Dict[str, Any]) -> tuple[int, int, int, str]:
    kind_priority = {
        "family_intel": 0,
        "search_result": 1,
        "supplemental": 2,
    }
    domain = _domain(item.get("url"))
    trusted = 1 if _trusted_domain(domain) else 0
    return (
        kind_priority.get(_text(item.get("kind")), 9),
        -int(item.get("weight") or 0),
        -trusted,
        _text(item.get("title")),
    )


def _candidate_urls(draft_analysis: Dict[str, Any], *, limit: int = 4) -> List[Dict[str, Any]]:
    evidence = list(draft_analysis.get("evidence") or [])
    selected: List[Dict[str, Any]] = []
    seen_keys: Set[str] = set()
    per_domain: Dict[str, int] = {}
    for item in sorted(evidence, key=_candidate_sort_key):
        if _text(item.get("kind")) not in {"search_result", "family_intel"}:
            continue
        if not bool(item.get("is_reportable")):
            continue
        if _text(item.get("evidence_tier")) == "noisy":
            continue
        if _skip_candidate(item):
            continue

        url = _normalize_url(item.get("url"))
        if not url:
            continue
        key = url
        if key in seen_keys:
            continue

        domain = _domain(url)
        domain_limit = 2 if _trusted_domain(domain) else 1
        if domain and per_domain.get(domain, 0) >= domain_limit:
            continue

        selected.append(
            {
                "url": url,
                "title": _text(item.get("title")),
                "source": _text(item.get("source")),
                "kind": _text(item.get("kind")),
                "weight": int(item.get("weight") or 0),
                "raw_ref": _text(item.get("raw_ref")),
            }
        )
        seen_keys.add(key)
        if domain:
            per_domain[domain] = per_domain.get(domain, 0) + 1
        if len(selected) >= limit:
            break
    return selected


def _split_sentences(text: str) -> List[str]:
    content = _text(text).replace("\r", "\n")
    chunks = []
    start = 0
    for idx, ch in enumerate(content):
        if ch in "。！？.!?\n":
            piece = content[start : idx + 1].strip()
            if piece:
                chunks.append(piece)
            start = idx + 1
    if start < len(content):
        tail = content[start:].strip()
        if tail:
            chunks.append(tail)
    return [item for item in chunks if 25 <= len(item) <= 420]


def _is_low_signal_claim(text: str) -> bool:
    lowered = _text(text).lower()
    if not lowered:
        return True
    if any(part in lowered for part in _LOW_SIGNAL_CLAIM_PARTS):
        return True
    words = re.findall(r"[a-zA-Z]+", lowered)
    if len(words) >= 8 and len(set(words)) <= max(3, len(words) // 4):
        return True
    return False


def _select_claim_texts(claims: Sequence[Dict[str, Any]], *, max_claims: int = 3) -> List[str]:
    ranked = sorted(
        claims,
        key=lambda item: (
            -int(item.get("score") or 0),
            _KIND_PRIORITY.get(_text(item.get("kind")), 9),
            -len(_text(item.get("text"))),
            _text(item.get("text")),
        ),
    )
    selected: List[str] = []
    seen: Set[str] = set()
    for item in ranked:
        text = _text(item.get("text"))
        if not text or text in seen or _is_low_signal_claim(text):
            continue
        seen.add(text)
        selected.append(text)
        if len(selected) >= max_claims:
            break
    return selected


def _fallback_claims_from_content(content: str, focus: str) -> List[str]:
    sentences = _split_sentences(content)
    if not sentences:
        return []
    focus_l = _text(focus).lower()
    preferred: List[str] = []
    secondary: List[str] = []
    for sentence in sentences:
        if _is_low_signal_claim(sentence):
            continue
        lowered = sentence.lower()
        if focus_l and focus_l in lowered:
            preferred.append(sentence)
            continue
        if any(token in lowered for token in ("spread", "propagate", "infect", "steal", "credential", "command", "control", "backdoor", "rat", "payload", "impact", "download", "browser", "wallet")):
            secondary.append(sentence)
    merged = preferred[:2] + secondary[:2]
    if merged:
        return merged[:3]
    return sentences[:2]


def _fetch_and_extract(candidate: Dict[str, Any], *, focus: str, max_chars: int = 7000) -> Dict[str, Any]:
    page = json.loads(fetch_page_content.invoke({"url": candidate["url"], "max_chars": max_chars}))
    if not page.get("ok") or not _text(page.get("content")):
        return {
            "ok": False,
            "url": candidate["url"],
            "title": candidate.get("title"),
            "source": candidate.get("source"),
            "page_fetch_ok": False,
            "error": _text(page.get("error")) or "fetch_failed",
        }

    content = _text(page.get("content"))
    claims_obs = json.loads(extract_claim_candidates_from_page.invoke({"content": content, "focus": focus}))
    claims = list(claims_obs.get("claims") or [])
    claim_texts = _select_claim_texts(claims, max_claims=3)
    if not claim_texts:
        claim_texts = _fallback_claims_from_content(content, focus)

    summary_hint = " ".join(claim_texts[:3]).strip()
    return {
        "ok": bool(summary_hint),
        "url": candidate["url"],
        "title": candidate.get("title") or page.get("title"),
        "page_title": _text(page.get("title")),
        "source": candidate.get("source"),
        "kind": candidate.get("kind"),
        "raw_ref": candidate.get("raw_ref"),
        "page_fetch_ok": True,
        "summary_hint": summary_hint,
        "claims": claim_texts,
        "entities": claims_obs.get("entities") or page.get("entities_hint") or {},
        "chars": int(page.get("chars") or 0),
        "truncated": bool(page.get("truncated")),
    }


def enrich_baseline_pages(
    *,
    draft_analysis: Dict[str, Any],
    event: Dict[str, Any],
    max_pages: int = 4,
    per_page_timeout_s: float = 12.0,
    total_timeout_s: float = 28.0,
) -> Dict[str, Any]:
    started = time.perf_counter()
    fp = (event.get("trigger_fingerprint") or {})
    focus = _text((draft_analysis.get("assessment") or {}).get("family"))
    if not focus or focus == "Unknown":
        focus = _text(fp.get("value"))

    candidates = _candidate_urls(draft_analysis, limit=max_pages)
    if not candidates:
        return {"ok": True, "items": [], "timings": {"page_enrichment_s": 0.0}, "focus": focus}

    items: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=min(len(candidates), 3)) as executor:
        future_map = {
            executor.submit(_fetch_and_extract, candidate, focus=focus): candidate
            for candidate in candidates
        }
        deadline = time.perf_counter() + total_timeout_s
        for future, candidate in list(future_map.items()):
            remaining = max(0.1, min(per_page_timeout_s, deadline - time.perf_counter()))
            try:
                result = future.result(timeout=remaining)
            except FutureTimeoutError:
                future.cancel()
                result = {
                    "ok": False,
                    "url": candidate["url"],
                    "title": candidate.get("title"),
                    "source": candidate.get("source"),
                    "kind": candidate.get("kind"),
                    "raw_ref": candidate.get("raw_ref"),
                    "page_fetch_ok": False,
                    "error": "timeout",
                }
            except Exception as exc:  # pragma: no cover - defensive runtime path
                result = {
                    "ok": False,
                    "url": candidate["url"],
                    "title": candidate.get("title"),
                    "source": candidate.get("source"),
                    "kind": candidate.get("kind"),
                    "raw_ref": candidate.get("raw_ref"),
                    "page_fetch_ok": False,
                    "error": str(exc),
                }
            items.append(result)
            if time.perf_counter() >= deadline:
                break

    return {
        "ok": True,
        "focus": focus,
        "items": items,
        "selected_urls": [candidate["url"] for candidate in candidates],
        "timings": {
            "page_enrichment_s": round(time.perf_counter() - started, 4),
            "page_enrichment_count": len(candidates),
        },
    }
