from __future__ import annotations

import json
import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from typing import Any, Dict, List, Optional, Sequence, Set
from urllib.parse import urlparse

from langchain_core.prompts import ChatPromptTemplate
from pydantic import BaseModel, Field

from ...tools import extract_claim_candidates_from_page, fetch_page_content

LOGGER = logging.getLogger(__name__)

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
_PAGE_SIGNAL_KEYWORDS = (
    "backdoor",
    "banking trojan",
    "browser",
    "c2",
    "command and control",
    "cookie",
    "credential",
    "dll",
    "download",
    "dropper",
    "email",
    "execute",
    "inject",
    "injection",
    "loader",
    "payload",
    "persistence",
    "phishing",
    "proxy",
    "ransomware",
    "rat",
    "self signed tls certificate",
    "steal",
    "stealer",
    "task",
    "wallet",
    "web inject",
)


class PageFindingModel(BaseModel):
    finding: str = Field(default="", description="Concrete page-supported fact in concise English.")


class PageExtractionModel(BaseModel):
    summary: str = Field(default="", description="1-2 sentence English summary of the most relevant page facts.")
    relevance: str = Field(default="", description="Why this page helps explain or support the current alert.")
    key_findings: List[PageFindingModel] = Field(default_factory=list, description="1-3 concrete malware facts grounded in the page excerpt.")
    iocs: List[str] = Field(default_factory=list, description="High-signal IPs, domains, URLs, hashes, JA3/JA4 strings, or named infrastructure clues from the page.")


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


def _line_signal_score(text: str, *, focus: str) -> int:
    lowered = _text(text).lower()
    if not lowered or _is_low_signal_claim(lowered):
        return -10
    score = 0
    focus_l = _text(focus).lower()
    if focus_l and focus_l in lowered:
        score += 6
    keyword_hits = sum(1 for token in _PAGE_SIGNAL_KEYWORDS if token in lowered)
    score += min(8, keyword_hits * 2)
    if re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", lowered):
        score += 2
    if re.search(r"\b[a-fA-F0-9]{32,64}\b", lowered):
        score += 2
    if re.search(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", lowered):
        score += 2
    if 60 <= len(lowered) <= 320:
        score += 2
    if len(lowered) < 35:
        score -= 2
    if lowered.count("|") >= 2:
        score -= 2
    return score


def _select_page_excerpt(content: str, *, focus: str, claims: Sequence[str], max_chars: int = 2600) -> str:
    lines = [_text(line) for line in str(content or "").splitlines()]
    lines = [line for line in lines if 30 <= len(line) <= 420 and not _is_low_signal_claim(line)]
    if not lines:
        return _text(content)[:max_chars].strip()

    chosen: List[tuple[int, str]] = []
    seen: Set[str] = set()
    preferred_lines = list(claims[:3])
    for line in preferred_lines:
        normalized = _text(line)
        if normalized and normalized.lower() not in seen:
            seen.add(normalized.lower())
            chosen.append((0, normalized))

    ranked = sorted(
        ((-_line_signal_score(line, focus=focus), idx, line) for idx, line in enumerate(lines)),
        key=lambda item: (item[0], item[1]),
    )
    for _, idx, line in ranked:
        key = line.lower()
        if key in seen:
            continue
        if _line_signal_score(line, focus=focus) < 2 and len(chosen) >= 4:
            continue
        seen.add(key)
        chosen.append((idx, line))
        if len(chosen) >= 12:
            break

    excerpt_parts: List[str] = []
    total = 0
    for _, line in sorted(chosen, key=lambda item: item[0]):
        if total + len(line) + 1 > max_chars:
            break
        excerpt_parts.append(line)
        total += len(line) + 1
    excerpt = "\n".join(excerpt_parts).strip()
    return excerpt or _text(content)[:max_chars].strip()


def _normalize_page_payload(payload: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(payload, dict):
        return None
    normalized = dict(payload)
    summary = _text(normalized.get("summary") or normalized.get("page_summary") or normalized.get("overview"))
    relevance = _text(normalized.get("relevance") or normalized.get("why_relevant") or normalized.get("alert_relevance"))
    findings_raw = normalized.get("key_findings")
    if findings_raw in (None, "", []):
        findings_raw = normalized.get("findings") or normalized.get("claims") or []
    if isinstance(findings_raw, str):
        findings_raw = [findings_raw]
    findings: List[Dict[str, str]] = []
    for item in list(findings_raw or []):
        if isinstance(item, str):
            text = _text(item)
        elif isinstance(item, dict):
            text = _text(item.get("finding") or item.get("text") or item.get("claim"))
        else:
            text = _text(item)
        if text:
            findings.append({"finding": text})
        if len(findings) >= 3:
            break
    iocs_raw = normalized.get("iocs")
    if iocs_raw in (None, "", []):
        iocs_raw = normalized.get("ioc") or normalized.get("indicators") or []
    if isinstance(iocs_raw, str):
        iocs_raw = [iocs_raw]
    iocs = [_text(item) for item in list(iocs_raw or []) if _text(item)][:6]
    return {
        "summary": summary,
        "relevance": relevance,
        "key_findings": findings,
        "iocs": iocs,
    }


def _llm_target_sort_key(item: Dict[str, Any]) -> tuple[int, int, int, str]:
    kind = _text(item.get("kind"))
    domain = _domain(item.get("url"))
    title = _text(item.get("title")).lower()
    url = _text(item.get("url")).lower()
    penalty = 0
    if kind != "family_intel":
        penalty += 3
    if domain.endswith("abuse.ch") and any(token in url for token in ("/ja3-fingerprints/", "/ssl-certificates/")):
        penalty += 6
    if "fingerprint" in title:
        penalty += 4
    if "threat description" in title or "malware family" in title or "analysis" in title or "malware" in title:
        penalty -= 2
    return (
        penalty,
        0 if _trusted_domain(domain) else 1,
        -int(item.get("weight") or 0),
        title,
    )


def _invoke_page_llm(
    llm: Any,
    messages: Sequence[Any],
    *,
    timeout_s: float,
    label: str,
) -> Optional[PageExtractionModel]:
    if llm is None:
        return None

    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="page-enrichment-llm") as executor:
        future = executor.submit(llm.invoke, list(messages))
        try:
            response = future.result(timeout=timeout_s)
        except FutureTimeoutError:
            future.cancel()
            LOGGER.warning("Page enrichment LLM timed out for %s after %.1fs", label, timeout_s)
            return None
        except Exception as exc:
            LOGGER.warning("Page enrichment LLM failed for %s: %s", label, exc)
            return None

    raw = _text(getattr(response, "content", response))
    if not raw:
        LOGGER.warning("Page enrichment LLM returned empty content for %s", label)
        return None

    decoder = json.JSONDecoder()
    for idx, ch in enumerate(raw):
        if ch not in "{[":
            continue
        try:
            payload, _ = decoder.raw_decode(raw[idx:])
        except json.JSONDecodeError:
            continue
        try:
            normalized = _normalize_page_payload(payload)
            if normalized is None:
                return None
            return PageExtractionModel.model_validate(normalized)
        except Exception as exc:
            LOGGER.warning("Page enrichment JSON validation failed for %s: %s", label, exc)
            return None

    LOGGER.warning("Page enrichment did not receive parseable JSON for %s", label)
    return None


def _extract_with_llm(
    *,
    llm: Any,
    event: Dict[str, Any],
    candidate: Dict[str, Any],
    focus: str,
    page_title: str,
    excerpt: str,
    heuristic_claims: Sequence[str],
    entities: Dict[str, Any],
    timeout_s: float,
) -> Optional[Dict[str, Any]]:
    if not excerpt:
        return None

    event_fp = (event.get("trigger_fingerprint") or {})
    prompt = ChatPromptTemplate.from_messages(
        [
            (
                "system",
                "You extract high-signal malware intelligence from one cleaned web page for an incident report."
                " Ignore navigation menus, cookie banners, marketing CTAs, author bios, legal text, index scaffolding, and other boilerplate."
                " Use only facts that are explicitly supported by the excerpt."
                " Prefer concrete malware capabilities, delivery chain, persistence, credential theft, browser injection, C2 behavior, loader behavior, victims, infrastructure, and timeline clues."
                " Keep technical terms in English and preserve indicators exactly."
                " If the excerpt is generic or too thin, return empty fields instead of guessing."
                " Return exactly one JSON object with keys summary, relevance, key_findings, and iocs."
                ' key_findings must be a list of objects like {{"finding":"..."}} and iocs must be a list of strings.'
                " Keep the JSON compact and limit key_findings to at most 3 items."
                " Do not wrap the JSON in markdown."
            ),
            (
                "user",
                "Alert context:\n"
                "- Focus family or indicator: {focus}\n"
                "- Alert fingerprint: {fp_type} {fp_value}\n"
                "- Source page title: {page_title}\n"
                "- Source name: {source}\n"
                "- URL: {url}\n"
                "- Heuristic claims: {heuristic_claims}\n"
                "- Extracted entities: {entities_json}\n\n"
                "Page excerpt:\n{excerpt}",
            ),
        ]
    )
    messages = prompt.format_messages(
        focus=focus or "unknown",
        fp_type=_text(event_fp.get("type")) or "unknown",
        fp_value=_text(event_fp.get("value")) or "unknown",
        page_title=page_title or _text(candidate.get("title")) or "unknown",
        source=_text(candidate.get("source")) or "unknown",
        url=_text(candidate.get("url")) or "unknown",
        heuristic_claims=" | ".join(_text(item) for item in heuristic_claims if _text(item)) or "none",
        entities_json=json.dumps(entities or {}, ensure_ascii=False),
        excerpt=excerpt,
    )
    result = _invoke_page_llm(
        llm,
        messages,
        timeout_s=timeout_s,
        label=_text(candidate.get("url")) or _text(candidate.get("title")) or "page",
    )
    if result is None:
        return None

    summary = _text(result.summary)
    relevance = _text(result.relevance)
    claims: List[str] = []
    seen: Set[str] = set()
    for item in list(result.key_findings or []):
        text = _text(getattr(item, "finding", ""))
        lowered = text.lower()
        if not text or lowered in seen or _is_low_signal_claim(text):
            continue
        seen.add(lowered)
        claims.append(text)
        if len(claims) >= 3:
            break

    iocs: List[str] = []
    seen_iocs: Set[str] = set()
    for item in list(result.iocs or []):
        value = _text(item)
        if not value:
            continue
        key = value.lower()
        if key in seen_iocs:
            continue
        seen_iocs.add(key)
        iocs.append(value)
        if len(iocs) >= 4:
            break

    if not summary and not claims and not relevance and not iocs:
        return None
    return {
        "summary_hint": summary,
        "claims": claims,
        "relevance": relevance,
        "iocs": iocs,
        "llm_used": True,
    }


def _finalize_item(item: Dict[str, Any]) -> Dict[str, Any]:
    finalized = dict(item)
    finalized.pop("content", None)
    finalized.pop("excerpt", None)
    finalized.pop("heuristic_claims", None)
    return finalized


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
    claim_texts = _select_claim_texts(claims, max_claims=5)
    if not claim_texts:
        claim_texts = _fallback_claims_from_content(content, focus)
    excerpt = _select_page_excerpt(content, focus=focus, claims=claim_texts)

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
        "relevance": "",
        "iocs": [],
        "entities": claims_obs.get("entities") or page.get("entities_hint") or {},
        "chars": int(page.get("chars") or 0),
        "truncated": bool(page.get("truncated")),
        "heuristic_claims": claim_texts,
        "excerpt": excerpt,
        "content": content,
        "llm_used": False,
    }


def enrich_baseline_pages(
    *,
    draft_analysis: Dict[str, Any],
    event: Dict[str, Any],
    llm: Any = None,
    max_pages: int = 4,
    llm_max_pages: int = 1,
    llm_timeout_s: float = 18.0,
    per_page_timeout_s: float = 12.0,
    total_timeout_s: float = 42.0,
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

    llm_count = 0
    if llm is not None:
        successful_items = sorted(
            [item for item in items if item.get("ok") and _text(item.get("excerpt"))],
            key=_llm_target_sort_key,
        )
        deadline = started + total_timeout_s
        for item in successful_items[: max(0, llm_max_pages)]:
            remaining = max(0.5, deadline - time.perf_counter())
            if remaining <= 0.5:
                break
            llm_result = _extract_with_llm(
                llm=llm,
                event=event,
                candidate=item,
                focus=focus,
                page_title=_text(item.get("page_title") or item.get("title")),
                excerpt=_text(item.get("excerpt")),
                heuristic_claims=list(item.get("heuristic_claims") or []),
                entities=item.get("entities") or {},
                timeout_s=min(llm_timeout_s, remaining),
            )
            if not llm_result:
                continue
            summary_hint = _text(llm_result.get("summary_hint")) or _text(item.get("summary_hint"))
            claims = [text for text in list(llm_result.get("claims") or []) if _text(text)]
            if not claims:
                claims = list(item.get("claims") or [])
            item["summary_hint"] = summary_hint
            item["claims"] = claims[:5]
            item["relevance"] = _text(llm_result.get("relevance"))
            item["iocs"] = list(llm_result.get("iocs") or [])[:6]
            item["llm_used"] = bool(llm_result.get("llm_used"))
            item["ok"] = bool(summary_hint or item["claims"])
            llm_count += 1

    return {
        "ok": True,
        "focus": focus,
        "items": [_finalize_item(item) for item in items],
        "selected_urls": [candidate["url"] for candidate in candidates],
        "timings": {
            "page_enrichment_s": round(time.perf_counter() - started, 4),
            "page_enrichment_count": len(candidates),
            "page_enrichment_llm_count": llm_count,
        },
    }
