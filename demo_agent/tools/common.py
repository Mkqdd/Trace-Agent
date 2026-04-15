from __future__ import annotations

import ipaddress
import json
import re
import urllib.parse
from html import unescape
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, unquote, urlparse

import requests
try:
    from bs4 import BeautifulSoup
except Exception:  # pragma: no cover - optional dependency fallback
    BeautifulSoup = None  # type: ignore[assignment]


_CACHE_VT_IP: Dict[str, Dict[str, Any]] = {}
_CACHE_WEB: Dict[str, Dict[str, Any]] = {}
_CACHE_LOCAL_INTEL: Dict[str, Dict[str, Any]] = {}
_CACHE_PAGE: Dict[str, Dict[str, Any]] = {}
_CONTENT_SELECTORS = (
    "article",
    "main",
    "[role='main']",
    "[itemprop='articleBody']",
    ".article-body",
    ".article-content",
    ".entry-content",
    ".post-content",
    ".post-body",
    ".threat-library",
    ".main-content",
    "#main-content",
    "#main",
)
_BOILERPLATE_LINE_PARTS = (
    "get a demo",
    "start for free",
    "portal login",
    "investor relations",
    "choose your language",
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
    "all rights reserved",
    "privacy policy",
    "cookie policy",
    "accept cookies",
    "terms of use",
)
_NAV_LINE_WORDS = {
    "about",
    "awards",
    "blog",
    "careers",
    "company",
    "contact",
    "demo",
    "documentation",
    "download",
    "free",
    "home",
    "integrations",
    "investor",
    "language",
    "leadership",
    "login",
    "newsroom",
    "portal",
    "pricing",
    "products",
    "report",
    "search",
    "services",
    "solutions",
    "start",
    "support",
    "team",
}
_NON_DOMAIN_TLDS = {
    "apk",
    "bat",
    "bin",
    "cfg",
    "cmd",
    "csv",
    "dat",
    "dll",
    "doc",
    "docx",
    "exe",
    "gif",
    "hta",
    "html",
    "ini",
    "jar",
    "jpg",
    "js",
    "json",
    "log",
    "msi",
    "pdf",
    "php",
    "png",
    "ps1",
    "rar",
    "rtf",
    "sh",
    "svg",
    "sys",
    "tar",
    "txt",
    "vbs",
    "xml",
    "yaml",
    "yml",
    "zip",
}


def _direct_session() -> requests.Session:
    session = requests.Session()
    session.trust_env = False
    return session


def strip_quotes(value: str) -> str:
    return (value or "").strip().strip('"').strip("'")


def clean_text(value: Any) -> str:
    text = unescape(str(value or ""))
    text = re.sub(r"\s+", " ", text).strip()
    return text


def normalize_url(url: Any) -> Optional[str]:
    text = clean_text(url)
    if not text:
        return None
    if text.startswith("//"):
        text = f"https:{text}"
    parsed = urlparse(text)
    if "duckduckgo.com" in (parsed.netloc or ""):
        uddg = parse_qs(parsed.query).get("uddg")
        if uddg:
            target = clean_text(unquote(uddg[0]))
            if target.startswith("//"):
                target = f"https:{target}"
            return target
    return text


def _looks_like_boilerplate_line(text: str) -> bool:
    normalized = clean_text(text)
    lowered = normalized.lower()
    if not lowered:
        return True
    if any(part in lowered for part in _BOILERPLATE_LINE_PARTS):
        return True
    words = re.findall(r"[a-zA-Z]+", lowered)
    if len(words) >= 8:
        nav_hits = sum(1 for word in words if word in _NAV_LINE_WORDS)
        if nav_hits / max(len(words), 1) >= 0.45:
            return True
    if len(words) >= 6 and len(set(words)) <= max(3, len(words) // 4):
        return True
    return False


def _filtered_page_lines(text: str) -> List[str]:
    lines: List[str] = []
    seen = set()
    for raw_line in re.split(r"\n+", str(text or "")):
        line = clean_text(raw_line)
        if not line:
            continue
        if _looks_like_boilerplate_line(line):
            continue
        key = line.lower()
        if key in seen:
            continue
        seen.add(key)
        lines.append(line)
    return lines


def _page_text_from_node(node: Any) -> str:
    if node is None:
        return ""
    return node.get_text(separator="\n", strip=True)


def _select_best_content_node(soup: Any) -> Any:
    body = soup.body or soup
    best_node = None
    best_score = 0
    seen = set()
    for selector in _CONTENT_SELECTORS:
        for node in soup.select(selector):
            node_id = id(node)
            if node_id in seen:
                continue
            seen.add(node_id)
            filtered = _filtered_page_lines(_page_text_from_node(node))
            if not filtered:
                continue
            score = sum(len(item) for item in filtered)
            if score > best_score:
                best_score = score
                best_node = node
    return best_node or body


def merge_search_observations(*observations: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    merged_results: List[Dict[str, Any]] = []
    query_parts: List[str] = []
    modes: List[str] = []
    ok = False
    errors: List[str] = []
    seen = set()

    for obs in observations:
        if not isinstance(obs, dict):
            continue
        ok = ok or bool(obs.get("ok"))
        query = clean_text(obs.get("query"))
        if query:
            query_parts.append(query)
        mode = clean_text(obs.get("mode"))
        if mode:
            modes.append(mode)
        error = clean_text(obs.get("error"))
        if error:
            errors.append(error)
        for item in list(obs.get("results") or []):
            title = clean_text(item.get("title"))
            url = normalize_url(item.get("url"))
            snippet = clean_text(item.get("snippet"))
            source = clean_text(item.get("source"))
            key = (title, url, snippet)
            if key in seen:
                continue
            seen.add(key)
            merged_item = {
                "title": title,
                "url": url,
                "snippet": snippet,
                "source": source,
            }
            for extra_key in (
                "family",
                "confidence",
                "tags",
                "host",
                "ioc",
                "indicator_type",
                "malware_label",
                "reference",
                "malpedia_url",
                "signature",
            ):
                if item.get(extra_key) not in (None, "", [], {}):
                    merged_item[extra_key] = item.get(extra_key)
            merged_results.append(merged_item)

    merged: Dict[str, Any] = {
        "ok": ok or bool(merged_results),
        "query": " | ".join(part for part in query_parts if part),
        "results": merged_results,
    }
    if modes:
        merged["mode"] = ",".join(dict.fromkeys(modes))
    if errors and not merged["ok"]:
        merged["error"] = " | ".join(errors)
    return merged


def vt_stats_to_confidence(stats: Dict[str, int]) -> int:
    mal = int(stats.get("malicious", 0))
    susp = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    undet = int(stats.get("undetected", 0))
    total = max(1, mal + susp + harmless + undet)
    score = (mal * 1.0 + susp * 0.6) / total
    return int(round(40 + score * 60))


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(strip_quotes(value))
        return True
    except Exception:
        return False


def search_web(query: str, max_results: int = 5, *, constraint: str = "") -> Dict[str, Any]:
    query = strip_quotes(query)
    constraint = strip_quotes(constraint)
    full_query = " ".join(part for part in [constraint, query] if part).strip()
    cache_key = f"{full_query}::{max_results}"
    if cache_key in _CACHE_WEB:
        cached = dict(_CACHE_WEB[cache_key])
        cached["cache_hit"] = True
        cached["note"] = cached.get("note") or "cached result; do not search again"
        return cached

    try:
        import os

        serp_key = os.getenv("SERPAPI_API_KEY") or os.getenv("SERP_API_KEY")
    except Exception:
        serp_key = None

    if serp_key:
        try:
            with _direct_session() as session:
                resp = session.get(
                "https://serpapi.com/search.json",
                params={"engine": "google", "q": full_query, "api_key": serp_key, "num": max_results},
                timeout=25,
                )
            resp.raise_for_status()
            data = resp.json()
            results: List[Dict[str, Any]] = []
            for item in (data.get("organic_results") or [])[:max_results]:
                results.append(
                    {
                        "title": clean_text(item.get("title")),
                        "url": normalize_url(item.get("link")),
                        "snippet": clean_text(item.get("snippet")),
                        "source": "serpapi",
                    }
                )
            obs = {"ok": True, "query": full_query, "results": results, "mode": "serpapi", "constraint": constraint or None}
            _CACHE_WEB[cache_key] = obs
            return obs
        except Exception:
            pass

    try:
        from duckduckgo_search import DDGS
    except Exception:
        DDGS = None  # type: ignore[assignment]

    if DDGS is not None:
        try:
            results = []
            with DDGS() as ddgs:
                for item in ddgs.text(full_query, max_results=max_results):
                    results.append(
                        {
                            "title": clean_text(item.get("title")),
                            "url": normalize_url(item.get("href") or item.get("url")),
                            "snippet": clean_text(item.get("body") or item.get("snippet")),
                            "source": "ddgs",
                        }
                    )
            obs = {"ok": True, "query": full_query, "results": results, "mode": "ddgs", "constraint": constraint or None}
            _CACHE_WEB[cache_key] = obs
            return obs
        except Exception:
            pass

    try:
        url = "https://duckduckgo.com/html/?" + urllib.parse.urlencode({"q": full_query})
        with _direct_session() as session:
            resp = session.get(
                url,
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 (Macintosh; Intel Mac OS X) AppleWebKit/537.36 "
                        "(KHTML, like Gecko) Chrome/123 Safari/537.36"
                    )
                },
                timeout=20,
            )
        resp.raise_for_status()
        html = resp.text
        link_re = re.compile(r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>', re.IGNORECASE)
        snip_re = re.compile(
            r'<a[^>]+class="result__snippet"[^>]*>(.*?)</a>|<div[^>]+class="result__snippet"[^>]*>(.*?)</div>',
            re.IGNORECASE,
        )

        def strip_tags(text: str) -> str:
            return clean_text(re.sub(r"<[^>]+>", "", text))

        links = link_re.findall(html)
        snippets = snip_re.findall(html)
        results: List[Dict[str, Any]] = []
        for index, (href, title_html) in enumerate(links[:max_results]):
            snippet_html = ""
            if index < len(snippets):
                snippet_html = snippets[index][0] or snippets[index][1] or ""
            results.append(
                {
                    "title": strip_tags(title_html),
                    "url": normalize_url(href),
                    "snippet": strip_tags(snippet_html),
                    "source": "html_fallback",
                }
            )
        obs = {"ok": True, "query": full_query, "results": results, "mode": "html_fallback", "constraint": constraint or None}
        _CACHE_WEB[cache_key] = obs
        return obs
    except Exception as exc:
        obs = {"ok": False, "query": full_query, "constraint": constraint or None, "error": str(exc)}
        _CACHE_WEB[cache_key] = obs
        return obs


def fetch_page(url: str, *, max_chars: int = 6000, timeout_s: int = 20) -> Dict[str, Any]:
    normalized = normalize_url(url)
    if not normalized:
        return {"ok": False, "url": url, "error": "invalid url"}
    cache_key = f"{normalized}::{max_chars}"
    if cache_key in _CACHE_PAGE:
        cached = dict(_CACHE_PAGE[cache_key])
        cached["cache_hit"] = True
        return cached

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/123 Safari/537.36"
        )
    }
    try:
        with _direct_session() as session:
            resp = session.get(normalized, headers=headers, timeout=timeout_s)
        resp.raise_for_status()
        html = resp.text
    except Exception as exc:
        obs = {"ok": False, "url": normalized, "error": str(exc)}
        _CACHE_PAGE[cache_key] = obs
        return obs

    title_match = re.search(r"<title[^>]*>(.*?)</title>", html, flags=re.IGNORECASE | re.DOTALL)
    title = clean_text(title_match.group(1)) if title_match else ""
    max_chars = max(1000, min(int(max_chars or 6000), 8000))

    if BeautifulSoup is not None:
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup(["script", "style", "noscript", "svg", "nav", "footer", "header", "aside"]):
            tag.decompose()
        root = _select_best_content_node(soup)
        lines = _filtered_page_lines(_page_text_from_node(root))
        if sum(len(item) for item in lines) < 400:
            fallback_lines = _filtered_page_lines(_page_text_from_node(soup.body or soup))
            if sum(len(item) for item in fallback_lines) > sum(len(item) for item in lines):
                lines = fallback_lines
        text = "\n".join(lines).strip()
    else:
        text = re.sub(r"(?is)<script.*?>.*?</script>", " ", html)
        text = re.sub(r"(?is)<style.*?>.*?</style>", " ", text)
        text = re.sub(r"(?is)<noscript.*?>.*?</noscript>", " ", text)
        text = re.sub(r"(?is)<svg.*?>.*?</svg>", " ", text)
        text = re.sub(r"(?is)<[^>]+>", " ", text)
        text = "\n".join(_filtered_page_lines(text))

    truncated = len(text) > max_chars
    content = text[:max_chars].rstrip()
    obs = {
        "ok": True,
        "url": normalized,
        "title": title,
        "content": content,
        "chars": len(content),
        "truncated": truncated,
        "status_code": resp.status_code,
    }
    _CACHE_PAGE[cache_key] = obs
    return obs


def extract_text_entities(text: str) -> Dict[str, List[str]]:
    content = clean_text(text)
    ips = sorted(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", content)))
    urls = sorted(set(re.findall(r"https?://[^\s)>\"]+", content)))
    sha256 = sorted(set(re.findall(r"\b[a-fA-F0-9]{64}\b", content)))
    sha1 = sorted(set(re.findall(r"\b[a-fA-F0-9]{40}\b", content)))
    md5 = sorted(set(re.findall(r"\b[a-fA-F0-9]{32}\b", content)))
    domains = []
    for match in re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", content):
        tld = match.rsplit(".", 1)[-1].lower()
        if not is_ip(match) and tld not in _NON_DOMAIN_TLDS:
            domains.append(match.lower())
    return {
        "ips": ips[:20],
        "domains": sorted(set(domains))[:20],
        "urls": urls[:20],
        "sha256": sha256[:20],
        "sha1": sha1[:20],
        "md5": md5[:20],
    }


def dumps_json(payload: Dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False)
