import json
import ipaddress
import re
import urllib.parse
from typing import Any, Dict, List

from langchain_core.tools import tool

from .artifacts import build_topology
from .io import save_text
from .vt_client import VirusTotalClient


def _strip_quotes(s: str) -> str:
    return (s or "").strip().strip('"').strip("'")


_CACHE_VT_IP: Dict[str, Dict[str, Any]] = {}
_CACHE_WEB: Dict[str, Dict[str, Any]] = {}


def _vt_stats_to_confidence(stats: Dict[str, int]) -> int:
    mal = int(stats.get("malicious", 0))
    susp = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    undet = int(stats.get("undetected", 0))
    total = max(1, mal + susp + harmless + undet)
    score = (mal * 1.0 + susp * 0.6) / total
    return int(round(40 + score * 60))


@tool
def vt_enrich_ip(ip: str) -> str:
    """Use VirusTotal to enrich an IP address (IP only). Returns JSON string."""
    ip = _strip_quotes(ip)
    if ip in _CACHE_VT_IP:
        cached = dict(_CACHE_VT_IP[ip])
        cached["cache_hit"] = True
        cached["note"] = cached.get("note") or "cached result; do not query again"
        return json.dumps(cached, ensure_ascii=False)
    try:
        ipaddress.ip_address(ip)
    except Exception:
        return json.dumps({"enabled": False, "error": "invalid ip", "ip": ip}, ensure_ascii=False)
    vt = VirusTotalClient()
    if not vt.enabled():
        obs = {"enabled": False, "note": "VT_API_KEY not set; skipped.", "ip": ip}
        _CACHE_VT_IP[ip] = obs
        return json.dumps(obs, ensure_ascii=False)
    e = vt.enrich_ip(ip)
    obs = {
        "enabled": True,
        "ip": ip,
        "country": e.country,
        "asn": e.asn,
        "as_owner": e.as_owner,
        "reputation": e.reputation,
        "last_analysis_stats": e.stats,
        "confidence": _vt_stats_to_confidence(e.stats),
    }
    _CACHE_VT_IP[ip] = obs
    return json.dumps(obs, ensure_ascii=False)


@tool
def web_search(query: str, max_results: int = 5) -> str:
    """
    Web search tool for JA3 (or any keyword). Returns JSON string.
    Uses SerpAPI (Google) if SERPAPI_API_KEY is set; otherwise falls back to DuckDuckGo.
    """
    query = _strip_quotes(query)
    if query in _CACHE_WEB:
        cached = dict(_CACHE_WEB[query])
        cached["cache_hit"] = True
        cached["note"] = cached.get("note") or "cached result; do not search again"
        return json.dumps(cached, ensure_ascii=False)

    # Prefer SerpAPI when available (more stable than HTML scraping).
    try:
        import os

        serp_key = os.getenv("SERPAPI_API_KEY") or os.getenv("SERP_API_KEY")
    except Exception:
        serp_key = None

    if serp_key:
        try:
            import requests

            resp = requests.get(
                "https://serpapi.com/search.json",
                params={"engine": "google", "q": query, "api_key": serp_key, "num": max_results},
                timeout=25,
            )
            resp.raise_for_status()
            data = resp.json()
            results: List[Dict[str, Any]] = []
            for r in (data.get("organic_results") or [])[:max_results]:
                results.append(
                    {
                        "title": r.get("title"),
                        "url": r.get("link"),
                        "snippet": r.get("snippet"),
                        "source": "serpapi",
                    }
                )
            obs = {"ok": True, "query": query, "results": results, "mode": "serpapi"}
            _CACHE_WEB[query] = obs
            return json.dumps(obs, ensure_ascii=False)
        except Exception as e:
            # Fall through to DuckDuckGo mode
            pass

    try:
        from duckduckgo_search import DDGS
    except Exception as e:
        DDGS = None  # type: ignore[assignment]

    results: List[Dict[str, Any]] = []
    if DDGS is not None:
        try:
            with DDGS() as ddgs:
                for r in ddgs.text(query, max_results=max_results):
                    results.append(
                        {
                            "title": r.get("title"),
                            "url": r.get("href") or r.get("url"),
                            "snippet": r.get("body") or r.get("snippet"),
                        }
                    )
            return json.dumps({"ok": True, "query": query, "results": results, "mode": "ddgs"}, ensure_ascii=False)
        except Exception:
            results = []

    # Fallback: DuckDuckGo HTML (best-effort, no extra deps)
    try:
        import requests

        url = "https://duckduckgo.com/html/?" + urllib.parse.urlencode({"q": query})
        r = requests.get(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123 Safari/537.36"
            },
            timeout=20,
        )
        r.raise_for_status()
        html = r.text

        link_re = re.compile(r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>', re.IGNORECASE)
        snip_re = re.compile(r'<a[^>]+class="result__snippet"[^>]*>(.*?)</a>|<div[^>]+class="result__snippet"[^>]*>(.*?)</div>', re.IGNORECASE)

        def _strip_tags(s: str) -> str:
            s = re.sub(r"<[^>]+>", "", s)
            return re.sub(r"\s+", " ", s).strip()

        links = link_re.findall(html)
        snippets = snip_re.findall(html)

        for i, (href, title_html) in enumerate(links[:max_results]):
            snippet_html = ""
            if i < len(snippets):
                snippet_html = snippets[i][0] or snippets[i][1] or ""
            results.append({"title": _strip_tags(title_html), "url": href, "snippet": _strip_tags(snippet_html)})

        obs = {"ok": True, "query": query, "results": results, "mode": "html_fallback"}
        _CACHE_WEB[query] = obs
        return json.dumps(obs, ensure_ascii=False)
    except Exception as e:
        obs = {"ok": False, "query": query, "error": str(e)}
        _CACHE_WEB[query] = obs
        return json.dumps(obs, ensure_ascii=False)


@tool
def family_intel(family: str, context: str = "", max_results: int = 5) -> str:
    """
    Search & compress malware-family intel into bullet-ready points.
    Intended to enrich reports (e.g., family=Tofsee/Emotet/etc).
    Returns JSON string with short 'highlights'.
    """
    family = _strip_quotes(family)
    context = _strip_quotes(context)
    q = family
    if context:
        q = f"{family} {context}"
    q = f"{q} malware family C2"

    # Call the tool via .invoke() to avoid BaseTool.__call__ kwargs issues.
    raw = json.loads(web_search.invoke({"query": q, "max_results": max_results}))
    if not raw.get("ok"):
        return json.dumps({"ok": False, "family": family, "query": q, "error": raw.get("error"), "raw": raw}, ensure_ascii=False)

    highlights: List[str] = []
    for r in (raw.get("results") or [])[:5]:
        title = (r.get("title") or "").strip()
        snippet = (r.get("snippet") or "").strip()
        url = (r.get("url") or "").strip()
        if title and url:
            highlights.append(f"- {title}（{url}）")
        elif title:
            highlights.append(f"- {title}")
        elif snippet:
            highlights.append(f"- {snippet}")

    return json.dumps({"ok": True, "family": family, "query": q, "highlights": highlights, "raw": raw}, ensure_ascii=False)


@tool
def build_topology_json(event_json: str) -> str:
    """Build topology JSON from event JSON. Returns topology JSON string."""
    event = json.loads(event_json)
    topo = build_topology(event)
    return json.dumps(topo, ensure_ascii=False)


@tool
def save_report_md(out_dir: str, content: str) -> str:
    """Save Markdown report to report.md in out_dir. Returns JSON with path."""
    from pathlib import Path

    out = Path(out_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)
    path = out / "report.md"
    save_text(path, content)
    return json.dumps({"ok": True, "done": True, "path": str(path)}, ensure_ascii=False)

