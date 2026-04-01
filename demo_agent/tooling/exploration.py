from __future__ import annotations

from typing import Any, Dict, List

from langchain_core.tools import tool

from .common import dumps_json, extract_text_entities, fetch_page, merge_search_observations, search_web, strip_quotes


@tool
def advanced_web_search(query: str, constraint: str = "", max_results: int = 5) -> str:
    """Advanced web search with optional site/domain constraint for React exploration."""
    obs = search_web(query=strip_quotes(query), constraint=strip_quotes(constraint), max_results=max_results)
    return dumps_json(obs)


@tool
def fetch_page_content(url: str, max_chars: int = 6000) -> str:
    """Fetch page body text with cleanup and truncation. Returns JSON string."""
    return dumps_json(fetch_page(url=strip_quotes(url), max_chars=max_chars))


@tool
def extract_entities_from_page(content: str) -> str:
    """Extract related indicators and entities from page content. Returns JSON string."""
    entities = extract_text_entities(content)
    return dumps_json({"ok": True, "entities": entities})


@tool
def pivot_related_indicators(indicator_or_family: str, max_results: int = 5) -> str:
    """Search for secondary infrastructure or related indicators around an IOC/family."""
    seed = strip_quotes(indicator_or_family)
    searches = [
        search_web(query=f"{seed} related indicators C2 infrastructure", max_results=max_results),
        search_web(
            query=f"{seed} IOC malware infrastructure",
            constraint="site:abuse.ch OR site:threatfox.abuse.ch OR site:urlhaus.abuse.ch OR site:any.run",
            max_results=max_results,
        ),
    ]
    merged = merge_search_observations(*searches)
    return dumps_json(merged)


@tool
def malware_profile_lookup(family: str, max_results: int = 5) -> str:
    """Fetch high-quality family profile references for deep investigation."""
    family = strip_quotes(family)
    searches: List[Dict[str, Any]] = [
        search_web(
            query=f"{family} malware family profile",
            constraint="site:malpedia.caad.fkie.fraunhofer.de OR site:microsoft.com OR site:mitre.org OR site:trendmicro.com OR site:proofpoint.com OR site:checkpoint.com",
            max_results=max_results,
        ),
        search_web(query=f"{family} malware TTP", max_results=max_results),
    ]
    merged = merge_search_observations(*searches)
    return dumps_json({"ok": merged.get("ok", False), "family": family, "query": family, "results": merged.get("results", []), "mode": merged.get("mode")})
