from __future__ import annotations

import re
from typing import Any, Dict, List

from langchain_core.tools import tool

from .common import clean_text, dumps_json, extract_text_entities, fetch_page, merge_search_observations, search_web, strip_quotes


@tool
def advanced_web_search(query: str, constraint: str = "", max_results: int = 5) -> str:
    """Advanced web search with optional site/domain constraint for React exploration."""
    obs = search_web(query=strip_quotes(query), constraint=strip_quotes(constraint), max_results=max_results)
    return dumps_json(obs)


@tool
def fetch_page_content(url: str, max_chars: int = 6000) -> str:
    """Fetch page body text with cleanup and truncation. Returns JSON string."""
    page = fetch_page(url=strip_quotes(url), max_chars=max_chars)
    if page.get("ok") and page.get("content"):
        page["entities_hint"] = extract_text_entities(str(page.get("content") or ""))
    return dumps_json(page)


@tool
def extract_entities_from_page(content: str) -> str:
    """Extract related indicators and entities from page content. Returns JSON string."""
    entities = extract_text_entities(content)
    return dumps_json({"ok": True, "entities": entities})


_TECHNICAL_SEARCH_PRESETS = {
    "family_attribution": [
        (
            "{seed} malware family",
            "site:threatfox.abuse.ch OR site:any.run OR site:bazaar.abuse.ch OR site:urlhaus.abuse.ch OR "
            "site:malpedia.caad.fkie.fraunhofer.de OR site:virustotal.com",
        ),
        (
            "{seed} malware",
            "site:any.run OR site:threatfox.abuse.ch OR site:bazaar.abuse.ch OR site:virustotal.com",
        ),
        (
            "{seed} malware report",
            "filetype:pdf",
        ),
    ],
    "behavior_context": [
        (
            "{seed} malware TTP persistence injection C2",
            "site:mitre.org OR site:malpedia.caad.fkie.fraunhofer.de OR site:microsoft.com OR "
            "site:trendmicro.com OR site:proofpoint.com OR site:checkpoint.com OR site:any.run",
        ),
        (
            "{seed} malware report",
            "filetype:pdf",
        ),
    ],
    "infra_context": [
        (
            "{seed} IOC infrastructure C2",
            "site:threatfox.abuse.ch OR site:urlhaus.abuse.ch OR site:bazaar.abuse.ch OR "
            "site:any.run OR site:virustotal.com",
        ),
        (
            "{seed} related domain malware",
            "site:any.run OR site:abuse.ch OR site:virustotal.com",
        ),
    ],
}

_CLAIM_KEYWORDS = (
    "persistence",
    "inject",
    "injection",
    "scheduled task",
    "registry",
    "service",
    "dll",
    "loader",
    "stealer",
    "rat",
    "backdoor",
    "c2",
    "command and control",
    "beacon",
    "phishing",
    "exfil",
    "download",
    "powershell",
    "credential",
    "botnet",
    "ttp",
)


def _split_sentences(content: str) -> List[str]:
    text = str(content or "").replace("\r", "\n")
    chunks = re.split(r"(?<=[。！？.!?])\s+|\n+", text)
    sentences: List[str] = []
    for chunk in chunks:
        sentence = clean_text(chunk)
        if 20 <= len(sentence) <= 500:
            sentences.append(sentence)
    return sentences


def _claim_kind(sentence: str, entities: Dict[str, List[str]], focus: str) -> str:
    lowered = sentence.lower()
    focus_text = focus.lower().strip()
    if any(values for values in entities.values()):
        return "ioc"
    if focus_text and focus_text in lowered:
        return "family_or_indicator"
    if any(keyword in lowered for keyword in _CLAIM_KEYWORDS):
        return "ttp"
    return "context"


@tool
def technical_source_search(query: str, goal: str = "family_attribution", max_results: int = 6) -> str:
    """Search curated technical sources for family attribution, behavior, or infrastructure context."""
    seed = strip_quotes(query)
    goal = strip_quotes(goal).lower() or "family_attribution"
    presets = _TECHNICAL_SEARCH_PRESETS.get(goal) or _TECHNICAL_SEARCH_PRESETS["family_attribution"]

    searches: List[Dict[str, Any]] = []
    per_query_results = max(3, min(int(max_results or 6), 8))
    for query_template, constraint in presets:
        searches.append(
            search_web(
                query=query_template.format(seed=seed),
                constraint=constraint,
                max_results=per_query_results,
            )
        )
    fallback_query = {
        "family_attribution": f"{seed} malware family",
        "behavior_context": f"{seed} malware TTP behavior",
        "infra_context": f"{seed} malware infrastructure IOC",
    }.get(goal, f"{seed} malware family")
    searches.append(search_web(query=fallback_query, max_results=per_query_results))

    merged = merge_search_observations(*searches)
    return dumps_json(
        {
            "ok": merged.get("ok", False),
            "seed": seed,
            "goal": goal,
            "query": merged.get("query"),
            "results": merged.get("results", []),
            "mode": merged.get("mode"),
            "strategy": "technical_source_search",
        }
    )


@tool
def extract_claim_candidates_from_page(content: str, focus: str = "") -> str:
    """Extract concrete claim sentences, TTP hints, and secondary IOCs from page text."""
    text = str(content or "")
    focus = strip_quotes(focus)
    sentences = _split_sentences(text)
    seen = set()
    claims: List[Dict[str, Any]] = []

    for sentence in sentences:
        lowered = sentence.lower()
        if focus and focus.lower() not in lowered and not any(keyword in lowered for keyword in _CLAIM_KEYWORDS):
            entities = extract_text_entities(sentence)
            if not any(values for values in entities.values()):
                continue
        entities = extract_text_entities(sentence)
        kind = _claim_kind(sentence, entities, focus)
        key = (kind, sentence)
        if key in seen:
            continue
        seen.add(key)
        claims.append(
            {
                "kind": kind,
                "text": sentence,
                "entities": entities,
            }
        )
        if len(claims) >= 8:
            break

    return dumps_json(
        {
            "ok": True,
            "focus": focus,
            "claims": claims,
            "entities": extract_text_entities(text),
        }
    )


@tool
def pivot_related_indicators(query: str, max_results: int = 5) -> str:
    """Search for secondary infrastructure or related indicators around an IOC/family."""
    seed = strip_quotes(query)
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
def malware_profile_lookup(query: str, max_results: int = 5) -> str:
    """Fetch high-quality family profile references for deep investigation."""
    family = strip_quotes(query)
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
