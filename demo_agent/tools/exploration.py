from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
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
    "allows",
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
    "downloader",
    "dropper",
    "execute",
    "execution",
    "remote access",
    "remote control",
    "powershell",
    "credential",
    "cookies",
    "wallet",
    "browser",
    "token",
    "ransomware",
    "infostealer",
    "steal",
    "stealer",
    "exfiltrate",
    "exfiltration",
    "loader",
    "phishing",
    "botnet",
    "ttp",
)
_CLAIM_SIGNAL_PARTS = (
    "is a",
    "is an",
    "used to",
    "capable of",
    "used by",
    "allows attackers",
    "allows the attacker",
    "can ",
    "targets",
    "steals",
    "collects",
    "downloads",
    "drops",
    "communicates",
    "connects",
    "delivers",
    "installs",
    "executes",
    "loads",
)
_BOILERPLATE_SENTENCE_PARTS = (
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
    "privacy policy",
    "cookie policy",
    "what to do now",
)


def _parallel_search_web(search_specs: List[Dict[str, Any]], *, timeout_s: float = 18.0) -> List[Dict[str, Any]]:
    if not search_specs:
        return []
    results: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=min(len(search_specs), 4)) as executor:
        futures = [
            executor.submit(
                search_web,
                spec.get("query", ""),
                int(spec.get("max_results") or 5),
                constraint=str(spec.get("constraint") or ""),
            )
            for spec in search_specs
        ]
        for future in futures:
            try:
                results.append(future.result(timeout=timeout_s))
            except Exception as exc:
                results.append({"ok": False, "error": str(exc), "results": []})
    return results


def _split_sentences(content: str) -> List[str]:
    text = str(content or "").replace("\r", "\n")
    chunks = re.split(r"(?<=[。！？.!?])\s+|\n+", text)
    sentences: List[str] = []
    for chunk in chunks:
        sentence = clean_text(chunk)
        if 20 <= len(sentence) <= 500:
            sentences.append(sentence)
    return sentences


def _looks_like_boilerplate_sentence(sentence: str) -> bool:
    lowered = clean_text(sentence).lower()
    if not lowered:
        return True
    if any(part in lowered for part in _BOILERPLATE_SENTENCE_PARTS):
        return True
    words = re.findall(r"[a-zA-Z]+", lowered)
    if len(words) >= 8 and len(set(words)) <= max(3, len(words) // 4):
        return True
    return False


def _claim_kind(sentence: str, entities: Dict[str, List[str]], focus: str) -> str:
    lowered = sentence.lower()
    focus_text = focus.lower().strip()
    if focus_text and focus_text in lowered:
        return "family_or_indicator"
    if any(keyword in lowered for keyword in _CLAIM_KEYWORDS):
        return "ttp"
    if any(values for values in entities.values()):
        return "ioc"
    return "context"


def _claim_score(sentence: str, entities: Dict[str, List[str]], focus: str) -> int:
    lowered = sentence.lower()
    score = 0
    if focus and focus.lower() in lowered:
        score += 6
    keyword_hits = sum(1 for keyword in _CLAIM_KEYWORDS if keyword in lowered)
    score += min(6, keyword_hits * 2)
    signal_hits = sum(1 for token in _CLAIM_SIGNAL_PARTS if token in lowered)
    score += min(4, signal_hits)
    if any(values for values in entities.values()):
        score += 3
    if 60 <= len(sentence) <= 320:
        score += 2
    if len(sentence) < 35:
        score -= 2
    if _looks_like_boilerplate_sentence(sentence):
        score -= 8
    return score


@tool
def technical_source_search(query: str, goal: str = "family_attribution", max_results: int = 6) -> str:
    """Search curated technical sources for family attribution, behavior, or infrastructure context."""
    seed = strip_quotes(query)
    goal = strip_quotes(goal).lower() or "family_attribution"
    presets = _TECHNICAL_SEARCH_PRESETS.get(goal) or _TECHNICAL_SEARCH_PRESETS["family_attribution"]

    per_query_results = max(3, min(int(max_results or 6), 8))
    search_specs: List[Dict[str, Any]] = []
    for query_template, constraint in presets:
        search_specs.append(
            {
                "query": query_template.format(seed=seed),
                "constraint": constraint,
                "max_results": per_query_results,
            }
        )
    fallback_query = {
        "family_attribution": f"{seed} malware family",
        "behavior_context": f"{seed} malware TTP behavior",
        "infra_context": f"{seed} malware infrastructure IOC",
    }.get(goal, f"{seed} malware family")
    search_specs.append({"query": fallback_query, "max_results": per_query_results})

    searches = _parallel_search_web(search_specs)
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
        if _looks_like_boilerplate_sentence(sentence):
            continue
        lowered = sentence.lower()
        has_keyword = any(keyword in lowered for keyword in _CLAIM_KEYWORDS)
        has_signal = any(token in lowered for token in _CLAIM_SIGNAL_PARTS)
        if focus and focus.lower() not in lowered and not has_keyword and not has_signal:
            entities = extract_text_entities(sentence)
            if not any(values for values in entities.values()):
                continue
        else:
            entities = extract_text_entities(sentence)
        kind = _claim_kind(sentence, entities, focus)
        score = _claim_score(sentence, entities, focus)
        if score < 2:
            continue
        key = (kind, sentence)
        if key in seen:
            continue
        seen.add(key)
        claims.append(
            {
                "kind": kind,
                "text": sentence,
                "entities": entities,
                "score": score,
            }
        )
    claims.sort(
        key=lambda item: (
            -int(item.get("score") or 0),
            {"family_or_indicator": 0, "ttp": 1, "ioc": 2, "context": 3}.get(str(item.get("kind") or ""), 9),
            -len(str(item.get("text") or "")),
        )
    )
    claims = claims[:8]

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
    searches = _parallel_search_web(
        [
            {"query": f"{seed} related indicators C2 infrastructure", "max_results": max_results},
            {
                "query": f"{seed} IOC malware infrastructure",
                "constraint": "site:abuse.ch OR site:threatfox.abuse.ch OR site:urlhaus.abuse.ch OR site:any.run",
                "max_results": max_results,
            },
        ]
    )
    merged = merge_search_observations(*searches)
    return dumps_json(merged)


@tool
def malware_profile_lookup(query: str, max_results: int = 5) -> str:
    """Fetch high-quality family profile references for deep investigation."""
    family = strip_quotes(query)
    searches = _parallel_search_web(
        [
            {
                "query": f"{family} malware family profile",
                "constraint": "site:malpedia.caad.fkie.fraunhofer.de OR site:microsoft.com OR site:mitre.org OR site:trendmicro.com OR site:proofpoint.com OR site:checkpoint.com",
                "max_results": max_results,
            },
            {"query": f"{family} malware TTP", "max_results": max_results},
        ]
    )
    merged = merge_search_observations(*searches)
    return dumps_json({"ok": merged.get("ok", False), "family": family, "query": family, "results": merged.get("results", []), "mode": merged.get("mode")})
