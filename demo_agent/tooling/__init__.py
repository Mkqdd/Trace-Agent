import json

from langchain_core.tools import tool

from ..renderers.artifacts import build_topology
from ..storage.io import save_text
from .baseline import abuse_ch_lookup, family_intel_lookup, local_intel_lookup, standard_web_search, vt_enrich_ioc, vt_enrich_ip
from .exploration import (
    advanced_web_search,
    extract_claim_candidates_from_page,
    extract_entities_from_page,
    fetch_page_content,
    malware_profile_lookup,
    pivot_related_indicators,
    technical_source_search,
)


web_search = standard_web_search
family_intel = family_intel_lookup


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


__all__ = [
    "abuse_ch_lookup",
    "advanced_web_search",
    "build_topology_json",
    "extract_claim_candidates_from_page",
    "extract_entities_from_page",
    "family_intel",
    "family_intel_lookup",
    "fetch_page_content",
    "local_intel_lookup",
    "malware_profile_lookup",
    "pivot_related_indicators",
    "save_report_md",
    "standard_web_search",
    "technical_source_search",
    "vt_enrich_ioc",
    "vt_enrich_ip",
    "web_search",
]
