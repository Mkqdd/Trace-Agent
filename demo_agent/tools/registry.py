from . import (
    abuse_ch_lookup,
    advanced_web_search,
    extract_claim_candidates_from_page,
    extract_entities_from_page,
    family_intel_lookup,
    fetch_page_content,
    local_intel_lookup,
    malware_profile_lookup,
    pivot_related_indicators,
    standard_web_search,
    technical_source_search,
    threatfox_ioc_lookup,
    urlhaus_ioc_lookup,
    vt_enrich_ioc,
)


BASELINE_TOOLS = [
    local_intel_lookup,
    vt_enrich_ioc,
    standard_web_search,
    abuse_ch_lookup,
    family_intel_lookup,
]

REACT_TOOLS = [
    advanced_web_search,
    technical_source_search,
    fetch_page_content,
    extract_claim_candidates_from_page,
    extract_entities_from_page,
    pivot_related_indicators,
    malware_profile_lookup,
    threatfox_ioc_lookup,
    urlhaus_ioc_lookup,
]
