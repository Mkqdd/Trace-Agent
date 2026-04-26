from __future__ import annotations

from typing import Any, Dict


def build_ops_report_contract(
    *,
    title: str,
    template_version: str,
    evidence_roles: Dict[str, Any],
    report_header: Dict[str, Any],
    background_and_leads: Dict[str, Any],
    scope_definition: Dict[str, Any],
    coverage_plan: Dict[str, Any],
    mechanism_breakdown: Dict[str, Any],
    evidence_blocks: Dict[str, Any],
    timeline: Dict[str, Any],
    relationship_analysis: Dict[str, Any],
    impact_assessment: Dict[str, Any],
    evidence_gap_summary: Dict[str, Any],
    recommended_actions: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "title": title,
        "template_version": template_version,
        "evidence_roles": dict(evidence_roles or {}),
        "report_header": dict(report_header or {}),
        "background_and_leads": dict(background_and_leads or {}),
        "scope_definition": dict(scope_definition or {}),
        "coverage_plan": dict(coverage_plan or {}),
        "mechanism_breakdown": dict(mechanism_breakdown or {}),
        "evidence_blocks": dict(evidence_blocks or {}),
        "timeline": dict(timeline or {}),
        "relationship_analysis": dict(relationship_analysis or {}),
        "impact_assessment": dict(impact_assessment or {}),
        "evidence_gap_summary": dict(evidence_gap_summary or {}),
        "recommended_actions": dict(recommended_actions or {}),
    }


def build_appendix_contract(
    *,
    ioc_rows: Any,
    key_object_rows: Any,
    evidence_details: Any,
    observation_rows: Any,
    section_reference_rows: Any,
    source_rows: Any,
    gap_rows: Any,
) -> Dict[str, Any]:
    return {
        "ioc_rows": list(ioc_rows or []),
        "key_object_rows": list(key_object_rows or []),
        "evidence_details": list(evidence_details or []),
        "observation_rows": list(observation_rows or []),
        "section_reference_rows": list(section_reference_rows or []),
        "source_rows": list(source_rows or []),
        "gap_rows": list(gap_rows or []),
    }
