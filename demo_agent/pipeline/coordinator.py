from __future__ import annotations

import json
import os
import threading
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from langchain_core.prompts import ChatPromptTemplate

from ..analysis import build_analysis
from ..agents.react_agent import build_gap_fill_executor, run_gap_fill_react
from ..baseline_investigators import get_investigator
from ..config import AgentConfig
from ..renderers.report_markdown import render_report_from_analysis
from ..schemas import GapPlan, model_dump
from ..tooling import (
    advanced_web_search,
    extract_claim_candidates_from_page,
    extract_entities_from_page,
    fetch_page_content,
    malware_profile_lookup,
    pivot_related_indicators,
    save_report_md,
    technical_source_search,
)
from .gap_planner import plan_gap_actions


def _plan_gap_actions_with_timeout(llm: Any, analysis: Dict[str, Any], timeout_s: float = 15.0) -> GapPlan:
    holder: Dict[str, Any] = {"result": None}

    def _target() -> None:
        holder["result"] = plan_gap_actions(llm, analysis)

    worker = threading.Thread(target=_target, daemon=True)
    worker.start()
    worker.join(timeout=timeout_s)
    if worker.is_alive() or holder.get("result") is None:
        return plan_gap_actions(None, analysis)
    result = holder.get("result")
    return result if isinstance(result, GapPlan) else plan_gap_actions(None, analysis)


def _run_gap_fill_with_timeout(
    gap_executor: Any,
    *,
    analysis: Dict[str, Any],
    gap_plan: Dict[str, Any],
    out_dir: str,
    timeout_s: float = 35.0,
) -> Optional[Dict[str, Any]]:
    holder: Dict[str, Any] = {"result": None, "error": None}

    def _target() -> None:
        try:
            holder["result"] = run_gap_fill_react(
                gap_executor,
                analysis=analysis,
                gap_plan=gap_plan,
                out_dir=out_dir,
            )
        except Exception as exc:  # pragma: no cover - defensive runtime path
            holder["error"] = exc

    worker = threading.Thread(target=_target, daemon=True)
    worker.start()
    worker.join(timeout=timeout_s)
    if worker.is_alive():
        return None
    if holder.get("error") is not None:
        return None
    return holder.get("result")


def _load_tool_json(tool: Any, params: Dict[str, Any]) -> Dict[str, Any]:
    try:
        raw = tool.invoke(params)
        if isinstance(raw, dict):
            return raw
        if isinstance(raw, str):
            return json.loads(raw)
    except Exception:
        return {}
    return {}


def _supplemental_has_evidence(supplemental: Optional[Dict[str, Any]]) -> bool:
    if not isinstance(supplemental, dict):
        return False
    return bool(list(supplemental.get("supplemental_evidence") or []))


def _prefer_deterministic_gap_fill(analysis: Dict[str, Any]) -> bool:
    assessment = analysis.get("assessment") or {}
    family = str(assessment.get("family") or "").strip()
    gap_types = {str(item.get("type") or "") for item in list(analysis.get("gaps") or [])}
    deterministic_types = {
        "missing_local_match",
        "single_source_attribution",
        "no_secondary_confirmation",
        "behavior_context_missing",
    }
    return bool(family and family != "Unknown" and gap_types and gap_types.issubset(deterministic_types))


def _result_rank(result: Dict[str, Any]) -> tuple[int, str]:
    url = str(result.get("url") or "")
    domain = urlparse(url).netloc.lower()
    title = str(result.get("title") or "")
    priority = 50
    for needle, score in (
        ("any.run", 95),
        ("threatfox.abuse.ch", 92),
        ("urlhaus.abuse.ch", 90),
        ("bazaar.abuse.ch", 90),
        ("malpedia.caad.fkie.fraunhofer.de", 88),
        ("microsoft.com", 86),
        ("trendmicro.com", 84),
        ("proofpoint.com", 82),
        ("checkpoint.com", 80),
        ("virustotal.com", 78),
        ("abuse.ch", 76),
    ):
        if needle in domain:
            priority = score
            break
    return (-priority, title)


def _deterministic_gap_fill(analysis: Dict[str, Any], gap_plan: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    items = list((gap_plan or {}).get("items") or [])
    if not items:
        return None

    assessment = analysis.get("assessment") or {}
    facts = analysis.get("facts") or {}
    fingerprint = facts.get("fingerprint") or {}
    focus = str(assessment.get("family") or fingerprint.get("value") or "").strip()

    search_obs: Dict[str, Any] = {}
    top_result: Dict[str, Any] = {}
    page_obs: Dict[str, Any] = {}
    claim_obs: Dict[str, Any] = {}
    entity_obs: Dict[str, Any] = {}

    for item in items:
        for action in list(item.get("actions") or []):
            tool_name = str(action.get("tool") or "")
            if tool_name in {"technical_source_search", "advanced_web_search", "malware_profile_lookup", "pivot_related_indicators"}:
                payload: Dict[str, Any] = {}
                if action.get("query"):
                    payload["query"] = action.get("query")
                if action.get("goal"):
                    payload["goal"] = action.get("goal")
                if action.get("constraint"):
                    payload["constraint"] = action.get("constraint")
                if action.get("max_results"):
                    payload["max_results"] = action.get("max_results")
                tool_ref = {
                    "technical_source_search": technical_source_search,
                    "advanced_web_search": advanced_web_search,
                    "malware_profile_lookup": malware_profile_lookup,
                    "pivot_related_indicators": pivot_related_indicators,
                }[tool_name]
                search_obs = _load_tool_json(tool_ref, payload)
                results = list(search_obs.get("results") or [])
                if results:
                    results.sort(key=_result_rank)
                    top_result = results[0]
                    break
        if top_result:
            break

    if not top_result:
        external_intel = analysis.get("external_intel") or {}
        fallback_results = []
        family_raw = ((external_intel.get("family_intel") or {}).get("raw") or {}) if isinstance(external_intel.get("family_intel"), dict) else {}
        fallback_results.extend(list(family_raw.get("results") or []))
        fallback_results.extend(list((external_intel.get("context_search") or {}).get("results") or []))
        if fallback_results:
            fallback_results.sort(key=_result_rank)
            top_result = fallback_results[0]
            search_obs = {
                "query": ((external_intel.get("family_intel") or {}).get("query")) or ((external_intel.get("context_search") or {}).get("query")),
                "results": fallback_results,
            }

    if top_result.get("url"):
        page_obs = _load_tool_json(fetch_page_content, {"url": top_result.get("url"), "max_chars": 6000})
        content = str(page_obs.get("content") or "")
        if content:
            claim_obs = _load_tool_json(
                extract_claim_candidates_from_page,
                {"content": content, "focus": focus},
            )
            entity_obs = _load_tool_json(extract_entities_from_page, {"content": content})

    supplemental_evidence = []
    seen_claims = set()
    for item in list(claim_obs.get("claims") or [])[:3]:
        claim_text = str(item.get("text") or "").strip()
        if not claim_text or claim_text in seen_claims:
            continue
        seen_claims.add(claim_text)
        claim_kind = str(item.get("kind") or "page_claim")
        confidence = 72 if claim_kind in {"family_or_indicator", "ttp"} else 66
        supplemental_evidence.append(
            {
                "kind": "supplemental",
                "source": urlparse(str(top_result.get("url") or "")).netloc or top_result.get("source") or "deterministic_gap_fill",
                "type": f"page_{claim_kind}",
                "query": search_obs.get("query"),
                "url": top_result.get("url"),
                "title": page_obs.get("title") or top_result.get("title") or "补查页面证据",
                "claim": claim_text,
                "confidence": confidence,
                "raw_ref": "deterministic_gap_fill.page_claim",
            }
        )

    entities = entity_obs.get("entities") if isinstance(entity_obs, dict) else None
    if not supplemental_evidence and top_result.get("snippet"):
        supplemental_evidence.append(
            {
                "kind": "supplemental",
                "source": urlparse(str(top_result.get("url") or "")).netloc or top_result.get("source") or "deterministic_gap_fill",
                "type": "search_snippet",
                "query": search_obs.get("query"),
                "url": top_result.get("url"),
                "title": top_result.get("title") or "补查搜索结果",
                "claim": str(top_result.get("snippet") or "").strip(),
                "confidence": 58,
                "raw_ref": "deterministic_gap_fill.search_result",
            }
        )
    elif entities and any(list(entities.get(key) or []) for key in ("ips", "domains", "urls", "sha256", "sha1", "md5")):
        parts = []
        for key, label in (("ips", "IP"), ("domains", "域名"), ("urls", "URL"), ("sha256", "SHA256"), ("sha1", "SHA1"), ("md5", "MD5")):
            values = list(entities.get(key) or [])[:3]
            if values:
                parts.append(f"{label}: {', '.join(values)}")
        if parts:
            supplemental_evidence.append(
                {
                    "kind": "supplemental",
                    "source": urlparse(str(top_result.get("url") or "")).netloc or top_result.get("source") or "deterministic_gap_fill",
                    "type": "entity_pivot",
                    "query": search_obs.get("query"),
                    "url": top_result.get("url"),
                    "title": page_obs.get("title") or top_result.get("title") or "补查实体线索",
                    "claim": "页面正文中提取到二跳实体线索：" + "；".join(parts),
                    "confidence": 62,
                    "raw_ref": "deterministic_gap_fill.entities",
                }
            )

    if not supplemental_evidence:
        return None

    candidate_family = None
    family = str(assessment.get("family") or "").strip()
    if family and family != "Unknown":
        candidate_family = family

    gap_updates = []
    for gap in list(analysis.get("gaps") or []):
        gap_updates.append(
            {
                "gap_id": gap.get("id") or "",
                "status": "partially_resolved",
                "note": "通过确定性补查链补回了补充证据。",
            }
        )

    return {
        "supplemental_evidence": supplemental_evidence,
        "gap_updates": gap_updates,
        "candidate_family": candidate_family,
        "supplemental_summary": "React 未产出有效补充证据，已使用确定性补查链回收高价值页面证据。",
    }


def run_pipeline(llm: Any, cfg: AgentConfig, *, event: Dict[str, Any], out_dir: str) -> Dict[str, Any]:
    fp = event.get("trigger_fingerprint") or {}
    fp_type = str(fp.get("type") or "").upper()

    investigator = get_investigator(fp_type)
    baseline = investigator(event)
    local_obs = baseline.get("local_obs")
    obs_fp = baseline.get("obs_fp")
    obs_context = baseline.get("obs_context")
    obs_family = baseline.get("obs_family")
    supplemental: Optional[Dict[str, Any]] = None
    gap_plan = GapPlan(items=[])

    analysis = build_analysis(
        event=event,
        mode="plan",
        local_intel=local_obs,
        obs_fp=obs_fp,
        obs_context=obs_context,
        obs_family=obs_family,
    )

    if analysis.get("gap_fill_needed"):
        gap_plan = _plan_gap_actions_with_timeout(llm, analysis, timeout_s=15.0)
        if gap_plan.items:
            if _prefer_deterministic_gap_fill(analysis):
                supplemental = _deterministic_gap_fill(analysis, model_dump(gap_plan))
            else:
                exploration_tools = [
                    advanced_web_search,
                    technical_source_search,
                    fetch_page_content,
                    extract_claim_candidates_from_page,
                    extract_entities_from_page,
                    pivot_related_indicators,
                    malware_profile_lookup,
                ]
                gap_executor = build_gap_fill_executor(llm, exploration_tools, verbose=False)
                gap_result = _run_gap_fill_with_timeout(
                    gap_executor,
                    analysis=analysis,
                    gap_plan=model_dump(gap_plan),
                    out_dir=out_dir,
                    timeout_s=35.0,
                )
                try:
                    if gap_result is not None:
                        supplemental = gap_result.get("parsed") or {}
                    else:
                        supplemental = None
                except Exception:
                    supplemental = None
                if not _supplemental_has_evidence(supplemental):
                    supplemental = _deterministic_gap_fill(analysis, model_dump(gap_plan)) or supplemental
            if supplemental:
                analysis = build_analysis(
                    event=event,
                    mode="plan",
                    local_intel=local_obs,
                    obs_fp=obs_fp,
                    obs_context=obs_context,
                    obs_family=obs_family,
                    supplemental=supplemental,
                )

    use_local_renderer = str(os.getenv("REPORT_RENDERER") or "").strip().lower() == "local"
    report_md = ""
    if use_local_renderer:
        report_md = render_report_from_analysis(analysis)
    else:
        prompt = ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    "你是网络安全分析师。请仅基于提供的 analysis JSON 生成中文 Markdown 报告。"
                    "不要编造 analysis 中不存在的 IOC、结论或证据。"
                    "请生成适合对外展示的报告，包含：事件概述、研判结论、关键证据与情报、家族/威胁背景、处置建议、参考链接。"
                    "如果 analysis 中的标题或摘要是英文，请转述为中文，URL 保持原样。",
                ),
                ("user", "analysis:\n{analysis_json}\n\nout_dir:\n{out_dir}"),
            ]
        )
        msg = prompt.format_messages(
            analysis_json=json.dumps(analysis, ensure_ascii=False, indent=2),
            out_dir=out_dir,
        )
        try:
            report_md = (llm.invoke(msg).content or "").strip()  # type: ignore[attr-defined]
        except Exception:
            report_md = render_report_from_analysis(analysis)

    saved = json.loads(save_report_md.invoke({"out_dir": out_dir, "content": report_md}))
    final_analysis = dict(analysis)
    final_analysis["gap_plan"] = model_dump(gap_plan)
    final_analysis["report"] = {
        "path": saved.get("path"),
        "content": report_md,
    }
    return {
        "ok": True,
        "saved": saved,
        "local_obs": local_obs,
        "obs_fp": obs_fp,
        "obs_context": obs_context,
        "obs_family": obs_family,
        "supplemental": supplemental,
        "gap_plan": model_dump(gap_plan),
        "analysis": final_analysis,
    }
