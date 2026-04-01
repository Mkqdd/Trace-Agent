import json
import os
from typing import Any, Dict, Optional

from langchain_core.prompts import ChatPromptTemplate

from ..analysis import build_analysis
from ..agents.react_agent import build_gap_fill_executor, run_gap_fill_react
from ..config import AgentConfig
from ..renderers.report_markdown import render_report_from_analysis
from ..tooling import family_intel, local_intel_lookup, save_report_md, vt_enrich_ip, web_search


def _first_non_empty(*values: Any) -> str:
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return ""


def _fingerprint_query(fp_type: str, fp_value: str, family_seed: str) -> str:
    prefix = fp_type if fp_type else "indicator"
    query = f"{prefix} {fp_value} {family_seed}".strip()
    return query


def _context_query(fp_type: str, fp_value: str, family_seed: str) -> str:
    if fp_type == "IP":
        return f"{fp_value} malware C2 {family_seed}".strip()
    if fp_type in {"JA3", "JA4", "SSL_SHA1"}:
        return f"{fp_type} {fp_value} malware family {family_seed}".strip()
    return f"{fp_type} {fp_value} malware context {family_seed}".strip()


def run_plan_and_solve(llm: Any, cfg: AgentConfig, *, event: Dict[str, Any], out_dir: str) -> Dict[str, Any]:
    """
    Deterministic Plan-and-Solve runner to avoid ReAct loops:
    - Enrich exactly once based on fingerprint type
    - Optionally enrich family intel once (if enrichment.info exists)
    - Build topology once
    - Ask LLM to write report once
    - Save report
    """
    fp = event.get("trigger_fingerprint") or {}
    fp_type = str(fp.get("type") or "").upper()
    fp_value = str(fp.get("value") or "")

    local_obs: Optional[Dict[str, Any]] = None
    obs_fp: Optional[Dict[str, Any]] = None
    obs_context: Optional[Dict[str, Any]] = None
    obs_family: Optional[Dict[str, Any]] = None
    supplemental: Optional[Dict[str, Any]] = None

    # 1) Local structured intel (always try first, but do not stop the flow on failure)
    local_obs = json.loads(local_intel_lookup.invoke({"indicator_type": fp_type, "indicator_value": fp_value}))
    local_best = (local_obs or {}).get("best_match") or {}
    family_seed = _first_non_empty(local_best.get("malware_family"), (event.get("enrichment") or {}).get("info"))

    # 2) External fingerprint-driven enrichment (always try)
    if fp_type == "IP":
        obs_fp = json.loads(vt_enrich_ip.invoke(fp_value))
        context_query = _context_query(fp_type, fp_value, family_seed)
        obs_context = json.loads(web_search.invoke({"query": context_query, "max_results": 5}))
    elif fp_type in {"JA3", "JA4", "SSL_SHA1", "CERT_SHA1"}:
        query = _fingerprint_query(fp_type, fp_value, family_seed)
        obs_fp = json.loads(web_search.invoke({"query": query, "max_results": 5}))
        context_query = _context_query(fp_type, fp_value, family_seed)
        obs_context = json.loads(web_search.invoke({"query": context_query, "max_results": 5}))
    else:
        query = _fingerprint_query(fp_type, fp_value, family_seed)
        obs_fp = json.loads(web_search.invoke({"query": query, "max_results": 5}))
        obs_context = obs_fp

    # 3) Family intel (use local match or event hint as seed)
    if family_seed:
        obs_family = json.loads(
            family_intel.invoke({"family": family_seed, "context": str(fp_value), "max_results": 5})
        )

    # 4) Derive analysis after the first dual-track enrichment
    analysis = build_analysis(
        event=event,
        mode="plan",
        local_intel=local_obs,
        obs_fp=obs_fp,
        obs_context=obs_context,
        obs_family=obs_family,
    )

    # 5) Optional constrained React gap fill
    if analysis.get("gap_fill_needed"):
        gap_tools = [local_intel_lookup, vt_enrich_ip, web_search, family_intel]
        gap_executor = build_gap_fill_executor(llm, gap_tools, verbose=False)
        try:
            gap_result = run_gap_fill_react(gap_executor, analysis=analysis, out_dir=out_dir)
            supplemental = gap_result.get("parsed") or {}
        except Exception:
            supplemental = None
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

    # 6) Report generation from analysis
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
                    "analysis JSON 已经包含事件事实、本地命中、外部佐证、交叉验证结果、剩余缺口和处置建议。"
                    "必须围绕这些结构来写，不能编造 analysis JSON 中不存在的 IOC、结论或证据。"
                    "报告必须包含：研判结论、事件摘要、本地命中结论、外部佐证与上下文、交叉验证结果、剩余缺口、处置建议。"
                    "每条关键结论尽量引用 evidence/findings 中已有内容；如果标题或摘要是英文，请转述为中文，URL 保持原样。",
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

    # 7) Save report once
    saved = json.loads(save_report_md.invoke({"out_dir": out_dir, "content": report_md}))
    final_analysis = dict(analysis)
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
        "analysis": final_analysis,
    }

