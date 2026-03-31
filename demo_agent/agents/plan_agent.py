import json
import os
from typing import Any, Dict, Optional

from langchain_core.prompts import ChatPromptTemplate

from ..analysis import build_analysis
from ..renderers.report_markdown import render_report_from_analysis
from ..tooling import family_intel, save_report_md, vt_enrich_ip, web_search


def run_plan_and_solve(llm: Any, *, event: Dict[str, Any], out_dir: str) -> Dict[str, Any]:
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

    obs_fp: Optional[Dict[str, Any]] = None
    obs_family: Optional[Dict[str, Any]] = None

    # 1) Fingerprint-driven enrichment (exactly once)
    if fp_type == "IP":
        obs_fp = json.loads(vt_enrich_ip.invoke(fp_value))
    elif fp_type == "JA3":
        # Search JA3 directly
        info = (event.get("enrichment") or {}).get("info") or ""
        query = f"JA3 {fp_value} {info}".strip()
        obs_fp = json.loads(web_search.invoke({"query": query, "max_results": 5}))
    else:
        # Domain/URL/others: fallback to web_search
        info = (event.get("enrichment") or {}).get("info") or ""
        query = f"{fp_type} {fp_value} {info}".strip()
        obs_fp = json.loads(web_search.invoke({"query": query, "max_results": 5}))

    # 2) Family intel (at most once)
    family = (event.get("enrichment") or {}).get("info")
    if isinstance(family, str) and family.strip():
        obs_family = json.loads(
            family_intel.invoke({"family": family.strip(), "context": str(fp_value), "max_results": 5})
        )

    # 3) Derive analysis after enrichment
    analysis = build_analysis(event=event, mode="plan", obs_fp=obs_fp, obs_family=obs_family)

    # 4) Report generation from analysis
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
                    "analysis JSON 已经包含事件事实、结构化证据、研判结论、不确定性和处置建议。"
                    "必须围绕这些结构来写，不能编造 analysis JSON 中不存在的 IOC、结论或证据。"
                    "报告必须包含：研判结论、事件摘要、证据与情报、不确定性、处置建议。"
                    "证据部分优先引用 evidence/findings 中已有内容；如果标题或摘要是英文，请转述为中文，URL 保持原样。",
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

    # 5) Save report once
    saved = json.loads(save_report_md.invoke({"out_dir": out_dir, "content": report_md}))
    final_analysis = dict(analysis)
    final_analysis["report"] = {
        "path": saved.get("path"),
        "content": report_md,
    }
    return {"ok": True, "saved": saved, "obs_fp": obs_fp, "obs_family": obs_family, "analysis": final_analysis}

