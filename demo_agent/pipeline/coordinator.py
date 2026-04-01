from __future__ import annotations

import json
import os
import threading
from typing import Any, Dict, Optional

from langchain_core.prompts import ChatPromptTemplate

from ..analysis import build_analysis
from ..agents.react_agent import build_gap_fill_executor, run_gap_fill_react
from ..baseline_investigators import get_investigator
from ..config import AgentConfig
from ..renderers.report_markdown import render_report_from_analysis
from ..schemas import GapPlan, model_dump
from ..tooling import (
    advanced_web_search,
    extract_entities_from_page,
    fetch_page_content,
    malware_profile_lookup,
    pivot_related_indicators,
    save_report_md,
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
            exploration_tools = [
                advanced_web_search,
                fetch_page_content,
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
