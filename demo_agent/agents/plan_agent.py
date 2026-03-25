import json
from typing import Any, Dict, Optional

from langchain_core.prompts import ChatPromptTemplate

from ..tools import build_topology_json, family_intel, save_report_md, vt_enrich_ip, web_search


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

    # 3) Topology once (text only)
    topo = json.loads(build_topology_json.invoke(json.dumps(event, ensure_ascii=False)))

    # 4) Report generation once
    prompt = ChatPromptTemplate.from_messages(
        [
            (
                "system",
                "你是网络安全分析师。请仅基于提供的 JSON 数据生成中文 Markdown 报告（结构自由，不要固定模板）。"
                "必须包含：研判结论、事件摘要、证据与情报（引用提供的搜索/VT结果）、处置建议。"
                "如果 simulated=true，请标注“模拟数据”。不要编造不存在的 IOC。"
                "证据与情报部分必须用中文表述：如果搜索结果的标题/摘要是英文，请将其含义翻译或转述为中文；"
                "URL 保持原样可点击；如需保留英文原文标题，可放在中文后面的括号中。",
            ),
            ("user", "event:\n{event_json}\n\nfingerprint_enrich:\n{obs_fp}\n\nfamily_intel:\n{obs_family}\n\ntopology:\n{topo_json}\n\nout_dir:\n{out_dir}"),
        ]
    )
    msg = prompt.format_messages(
        event_json=json.dumps(event, ensure_ascii=False, indent=2),
        obs_fp=json.dumps(obs_fp, ensure_ascii=False, indent=2),
        obs_family=json.dumps(obs_family, ensure_ascii=False, indent=2) if obs_family is not None else "null",
        topo_json=json.dumps(topo, ensure_ascii=False, indent=2),
        out_dir=out_dir,
    )
    report_md = (llm.invoke(msg).content or "").strip()  # type: ignore[attr-defined]

    # 5) Save report once
    saved = json.loads(save_report_md.invoke({"out_dir": out_dir, "content": report_md}))
    return {"ok": True, "saved": saved, "obs_fp": obs_fp, "obs_family": obs_family, "topology": topo}

