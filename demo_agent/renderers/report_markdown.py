from typing import Any, Dict, List


def _json_path(path: str) -> str:
    return f"`{path}`" if path else "`raw`"


def render_report_from_analysis(analysis: Dict[str, Any]) -> str:
    event = analysis.get("event") or {}
    derived = analysis.get("derived") or {}
    evidence: List[Dict[str, Any]] = list(analysis.get("evidence") or [])
    findings: List[Dict[str, Any]] = list(analysis.get("findings") or [])
    uncertainties: List[Dict[str, Any]] = list(analysis.get("uncertainties") or [])
    actions: List[Dict[str, Any]] = list(analysis.get("recommended_actions") or [])

    lines: List[str] = ["# 网络安全事件分析报告", ""]

    lines.append("## 研判结论")
    if findings:
        for item in findings:
            lines.append(f"- {item.get('statement')}")
    else:
        lines.append("- 当前未产出明确的结构化研判结论。")
    lines.append("")

    lines.append("## 事件摘要")
    lines.append(f"- 事件时间：{event.get('event_time')}")
    lines.append(f"- 源地址：`{(event.get('src') or {}).get('ip')}`")
    lines.append(f"- 目的地址：`{(event.get('dst') or {}).get('ip')}`")
    lines.append(f"- 协议：{event.get('protocol')}")
    lines.append(
        f"- 命中指纹：{(event.get('trigger_fingerprint') or {}).get('type')} "
        f"`{(event.get('trigger_fingerprint') or {}).get('value')}`"
    )
    lines.append(f"- 推断家族：{derived.get('family')}")
    lines.append(f"- 置信度：{derived.get('confidence')}")
    lines.append(f"- 严重度：{derived.get('severity')}")
    lines.append("")

    lines.append("## 证据与情报")
    if evidence:
        for item in evidence:
            lines.append(f"### {item.get('id')} {item.get('title')}")
            lines.append(f"- 来源：{item.get('source')}")
            if item.get("query"):
                lines.append(f"- 查询：`{item.get('query')}`")
            lines.append(f"- 说明：{item.get('claim')}")
            if item.get("url"):
                lines.append(f"- 链接：{item.get('url')}")
            lines.append(f"- 置信度：{item.get('confidence')}")
            lines.append(f"- 原始引用：{_json_path(str(item.get('raw_ref') or ''))}")
            lines.append("")
    else:
        lines.append("- 当前没有结构化证据。")
        lines.append("")

    lines.append("## 不确定性")
    if uncertainties:
        for item in uncertainties:
            lines.append(f"- {item.get('statement')} 原因：{item.get('reason')}")
    else:
        lines.append("- 当前未记录明显的不确定性。")
    lines.append("")

    lines.append("## 处置建议")
    if actions:
        for item in actions:
            lines.append(
                f"- [{str(item.get('priority') or '').upper()}] {item.get('action')} "
                f"理由：{item.get('rationale')}"
            )
    else:
        lines.append("- 当前未生成结构化处置建议。")

    return "\n".join(lines).strip() + "\n"
