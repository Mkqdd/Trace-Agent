from __future__ import annotations

import ipaddress
import json
import os
import re
import time
from typing import Any, Dict, List, Tuple

from .evidence_store import build_evidence_store, build_legacy_evidence_contract
from .report_agent import run_report_material_loop
from .report_agent_writer import render_polished_body_from_materials
from .report_fact_cards import build_report_fact_cards
from .report_polish_validator import validate_report_polish
from .report_source_bundle import build_report_source_bundle
from .report_contracts import build_appendix_contract, build_ops_report_contract
from .report_inputs import build_report_inputs
from .report_render import render_appendix_report, render_ops_report
from .reviewer import build_delivery_decision, build_reviewer_input
from ..services.api.llm_observability import invoke_llm_with_trace

EVENT_TOOL_NAMES = {"search_seed_context", "search_related_events", "expand_asset_scope"}
STAGE_LABELS = {
    "initial-access": "初始访问",
    "execution": "执行",
    "command-and-control": "命令与控制",
    "lateral-movement": "横向移动",
    "credential-access": "凭据获取",
    "persistence": "持久化",
    "discovery": "侦察",
    "collection": "收集",
    "exfiltration": "数据外传",
    "impact": "破坏",
}
OBJECT_ROLE_LABELS = {
    "seed_asset": "种子资产",
    "affected_asset": "已确认受影响资产",
    "related_asset": "待确认关联资产",
    "core_external_indicator": "核心外部基础设施",
    "contextual_indicator": "背景/上下文指标",
    "seed_fingerprint": "种子命中指纹",
    "family_hint": "家族/工具提示",
    "expansion_candidate": "扩展查询候选",
    "related_internal_address": "关联内部地址",
}
OBJECT_ROLE_PRIORITY = {
    "seed_asset": 0,
    "affected_asset": 1,
    "related_asset": 2,
    "core_external_indicator": 3,
    "contextual_indicator": 4,
    "seed_fingerprint": 5,
    "family_hint": 6,
    "related_internal_address": 7,
    "expansion_candidate": 8,
}
OBJECT_TYPE_LABELS = {
    "asset": "资产",
    "IP": "IP",
    "internal_ip": "内网 IP",
    "domain": "域名",
    "URL": "URL",
    "JA3": "JA3",
    "JA4": "JA4",
    "SSL_SHA1": "SSL 指纹",
    "CERT_SHA1": "证书指纹",
    "fingerprint": "指纹",
    "family": "家族提示",
    "indicator": "指标",
    "user": "账号",
}
PROVENANCE_LABELS = {
    "local_observation": "内部观测",
    "analyst_note": "内部调查摘要",
    "external_intel": "外部结构化情报",
    "counterevidence": "反证核查",
    "unverified_inference": "候选推断",
    "derived_relation": "归并关系",
}
GAP_STATUS_LABELS = {
    "open": "待补",
    "partially_closed": "部分收敛",
    "unresolved_but_deliverable": "可交付但未完全闭合",
    "closed": "已闭合",
}
GAP_STATUS_PRIORITY = {
    "open": 0,
    "partially_closed": 1,
    "unresolved_but_deliverable": 2,
    "closed": 3,
}
MAIN_REPORT_ROLE_LABELS = {
    "trigger_evidence": "调查触发证据",
    "corroborating_evidence": "连续性支撑证据",
    "progression_evidence": "风险升级证据",
    "scope_evidence": "范围确认依据",
    "counterevidence": "反证与替代解释",
    "boundary_gap_evidence": "交付边界与缺口",
}


def _join_items(values: List[str]) -> str:
    items = [str(value or "").strip() for value in values if str(value or "").strip()]
    return "、".join(items) if items else "未识别"


def _dedupe_text(values: List[str]) -> List[str]:
    seen: set[str] = set()
    result: List[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def _format_time(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return "unknown"
    return text.replace("T", " ").replace("Z", " UTC")


def _stage_label(stage: str) -> str:
    text = str(stage or "").strip()
    return STAGE_LABELS.get(text, text)


def _format_stage_list(stages: List[str]) -> str:
    labels = [_stage_label(stage) for stage in stages if str(stage or "").strip()]
    return _join_items(labels)


def _reader_confidence_level(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return "未评估"
    try:
        score = float(text)
    except ValueError:
        return text
    if score <= 1:
        score *= 100
    score = max(0, min(int(round(score)), 100))
    if score >= 85:
        level = "高"
    elif score >= 70:
        level = "高"
    elif score >= 50:
        level = "中"
    else:
        level = "低"
    return level


def _reader_confidence_text(value: Any, *, precise: bool = True) -> str:
    text = str(value or "").strip()
    if not text:
        return "未评估"
    level = _reader_confidence_level(value)
    if not precise:
        return level
    try:
        score = float(text)
    except ValueError:
        return text
    if score <= 1:
        score *= 100
    score = max(0, min(int(round(score)), 100))
    return f"{level}（{score}/100）"


def _reader_severity_text(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return "未评估"
    mapping = {
        "critical": "高",
        "high": "高",
        "medium": "中",
        "low": "低",
        "info": "低",
        "紧急": "高",
        "高危": "高",
        "中危": "中",
        "低危": "低",
        "高": "高",
        "中": "中",
        "低": "低",
        "提示": "低",
    }
    return mapping.get(text.lower(), mapping.get(text, text))


def _reader_clean_text(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    replacements = {
        "command-and-control": "命令与控制",
        "initial-access": "初始访问",
        "monitor_only": "背景活动，建议持续观察",
        "needs_review": "可疑事件，建议继续复核",
        "confirmed_incident": "确认安全事件",
        "seed alert": "种子告警",
        "seed 指标": "种子告警涉及的指标",
        "dst_ip": "目标 IP",
        "JA4": "通信指纹",
        "JA3": "通信指纹",
        "事件簇": "当前关联事件",
        "自动结论": "当前结论",
        "主支撑信号": "主要支撑迹象",
        "枢纽": "关键关联指标",
        "显式扩线": "扩线核查",
        "material delta": "新的有效信息",
    }
    for source, target in replacements.items():
        text = text.replace(source, target)
    text = re.sub(r"\bpivot\b", "关键关联指标", text, flags=re.IGNORECASE)
    text = re.sub(r"当前\s+关键关联指标", "当前关键关联指标", text)
    text = text.replace("仍需围绕当前关键关联指标做一次扩线核查", "仍需围绕当前关键关联指标开展一轮扩线核查")
    text = re.sub(r"围绕当前关键关联指标\s*做一次\s*扩线核查", "围绕当前关键关联指标开展一轮扩线核查", text)
    text = re.sub(r"做一次\s+扩线核查", "开展扩线核查", text)
    text = text.replace("该 gap 已经过多轮相关尝试但没有 新的有效信息，更适合作为报告未决事项。", "该缺口已多轮核查但仍未获得新的有效信息，更适合作为报告未决事项。")
    text = text.replace("当前没有仍然适合继续缩小该 gap 的工具，更适合作为报告边界说明。", "当前缺少继续缩小该缺口的有效手段，更适合作为报告边界说明。")
    text = re.sub(
        r"Approved .*patch staging began on ([A-Za-z0-9_.-]+) in the same hour and could explain some routine admin activity\.?",
        r"资产 `\1` 同时间窗存在已批准的补丁或维护活动，可解释部分日常管理行为。",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(
        r"Windows update content was downloaded from an approved Microsoft endpoint during the maintenance window\.?",
        "该访问更接近维护窗口内的计划内 Windows 更新流量。",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(
        r"A QA telemetry job also touched the same hosting IP through a different vendor domain, indicating the secondary IP is shared infrastructure\.?",
        "另有 QA 遥测任务通过其他供应商域名访问了同一托管 IP，说明该次级 IP 更可能属于共享基础设施。",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(
        r"The EDR sensor on ([A-Za-z0-9_.-]+) reported degraded process telemetry, so the execution lineage behind the second beacon cannot be reconstructed\.?",
        r"资产 `\1` 的 EDR 进程遥测出现降级，因此第二条 beacon 背后的执行链暂时无法完整重建。",
        text,
        flags=re.IGNORECASE,
    )
    return text


def _reader_action_text(value: Any) -> str:
    text = _reader_clean_text(value)
    if not text:
        return ""
    replacements = {
        "以 种子告警涉及的指标和当前关联事件中的域名 / IP 为 枢纽，继续检索同时间窗内的重复通信。": "围绕种子告警涉及的域名、IP 和同基础设施指标，继续检索同时间窗内是否存在重复通信。",
        "以种子告警涉及的指标和当前关联事件中的域名 / IP 为枢纽，继续检索同时间窗内的重复通信。": "围绕种子告警涉及的域名、IP 和同基础设施指标，继续检索同时间窗内是否存在重复通信。",
        "同域名 / 同 目标 IP / 同 通信指纹": "相同域名、目标 IP 和相似通信特征",
        "同域名 / 同目标 IP / 同通信指纹": "相同域名、目标 IP 和相似通信特征",
        "同域名/同目标 IP/同通信指纹": "相同域名、目标 IP 和相似通信特征",
        "继续围绕相同域名、目标 IP 和相似通信特征 搜索更宽时间窗内的关联事件。": "继续围绕相同域名、目标 IP 和相似通信特征，在更宽时间窗内搜索关联事件。",
    }
    for source, target in replacements.items():
        text = text.replace(source, target)
    return text


def _reader_open_question_text(value: Any) -> str:
    text = _reader_clean_text(value)
    if not text:
        return ""
    replacements = {
        "当前仍缺少足够强的主机侧执行或扩散证据，当前结论需要结合人工复核。": "当前仍缺少足够强的主机侧执行或扩散证据，因此本次结论仍需要结合人工复核。",
        "当前关联事件中尚未观测到稳定的执行阶段证据。": "目前尚未看到足以确认执行阶段的稳定证据。",
        "其他关联资产目前更多体现为共享基础设施上的弱关联，仍需逐台确认是否真正受影响。": "其他关联资产目前更像共享基础设施带来的弱关联，仍需逐台确认是否真正受影响。",
    }
    for source, target in replacements.items():
        text = text.replace(source, target)
    if text == "是否存在主机侧执行、持久化或横向移动证据？":
        return "还需要进一步确认主机侧是否已经掌握能够直接支撑执行、持久化或横向移动的证据。"
    return text


def _reader_gap_clause_text(value: Any) -> str:
    text = _reader_open_question_text(value)
    if not text:
        return ""
    text = re.sub(r"^(.*)，是否", r"\1，仍需确认是否", text)
    text = re.sub(r"[？?。]+$", "", text).strip()
    if text.startswith("是否"):
        return f"还需要进一步确认{text[2:]}"
    return text


def _timeline_role_label(item: Dict[str, Any]) -> str:
    role = str(item.get("role") or "").strip()
    if role == "seed":
        return "种子告警"
    if role == "counterevidence":
        return "反证"
    stages = list(item.get("stages") or [])
    if "execution" in stages:
        return "执行线索"
    if "command-and-control" in stages:
        return "主证据"
    if role == "supporting":
        return "支撑证据"
    return "上下文"


def _status_code(status: str) -> str:
    if status == "confirmed_incident":
        return "confirmed"
    if status == "monitor_only":
        return "monitor_only"
    return "needs_review"


def _analysis_verdict(incident: Dict[str, Any]) -> Dict[str, Any]:
    return (
        incident.get("analysis_verdict")
        or incident.get("provisional_verdict")
        or ((incident.get("incident_state") or {}).get("analysis_verdict"))
        or ((incident.get("incident_state") or {}).get("provisional_verdict"))
        or incident.get("verdict")
        or {}
    )


def _delivery_verdict(incident: Dict[str, Any]) -> Dict[str, Any]:
    return (
        incident.get("delivery_verdict")
        or ((incident.get("incident_state") or {}).get("delivery_verdict"))
        or incident.get("verdict")
        or _analysis_verdict(incident)
        or {}
    )


def _verdicts_diverge(incident: Dict[str, Any]) -> bool:
    analysis = str((_analysis_verdict(incident).get("status")) or "").strip()
    delivery = str((_delivery_verdict(incident).get("status")) or "").strip()
    return bool(analysis and delivery and analysis != delivery)


def _reader_status_label_for_status(status: str) -> str:
    mapping = {
        "confirmed_incident": "确认安全事件",
        "needs_review": "可疑事件，建议继续复核",
        "monitor_only": "背景活动，建议持续观察",
    }
    return mapping.get(str(status or "").strip(), str(status or "").strip() or "待确认")


def _reader_status_label(incident: Dict[str, Any]) -> str:
    return _reader_status_label_for_status(str((_delivery_verdict(incident).get("status")) or "").strip())


def _meaningful_family_hint(text: str) -> str:
    hint = str(text or "").strip()
    lowered = hint.lower()
    if not hint:
        return ""
    if lowered.startswith("unknown"):
        return ""
    if lowered in {"suspicious", "unknown suspicious tls fingerprint"}:
        return ""
    if lowered in {
        "suspicious shared-infra beacon candidate",
        "backup traffic outlier candidate",
    }:
        return ""
    if "candidate" in lowered and "possible" not in lowered:
        return ""
    return hint


def _format_obs_refs(observation_ids: List[str]) -> str:
    refs = [str(item or "").strip() for item in observation_ids if str(item or "").strip()]
    if not refs:
        return "未引用"
    return ", ".join(refs)


def _kind_label(kind: str) -> str:
    mapping = {
        "alert": "告警",
        "flow": "网络流量",
        "dns": "DNS",
        "http": "HTTP",
        "asset_context": "资产背景",
    }
    return mapping.get(str(kind or "").strip(), str(kind or "").strip() or "上下文")


def _evidence_category(item: Dict[str, Any]) -> str:
    kind = str(item.get("kind") or "").strip()
    stages = list(item.get("stages") or [])
    summary = str(item.get("summary") or "").lower()
    if "execution" in stages or "powershell" in summary or "process" in summary or "w3wp" in summary:
        return "主机"
    if kind == "asset_context":
        return "资产背景"
    if kind in {"dns", "flow", "http", "alert"}:
        return "网络"
    return "上下文"


def _evidence_strength(item: Dict[str, Any], relation: str) -> str:
    stages = list(item.get("stages") or [])
    role = str(item.get("role") or "").strip()
    classification = str(item.get("classification") or "").strip()
    if relation == "counterevidence":
        if classification == "benign":
            return "高"
        return "中"
    if "execution" in stages or role == "seed" or classification == "malicious":
        return "高"
    if "command-and-control" in stages or classification in {"suspicious", "needs_review"}:
        return "高"
    return "中"


def _fact_description(item: Dict[str, Any]) -> str:
    ts = _format_time(item.get("ts"))
    asset_id = str(item.get("asset_id") or "").strip()
    indicator_text = str(item.get("indicator_text") or "").strip()
    summary = str(item.get("summary") or "").strip()
    stages = {str(stage or "").strip() for stage in list(item.get("stages") or [])}
    kind_label = "主机侧" if stages.intersection({"execution", "lateral-movement", "persistence", "credential-access"}) else _kind_label(str(item.get("kind") or "").strip())
    prefix_parts: List[str] = []
    if ts != "unknown":
        prefix_parts.append(f"在 {ts}")
    if asset_id:
        prefix_parts.append(f"资产 `{asset_id}`")
    prefix = "，".join(prefix_parts) if prefix_parts else "当前事件中"
    sentence = f"{prefix} 出现了一条{kind_label}观测"
    if indicator_text:
        sentence += f"，关联的核心指示物为 {indicator_text}"
    sentence += "。"
    if summary:
        sentence += f" 原始摘要显示：{summary}"
    return sentence.strip()


def _support_reason(item: Dict[str, Any], relation: str) -> str:
    why_it_matters = str(item.get("why_it_matters") or "").strip()
    stages = list(item.get("stages") or [])
    role = str(item.get("role") or "").strip()
    if relation == "counterevidence":
        if why_it_matters:
            return why_it_matters
        return "这条观测更支持背景解释或替代解释，而不是继续放大当前主假设。"
    if why_it_matters:
        return why_it_matters
    if "execution" in stages:
        return "它把网络侧异常推进到了主机侧异常，对事件定性的权重明显更高。"
    if "command-and-control" in stages:
        return "同一资产围绕同一基础设施的重复通信，是把单点告警扩展成事件链的关键。"
    if "initial-access" in stages:
        return "它补足了外联之前的高风险上下文，使后续可疑通信不再显得孤立。"
    if role == "seed":
        return "它为整个事件链提供了明确锚点，让后续调查可以围绕同一批指示物继续收敛。"
    return "这条观测为当前主假设提供了补充支撑，但需要和其他上下文结合理解。"


def _limitation_text(item: Dict[str, Any], relation: str) -> str:
    stages = list(item.get("stages") or [])
    role = str(item.get("role") or "").strip()
    if relation == "counterevidence":
        return "这类背景解释能够帮助收窄判断，但如果后续出现脱离基线的重复通信、执行线索或跨资产异常，它本身并不能永久关闭事件。"
    if "execution" in stages:
        return "当前仍缺少更细的命令行、落地文件、持久化或内存证据，因此可以确认存在执行线索，但还不能完整描述具体载荷。"
    if role == "seed":
        return "单条种子命中本身不能独立证明事件成立，仍需要结合重复通信、资产背景或主机侧线索共同定性。"
    if "command-and-control" in stages:
        return "仅凭网络侧重复通信仍可能在少数情况下被正常组件、同步组件或运维脚本解释，因此仍需要结合资产背景或主机侧结果。"
    if "initial-access" in stages:
        return "它解释了事件为何进入高风险状态，但单独仍不能证明漏洞利用已经成功执行。"
    return "这条观测本身更适合用来补足上下文，而不是单独承担最终结论。"


def _family_context(incident: Dict[str, Any]) -> Dict[str, Any] | None:
    seed = incident.get("seed") or {}
    entities = incident.get("entities") or {}
    session_state = incident.get("session_state") or {}
    incident_state = incident.get("incident_state") or {}
    hints = _dedupe_text(
        [_meaningful_family_hint((((seed.get("enrichment") or {}).get("info")) or ""))]
        + [_meaningful_family_hint(item) for item in list(entities.get("families") or [])]
    )
    if not hints:
        return None

    background_observation_ids = [
        str(item.get("observation_id") or "").strip()
        for item in list(incident_state.get("observations") or [])
        if str(item.get("tool_name") or "").strip() not in EVENT_TOOL_NAMES
    ]
    if not background_observation_ids:
        background_observation_ids = list(((incident.get("decision_basis") or {}).get("positive_observation_ids")) or [])

    primary_hint = hints[0]
    stage_labels = list(((incident.get("hypothesis") or {}).get("stages")) or [])
    stage_text = _format_stage_list(stage_labels)
    if stage_labels:
        summary = f"当前可获得的背景提示主要来自 seed 告警自带的家族/工具描述：{primary_hint}。它与本案已经观察到的阶段形态 {stage_text} 基本一致，更适合作为解释当前事件链的辅助背景。"
    else:
        summary = f"当前可获得的背景提示主要来自 seed 告警自带的家族/工具描述：{primary_hint}。它可以帮助理解为什么该告警被优先纳入调查，但不足以单独决定最终结论。"
    return {
        "hint": primary_hint,
        "summary": summary,
        "limits": "这类背景提示的价值在于帮助理解攻击链或工具形态，而不是直接完成家族归因、攻击团伙归因或样本级确认。",
        "observation_ids": _dedupe_text(background_observation_ids),
    }


def _unresolved_items(incident: Dict[str, Any]) -> List[str]:
    uncertainties = [str(item or "").strip() for item in list(incident.get("uncertainties") or [])]
    questions = [
        str((item.get("question") if isinstance(item, dict) else item) or "").strip()
        for item in list(incident.get("open_questions") or [])
    ]
    return _dedupe_text(uncertainties + questions)


def _boundary_candidate_events(incident: Dict[str, Any]) -> List[Dict[str, Any]]:
    incident_state = incident.get("incident_state") or {}
    event_map: Dict[str, Dict[str, Any]] = {}
    for event in list(((incident.get("cluster") or {}).get("events")) or []):
        event_id = str(event.get("id") or "").strip()
        if event_id:
            event_map[event_id] = dict(event)
    for event_id, event in dict(incident_state.get("known_events") or {}).items():
        normalized_id = str(event_id or "").strip()
        if normalized_id and normalized_id not in event_map:
            event_map[normalized_id] = dict(event)

    boundary_rows: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for observation in list(incident_state.get("observations") or []):
        if str(observation.get("tool_name") or "").strip() != "ground_candidate_event":
            continue
        boundary_event_ids = _dedupe_text(
            [str(item or "").strip() for item in list(observation.get("boundary_event_ids") or []) if str(item or "").strip()]
        )
        if not boundary_event_ids and str(observation.get("relation") or "").strip() == "context":
            boundary_event_ids = _dedupe_text(
                [str(item.get("id") or "").strip() for item in list(observation.get("events") or []) if str(item.get("id") or "").strip()]
            )
        for event_id in boundary_event_ids:
            if not event_id or event_id in seen:
                continue
            event = dict(event_map.get(event_id) or {})
            if not event:
                continue
            seen.add(event_id)
            boundary_rows.append(
                {
                    "event_id": event_id,
                    "event": event,
                    "summary": str(observation.get("summary") or "").strip(),
                    "observation_id": str(observation.get("observation_id") or "").strip(),
                }
            )
    boundary_rows.sort(key=lambda item: str(((item.get("event") or {}).get("ts")) or ""))
    return boundary_rows


def _boundary_indicator_text(event: Dict[str, Any]) -> str:
    values = _dedupe_text(
        [
            str(event.get("domain") or "").strip(),
            str(event.get("dst_ip") or "").strip(),
        ]
    )
    return " / ".join(values[:2]) if values else "相关对象"


def _boundary_candidate_summary(incident: Dict[str, Any]) -> str:
    rows = _boundary_candidate_events(incident)
    if not rows:
        return ""
    assets = _dedupe_text(str((item.get("event") or {}).get("asset_id") or "").strip() for item in rows)
    indicators = _dedupe_text(_boundary_indicator_text(dict(item.get("event") or {})) for item in rows)
    asset_text = "、".join(assets[:3]) if assets else "关联资产"
    indicator_text = "、".join(indicators[:3]) if indicators else "后续基础设施"
    return f"另有 {len(rows)} 条已完成 grounding 但仍缺少独立支撑的扩展线索，主要涉及 {asset_text} 与 {indicator_text}，当前先作为边界保留，不直接计入已确认影响范围。"


def _boundary_candidate_clauses(incident: Dict[str, Any], *, limit: int = 2) -> List[str]:
    clauses: List[str] = []
    for item in _boundary_candidate_events(incident)[: max(0, int(limit))]:
        event = dict(item.get("event") or {})
        asset_id = str(event.get("asset_id") or "").strip() or "相关资产"
        indicator_text = _boundary_indicator_text(event)
        stages = {str(stage or "").strip() for stage in list(event.get("stages") or [])}
        if "lateral-movement" in stages or "execution" in stages:
            clauses.append(
                f"{asset_id} 围绕 {indicator_text} 的后续主机侧动作已被观察到，但暂缺独立命中，当前只作为待确认扩展"
            )
        elif "command-and-control" in stages:
            clauses.append(
                f"{asset_id} 围绕 {indicator_text} 的后续可疑通信已被观察到，但暂缺独立命中，当前只作为待确认扩展"
            )
        elif str(event.get("kind") or "").strip().lower() == "dns":
            clauses.append(
                f"{asset_id} 围绕 {indicator_text} 的后续解析线索已被观察到，但暂缺独立命中，当前只作为待确认扩展"
            )
        else:
            clauses.append(
                f"{asset_id} 围绕 {indicator_text} 的后续关联线索已被观察到，但暂缺独立命中，当前只作为待确认扩展"
            )
    return _dedupe_text(clauses)


def _boundary_lines(incident: Dict[str, Any]) -> List[str]:
    verdict = _analysis_verdict(incident)
    entities = incident.get("entities") or {}
    status = str(verdict.get("status") or "").strip()
    unresolved = _unresolved_items(incident)

    if status == "confirmed_incident":
        lines = [
            f"目前事件范围主要收敛在 {'、'.join(entities.get('suspected_assets') or []) or '最先发现的资产'} 上，已经可以按安全事件处置，但暂未确认是否存在更大范围扩散。"
        ]
    elif status == "monitor_only":
        lines = [
            "目前更倾向于把这起异常解释为计划内活动中的弱信号，而不是已成立入侵事件。"
        ]
    else:
        lines = [
            "目前已经形成相互关联的异常线索，但还不足以直接确认为已成立安全事件。"
        ]

    boundary_summary = _boundary_candidate_summary(incident)
    if boundary_summary:
        unresolved = [boundary_summary] + unresolved
    return _dedupe_text(lines + unresolved)


def _supporting_entries(incident: Dict[str, Any]) -> List[Dict[str, Any]]:
    items = list(((incident.get("decision_basis") or {}).get("positive_signals")) or [])[:4]
    entries: List[Dict[str, Any]] = []
    for index, item in enumerate(items, start=1):
        entries.append(
            {
                "id": f"E-{index:02d}",
                "category": _evidence_category(item),
                "strength": _evidence_strength(item, "supporting"),
                "fact_description": _fact_description(item),
                "reason_text": _support_reason(item, "supporting"),
                "limitation_text": _limitation_text(item, "supporting"),
                "observation_ids": list(item.get("observation_ids") or []),
            }
        )
    return entries


def _counter_entries(incident: Dict[str, Any]) -> List[Dict[str, Any]]:
    items = list(((incident.get("decision_basis") or {}).get("counterevidence")) or [])[:4]
    entries: List[Dict[str, Any]] = []
    for index, item in enumerate(items, start=1):
        entries.append(
            {
                "id": f"C-{index:02d}",
                "category": _evidence_category(item),
                "strength": _evidence_strength(item, "counterevidence"),
                "fact_description": _fact_description(item),
                "reason_text": _support_reason(item, "counterevidence"),
                "limitation_text": _limitation_text(item, "counterevidence"),
                "observation_ids": list(item.get("observation_ids") or []),
            }
        )
    return entries


def _timeline_entries(incident: Dict[str, Any]) -> List[Dict[str, Any]]:
    timeline = list(incident.get("timeline") or [])
    event_map = {
        str(item.get("id") or "").strip(): item
        for item in list(((incident.get("cluster") or {}).get("events")) or [])
        if str(item.get("id") or "").strip()
    }
    decision_basis = incident.get("decision_basis") or {}
    boundary_event_ids = {
        str(item.get("event_id") or "").strip()
        for item in _boundary_candidate_events(incident)
        if str(item.get("event_id") or "").strip()
    }
    observation_map: Dict[str, List[str]] = {}
    for item in list(decision_basis.get("positive_signals") or []) + list(decision_basis.get("counterevidence") or []):
        event_id = str(item.get("event_id") or "").strip()
        if event_id:
            observation_map[event_id] = list(item.get("observation_ids") or [])

    entries: List[Dict[str, Any]] = []
    for item in timeline:
        event_id = str(item.get("event_id") or "").strip()
        summary = str(item.get("summary") or "").strip()
        source_event = event_map.get(event_id)
        if source_event:
            signal = _signal_view_from_event(source_event)
            stages = {str(stage or "").strip() for stage in list(signal.get("stages") or [])}
            event_role = str(source_event.get("role") or "").strip()
            report_role = "corroborating_evidence"
            relation = "supporting"
            if event_role == "seed":
                report_role = "trigger_evidence"
            elif event_role == "counterevidence":
                report_role = "counterevidence"
                relation = "counterevidence"
            elif stages.intersection({"execution", "lateral-movement", "exfiltration", "persistence", "credential-access"}):
                report_role = "progression_evidence"
            body = _report_fact_body_from_signal(signal, role=report_role, relation=relation)
            asset_id = str(source_event.get("asset_id") or "").strip()
            if body and asset_id:
                summary = _reader_clean_text(f"资产 `{asset_id}` {body}。")
            elif body:
                summary = _reader_clean_text(f"{body}。")
        summary = _reader_clean_text(summary)
        entries.append(
            {
                "ts": item.get("ts"),
                "summary": summary,
                "role": "待确认扩展" if event_id in boundary_event_ids else _timeline_role_label(source_event or item),
                "observation_ids": observation_map.get(event_id, []),
            }
        )
    return entries


def _primary_action(recommendations: List[str]) -> str:
    if recommendations:
        return recommendations[0]
    return "结合事件边界和关键证据，优先围绕种子资产与核心外部指示物继续收敛处置。"


def _bucket_recommendations(recommendations: List[str]) -> Dict[str, List[str]]:
    immediate: List[str] = []
    short_term: List[str] = []
    follow_up: List[str] = []
    immediate_hints = ("立即", "隔离", "封禁", "阻断", "优先", "重点监控")
    follow_hints = ("剧本", "规则", "白名单", "基线", "沉淀", "持续检测")

    for item in recommendations:
        text = str(item or "").strip()
        if not text:
            continue
        if any(hint in text for hint in follow_hints):
            follow_up.append(text)
        elif any(hint in text for hint in immediate_hints):
            immediate.append(text)
        else:
            short_term.append(text)

    if not immediate and short_term:
        immediate.append(short_term.pop(0))
    return {
        "immediate": _dedupe_text(immediate),
        "short_term": _dedupe_text(short_term),
        "follow_up": _dedupe_text(follow_up),
    }


def _ioc_rows(incident: Dict[str, Any]) -> List[Dict[str, str]]:
    entities = incident.get("entities") or {}
    scope = incident.get("scope") or {}
    seed = incident.get("seed") or {}
    rows: List[Dict[str, str]] = []

    primary_external = set(str(item or "").strip() for item in list(scope.get("primary_external_indicators") or []))
    for ip in list(entities.get("external_ips") or []):
        rows.append(
            {
                "type": "IP",
                "value": str(ip or "").strip(),
                "relation": "事件中的核心外部基础设施" if str(ip or "").strip() in primary_external else "事件中的关联外部地址",
            }
        )
    for domain in list(entities.get("domains") or []):
        rows.append(
            {
                "type": "域名",
                "value": str(domain or "").strip(),
                "relation": "种子告警前后持续出现的关联域名" if str(domain or "").strip() in primary_external else "事件中的关联域名",
            }
        )
    fingerprint = (seed.get("trigger_fingerprint") or {})
    fp_type = str(fingerprint.get("type") or "").strip()
    fp_value = str(fingerprint.get("value") or "").strip()
    if fp_type and fp_value:
        rows.append(
            {
                "type": fp_type,
                "value": fp_value,
                "relation": "种子告警命中的关键指纹",
            }
        )

    for item in list(((incident.get("decision_basis") or {}).get("positive_signals")) or []):
        summary = str(item.get("summary") or "").strip()
        if "execution" in list(item.get("stages") or []) or "powershell" in summary.lower() or "w3wp" in summary.lower():
            rows.append(
                {
                    "type": "行为线索",
                    "value": summary,
                    "relation": "执行阶段的重要主机侧线索",
                }
            )
            break

    return [row for row in rows if row["value"]]


def _observation_rows(incident: Dict[str, Any]) -> List[Dict[str, str]]:
    observations = list(((incident.get("incident_state") or {}).get("observations")) or [])
    rows: List[Dict[str, str]] = []
    for item in observations:
        obs_id = str(item.get("observation_id") or "").strip()
        tool_name = str(item.get("tool_name") or "").strip()
        summary = str(item.get("summary") or "").strip()
        source_type = str(item.get("source_type") or "").strip()
        source_ref = str(item.get("source_ref") or "").strip()
        if obs_id:
            rows.append(
                {
                    "observation_id": obs_id,
                    "tool_name": tool_name,
                    "source_type": source_type or "unknown",
                    "source_ref": source_ref,
                    "summary": summary or "无摘要",
                }
            )
    return rows


def _delivery_readiness(incident: Dict[str, Any]) -> Dict[str, Any]:
    readiness = incident.get("readiness") or {}
    provisional = _analysis_verdict(incident)
    delivery = _delivery_verdict(incident)
    blocking_checks = list(readiness.get("blocking_checks") or [])
    blocking_items = [str(item.get("reason") or "").strip() for item in blocking_checks if str(item.get("reason") or "").strip()]
    provisional_label = str(provisional.get("status_label") or "").strip()
    delivery_label = str(delivery.get("status_label") or "").strip()

    provisional_status = str(provisional.get("status") or "").strip()
    delivery_status = str(delivery.get("status") or "").strip()

    if provisional_label and delivery_label and provisional_label != delivery_label:
        if provisional_status == "monitor_only" and delivery_status == "needs_review":
            summary = "现有迹象更接近计划内背景活动，但由于关键背景链路仍需进一步核实，当前仍建议按可疑事件继续复核。"
        elif provisional_status == "confirmed_incident" and delivery_status == "needs_review":
            summary = "现有迹象已经明显偏向安全事件，但在完成关键核验前，当前仍建议按高优先级可疑事件持续处置。"
        else:
            summary = "当前证据与交付结论之间仍存在需要补足的核查环节，建议继续补充证据后再完成正式交付。"
    else:
        if bool(readiness.get("ready_for_delivery")):
            if delivery_status == "confirmed_incident":
                summary = "主要证据和必要核查已到位，可按确认安全事件处置。"
            elif delivery_status == "monitor_only":
                summary = "背景解释已经完成必要核查，可按背景活动持续观察。"
            else:
                summary = "当前已能形成稳定的可疑事件结论，建议继续人工复核。"
        else:
            summary = "当前还缺少直接支撑最终结论的关键核查，建议继续补充证据后再完成正式交付。"
    return {
        "ready_for_delivery": bool(readiness.get("ready_for_delivery")),
        "summary": summary,
        "blocking_items": blocking_items,
        "provisional_conclusion": provisional_label,
        "delivery_conclusion": delivery_label,
    }


def _scope_summary(incident: Dict[str, Any]) -> Dict[str, Any]:
    verdict = _delivery_verdict(incident)
    entities = incident.get("entities") or {}
    scope = incident.get("scope") or {}
    seed = incident.get("seed") or {}
    boundary = _boundary_lines(incident)
    unresolved = boundary[1:] if len(boundary) > 1 else []
    status = str(verdict.get("status") or "").strip()
    suspected_label = "疑似受影响资产" if status == "confirmed_incident" else "重点观察资产"
    related_label = "待排查关联资产" if status == "needs_review" else "关联资产"
    seed_time = _format_time(seed.get("event_time"))
    trigger_fingerprint = (seed.get("trigger_fingerprint") or {})
    seed_text = (
        f"{seed_time}，{entities.get('seed_asset') or '种子资产'} 命中 {str(((seed.get('enrichment') or {}).get('info')) or 'seed alert').strip()} "
        f"{trigger_fingerprint.get('type') or ''} 规则。"
    ).replace("  ", " ").strip()

    result = {
        "seed_alert": seed_text,
        "time_window": scope.get("time_window") or {},
        "seed_asset": entities.get("seed_asset"),
        "suspected_label": suspected_label,
        "suspected_assets": list(entities.get("suspected_assets") or []),
        "related_label": related_label,
        "related_assets": list(entities.get("related_assets") or []),
        "internal_ips": list(entities.get("internal_ips") or []),
        "external_ips": list(entities.get("external_ips") or []),
        "domains": list(entities.get("domains") or []),
        "stage_labels": [_stage_label(stage) for stage in list(((incident.get("hypothesis") or {}).get("stages")) or [])],
        "primary_external_indicators": list(scope.get("primary_external_indicators") or []),
        "contextual_external_indicators": list(scope.get("contextual_external_indicators") or []),
        "event_count": scope.get("event_count"),
        "primary_event_count": scope.get("primary_event_count"),
        "context_event_count": scope.get("context_event_count"),
        "counterevidence_count": scope.get("counterevidence_count"),
        "current_boundary": boundary[0] if boundary else "",
        "unresolved_scope": unresolved,
    }
    return result


def _analysis_summary(incident: Dict[str, Any]) -> Dict[str, Any]:
    verdict = _analysis_verdict(incident)
    decision_basis = incident.get("decision_basis") or {}
    session_state = incident.get("session_state") or {}
    hypotheses = list(session_state.get("working_hypotheses") or [])
    primary = next((item for item in hypotheses if str(item.get("kind") or "") == "primary"), {})
    benign = next((item for item in hypotheses if str(item.get("kind") or "") == "benign"), {})
    secondary = next((item for item in hypotheses if str(item.get("kind") or "") == "secondary"), {})
    unresolved = _unresolved_items(incident)
    status = str(verdict.get("status") or "").strip()
    rationale_items = _dedupe_text(
        [str(decision_basis.get("narrative") or "").strip(), str(decision_basis.get("positive_summary") or "").strip()]
        + [str(item or "").strip() for item in list(verdict.get("rationale") or [])]
    )
    status_reason = str(decision_basis.get("counter_summary") or "").strip()
    if not status_reason:
        if status == "confirmed_incident":
            status_reason = "当前已经足够升级为确认事件，但还没有证据支持把事件范围直接扩大到明确扩散或明确数据外传。"
        elif status == "monitor_only":
            status_reason = "当前反证和背景解释足以让我们把告警降级为观察对象，而不是直接按入侵事件处置。"
        else:
            status_reason = "当前已经形成可疑上下文，但还缺少把结论稳定推进到确认事件的关键补强证据。"
    return {
        "primary_hypothesis": str(primary.get("title") or (incident.get("hypothesis") or {}).get("title") or "").strip(),
        "alternative_hypothesis": str(benign.get("title") or secondary.get("title") or "暂无稳定替代解释").strip(),
        "why_this_conclusion": _reader_clean_text(" ".join(item for item in rationale_items if item)),
        "why_not_other_status": _reader_clean_text(status_reason),
        "unresolved_items": [_reader_clean_text(item) for item in unresolved if _reader_clean_text(item)],
        "next_best_evidence": unresolved[:3],
    }


def build_incident_topology(incident: Dict[str, Any]) -> Dict[str, Any]:
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    added_nodes: set[str] = set()

    def add_node(node_id: str, *, label: str, node_type: str) -> None:
        if node_id in added_nodes:
            return
        added_nodes.add(node_id)
        nodes.append({"id": node_id, "label": label, "type": node_type})

    events = list(((incident.get("cluster") or {}).get("events")) or [])
    entities = incident.get("entities") or {}
    fingerprint = (incident.get("seed") or {}).get("trigger_fingerprint") or {}
    fp_value = str(fingerprint.get("value") or "").strip()
    fp_type = str(fingerprint.get("type") or "").strip().lower()
    if fp_value and fp_type:
        add_node(f"fp:{fp_type}:{fp_value}", label=f"{fingerprint.get('type')} {fp_value}", node_type=f"fingerprint_{fp_type}")

    for asset_id in _dedupe_text(list(entities.get("observed_assets") or []) + list(entities.get("assets") or [])):
        add_node(f"asset:{asset_id}", label=asset_id, node_type="internal_host")

    for ip in _dedupe_text(list(entities.get("external_ips") or [])):
        add_node(f"ip:{ip}", label=ip, node_type="external_ip")

    for domain in _dedupe_text(list(entities.get("domains") or [])):
        add_node(f"domain:{domain}", label=domain, node_type="domain")

    for event in events:
        asset_id = str(event.get("asset_id") or "").strip()
        dst_ip = str(event.get("dst_ip") or "").strip()
        domain = str(event.get("domain") or "").strip()

        if asset_id:
            add_node(f"asset:{asset_id}", label=asset_id, node_type="internal_host")
        if dst_ip:
            add_node(f"ip:{dst_ip}", label=dst_ip, node_type="external_ip")
        if domain:
            add_node(f"domain:{domain}", label=domain, node_type="domain")

        if asset_id and dst_ip:
            edges.append(
                {
                    "id": f"edge:{event['id']}:asset-ip",
                    "source": f"asset:{asset_id}",
                    "target": f"ip:{dst_ip}",
                    "label": str(event.get("kind") or "event"),
                }
            )
        if dst_ip and domain:
            edges.append(
                {
                    "id": f"edge:{event['id']}:ip-domain",
                    "source": f"ip:{dst_ip}",
                    "target": f"domain:{domain}",
                    "label": "resolves_to",
                }
            )
        if asset_id and fp_value:
            edges.append(
                {
                    "id": f"edge:{event['id']}:asset-fp",
                    "source": f"asset:{asset_id}",
                    "target": f"fp:{fp_type}:{fp_value}",
                    "label": "seed_indicator",
                }
            )

    return {
        "version": "2.0",
        "title": "事件级溯源拓扑",
        "nodes": nodes,
        "edges": edges,
    }


def _reader_delivery_judgment(verdict: Dict[str, Any]) -> str:
    status = str(verdict.get("status") or "").strip()
    if status == "confirmed_incident":
        return "当前证据支持将本案按已成立安全事件处置。"
    if status == "monitor_only":
        return "当前更适合按背景活动中的弱信号处理，并保留后续复核。"
    return "当前已经形成可疑事件链，但仍应按待人工复核结论交付。"


def _reader_analysis_judgment(incident: Dict[str, Any]) -> str:
    verdict = _analysis_verdict(incident)
    status = str(verdict.get("status") or "").strip()
    if status == "confirmed_incident":
        return "从现有证据看，本案已经具备按已成立安全事件研判的基础。"
    if status == "monitor_only":
        return "从现有证据看，本案更接近背景活动中的弱信号，而不是已成立入侵事件。"
    return "从现有证据看，本案已经形成可疑事件链，但关键定性证据仍需补强。"


def _reader_boundary_text(incident: Dict[str, Any]) -> str:
    entities = incident.get("entities") or {}
    scope = incident.get("scope") or {}
    affected_assets = list(entities.get("suspected_assets") or [])
    related_assets = list(entities.get("related_assets") or [])
    indicators = list(scope.get("primary_external_indicators") or [])

    asset_text = "、".join(affected_assets) if affected_assets else (entities.get("seed_asset") or "最先发现的资产")
    indicator_text = "、".join(indicators[:3]) if indicators else "当前关键对外通信对象"
    if related_assets:
        return f"目前影响范围主要收敛在 {asset_text}，另外还有需要继续核实的关联资产 { '、'.join(related_assets[:3]) }；关键对外通信对象为 {indicator_text}。"
    return f"目前影响范围主要收敛在 {asset_text}，关键对外通信对象为 {indicator_text}。"


def _reader_user_judgment(incident: Dict[str, Any]) -> str:
    analysis_status = str((_analysis_verdict(incident).get("status")) or "").strip()
    delivery_status = str((_delivery_verdict(incident).get("status")) or "").strip()
    if analysis_status and delivery_status and analysis_status != delivery_status:
        if analysis_status == "monitor_only" and delivery_status == "needs_review":
            return "当前异常与计划内维护或更新活动高度重合，但关键背景链路仍缺少直接核验，因此本次仍建议继续复核。"
        if analysis_status == "confirmed_incident" and delivery_status == "needs_review":
            return "现有迹象已经明显偏向安全事件，但在完成关键核验前，仍建议按高优先级可疑事件持续处置。"
    if delivery_status == "confirmed_incident":
        return "当前证据已经足以支撑按安全事件处置。"
    if delivery_status == "monitor_only":
        return "当前更接近背景活动，建议保留样本并持续观察。"
    return "目前已形成可疑事件线索，但仍需继续核实关键细节。"


def _reader_one_sentence_summary(incident: Dict[str, Any]) -> str:
    analysis_verdict = _analysis_verdict(incident)
    delivery_verdict = _delivery_verdict(incident)
    entities = incident.get("entities") or {}
    scope = incident.get("scope") or {}
    events = list(((incident.get("cluster") or {}).get("events")) or [])
    asset_text = str(entities.get("seed_asset") or "相关资产").strip()
    indicator_text = _join_items(list(scope.get("primary_external_indicators") or [])[:2])
    has_execution = any("execution" in list(item.get("stages") or []) for item in events)
    has_repeated_c2 = sum(1 for item in events if "command-and-control" in list(item.get("stages") or [])) >= 2
    analysis_status = str(analysis_verdict.get("status") or "").strip()
    delivery_status = str(delivery_verdict.get("status") or "").strip()

    if analysis_status and delivery_status and analysis_status != delivery_status:
        if analysis_status == "monitor_only":
            return f"当前围绕资产 {asset_text} 的异常更接近计划内背景活动，但由于关键背景链路仍需进一步核实，本次仍建议继续复核。"
        elif analysis_status == "confirmed_incident":
            return f"围绕资产 {asset_text} 的证据已经明显偏向已成立安全事件，但在完成关键核验前仍建议按高优先级可疑事件持续处置。"
        return f"围绕资产 {asset_text} 已形成可疑事件链，但在完成关键核验前仍建议继续复核。"

    if analysis_status == "confirmed_incident":
        if has_execution and indicator_text != "未识别":
            return f"资产 {asset_text} 围绕 {indicator_text} 出现重复可疑外联，并在随后出现执行线索，当前应按已成立安全事件处置。"
        if has_repeated_c2 and indicator_text != "未识别":
            return f"资产 {asset_text} 围绕 {indicator_text} 出现重复可疑外联，已经形成连续事件链，当前应按已成立安全事件处置。"
        return f"当前围绕资产 {asset_text} 已形成足以支撑事件成立的关键证据链，建议按已成立安全事件处置。"

    if analysis_status == "monitor_only":
        return f"当前围绕资产 {asset_text} 的异常更接近背景活动或计划内行为，建议持续观察并保留后续复核。"

    if has_execution:
        return f"资产 {asset_text} 已出现从可疑外联延伸到执行线索的迹象，但关键定性证据仍需人工复核。"
    if indicator_text != "未识别":
        return f"资产 {asset_text} 围绕 {indicator_text} 已形成可疑事件链，但目前仍需进一步核实。"
    return f"当前已形成围绕资产 {asset_text} 的可疑事件链，但关键定性证据仍需进一步补强。"


def _event_observation_map(incident: Dict[str, Any]) -> Dict[str, List[str]]:
    mapping: Dict[str, List[str]] = {}
    for item in list(incident.get("evidence_ledger") or []):
        observation_id = str(item.get("observation_id") or "").strip()
        if not observation_id:
            continue
        for event_id in list(item.get("event_ids") or []):
            event_key = str(event_id or "").strip()
            if not event_key:
                continue
            mapping.setdefault(event_key, []).append(observation_id)
    return {key: _dedupe_text(value) for key, value in mapping.items()}


def _event_indicator_text(event: Dict[str, Any]) -> str:
    values: List[str] = []
    dst_ip = str(event.get("dst_ip") or "").strip()
    domain = str(event.get("domain") or "").strip()
    if dst_ip:
        values.append(dst_ip)
    if domain:
        values.append(domain)
    if event.get("ja4"):
        values.append(f"JA4 {event['ja4']}")
    answers = [str(item or "").strip() for item in list(event.get("answers") or []) if str(item or "").strip()]
    if answers:
        values.append(f"DNS answers {', '.join(answers[:2])}")
    return " / ".join(values)


def _reader_indicator_text(event: Dict[str, Any]) -> str:
    values: List[str] = []
    domain = str(event.get("domain") or "").strip()
    dst_ip = str(event.get("dst_ip") or "").strip()
    if domain:
        values.append(domain)
    if dst_ip and dst_ip not in values:
        values.append(dst_ip)
    return " / ".join(values[:2])


def _signal_view_from_event(event: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "ts": event.get("ts"),
        "asset_id": event.get("asset_id"),
        "src_ip": event.get("src_ip"),
        "dst_ip": event.get("dst_ip"),
        "domain": event.get("domain"),
        "answers": list(event.get("answers") or []),
        "tags": list(event.get("tags") or []),
        "indicator_text": _event_indicator_text(event),
        "summary": event.get("summary"),
        "kind": event.get("kind"),
        "role": event.get("role"),
        "classification": event.get("classification"),
        "stages": list(event.get("stages") or []),
    }


def _reader_fact_from_event(event: Dict[str, Any]) -> str:
    ts = _format_time(event.get("ts"))
    asset_id = str(event.get("asset_id") or "").strip() or "相关资产"
    indicator_text = _reader_indicator_text(event)
    has_indicator = bool(str(indicator_text or "").strip())
    indicator_text = indicator_text or "相关对外通信对象"
    role = str(event.get("role") or "").strip()
    kind = str(event.get("kind") or "").strip().lower()
    stages = list(event.get("stages") or [])

    if role == "seed":
        return f"在 {ts}，最先在资产 `{asset_id}` 上发现与 {indicator_text} 相关的异常通信。"
    if "execution" in stages:
        return f"在 {ts}，同一资产 `{asset_id}` 在异常通信之后出现执行或横向操作迹象，说明风险已经进一步升级。"
    if role == "counterevidence":
        if not has_indicator:
            return f"在 {ts}，同时间窗内还出现了更接近计划内维护或更新背景的活动。"
        return f"在 {ts}，同时间窗内还观察到与 {indicator_text} 相关、但更接近计划内维护或更新背景的访问。"
    if kind == "dns":
        return f"在 {ts}，资产 `{asset_id}` 已经提前与 {indicator_text} 建立了解析或访问准备。"
    if "command-and-control" in stages:
        return f"在 {ts}，资产 `{asset_id}` 再次与 {indicator_text} 通信，说明该行为具有持续性，而不是孤立命中。"
    if not has_indicator:
        return f"在 {ts}，资产 `{asset_id}` 出现了一条关键关联观测。"
    return f"在 {ts}，资产 `{asset_id}` 出现了一条与 {indicator_text} 相关的关键关联观测。"


def _story_line_from_event(event: Dict[str, Any], observation_map: Dict[str, List[str]]) -> str:
    return _reader_fact_from_event(event)


def _reader_progression(incident: Dict[str, Any]) -> List[str]:
    events = list(((incident.get("cluster") or {}).get("events")) or [])
    observation_map = _event_observation_map(incident)
    events.sort(key=lambda item: str(item.get("ts") or ""))

    selected: List[Dict[str, Any]] = []
    seen_themes: set[str] = set()
    for event in events:
        role = str(event.get("role") or "").strip()
        if role == "counterevidence":
            continue
        stages = list(event.get("stages") or [])
        kind = str(event.get("kind") or "").strip().lower()
        theme = "context"
        if "execution" in stages:
            theme = "execution"
        elif role == "seed":
            theme = "seed"
        elif kind == "dns":
            theme = "pre_beacon_dns"
        elif "command-and-control" in stages:
            theme = "beacon"
        if theme in seen_themes:
            continue
        seen_themes.add(theme)
        selected.append(event)
    if not selected and events:
        selected.append(events[0])
    selected.sort(key=lambda item: str(item.get("ts") or ""))
    return [_story_line_from_event(event, observation_map) for event in selected[:5]]


def _reader_theme_key(item: Dict[str, Any]) -> str:
    stages = list(item.get("stages") or [])
    role = str(item.get("role") or "").strip()
    kind = str(item.get("kind") or "").strip().lower()
    if "execution" in stages:
        return "execution"
    if "initial-access" in stages:
        return "initial_access"
    if kind == "dns":
        return "prep"
    if role == "seed" or "command-and-control" in stages:
        return "beacon"
    return "context"


def _reader_theme_title(theme: str) -> str:
    mapping = {
        "beacon": "为什么认为这是异常通信",
        "execution": "为什么判断风险已经升级",
        "initial_access": "为什么怀疑存在入侵迹象",
        "prep": "异常发生前后的关联迹象",
        "context": "补充背景",
    }
    return mapping.get(theme, "关键关联事实")


def _reader_supporting_blocks(incident: Dict[str, Any]) -> List[Dict[str, Any]]:
    items = [
        item
        for item in list(((incident.get("cluster") or {}).get("events")) or [])
        if str(item.get("role") or "").strip() in {"seed", "supporting"}
    ]
    observation_map = _event_observation_map(incident)
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for item in items:
        groups.setdefault(_reader_theme_key(item), []).append(item)

    blocks: List[Dict[str, Any]] = []
    for theme in ("beacon", "execution", "initial_access", "prep", "context"):
        group_items = groups.get(theme) or []
        if not group_items:
            continue
        facts = [_reader_fact_from_event(item) for item in group_items[:2]]
        reasons = _dedupe_text(
            [
                _support_reason(_signal_view_from_event(item), "supporting")
                for item in group_items
                if _support_reason(_signal_view_from_event(item), "supporting")
            ]
        )
        limits = _dedupe_text(
            [
                _limitation_text(_signal_view_from_event(item), "supporting")
                for item in group_items
                if _limitation_text(_signal_view_from_event(item), "supporting")
            ]
        )
        observation_ids = _dedupe_text(
            observation_id
            for item in group_items
            for observation_id in list(observation_map.get(str(item.get("id") or "").strip(), []))
        )
        blocks.append(
            {
                "title": _reader_theme_title(theme),
                "facts": facts,
                "judgment": reasons[0] if reasons else "这组事实为当前结论提供了直接支撑。",
                "boundary": limits[0] if limits else "当前仍需结合其他证据共同理解。",
                "observation_ids": observation_ids,
            }
        )
    return blocks[:2]


def _reader_counter_block(incident: Dict[str, Any]) -> Dict[str, Any] | None:
    items = [
        item
        for item in list(((incident.get("cluster") or {}).get("events")) or [])
        if str(item.get("role") or "").strip() == "counterevidence"
    ]
    if not items:
        return None
    observation_map = _event_observation_map(incident)
    facts = [_reader_fact_from_event(item) for item in items[:2]]
    reasons = _dedupe_text(
        [
            _support_reason(_signal_view_from_event(item), "counterevidence")
            for item in items
            if _support_reason(_signal_view_from_event(item), "counterevidence")
        ]
    )
    limits = _dedupe_text(
        [
            _limitation_text(_signal_view_from_event(item), "counterevidence")
            for item in items
            if _limitation_text(_signal_view_from_event(item), "counterevidence")
        ]
    )
    observation_ids = _dedupe_text(
        observation_id
        for item in items
        for observation_id in list(observation_map.get(str(item.get("id") or "").strip(), []))
    )
    return {
        "title": "反证与替代解释",
        "facts": facts,
        "judgment": reasons[0] if reasons else "这些背景事实提醒我们不要把所有异常都直接解释为入侵。",
        "boundary": limits[0] if limits else "反证有助于收窄判断，但不能替代主证据链。",
        "observation_ids": observation_ids,
    }


def _render_action_group(title: str, items: List[str]) -> List[str]:
    if not items:
        return []
    lines = ["", title]
    for item in items:
        lines.append(f"- {item}")
    return lines


def _delivery_blocking_primary_action(incident: Dict[str, Any]) -> str:
    readiness = incident.get("readiness") or {}
    analysis_status = str((_analysis_verdict(incident).get("status")) or "").strip()
    blocking_ids = [
        str(item.get("id") or "").strip()
        for item in list(readiness.get("blocking_checks") or [])
        if str(item.get("id") or "").strip()
    ]
    action_map = {
        "context_built": "先补充最初告警前后的上下文，确认该行为不是孤立访问。",
        "cluster_built": "继续核实是否存在重复通信或关联资产上的同类行为。",
        "timeline_built": "补齐关键时间线，确认异常发生前后是否与计划内活动一致。",
        "scope_assessed": "进一步确认影响资产和对外通信对象，避免误判事件范围。",
        "evidence_chain_ready": "补充能够直接支撑当前判断的关键核查结果。",
        "counterevidence_checked": "优先补做显式反证检查，核验维护窗口、补丁、备份或共享基线是否足以解释当前信号。",
        "supplemental_context_reviewed": "整理关键事实和背景信息，确保当前结论能够直接支撑正式交付。",
    }
    if analysis_status == "monitor_only":
        preferred_order = [
            "counterevidence_checked",
            "supplemental_context_reviewed",
            "timeline_built",
            "scope_assessed",
            "evidence_chain_ready",
            "cluster_built",
            "context_built",
        ]
    else:
        preferred_order = [
            "context_built",
            "cluster_built",
            "timeline_built",
            "scope_assessed",
            "evidence_chain_ready",
            "counterevidence_checked",
            "supplemental_context_reviewed",
        ]
    ordered_ids = preferred_order + [item for item in blocking_ids if item not in preferred_order]
    for check_id in ordered_ids:
        if check_id not in blocking_ids:
            continue
        action = action_map.get(check_id)
        if action:
            return action
    return ""


def _executive_headline(incident: Dict[str, Any]) -> str:
    analysis = _analysis_verdict(incident)
    delivery = _delivery_verdict(incident)
    entities = incident.get("entities") or {}
    asset_text = _join_items(list(entities.get("suspected_assets") or [])[:2])
    analysis_status = str(analysis.get("status") or "").strip()
    delivery_status = str(delivery.get("status") or "").strip()
    if analysis_status and delivery_status and analysis_status != delivery_status:
        if analysis_status == "monitor_only":
            return "当前更像背景活动，但仍需继续复核"
        if analysis_status == "confirmed_incident":
            return "已具备安全事件特征，但仍需补完关键核验"
        return "已形成可疑事件线索，仍需继续复核"
    if delivery_status == "confirmed_incident":
        return f"{asset_text or '相关资产'} 已形成可确认的安全事件"
    if delivery_status == "monitor_only":
        return "当前更接近背景活动，建议持续观察"
    return "已形成可疑事件线索，建议继续复核"


def _join_or_fallback(values: List[str], fallback: str = "当前未获取") -> str:
    text = _join_items(values)
    return fallback if text == "未识别" else text


def _first_nonempty_text(*values: Any, fallback: str = "") -> str:
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return fallback


def _is_ip_text(value: str) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _is_internal_ip_text(value: str) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False
    if ip.version == 4:
        private_networks = [
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        ]
        return any(ip in network for network in private_networks)
    return bool(ip in ipaddress.ip_network("fc00::/7"))


def _sanitize_external_indicator_values(values: List[Any]) -> List[str]:
    return _dedupe_text(
        value
        for value in list(values or [])
        if str(value or "").strip() and not _is_internal_ip_text(str(value or "").strip())
    )


def _confirmed_asset_list_text(*, delivery_status: str, confirmed_assets: List[str]) -> str:
    if delivery_status != "confirmed_incident":
        return ""
    return _join_or_fallback(confirmed_assets, "")


def _indicator_type_from_value(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return "indicator"
    upper = text.upper()
    if upper.startswith("JA3 "):
        return "JA3"
    if upper.startswith("JA4 "):
        return "JA4"
    if _is_ip_text(text):
        return "internal_ip" if _is_internal_ip_text(text) else "IP"
    if text.startswith(("http://", "https://")):
        return "URL"
    if "." in text and "/" not in text and " " not in text:
        return "domain"
    return "indicator"


def _object_role_label(role: str) -> str:
    return OBJECT_ROLE_LABELS.get(str(role or "").strip(), str(role or "").strip() or "未命名角色")


def _object_type_label(object_type: str) -> str:
    return OBJECT_TYPE_LABELS.get(str(object_type or "").strip(), str(object_type or "").strip() or "对象")


def _gap_status_for_report(status: str) -> str:
    text = str(status or "").strip()
    if text == "closed":
        return "closed"
    if text == "reportable_unresolved":
        return "unresolved_but_deliverable"
    if text in {"stalled", "open_unaddressable"}:
        return "partially_closed"
    return "open"


def _gap_status_label(status: str) -> str:
    return GAP_STATUS_LABELS.get(str(status or "").strip(), str(status or "").strip() or "待补")


def _gap_limited_conclusion(gap: Dict[str, Any]) -> str:
    gap_type = str(gap.get("gap_type") or "").strip()
    question = str(gap.get("question") or "").strip()
    if gap_type == "host_confirmation":
        return "当前尚未观测到稳定的执行阶段证据，因此还不能确认主机侧执行、持久化或横向移动是否已经成立。"
    if gap_type == "scope":
        return "当前不能把所有候选关联对象直接写成已受影响范围。"
    if gap_type == "counterevidence":
        return "当前不能完全排除维护窗口、共享基础设施或正常组件造成的替代解释。"
    if gap_type == "external_context":
        return "当前不适合仅凭背景情报完成基础设施或家族级强归因。"
    if gap_type == "context":
        return "当前还不能把事件写成完整闭环，需要更多上下文来确认它不是孤立命中。"
    if question:
        return f"当前仍缺少对“{question}”的直接补证。"
    return "当前仍存在会限制结论表达边界的关键缺口。"


def _observation_provenance(observation: Dict[str, Any]) -> str:
    relation = str(observation.get("relation") or "").strip().lower()
    source_type = str(observation.get("source_type") or "").strip().lower()
    tool_name = str(observation.get("tool_name") or "").strip().lower()
    if relation == "counterevidence" or tool_name == "check_counterevidence":
        return "counterevidence"
    if source_type.startswith("trace_store"):
        return "local_observation"
    if source_type.startswith("internal_digest"):
        return "analyst_note"
    if source_type.startswith("intel_tool") or source_type.startswith("page_content") or source_type.startswith("candidate_grounding"):
        return "external_intel"
    if relation == "candidate":
        return "unverified_inference"
    return "derived_relation"


def _provenance_label(provenance: str) -> str:
    return PROVENANCE_LABELS.get(str(provenance or "").strip(), str(provenance or "").strip() or "归并关系")


def _observation_source_label(observation: Dict[str, Any]) -> str:
    source_type = str(observation.get("source_type") or "").strip().lower()
    relation = str(observation.get("relation") or "").strip().lower()
    tool_name = str(observation.get("tool_name") or "").strip().lower()
    if relation == "counterevidence" or tool_name == "check_counterevidence":
        return "显式反证检查"
    if source_type.startswith("trace_store.seed_context"):
        return "种子事件窗观测"
    if source_type.startswith("trace_store.related_events"):
        return "关联事件扩查"
    if source_type.startswith("trace_store.asset_context"):
        return "资产背景核查"
    if source_type.startswith("internal_digest"):
        return "内部调查摘要"
    if source_type.startswith("page_content"):
        return "外部网页/报告"
    if source_type.startswith("candidate_grounding"):
        return "候选对象情报验证"
    if source_type.startswith("intel_tool"):
        return "外部结构化情报"
    return _provenance_label(_observation_provenance(observation))


def _section_source_labels(evidence_contract: Dict[str, Any], observation_ids: List[str]) -> List[str]:
    observation_map = {
        str(item.get("id") or "").strip(): item
        for item in list(evidence_contract.get("observations") or [])
        if str(item.get("id") or "").strip()
    }
    labels = []
    for observation_id in list(observation_ids or []):
        observation = observation_map.get(str(observation_id or "").strip())
        if observation:
            labels.append(_observation_source_label(observation))
    return _dedupe_text(labels)


def _section_source_text(evidence_contract: Dict[str, Any], observation_ids: List[str], fallback: str = "当前调查产物") -> str:
    labels = _section_source_labels(evidence_contract, observation_ids)
    return "、".join(labels) if labels else fallback


def _clean_fact_description(value: Any) -> str:
    text = str(value or "").strip()
    if " 原始摘要显示：" in text:
        text = text.split(" 原始摘要显示：", 1)[0].strip()
    return _reader_clean_text(text)


def _report_title(incident: Dict[str, Any]) -> str:
    summary = incident.get("summary") or {}
    hypothesis = incident.get("hypothesis") or {}
    headline = _reader_clean_text(_first_nonempty_text(summary.get("headline"), hypothesis.get("title")))
    generic_markers = ("上下文已形成", "已形成可疑事件线索", "当前更接近背景活动", "建议继续复核")
    if headline and not any(marker in headline for marker in generic_markers):
        return headline if headline.endswith(("事件", "报告")) else f"{headline}事件"
    seed_asset = str((incident.get("entities") or {}).get("seed_asset") or "").strip()
    enrichment = _reader_clean_text(((incident.get("seed") or {}).get("enrichment") or {}).get("info"))
    if seed_asset and enrichment:
        return f"{seed_asset} {enrichment} 调查报告"
    if seed_asset:
        return f"{seed_asset} 异常通信调查报告"
    return "事件调查报告"


def _analysis_window_text(incident: Dict[str, Any]) -> str:
    window = ((incident.get("scope") or {}).get("time_window")) or {}
    start = _format_time(window.get("start"))
    end = _format_time(window.get("end"))
    if start == "unknown" and end == "unknown":
        return "当前未获取"
    return f"{start} 至 {end}"


def _supporting_observation_ids(entries: List[Dict[str, Any]]) -> List[str]:
    return _dedupe_text(
        [str(observation_id or "").strip() for entry in entries for observation_id in list(entry.get("observation_ids") or [])]
    )


def _evidence_objects(evidence_contract: Dict[str, Any]) -> List[Dict[str, Any]]:
    return list(evidence_contract.get("objects") or evidence_contract.get("object_registry") or [])


def _evidence_gaps(evidence_contract: Dict[str, Any]) -> List[Dict[str, Any]]:
    return list(evidence_contract.get("gaps") or evidence_contract.get("evidence_gaps") or [])


def _top_evidence_gaps(evidence_contract: Dict[str, Any], limit: int = 3, *, include_closed: bool = False) -> List[Dict[str, Any]]:
    gaps = _evidence_gaps(evidence_contract)
    if not include_closed:
        gaps = [item for item in gaps if str(item.get("status") or "").strip() != "closed"]
    priority_order = {"high": 0, "medium": 1, "low": 2}
    return sorted(
        gaps,
        key=lambda item: (
            GAP_STATUS_PRIORITY.get(str(item.get("status") or "").strip(), 9),
            priority_order.get(str(item.get("priority") or "").strip(), 9),
            str(item.get("gap_id") or ""),
        ),
    )[:limit]


def _gap_followup_text(gap: Dict[str, Any]) -> str:
    return _reader_clean_text(
        str(gap.get("status_reason") or "").strip()
        or str(gap.get("question") or "").strip()
        or "当前需继续补充相关证据。"
    )


def _registry_values(evidence_contract: Dict[str, Any], roles: List[str]) -> List[str]:
    result: List[str] = []
    role_set = {str(role or "").strip() for role in roles}
    for item in _evidence_objects(evidence_contract):
        item_roles = {str(role or "").strip() for role in list(item.get("roles") or [])}
        current_role = str(item.get("current_role") or "").strip()
        if current_role in role_set or item_roles.intersection(role_set):
            result.append(str(item.get("value") or "").strip())
    return _dedupe_text(result)


def _registry_current_values(evidence_contract: Dict[str, Any], roles: List[str]) -> List[str]:
    role_set = {str(role or "").strip() for role in roles}
    return _dedupe_text(
        str(item.get("value") or "").strip()
        for item in _evidence_objects(evidence_contract)
        if str(item.get("current_role") or "").strip() in role_set
    )


def _registry_indicator_rows(evidence_contract: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [
        item
        for item in _evidence_objects(evidence_contract)
        if str(item.get("object_type") or "").strip() not in {"asset", "family", "user"}
    ]


def _source_rows(incident: Dict[str, Any], evidence_contract: Dict[str, Any]) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add_row(source_type: str, source_name: str, usage: str, boundary: str) -> None:
        key = (source_type, source_name)
        if not source_name or key in seen:
            return
        seen.add(key)
        rows.append(
            {
                "source_type": source_type,
                "source_name": source_name,
                "usage": usage,
                "boundary": boundary,
            }
        )

    seed = incident.get("seed") or {}
    fingerprint = seed.get("trigger_fingerprint") or {}
    fingerprint_type = str(fingerprint.get("type") or "").strip()
    fingerprint_value = str(fingerprint.get("value") or "").strip()
    enrichment = (seed.get("enrichment") or {}).get("info")
    seed_name_parts = []
    if fingerprint_type and fingerprint_value:
        seed_name_parts.append(f"{fingerprint_type} {fingerprint_value}")
    elif fingerprint_type:
        seed_name_parts.append(f"{fingerprint_type} 指纹命中")
    if enrichment:
        seed_name_parts.append(str(enrichment).strip())
    add_row(
        "上游检测",
        " / ".join(seed_name_parts) if seed_name_parts else "seed alert",
        "提供本案的调查起点与初始命中线索。",
        "命中本身并不自动等于事件成立，仍需要后续本地事实补强。",
    )

    for observation in list(evidence_contract.get("observations") or []):
        provenance = str(observation.get("provenance") or "").strip()
        source_ref = str(observation.get("source_ref") or "").strip()
        label = _observation_source_label(observation)
        if provenance == "local_observation":
            add_row(
                "内部观测",
                source_ref or label,
                "支撑时间线、范围和关键事实。",
                "仅覆盖当前调查纳入的本地流量与上下文数据。",
            )
        elif provenance == "analyst_note":
            add_row(
                "内部整理",
                source_ref or label,
                "把零散观测沉淀为可引用的事实、实体与报告素材。",
                "内部整理不会新增外部事实，只负责结构化已有调查结果。",
            )
        elif provenance == "external_intel":
            add_row(
                "外部结构化情报",
                source_ref or label,
                "补充基础设施、家族或公开背景解释。",
                "外部情报不能单独替代本地事实，也不能直接把本案写成强归因。",
            )
        elif provenance == "counterevidence":
            add_row(
                "背景核查",
                source_ref or label,
                "验证维护窗口、补丁、备份或共享基线等替代解释。",
                "反证核查只能说明是否存在降级解释，不能替代主证据链。",
            )
    return rows


def build_incident_evidence_contract(incident: Dict[str, Any]) -> Dict[str, Any]:
    return build_legacy_evidence_contract(incident)


def _main_report_role_label(role: str) -> str:
    return MAIN_REPORT_ROLE_LABELS.get(str(role or "").strip(), str(role or "").strip() or "证据")


def _role_signal_object_refs(item: Dict[str, Any]) -> List[str]:
    indicator_text = str(item.get("indicator_text") or "").strip()
    indicator_parts = [part.strip() for part in indicator_text.split("/") if part.strip()]
    return _dedupe_text([str(item.get("asset_id") or "").strip()] + indicator_parts)


def _summary_has_any(summary: Any, needles: List[str]) -> bool:
    text = str(summary or "").strip().lower()
    if not text:
        return False
    return any(str(needle or "").strip().lower() in text for needle in needles if str(needle or "").strip())


def _signal_indicator_text(item: Dict[str, Any]) -> str:
    return str(item.get("indicator_text") or "").strip() or str(item.get("domain") or "").strip() or str(item.get("dst_ip") or "").strip()


def _report_fact_body_from_signal(item: Dict[str, Any], *, role: str, relation: str) -> str:
    kind = str(item.get("kind") or "").strip().lower()
    stages = {str(stage or "").strip() for stage in list(item.get("stages") or [])}
    tags = {str(tag or "").strip().lower() for tag in list(item.get("tags") or [])}
    summary = str(item.get("summary") or "").strip()
    summary_lower = summary.lower()
    domain = str(item.get("domain") or "").strip()
    dst_ip = str(item.get("dst_ip") or "").strip()
    answers = [str(answer or "").strip() for answer in list(item.get("answers") or []) if str(answer or "").strip()]
    indicator_text = _signal_indicator_text(item)

    if "exploit" in summary_lower and any(token in summary_lower for token in ["request", "requests", "portal", "admin", "post"]):
        return "对外服务入口出现可疑利用请求"

    if relation == "counterevidence":
        if kind == "asset_context":
            return "同时间窗存在已批准的补丁/维护活动，可解释部分日常管理行为"
        if _summary_has_any(summary, ["windows update", "approved microsoft endpoint"]):
            return "与已批准的微软更新端点通信，更接近计划内更新流量"
        if _summary_has_any(summary, ["qa telemetry", "shared infrastructure"]):
            return "另有 QA 遥测任务通过其他供应商域名访问了同一托管 IP，说明该次级 IP 更可能属于共享基础设施"
        if indicator_text:
            return f"与 {indicator_text} 的访问更接近计划内更新、维护或共享基础设施背景"
        return "同时间窗存在更接近计划内活动的背景线索"

    if kind == "asset_context" and (_summary_has_any(summary, ["degraded process telemetry", "telemetry degraded"]) or "telemetry-gap" in tags):
        return "的 EDR 进程遥测出现降级，导致该主机在扩展阶段的执行链暂时无法完整回溯"

    if "lateral-movement" in stages:
        target_text = dst_ip or indicator_text or "关联内部主机"
        if _summary_has_any(summary, ["wmi remote process creation", "wmi"]):
            body = f"出现指向 `{target_text}` 的 WMI 远程进程创建"
        elif _summary_has_any(summary, ["psexec", "remote service creation"]):
            body = f"出现指向 `{target_text}` 的 PsExec 远程服务创建"
        else:
            body = f"出现指向 `{target_text}` 的横向操作告警"
        if role == "progression_evidence":
            body += "，说明异常已经开始跨主机推进"
        return body

    if kind == "process" or ("execution" in stages and kind not in {"alert", "flow", "dns", "http", "asset_context"}):
        body_parts: List[str] = []
        process_match = re.search(r"\b([A-Za-z0-9_.-]+\.exe)\b", summary)
        if process_match:
            body_parts.append(f"在异常通信后出现 `{process_match.group(1)}` 可疑启动")
        else:
            body_parts.append("在异常通信后出现可疑进程执行")
        if "dll" in summary_lower:
            body_parts.append("伴随 DLL 加载")
        if _summary_has_any(summary, ["user-writable path", "user writable path"]):
            body_parts.append("路径位于用户可写目录")
        return "，".join(body_parts)

    if kind == "dns":
        if domain and (_summary_has_any(summary, ["rare domain"]) or "rare" in tags):
            body = f"先解析了少见域名 `{domain}`"
        elif domain:
            body = f"先解析了域名 `{domain}`"
        else:
            body = "先出现了可疑域名解析"
        if answers:
            body += f"，返回 `{answers[0]}`"
        if "command-and-control" in stages or role in {"trigger_evidence", "corroborating_evidence"}:
            body += "，为后续与同一基础设施的通信提供了准备"
        return body

    if kind in {"alert", "flow", "http"} and "command-and-control" in stages:
        if role == "trigger_evidence" or str(item.get("role") or "").strip() == "seed":
            if indicator_text:
                return f"围绕 {indicator_text} 的异常通信触发了种子告警"
            return "异常通信触发了种子告警"
        if kind == "flow" or _summary_has_any(summary, ["reconnect", "reconnected", "contacted", "same beacon", "same c2", "same infrastructure"]):
            if indicator_text:
                return f"再次与 {indicator_text} 通信，说明同一基础设施上的异常仍在持续"
            return "再次出现异常通信，说明相关行为仍在持续"
        if indicator_text:
            return f"与 {indicator_text} 建立了可疑通信"
        return "建立了可疑通信"

    if "execution" in stages:
        return "出现了高风险主机侧动作"

    if indicator_text:
        return f"出现了一条与 {indicator_text} 相关的关键观测"
    return "出现了一条关键观测"


def _report_fact_from_signal(item: Dict[str, Any], *, role: str, relation: str) -> str:
    body = _report_fact_body_from_signal(item, role=role, relation=relation).strip()
    if not body:
        return _reader_clean_text(_clean_fact_description(_fact_description(item)))
    ts = _format_time(item.get("ts"))
    asset_id = str(item.get("asset_id") or "").strip() or "相关资产"
    prefix = f"在 {ts}，资产 `{asset_id}`" if ts != "unknown" else f"资产 `{asset_id}`"
    return _reader_clean_text(f"{prefix} {body}。")


def _role_why_selected(item: Dict[str, Any], *, role: str, relation: str) -> str:
    stages = {str(stage or "").strip() for stage in list(item.get("stages") or [])}
    tags = {str(tag or "").strip().lower() for tag in list(item.get("tags") or [])}
    summary = str(item.get("summary") or "").strip()
    if relation == "counterevidence":
        return _support_reason(item, relation)
    if role == "trigger_evidence":
        return "这是种子命中的直接落点，说明调查起点并不是孤立的指纹命中。"
    if role == "corroborating_evidence":
        return "同一基础设施在种子资产或关联资产上再次出现，使单点告警扩展成可复核的连续事件链。"
    if role == "progression_evidence":
        if "lateral-movement" in stages:
            return "它表明异常已经从外联推进到跨主机动作，比单纯重复通信更能支撑事件升级。"
        if stages.intersection({"execution", "exfiltration", "persistence", "credential-access"}):
            return "它把异常从通信层推进到主机执行或其他更高风险阶段，对事件定性的权重明显更高。"
    if role == "scope_evidence":
        if (_summary_has_any(summary, ["degraded process telemetry", "telemetry degraded"]) or "telemetry-gap" in tags):
            return "这说明异常链已经触及新的资产，但该主机在关键时刻缺少完整主机可见性，因此范围可以确认扩展，细节仍需保守表述。"
        if "lateral-movement" in stages:
            return "这说明异常已经从种子资产延伸到其他主机，事件范围不再局限于单点。"
        return "它把事件范围从种子资产推进到其他资产，使当前结论不再只停留在单点异常。"
    return _support_reason(item, relation)


def _role_entry_from_signal(item: Dict[str, Any], *, role: str, index: int, relation: str = "supporting") -> Dict[str, Any]:
    observation_ids = _dedupe_text([str(observation_id or "").strip() for observation_id in list(item.get("observation_ids") or []) if str(observation_id or "").strip()])
    return {
        "role": role,
        "role_label": _main_report_role_label(role),
        "entry_id": f"ROLE-{index:02d}",
        "event_id": str(item.get("event_id") or "").strip(),
        "observation_ids": observation_ids,
        "object_refs": _role_signal_object_refs(item),
        "grounding_status": "grounded" if observation_ids else "partially_grounded",
        "evidence_strength": _evidence_strength(item, relation),
        "category": _evidence_category(item),
        "why_selected": _reader_clean_text(_role_why_selected(item, role=role, relation=relation)),
        "reader_fact": _report_fact_from_signal(item, role=role, relation=relation),
        "reader_limit": _reader_clean_text(_limitation_text(item, relation)),
        "citation_refs": observation_ids,
        "ts": str(item.get("ts") or "").strip(),
        "asset_id": str(item.get("asset_id") or "").strip(),
        "kind": str(item.get("kind") or "").strip(),
        "summary": str(item.get("summary") or "").strip(),
        "stages": list(item.get("stages") or []),
        "tags": list(item.get("tags") or []),
        "indicator_text": str(item.get("indicator_text") or "").strip(),
        "dst_ip": str(item.get("dst_ip") or "").strip(),
        "domain": str(item.get("domain") or "").strip(),
        "answers": list(item.get("answers") or []),
    }


def _role_entry_from_gap(gap: Dict[str, Any], *, index: int) -> Dict[str, Any]:
    status = str(gap.get("status") or "").strip()
    strength = "高" if bool(gap.get("delivery_blocking")) or str(gap.get("priority") or "").strip() == "high" else "中"
    question = str(gap.get("question") or "").strip() or "当前存在待补关键缺口。"
    followup_text = _gap_followup_text(gap)
    return {
        "role": "boundary_gap_evidence",
        "role_label": _main_report_role_label("boundary_gap_evidence"),
        "entry_id": f"GAP-{index:02d}",
        "gap_id": str(gap.get("gap_id") or "").strip(),
        "observation_ids": [],
        "object_refs": [],
        "grounding_status": "candidate_only" if status == "open" else "partially_grounded",
        "evidence_strength": strength,
        "category": "交付缺口",
        "why_selected": _reader_clean_text(_gap_limited_conclusion(gap)),
        "reader_fact": _reader_clean_text(question),
        "reader_limit": followup_text or _reader_clean_text(question),
        "citation_refs": [str(gap.get("gap_id") or "").strip()] if str(gap.get("gap_id") or "").strip() else [],
        "status": status,
        "next_best_query": followup_text,
    }


def _role_signal_from_event(event: Dict[str, Any], observation_map: Dict[str, List[str]]) -> Dict[str, Any]:
    signal = _signal_view_from_event(event)
    event_id = str(event.get("id") or "").strip()
    signal["event_id"] = event_id
    signal["observation_ids"] = list(observation_map.get(event_id, []))
    signal["detail"] = str(event.get("summary") or "").strip()
    return signal


def _pick_role_signals(
    candidates: List[Dict[str, Any]],
    *,
    seed_asset: str,
    preferred_roles: List[str] | None = None,
    preferred_stages: List[str] | None = None,
    require_other_asset: bool = False,
    limit: int = 1,
    exclude_event_ids: set[str] | None = None,
) -> List[Dict[str, Any]]:
    exclude = set(exclude_event_ids or set())
    preferred_role_set = {str(item or "").strip() for item in list(preferred_roles or []) if str(item or "").strip()}
    preferred_stage_set = {str(item or "").strip() for item in list(preferred_stages or []) if str(item or "").strip()}

    def score(item: Dict[str, Any]) -> tuple[int, int, int, str]:
        event_id = str(item.get("event_id") or "").strip()
        stages = {str(stage or "").strip() for stage in list(item.get("stages") or [])}
        item_role = str(item.get("role") or "").strip()
        asset_id = str(item.get("asset_id") or "").strip()
        kind = str(item.get("kind") or "").strip().lower()
        item_score = 0
        if event_id and event_id in exclude:
            item_score -= 1000
        if preferred_role_set and item_role in preferred_role_set:
            item_score += 60
        if preferred_stage_set:
            item_score += 35 * len(preferred_stage_set.intersection(stages))
        if item_role == "seed":
            item_score += 20
        if asset_id and asset_id != seed_asset:
            item_score += 12
        if require_other_asset and asset_id and asset_id != seed_asset:
            item_score += 50
        elif require_other_asset:
            item_score -= 40
        if list(item.get("observation_ids") or []):
            item_score += 8
        if kind == "process":
            item_score += 14
        elif kind == "alert":
            item_score += 6
        elif kind == "asset_context":
            item_score -= 8
        if str(item.get("kind") or "").strip().lower() == "dns":
            item_score += 4
        return (
            item_score,
            1 if asset_id and asset_id != seed_asset else 0,
            len(stages),
            str(item.get("ts") or ""),
        )

    selected: List[Dict[str, Any]] = []
    used_ids: set[str] = set()
    for item in sorted(candidates, key=score, reverse=True):
        event_id = str(item.get("event_id") or "").strip()
        if event_id and (event_id in exclude or event_id in used_ids):
            continue
        if require_other_asset and str(item.get("asset_id") or "").strip() == seed_asset:
            continue
        selected.append(item)
        if event_id:
            used_ids.add(event_id)
        if len(selected) >= max(0, int(limit)):
            break
    return selected


def _build_main_report_evidence_roles(
    *,
    cluster_events: List[Dict[str, Any]],
    event_observation_map: Dict[str, List[str]],
    seed_asset: str,
    evidence_contract: Dict[str, Any],
) -> Dict[str, List[Dict[str, Any]]]:
    observation_map = dict(event_observation_map or {})
    cluster_events = list(cluster_events or [])
    positives = [
        _role_signal_from_event(item, observation_map)
        for item in cluster_events
        if str(item.get("role") or "").strip() in {"seed", "supporting"}
        and str(item.get("classification") or "").strip().lower() != "benign"
    ]
    counters = [
        _role_signal_from_event(item, observation_map)
        for item in cluster_events
        if str(item.get("role") or "").strip() == "counterevidence"
    ]
    contextual = [
        _role_signal_from_event(item, observation_map)
        for item in cluster_events
        if str(item.get("role") or "").strip() == "context"
        and str(item.get("classification") or "").strip().lower() != "benign"
    ]
    seed_asset = str(seed_asset or "").strip()
    top_gaps = _top_evidence_gaps(evidence_contract, limit=3)

    def stage_set(item: Dict[str, Any]) -> set[str]:
        return {str(stage or "").strip() for stage in list(item.get("stages") or [])}

    def is_high_risk_progression(item: Dict[str, Any]) -> bool:
        return bool(stage_set(item).intersection({"execution", "lateral-movement", "exfiltration", "persistence", "credential-access"}))

    def is_continuity_signal(item: Dict[str, Any]) -> bool:
        kind = str(item.get("kind") or "").strip().lower()
        stages = stage_set(item)
        return (kind in {"dns", "flow", "alert", "http"} or "command-and-control" in stages) and not is_high_risk_progression(item)

    used_event_ids: set[str] = set()
    role_entries: Dict[str, List[Dict[str, Any]]] = {
        "trigger_evidence": [],
        "corroborating_evidence": [],
        "progression_evidence": [],
        "scope_evidence": [],
        "counterevidence": [],
        "boundary_gap_evidence": [],
    }

    trigger_candidates = _pick_role_signals(positives, seed_asset=seed_asset, preferred_roles=["seed"], limit=1)
    if not trigger_candidates and positives:
        trigger_candidates = _pick_role_signals(positives, seed_asset=seed_asset, limit=1)
    for item in trigger_candidates:
        event_id = str(item.get("event_id") or "").strip()
        if event_id:
            used_event_ids.add(event_id)
        role_entries["trigger_evidence"].append(
            _role_entry_from_signal(item, role="trigger_evidence", index=len(role_entries["trigger_evidence"]) + 1)
        )

    corroborating_pool = [item for item in positives if is_continuity_signal(item)]
    corroborating_candidates = _pick_role_signals(
        corroborating_pool,
        seed_asset=seed_asset,
        preferred_stages=["command-and-control"],
        preferred_roles=["supporting", "seed"],
        limit=2,
        exclude_event_ids=used_event_ids,
    )
    if not corroborating_candidates:
        corroborating_candidates = _pick_role_signals(
            corroborating_pool or positives,
            seed_asset=seed_asset,
            preferred_roles=["supporting"],
            limit=2,
            exclude_event_ids=used_event_ids,
        )
    for item in corroborating_candidates:
        event_id = str(item.get("event_id") or "").strip()
        if event_id:
            used_event_ids.add(event_id)
        role_entries["corroborating_evidence"].append(
            _role_entry_from_signal(item, role="corroborating_evidence", index=len(role_entries["corroborating_evidence"]) + 1)
        )

    progression_pool = [item for item in positives if is_high_risk_progression(item)]
    progression_candidates = _pick_role_signals(
        progression_pool or positives,
        seed_asset=seed_asset,
        preferred_stages=["execution", "lateral-movement", "exfiltration", "persistence", "credential-access"],
        limit=2,
        exclude_event_ids=used_event_ids,
    )
    for item in progression_candidates:
        event_id = str(item.get("event_id") or "").strip()
        if event_id:
            used_event_ids.add(event_id)
        role_entries["progression_evidence"].append(
            _role_entry_from_signal(item, role="progression_evidence", index=len(role_entries["progression_evidence"]) + 1)
        )

    scope_pool = [
        item
        for item in positives + contextual
        if str(item.get("asset_id") or "").strip() and str(item.get("asset_id") or "").strip() != seed_asset
    ]
    scope_candidates = _pick_role_signals(
        scope_pool,
        seed_asset=seed_asset,
        require_other_asset=True,
        preferred_stages=["lateral-movement", "command-and-control", "execution"],
        limit=2,
        exclude_event_ids=used_event_ids,
    )
    if not scope_candidates:
        scope_candidates = _pick_role_signals(
            scope_pool,
            seed_asset=seed_asset,
            require_other_asset=True,
            limit=2,
            exclude_event_ids=used_event_ids,
        )
    if not scope_candidates:
        scope_candidates = _pick_role_signals(
            scope_pool,
            seed_asset=seed_asset,
            require_other_asset=True,
            preferred_stages=["lateral-movement", "command-and-control", "execution"],
            limit=2,
        )
    for item in scope_candidates:
        event_id = str(item.get("event_id") or "").strip()
        if event_id:
            used_event_ids.add(event_id)
        role_entries["scope_evidence"].append(
            _role_entry_from_signal(item, role="scope_evidence", index=len(role_entries["scope_evidence"]) + 1)
        )

    for index, item in enumerate(counters[:2], start=1):
        role_entries["counterevidence"].append(
            _role_entry_from_signal(item, role="counterevidence", index=index, relation="counterevidence")
        )

    for index, gap in enumerate(top_gaps, start=1):
        role_entries["boundary_gap_evidence"].append(_role_entry_from_gap(gap, index=index))

    return role_entries


def _main_supporting_entries_from_roles(evidence_roles: Dict[str, List[Dict[str, Any]]], evidence_contract: Dict[str, Any]) -> List[Dict[str, Any]]:
    supporting_roles = ("trigger_evidence", "corroborating_evidence", "progression_evidence", "scope_evidence")
    entries: List[Dict[str, Any]] = []
    index = 1
    for role_name in supporting_roles:
        for item in list(evidence_roles.get(role_name) or []):
            entries.append(
                {
                    "id": f"E-{index:02d}",
                    "category": f"{item.get('role_label')}（{item.get('category')}）",
                    "strength": item.get("evidence_strength"),
                    "fact_text": item.get("reader_fact"),
                    "reason_text": item.get("why_selected"),
                    "limitation_text": item.get("reader_limit"),
                    "source_text": _section_source_text(evidence_contract, list(item.get("observation_ids") or []), fallback="内部观测"),
                    "observation_ids": list(item.get("observation_ids") or []),
                }
            )
            index += 1
    return entries


def _main_counter_entries_from_roles(evidence_roles: Dict[str, List[Dict[str, Any]]], evidence_contract: Dict[str, Any]) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    for index, item in enumerate(list(evidence_roles.get("counterevidence") or []), start=1):
        entries.append(
            {
                "id": f"C-{index:02d}",
                "category": f"{item.get('role_label')}（{item.get('category')}）",
                "strength": item.get("evidence_strength"),
                "fact_text": item.get("reader_fact"),
                "reason_text": item.get("why_selected"),
                "limitation_text": item.get("reader_limit"),
                "source_text": _section_source_text(evidence_contract, list(item.get("observation_ids") or []), fallback="背景核查"),
                "observation_ids": list(item.get("observation_ids") or []),
            }
        )
    return entries


def _main_role_source_text(evidence_contract: Dict[str, Any], entries: List[Dict[str, Any]], fallback: str) -> str:
    observation_ids = _dedupe_text(
        [str(observation_id or "").strip() for entry in entries for observation_id in list(entry.get("observation_ids") or []) if str(observation_id or "").strip()]
    )
    return _section_source_text(evidence_contract, observation_ids, fallback=fallback)


def _main_strongest_supporting_entry(evidence_roles: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
    for role_name in ("progression_evidence", "scope_evidence", "corroborating_evidence", "trigger_evidence"):
        entries = list(evidence_roles.get(role_name) or [])
        if entries:
            return entries[0]
    return {}


def _sorted_role_entries(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(
        list(entries or []),
        key=lambda item: (
            str(item.get("ts") or ""),
            str(item.get("event_id") or ""),
        ),
    )


def _main_entry_body(entry: Dict[str, Any]) -> str:
    role = str(entry.get("role") or "").strip() or "corroborating_evidence"
    relation = "counterevidence" if role == "counterevidence" else "supporting"
    return _reader_clean_text(_report_fact_body_from_signal(entry, role=role, relation=relation))


def _main_reason_followup(reason: str) -> str:
    text = _reader_clean_text(reason).rstrip("。")
    if not text:
        return ""
    if text.startswith("它表明"):
        return text[1:]
    if text.startswith("它说明"):
        return text[1:]
    if text.startswith("它把异常"):
        return f"说明异常{text[len('它把异常'):]}"
    if text.startswith("它把"):
        return f"说明{text[1:]}"
    return text


def _main_strongest_evidence_text(strongest_entry: Dict[str, Any]) -> str:
    fact = _reader_clean_text(str(strongest_entry.get("reader_fact") or "").strip()).rstrip("。")
    if not fact:
        return "当前主判断主要建立在已纳入事件窗内的连续异常链上。"
    role = str(strongest_entry.get("role") or "").strip()
    followup = _main_reason_followup(str(strongest_entry.get("why_selected") or "").strip())
    if role in {"progression_evidence", "scope_evidence"} and followup and followup not in fact:
        return f"{fact}，{followup}。"
    return f"{fact}。"


def _main_conclusion_basis_clauses(
    evidence_roles: Dict[str, List[Dict[str, Any]]],
    counter_entries: List[Dict[str, Any]],
) -> List[str]:
    clauses: List[str] = []
    if list(evidence_roles.get("trigger_evidence") or []):
        clauses.append("种子告警已经和明确异常起点对齐")
    if list(evidence_roles.get("corroborating_evidence") or []):
        clauses.append("同一基础设施的连续通信已在同资产或关联资产上被复现")
    progression_entries = list(evidence_roles.get("progression_evidence") or [])
    if progression_entries:
        if any("lateral-movement" in set(item.get("stages") or []) for item in progression_entries):
            clauses.append("事件链已经推进到执行或横向动作")
        else:
            clauses.append("事件链已经推进到更高风险的主机动作")
    if list(evidence_roles.get("scope_evidence") or []):
        clauses.append("异常范围已经不再局限于种子资产")
    if counter_entries:
        clauses.append("已核查的维护或更新背景不足以解释整条主链")
    return _dedupe_text(clauses)


def _main_hypothesis_requirements_text(
    evidence_roles: Dict[str, List[Dict[str, Any]]],
    counter_entries: List[Dict[str, Any]],
    boundary_entries: List[Dict[str, Any]],
) -> str:
    requirements: List[str] = []
    if list(evidence_roles.get("trigger_evidence") or []):
        requirements.append("种子告警需要能够对应到明确异常起点")
    if list(evidence_roles.get("corroborating_evidence") or []):
        requirements.append("同一基础设施的异常通信需要在同资产或关联资产上被再次观察到")
    if list(evidence_roles.get("progression_evidence") or []):
        requirements.append("事件链需要推进到执行或横向动作，而不只是停留在单点外联")
    if counter_entries:
        requirements.append("已核查的维护或更新背景不足以解释整条主链")
    if boundary_entries:
        requirements.append("未独立验证的候选对象只能作为边界线索保留，不能直接写成确认影响范围")
    if not requirements:
        return "主假设至少需要形成可复核的起点、连续性和边界判断。"
    return f"当前主假设至少需要同时满足：{'；'.join(_dedupe_text(requirements))}。"


def _main_chain_text(evidence_roles: Dict[str, List[Dict[str, Any]]], seed_asset: str) -> str:
    trigger = (_sorted_role_entries(list(evidence_roles.get("trigger_evidence") or [])) or [{}])[0]
    corroborating = _sorted_role_entries(list(evidence_roles.get("corroborating_evidence") or []))
    progression = _sorted_role_entries(list(evidence_roles.get("progression_evidence") or []))
    scope_entries = _sorted_role_entries(list(evidence_roles.get("scope_evidence") or []))
    trigger_ts = str(trigger.get("ts") or "")

    pre_trigger = next(
        (
            item
            for item in corroborating
            if str(item.get("asset_id") or "").strip() == seed_asset and str(item.get("ts") or "").strip() and str(item.get("ts") or "").strip() <= trigger_ts
        ),
        {},
    )
    host_exec = next((item for item in progression if "execution" in set(item.get("stages") or [])), progression[0] if progression else {})
    spread_signal = next((item for item in progression if "lateral-movement" in set(item.get("stages") or [])), {})
    other_asset_signal = next(
        (
            item
            for item in scope_entries + corroborating
            if str(item.get("asset_id") or "").strip() and str(item.get("asset_id") or "").strip() != seed_asset
        ),
        {},
    )

    sentences: List[str] = []
    if trigger:
        trigger_asset = str(trigger.get("asset_id") or "").strip() or seed_asset or "相关资产"
        trigger_body = _main_entry_body(trigger)
        if pre_trigger and str(pre_trigger.get("event_id") or "").strip() != str(trigger.get("event_id") or "").strip():
            pre_body = _main_entry_body(pre_trigger)
            sentences.append(f"事件链先表现为资产 `{seed_asset}` {pre_body}，随后资产 `{trigger_asset}` {trigger_body}。")
        else:
            sentences.append(f"事件链以资产 `{trigger_asset}` {trigger_body} 为起点。")
    if host_exec:
        host_asset = str(host_exec.get("asset_id") or "").strip() or seed_asset or "相关资产"
        sentences.append(f"随后，资产 `{host_asset}` {_main_entry_body(host_exec)}。")
    if spread_signal and str(spread_signal.get("event_id") or "").strip() != str(host_exec.get("event_id") or "").strip():
        spread_asset = str(spread_signal.get("asset_id") or "").strip() or seed_asset or "相关资产"
        spread_body = _main_entry_body(spread_signal)
        tail = "" if "说明" in spread_body else "，说明异常已经开始跨资产推进"
        sentences.append(f"之后，资产 `{spread_asset}` {spread_body}{tail}。")
    if other_asset_signal and str(other_asset_signal.get("event_id") or "").strip() not in {
        str(host_exec.get("event_id") or "").strip(),
        str(spread_signal.get("event_id") or "").strip(),
    }:
        other_asset = str(other_asset_signal.get("asset_id") or "").strip() or "关联资产"
        other_body = _main_entry_body(other_asset_signal)
        tail = "" if "说明" in other_body else "，说明相同基础设施上的异常已经扩展到其他资产"
        sentences.append(f"其后，资产 `{other_asset}` {other_body}{tail}。")
    if not sentences:
        return "当前已经形成可复核的事件主链，但关键机制仍需结合证据块理解。"
    return _reader_clean_text(" ".join(sentences))


def _main_amplifier_text(evidence_roles: Dict[str, List[Dict[str, Any]]], seed_asset: str) -> str:
    scope_entries = list(evidence_roles.get("scope_evidence") or [])
    progression_entries = list(evidence_roles.get("progression_evidence") or [])
    other_assets = _dedupe_text(
        [
            str(item.get("asset_id") or "").strip()
            for item in scope_entries + list(evidence_roles.get("corroborating_evidence") or [])
            if str(item.get("asset_id") or "").strip() and str(item.get("asset_id") or "").strip() != seed_asset
        ]
    )
    if any("lateral-movement" in set(item.get("stages") or []) for item in progression_entries) and other_assets:
        return f"横向动作之后，{_join_or_fallback(other_assets[:3], '其他资产')} 也出现了后续异常，说明事件已经具备跨资产扩展特征。"
    if any("lateral-movement" in set(item.get("stages") or []) for item in progression_entries):
        return "事件链已经从外联推进到跨主机动作，这会显著放大影响范围和处置紧迫性。"
    if other_assets:
        return f"同一基础设施上的异常已经出现在 {_join_or_fallback(other_assets[:3], '其他资产')} 等资产上，说明当前结论不再局限于单点告警。"
    return "当前主链已经超过单点告警，影响判断不再只依赖种子资产本身。"


def _main_one_sentence_summary(
    *,
    delivery_status: str,
    confirmed_assets: List[str],
    seed_asset: str,
    core_indicators: List[str],
    strongest_entry: Dict[str, Any],
    key_gap: str,
) -> str:
    asset_text = _join_or_fallback(confirmed_assets, seed_asset or "相关资产")
    indicator_text = _join_or_fallback(core_indicators[:2], "当前关键通信对象")
    strongest_reason = _reader_clean_text(str(strongest_entry.get("why_selected") or "").strip())
    key_gap_clause = _reader_gap_clause_text(key_gap)
    if delivery_status == "confirmed_incident":
        return f"{asset_text} 围绕 {indicator_text} 已形成可以稳定交付的异常链，当前应按安全事件处置。"
    if delivery_status == "monitor_only":
        return f"当前围绕 {asset_text} 的异常更接近背景活动或计划内行为，建议持续观察并保留后续复核。"
    if key_gap_clause:
        return f"{asset_text} 围绕 {indicator_text} 已出现连续高风险迹象，但由于{key_gap_clause}，当前仍按待人工复核事件交付。"
    if strongest_reason:
        return f"{asset_text} 围绕 {indicator_text} 已形成连续异常链，但关键核验仍未完全闭合，因此当前仍按待人工复核事件交付。"
    return f"{asset_text} 已形成需要继续收敛的异常事件链，当前仍按待人工复核事件交付。"


def _confirmed_scope_text(*, delivery_status: str, confirmed_assets: List[str], seed_asset: str) -> str:
    if delivery_status == "confirmed_incident":
        return _join_or_fallback(confirmed_assets, seed_asset or "相关资产")
    if delivery_status == "monitor_only":
        return "当前无已确认受影响资产"
    return "当前尚无已确认受影响资产"


def _scope_focus_text(*, delivery_status: str, confirmed_assets: List[str], seed_asset: str) -> str:
    if delivery_status == "confirmed_incident":
        return _join_or_fallback(confirmed_assets, seed_asset or "相关资产")
    return seed_asset or "相关资产"


def _coverage_boundary_text(
    *,
    delivery_status: str,
    confirmed_assets: List[str],
    related_assets: List[str],
    expansion_candidates: List[str],
    seed_asset: str,
) -> str:
    if delivery_status == "confirmed_incident":
        return f"当前已确认范围收敛在 {_join_or_fallback(confirmed_assets, seed_asset)}；未独立验证的候选对象暂只作为边界线索保留。"
    candidate_text = _join_or_fallback(_dedupe_text(related_assets + expansion_candidates), "当前无")
    if delivery_status == "monitor_only":
        return f"当前没有可写入已确认影响范围的资产；`{seed_asset}` 仅作为调查起点保留，其余候选对象 {candidate_text} 继续按背景或待确认状态处理。"
    return f"当前调查重点仍围绕 `{seed_asset}` 收敛，但还没有资产可以写成已确认受影响范围；候选对象 {candidate_text} 继续作为边界线索保留。"


def _main_current_conclusion_text(
    *,
    delivery_status: str,
    strongest_entry: Dict[str, Any],
    delivery_summary: str,
    key_gap: str,
    basis_clauses: List[str] | None = None,
) -> str:
    basis_text = "；".join(_dedupe_text(list(basis_clauses or [])))
    strongest_reason = _reader_clean_text(str(strongest_entry.get("why_selected") or "").strip())
    key_gap_clause = _reader_gap_clause_text(key_gap)
    if delivery_status == "confirmed_incident":
        if basis_text:
            return _reader_clean_text(f"当前同时满足：{basis_text}，因此本案可以按确认安全事件交付。")
        return _reader_clean_text(f"{strongest_reason} {delivery_summary}".strip())
    if delivery_status == "monitor_only":
        if basis_text:
            return _reader_clean_text(f"当前判断主要基于：{basis_text}；但现有证据仍更接近背景活动或低确定性异常。")
        return _reader_clean_text(f"{delivery_summary} {strongest_reason}".strip()) if strongest_reason else delivery_summary
    if key_gap_clause:
        if basis_text:
            return _reader_clean_text(f"当前已经形成：{basis_text}；但由于{key_gap_clause}，本案仍需要按待人工复核结论交付。")
        return _reader_clean_text(f"{strongest_reason} 但由于{key_gap_clause}，当前仍需要按待人工复核结论交付。".strip())
    return _reader_clean_text(f"{strongest_reason} {delivery_summary}".strip()) if strongest_reason else delivery_summary


def _main_not_other_status_text(
    *,
    delivery_status: str,
    counter_entries: List[Dict[str, Any]],
    boundary_entries: List[Dict[str, Any]],
) -> str:
    if delivery_status == "confirmed_incident":
        if boundary_entries:
            return _reader_clean_text(f"虽然仍有边界待确认对象，但这些缺口只限制扩展范围，不会推翻当前已确认主链。")
        return "当前未见足以把本案降级为背景活动的强反证，因此可以按确认事件交付。"
    if delivery_status == "monitor_only":
        if counter_entries:
            return _reader_clean_text(f"{counter_entries[0].get('reason_text') or '当前更强的背景解释占优'}，因此不适合把本案直接上升为确认事件。")
        return "当前没有形成足以支撑事件成立的连续高风险证据链，因此不适合把本案直接上升为确认事件。"
    if boundary_entries:
        boundary_clause = _reader_gap_clause_text(boundary_entries[0].get("reader_fact")) or "关键交付缺口仍未闭合"
        return _reader_clean_text(f"当前主链已经超过单点命中，但{boundary_clause}，因此暂不直接升级为确认事件。")
    if counter_entries:
        return _reader_clean_text(f"当前也存在需要谨慎对待的替代解释，例如：{counter_entries[0].get('reason_text') or counter_entries[0].get('fact_text')}")
    return "当前虽然已经形成可疑事件链，但交付级核验仍未完全闭合，因此暂不直接升级为确认事件。"


def _build_main_report_contract(
    report_inputs: Dict[str, Any],
    evidence_store: Dict[str, Any],
    delivery_decision: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    delivery_decision = delivery_decision or {}
    report_inputs = report_inputs or {}
    verdict = dict(report_inputs.get("delivery_verdict") or delivery_decision.get("delivery_verdict") or {})
    family_context = dict(report_inputs.get("family_context") or {})
    timeline_entries = list(report_inputs.get("timeline_entries") or [])
    bucketed_actions = dict(report_inputs.get("bucketed_actions") or {})
    seed_asset = str(report_inputs.get("seed_asset") or "").strip() or "相关资产"
    evidence_roles = _build_main_report_evidence_roles(
        cluster_events=list(report_inputs.get("cluster_events") or []),
        event_observation_map=dict(report_inputs.get("event_observation_map") or {}),
        seed_asset=seed_asset,
        evidence_contract=evidence_store,
    )
    supporting_entries = _main_supporting_entries_from_roles(evidence_roles, evidence_store)
    counter_entries = _main_counter_entries_from_roles(evidence_roles, evidence_store)
    strongest_entry = _main_strongest_supporting_entry(evidence_roles)
    boundary_entries = list(evidence_roles.get("boundary_gap_evidence") or [])
    top_gaps = _top_evidence_gaps(evidence_store, limit=3)

    confirmed_assets = list(delivery_decision.get("confirmed_scope") or _registry_values(evidence_store, ["seed_asset", "affected_asset"]))
    related_assets = list(delivery_decision.get("candidate_scope") or _registry_values(evidence_store, ["related_asset"]))
    core_indicators = _sanitize_external_indicator_values(_registry_values(evidence_store, ["core_external_indicator"]))
    context_indicators = _registry_values(evidence_store, ["contextual_indicator", "related_internal_address"])
    seed_fingerprints = _registry_values(evidence_store, ["seed_fingerprint"])
    expansion_candidates = _registry_current_values(evidence_store, ["expansion_candidate"])
    expansion_candidates = [
        item
        for item in expansion_candidates
        if item not in set(_dedupe_text(confirmed_assets + core_indicators + seed_fingerprints))
    ]

    analysis_window = str(report_inputs.get("analysis_window") or "").strip() or "当前未获取"
    delivery_status = (
        str(report_inputs.get("delivery_status") or "").strip()
        or str(delivery_decision.get("delivery_status") or "").strip()
        or str(verdict.get("status") or "").strip()
    )
    delivery_label = (
        str(report_inputs.get("delivery_status_label") or "").strip()
        or str(delivery_decision.get("delivery_status_label") or "").strip()
        or _reader_status_label_for_status(delivery_status)
    )
    confirmed_scope_text = _confirmed_scope_text(
        delivery_status=delivery_status,
        confirmed_assets=confirmed_assets,
        seed_asset=seed_asset,
    )
    confirmed_asset_text = _confirmed_asset_list_text(
        delivery_status=delivery_status,
        confirmed_assets=confirmed_assets,
    )
    scope_focus_text = _scope_focus_text(
        delivery_status=delivery_status,
        confirmed_assets=confirmed_assets,
        seed_asset=seed_asset,
    )
    coverage_boundary_text = _coverage_boundary_text(
        delivery_status=delivery_status,
        confirmed_assets=confirmed_assets,
        related_assets=related_assets,
        expansion_candidates=expansion_candidates,
        seed_asset=seed_asset,
    )
    delivery_summary = (
        str(delivery_decision.get("reviewer_rationale") or "").strip()
        or str(((delivery_decision.get("readiness") or {}).get("summary")) or "").strip()
        or "当前交付判断主要依据现有证据链和剩余缺口。"
    )
    strongest_evidence = _main_strongest_evidence_text(strongest_entry)
    key_gap = _reader_clean_text(
        str((boundary_entries[0] or {}).get("reader_fact") or "").strip()
        if boundary_entries
        else (top_gaps[0].get("question") if top_gaps else "")
    ) or "当前没有阻塞交付的关键缺口。"
    primary_action = str(report_inputs.get("primary_action") or "").strip() or (
        _gap_followup_text(top_gaps[0]) if top_gaps else key_gap
    )
    initial_hits = list(report_inputs.get("initial_hits") or [])
    seed_alert_text = str(report_inputs.get("seed_alert_text") or "").strip()
    stage_text = _format_stage_list(list(report_inputs.get("stage_values") or []))
    one_sentence_summary = str(report_inputs.get("one_sentence_summary") or "").strip() or _main_one_sentence_summary(
        delivery_status=delivery_status,
        confirmed_assets=confirmed_assets,
        seed_asset=seed_asset,
        core_indicators=core_indicators,
        strongest_entry=strongest_entry,
        key_gap=key_gap,
    )

    pattern_lines: List[str] = []
    if "initial-access" in set(report_inputs.get("stage_values") or []):
        pattern_lines.append("时间线上已经出现疑似初始入侵入口相关活动，说明当前异常并不是从单条外联噪声突然开始。")
    elif delivery_status != "monitor_only":
        pattern_lines.append("当前尚未识别明确的初始入侵入口，现有证据主要从异常外联及后续行为开始收敛。")
    if any("网络" in str(entry.get("category") or "").strip() and "解析" in str(entry.get("fact_text") or "") for entry in supporting_entries):
        pattern_lines.append("告警前后已经出现了解析或访问准备动作，说明异常不是完全孤立的单点命中。")
    if list(evidence_roles.get("corroborating_evidence") or []):
        pattern_lines.append("告警后存在复现或持续性通信，说明相关行为具有连续性。")
    if list(evidence_roles.get("progression_evidence") or []):
        pattern_lines.append("事件链已经从单纯通信异常推进到更高风险的后续动作，风险等级明显上升。")
    if counter_entries:
        pattern_lines.append("同时间窗也完成了替代解释检查，但现有反证不足以完全推翻主链。")
    if not pattern_lines:
        pattern_lines.append("当前时间线足以说明调查起点与关键节点，但行为模式仍偏薄。")

    if delivery_status == "confirmed_incident":
        confirmed_impact = f"当前已确认 { _join_or_fallback(confirmed_assets, seed_asset) } 围绕 { _join_or_fallback(core_indicators[:4], '当前关键对象') } 形成了连续异常链。"
    elif delivery_status == "monitor_only":
        confirmed_impact = "当前已确认的主要是弱异常或背景活动线索，尚不足以按已成立安全事件处置。"
    else:
        confirmed_impact = f"当前已确认的事实主要收敛在 { _join_or_fallback(confirmed_assets, seed_asset) } 与 { _join_or_fallback(core_indicators[:4], '当前关键对象') } 之间的异常通信及后续高风险迹象。"

    if related_assets or expansion_candidates:
        suspected_impact = f"仍需继续核实的对象包括 { _join_or_fallback(_dedupe_text(related_assets + expansion_candidates[:3]), '当前没有额外待确认对象') }。"
    else:
        suspected_impact = "当前没有额外进入主报告的待确认受影响对象。"

    unresolved_impact = _dedupe_text(
        [str(item.get("why_selected") or "").strip() for item in boundary_entries if str(item.get("why_selected") or "").strip()]
    ) or ["当前没有额外必须单列的影响边界限制。"]

    if delivery_status == "confirmed_incident":
        judgment_ceiling = "当前证据已经足以稳定交付为 `确认安全事件`，但仍不宜把未独立验证的候选对象直接写成已受影响范围。"
    elif delivery_status == "monitor_only":
        judgment_ceiling = "当前最多适合稳定交付为 `背景活动，建议持续观察`，仍不应把本案写成已成立安全事件。"
    else:
        judgment_ceiling = "当前最多适合稳定交付为 `可疑事件，建议继续复核`，尚不足以直接升级为 `确认安全事件`。"

    basis_clauses = _main_conclusion_basis_clauses(evidence_roles, counter_entries)
    judgment_basis = _reader_clean_text("；".join(basis_clauses) + "。") if basis_clauses else strongest_evidence

    main_report_contract = {
        "title": str(report_inputs.get("report_title") or "").strip() or "事件调查报告",
        "template_version": "incident-agent-v4",
        "evidence_roles": evidence_roles,
        "report_header": {
            "event_title": str(report_inputs.get("report_title") or "").strip() or "事件调查报告",
            "analysis_window": analysis_window,
            "current_status": delivery_status,
            "current_status_label": delivery_label,
            "severity": _reader_severity_text(verdict.get("severity")),
            "confidence": _reader_confidence_text(report_inputs.get("confidence_value") or verdict.get("confidence"), precise=False),
            "confirmed_scope": confirmed_scope_text,
            "strongest_evidence": strongest_evidence,
            "key_gap": key_gap,
            "immediate_action": primary_action,
            "one_sentence_summary": one_sentence_summary,
            "delivery_note": delivery_summary,
        },
        "background_and_leads": {
            "event_title": str(report_inputs.get("report_title") or "").strip() or "事件调查报告",
            "analysis_window": analysis_window,
            "seed_alert": seed_alert_text,
            "initial_hits": initial_hits,
            "upstream_context": str(report_inputs.get("upstream_context") or "").strip() or "当前没有额外上游背景被纳入主报告。",
            "investigation_focus": strongest_evidence,
            "source_text": _main_role_source_text(
                evidence_store,
                list(evidence_roles.get("trigger_evidence") or []) + list(evidence_roles.get("corroborating_evidence") or []) + list(evidence_roles.get("progression_evidence") or []),
                "上游检测、种子事件窗观测",
            ),
        },
        "scope_definition": {
            "investigation_scope": f"本轮调查覆盖 {analysis_window} 内围绕 {seed_asset} 与 {_join_or_fallback(core_indicators[:3], '当前关键通信对象')} 的关键事件窗。",
            "primary_hypothesis": (
                f"围绕 {scope_focus_text} 与 {_join_or_fallback(core_indicators[:4], '当前关键通信对象')} 的异常通信及后续高风险迹象，当前应按“{delivery_label}”收敛交付。"
                if delivery_status != "monitor_only"
                else f"围绕 {scope_focus_text} 与 {_join_or_fallback(core_indicators[:4], '当前关键通信对象')} 的异常，目前更接近背景活动或计划内行为，应以持续观察为主。"
            ),
            "alternative_hypothesis": counter_entries[0].get("fact_text") if counter_entries else "当前暂无比现有主链更强的稳定替代解释。",
            "out_of_scope": f"本轮不把未经过独立验证的候选对象 {_join_or_fallback(_dedupe_text(related_assets + expansion_candidates), '当前无') } 直接写成已确认范围，也不把背景情报直接写成已确认事实。",
            "primary_hypothesis_requirements": _main_hypothesis_requirements_text(evidence_roles, counter_entries, boundary_entries),
            "primary_hypothesis_failure_conditions": counter_entries[0].get("reason_text") if counter_entries else "如果后续出现更强的背景解释并且主链无法持续复现，当前结论需要重新收敛。",
            "source_text": _main_role_source_text(
                evidence_store,
                list(evidence_roles.get("trigger_evidence") or [])
                + list(evidence_roles.get("corroborating_evidence") or [])
                + list(evidence_roles.get("counterevidence") or [])
                + list(evidence_roles.get("boundary_gap_evidence") or []),
                "种子事件窗观测、背景核查",
            ),
        },
        "coverage_plan": {
            "in_chain_objects": _join_or_fallback(_dedupe_text(confirmed_assets + core_indicators + seed_fingerprints), "当前未单列纳入主链的对象"),
            "core_objects": _join_or_fallback(_dedupe_text([seed_asset] + confirmed_assets[:2] + core_indicators[:3]), "当前未单列核心观测对象"),
            "comparison_objects": _join_or_fallback(_dedupe_text(context_indicators[:6]), "当前未单列横向对比对象"),
            "expansion_candidates": _join_or_fallback(_dedupe_text(related_assets + expansion_candidates), "当前没有额外扩展候选"),
            "seed_asset": seed_asset,
            "confirmed_assets": confirmed_asset_text,
            "related_assets": _join_or_fallback(related_assets, "当前没有额外待确认关联资产"),
            "core_external_indicators": _join_or_fallback(core_indicators, "当前未单列核心外部基础设施"),
            "key_indicators": _join_or_fallback(_dedupe_text(core_indicators + seed_fingerprints), "当前未单列关键指示物"),
            "coverage_boundary": coverage_boundary_text,
            "source_text": _main_role_source_text(
                evidence_store,
                list(evidence_roles.get("scope_evidence") or []) + list(evidence_roles.get("boundary_gap_evidence") or []) + list(evidence_roles.get("trigger_evidence") or []),
                "内部观测、对象归并",
            ),
        },
        "mechanism_breakdown": {
            "trigger_or_start": (evidence_roles.get("trigger_evidence") or [{}])[0].get("reader_fact") or seed_alert_text,
            "main_chain": _main_chain_text(evidence_roles, seed_asset),
            "amplifier": _main_amplifier_text(evidence_roles, seed_asset),
            "unconfirmed_links": (
                _dedupe_text([str(item.get("reader_fact") or "").strip() for item in boundary_entries if str(item.get("reader_fact") or "").strip()])
                or _dedupe_text([str(item.get("why_selected") or "").strip() for item in boundary_entries if str(item.get("why_selected") or "").strip()])
                or ["当前没有必须单独展开的未确认机制环节。"]
            ),
            "source_text": _main_role_source_text(
                evidence_store,
                list(evidence_roles.get("trigger_evidence") or [])
                + list(evidence_roles.get("corroborating_evidence") or [])
                + list(evidence_roles.get("progression_evidence") or [])
                + list(evidence_roles.get("scope_evidence") or []),
                "内部观测",
            ),
        },
        "evidence_blocks": {
            "supporting": supporting_entries,
            "counterevidence": counter_entries,
            "background": {
                "hint": str((family_context or {}).get("hint") or "").strip(),
                "summary": _reader_clean_text((family_context or {}).get("summary")),
                "limits": _reader_clean_text((family_context or {}).get("limits")),
                "source_text": _section_source_text(
                    evidence_store,
                    list((family_context or {}).get("observation_ids") or []),
                    fallback="上游检测",
                ),
            }
            if family_context
            else {},
        },
        "timeline": {
            "entries": timeline_entries,
            "pattern_lines": pattern_lines,
            "source_text": _section_source_text(
                evidence_store,
                _dedupe_text(
                    [str(observation_id or "").strip() for item in timeline_entries for observation_id in list(item.get("observation_ids") or [])]
                ),
                fallback="内部观测",
            ),
        },
        "relationship_analysis": {
            "pivot_text": _join_or_fallback(
                _dedupe_text(
                    list((evidence_store.get("pivots") or {}).get("domains") or [])
                    + list((evidence_store.get("pivots") or {}).get("dst_ips") or [])
                    + list((evidence_store.get("pivots") or {}).get("fingerprints") or [])
                ),
                "当前未单列扩线 pivot",
            ),
            "confirmed_relationships": _dedupe_text(
                [str(item.get("reader_fact") or "").strip() for item in list(evidence_roles.get("scope_evidence") or []) if str(item.get("reader_fact") or "").strip()]
                + [
                    (
                        f"当前调查一共纳入了 {int(report_inputs.get('event_count') or 0)} 条关键事件，范围主要落在 {confirmed_scope_text}。"
                        if delivery_status == "confirmed_incident"
                        else f"当前调查一共纳入了 {int(report_inputs.get('event_count') or 0)} 条关键事件，当前调查重点仍围绕 `{scope_focus_text}`。"
                    )
                ]
            ),
            "candidate_relationships": _dedupe_text(
                [str(item.get("reader_fact") or "").strip() for item in boundary_entries if str(item.get("reader_fact") or "").strip()]
            ) or [suspected_impact],
            "unverified_objects": _join_or_fallback(_dedupe_text(related_assets + expansion_candidates), "当前没有额外未完成独立验证的对象"),
            "relationship_boundary": (
                f"当前确认范围收敛在 {confirmed_scope_text}；其余候选对象保持待确认状态。"
                if delivery_status == "confirmed_incident"
                else f"当前还没有可写入已确认影响范围的资产；调查重点仍围绕 `{scope_focus_text}`，其余候选对象保持待确认状态。"
            ),
            "source_text": _main_role_source_text(
                evidence_store,
                list(evidence_roles.get("scope_evidence") or []) + list(evidence_roles.get("boundary_gap_evidence") or []),
                "内部观测、关联扩查",
            ),
        },
        "impact_assessment": {
            "confirmed_impact": confirmed_impact,
            "suspected_impact": suspected_impact,
            "time_range": analysis_window,
            "asset_range": _join_or_fallback(confirmed_assets, seed_asset),
            "external_range": _join_or_fallback(core_indicators, "当前未单列外部基础设施"),
            "attack_stage": stage_text if stage_text != "未识别" else "当前尚未形成稳定的阶段判断",
            "unresolved_impact": unresolved_impact,
            "source_text": _main_role_source_text(
                evidence_store,
                list(evidence_roles.get("scope_evidence") or [])
                + list(evidence_roles.get("progression_evidence") or [])
                + list(evidence_roles.get("boundary_gap_evidence") or []),
                "内部观测、关联扩查",
            ),
        },
        "evidence_gap_summary": {
            "judgment_basis": judgment_basis,
            "strongest_evidence": strongest_evidence,
            "key_gap": key_gap,
            "judgment_ceiling": judgment_ceiling,
            "cannot_conclude": _dedupe_text([str(item.get("why_selected") or "").strip() for item in boundary_entries if str(item.get("why_selected") or "").strip()]) or ["当前没有额外必须单列的结论限制项。"],
            "next_best_evidence": _dedupe_text([str(item.get("reader_limit") or item.get("reader_fact") or "").strip() for item in boundary_entries if str(item.get("reader_limit") or item.get("reader_fact") or "").strip()]) or ["当前暂无需要优先补查的额外证据。"],
            "source_text": _main_role_source_text(
                evidence_store,
                list(evidence_roles.get("boundary_gap_evidence") or []) + list(evidence_roles.get("progression_evidence") or []) + list(evidence_roles.get("corroborating_evidence") or []),
                "内部观测、边界核查",
            ),
        },
        "recommended_actions": {
            "current_conclusion": delivery_label,
            "current_status": delivery_status,
            "severity": _reader_severity_text(verdict.get("severity")),
            "confidence": _reader_confidence_text(report_inputs.get("confidence_value") or verdict.get("confidence"), precise=False),
            "one_sentence_summary": one_sentence_summary,
            "why_current_conclusion": _main_current_conclusion_text(
                delivery_status=delivery_status,
                strongest_entry=strongest_entry,
                delivery_summary=delivery_summary,
                key_gap=key_gap,
                basis_clauses=basis_clauses,
            ),
            "why_not_other_status": _main_not_other_status_text(
                delivery_status=delivery_status,
                counter_entries=counter_entries,
                boundary_entries=boundary_entries,
            ),
            "immediate_actions": [_reader_action_text(item) for item in list(bucketed_actions.get("immediate") or []) if _reader_action_text(item)],
            "short_term_actions": [_reader_action_text(item) for item in list(bucketed_actions.get("short_term") or []) if _reader_action_text(item)],
            "follow_up_actions": [_reader_action_text(item) for item in list(bucketed_actions.get("follow_up") or []) if _reader_action_text(item)],
            "next_best_evidence": _dedupe_text([str(item.get("reader_limit") or item.get("reader_fact") or "").strip() for item in boundary_entries if str(item.get("reader_limit") or item.get("reader_fact") or "").strip()]) or ["当前暂无额外复核重点。"],
        },
    }
    return build_ops_report_contract(**main_report_contract)


def _build_appendix_contract_from_inputs(
    report_inputs: Dict[str, Any],
    evidence_contract: Dict[str, Any],
    main_report_contract: Dict[str, Any],
) -> Dict[str, Any]:
    report_inputs = report_inputs or {}
    evidence_blocks = dict(main_report_contract.get("evidence_blocks") or {})
    supporting_entries = list(evidence_blocks.get("supporting") or [])
    counter_entries = list(evidence_blocks.get("counterevidence") or [])
    top_gaps = _top_evidence_gaps(evidence_contract, limit=3)

    home_references = [entry.get("id") for entry in supporting_entries[:2] if entry.get("id")]
    if top_gaps:
        home_references.append(top_gaps[0].get("gap_id"))
    section_reference_rows = [
        {
            "section": "首页摘要",
            "references": _dedupe_text([str(item or "").strip() for item in home_references if str(item or "").strip()]),
            "purpose": "当前状态 / 当前最强证据 / 当前最关键缺口",
        },
        {
            "section": "第 5 节",
            "references": _dedupe_text(
                [str(item.get("id") or "").strip() for item in supporting_entries + counter_entries if str(item.get("id") or "").strip()]
            ),
            "purpose": "主支撑证据 / 反证与替代解释",
        },
        {
            "section": "第 9 节",
            "references": _dedupe_text(
                [str(item.get("gap_id") or "").strip() for item in top_gaps if str(item.get("gap_id") or "").strip()]
            ),
            "purpose": "证据链摘要 / 缺口说明",
        },
        {
            "section": "第 10 节",
            "references": _dedupe_text(
                [str(item.get("id") or "").strip() for item in supporting_entries[:2] if str(item.get("id") or "").strip()]
            ),
            "purpose": "结论 / 动作 / 复核重点",
        },
    ]

    appendix_ioc_rows: List[Dict[str, str]] = []
    seen_iocs: set[str] = set()
    registry_by_value = {
        str(item.get("value") or "").strip(): item for item in _registry_indicator_rows(evidence_contract)
    }
    for row in list(report_inputs.get("ioc_rows") or []):
        value = str(row.get("value") or "").strip()
        if not value or value in seen_iocs:
            continue
        seen_iocs.add(value)
        registry_row = registry_by_value.get(value, {})
        appendix_ioc_rows.append(
            {
                "type": _object_type_label(str(registry_row.get("object_type") or row.get("type") or "").strip()),
                "value": value,
                "role": str(registry_row.get("role_label") or row.get("relation") or "").strip() or "关联指标",
                "status": str(registry_row.get("status") or "已确认").strip(),
            }
        )
    for item in _registry_indicator_rows(evidence_contract):
        value = str(item.get("value") or "").strip()
        if not value or value in seen_iocs:
            continue
        seen_iocs.add(value)
        appendix_ioc_rows.append(
            {
                "type": str(item.get("type_label") or "").strip(),
                "value": value,
                "role": str(item.get("role_label") or "").strip(),
                "status": str(item.get("status") or "").strip() or "待确认",
            }
        )

    return build_appendix_contract(
        ioc_rows=appendix_ioc_rows,
        key_object_rows=[
            {
                "object": str(item.get("value") or "").strip(),
                "type": str(item.get("type_label") or "").strip(),
                "current_role": str(item.get("role_label") or "").strip(),
                "in_evidence_chain": "是" if bool(item.get("in_evidence_chain")) else "否",
                "note": "；".join(list(item.get("notes") or [])) or "无",
            }
            for item in _evidence_objects(evidence_contract)
        ],
        evidence_details=[
            {
                "id": str(entry.get("id") or "").strip(),
                "kind": "supporting",
                "category": str(entry.get("category") or "").strip(),
                "strength": str(entry.get("strength") or "").strip(),
                "fact_description": str(entry.get("fact_text") or "").strip(),
                "reason_text": str(entry.get("reason_text") or "").strip(),
                "limitation_text": str(entry.get("limitation_text") or "").strip(),
                "observation_ids": list(entry.get("observation_ids") or []),
                "source_text": str(entry.get("source_text") or "").strip()
                or _section_source_text(evidence_contract, list(entry.get("observation_ids") or []), fallback="内部观测"),
            }
            for entry in supporting_entries
        ]
        + [
            {
                "id": str(entry.get("id") or "").strip(),
                "kind": "counterevidence",
                "category": str(entry.get("category") or "").strip(),
                "strength": str(entry.get("strength") or "").strip(),
                "fact_description": str(entry.get("fact_text") or "").strip(),
                "reason_text": str(entry.get("reason_text") or "").strip(),
                "limitation_text": str(entry.get("limitation_text") or "").strip(),
                "observation_ids": list(entry.get("observation_ids") or []),
                "source_text": str(entry.get("source_text") or "").strip()
                or _section_source_text(evidence_contract, list(entry.get("observation_ids") or []), fallback="背景核查"),
            }
            for entry in counter_entries
        ],
        observation_rows=[
            {
                "observation_id": str(item.get("id") or "").strip(),
                "tool_name": str(item.get("tool_name") or "").strip(),
                "summary": str(item.get("summary") or "").strip(),
                "relation": str(item.get("relation") or "").strip() or "context",
            }
            for item in list(evidence_contract.get("observations") or [])
        ],
        section_reference_rows=section_reference_rows,
        source_rows=list(report_inputs.get("source_rows") or []),
        gap_rows=[
            {
                "gap": str(item.get("question") or "").strip(),
                "limited_conclusion": _gap_limited_conclusion(item),
                "actionable": "是" if bool(item.get("actionable_now")) else "否",
                "best_query": _gap_followup_text(item),
            }
            for item in _evidence_gaps(evidence_contract)
            if str(item.get("status") or "").strip() != "closed"
        ],
    )


def build_report_outline_from_artifacts(
    *,
    evidence_store: Dict[str, Any],
    reviewer_input: Dict[str, Any],
    delivery_decision: Dict[str, Any],
) -> Dict[str, Any]:
    report_inputs = build_report_inputs(evidence_store, delivery_decision)
    main_report_contract = _build_main_report_contract(report_inputs, evidence_store, delivery_decision)
    appendix_contract = _build_appendix_contract_from_inputs(report_inputs, evidence_store, main_report_contract)
    evidence_blocks = dict(main_report_contract.get("evidence_blocks") or {})
    supporting_entries = list(evidence_blocks.get("supporting") or [])
    counter_entries = list(evidence_blocks.get("counterevidence") or [])
    relationship_analysis = dict(main_report_contract.get("relationship_analysis") or {})
    delivery_readiness = dict(delivery_decision.get("readiness") or {})

    return {
        "title": "事件调查报告",
        "template_version": "incident-agent-v4",
        "evidence_store": evidence_store,
        "reviewer_input": reviewer_input,
        "delivery_decision": delivery_decision,
        "ops_report_contract": main_report_contract,
        "appendix_contract": appendix_contract,
        "evidence_contract": evidence_store,
        "main_report_contract": main_report_contract,
        "report_header": dict(main_report_contract.get("report_header") or {}),
        "executive_summary": dict(main_report_contract.get("report_header") or {}),
        "background_and_leads": dict(main_report_contract.get("background_and_leads") or {}),
        "scope_definition": dict(main_report_contract.get("scope_definition") or {}),
        "coverage_plan": dict(main_report_contract.get("coverage_plan") or {}),
        "mechanism_breakdown": dict(main_report_contract.get("mechanism_breakdown") or {}),
        "evidence_blocks": evidence_blocks,
        "counterevidence_blocks": list(evidence_blocks.get("counterevidence") or []),
        "timeline": dict(main_report_contract.get("timeline") or {}),
        "relationship_analysis": relationship_analysis,
        "impact_assessment": dict(main_report_contract.get("impact_assessment") or {}),
        "evidence_gap_summary": dict(main_report_contract.get("evidence_gap_summary") or {}),
        "recommended_actions": dict(main_report_contract.get("recommended_actions") or {}),
        "section_presence": {
            "mechanism_breakdown": bool(main_report_contract.get("mechanism_breakdown")),
            "timeline": bool((main_report_contract.get("timeline") or {}).get("entries")),
            "relationship_analysis": bool(
                list(relationship_analysis.get("confirmed_relationships") or [])
                or list(relationship_analysis.get("candidate_relationships") or [])
            ),
            "background_context": bool((evidence_blocks.get("background") or {}).get("summary")),
        },
        "appendix": appendix_contract,
        "analysis": dict(report_inputs.get("analysis") or {}),
        "scope_summary": dict(report_inputs.get("scope_summary") or {}),
        "scope": dict(report_inputs.get("scope_summary") or {}),
        "supporting_entries": supporting_entries,
        "counter_entries": counter_entries,
        "delivery_readiness": delivery_readiness,
        "analysis_verdict": dict(report_inputs.get("analysis_verdict") or {}),
    }


def _prune_empty_structure(value: Any) -> Any:
    if isinstance(value, dict):
        pruned: Dict[str, Any] = {}
        for key, item in value.items():
            normalized = _prune_empty_structure(item)
            if normalized in ("", None, [], {}):
                continue
            pruned[str(key)] = normalized
        return pruned
    if isinstance(value, list):
        pruned_list = [_prune_empty_structure(item) for item in value]
        return [item for item in pruned_list if item not in ("", None, [], {})]
    return value


def _polish_input_text(value: Any) -> str:
    text = _reader_clean_text(value)
    if not text:
        return ""
    replacements = {
        "material delta": "新的有效信息",
        "reportable_unresolved": "可交付但未完全闭合",
        "open_unaddressable": "当前暂缺继续缩小所需证据或工具",
        "deterministic report": "结构化报告",
    }
    for source, target in replacements.items():
        text = text.replace(source, target)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _polish_input_list(values: List[Any], *, limit: int | None = None) -> List[str]:
    items = _dedupe_text([_polish_input_text(value) for value in list(values or []) if _polish_input_text(value)])
    if limit is None:
        return items
    return items[:limit]


def _extract_fact_time(text: Any) -> str:
    match = re.search(r"在\s+(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC)", str(text or ""))
    return str(match.group(1) or "").strip() if match else ""


def _polish_signal_role(category: Any, *, is_counter: bool = False) -> str:
    text = str(category or "").strip()
    if is_counter:
        return "反证检查"
    if "调查触发" in text:
        return "调查起点"
    if "连续性支撑" in text:
        return "持续通信"
    if "风险升级" in text:
        return "风险升级"
    if "范围确认" in text:
        return "范围扩展"
    return _polish_input_text(text) or "关键观察"


def _select_polish_supporting_entries(entries: List[Dict[str, Any]], *, limit: int = 5) -> List[Dict[str, Any]]:
    ordered: List[Dict[str, Any]] = []
    seen_ids: set[str] = set()
    category_priority = ["调查触发", "连续性支撑", "风险升级", "范围确认"]
    for category_keyword in category_priority:
        for entry in list(entries or []):
            entry_id = str(entry.get("id") or "").strip()
            if not entry_id or entry_id in seen_ids:
                continue
            if category_keyword in str(entry.get("category") or ""):
                ordered.append(entry)
                seen_ids.add(entry_id)
                break
    for entry in list(entries or []):
        entry_id = str(entry.get("id") or "").strip()
        if not entry_id or entry_id in seen_ids:
            continue
        ordered.append(entry)
        seen_ids.add(entry_id)
    return ordered[:limit]


def _report_polish_timeline_rows_from_evidence(
    supporting_entries: List[Dict[str, Any]],
    counter_entries: List[Dict[str, Any]],
    *,
    limit: int = 6,
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    candidates: List[Dict[str, Any]] = []
    for entry in list(supporting_entries or []):
        fact = _polish_input_text(entry.get("fact_text"))
        if not fact:
            continue
        candidates.append(
            {
                "time": _extract_fact_time(fact),
                "role": _polish_signal_role(entry.get("category")),
                "event": fact,
            }
        )
    for entry in list(counter_entries or []):
        fact = _polish_input_text(entry.get("fact_text"))
        if not fact:
            continue
        candidates.append(
            {
                "time": _extract_fact_time(fact),
                "role": _polish_signal_role(entry.get("category"), is_counter=True),
                "event": fact,
            }
        )

    seen: set[tuple[str, str, str]] = set()
    for entry in sorted(candidates, key=lambda item: (str(item.get("time") or ""), str(item.get("role") or ""), str(item.get("event") or ""))):
        key = (str(entry.get("time") or ""), str(entry.get("role") or ""), str(entry.get("event") or ""))
        if key in seen:
            continue
        seen.add(key)
        rows.append(
            {
                "time": str(entry.get("time") or "").strip(),
                "role": str(entry.get("role") or "").strip(),
                "event": str(entry.get("event") or "").strip(),
            }
        )
        if len(rows) >= limit:
            break
    return rows


def _report_polish_evidence_rows(entries: List[Dict[str, Any]], *, limit: int) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for entry in list(entries or [])[:limit]:
        rows.append(
            {
                "id": str(entry.get("id") or "").strip(),
                "category": _polish_input_text(entry.get("category")),
                "strength": _polish_input_text(entry.get("strength")),
                "fact": _polish_input_text(entry.get("fact_text")),
                "why_it_matters": _polish_input_text(entry.get("reason_text")),
                "limitation": _polish_input_text(entry.get("limitation_text")),
            }
        )
    return rows


def _select_polish_boundary_findings(
    relationships: Dict[str, Any],
    gaps: Dict[str, Any],
) -> List[str]:
    direct_items = _polish_input_list(list(relationships.get("candidate_relationships") or []), limit=3)
    if direct_items:
        return direct_items
    constrained_items = [
        item
        for item in _polish_input_list(list(gaps.get("cannot_conclude") or []))
        if not item.startswith("当前仍缺少对“")
    ]
    if constrained_items:
        return constrained_items[:3]
    return _polish_input_list(list(gaps.get("next_best_evidence") or []), limit=2)


def _build_report_polish_input_legacy(outline: Dict[str, Any]) -> Dict[str, Any]:
    outline = dict(outline or {})
    main_report = dict(outline.get("ops_report_contract") or outline.get("main_report_contract") or {})
    report_header = dict(main_report.get("report_header") or {})
    background = dict(main_report.get("background_and_leads") or {})
    scope = dict(main_report.get("scope_definition") or {})
    coverage = dict(main_report.get("coverage_plan") or {})
    mechanism = dict(main_report.get("mechanism_breakdown") or {})
    evidence_blocks = dict(main_report.get("evidence_blocks") or {})
    timeline = dict(main_report.get("timeline") or {})
    relationships = dict(main_report.get("relationship_analysis") or {})
    impact = dict(main_report.get("impact_assessment") or {})
    gaps = dict(main_report.get("evidence_gap_summary") or {})
    actions = dict(main_report.get("recommended_actions") or {})
    supporting = _select_polish_supporting_entries(list(evidence_blocks.get("supporting") or []), limit=5)
    counterevidence = list(evidence_blocks.get("counterevidence") or [])[:2]
    background_context = dict(evidence_blocks.get("background") or {})
    boundary_findings = _select_polish_boundary_findings(relationships, gaps)
    relationship_findings = _polish_input_list(list(relationships.get("confirmed_relationships") or []), limit=4)

    polish_input = {
        "schema_version": "report-polish-input-v1",
        "audience": "运维人员与安全运营协同对象",
        "goal": "在不引入新事实的前提下，把结构化调查结果写成更像分析师交付给运维的中文 Markdown 报告。",
        "report_brief": {
            "title": _polish_input_text(main_report.get("title") or report_header.get("event_title")),
            "analysis_window": _polish_input_text(report_header.get("analysis_window")),
            "final_verdict": _polish_input_text(report_header.get("current_status_label") or report_header.get("current_status")),
            "severity": _polish_input_text(report_header.get("severity")),
            "confidence": _polish_input_text(report_header.get("confidence")),
            "confirmed_scope": _polish_input_text(report_header.get("confirmed_scope")),
            "suspected_scope": _polish_input_text(impact.get("suspected_impact")),
            "executive_summary": _polish_input_text(report_header.get("one_sentence_summary")),
            "strongest_evidence": _polish_input_text(report_header.get("strongest_evidence")),
            "key_gap": _polish_input_text(report_header.get("key_gap")),
            "why_current_conclusion": _polish_input_text(actions.get("why_current_conclusion")),
            "why_not_other_status": _polish_input_text(actions.get("why_not_other_status")),
            "immediate_actions": _polish_input_list(list(actions.get("immediate_actions") or []), limit=5),
            "short_term_actions": _polish_input_list(list(actions.get("short_term_actions") or []), limit=5),
            "follow_up_actions": _polish_input_list(list(actions.get("follow_up_actions") or []), limit=5),
        },
        "evidence_pack": {
            "background": {
            "seed_alert": _polish_input_text(background.get("seed_alert")),
            "initial_hits": _polish_input_list(list(background.get("initial_hits") or []), limit=6),
            "upstream_context": _polish_input_text(background.get("upstream_context")),
            "investigation_focus": _polish_input_text(background.get("investigation_focus")),
            },
            "scope_snapshot": {
                "investigation_scope": _polish_input_text(scope.get("investigation_scope")),
                "primary_hypothesis": _polish_input_text(scope.get("primary_hypothesis")),
                "alternative_hypothesis": _polish_input_text(scope.get("alternative_hypothesis")),
                "out_of_scope": _polish_input_text(scope.get("out_of_scope")),
                "hypothesis_requirements": _polish_input_text(scope.get("primary_hypothesis_requirements")),
                "hypothesis_failure_conditions": _polish_input_text(scope.get("primary_hypothesis_failure_conditions")),
                "confirmed_assets": _polish_input_text(coverage.get("confirmed_assets")),
                "related_assets": _polish_input_text(coverage.get("related_assets")),
                "core_external_indicators": _polish_input_text(coverage.get("core_external_indicators")),
                "key_indicators": _polish_input_text(coverage.get("key_indicators")),
                "coverage_boundary": _polish_input_text(coverage.get("coverage_boundary")),
            },
            "mechanism_summary": {
                "trigger_or_start": _polish_input_text(mechanism.get("trigger_or_start")),
                "main_chain": _polish_input_text(mechanism.get("main_chain")),
                "amplifier": _polish_input_text(mechanism.get("amplifier")),
                "unconfirmed_links": _polish_input_list(list(mechanism.get("unconfirmed_links") or []), limit=3),
            },
            "supporting_evidence": _report_polish_evidence_rows(supporting, limit=5),
            "counterevidence": _report_polish_evidence_rows(counterevidence, limit=2),
            "background_context": {
                "hint": _polish_input_text(background_context.get("hint")),
                "summary": _polish_input_text(background_context.get("summary")),
                "limits": _polish_input_text(background_context.get("limits")),
            },
            "timeline_highlights": {
                "patterns": _polish_input_list(list(timeline.get("pattern_lines") or []), limit=5),
                "key_events": _report_polish_timeline_rows_from_evidence(supporting, counterevidence, limit=6),
            },
            "relationship_findings": {
                "pivots": _polish_input_text(relationships.get("pivot_text")),
                "confirmed_relationships": relationship_findings,
                "candidate_relationships": _polish_input_list(list(relationships.get("candidate_relationships") or []), limit=3),
                "unverified_objects": _polish_input_text(relationships.get("unverified_objects")),
                "relationship_boundary": _polish_input_text(relationships.get("relationship_boundary")),
            },
            "impact_summary": {
                "confirmed_impact": _polish_input_text(impact.get("confirmed_impact")),
                "suspected_impact": _polish_input_text(impact.get("suspected_impact")),
                "time_range": _polish_input_text(impact.get("time_range")),
                "asset_range": _polish_input_text(impact.get("asset_range")),
                "external_range": _polish_input_text(impact.get("external_range")),
                "attack_stage": _polish_input_text(impact.get("attack_stage")),
                "unresolved_impact": _polish_input_list(list(impact.get("unresolved_impact") or []), limit=3),
            },
            "open_limits": {
                "judgment_basis": _polish_input_text(gaps.get("judgment_basis")),
                "judgment_ceiling": _polish_input_text(gaps.get("judgment_ceiling")),
                "boundary_findings": boundary_findings,
                "next_best_evidence": _polish_input_list(list(actions.get("next_best_evidence") or []), limit=3),
            },
        },
        "output_requirements": {
            "must_keep_single_report": True,
            "technical_appendix_will_be_appended": True,
            "appendix_note": "系统会在正文后自动追加完整技术附录；正文只需在第11节提示读者重点关注哪些技术明细。",
            "writer_style": [
                "优先写清楚为什么判断成立，而不是逐字段复述材料。",
                "相近证据要归并叙述，避免对重复网络复现逐条使用同样解释。",
                "如果材料中出现英文事件描述，请改写成自然中文运维表述。",
                "不要引入新事实，不要暴露内部实现术语。",
            ],
        },
    }
    return _prune_empty_structure(polish_input)


def _fact_card_index(report_fact_cards: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {
        str(item.get("fact_id") or "").strip(): dict(item)
        for item in list(report_fact_cards.get("fact_cards") or [])
        if isinstance(item, dict) and str(item.get("fact_id") or "").strip()
    }


def _fact_cards_by_type(
    report_fact_cards: Dict[str, Any],
    *,
    fact_type: str,
    status: str | None = None,
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for item in list(report_fact_cards.get("fact_cards") or []):
        if not isinstance(item, dict):
            continue
        if str(item.get("fact_type") or "").strip() != fact_type:
            continue
        if status is not None and str(item.get("status") or "").strip() != status:
            continue
        rows.append(dict(item))
    return rows


def _scope_role_index(report_fact_cards: Dict[str, Any]) -> Dict[str, str]:
    index: Dict[str, str] = {}
    for item in _fact_cards_by_type(report_fact_cards, fact_type="scope"):
        entity = _polish_input_text(item.get("entity"))
        role = _polish_input_text(item.get("role"))
        if entity and role and entity not in index:
            index[entity] = role
    return index


def _fact_id(item: Dict[str, Any]) -> str:
    return _polish_input_text(item.get("fact_id"))


def _event_fact_subject_role(event_fact: Dict[str, Any], scope_roles: Dict[str, str]) -> str:
    subject = _polish_input_text(event_fact.get("subject"))
    return scope_roles.get(subject, "")


def _event_fact_action(event_fact: Dict[str, Any]) -> str:
    return _polish_input_text(event_fact.get("action"))


def _take_fact_ids(
    rows: List[Dict[str, Any]],
    *,
    limit: int,
    skip: set[str] | None = None,
    predicate: Any | None = None,
) -> List[str]:
    used = skip if skip is not None else set()
    selected: List[str] = []
    for row in rows:
        fact_id = _fact_id(row)
        if not fact_id or fact_id in used:
            continue
        if predicate is not None and not predicate(row):
            continue
        selected.append(fact_id)
        used.add(fact_id)
        if len(selected) >= max(0, int(limit)):
            break
    return selected


def _fact_reporting_focus(fact: Dict[str, Any], scope_roles: Dict[str, str]) -> str:
    fact_type = _polish_input_text(fact.get("fact_type"))
    status = _polish_input_text(fact.get("status"))
    if fact_type == "event":
        action = _event_fact_action(fact)
        subject_role = _event_fact_subject_role(fact, scope_roles)
        if status == "candidate":
            return "待确认扩展"
        if status == "background":
            return "背景反证"
        if action == "解析域名":
            return "异常起点"
        if action == "对外通信" and subject_role == "seed_asset":
            return "落地外联"
        if action == "对外通信" and subject_role == "affected_asset":
            return "跨资产复现"
        if action == "出现执行迹象":
            return "主机升级"
        if action == "访问内网目标" and subject_role == "seed_asset":
            return "横向推进"
        if action == "访问内网目标":
            return "范围确认"
        return "关键事件"
    if fact_type == "scope":
        role = _polish_input_text(fact.get("role"))
        mapping = {
            "seed_asset": "调查锚点",
            "affected_asset": "已确认受影响资产",
            "related_asset": "待确认对象",
            "core_external_indicator": "已确认关联基础设施",
            "related_internal_address": "内网关联对象",
            "contextual_indicator": "背景指标",
            "family_hint": "背景提示",
            "seed_fingerprint": "种子指标",
            "expansion_candidate": "待确认对象",
        }
        return mapping.get(role, "关键对象")
    if fact_type == "gap":
        return "交付边界"
    if fact_type == "counterevidence":
        return "替代解释"
    if fact_type == "action_basis":
        return "处置动作"
    return "关键事实"


def _fact_boundary_note(fact: Dict[str, Any], scope_roles: Dict[str, str]) -> str:
    fact_type = _polish_input_text(fact.get("fact_type"))
    status = _polish_input_text(fact.get("status"))
    if fact_type == "event":
        action = _event_fact_action(fact)
        subject_role = _event_fact_subject_role(fact, scope_roles)
        if status == "candidate":
            return "未独立验证，不能并入已确认范围"
        if status == "background":
            return "只能帮助收窄边界，不能单独推翻主结论"
        if action == "解析域名":
            return "单次解析不足以独立定性"
        if action == "对外通信" and subject_role == "seed_asset":
            return "仍需结合复现或主机侧线索共同定性"
        if action == "对外通信" and subject_role == "affected_asset":
            return "要结合时序或主机线索，避免把共享基础设施直接写成确认感染"
        if action == "出现执行迹象":
            return "可确认风险升级，但仍缺少更细载荷细节"
        if action == "访问内网目标":
            return "说明内网推进，但要结合对象角色说明实际影响范围"
        return "不要脱离上下文单独放大这条事实"
    if fact_type == "scope":
        role = _polish_input_text(fact.get("role"))
        mapping = {
            "seed_asset": "作为起点表述，不等于单点即可完成定性，也不要写成已确认受影响范围",
            "affected_asset": "说明对象已进入已确认影响范围，但不要替代具体证据链",
            "related_asset": "保持待确认，不写成已确认受影响",
            "core_external_indicator": "只应写入外联判断或边界封禁动作，不写成已确认受影响范围",
            "related_internal_address": "只应写入内网推进或核查动作，不写成已确认受影响范围",
            "contextual_indicator": "只能作为背景，不要抬成主结论",
            "family_hint": "只能辅助解释，不做强归因",
            "seed_fingerprint": "仅作为起点指标，不直接等于事件成立",
            "expansion_candidate": "仍需独立验证，不能直接升格",
        }
        return mapping.get(role, "")
    if fact_type == "gap":
        return "限制范围继续扩大，但不否定当前主结论"
    if fact_type == "counterevidence":
        return "要解释为何不足以推翻主判断，而不是只罗列背景事件"
    if fact_type == "action_basis":
        return "动作需回扣前文证据或边界判断"
    return ""


def _fact_catalog_entry(fact: Dict[str, Any], scope_roles: Dict[str, str]) -> Dict[str, Any]:
    return {
        "fact_id": _polish_input_text(fact.get("fact_id")),
        "fact_type": _polish_input_text(fact.get("fact_type")),
        "status": _polish_input_text(fact.get("status")),
        "summary_line": _polish_input_text(fact.get("summary_line")),
        "reporting_focus": _fact_reporting_focus(fact, scope_roles),
        "boundary_note": _fact_boundary_note(fact, scope_roles),
    }


def _build_fact_catalog_for_ids(
    report_fact_cards: Dict[str, Any],
    *,
    allowed_fact_ids: set[str] | None,
) -> List[Dict[str, Any]]:
    scope_roles = _scope_role_index(report_fact_cards)
    scope_cards = _fact_cards_by_type(report_fact_cards, fact_type="scope")

    def _scope_cards_for_roles(*roles: str) -> List[Dict[str, Any]]:
        role_set = {str(role).strip() for role in roles if str(role).strip()}
        return [item for item in scope_cards if _polish_input_text(item.get("role")) in role_set]

    group_specs = [
        ("已确认事件事实", _fact_cards_by_type(report_fact_cards, fact_type="event", status="confirmed")),
        ("待确认事件事实", _fact_cards_by_type(report_fact_cards, fact_type="event", status="candidate")),
        ("背景事件事实", _fact_cards_by_type(report_fact_cards, fact_type="event", status="background")),
        ("调查锚点对象", _scope_cards_for_roles("seed_asset")),
        ("已确认受影响对象", _scope_cards_for_roles("affected_asset")),
        ("待确认范围对象", _scope_cards_for_roles("related_asset", "expansion_candidate")),
        ("已确认关联基础设施", _scope_cards_for_roles("core_external_indicator")),
        ("内网关联对象", _scope_cards_for_roles("related_internal_address")),
        ("背景指标对象", _scope_cards_for_roles("contextual_indicator", "family_hint", "seed_fingerprint")),
        ("反证事实", _fact_cards_by_type(report_fact_cards, fact_type="counterevidence")),
        ("缺口事实", _fact_cards_by_type(report_fact_cards, fact_type="gap")),
        ("动作依据事实", _fact_cards_by_type(report_fact_cards, fact_type="action_basis")),
    ]
    catalog: List[Dict[str, Any]] = []
    for group_title, facts in group_specs:
        entries = []
        for fact in facts:
            fact_id = _polish_input_text(fact.get("fact_id"))
            if not fact_id:
                continue
            if allowed_fact_ids is not None and fact_id not in allowed_fact_ids:
                continue
            entries.append(_fact_catalog_entry(fact, scope_roles))
        if not entries:
            continue
        catalog.append(
            {
                "group_title": group_title,
                "facts": entries,
            }
        )
    return catalog


def _section_fact_payload(
    fact_index: Dict[str, Dict[str, Any]],
    *,
    fact_ids: List[str],
    packet_refs: List[str],
    objective: str,
    section_id: str,
    section_title: str,
) -> Dict[str, Any]:
    cleaned_fact_ids = [fact_id for fact_id in _dedupe_text(fact_ids) if dict(fact_index.get(fact_id) or {})]
    return {
        "section_id": section_id,
        "section_title": section_title,
        "objective": objective,
        "packet_refs": _dedupe_text(packet_refs),
        "allowed_fact_ids": cleaned_fact_ids,
    }


def _build_section_fact_map(report_fact_cards: Dict[str, Any]) -> List[Dict[str, Any]]:
    fact_index = _fact_card_index(report_fact_cards)
    verdict_packet = dict(report_fact_cards.get("verdict_packet") or {})
    constraint_packet = dict(report_fact_cards.get("constraint_packet") or {})
    action_packet = dict(report_fact_cards.get("action_packet") or {})
    scope_roles = _scope_role_index(report_fact_cards)

    confirmed_events = _fact_cards_by_type(report_fact_cards, fact_type="event", status="confirmed")
    candidate_events = _fact_cards_by_type(report_fact_cards, fact_type="event", status="candidate")
    background_events = _fact_cards_by_type(report_fact_cards, fact_type="event", status="background")
    key_scope_cards = [
        item
        for item in _fact_cards_by_type(report_fact_cards, fact_type="scope")
        if str(item.get("role") or "").strip() in {"seed_asset", "affected_asset", "related_asset", "expansion_candidate", "core_external_indicator"}
    ]
    anchor_scope_ids = [
        str(item.get("fact_id") or "").strip()
        for item in key_scope_cards
        if str(item.get("role") or "").strip() == "seed_asset"
    ]
    core_external_scope_ids = [
        str(item.get("fact_id") or "").strip()
        for item in key_scope_cards
        if str(item.get("role") or "").strip() == "core_external_indicator"
    ]
    affected_scope_ids = [
        str(item.get("fact_id") or "").strip()
        for item in key_scope_cards
        if str(item.get("role") or "").strip() == "affected_asset"
    ]
    candidate_scope_ids = [
        str(item.get("fact_id") or "").strip()
        for item in key_scope_cards
        if str(item.get("role") or "").strip() in {"related_asset", "expansion_candidate"}
    ]
    counter_cards = _fact_cards_by_type(report_fact_cards, fact_type="counterevidence")
    gap_cards = _fact_cards_by_type(report_fact_cards, fact_type="gap")

    def _role_is(row: Dict[str, Any], role_name: str) -> bool:
        return _event_fact_subject_role(row, scope_roles) == role_name

    def _action_is(row: Dict[str, Any], action_name: str) -> bool:
        return _event_fact_action(row) == action_name

    seed_dns_ids = _take_fact_ids(
        confirmed_events,
        limit=2,
        predicate=lambda row: _action_is(row, "解析域名") and _role_is(row, "seed_asset"),
    )
    seed_external_ids = _take_fact_ids(
        confirmed_events,
        limit=3,
        predicate=lambda row: _action_is(row, "对外通信") and _role_is(row, "seed_asset"),
    )
    affected_external_ids = _take_fact_ids(
        confirmed_events,
        limit=3,
        predicate=lambda row: _action_is(row, "对外通信") and _role_is(row, "affected_asset"),
    )
    execution_ids = _take_fact_ids(
        confirmed_events,
        limit=3,
        predicate=lambda row: _action_is(row, "出现执行迹象"),
    )
    seed_lateral_ids = _take_fact_ids(
        confirmed_events,
        limit=3,
        predicate=lambda row: _action_is(row, "访问内网目标") and _role_is(row, "seed_asset"),
    )
    affected_lateral_ids = _take_fact_ids(
        confirmed_events,
        limit=3,
        predicate=lambda row: _action_is(row, "访问内网目标") and _role_is(row, "affected_asset"),
    )
    candidate_event_ids = [_fact_id(item) for item in candidate_events if _fact_id(item)]
    background_event_ids = [_fact_id(item) for item in background_events if _fact_id(item)]
    counter_ids = [_fact_id(item) for item in counter_cards if _fact_id(item)]
    gap_ids = [_fact_id(item) for item in gap_cards if _fact_id(item)]

    return [
        _section_fact_payload(
            fact_index,
            section_id="summary",
            section_title="首页摘要",
            objective="只收敛结论、严重度、把握度、已确认受影响范围和立即动作，不展开附录型对象清单；如果当前只有调查锚点而没有已确认受影响资产，不要把调查锚点改写成已确认影响范围。",
            packet_refs=["verdict_packet", "scope_packet", "action_packet"],
            fact_ids=list(verdict_packet.get("supporting_fact_ids") or [])[:4] + core_external_scope_ids[:1] + affected_scope_ids[:1],
        ),
        _section_fact_payload(
            fact_index,
            section_id="1",
            section_title="1. 事件背景与已知线索",
            objective="说明事件为什么进入调查、调查起点资产是什么、初始异常是什么，以及当前最关键的外部基础设施是什么。",
            packet_refs=["verdict_packet", "scope_packet"],
            fact_ids=seed_dns_ids[:1] + seed_external_ids[:1] + anchor_scope_ids[:1] + core_external_scope_ids[:2],
        ),
        _section_fact_payload(
            fact_index,
            section_id="2",
            section_title="2. 范围界定与调查假设",
            objective="说明调查锚点、已确认受影响范围和待确认对象各落在哪里，以及为什么边界停在这里。",
            packet_refs=["scope_packet", "constraint_packet"],
            fact_ids=anchor_scope_ids[:1] + affected_scope_ids[:2] + core_external_scope_ids[:2] + candidate_scope_ids[:1] + gap_ids[:1] + counter_ids[:1],
        ),
        _section_fact_payload(
            fact_index,
            section_id="3",
            section_title="3. 对象覆盖策略与关键实体",
            objective="区分调查锚点、已确认受影响对象、待确认对象、核心外部基础设施和背景指标，只点关键对象。",
            packet_refs=["scope_packet"],
            fact_ids=anchor_scope_ids[:1] + affected_scope_ids[:2] + candidate_scope_ids[:1] + core_external_scope_ids[:2],
        ),
        _section_fact_payload(
            fact_index,
            section_id="4",
            section_title="4. 事件机制分解",
            objective="按推进关系解释事件从异常通信到执行/横向的主链，不逐条重放所有时间点。",
            packet_refs=["verdict_packet", "scope_packet"],
            fact_ids=seed_dns_ids[:1] + seed_external_ids[:1] + execution_ids[:1] + seed_lateral_ids[:1] + (affected_external_ids[:1] or affected_lateral_ids[:1]),
        ),
        _section_fact_payload(
            fact_index,
            section_id="5",
            section_title="5. 关键证据与异常事实",
            objective="只抓最关键的支撑事实与反证边界，写清它们为什么改变判断。",
            packet_refs=["verdict_packet", "constraint_packet"],
            fact_ids=seed_external_ids[:1] + affected_external_ids[:1] + execution_ids[:1] + (seed_lateral_ids[:1] or affected_lateral_ids[:1]) + counter_ids[:1],
        ),
        _section_fact_payload(
            fact_index,
            section_id="6",
            section_title="6. 时序特征与行为模式",
            objective="只保留少量关键时间节点，并说明这些节点对判断意味着什么。",
            packet_refs=["verdict_packet", "constraint_packet"],
            fact_ids=seed_dns_ids[:1] + seed_external_ids[:1] + execution_ids[:1] + (affected_external_ids[:1] or affected_lateral_ids[:1]) + background_event_ids[:1],
        ),
        _section_fact_payload(
            fact_index,
            section_id="7",
            section_title="7. 传播与关联分析",
            objective="说明哪些关联已经进入主判断，哪些扩线结果仍只是候选或边界说明，不要把调查锚点直接写成范围扩大。",
            packet_refs=["scope_packet", "constraint_packet"],
            fact_ids=seed_lateral_ids[:1] + (affected_external_ids[:1] or affected_lateral_ids[:1]) + candidate_event_ids[:3] + candidate_scope_ids[:1],
        ),
        _section_fact_payload(
            fact_index,
            section_id="8",
            section_title="8. 影响分析",
            objective="说明已确认受影响范围、已确认异常行为和仍待确认部分之间的区别；如果没有已确认受影响资产，必须写成“当前尚无已确认受影响资产；已观察到的异常行为主要落在调查锚点”，不要使用“影响范围仅限于调查锚点”这类表述。",
            packet_refs=["verdict_packet", "scope_packet", "action_packet"],
            fact_ids=anchor_scope_ids[:1] + affected_scope_ids[:2] + candidate_scope_ids[:1] + core_external_scope_ids[:2] + (affected_external_ids[:1] or execution_ids[:1] or seed_external_ids[:1]) + (affected_lateral_ids[:1] or seed_lateral_ids[:1]),
        ),
        _section_fact_payload(
            fact_index,
            section_id="9",
            section_title="9. 证据链摘要与观测缺口",
            objective="说明判断上限、当前仍未闭合的缺口，以及为什么这些缺口没有推翻主判断。",
            packet_refs=["constraint_packet"],
            fact_ids=list(constraint_packet.get("supporting_fact_ids") or []) + candidate_event_ids[:2],
        ),
        _section_fact_payload(
            fact_index,
            section_id="10",
            section_title="10. 结论与后续建议",
            objective="按立即处置、短期核查、持续复核三类写动作建议，并回扣前文证据边界。",
            packet_refs=["verdict_packet", "action_packet", "constraint_packet"],
            fact_ids=list(action_packet.get("supporting_fact_ids") or []) + gap_ids[:1],
        ),
        _section_fact_payload(
            fact_index,
            section_id="11",
            section_title="11. 技术附录提示",
            objective="只提示附录里有哪些技术明细可以进一步查阅，不重复附录内容。",
            packet_refs=["scope_packet", "constraint_packet"],
            fact_ids=counter_ids[:1] + gap_ids[:1],
        ),
    ]


def _collect_report_writer_fact_ids(
    packets: Dict[str, Dict[str, Any]],
    section_fact_map: List[Dict[str, Any]],
) -> set[str]:
    fact_ids: List[str] = []
    for packet in packets.values():
        fact_ids.extend(list(packet.get("supporting_fact_ids") or []))
    for section in section_fact_map:
        fact_ids.extend(list(section.get("allowed_fact_ids") or []))
    return set(_dedupe_text(fact_ids))


def build_report_polish_input_v2(outline: Dict[str, Any], report_fact_cards: Dict[str, Any]) -> Dict[str, Any]:
    outline = dict(outline or {})
    report_fact_cards = dict(report_fact_cards or {})
    main_report = dict(outline.get("ops_report_contract") or outline.get("main_report_contract") or {})
    report_header = dict(main_report.get("report_header") or {})
    verdict_packet = dict(report_fact_cards.get("verdict_packet") or {})
    scope_packet = dict(report_fact_cards.get("scope_packet") or {})
    constraint_packet = dict(report_fact_cards.get("constraint_packet") or {})
    action_packet = dict(report_fact_cards.get("action_packet") or {})
    section_fact_map = _build_section_fact_map(report_fact_cards)
    referenced_fact_ids = _collect_report_writer_fact_ids(
        {
            "verdict_packet": verdict_packet,
            "scope_packet": scope_packet,
            "constraint_packet": constraint_packet,
            "action_packet": action_packet,
        },
        section_fact_map,
    )

    return _prune_empty_structure(
        {
            "schema_version": "report-polish-input-v2",
            "source_mode": "fact_cards_v2",
            "audience": "运维人员与安全运营协同对象",
            "goal": "在不引入新事实的前提下，基于统一事实卡和结论 packet 写成更像分析师交付给运维的中文 Markdown 报告。",
            "fact_card_count": len(list(report_fact_cards.get("fact_cards") or [])),
            "packet_refs": ["verdict_packet", "scope_packet", "constraint_packet", "action_packet"],
            "report_header": {
                "title": _polish_input_text(main_report.get("title") or report_header.get("event_title")),
                "analysis_window": _polish_input_text(report_header.get("analysis_window")),
                "final_verdict": _polish_input_text(report_header.get("current_status_label") or report_header.get("current_status")),
                "severity": _polish_input_text(verdict_packet.get("severity") or report_header.get("severity")),
                "confidence": _polish_input_text(verdict_packet.get("confidence") or report_header.get("confidence")),
                "confirmed_scope": _polish_input_text(report_header.get("confirmed_scope")),
                "one_sentence_summary": _polish_input_text(verdict_packet.get("conclusion_statement") or report_header.get("one_sentence_summary")),
            },
            "packets": {
                "verdict_packet": verdict_packet,
                "scope_packet": scope_packet,
                "constraint_packet": constraint_packet,
                "action_packet": action_packet,
            },
            "fact_catalog": _build_fact_catalog_for_ids(report_fact_cards, allowed_fact_ids=referenced_fact_ids),
            "section_fact_map": section_fact_map,
            "output_requirements": {
                "must_keep_single_report": True,
                "technical_appendix_will_be_appended": True,
                "appendix_note": "系统会在正文后自动追加完整技术附录；正文只需在第11节提示读者重点关注哪些技术明细。",
                "writer_style": [
                    "优先解释为什么判断成立、为什么边界停在这里、运维最该先做什么。",
                    "正文只基于 packet 与各节允许引用的 fact cards 写作，不要重新发明新的事实层。",
                    "相近事实要归并叙述，不要把重复通信逐条写成同一句话的改写版。",
                    "不要引入新事实，不要暴露内部实现术语。",
                ],
            },
        }
    )


def _append_polish_brief_line(lines: List[str], label: str, value: Any) -> None:
    text = _polish_input_text(value)
    if text:
        lines.append(f"- {label}：{text}")


def _append_polish_brief_list(lines: List[str], label: str, values: List[Any]) -> None:
    items = _polish_input_list(list(values or []))
    if items:
        lines.append(f"- {label}：{'；'.join(items)}")


def _brief_entry_matches(entry: Dict[str, Any], keyword: str) -> bool:
    text = " ".join(
        [
            _polish_input_text(entry.get("category")),
            _polish_input_text(entry.get("fact")),
            _polish_input_text(entry.get("why_it_matters")),
        ]
    ).lower()
    return keyword.lower() in text


def _brief_find_entry(
    entries: List[Dict[str, Any]],
    *,
    keywords: List[str],
    used_ids: set[str] | None = None,
) -> Dict[str, Any] | None:
    seen = used_ids if used_ids is not None else set()
    for entry in list(entries or []):
        entry_id = str(entry.get("id") or "").strip()
        if entry_id and entry_id in seen:
            continue
        if any(_brief_entry_matches(entry, keyword) for keyword in keywords):
            if entry_id:
                seen.add(entry_id)
            return entry
    return None


def _brief_entry_fact(entry: Dict[str, Any] | None) -> str:
    if not entry:
        return ""
    return _polish_input_text(entry.get("fact"))


def _brief_entry_reason(entry: Dict[str, Any] | None) -> str:
    if not entry:
        return ""
    return _polish_input_text(entry.get("why_it_matters"))


def _brief_entry_limit(entry: Dict[str, Any] | None) -> str:
    if not entry:
        return ""
    return _polish_input_text(entry.get("limitation"))


def _brief_anchor_packets(
    supporting_evidence: List[Dict[str, Any]],
    counterevidence: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    used_ids: set[str] = set()
    anchors: List[Dict[str, Any]] = []
    anchor_specs = [
        ("触发锚点", ["调查触发"]),
        ("持续性锚点", ["连续性支撑"]),
        ("升级锚点", ["风险升级"]),
        ("范围锚点", ["范围确认"]),
    ]
    for label, keywords in anchor_specs:
        entry = _brief_find_entry(supporting_evidence, keywords=keywords, used_ids=used_ids)
        if entry:
            anchors.append({"label": label, "entry": entry, "is_counter": False})
    if counterevidence:
        anchors.append({"label": "反证锚点", "entry": dict(counterevidence[0]), "is_counter": True})
    return anchors


def _brief_story_spine(
    supporting_evidence: List[Dict[str, Any]],
    relationship_findings: Dict[str, Any],
    open_limits: Dict[str, Any],
    report_brief: Dict[str, Any],
) -> List[str]:
    used_ids: set[str] = set()
    trigger = _brief_find_entry(supporting_evidence, keywords=["调查触发"], used_ids=used_ids)
    continuity = _brief_find_entry(supporting_evidence, keywords=["连续性支撑"], used_ids=used_ids)
    escalation = _brief_find_entry(supporting_evidence, keywords=["风险升级"], used_ids=used_ids)
    scope = _brief_find_entry(supporting_evidence, keywords=["范围确认"], used_ids=used_ids)

    steps: List[str] = []
    if trigger:
        steps.append(f"异常起点：{_brief_entry_fact(trigger)}")
    if continuity:
        steps.append(f"持续性确认：{_brief_entry_fact(continuity)}")
    if escalation:
        steps.append(f"风险升级：{_brief_entry_fact(escalation)}")
    if scope:
        steps.append(f"范围扩展：{_brief_entry_fact(scope)}")

    boundary = _polish_input_text(report_brief.get("key_gap"))
    if not boundary:
        boundary = _polish_input_text(relationship_findings.get("relationship_boundary"))
    if not boundary:
        boundary_items = _polish_input_list(list(open_limits.get("boundary_findings") or []), limit=1)
        boundary = boundary_items[0] if boundary_items else ""
    if boundary:
        steps.append(f"交付边界：{boundary}")
    return steps[:5]


def _append_polish_brief_heading(lines: List[str], heading: str) -> None:
    lines.extend(["", heading])


def build_report_polish_brief(polish_input: Dict[str, Any]) -> str:
    if str(polish_input.get("source_mode") or "").strip() == "fact_cards_v2":
        report_header = dict(polish_input.get("report_header") or {})
        packets = dict(polish_input.get("packets") or {})
        verdict_packet = dict(packets.get("verdict_packet") or {})
        scope_packet = dict(packets.get("scope_packet") or {})
        constraint_packet = dict(packets.get("constraint_packet") or {})
        action_packet = dict(packets.get("action_packet") or {})
        fact_catalog = list(polish_input.get("fact_catalog") or [])
        section_fact_map = list(polish_input.get("section_fact_map") or [])

        lines: List[str] = ["# Report Writer Brief", ""]
        lines.append("## Writing Task")
        lines.append("- 目标读者：运维人员与安全运营协同对象。")
        lines.append("- 正文必须只基于下方 packets 与各章节允许引用的 fact cards 写作，不要使用这些材料之外的事实。")
        lines.append("- 正文只负责解释判断、范围和动作；完整技术细节会在正文后自动追加，不要在正文重复 IOC 表、对象表和观测映射表。")
        lines.append("- 如果某节材料不足，请保留标题并用保守表述说明当前证据不足，不得补写。")
        lines.append("- Fact Catalog 会把全部可用事实只列一次；各章节仅围绕 Section Fact Map 中给出的 fact ID 取材。")
        lines.append("- 如果某条 fact 带有“判断作用 / 书写边界”，正文应先解释它为什么改变判断，再交代边界，不要只复述事件发生。")
        lines.append("- 调查锚点、已确认受影响对象、核心外部基础设施是三类不同角色，必须分开表述。")
        lines.append("- 如果当前没有已确认受影响资产，可以写调查锚点和处置焦点，但不要把调查起点改写成已确认影响范围。")

        _append_polish_brief_heading(lines, "## Header Packet")
        _append_polish_brief_line(lines, "事件标题", report_header.get("title"))
        _append_polish_brief_line(lines, "分析窗口", report_header.get("analysis_window"))
        _append_polish_brief_line(lines, "最终结论", report_header.get("final_verdict"))
        _append_polish_brief_line(lines, "严重度", report_header.get("severity"))
        _append_polish_brief_line(lines, "研判把握", report_header.get("confidence"))
        _append_polish_brief_line(lines, "已确认受影响范围", report_header.get("confirmed_scope"))
        _append_polish_brief_line(lines, "一句话结论", report_header.get("one_sentence_summary"))

        _append_polish_brief_heading(lines, "## Verdict Packet")
        _append_polish_brief_line(lines, "结论陈述", verdict_packet.get("conclusion_statement"))

        _append_polish_brief_heading(lines, "## Scope Packet")
        confirmed_entities = list(scope_packet.get("confirmed_entities") or [])
        if confirmed_entities:
            _append_polish_brief_list(lines, "已确认受影响对象", confirmed_entities)
        else:
            _append_polish_brief_line(lines, "已确认受影响对象", "当前尚无已确认受影响资产")
        _append_polish_brief_list(lines, "待确认对象", list(scope_packet.get("candidate_entities") or []))

        _append_polish_brief_heading(lines, "## Constraint Packet")
        _append_polish_brief_line(lines, "边界陈述", constraint_packet.get("boundary_statement"))
        _append_polish_brief_list(lines, "未闭合问题", list(constraint_packet.get("blocking_gaps") or []))
        _append_polish_brief_list(lines, "反证与替代解释", list(constraint_packet.get("counterevidence") or []))

        _append_polish_brief_heading(lines, "## Action Packet")
        _append_polish_brief_list(lines, "立即动作", list(action_packet.get("immediate_actions") or []))
        _append_polish_brief_list(lines, "下一步动作", list(action_packet.get("next_steps") or []))

        _append_polish_brief_heading(lines, "## Fact Catalog")
        for group in fact_catalog:
            lines.append(f"### {group.get('group_title')}")
            facts = list(group.get("facts") or [])
            for fact in facts:
                fact_id = _polish_input_text(fact.get("fact_id"))
                summary_line = _polish_input_text(fact.get("summary_line"))
                reporting_focus = _polish_input_text(fact.get("reporting_focus"))
                boundary_note = _polish_input_text(fact.get("boundary_note"))
                if fact_id and summary_line:
                    line = f"- `{fact_id}`"
                    if reporting_focus:
                        line += f" [{reporting_focus}]"
                    line += f"：{summary_line}"
                    if boundary_note:
                        line += f"；书写边界：{boundary_note}"
                    lines.append(line)

        _append_polish_brief_heading(lines, "## Section Fact Map")
        for section in section_fact_map:
            lines.append(f"### {section.get('section_title')}")
            _append_polish_brief_line(lines, "本节目标", section.get("objective"))
            _append_polish_brief_list(lines, "可引用 packets", list(section.get("packet_refs") or []))
            _append_polish_brief_list(lines, "优先引用事实 ID（按顺序）", list(section.get("allowed_fact_ids") or []))

        _append_polish_brief_heading(lines, "## Writing Priorities")
        lines.append("- 第1、2、4、5、7、8、9节默认写成连续短段落，不要把正文写成 fact card 清单。")
        lines.append("- 调查锚点、已确认受影响对象、待确认对象、背景指标必须分开表述，不能混写。")
        lines.append("- 调查起点资产只写成调查锚点或调查焦点，不写成已确认受影响资产。")
        lines.append("- 核心外部基础设施只写成已确认关联基础设施或关键外联对象，不写成已确认受影响范围。")
        lines.append("- 第8节如果没有已确认受影响对象，使用“当前尚无已确认受影响资产；已观察到的异常行为主要落在调查锚点”这类句式，不要使用任何“影响范围仅限于调查锚点”的变体。")
        lines.append("- 反证只说明为什么它不足以推翻主判断，不要把背景流量写成主结论。")
        return "\n".join(lines).strip() + "\n"

    report_brief = dict(polish_input.get("report_brief") or {})
    evidence_pack = dict(polish_input.get("evidence_pack") or {})
    background = dict(evidence_pack.get("background") or {})
    scope_snapshot = dict(evidence_pack.get("scope_snapshot") or {})
    background_context = dict(evidence_pack.get("background_context") or {})
    relationship_findings = dict(evidence_pack.get("relationship_findings") or {})
    impact_summary = dict(evidence_pack.get("impact_summary") or {})
    open_limits = dict(evidence_pack.get("open_limits") or {})
    supporting_evidence = list(evidence_pack.get("supporting_evidence") or [])
    counterevidence = list(evidence_pack.get("counterevidence") or [])
    anchor_packets = _brief_anchor_packets(supporting_evidence, counterevidence)
    story_spine = _brief_story_spine(supporting_evidence, relationship_findings, open_limits, report_brief)

    lines: List[str] = ["# Report Writer Brief", ""]

    lines.append("## Writing Task")
    lines.append("- 目标读者：运维人员与安全运营协同对象。")
    lines.append("- 正文只负责解释判断、范围和动作；完整技术细节会在正文后自动追加，不要在正文重复 IOC 表、对象表和观测映射表。")
    lines.append("- 正文必须优先回答三个问题：为什么这起告警已经可以按事件交付、当前确认范围到哪里、运维现在最该做什么。")

    _append_polish_brief_heading(lines, "## Judgment Packet")
    _append_polish_brief_line(lines, "事件标题", report_brief.get("title"))
    _append_polish_brief_line(lines, "分析窗口", report_brief.get("analysis_window"))
    _append_polish_brief_line(lines, "最终结论", report_brief.get("final_verdict"))
    _append_polish_brief_line(lines, "严重度", report_brief.get("severity"))
    _append_polish_brief_line(lines, "研判把握", report_brief.get("confidence"))
    _append_polish_brief_line(lines, "一句话结论", report_brief.get("executive_summary"))
    _append_polish_brief_line(lines, "当前最强证据", report_brief.get("strongest_evidence"))
    _append_polish_brief_line(lines, "为什么当前结论成立", report_brief.get("why_current_conclusion"))
    _append_polish_brief_line(lines, "为什么不是相邻状态", report_brief.get("why_not_other_status"))
    _append_polish_brief_line(lines, "本案当前关键缺口", report_brief.get("key_gap"))
    _append_polish_brief_line(lines, "背景提示只能怎么用", background_context.get("limits"))

    _append_polish_brief_heading(lines, "## Narrative Spine")
    for index, step in enumerate(story_spine, start=1):
        lines.append(f"{index}. {step}")

    _append_polish_brief_heading(lines, "## Evidence Anchors")
    for packet in anchor_packets:
        entry = dict(packet.get("entry") or {})
        lines.append(f"### {packet.get('label')}")
        _append_polish_brief_line(lines, "证据类别", entry.get("category"))
        _append_polish_brief_line(lines, "事实", _brief_entry_fact(entry))
        if packet.get("is_counter"):
            _append_polish_brief_line(lines, "正文要表达的判断", _brief_entry_reason(entry))
        else:
            _append_polish_brief_line(lines, "正文要表达的判断", _brief_entry_reason(entry))
        _append_polish_brief_line(lines, "边界", _brief_entry_limit(entry))

    _append_polish_brief_heading(lines, "## Scope Packet")
    _append_polish_brief_line(lines, "种子告警", background.get("seed_alert"))
    _append_polish_brief_line(lines, "上游背景", background.get("upstream_context"))
    _append_polish_brief_line(lines, "本次调查范围", scope_snapshot.get("investigation_scope"))
    _append_polish_brief_line(lines, "主假设", scope_snapshot.get("primary_hypothesis"))
    _append_polish_brief_line(lines, "备选解释", scope_snapshot.get("alternative_hypothesis"))
    _append_polish_brief_line(lines, "已确认影响范围", report_brief.get("confirmed_scope"))
    _append_polish_brief_line(lines, "疑似影响范围", report_brief.get("suspected_scope"))
    _append_polish_brief_line(lines, "已确认资产", scope_snapshot.get("confirmed_assets"))
    _append_polish_brief_line(lines, "待确认关联资产", scope_snapshot.get("related_assets"))
    _append_polish_brief_line(lines, "核心外部基础设施", scope_snapshot.get("core_external_indicators"))
    _append_polish_brief_line(lines, "关键指示物", scope_snapshot.get("key_indicators"))
    _append_polish_brief_line(lines, "不要直接写成已确认范围的对象", scope_snapshot.get("out_of_scope"))
    _append_polish_brief_line(lines, "当前关联边界", relationship_findings.get("relationship_boundary"))
    _append_polish_brief_line(lines, "未独立验证的对象", relationship_findings.get("unverified_objects"))
    _append_polish_brief_list(lines, "边界保留事项", list(open_limits.get("boundary_findings") or []))

    _append_polish_brief_heading(lines, "## Ops Packet")
    _append_polish_brief_line(lines, "已确认影响", impact_summary.get("confirmed_impact"))
    _append_polish_brief_line(lines, "仍需核实的影响", impact_summary.get("suspected_impact"))
    _append_polish_brief_line(lines, "时间范围", impact_summary.get("time_range"))
    _append_polish_brief_line(lines, "资产范围", impact_summary.get("asset_range"))
    _append_polish_brief_line(lines, "外部基础设施范围", impact_summary.get("external_range"))
    _append_polish_brief_line(lines, "当前攻击阶段", impact_summary.get("attack_stage"))
    _append_polish_brief_line(lines, "本次调查关注点", background.get("investigation_focus"))
    _append_polish_brief_list(lines, "建议立即动作", list(report_brief.get("immediate_actions") or []))
    _append_polish_brief_list(lines, "短期排查动作", list(report_brief.get("short_term_actions") or []))
    _append_polish_brief_list(lines, "持续监控或复核动作", list(report_brief.get("follow_up_actions") or []))
    _append_polish_brief_list(lines, "下一轮最值得补的证据", list(open_limits.get("next_best_evidence") or []))

    _append_polish_brief_heading(lines, "## Writing Priorities")
    lines.append("- 第 1、2、4、7、8、9、10 节优先写成短段落，不要主要依赖 bullet 罗列。")
    lines.append("- 正文必须明确点名核心外部基础设施，并说清它当前是核心可疑基础设施还是仅作为背景指标出现。")
    lines.append("- 反证要写出“为什么它不足以推翻主结论”，不能只写存在维护窗口。")
    lines.append("- 影响分析要写清已经确认影响到哪里，以及为什么还不能把边界外对象写成已确认受影响。")

    return "\n".join(lines).strip() + "\n"


def _compose_polished_report(body_markdown: str, appendix_markdown: str) -> str:
    body = str(body_markdown or "").strip()
    appendix = str(appendix_markdown or "").strip()
    if not body:
        return ""
    if not appendix:
        return body + "\n"
    if "事件调查技术附录" in body:
        return body + ("\n" if body.endswith("\n") else "\n")
    return f"{body}\n\n---\n\n{appendix}\n"


def _report_polish_has_hard_fail(validation: Dict[str, Any]) -> bool:
    status = _polish_input_text(validation.get("status"))
    if status == "hard_fail":
        return True
    issue_counts = dict(validation.get("issue_counts") or {})
    try:
        return int(issue_counts.get("hard_fail") or 0) > 0
    except (TypeError, ValueError):
        return False


def _format_report_polish_issues(validation: Dict[str, Any], *, limit: int = 8) -> str:
    issues = [dict(item) for item in list(validation.get("issues") or []) if isinstance(item, dict)]
    if not issues:
        return "- 当前没有可修订的问题。"

    lines: List[str] = []
    for issue in issues[:limit]:
        code = _polish_input_text(issue.get("code")) or "unknown_issue"
        section = _polish_input_text(issue.get("section")) or "未知章节"
        message = _polish_input_text(issue.get("message"))
        sentence = _polish_input_text(issue.get("sentence"))
        evidence = _dedupe_text(list(issue.get("evidence") or []))

        line = f"- [{code}] {section}：{message}"
        if evidence:
            line += f"；涉及：{' / '.join(evidence)}"
        if sentence:
            line += f"；原句：{sentence}"
        lines.append(line)

    remaining = len(issues) - len(lines)
    if remaining > 0:
        lines.append(f"- 其余 {remaining} 条问题也需要一并修正。")
    return "\n".join(lines)


SECTION_HEADING_RE = re.compile(r"^(#{1,3})\s+(.+?)\s*$")


def _body_only_markdown(markdown: str) -> str:
    text = str(markdown or "")
    if "\n---\n" in text:
        text = text.split("\n---\n", 1)[0]
    appendix_marker = "## 事件调查技术附录"
    if appendix_marker in text:
        text = text.split(appendix_marker, 1)[0]
    return text.strip()


def _split_markdown_sections(markdown: str) -> List[Dict[str, Any]]:
    sections: List[Dict[str, Any]] = []
    current: Dict[str, Any] | None = None
    for raw_line in str(markdown or "").splitlines():
        line = raw_line.rstrip()
        match = SECTION_HEADING_RE.match(line)
        if match and match.group(2):
            if current is not None:
                current["text"] = "\n".join(current.pop("lines", [])).strip()
                sections.append(current)
            current = {
                "level": len(match.group(1)),
                "title": _polish_input_text(match.group(2)),
                "lines": [],
            }
            continue
        if current is not None:
            current.setdefault("lines", []).append(line)
    if current is not None:
        current["text"] = "\n".join(current.pop("lines", [])).strip()
        sections.append(current)
    return sections


def _section_to_markdown(section: Dict[str, Any]) -> str:
    level = int(section.get("level") or 2)
    title = _polish_input_text(section.get("title"))
    text = str(section.get("text") or "").strip()
    heading = f"{'#' * max(1, level)} {title}".rstrip()
    if not text:
        return heading
    return f"{heading}\n{text}"


def _sections_to_markdown(sections: List[Dict[str, Any]]) -> str:
    return "\n\n".join(_section_to_markdown(section) for section in sections if _polish_input_text(section.get("title"))).strip()


def _validation_section_titles(validation: Dict[str, Any]) -> List[str]:
    titles: List[str] = []
    for issue in list(validation.get("issues") or []):
        if not isinstance(issue, dict):
            continue
        title = _polish_input_text(issue.get("section"))
        if title and title not in titles:
            titles.append(title)
    return titles


def _format_report_polish_section_issues(validation: Dict[str, Any], section_title: str, *, limit: int = 6) -> str:
    issues = [
        dict(item)
        for item in list(validation.get("issues") or [])
        if isinstance(item, dict) and _polish_input_text(item.get("section")) == section_title
    ]
    if not issues:
        return "- 当前没有需要修正的该节问题。"
    return _format_report_polish_issues({"issues": issues}, limit=limit)


def _fact_catalog_entry_index(polish_input: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    index: Dict[str, Dict[str, Any]] = {}
    for group in list(polish_input.get("fact_catalog") or []):
        if not isinstance(group, dict):
            continue
        for fact in list(group.get("facts") or []):
            if not isinstance(fact, dict):
                continue
            fact_id = _polish_input_text(fact.get("fact_id"))
            if fact_id:
                index[fact_id] = dict(fact)
    return index


def _append_section_packet_lines(lines: List[str], packet_name: str, packet: Dict[str, Any]) -> None:
    label_map = {
        "verdict_packet": "Verdict Packet",
        "scope_packet": "Scope Packet",
        "constraint_packet": "Constraint Packet",
        "action_packet": "Action Packet",
    }
    visible_items = []
    for key, value in packet.items():
        if key in {"supporting_fact_ids", "schema_version"}:
            continue
        if isinstance(value, list):
            cleaned = _polish_input_list(list(value or []))
            if cleaned:
                visible_items.append((key, "；".join(cleaned)))
        else:
            cleaned = _polish_input_text(value)
            if cleaned:
                visible_items.append((key, cleaned))
    if not visible_items:
        return
    lines.append(f"## {label_map.get(packet_name, packet_name)}")
    for key, value in visible_items:
        lines.append(f"- {key}：{value}")
    lines.append("")


def _build_report_polish_section_brief(polish_input: Dict[str, Any], section_title: str) -> str:
    section_map = [
        dict(item)
        for item in list(polish_input.get("section_fact_map") or [])
        if isinstance(item, dict) and _polish_input_text(item.get("section_title")) == section_title
    ]
    if not section_map:
        return ""
    section = section_map[0]
    report_header = dict(polish_input.get("report_header") or {})
    packets = dict(polish_input.get("packets") or {})
    fact_index = _fact_catalog_entry_index(polish_input)

    lines: List[str] = [
        "# Section Writer Brief",
        "",
        "## Repair Task",
        f"- 目标章节：{section_title}",
        f"- 本节目标：{_polish_input_text(section.get('objective'))}",
        "- 你只能输出这一节，不要输出其他章节。",
        "- 必须保留该节标题，并且正文只能基于下方 packet 与 allowed facts。",
        "- 若信息不足，请保守表述，不得补写新事实。",
        "",
        "## Header Context",
    ]
    for key in ["title", "analysis_window", "final_verdict", "severity", "confidence", "confirmed_scope", "one_sentence_summary"]:
        value = _polish_input_text(report_header.get(key))
        if value:
            lines.append(f"- {key}：{value}")
    lines.append("")

    for packet_name in list(section.get("packet_refs") or []):
        packet = dict(packets.get(packet_name) or {})
        _append_section_packet_lines(lines, packet_name, packet)

    lines.append("## Allowed Facts")
    for fact_id in list(section.get("allowed_fact_ids") or []):
        fact = dict(fact_index.get(_polish_input_text(fact_id)) or {})
        if not fact:
            continue
        summary_line = _polish_input_text(fact.get("summary_line"))
        reporting_focus = _polish_input_text(fact.get("reporting_focus"))
        boundary_note = _polish_input_text(fact.get("boundary_note"))
        line = f"- `{fact_id}`"
        if reporting_focus:
            line += f" [{reporting_focus}]"
        if summary_line:
            line += f"：{summary_line}"
        if boundary_note:
            line += f"；书写边界：{boundary_note}"
        lines.append(line)
    lines.append("")
    return "\n".join(lines).strip() + "\n"


def _normalize_single_section_response(raw_markdown: str, *, section_title: str, default_level: int) -> Dict[str, Any] | None:
    body = _body_only_markdown(raw_markdown)
    sections = _split_markdown_sections(body)
    for section in sections:
        if _polish_input_text(section.get("title")) == section_title:
            return {
                "level": int(section.get("level") or default_level),
                "title": section_title,
                "text": str(section.get("text") or "").strip(),
            }
    text = body.strip()
    if not text:
        return None
    return {
        "level": default_level,
        "title": section_title,
        "text": text,
    }


def _repair_polished_sections(
    *,
    content: str,
    deterministic: str,
    validation: Dict[str, Any],
    report_writer: Any,
    section_repair_prompt: Any,
    polish_input: Dict[str, Any],
    report_fact_cards: Dict[str, Any],
) -> Tuple[str, Dict[str, Any], str]:
    body = _body_only_markdown(content)
    sections = _split_markdown_sections(body)
    if not sections:
        return content, validation, ""

    section_index = {
        _polish_input_text(section.get("title")): idx
        for idx, section in enumerate(sections)
        if _polish_input_text(section.get("title"))
    }
    if not section_index:
        return content, validation, ""

    deterministic_sections = _split_markdown_sections(_body_only_markdown(deterministic))
    deterministic_index = {
        _polish_input_text(section.get("title")): dict(section)
        for section in deterministic_sections
        if _polish_input_text(section.get("title"))
    }

    repaired_titles: List[str] = []
    fallback_titles: List[str] = []
    failing_titles = [title for title in _validation_section_titles(validation) if title in section_index]

    for section_title in failing_titles:
        section_brief = _build_report_polish_section_brief(polish_input, section_title)
        if not section_brief:
            continue
        current_section = dict(sections[section_index[section_title]])
        validation_notes = _format_report_polish_section_issues(validation, section_title)
        response = _invoke_report_writer_with_retry(
            report_writer,
            section_repair_prompt.format_messages(
                section_title=section_title,
                section_brief=section_brief,
                section_markdown=_section_to_markdown(current_section),
                validation_notes=validation_notes,
            ),
            role="report_polish_section_repair",
            extra={"section_title": section_title},
        )
        repaired_section = _normalize_single_section_response(
            str(getattr(response, "content", "") or "").strip(),
            section_title=section_title,
            default_level=int(current_section.get("level") or 2),
        )
        if repaired_section is None:
            continue
        sections[section_index[section_title]] = repaired_section
        repaired_titles.append(section_title)

    updated_content = _sections_to_markdown(sections)
    updated_validation = validate_report_polish(updated_content, report_fact_cards)

    if _report_polish_has_hard_fail(updated_validation):
        for section_title in [title for title in _validation_section_titles(updated_validation) if title in section_index]:
            deterministic_section = dict(deterministic_index.get(section_title) or {})
            if not deterministic_section:
                continue
            current_level = int(sections[section_index[section_title]].get("level") or deterministic_section.get("level") or 2)
            deterministic_section["level"] = current_level
            sections[section_index[section_title]] = deterministic_section
            if section_title not in fallback_titles:
                fallback_titles.append(section_title)
        updated_content = _sections_to_markdown(sections)
        updated_validation = validate_report_polish(updated_content, report_fact_cards)

    notes: List[str] = []
    if repaired_titles:
        notes.append("section_repair:" + ",".join(repaired_titles))
    if fallback_titles:
        notes.append("section_fallback:" + ",".join(fallback_titles))
    return updated_content, updated_validation, " | ".join(notes)


def _is_transient_report_polish_error(exc: Exception) -> bool:
    text = f"{type(exc).__name__}: {exc}".lower()
    transient_markers = (
        "apiconnectionerror",
        "connection error",
        "connection reset",
        "timed out",
        "timeout",
        "temporarily unavailable",
        "server disconnected",
        "rate limit",
        "429",
        "502",
        "503",
        "504",
    )
    return any(marker in text for marker in transient_markers)


def _invoke_report_writer_with_retry(
    report_writer: Any,
    messages: Any,
    *,
    max_attempts: int = 3,
    role: str = "report_polish",
    extra: Dict[str, Any] | None = None,
) -> Any:
    last_exc: Exception | None = None
    for attempt in range(1, max_attempts + 1):
        try:
            return invoke_llm_with_trace(
                report_writer,
                messages,
                role=role,
                extra={
                    **dict(extra or {}),
                    "attempt": attempt,
                    "max_attempts": max_attempts,
                },
            )
        except Exception as exc:
            last_exc = exc
            if attempt >= max_attempts or not _is_transient_report_polish_error(exc):
                raise
            time.sleep(float(attempt))
    if last_exc is not None:
        raise last_exc
    raise RuntimeError("report_writer_invoke_failed_without_exception")


def build_incident_report_outline(incident: Dict[str, Any]) -> Dict[str, Any]:
    evidence_store = incident.get("evidence_store") or {}
    if not evidence_store:
        evidence_store = build_evidence_store(incident)
    reviewer_input = incident.get("reviewer_input") or build_reviewer_input(incident, evidence_store)
    delivery_decision = incident.get("delivery_decision") or build_delivery_decision(evidence_store, reviewer_input)
    return build_report_outline_from_artifacts(
        evidence_store=evidence_store,
        reviewer_input=reviewer_input,
        delivery_decision=delivery_decision,
    )


def _resolve_report_outline(incident: Dict[str, Any], outline: Dict[str, Any] | None = None) -> Dict[str, Any]:
    if outline:
        return dict(outline)
    return build_incident_report_outline(incident)


def render_incident_report_appendix(incident: Dict[str, Any], *, outline: Dict[str, Any] | None = None) -> str:
    outline = _resolve_report_outline(incident, outline)
    appendix_contract = outline.get("appendix_contract") or outline.get("appendix") or {}
    return render_appendix_report(appendix_contract)


def render_incident_report(incident: Dict[str, Any], *, outline: Dict[str, Any] | None = None) -> str:
    outline = _resolve_report_outline(incident, outline)
    ops_report_contract = outline.get("ops_report_contract") or outline.get("main_report_contract") or {}
    return render_ops_report(ops_report_contract)


def render_incident_report_with_llm(
    incident: Dict[str, Any],
    llm: Any = None,
    *,
    outline: Dict[str, Any] | None = None,
    use_report_agent_materials: bool | None = None,
) -> Dict[str, Any]:
    resolved_outline = _resolve_report_outline(incident, outline)
    deterministic = render_incident_report(incident, outline=resolved_outline)
    appendix = render_incident_report_appendix(incident, outline=resolved_outline)
    outline = resolved_outline
    evidence_store = incident.get("evidence_store") or build_evidence_store(incident)
    reviewer_input = incident.get("reviewer_input") or build_reviewer_input(incident, evidence_store)
    delivery_decision = incident.get("delivery_decision") or build_delivery_decision(evidence_store, reviewer_input)
    report_fact_cards = build_report_fact_cards(evidence_store, delivery_decision)
    polish_input = build_report_polish_input_v2(outline, report_fact_cards)
    polish_brief = build_report_polish_brief(polish_input)
    report_source_bundle = build_report_source_bundle(
        incident,
        evidence_store=evidence_store,
        delivery_decision=delivery_decision,
        outline=outline,
    )
    report_writer_materials: Dict[str, Any] = {}
    report_material_loop_trace: Dict[str, Any] = {}
    report_agent_error = ""
    if use_report_agent_materials is None:
        report_agent_flag = str(os.getenv("INCIDENT_AGENT_USE_REPORT_AGENT_MATERIALS") or "").strip().lower()
        use_report_agent_materials = report_agent_flag not in {"0", "false", "no", "off"}

    def _with_report_agent_artifacts(payload: Dict[str, Any]) -> Dict[str, Any]:
        payload = dict(payload)
        payload.update(
            {
                "report_source_bundle": report_source_bundle,
                "report_writer_materials": report_writer_materials,
                "report_material_loop_trace": report_material_loop_trace,
                "report_agent_error": report_agent_error,
                "report_agent_materials_enabled": bool(use_report_agent_materials),
            }
        )
        return payload

    skipped_validation = {
        "schema_version": "report-polish-validation-v1",
        "applied": False,
        "status": "skipped_no_polished_report",
        "summary": "当前没有生成 polished 正文，因此跳过后置校验。",
        "issue_counts": {"hard_fail": 0, "soft_warn": 0},
        "issues": [],
    }
    if llm is None:
        return _with_report_agent_artifacts({
            "report_markdown": deterministic,
            "report_polished_markdown": "",
            "report_appendix_markdown": appendix,
            "report_fact_cards": report_fact_cards,
            "report_polish_input": polish_input,
            "report_polish_brief": polish_brief,
            "report_polish_validation": skipped_validation,
            "report_polish_error": "",
        })

    if use_report_agent_materials:
        try:
            report_writer_materials, report_material_loop_trace = run_report_material_loop(report_source_bundle, llm)
            loop_status = str(report_material_loop_trace.get("status") or "")
            loop_validation = report_material_loop_trace.get("validation") or {}
            if loop_validation.get("ok"):
                body = render_polished_body_from_materials(llm, report_writer_materials)
                if body.strip():
                    validation = validate_report_polish(body, report_fact_cards)
                    return _with_report_agent_artifacts({
                        "report_markdown": deterministic,
                        "report_polished_markdown": _compose_polished_report(body, appendix),
                        "report_appendix_markdown": appendix,
                        "report_fact_cards": report_fact_cards,
                        "report_polish_input": polish_input,
                        "report_polish_brief": polish_brief,
                        "report_polish_validation": validation,
                        "report_polish_error": "",
                    })
                report_agent_error = "report_agent_writer_empty_response"
            else:
                report_agent_error = f"report_material_loop_invalid:{loop_status or 'unknown'}"
        except Exception as exc:
            report_agent_error = f"{type(exc).__name__}: {exc}"

    try:
        from langchain_core.prompts import ChatPromptTemplate

        system_prompt = (
            "你是网络安全事件分析师。请仅基于 report_writer_brief 生成一份面向运维人员和安全运营协同对象的中文 Markdown 报告。\n"
            "技术附录会由系统在正文后自动追加；你现在只需要写正文，不要把 IOC 表、对象表、观测引用表整段重复写进正文。\n"
            "正文必须像分析师写给运维的调查报告，优先解释判断为什么成立、哪些证据最关键、哪些边界仍未闭合，而不是按 JSON 键名逐条转述。\n"
            "如果 brief 中某条 fact 带有“判断作用”或“书写边界”，应吸收这些分析含义，不要只重复事实句本身。\n"
            "正文以分析叙述为主，尽量不用表格；全文目标约 1800 到 3000 中文字，避免为了压缩篇幅而把章节写成只有标题没有信息的空壳。\n"
            "每一节只保留最关键的判断、依据和边界；技术细目统一留给系统自动追加的附录。\n"
            "绝不引入输入中不存在的新 IOC、新结论、新阶段或新资产。\n"
            "如果 analysis_conclusion 与 event_conclusion 不一致，只能使用读者能理解的外部表述，不要写内部方向、交付门槛、readiness、selector、reviewer 等内部术语。\n"
            "不要暴露 tool 名、source_type、internal_digest、observation_id、证据编号、精确置信度分数、工作流细节，也不要直接使用 pivot、枢纽 这类内部工作词。\n"
            "如果 brief 本身含有 pivot、枢纽、readiness、reviewer、selector 这类内部词，也必须改写成读者能理解的外部表达，不能原样回写。\n"
            "除非直接影响处置动作，否则不要在主报告中展开 JA3、JA4、DNS answers 等过细技术字段；这些内容应留在附录。\n"
            "如果时间线或事件摘要里有英文，请改写成自然的中文运维表述。\n"
            "如果 brief 里的一句话结论、已确认范围或动作建议把不同角色的对象并列写在一起，你必须先按对象角色重组后再写，不能照抄原句。\n"
            "这里的“已确认范围”专指已确认受影响范围，不包括仅作为调查锚点、调查焦点或外部基础设施出现的对象。\n"
            "凡是域名、IP、资产名、内网地址、时间这类精确实体，一律逐字沿用 brief 中已有写法，不要缩写、改写、补字、漏字或替换字符。\n"
            "当规则冲突时，优先级如下：1. 不新增事实；2. 对象角色规则；3. 固定章节结构与固定枚举；4. 各章节写作任务；5. 风格与篇幅要求。\n"
            "最终只返回 Markdown 正文，不要返回 JSON、额外说明或实现解释。\n"
        )

        writer_prompt = (
            "请严格使用以下 Markdown 标题模板，不得改名、增删或调整标题层级：\n"
            "# 首页摘要\n"
            "## 1. 事件背景与已知线索\n"
            "## 2. 范围界定与调查假设\n"
            "## 3. 对象覆盖策略与关键实体\n"
            "## 4. 事件机制分解\n"
            "## 5. 关键证据与异常事实\n"
            "## 6. 时序特征与行为模式\n"
            "## 7. 传播与关联分析\n"
            "## 8. 影响分析\n"
            "## 9. 证据链摘要与观测缺口\n"
            "## 10. 结论与后续建议\n"
            "## 11. 技术附录提示\n"
            "\n"
            "首页摘要必须固定为以下 6 行，每行都保留且按顺序输出：\n"
            "- **结论**：\n"
            "- **严重度**：\n"
            "- **研判把握**：\n"
            "- **已确认范围**：\n"
            "- **一句话结论**：\n"
            "- **立即动作**：\n"
            "首页摘要视为格式校验点：不要额外添加报告总标题、案例标题、导语、空行说明或第 7 行摘要。\n"
            "其中“已确认范围”这一行专指已确认受影响范围；如果当前只有调查锚点而没有已确认受影响资产，必须如实写成“当前尚无已确认受影响资产”或同等保守表述。\n"
            "\n"
            "固定枚举要求：\n"
            "1. 严重度只能写：高 / 中 / 低。\n"
            "2. 研判把握只能写：高 / 中 / 低。\n"
            "3. 严重度和研判把握必须严格等于枚举值本身，不得写成 高危 / 中危 / 低危 / 较高 / 中高 / 偏高 这类带修饰或带后缀的变体。\n"
            "4. 正文中描述对象状态时，优先使用：已确认 / 待确认 / 背景指标 这三类标准表述，不要写成 中高、较高、基本确认、偏可疑 这类漂移说法。\n"
            "\n"
            "缺信息时的保守写法：\n"
            "1. 若 brief 未提供支撑某节所需的信息，请保留该节标题，并用 1 到 2 句说明“当前证据不足以支持进一步确认”或“当前仅能保守收敛到以下范围”，不得为了补齐章节而补写新事实。\n"
            "2. 若不存在足够反证，只说明“目前未见足以推翻主判断的反向证据”，不要为了满足结构制造反证段落。\n"
            "3. 若 brief 同时包含已确认受影响对象与候选对象，必须先写已确认范围，再单独写待确认对象，禁止混写。\n"
            "4. 若 brief 中直接出现内部工作词，必须先改写成读者向表达再落文；例如把内部扩线话术改写为“围绕当前关键关联指标继续核查”，而不是保留原词。\n"
            "\n"
            "对象角色规则：\n"
            "1. 调查锚点或调查起点资产，只能写成调查锚点、调查焦点或当前处置重点，不能直接写成已确认受影响范围。\n"
            "2. 已确认受影响对象，才可以写进已确认范围、已确认影响或确认传播范围。\n"
            "3. 核心外部基础设施或外部基础设施范围，只能写进外联异常判断、边界封禁或出口侧排查动作。\n"
            "4. 关联内部地址、横向目标、内网 IP，只能写进横向移动、内网核查或主机侧排查动作，不能写成需要边界封禁的外部基础设施。\n"
            "5. 待确认对象、候选对象、背景指标，必须和已确认对象分开表述，不能并入已确认范围。\n"
            "6. 如果同一节里同时出现外部基础设施和内部横向目标，必须明确说明二者在事件链中的角色不同。\n"
            "7. 如果 brief 中明确给出了核心外部基础设施，正文必须点名这些域名或 IP，并说明它们为什么被视为当前事件链的核心可疑基础设施，而不只是普通背景流量。\n"
            "\n"
            "各章节的写作任务如下：\n"
            "首页摘要：只放结论、严重度、把握度、已确认范围、一句话结论和立即动作，不要塞附录型对象清单。\n"
            "第1节：说明这起事件最初为什么进入调查，初始异常是什么，核心外部基础设施是什么。\n"
            "第2节：说明本轮调查试图回答什么问题，当前结论覆盖到哪里，不覆盖到哪里；若边界未闭合，要明确写出保守边界。\n"
            "第3节：只写真正影响判断的关键对象，明确区分调查锚点、已确认受影响对象、待确认对象、核心外部基础设施和背景指标。\n"
            "第4节：把事件写成因果链，突出从网络异常到主机执行再到范围扩展的推进关系，不要逐条重放全部时间点。\n"
            "第5节：只选最关键的 3 到 4 组证据，按“事实 -> 为什么它改变判断 -> 它的边界”来写；优先覆盖异常起点、持续复现、主机或横向升级、反证不足这几类内容。\n"
            "第6节：总结时序模式，只保留 3 到 4 个决定性时间节点，并写清这些节点对判断意味着什么。\n"
            "第7节：说明传播和关联是如何被确认的，哪些扩线结果仍只是候选，为什么它们暂时不能并入主范围；若目标仍待确认，只能写成“出现关联命中”或“需要继续核实”，不能直接写成“已确认扩散到该资产”。\n"
            "第8节：说明已确认受影响范围、已确认异常行为和待确认影响之间的区别；如果当前没有已确认受影响对象，必须使用“当前尚无已确认受影响资产；已观察到的异常行为主要落在调查锚点”这类句式，不要使用任何“影响范围仅限于调查锚点”的变体。\n"
            "第9节：明确指出当前还能做出的判断上限，以及剩余缺口限制了哪些更强结论，但不要把缺口写成否定当前主结论。\n"
            "第10节：动作建议必须分清优先级，并尽量回扣前文证据或边界判断；只分成“立即处置 / 短期核查 / 持续复核”三组，不要扩成更细的 checklist。\n"
            "第11节：只提示读者附录里能看到什么技术明细，不要在这一节重复附录内容。\n"
            "\n"
            "成文形式要求：\n"
            "1. 第1、2、4、5、7、8、9节默认写成连续短段落，每节 2 到 5 句，不要写成编号清单。\n"
            "2. 第3节可以用少量项目符号，但更推荐用短段落把对象按角色分组解释清楚。\n"
            "3. 第6节允许按时间顺序列 3 到 4 个关键节点，但每个节点都要带出它对判断的意义。\n"
            "4. 第10节使用 3 个分组项目符号即可，每组 1 到 2 句分析性建议，不要写成机械 checklist。\n"
            "\n"
            "务必避免以下坏写法：\n"
            "- 把内部横向目标和外部可疑基础设施混写成同一类对象。\n"
            "- 同一句话在多个章节重复出现，只是换个标题。\n"
            "- 只说“异常仍在持续”而不说明为什么它重要。\n"
            "- 只写存在维护窗口或背景流量，但不解释为什么这些反证不足以推翻主结论。\n"
            "- 把疑似对象直接写成已确认受影响范围。\n"
            "- 在没有已确认受影响对象时，写“当前影响范围仅限于该资产”“当前的影响范围仅限于调查锚点的异常行为”等同类表述。\n"
            "- 把待确认关联资产写成已确认传播终点，例如“已确认异常从 A 扩散到了 B”。\n"
            "- 直接照抄 brief 里的动作句或一句话结论，导致对象角色混乱。\n"
            "- 把附录型对象清单改写成正文枚举，导致主体段落失去分析性。\n"
        )

        prompt = ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    system_prompt,
                ),
                (
                    "system",
                    writer_prompt,
                ),
                ("user", "仅基于以下 report_writer_brief 生成正文，不要使用 brief 之外的事实：\n{report_polish_brief}"),
            ]
        )
        repair_prompt = ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    system_prompt,
                ),
                (
                    "system",
                    writer_prompt,
                ),
                (
                    "system",
                    "你现在处于正文修订阶段。你会收到同一份 report_writer_brief、一版正文草稿，以及 validator 指出的事实漂移问题。"
                    "请在保持原有章节结构、细节密度和主体分析判断的前提下，做最小必要修订，修掉所有问题。"
                    "默认把当前草稿当作基线，未被 validator 点中的句子和段落尽量原样保留；不要为了修一个词而整段重写。"
                    "如果问题只是域名、IP、资产名、内网地址、时间、对象角色或确认范围表述漂移，优先只修对应句子里的问题片段，不要改写无关句子。"
                    "不要删除整节，不要把正文退化成 fact 清单，也不要为了求稳而压缩已经存在的关键细节。"
                    "修订后的正文应尽量保留草稿里已经成立的分析性叙述，而不是重新生成一版更泛化的报告。"
                    "凡是域名、IP、资产名、内网地址、时间这类精确实体，必须逐字使用 brief 中已有写法。"
                    "最终只返回修订后的完整 Markdown 正文。",
                ),
                (
                    "user",
                    "report_writer_brief：\n{report_polish_brief}\n\n当前正文草稿：\n{draft_markdown}\n\nvalidator 问题：\n{validation_notes}",
                ),
            ]
        )
        section_repair_prompt = ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    system_prompt,
                ),
                (
                    "system",
                    "你现在只修复单个章节。你会收到该章节的 section_writer_brief、当前章节草稿，以及 validator 指出的该节问题。"
                    "你只能输出这一个章节，必须保留原章节标题，不要输出其他章节。"
                    "修订时优先做最小必要修改，未被点中的句子尽量保留。"
                    "如果 validator 问题只涉及时间、IP、域名、资产名、对象状态或某个事件句，就只修对应句子，不要重写整节。"
                    "如果材料不足，请在该节内部用保守表述承认边界，不得补写新事实。"
                    "最终只返回该章节的 Markdown。",
                ),
                (
                    "user",
                    "section_writer_brief：\n{section_brief}\n\n当前章节草稿：\n{section_markdown}\n\nvalidator 问题：\n{validation_notes}",
                ),
            ]
        )
        report_writer = llm.bind(max_tokens=2400) if hasattr(llm, "bind") else llm
        last_error = "empty_response"
        last_validation = skipped_validation
        last_content = ""
        for attempt in range(1, 3):
            try:
                response = _invoke_report_writer_with_retry(
                    report_writer,
                    prompt.format_messages(report_polish_brief=polish_brief),
                    role="report_polish_initial",
                )
                content = str(getattr(response, "content", "") or "").strip()
                if content:
                    validation = validate_report_polish(content, report_fact_cards)
                    final_content = content
                    final_validation = validation
                    last_content = final_content
                    last_validation = final_validation

                    if _report_polish_has_hard_fail(validation):
                        repair_notes = _format_report_polish_issues(validation)
                        repair_response = _invoke_report_writer_with_retry(
                            report_writer,
                            repair_prompt.format_messages(
                                report_polish_brief=polish_brief,
                                draft_markdown=content,
                                validation_notes=repair_notes,
                            ),
                            role="report_polish_full_repair",
                        )
                        repaired_content = str(getattr(repair_response, "content", "") or "").strip()
                        if repaired_content:
                            repaired_validation = validate_report_polish(repaired_content, report_fact_cards)
                            final_content = repaired_content
                            final_validation = repaired_validation
                        else:
                            last_error = f"attempt_{attempt}:repair_empty_response"

                    if _report_polish_has_hard_fail(final_validation):
                        section_repaired_content, section_repaired_validation, section_repair_note = _repair_polished_sections(
                            content=final_content,
                            deterministic=deterministic,
                            validation=final_validation,
                            report_writer=report_writer,
                            section_repair_prompt=section_repair_prompt,
                            polish_input=polish_input,
                            report_fact_cards=report_fact_cards,
                        )
                        final_content = section_repaired_content
                        final_validation = section_repaired_validation
                        if section_repair_note:
                            last_error = f"attempt_{attempt}:{section_repair_note}"

                    last_content = final_content
                    last_validation = final_validation
                    if _report_polish_has_hard_fail(final_validation):
                        last_error = f"attempt_{attempt}:validation_hard_fail:{_polish_input_text(final_validation.get('summary'))}"
                        continue

                    polished_report = _compose_polished_report(final_content, appendix)
                    return _with_report_agent_artifacts({
                        "report_markdown": deterministic,
                        "report_polished_markdown": polished_report,
                        "report_appendix_markdown": appendix,
                        "report_fact_cards": report_fact_cards,
                        "report_polish_input": polish_input,
                        "report_polish_brief": polish_brief,
                        "report_polish_validation": final_validation,
                        "report_polish_error": "",
                    })
                last_error = f"attempt_{attempt}:empty_response"
            except Exception as exc:
                last_error = f"attempt_{attempt}:{type(exc).__name__}: {exc}"
        if last_content:
            if _report_polish_has_hard_fail(last_validation):
                return _with_report_agent_artifacts({
                    "report_markdown": deterministic,
                    "report_polished_markdown": "",
                    "report_appendix_markdown": appendix,
                    "report_fact_cards": report_fact_cards,
                    "report_polish_input": polish_input,
                    "report_polish_brief": polish_brief,
                    "report_polish_validation": last_validation,
                    "report_polish_error": last_error or "validation_hard_fail",
                })
            return _with_report_agent_artifacts({
                "report_markdown": deterministic,
                "report_polished_markdown": _compose_polished_report(last_content, appendix),
                "report_appendix_markdown": appendix,
                "report_fact_cards": report_fact_cards,
                "report_polish_input": polish_input,
                "report_polish_brief": polish_brief,
                "report_polish_validation": last_validation,
                "report_polish_error": last_error,
            })
        return _with_report_agent_artifacts({
            "report_markdown": deterministic,
            "report_polished_markdown": "",
            "report_appendix_markdown": appendix,
            "report_fact_cards": report_fact_cards,
            "report_polish_input": polish_input,
            "report_polish_brief": polish_brief,
            "report_polish_validation": skipped_validation,
            "report_polish_error": last_error,
        })
    except Exception as exc:
        return _with_report_agent_artifacts({
            "report_markdown": deterministic,
            "report_polished_markdown": "",
            "report_appendix_markdown": appendix,
            "report_fact_cards": report_fact_cards,
            "report_polish_input": polish_input,
            "report_polish_brief": polish_brief,
            "report_polish_validation": skipped_validation,
            "report_polish_error": f"{type(exc).__name__}: {exc}",
        })
    return _with_report_agent_artifacts({
        "report_markdown": deterministic,
        "report_polished_markdown": "",
        "report_appendix_markdown": appendix,
        "report_fact_cards": report_fact_cards,
        "report_polish_input": polish_input,
        "report_polish_brief": polish_brief,
        "report_polish_validation": skipped_validation,
        "report_polish_error": "",
    })
