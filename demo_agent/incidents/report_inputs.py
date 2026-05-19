from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List


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

STATUS_LABELS = {
    "confirmed_incident": "确认安全事件",
    "needs_review": "可疑事件，建议继续复核",
    "monitor_only": "背景活动，建议持续观察",
}


def _dedupe_text(values: List[Any]) -> List[str]:
    seen: set[str] = set()
    result: List[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result


def _join_or_fallback(values: List[Any], fallback: str = "当前未获取") -> str:
    cleaned = _dedupe_text(list(values or []))
    return "、".join(cleaned) if cleaned else fallback


def _first_nonempty(*values: Any, fallback: str = "") -> str:
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return fallback


def _format_time(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return "unknown"
    return text.replace("T", " ").replace("Z", " UTC")


def _object_type_label(object_type: str) -> str:
    text = str(object_type or "").strip()
    return OBJECT_TYPE_LABELS.get(text, text or "对象")


def _status_label_for_status(status: str) -> str:
    text = str(status or "").strip()
    return STATUS_LABELS.get(text, text or "待确认")


def _stage_label(stage: str) -> str:
    text = str(stage or "").strip()
    return STAGE_LABELS.get(text, text)


def _format_stage_list(stages: List[Any]) -> str:
    labels = _dedupe_text([_stage_label(str(stage or "").strip()) for stage in list(stages or [])])
    return "、".join(labels) if labels else "未识别"


def _normalize_report_text(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    replacements = {
        "alert观测": "告警",
        "seed alert": "种子告警",
        "Seed alert": "种子告警",
        "needs_review": "可疑事件，建议继续复核",
        "confirmed_incident": "确认安全事件",
        "monitor_only": "背景活动，建议持续观察",
        "material delta": "新的有效信息",
        "gap": "缺口",
    }
    for source, target in replacements.items():
        text = text.replace(source, target)
    text = re.sub(r"\bpivot\b", "关键关联指标", text, flags=re.IGNORECASE)
    text = re.sub(r"当前\s+关键关联指标", "当前关键关联指标", text)
    text = text.replace("仍需围绕当前关键关联指标做一次扩线核查", "仍需围绕当前关键关联指标开展一轮扩线核查")
    text = re.sub(r"围绕当前关键关联指标\s*做一次\s*扩线核查", "围绕当前关键关联指标开展一轮扩线核查", text)
    text = text.replace("该 gap 已经过多轮相关尝试但没有 新的有效信息，更适合作为报告未决事项。", "该缺口已多轮核查但仍未获得新的有效信息，更适合作为报告未决事项。")
    text = text.replace("当前没有仍然适合继续缩小该 gap 的工具，更适合作为报告边界说明。", "当前缺少继续缩小该缺口的有效手段，更适合作为报告边界说明。")
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _gap_clause_text(value: Any) -> str:
    text = _normalize_report_text(value)
    text = re.sub(r"[？?。]+$", "", text)
    if text == "是否存在主机侧执行、持久化或横向移动证据":
        return "还需要进一步确认主机侧是否已经出现能够直接支撑执行、持久化或横向移动的证据"
    text = re.sub(r"^(.*)，是否", r"\1，仍需确认是否", text)
    if text.startswith("是否"):
        return f"还需要进一步确认{text[2:]}"
    return text


def _is_internal_ip_text(value: Any) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    try:
        ip_obj = ipaddress.ip_address(text)
    except ValueError:
        return False
    private_networks = (
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),
        ipaddress.ip_network("fc00::/7"),
    )
    return any(ip_obj in network for network in private_networks)


def _sanitize_external_indicators(values: List[Any]) -> List[str]:
    return _dedupe_text(
        value
        for value in list(values or [])
        if str(value or "").strip() and not _is_internal_ip_text(value)
    )


def _evidence_objects(evidence_store: Dict[str, Any]) -> List[Dict[str, Any]]:
    return list(evidence_store.get("objects") or evidence_store.get("object_registry") or [])


def _evidence_gaps(evidence_store: Dict[str, Any]) -> List[Dict[str, Any]]:
    return list(evidence_store.get("gaps") or evidence_store.get("evidence_gaps") or [])


def _evidence_observations(evidence_store: Dict[str, Any]) -> List[Dict[str, Any]]:
    return list(evidence_store.get("observations") or [])


def _confirmed_events(evidence_store: Dict[str, Any]) -> List[Dict[str, Any]]:
    return list(evidence_store.get("confirmed_events") or [])


def _candidate_events(evidence_store: Dict[str, Any]) -> List[Dict[str, Any]]:
    return list(evidence_store.get("candidate_events") or [])


def _coverage(evidence_store: Dict[str, Any]) -> Dict[str, Any]:
    coverage = dict(evidence_store.get("coverage") or {})
    primary_external = _sanitize_external_indicators(list(coverage.get("primary_external_indicators") or []))
    contextual_external = _sanitize_external_indicators(list(coverage.get("contextual_external_indicators") or []))
    coverage["primary_external_indicators"] = primary_external
    coverage["contextual_external_indicators"] = contextual_external
    coverage["external_indicators"] = _sanitize_external_indicators(
        list(coverage.get("external_indicators") or []) + primary_external + contextual_external
    )
    return coverage


def _hypotheses(evidence_store: Dict[str, Any]) -> Dict[str, Any]:
    return dict(evidence_store.get("hypotheses") or {})


def _objects_with_roles(evidence_store: Dict[str, Any], roles: List[str], *, current_only: bool = False) -> List[Dict[str, Any]]:
    role_set = {str(role or "").strip() for role in list(roles or [])}
    result: List[Dict[str, Any]] = []
    for item in _evidence_objects(evidence_store):
        current_role = str(item.get("current_role") or "").strip()
        object_roles = {str(role or "").strip() for role in list(item.get("roles") or [])}
        if current_only:
            if current_role in role_set:
                result.append(item)
            continue
        if current_role in role_set or object_roles.intersection(role_set):
            result.append(item)
    return result


def _object_values(
    evidence_store: Dict[str, Any],
    roles: List[str],
    *,
    current_only: bool = False,
    object_types: List[str] | None = None,
) -> List[str]:
    type_set = {str(item or "").strip() for item in list(object_types or [])}
    values: List[str] = []
    for item in _objects_with_roles(evidence_store, roles, current_only=current_only):
        object_type = str(item.get("object_type") or "").strip()
        if type_set and object_type not in type_set:
            continue
        values.append(str(item.get("value") or "").strip())
    return _dedupe_text(values)


def _family_context(evidence_store: Dict[str, Any]) -> Dict[str, Any]:
    family_objects = _objects_with_roles(evidence_store, ["family_hint"])
    if not family_objects:
        return {}
    hint = str((family_objects[0] or {}).get("value") or "").strip()
    stages = list((_hypotheses(evidence_store).get("stages")) or [])
    stage_text = _format_stage_list(stages)
    summary = (
        f"当前可获得的背景提示主要来自家族/工具线索：{hint}。"
        if not stages
        else f"当前可获得的背景提示主要来自家族/工具线索：{hint}，与当前观察到的阶段形态 {stage_text} 基本一致。"
    )
    return {
        "hint": hint,
        "summary": summary,
        "limits": "这类背景提示更适合帮助理解攻击链或工具形态，不应直接当作样本级确认或强归因结论。",
        "observation_ids": [],
    }


def _event_observation_map(evidence_store: Dict[str, Any]) -> Dict[str, List[str]]:
    mapping: Dict[str, List[str]] = {}
    for observation in _evidence_observations(evidence_store):
        observation_id = str(observation.get("id") or observation.get("observation_id") or "").strip()
        if not observation_id:
            continue
        event_ids = _dedupe_text(
            list(observation.get("event_ids") or [])
            + list(observation.get("checked_event_ids") or [])
            + list(observation.get("boundary_event_ids") or [])
        )
        for event_id in event_ids:
            mapping.setdefault(event_id, []).append(observation_id)
    return {key: _dedupe_text(values) for key, values in mapping.items()}


def _event_indicator_text(event: Dict[str, Any]) -> str:
    return _join_or_fallback(
        [
            str(event.get("domain") or "").strip(),
            str(event.get("dst_ip") or "").strip(),
        ],
        "相关对象",
    )


def _background_summary_text(event: Dict[str, Any]) -> str:
    text = str(event.get("summary") or "").strip()
    lowered = text.lower()
    tags = {str(tag or "").strip().lower() for tag in list(event.get("tags") or [])}
    classification = str(event.get("classification") or "").strip().lower()
    if not lowered and not tags:
        return ""
    maintenance_markers = {"maintenance", "patching", "backup", "approved-change", "scheduled-change"}
    if classification == "benign" and tags.intersection(maintenance_markers):
        return "同时间窗存在已批准的维护、变更或备份活动，可解释部分日常管理行为"
    if "approved" in lowered and any(token in lowered for token in ["patch", "maintenance", "update", "change", "deployment", "backup"]):
        return "同时间窗存在已批准的维护、变更或更新活动，可解释部分日常管理行为"
    if "approved" in lowered and any(token in lowered for token in ["vendor", "endpoint", "update"]):
        return "访问了已批准的供应商或更新端点，更接近计划内流量"
    if "shared infrastructure" in lowered or "same hosting ip" in lowered or "different vendor domain" in lowered:
        return "存在共享基础设施背景，相关外部对象不能仅凭一次共现就升格为攻击基础设施"
    if "degraded" in lowered and "telemetry" in lowered:
        return "该主机侧遥测不完整，导致相关执行链暂时无法完整重建"
    if "cannot be reconstructed" in lowered:
        return "当前证据不足以完整重建相关执行链"
    return ""


def _timeline_event_summary(event: Dict[str, Any]) -> str:
    kind = str(event.get("kind") or "").strip().lower()
    role = str(event.get("role") or "").strip()
    stages = {str(stage or "").strip() for stage in list(event.get("stages") or [])}
    tags = {str(tag or "").strip().lower() for tag in list(event.get("tags") or [])}
    summary = str(event.get("summary") or "").strip()
    summary_lower = summary.lower()
    domain = str(event.get("domain") or "").strip()
    dst_ip = str(event.get("dst_ip") or "").strip()
    answers = [str(answer or "").strip() for answer in list(event.get("answers") or []) if str(answer or "").strip()]
    indicator_text = _event_indicator_text(event)
    background_summary = _background_summary_text(event)

    if "exploit" in summary_lower and any(token in summary_lower for token in ["request", "requests", "portal", "admin", "post"]):
        return "对外服务入口出现可疑利用请求"
    if background_summary:
        return background_summary

    if "lateral-movement" in stages:
        target_text = dst_ip or indicator_text or "关联内部主机"
        if "remote process creation" in summary_lower:
            return f"出现指向 `{target_text}` 的远程进程创建"
        if "remote service creation" in summary_lower:
            return f"出现指向 `{target_text}` 的远程服务创建"
        return f"出现指向 `{target_text}` 的横向操作告警"

    if "initial-access" in stages:
        if "exploit" in summary_lower and any(token in summary_lower for token in ["request", "requests", "portal", "admin"]):
            return "对外服务入口出现可疑利用请求"
        if "exploit" in summary_lower:
            return "出现疑似利用相关访问"
        return "出现疑似初始访问相关活动"

    if kind == "dns":
        if domain and ("rare domain" in summary_lower or "rare" in tags):
            body = f"先解析了少见域名 `{domain}`"
        elif domain:
            body = f"先解析了域名 `{domain}`"
        else:
            body = "先出现了可疑域名解析"
        if answers:
            body += f"，返回 `{answers[0]}`"
        if "command-and-control" in stages or role in {"seed", "supporting"}:
            body += "，为后续与同一基础设施的通信提供了准备"
        return body

    if kind in {"alert", "flow", "http"} and "command-and-control" in stages:
        if role == "seed":
            return f"围绕 {indicator_text} 的异常通信触发了种子告警"
        if any(token in summary_lower for token in ["reconnect", "reconnected", "contacted", "same beacon", "same c2", "same infrastructure"]):
            return f"再次与 {indicator_text} 通信，说明同一基础设施上的异常仍在持续"
        return f"与 {indicator_text} 建立了可疑通信"

    if kind == "process" or ("execution" in stages and kind not in {"alert", "flow", "dns", "http", "asset_context"}):
        process_match = re.search(r"\b([A-Za-z0-9_.-]+\.exe)\b", summary)
        if process_match:
            body = f"出现 `{process_match.group(1)}` 可疑启动"
        else:
            body = "出现可疑进程执行"
        if "dll" in summary_lower:
            body += "，伴随 DLL 加载"
        return body

    return _normalize_report_text(summary) or "出现关键观测"


def _timeline_role_label(event: Dict[str, Any]) -> str:
    role = str(event.get("role") or "").strip()
    stages = {str(stage or "").strip() for stage in list(event.get("stages") or [])}
    if role == "seed":
        return "调查起点"
    if role == "counterevidence":
        return "反证检查"
    if stages.intersection({"execution", "lateral-movement", "exfiltration", "persistence", "credential-access"}):
        return "风险升级"
    if role == "context":
        return "背景观测"
    if role == "candidate":
        return "待确认扩展"
    return "主证据"


def _timeline_entries(evidence_store: Dict[str, Any]) -> List[Dict[str, Any]]:
    event_obs_map = _event_observation_map(evidence_store)
    events = _confirmed_events(evidence_store) + _candidate_events(evidence_store)
    entries: List[Dict[str, Any]] = []
    for event in sorted(events, key=lambda item: (str(item.get("ts") or ""), str(item.get("id") or ""))):
        asset_id = str(event.get("asset_id") or "").strip()
        summary = _timeline_event_summary(event)
        event_summary = f"资产 `{asset_id}`：{summary}" if asset_id else summary
        event_id = str(event.get("id") or "").strip()
        entries.append(
            {
                "ts": event.get("ts"),
                "summary": event_summary,
                "role": _timeline_role_label(event),
                "observation_ids": list(event_obs_map.get(event_id) or []),
            }
        )
    return entries


def _analysis_window_text(evidence_store: Dict[str, Any]) -> str:
    window = dict((_coverage(evidence_store).get("time_window")) or {})
    start = _format_time(window.get("start"))
    end = _format_time(window.get("end"))
    if start == "unknown" and end == "unknown":
        return "当前未获取"
    return f"{start} 至 {end}"


def _report_title(evidence_store: Dict[str, Any]) -> str:
    coverage = _coverage(evidence_store)
    seed_asset = str(coverage.get("seed_asset") or "").strip()
    family_hint = str((_family_context(evidence_store).get("hint")) or "").strip()
    if seed_asset and family_hint:
        return f"{seed_asset} {family_hint} 调查报告"
    if seed_asset:
        return f"{seed_asset} 异常通信调查报告"
    return "事件调查报告"


def _seed_event(evidence_store: Dict[str, Any]) -> Dict[str, Any]:
    events = _confirmed_events(evidence_store)
    seed = next((item for item in events if str(item.get("role") or "").strip() == "seed"), {})
    if seed:
        return seed
    return min(events, key=lambda item: (str(item.get("ts") or ""), str(item.get("id") or "")), default={})


def _seed_alert_text(evidence_store: Dict[str, Any]) -> str:
    coverage = _coverage(evidence_store)
    seed_asset = str(coverage.get("seed_asset") or "").strip() or "相关资产"
    event = _seed_event(evidence_store)
    indicator_text = _event_indicator_text(event)
    kind = str(event.get("kind") or "").strip().lower()
    kind_label = {
        "alert": "告警",
        "flow": "网络通信",
        "dns": "DNS 解析",
        "http": "HTTP 访问",
        "process": "主机进程活动",
    }.get(kind, "相关观测")
    return _normalize_report_text(
        f"{_format_time(event.get('ts'))}，最先在 `{seed_asset}` 的{kind_label}中触发调查，当时关联对象为 {indicator_text}。"
    )


def _initial_hits(evidence_store: Dict[str, Any]) -> List[str]:
    hits: List[str] = []
    seed_fingerprints = _object_values(evidence_store, ["seed_fingerprint"])
    if seed_fingerprints:
        hits.append(f"命中了种子通信指纹：{_join_or_fallback(seed_fingerprints)}")
    family_hint = str((_family_context(evidence_store).get("hint")) or "").strip()
    if family_hint:
        hits.append(f"当前已有家族/工具背景提示：{family_hint}")
    primary_external = list((_coverage(evidence_store).get("primary_external_indicators")) or [])
    if primary_external:
        hits.append(f"当前已知关键对象包括 {_join_or_fallback(primary_external[:3])}")
    seed_summary = _timeline_event_summary(_seed_event(evidence_store))
    if seed_summary:
        hits.append(f"种子事件直接表现为：{seed_summary}")
    return _dedupe_text(_normalize_report_text(item) for item in hits if _normalize_report_text(item))


def _upstream_context(evidence_store: Dict[str, Any]) -> str:
    family_context = _family_context(evidence_store)
    if family_context.get("summary"):
        return str(family_context.get("summary") or "").strip()
    return "当前没有额外上游背景被纳入主报告。"


def _candidate_indicator_text(event: Dict[str, Any]) -> str:
    values = _dedupe_text(
        [
            str(event.get("domain") or "").strip(),
            str(event.get("dst_ip") or "").strip(),
        ]
    )
    return " / ".join(values[:2]) if values else "相关对象"


def _boundary_candidate_summary(evidence_store: Dict[str, Any], delivery_decision: Dict[str, Any]) -> str:
    candidate_events = _candidate_events(evidence_store)
    candidate_scope = list(delivery_decision.get("candidate_scope") or [])
    if candidate_events:
        assets = _dedupe_text(str(item.get("asset_id") or "").strip() for item in candidate_events)
        indicators = _dedupe_text(_candidate_indicator_text(item) for item in candidate_events)
        return (
            f"另有 {len(candidate_events)} 条候选扩展线索，主要涉及 "
            f"{_join_or_fallback(assets[:3], '关联资产')} 与 {_join_or_fallback(indicators[:3], '后续基础设施')}，"
            "当前先作为边界保留，不直接计入已确认影响范围。"
        )
    if candidate_scope:
        return f"当前仍有待独立验证的候选资产：{_join_or_fallback(candidate_scope[:4])}。"
    return ""


def _boundary_candidate_clauses(evidence_store: Dict[str, Any], delivery_decision: Dict[str, Any]) -> List[str]:
    clauses: List[str] = []
    for event in _candidate_events(evidence_store)[:2]:
        asset_id = str(event.get("asset_id") or "").strip() or "相关资产"
        indicator_text = _candidate_indicator_text(event)
        stages = {str(stage or "").strip() for stage in list(event.get("stages") or [])}
        if "lateral-movement" in stages or "execution" in stages:
            clauses.append(f"{asset_id} 围绕 {indicator_text} 的后续主机侧动作已被观察到，但当前仍缺少独立验证。")
        elif "command-and-control" in stages:
            clauses.append(f"{asset_id} 围绕 {indicator_text} 的后续可疑通信已被观察到，但当前仍缺少独立验证。")
        else:
            clauses.append(f"{asset_id} 围绕 {indicator_text} 的后续关联线索已被观察到，但当前仍缺少独立验证。")
    if not clauses:
        for asset in list(delivery_decision.get("candidate_scope") or [])[:2]:
            clauses.append(f"{asset} 当前仍处于候选影响范围，尚未获得足以独立确认的直接支撑。")
    return _dedupe_text(clauses)


def _analysis_summary(evidence_store: Dict[str, Any], delivery_decision: Dict[str, Any]) -> Dict[str, Any]:
    hypotheses = _hypotheses(evidence_store)
    gaps = [gap for gap in _evidence_gaps(evidence_store) if str(gap.get("status") or "").strip() != "closed"]
    delivery_status = str(delivery_decision.get("delivery_status") or "").strip() or "needs_review"
    blocking_gaps = list(delivery_decision.get("blocking_gaps") or [])
    next_best_questions = list(delivery_decision.get("next_best_questions") or [])
    unresolved_items = next_best_questions or [str(gap.get("question") or "").strip() for gap in gaps if str(gap.get("question") or "").strip()]
    why_this_conclusion = _first_nonempty(
        delivery_decision.get("reviewer_rationale"),
        hypotheses.get("positive_summary"),
        hypotheses.get("primary"),
        fallback="当前交付判断主要依据现有证据链和剩余缺口。",
    )
    if delivery_status == "confirmed_incident":
        why_not_other_status = (
            "当前主链已经具备可复核的连续性与高风险阶段支撑；剩余缺口只限制扩展边界，不足以把结论降回背景活动。"
        )
    elif delivery_status == "monitor_only":
        why_not_other_status = "当前更强的解释仍是背景活动或低确定性异常，因此不适合把本案直接上升为确认事件。"
    elif blocking_gaps:
        why_not_other_status = f"当前仍存在阻塞交付的关键缺口，例如：{_gap_clause_text((blocking_gaps[0] or {}).get('question'))}。"
    else:
        why_not_other_status = "当前已形成可疑事件链，但关键交付核验尚未完全闭合，因此暂不直接升级为确认事件。"
    return {
        "primary_hypothesis": _normalize_report_text(hypotheses.get("primary")),
        "alternative_hypothesis": _normalize_report_text(hypotheses.get("negative_summary") or "暂无稳定替代解释"),
        "why_this_conclusion": _normalize_report_text(why_this_conclusion),
        "why_not_other_status": _normalize_report_text(why_not_other_status),
        "unresolved_items": _dedupe_text(_normalize_report_text(item) for item in unresolved_items if _normalize_report_text(item)),
        "next_best_evidence": _dedupe_text(_normalize_report_text(item) for item in next_best_questions if _normalize_report_text(item))[:3],
    }


def _scope_summary(evidence_store: Dict[str, Any], delivery_decision: Dict[str, Any]) -> Dict[str, Any]:
    coverage = _coverage(evidence_store)
    confirmed_scope = list(delivery_decision.get("confirmed_scope") or [])
    candidate_scope = list(delivery_decision.get("candidate_scope") or [])
    seed_asset = str(coverage.get("seed_asset") or "").strip() or "相关资产"
    internal_ips = _object_values(evidence_store, ["related_internal_address"], object_types=["internal_ip"])
    external_ips = _object_values(
        evidence_store,
        ["core_external_indicator", "contextual_indicator", "expansion_candidate"],
        object_types=["IP"],
    )
    domains = _object_values(
        evidence_store,
        ["core_external_indicator", "contextual_indicator", "expansion_candidate"],
        object_types=["domain"],
    )
    if confirmed_scope and candidate_scope:
        current_boundary = f"当前确认范围收敛在 {_join_or_fallback(confirmed_scope)}；{_join_or_fallback(candidate_scope)} 保持待确认状态。"
    elif confirmed_scope:
        current_boundary = f"当前确认范围收敛在 {_join_or_fallback(confirmed_scope)}；当前没有额外待确认关联资产。"
    elif candidate_scope:
        current_boundary = f"当前调查重点仍围绕 `{seed_asset}` 收敛，{_join_or_fallback(candidate_scope)} 继续作为待确认对象保留。"
    else:
        current_boundary = f"当前调查重点仍围绕 `{seed_asset}` 收敛，尚未确认额外受影响范围。"
    return {
        "seed_alert": _seed_alert_text(evidence_store),
        "time_window": dict(coverage.get("time_window") or {}),
        "seed_asset": seed_asset,
        "suspected_label": "疑似受影响资产" if confirmed_scope else "重点观察资产",
        "suspected_assets": confirmed_scope,
        "related_label": "待排查关联资产",
        "related_assets": candidate_scope,
        "internal_ips": internal_ips,
        "external_ips": external_ips,
        "domains": domains,
        "stage_labels": [_stage_label(stage) for stage in list((_hypotheses(evidence_store).get("stages")) or [])],
        "primary_external_indicators": list(coverage.get("primary_external_indicators") or []),
        "contextual_external_indicators": list(coverage.get("contextual_external_indicators") or []),
        "event_count": int(coverage.get("event_count") or 0),
        "primary_event_count": int(coverage.get("event_count") or 0),
        "context_event_count": len(_candidate_events(evidence_store)),
        "counterevidence_count": len(
            [event for event in _confirmed_events(evidence_store) if str(event.get("role") or "").strip() == "counterevidence"]
        ),
        "current_boundary": current_boundary,
        "unresolved_scope": _dedupe_text(list(delivery_decision.get("next_best_questions") or [])),
    }


def _source_rows(evidence_store: Dict[str, Any]) -> List[Dict[str, str]]:
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

    seed_fingerprints = _object_values(evidence_store, ["seed_fingerprint"])
    family_hint = str((_family_context(evidence_store).get("hint")) or "").strip()
    upstream_name = " / ".join(_dedupe_text(seed_fingerprints + ([family_hint] if family_hint else [])))
    if upstream_name:
        add_row(
            "上游检测",
            upstream_name,
            "提供本案的调查起点与初始命中线索。",
            "命中本身并不自动等于事件成立，仍需要后续本地事实补强。",
        )

    for observation in _evidence_observations(evidence_store):
        provenance = str(observation.get("provenance") or "").strip()
        source_name = _first_nonempty(observation.get("source_ref"), observation.get("source_type"), observation.get("tool_name"))
        if provenance == "local_observation":
            add_row(
                "内部观测",
                source_name,
                "支撑时间线、范围和关键事实。",
                "仅覆盖当前调查纳入的本地流量与上下文数据。",
            )
        elif provenance == "analyst_note":
            add_row(
                "内部整理",
                source_name,
                "把零散观测沉淀为可引用的事实、实体与报告素材。",
                "内部整理不会新增外部事实，只负责结构化已有调查结果。",
            )
        elif provenance == "external_intel":
            add_row(
                "外部结构化情报",
                source_name,
                "补充基础设施、家族或公开背景解释。",
                "外部情报不能单独替代本地事实，也不能直接把本案写成强归因。",
            )
        elif provenance == "counterevidence":
            add_row(
                "背景核查",
                source_name,
                "验证维护窗口、补丁、备份或共享基线等替代解释。",
                "反证核查只能说明是否存在降级解释，不能替代主证据链。",
            )
        else:
            add_row(
                "调查记录",
                source_name,
                "补充报告中的上下文与过程性依据。",
                "该类记录主要用于辅助理解，不直接替代关键事实。",
            )
    return rows


def _ioc_rows(evidence_store: Dict[str, Any]) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for item in _evidence_objects(evidence_store):
        object_type = str(item.get("object_type") or "").strip()
        if object_type in {"asset", "family", "user"}:
            continue
        value = str(item.get("value") or "").strip()
        type_label = _object_type_label(object_type)
        key = (type_label, value)
        if not value or key in seen:
            continue
        seen.add(key)
        rows.append(
            {
                "type": type_label,
                "value": value,
                "relation": str(item.get("role_label") or item.get("current_role") or "").strip() or "关联指标",
                "status": str(item.get("status") or "").strip() or ("已确认" if bool(item.get("in_evidence_chain")) else "待确认"),
            }
        )
    return rows


def _process_name_from_summary(summary: Any) -> str:
    match = re.search(r"\b([A-Za-z0-9_.-]+\.exe)\b", str(summary or ""))
    return str(match.group(1) or "").strip() if match else ""


def _host_execution_followup_actions(evidence_store: Dict[str, Any]) -> List[str]:
    actions: List[str] = []
    events = list(_confirmed_events(evidence_store) + _candidate_events(evidence_store))
    for event in events:
        stages = {str(stage or "").strip() for stage in list(event.get("stages") or [])}
        kind = str(event.get("kind") or "").strip().lower()
        if kind != "process" and "execution" not in stages:
            continue

        summary = str(event.get("summary") or "").strip()
        process_name = _process_name_from_summary(summary)
        asset_id = str(event.get("asset_id") or "").strip()
        if not summary or not asset_id:
            continue

        lowered = summary.lower()
        has_command_detail = any(token in lowered for token in ["command line", "cmdline", "parent process", "sha256", "hash"])
        if has_command_detail and "dll" not in lowered:
            continue

        time_text = _format_time(event.get("ts"))
        time_clause = f"{time_text} 前后" if time_text != "unknown" else "对应时间窗"
        process_clause = f"`{process_name}` 的" if process_name else "可疑进程的"
        detail_fields = ["完整命令行", "父进程", "执行用户"]
        if "dll" in lowered:
            detail_fields.append("加载模块/库路径（如 DLL）")
        if "remote process" in lowered or "remote service" in lowered:
            detail_fields.append("远程来源与目标参数")
        detail_fields.extend(["文件哈希/签名", "落地时间"])
        tail = "；若摘要提示模块或库加载，确认实际加载了哪个模块/库（如 DLL）及其来源路径。" if "dll" in lowered else "。"
        actions.append(
            _normalize_report_text(
                f"在 `{asset_id}` 上围绕 {time_clause}，核查{process_clause}{'、'.join(detail_fields)}{tail}"
            )
        )
    return _dedupe_text(actions)


def _recommendations(evidence_store: Dict[str, Any], delivery_decision: Dict[str, Any]) -> List[str]:
    recommendations: List[str] = []
    confirmed_scope = list(delivery_decision.get("confirmed_scope") or [])
    candidate_scope = list(delivery_decision.get("candidate_scope") or [])
    seed_asset = str((_coverage(evidence_store).get("seed_asset")) or "").strip()
    core_indicators = list((_coverage(evidence_store).get("primary_external_indicators")) or [])
    next_best_questions = list(delivery_decision.get("next_best_questions") or [])
    host_followups = _host_execution_followup_actions(evidence_store)

    focus_assets = confirmed_scope or ([seed_asset] if seed_asset else [])
    if focus_assets:
        recommendations.append(f"优先隔离或重点监控资产：{_join_or_fallback(focus_assets)}。")
    if core_indicators:
        recommendations.append(f"在边界和代理设备上排查并封禁外部基础设施：{_join_or_fallback(core_indicators[:4])}。")
    recommendations.extend(host_followups[:2])
    if candidate_scope:
        recommendations.append(f"继续核实待复核关联资产 {_join_or_fallback(candidate_scope[:4])}。")
    if next_best_questions:
        recommendations.append(f"优先补查：{_normalize_report_text(next_best_questions[0])}。")
    if not recommendations:
        recommendations.append("结合当前事件边界和关键证据，围绕种子资产与核心外部指示物继续收敛处置。")
    return _dedupe_text(_normalize_report_text(item) for item in recommendations if _normalize_report_text(item))


def _bucket_recommendations(recommendations: List[str]) -> Dict[str, List[str]]:
    immediate = list(recommendations[:2])
    short_term = list(recommendations[2:4])
    follow_up = list(recommendations[4:])
    return {
        "immediate": immediate,
        "short_term": short_term,
        "follow_up": follow_up,
    }


def _one_sentence_summary(evidence_store: Dict[str, Any], delivery_decision: Dict[str, Any]) -> str:
    coverage = _coverage(evidence_store)
    seed_asset = str(coverage.get("seed_asset") or "相关资产").strip()
    confirmed_scope = list(delivery_decision.get("confirmed_scope") or [])
    delivery_status = str(delivery_decision.get("delivery_status") or "").strip() or "needs_review"
    primary_external = list(coverage.get("primary_external_indicators") or [])
    indicator_text = _join_or_fallback(primary_external[:2], "当前关键通信对象")
    if delivery_status == "confirmed_incident":
        return f"{_join_or_fallback(confirmed_scope, seed_asset)} 围绕 {indicator_text} 已形成可以稳定交付的异常链，当前应按安全事件处置。"
    if delivery_status == "monitor_only":
        return f"当前围绕 {seed_asset} 的异常更接近背景活动或计划内行为，建议持续观察并保留后续复核。"
    next_best = list(delivery_decision.get("next_best_questions") or [])
    if next_best:
        return f"{seed_asset} 围绕 {indicator_text} 已出现连续异常迹象，但由于{_gap_clause_text(next_best[0])}，当前仍按待人工复核事件交付。"
    return f"{seed_asset} 围绕 {indicator_text} 已形成需要继续收敛的异常事件链，当前仍按待人工复核事件交付。"


def build_report_inputs(
    evidence_store: Dict[str, Any],
    delivery_decision: Dict[str, Any],
) -> Dict[str, Any]:
    coverage = _coverage(evidence_store)
    hypotheses = _hypotheses(evidence_store)
    family_context = _family_context(evidence_store)
    cluster_events = list(_confirmed_events(evidence_store) + _candidate_events(evidence_store))
    recommendations = _recommendations(evidence_store, delivery_decision)
    bucketed_actions = _bucket_recommendations(recommendations)

    delivery_verdict = dict(delivery_decision.get("delivery_verdict") or {})
    analysis_verdict = dict(delivery_decision.get("analysis_verdict") or {})
    delivery_status = (
        str(delivery_decision.get("delivery_status") or "").strip()
        or str(delivery_verdict.get("status") or "").strip()
        or "needs_review"
    )
    delivery_status_label = (
        str(delivery_decision.get("delivery_status_label") or "").strip()
        or _status_label_for_status(delivery_status)
    )

    return {
        "schema_version": "report-inputs-v2",
        "report_title": _report_title(evidence_store),
        "analysis_window": _analysis_window_text(evidence_store),
        "delivery_verdict": delivery_verdict,
        "analysis_verdict": analysis_verdict,
        "delivery_status": delivery_status,
        "delivery_status_label": delivery_status_label,
        "confidence_value": delivery_verdict.get("confidence") or analysis_verdict.get("confidence"),
        "seed_asset": str(coverage.get("seed_asset") or "").strip() or "相关资产",
        "seed_indicator_text": _join_or_fallback(list(coverage.get("primary_external_indicators") or [])[:3], "当前关键通信对象"),
        "seed_alert_text": _seed_alert_text(evidence_store),
        "initial_hits": _initial_hits(evidence_store),
        "upstream_context": _upstream_context(evidence_store),
        "focus_statement": str(hypotheses.get("primary") or "").strip(),
        "positive_summary": str(hypotheses.get("positive_summary") or "").strip(),
        "one_sentence_summary": _one_sentence_summary(evidence_store, delivery_decision),
        "analysis": _analysis_summary(evidence_store, delivery_decision),
        "scope_summary": _scope_summary(evidence_store, delivery_decision),
        "family_context": family_context,
        "recommendations": recommendations,
        "bucketed_actions": bucketed_actions,
        "primary_action": _first_nonempty(*(bucketed_actions.get("immediate") or []), fallback="当前暂无需要优先强调的立即动作。"),
        "boundary_candidate_summary": _boundary_candidate_summary(evidence_store, delivery_decision),
        "boundary_candidate_clauses": _boundary_candidate_clauses(evidence_store, delivery_decision),
        "stage_values": list(hypotheses.get("stages") or []),
        "event_count": int(coverage.get("event_count") or len(cluster_events)),
        "ioc_rows": _ioc_rows(evidence_store),
        "source_rows": _source_rows(evidence_store),
        "cluster_events": cluster_events,
        "event_observation_map": _event_observation_map(evidence_store),
        "timeline_entries": _timeline_entries(evidence_store),
        "candidate_scope": list(delivery_decision.get("candidate_scope") or []),
        "confirmed_scope": list(delivery_decision.get("confirmed_scope") or []),
        "open_gaps": [gap for gap in _evidence_gaps(evidence_store) if str(gap.get("status") or "").strip() != "closed"],
    }
