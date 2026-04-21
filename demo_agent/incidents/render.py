from __future__ import annotations

import json
from typing import Any, Dict, List


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


def _reader_confidence_text(value: Any) -> str:
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
        level = "较高"
    elif score >= 50:
        level = "中"
    else:
        level = "低"
    return f"{level}（{score}/100）"


def _reader_clean_text(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    replacements = {
        "command-and-control": "命令与控制",
        "initial-access": "初始访问",
        "monitor_only": "持续观察",
        "needs_review": "待人工复核",
        "confirmed_incident": "确认事件",
        "seed alert": "种子告警",
        "seed 指标": "种子告警涉及的指标",
        "pivot": "枢纽",
    }
    for source, target in replacements.items():
        text = text.replace(source, target)
    return text


def _reader_action_text(value: Any) -> str:
    text = _reader_clean_text(value)
    if not text:
        return ""
    text = text.replace(
        "以 种子告警涉及的指标和事件簇中的域名 / IP 为 枢纽，继续检索同时间窗内的重复通信。",
        "围绕种子告警涉及的域名、IP 和同基础设施指标，继续检索同时间窗内是否存在重复通信。",
    )
    text = text.replace(
        "以种子告警涉及的指标和事件簇中的域名 / IP 为枢纽，继续检索同时间窗内的重复通信。",
        "围绕种子告警涉及的域名、IP 和同基础设施指标，继续检索同时间窗内是否存在重复通信。",
    )
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
    if kind == "asset_context":
        return "资产背景"
    if "execution" in stages or "powershell" in summary or "process" in summary or "w3wp" in summary:
        return "主机"
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
    kind_label = _kind_label(str(item.get("kind") or "").strip())
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


def _boundary_lines(incident: Dict[str, Any]) -> List[str]:
    verdict = incident.get("verdict") or {}
    entities = incident.get("entities") or {}
    status = str(verdict.get("status") or "").strip()
    unresolved = _unresolved_items(incident)

    if status == "confirmed_incident":
        lines = [
            f"当前自动化判断把事件边界收敛在 {'、'.join(entities.get('suspected_assets') or []) or '种子资产'} 上，已经足以把本案从单条告警提升为已成立事件，但尚未确认存在更大范围扩散。"
        ]
    elif status == "monitor_only":
        lines = [
            "当前更倾向于把这起告警解释为计划内活动中的弱信号，而不是已经成立的入侵事件。"
        ]
    else:
        lines = [
            "当前已经形成可关联的事件簇，但主要支撑信号仍不足以把结论稳定推进到确认事件。"
        ]

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
    decision_basis = incident.get("decision_basis") or {}
    observation_map: Dict[str, List[str]] = {}
    for item in list(decision_basis.get("positive_signals") or []) + list(decision_basis.get("counterevidence") or []):
        event_id = str(item.get("event_id") or "").strip()
        if event_id:
            observation_map[event_id] = list(item.get("observation_ids") or [])

    return [
        {
            "ts": item.get("ts"),
            "summary": item.get("summary"),
            "role": _timeline_role_label(item),
            "observation_ids": observation_map.get(str(item.get("event_id") or "").strip(), []),
        }
        for item in timeline
    ]


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
    provisional = incident.get("provisional_verdict") or incident.get("verdict") or {}
    delivery = incident.get("verdict") or {}
    blocking_checks = list(readiness.get("blocking_checks") or [])
    blocking_items = [str(item.get("reason") or "").strip() for item in blocking_checks if str(item.get("reason") or "").strip()]
    provisional_label = str(provisional.get("status_label") or "").strip()
    delivery_label = str(delivery.get("status_label") or "").strip()

    if provisional_label and delivery_label and provisional_label != delivery_label:
        summary = (
            f"当前内部方向更接近“{provisional_label}”，但交付门槛尚未全部通过，"
            f"因此最终对外交付维持为“{delivery_label}”。"
        )
    else:
        summary = str(readiness.get("summary") or "").strip()
    return {
        "ready_for_delivery": bool(readiness.get("ready_for_delivery")),
        "summary": summary,
        "blocking_items": blocking_items,
        "provisional_conclusion": provisional_label,
        "delivery_conclusion": delivery_label,
    }


def _scope_summary(incident: Dict[str, Any]) -> Dict[str, Any]:
    verdict = incident.get("verdict") or {}
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
    verdict = incident.get("verdict") or {}
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
    fingerprint = (incident.get("seed") or {}).get("trigger_fingerprint") or {}
    fp_value = str(fingerprint.get("value") or "").strip()
    fp_type = str(fingerprint.get("type") or "").strip().lower()
    if fp_value and fp_type:
        add_node(f"fp:{fp_type}:{fp_value}", label=f"{fingerprint.get('type')} {fp_value}", node_type=f"fingerprint_{fp_type}")

    for asset_id in list(((incident.get("entities") or {}).get("assets")) or []):
        add_node(f"asset:{asset_id}", label=asset_id, node_type="internal_host")

    for ip in list(((incident.get("entities") or {}).get("external_ips")) or []):
        add_node(f"ip:{ip}", label=ip, node_type="external_ip")

    for domain in list(((incident.get("entities") or {}).get("domains")) or []):
        add_node(f"domain:{domain}", label=domain, node_type="domain")

    for event in events:
        asset_id = str(event.get("asset_id") or "").strip()
        dst_ip = str(event.get("dst_ip") or "").strip()
        domain = str(event.get("domain") or "").strip()

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


def _reader_judgment(verdict: Dict[str, Any]) -> str:
    status = str(verdict.get("status") or "").strip()
    if status == "confirmed_incident":
        return "当前证据支持将本案按已成立安全事件处置。"
    if status == "monitor_only":
        return "当前更适合按背景活动中的弱信号处理，并保留后续复核。"
    return "当前已经形成可疑事件链，但仍应按待人工复核结论交付。"


def _reader_boundary_text(incident: Dict[str, Any]) -> str:
    entities = incident.get("entities") or {}
    scope = incident.get("scope") or {}
    affected_assets = list(entities.get("suspected_assets") or [])
    related_assets = list(entities.get("related_assets") or [])
    indicators = list(scope.get("primary_external_indicators") or [])

    asset_text = "、".join(affected_assets) if affected_assets else (entities.get("seed_asset") or "种子资产")
    indicator_text = "、".join(indicators[:3]) if indicators else "当前核心外部指示物"
    if related_assets:
        return f"当前影响范围主要收敛在 {asset_text}，同时还存在待复核关联资产 { '、'.join(related_assets[:3]) }；核心外部指示物为 {indicator_text}。"
    return f"当前影响范围主要收敛在 {asset_text}，核心外部指示物为 {indicator_text}。"


def _reader_one_sentence_summary(incident: Dict[str, Any]) -> str:
    verdict = incident.get("verdict") or {}
    entities = incident.get("entities") or {}
    scope = incident.get("scope") or {}
    events = list(((incident.get("cluster") or {}).get("events")) or [])
    asset_text = str(entities.get("seed_asset") or "相关资产").strip()
    indicator_text = _join_items(list(scope.get("primary_external_indicators") or [])[:2])
    has_execution = any("execution" in list(item.get("stages") or []) for item in events)
    has_repeated_c2 = sum(1 for item in events if "command-and-control" in list(item.get("stages") or [])) >= 2
    status = str(verdict.get("status") or "").strip()

    if status == "confirmed_incident":
        if has_execution and indicator_text != "未识别":
            return f"资产 {asset_text} 围绕 {indicator_text} 出现重复可疑外联，并在随后出现执行线索，当前应按已成立安全事件处置。"
        if has_repeated_c2 and indicator_text != "未识别":
            return f"资产 {asset_text} 围绕 {indicator_text} 出现重复可疑外联，已经形成连续事件链，当前应按已成立安全事件处置。"
        return f"当前围绕资产 {asset_text} 已形成足以支撑事件成立的关键证据链，建议按已成立安全事件处置。"

    if status == "monitor_only":
        return f"当前围绕资产 {asset_text} 的异常更接近背景活动或计划内行为，尚不足以按已成立入侵事件处置。"

    if has_execution:
        return f"资产 {asset_text} 已出现从可疑外联延伸到执行线索的迹象，但关键定性证据仍需人工复核。"
    if indicator_text != "未识别":
        return f"资产 {asset_text} 围绕 {indicator_text} 已形成可疑事件链，但现阶段更适合按待人工复核结论交付。"
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


def _signal_view_from_event(event: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "ts": event.get("ts"),
        "asset_id": event.get("asset_id"),
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
    indicator_text = _event_indicator_text(event) or "相关外部基础设施"
    role = str(event.get("role") or "").strip()
    kind = str(event.get("kind") or "").strip().lower()
    stages = list(event.get("stages") or [])

    if role == "seed":
        return f"在 {ts}，资产 `{asset_id}` 命中了以 {indicator_text} 为核心的种子告警。"
    if "execution" in stages:
        return f"在 {ts}，同一资产 `{asset_id}` 在可疑外联之后出现主机侧执行线索，说明事件已经从网络异常推进到执行阶段。"
    if role == "counterevidence":
        if indicator_text == "相关外部基础设施":
            return f"另有一条更接近计划内维护或更新背景的通信发生在 {ts}，提示同时间窗内存在可解释为正常运维的活动。"
        return f"另有一条更接近计划内维护或更新背景的通信发生在 {ts}，目标为 {indicator_text}。"
    if kind == "dns":
        return f"在 {ts}，资产 `{asset_id}` 先解析了 {indicator_text}，说明相关基础设施并非只在告警瞬间出现。"
    if "command-and-control" in stages:
        return f"在 {ts}，资产 `{asset_id}` 再次与 {indicator_text} 通信，表明该行为具有持续性，而不是孤立命中。"
    return f"在 {ts}，资产 `{asset_id}` 出现了一条与 {indicator_text} 相关的关键关联观测。"


def _story_line_from_event(event: Dict[str, Any], observation_map: Dict[str, List[str]]) -> str:
    sentence = _reader_fact_from_event(event)
    observation_ids = observation_map.get(str(event.get("id") or "").strip(), [])
    if observation_ids:
        sentence += f"（观测引用：{_format_obs_refs(observation_ids)}）"
    return sentence


def _reader_progression(incident: Dict[str, Any]) -> List[str]:
    events = list(((incident.get("cluster") or {}).get("events")) or [])
    observation_map = _event_observation_map(incident)
    events.sort(key=lambda item: str(item.get("ts") or ""))

    selected: List[Dict[str, Any]] = []
    seen_themes: set[str] = set()
    for event in events:
        role = str(event.get("role") or "").strip()
        stages = list(event.get("stages") or [])
        kind = str(event.get("kind") or "").strip().lower()
        theme = "context"
        if "execution" in stages:
            theme = "execution"
        elif role == "counterevidence":
            theme = "counterevidence"
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
    selected.sort(
        key=lambda item: (
            str(item.get("role") or "").strip() == "counterevidence",
            str(item.get("ts") or ""),
        )
    )
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
        "beacon": "重复外联与回连形态",
        "execution": "主机侧执行佐证",
        "initial_access": "初始入侵线索",
        "prep": "告警前准备动作",
        "context": "关联上下文",
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


def _build_reader_report_payload(incident: Dict[str, Any]) -> Dict[str, Any]:
    verdict = incident.get("verdict") or {}
    scope = incident.get("scope") or {}
    analysis = _analysis_summary(incident)
    bucketed = _bucket_recommendations(list(incident.get("recommendations") or []))
    recommendations = {
        bucket: [_reader_action_text(item) for item in items if _reader_action_text(item)]
        for bucket, items in bucketed.items()
    }
    unresolved = _dedupe_text(list(analysis.get("unresolved_items") or []))
    stage_text = _format_stage_list(list(((incident.get("hypothesis") or {}).get("stages")) or []))
    return {
        "title": "事件调查报告",
        "judgment_label": verdict.get("status_label"),
        "severity": verdict.get("severity"),
        "confidence": _reader_confidence_text((incident.get("summary") or {}).get("confidence") or verdict.get("confidence")),
        "one_sentence_summary": _reader_one_sentence_summary(incident),
        "judgment_text": _reader_clean_text(_reader_judgment(verdict)),
        "boundary_text": _reader_clean_text(_reader_boundary_text(incident)),
        "primary_action": _reader_action_text(_primary_action(list(incident.get("recommendations") or []))),
        "event_progression": _reader_progression(incident),
        "supporting_blocks": _reader_supporting_blocks(incident),
        "counter_block": _reader_counter_block(incident),
        "scope_lines": [
            f"时间窗口：{_format_time((scope.get('time_window') or {}).get('start'))} 至 {_format_time((scope.get('time_window') or {}).get('end'))}",
            f"种子资产：{(incident.get('entities') or {}).get('seed_asset') or '未识别'}",
            f"当前已确认范围：{_join_items(list((incident.get('entities') or {}).get('suspected_assets') or []))}",
            f"核心外部指示物：{_join_items(list(scope.get('primary_external_indicators') or []))}",
            f"当前攻击阶段：{stage_text if stage_text != '未识别' else '尚未稳定识别'}",
            f"当前边界：{_reader_clean_text(_scope_summary(incident).get('current_boundary'))}",
        ],
        "actions": recommendations,
        "open_questions": unresolved or ["当前暂无必须额外补充的未决事项。"],
    }


def build_incident_report_outline(incident: Dict[str, Any]) -> Dict[str, Any]:
    verdict = incident.get("verdict") or {}
    summary = incident.get("summary") or {}
    hypothesis = incident.get("hypothesis") or {}
    recommendations = list(incident.get("recommendations") or [])
    buckets = _bucket_recommendations(recommendations)
    family_context = _family_context(incident)
    delivery_readiness = _delivery_readiness(incident)

    return {
        "title": "事件级溯源报告",
        "template_version": "incident-agent-v2",
        "executive_summary": {
            "event_conclusion": verdict.get("status_label"),
            "status_code": _status_code(str(verdict.get("status") or "").strip()),
            "severity": verdict.get("severity"),
            "confidence": summary.get("confidence") or verdict.get("confidence"),
            "headline": summary.get("headline") or hypothesis.get("title"),
            "one_sentence_summary": hypothesis.get("narrative"),
            "primary_action": _primary_action(recommendations),
            "delivery_note": delivery_readiness.get("summary"),
        },
        "scope_and_boundary": _scope_summary(incident),
        "timeline": _timeline_entries(incident),
        "evidence_chain": {
            "supporting": _supporting_entries(incident),
            "counterevidence": _counter_entries(incident),
            "family_context": family_context,
        },
        "analysis": _analysis_summary(incident),
        "delivery_readiness": delivery_readiness,
        "recommendations": buckets,
        "reader_report": _build_reader_report_payload(incident),
        "appendix": {
            "ioc_rows": _ioc_rows(incident),
            "observation_rows": _observation_rows(incident),
        },
    }


def render_incident_report_appendix(incident: Dict[str, Any]) -> str:
    outline = build_incident_report_outline(incident)
    timeline = list(outline["timeline"] or [])
    evidence_chain = outline["evidence_chain"] or {}
    appendix = outline["appendix"] or {}

    lines: List[str] = [
        "# 事件调查技术附录",
        "",
        "## 1. 技术时间线",
        "",
        "| 时间 | 事件 | 作用 | 观测引用 |",
        "| -- | -- | -- | -- |",
    ]
    for item in timeline:
        lines.append(
            f"| {_format_time(item.get('ts'))} | {str(item.get('summary') or '').replace('|', '/')} | `{item.get('role')}` | {_format_obs_refs(list(item.get('observation_ids') or []))} |"
        )

    lines.extend(["", "## 2. 证据细目", "", "### 2.1 主支撑证据"])
    supporting = list(evidence_chain.get("supporting") or [])
    if not supporting:
        lines.append("- 当前没有足够的主支撑证据可供自动展开。")
    for entry in supporting:
        lines.extend(
            [
                "",
                f"#### 证据 {entry.get('id')}",
                f"- **证据类别**：{entry.get('category')}",
                f"- **证据强度**：{entry.get('strength')}",
                f"- **事实描述**：{entry.get('fact_description')}",
                f"- **为什么支持当前主假设**：{entry.get('reason_text')}",
                f"- **局限性与边界**：{entry.get('limitation_text')}",
                f"- **观测引用**：`{_format_obs_refs(list(entry.get('observation_ids') or []))}`",
            ]
        )

    lines.extend(["", "### 2.2 反证与替代解释"])
    counter_entries = list(evidence_chain.get("counterevidence") or [])
    if not counter_entries:
        lines.append("- 当前没有足以改变结论方向的强反证，但这并不意味着后续可以省略背景核查。")
    for entry in counter_entries:
        lines.extend(
            [
                "",
                f"#### 证据 {entry.get('id')}",
                f"- **反证或替代解释类别**：{entry.get('category')}",
                f"- **证据强度**：{entry.get('strength')}",
                f"- **相关事实**：{entry.get('fact_description')}",
                f"- **为什么它提示了替代解释，或为什么它不足以推翻主结论**：{entry.get('reason_text')}",
                f"- **边界与后续关注点**：{entry.get('limitation_text')}",
                f"- **观测引用**：`{_format_obs_refs(list(entry.get('observation_ids') or []))}`",
            ]
        )

    family_context = evidence_chain.get("family_context")
    if family_context:
        lines.extend(
            [
                "",
                "### 2.3 背景情报与家族上下文（可选）",
                f"- **相关家族/工具提示**：{family_context.get('hint')}",
                f"- **背景情报摘要**：{family_context.get('summary')}",
                f"- **不能据此直接推出的结论**：{family_context.get('limits')}",
                f"- **观测引用 / 来源引用**：`{_format_obs_refs(list(family_context.get('observation_ids') or []))}`",
            ]
        )

    lines.extend(["", "## 3. IOC / IOA 清单", "", "| 类型 | 值 | 与本案关系 |", "| -- | -- | -- |"])
    for row in list(appendix.get("ioc_rows") or []):
        lines.append(f"| {row.get('type')} | {str(row.get('value') or '').replace('|', '/')} | {str(row.get('relation') or '').replace('|', '/')} |")
    if not list(appendix.get("ioc_rows") or []):
        lines.append("| 暂无 | 暂无 | 暂无 |")

    lines.extend(["", "## 4. 观测引用对照", "", "| 观测编号 | 来源工具 | 来源类型 | 摘要 |", "| -- | -- | -- | -- |"])
    observation_rows = list(appendix.get("observation_rows") or [])
    for row in observation_rows:
        lines.append(
            f"| `{row.get('observation_id')}` | `{row.get('tool_name')}` | `{row.get('source_type')}` | {str(row.get('summary') or '').replace('|', '/')} |"
        )
    if not observation_rows:
        lines.append("| `obs-none` | `n/a` | `n/a` | 当前没有可展示的 observation 摘要。 |")

    return "\n".join(lines).strip() + "\n"


def render_incident_report(incident: Dict[str, Any]) -> str:
    outline = build_incident_report_outline(incident)
    reader = outline.get("reader_report") or {}
    actions = reader.get("actions") or {}
    support_blocks = list(reader.get("supporting_blocks") or [])
    counter_block = reader.get("counter_block") or {}

    lines: List[str] = [
        "# 事件调查报告",
        "",
        "技术细节、IOC 与观测对照请见《事件调查技术附录》。",
        "",
        "## 1. 核心结论",
        f"- **事件结论**：{reader.get('judgment_label')}",
        f"- **风险等级**：{reader.get('severity')}",
        f"- **信心水平**：{reader.get('confidence')}",
        f"- **一句话概括**：{reader.get('one_sentence_summary')}",
        f"- **当前判断**：{reader.get('judgment_text')}",
        f"- **当前影响范围**：{reader.get('boundary_text')}",
        f"- **最需要立即推进的动作**：{reader.get('primary_action')}",
        "",
        "## 2. 事件经过",
    ]

    progression = list(reader.get("event_progression") or [])
    if progression:
        for index, item in enumerate(progression, start=1):
            lines.append(f"{index}. {item}")
    else:
        lines.append("1. 当前没有足够的关键节点可供自动串联。")

    lines.extend(["", "## 3. 关键判断依据"])
    if not support_blocks:
        lines.append("- 当前没有足够的主支撑证据可供自动展开。")
    for block in support_blocks:
        lines.extend(
            [
                "",
                f"### {block.get('title')}",
                f"- **关键事实**：{' '.join(block.get('facts') or [])}",
                f"- **为什么重要**：{block.get('judgment')}",
                f"- **当前边界**：{block.get('boundary')}",
            ]
        )

    if counter_block:
        lines.extend(
            [
                "",
                "### 反证与替代解释",
                f"- **关键事实**：{' '.join(counter_block.get('facts') or [])}",
                f"- **为什么它没有直接推翻当前结论**：{counter_block.get('judgment')}",
                f"- **仍需注意的边界**：{counter_block.get('boundary')}",
            ]
        )

    lines.extend(["", "## 4. 范围与边界"])
    for item in list(reader.get("scope_lines") or []):
        lines.append(f"- {item}")

    lines.extend(["", "## 5. 建议动作"])
    lines.extend(_render_action_group("### 5.1 立即动作", list(actions.get("immediate") or [])))
    lines.extend(_render_action_group("### 5.2 短期排查", list(actions.get("short_term") or [])))
    lines.extend(_render_action_group("### 5.3 后续改进", list(actions.get("follow_up") or [])))
    if not any([actions.get("immediate"), actions.get("short_term"), actions.get("follow_up")]):
        lines.append("- 当前暂无可直接自动化生成的处置建议。")

    lines.extend(["", "## 6. 待确认事项"])
    for item in list(reader.get("open_questions") or []):
        lines.append(f"- {item}")

    return "\n".join(lines).strip() + "\n"


def render_incident_report_with_llm(incident: Dict[str, Any], llm: Any = None) -> Dict[str, str]:
    deterministic = render_incident_report(incident)
    appendix = render_incident_report_appendix(incident)
    outline = build_incident_report_outline(incident)
    if llm is None:
        return {
            "report_markdown": deterministic,
            "report_polished_markdown": "",
            "report_appendix_markdown": appendix,
        }

    try:
        from langchain_core.prompts import ChatPromptTemplate

        prompt = ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    "你是网络安全事件分析师。请仅基于 report_outline JSON 生成一份面向交付对象的中文 Markdown 报告。"
                    "报告必须使用以下固定结构：1.核心结论、2.事件经过、3.关键判断依据、4.范围与边界、5.建议动作、6.待确认事项。"
                    "绝不引入 outline 里不存在的新 IOC、新结论、新阶段或新资产。"
                    "不要暴露 tool 名、source_type、internal_digest、readiness check 等内部实现词。"
                    "如果某项信息不足，就保守描述，不要补写。",
                ),
                ("user", "report_outline:\n{outline_json}"),
            ]
        )
        response = llm.invoke(prompt.format_messages(outline_json=json.dumps(outline, ensure_ascii=False, indent=2)))
        content = str(getattr(response, "content", "") or "").strip()
        if content:
            return {
                "report_markdown": deterministic,
                "report_polished_markdown": content + ("\n" if not content.endswith("\n") else ""),
                "report_appendix_markdown": appendix,
            }
    except Exception:
        pass
    return {
        "report_markdown": deterministic,
        "report_polished_markdown": "",
        "report_appendix_markdown": appendix,
    }
