from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Dict, List

from .contracts import infer_stages, parse_timestamp, severity_from_confidence, suspicion_score, unique_preserve_order


def _status_label(status: str) -> str:
    mapping = {
        "confirmed_incident": "确认事件",
        "needs_review": "待人工复核",
        "monitor_only": "降级观察",
    }
    return mapping.get(status, status)


def _meaningful_family_hint(seed_event: Dict[str, Any]) -> str:
    hint = str((((seed_event.get("enrichment") or {}).get("info")) or "")).strip()
    lowered = hint.lower()
    if not hint:
        return ""
    if lowered.startswith("unknown"):
        return ""
    if lowered in {"suspicious", "unknown suspicious tls fingerprint"}:
        return ""
    if "candidate" in lowered and "possible" not in lowered:
        return ""
    return hint


def _event_details(event: Dict[str, Any]) -> str:
    asset_id = str(event.get("asset_id") or event.get("src_ip") or "unknown").strip()
    dst_ip = str(event.get("dst_ip") or "").strip()
    domain = str(event.get("domain") or "").strip()
    suffix = []
    if dst_ip:
        suffix.append(dst_ip)
    if domain:
        suffix.append(domain)
    target = " / ".join(suffix)
    if target:
        return f"{asset_id} -> {target}: {event.get('summary')}"
    return f"{asset_id}: {event.get('summary')}"


def _event_fingerprint_values(event: Dict[str, Any]) -> List[str]:
    return unique_preserve_order(
        [
            event.get("ja4"),
            event.get("ja3"),
            event.get("ssl_sha1"),
            event.get("cert_sha1"),
        ]
    )


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
    if event.get("ja3"):
        values.append(f"JA3 {event['ja3']}")
    if event.get("ssl_sha1"):
        values.append(f"SSL-SHA1 {event['ssl_sha1']}")
    if event.get("cert_sha1"):
        values.append(f"CERT-SHA1 {event['cert_sha1']}")
    answers = unique_preserve_order(event.get("answers") or [])
    if answers:
        values.append(f"DNS answers {', '.join(answers[:2])}")
    return " / ".join(values)


def _event_evidence_note(event: Dict[str, Any], *, status: str, seed_asset: str) -> str:
    role = str(event.get("role") or "").strip()
    kind = str(event.get("kind") or "").strip().lower()
    asset_id = str(event.get("asset_id") or "").strip()
    tags = {str(item or "").strip().lower() for item in list(event.get("tags") or [])}
    stages = {str(item or "").strip().lower() for item in list(event.get("stages") or [])}
    summary = str(event.get("summary") or "").strip().lower()

    if role == "seed":
        return "这是种子命中的直接落点，说明告警并不是孤立的指纹命中。"
    if "execution" in stages:
        return "这条记录把可疑外联推进到了主机侧执行层，显著提高了事件成立概率。"
    if role == "counterevidence" or "maintenance" in tags or "patching" in tags:
        return "这条记录更接近计划内维护或正常更新背景，是当前能够降级或收窄判断的重要原因。"
    if kind == "dns":
        if asset_id and asset_id == seed_asset:
            return "它给出了可疑外联之前的解析准备动作，说明相关基础设施不是只在告警瞬间出现。"
        return "它补足了外联前的解析准备动作，使通信链条更完整。"
    if "command-and-control" in stages and asset_id and asset_id == seed_asset:
        return "同一资产围绕同一批外部基础设施再次通信，单条告警已经扩展成连续事件链。"
    if "command-and-control" in stages:
        return "它说明可疑通信具备复现性，不像一次性噪声。"
    if role == "context" and asset_id and asset_id != seed_asset:
        if status == "needs_review":
            return "它把调查范围扩展到关联资产，但目前还不足以单独判定该资产已经受影响。"
        if status == "monitor_only":
            return "它说明同类通信可能是共享基线的一部分，而不是扩散迹象。"
    if "rare" in tags or "rare" in summary:
        return "它强调了这批外部基础设施在当前环境中的稀有性。"
    return "它补足了种子告警周围的上下文。"


def _annotate_events(
    seed_event: Dict[str, Any],
    events: List[Dict[str, Any]],
    event_relation_hints: Dict[str, str] | None = None,
) -> Dict[str, Any]:
    seed_src = str(((seed_event.get("src") or {}).get("ip")) or "").strip()
    seed_dst = str(((seed_event.get("dst") or {}).get("ip")) or "").strip()
    seed_fp = str((((seed_event.get("trigger_fingerprint") or {}).get("value")) or "")).strip()
    seed_ts = parse_timestamp(seed_event.get("event_time"))
    relation_hints = {
        str(key or "").strip(): str(value or "").strip()
        for key, value in dict(event_relation_hints or {}).items()
        if str(key or "").strip() and str(value or "").strip()
    }

    best_seed_id = ""
    best_seed_score = -1
    best_seed_delta = float("inf")
    for event in events:
        score = 0
        if seed_src and str(event.get("src_ip") or "").strip() == seed_src:
            score += 2
        if seed_dst and str(event.get("dst_ip") or "").strip() == seed_dst:
            score += 2
        if seed_fp and seed_fp in _event_fingerprint_values(event):
            score += 3
        delta = abs((parse_timestamp(event.get("ts")) - seed_ts).total_seconds())
        if delta <= 60:
            score += 3
        elif delta <= 600:
            score += 1
        if score > best_seed_score or (score == best_seed_score and delta < best_seed_delta):
            best_seed_score = score
            best_seed_delta = delta
            best_seed_id = str(event.get("id") or "")

    seed_asset_id = ""
    for event in events:
        if str(event.get("id") or "") == best_seed_id:
            seed_asset_id = str(event.get("asset_id") or "").strip()
            break

    annotated_events: List[Dict[str, Any]] = []
    supporting_ids: List[str] = []
    counterevidence_ids: List[str] = []
    candidate_ids: List[str] = []
    for event in events:
        stages = infer_stages(event)
        classification = str(event.get("classification") or "unknown").strip().lower()
        event_id = str(event.get("id") or "")
        explicit_relation = relation_hints.get(event_id, "")
        asset_id = str(event.get("asset_id") or "").strip()
        suspicious_classification = classification in {"malicious", "suspicious", "needs_review"}
        high_risk_progression = bool(
            set(stages) & {"initial-access", "execution", "lateral-movement", "exfiltration", "credential-access", "persistence"}
        )
        role = "context"
        if event_id == best_seed_id:
            role = "seed"
        elif explicit_relation == "counterevidence":
            role = "counterevidence"
        elif explicit_relation == "supporting":
            role = "supporting"
        elif explicit_relation == "candidate":
            role = "candidate"
        elif explicit_relation in {"context", "alternative"}:
            if suspicious_classification and high_risk_progression and asset_id and asset_id == seed_asset_id:
                role = "supporting"
            else:
                role = "context"
        elif classification == "benign":
            role = "counterevidence"
        elif classification in {"malicious", "suspicious", "needs_review"} or stages:
            role = "supporting"

        event_copy = dict(event)
        event_copy["role"] = role
        event_copy["stages"] = stages
        annotated_events.append(event_copy)

        if role in {"seed", "supporting"}:
            supporting_ids.append(event_copy["id"])
        if role == "counterevidence":
            counterevidence_ids.append(event_copy["id"])
        if role == "candidate":
            candidate_ids.append(event_copy["id"])

    return {
        "seed_event_id": best_seed_id,
        "events": annotated_events,
        "supporting_event_ids": supporting_ids,
        "counterevidence_event_ids": counterevidence_ids,
        "candidate_event_ids": candidate_ids,
    }


def _assess_entry(seed_event: Dict[str, Any], minimal_context: List[Dict[str, Any]]) -> Dict[str, Any]:
    scores = [suspicion_score(item) for item in minimal_context]
    suspicious_count = sum(1 for score in scores if score > 0)
    benign_count = sum(1 for score in scores if score < 0)
    positive_score = sum(score for score in scores if score > 0)
    negative_score = abs(sum(score for score in scores if score < 0))
    repeated_dst_count = Counter(str(item.get("dst_ip") or "").strip() for item in minimal_context if item.get("dst_ip"))
    repeated_domain_count = Counter(str(item.get("domain") or "").strip() for item in minimal_context if item.get("domain"))
    repeated_infra = [value for value, count in {**repeated_dst_count, **repeated_domain_count}.items() if value and count >= 2]
    reasons: List[str] = []

    if benign_count >= 3 and positive_score <= 2:
        status = "monitor_only"
        confidence = 32
        reasons.append("虽然存在重复通信，但上下文中的主要证据都指向计划内活动或正常维护。")
    elif suspicious_count >= 3 and positive_score > negative_score:
        status = "confirmed_incident"
        confidence = min(92, 68 + suspicious_count * 6 + len(repeated_infra) * 4)
        reasons.append("最小上下文中已出现多条高风险相关事件，且正向恶意信号明显强于反证。")
        if repeated_infra:
            reasons.append("同一批外部基础设施在最小上下文里被重复命中，具备持续通信特征。")
    elif benign_count >= max(2, suspicious_count + 1):
        status = "monitor_only"
        confidence = 38
        reasons.append("上下文中的多数事件可以被计划内活动或正常变更解释。")
    else:
        status = "needs_review"
        confidence = 58
        reasons.append("当前上下文已形成关联，但证据强度仍不足以自动确认事件。")

    seed_family_hint = _meaningful_family_hint(seed_event)
    if seed_family_hint:
        reasons.append(f"seed alert 自带家族/工具提示：{seed_family_hint}。")

    return {
        "step": "context_aware_verify",
        "status": status,
        "status_label": _status_label(status),
        "confidence": confidence,
        "reasons": reasons,
        "suspicious_count": suspicious_count,
        "benign_count": benign_count,
        "positive_score": positive_score,
        "negative_score": negative_score,
        "repeated_infrastructure": repeated_infra,
    }


def _extract_entities(seed_event: Dict[str, Any], events: List[Dict[str, Any]], *, seed_event_id: str) -> Dict[str, Any]:
    seed_src = ((seed_event.get("src") or {}).get("ip")) or ""
    seed_dst = ((seed_event.get("dst") or {}).get("ip")) or ""
    seed_asset = ""
    observed_assets = unique_preserve_order(item.get("asset_id") for item in events)
    for item in events:
        if str(item.get("id") or "") == seed_event_id:
            seed_asset = str(item.get("asset_id") or "").strip()
            break
    supporting_by_asset: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    lateral_target_ips = {
        str(item.get("dst_ip") or "").strip()
        for item in events
        if "lateral-movement" in infer_stages(item) and str(item.get("dst_ip") or "").strip()
    }
    for item in events:
        asset_id = str(item.get("asset_id") or "").strip()
        if asset_id and str(item.get("role") or "") in {"seed", "supporting"}:
            supporting_by_asset[asset_id].append(item)

    suspected_assets: List[str] = []
    candidate_seed_asset = seed_asset or (observed_assets[0] if observed_assets else "")
    for asset_id, asset_events in supporting_by_asset.items():
        if asset_id == candidate_seed_asset:
            suspected_assets.append(asset_id)
            continue
        stage_labels = {
            stage
            for item in asset_events
            for stage in infer_stages(item)
        }
        asset_src_ips = {
            str(item.get("src_ip") or "").strip()
            for item in asset_events
            if str(item.get("src_ip") or "").strip()
        }
        high_risk_stage = bool(stage_labels & {"initial-access", "execution", "lateral-movement", "exfiltration"})
        repeated_support = len(asset_events) >= 2
        lateral_targeted = any(ip in lateral_target_ips for ip in asset_src_ips)
        if high_risk_stage or repeated_support or lateral_targeted:
            suspected_assets.append(asset_id)

    suspected_assets = unique_preserve_order(suspected_assets)
    if not seed_asset and suspected_assets:
        seed_asset = suspected_assets[0]
    context_or_candidate_assets = {
        str(item.get("asset_id") or "").strip()
        for item in events
        if str(item.get("asset_id") or "").strip()
        and str(item.get("role") or "").strip() in {"context", "candidate"}
    }
    related_assets = [
        asset
        for asset in observed_assets
        if asset not in suspected_assets and asset in context_or_candidate_assets
    ]
    incident_assets = unique_preserve_order(([seed_asset] if seed_asset else []) + suspected_assets + related_assets)

    primary_external_ips = unique_preserve_order(
        [seed_dst] + [item.get("dst_ip") for item in events if str(item.get("role") or "") in {"seed", "supporting"}]
    )
    contextual_external_ips = unique_preserve_order(
        item.get("dst_ip") for item in events if str(item.get("role") or "") == "counterevidence"
    )
    primary_domains = unique_preserve_order(
        item.get("domain") for item in events if str(item.get("role") or "") in {"seed", "supporting"}
    )
    contextual_domains = unique_preserve_order(
        item.get("domain") for item in events if str(item.get("role") or "") == "counterevidence"
    )

    return {
        "seed_asset": seed_asset or None,
        "assets": incident_assets,
        "observed_assets": observed_assets,
        "suspected_assets": suspected_assets,
        "related_assets": related_assets,
        "internal_ips": unique_preserve_order([seed_src] + [item.get("src_ip") for item in events]),
        "external_ips": unique_preserve_order([seed_dst] + [item.get("dst_ip") for item in events]),
        "primary_external_ips": primary_external_ips,
        "contextual_external_ips": contextual_external_ips,
        "domains": unique_preserve_order(item.get("domain") for item in events),
        "primary_domains": primary_domains,
        "contextual_domains": contextual_domains,
        "users": unique_preserve_order(item.get("user") for item in events),
    }


def _build_timeline(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [
        {
            "event_id": item["id"],
            "ts": item.get("ts"),
            "kind": item.get("kind"),
            "classification": item.get("classification"),
            "role": item.get("role"),
            "stages": list(item.get("stages") or []),
            "summary": item.get("summary"),
        }
        for item in events
    ]


def _build_evidence_clusters(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    buckets: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"title": "", "summary": "", "event_ids": [], "details": []})
    for event in events:
        stages = infer_stages(event)
        classification = str(event.get("classification") or "unknown").strip().lower()
        role = str(event.get("role") or "").strip()
        if role == "candidate":
            key = "candidate"
            buckets[key]["title"] = "待验证关联线索"
            buckets[key]["summary"] = "这些事件是通过共享 pivot 扩展出来的关联线索，但尚未完成独立验证。"
        elif "command-and-control" in stages:
            key = "c2"
            buckets[key]["title"] = "C2 / Beacon 证据簇"
            buckets[key]["summary"] = "多条事件指向同一批外联基础设施，并表现出重复 beacon 特征。"
        elif "execution" in stages:
            key = "execution"
            buckets[key]["title"] = "执行痕迹证据簇"
            buckets[key]["summary"] = "事件簇中已经出现主机侧执行或载荷落地后的行为。"
        elif classification == "benign":
            key = "counterevidence"
            buckets[key]["title"] = "反证 / 基线解释"
            buckets[key]["summary"] = "这些事件提供了计划内活动或正常运维背景。"
        else:
            key = "supporting"
            buckets[key]["title"] = "支撑性上下文"
            buckets[key]["summary"] = "这些事件补足了 seed alert 的上下文。"

        buckets[key]["event_ids"].append(event["id"])
        buckets[key]["details"].append(_event_details(event))

    return [value for value in buckets.values() if value.get("event_ids")]


def _build_focus_statement(
    *,
    status: str,
    entities: Dict[str, Any],
    scope: Dict[str, Any],
    events: List[Dict[str, Any]],
) -> str:
    primary_assets = list(entities.get("suspected_assets") or [])
    related_assets = list(entities.get("related_assets") or [])
    indicators = list(scope.get("primary_external_indicators") or [])
    asset_text = "、".join(primary_assets) if primary_assets else "种子资产"
    related_text = "、".join(related_assets[:2])
    indicator_text = "、".join(indicators[:3]) if indicators else "种子命中基础设施"
    has_execution = any("execution" in infer_stages(item) for item in events)

    if status == "confirmed_incident":
        if has_execution:
            return f"{asset_text} 围绕 {indicator_text} 的重复外联已经延伸到主机侧执行，事件闭环已经基本形成。"
        return f"{asset_text} 在短时间内围绕 {indicator_text} 出现重复通信，单条告警已经扩展为连续事件链。"
    if status == "monitor_only":
        return f"虽然 seed alert 命中了 {indicator_text}，但同时间窗内的整体证据更符合维护或更新背景。"
    if related_text:
        return f"当前主支撑信号仍集中在 {asset_text}；{related_text} 仅表现出共享基础设施上的弱关联，暂时不能按扩散处理。"
    return f"当前主支撑信号主要来自 {asset_text} 围绕 {indicator_text} 的重复通信，但还缺少足够强的后续证据。"


def _build_positive_summary(
    *,
    status: str,
    positive_events: List[Dict[str, Any]],
    scope: Dict[str, Any],
    entities: Dict[str, Any],
) -> str:
    indicators = list(scope.get("primary_external_indicators") or [])
    repeated_assets = list(entities.get("suspected_assets") or [])
    indicator_text = "、".join(indicators[:3]) if indicators else "同一批外部基础设施"
    asset_text = "、".join(repeated_assets) if repeated_assets else "种子资产"
    execution_events = [item for item in positive_events if "execution" in infer_stages(item)]
    repeated_flows = [
        item for item in positive_events if str(item.get("kind") or "").strip().lower() in {"flow", "alert", "dns"}
    ]

    if status == "confirmed_incident":
        if execution_events:
            return f"{asset_text} 先围绕 {indicator_text} 形成重复外联，随后又出现主机侧执行痕迹，因此判断已经超过单点命中。"
        return f"{asset_text} 围绕 {indicator_text} 形成了重复通信链，已经能够支撑事件成立。"
    if status == "monitor_only":
        if repeated_flows:
            return "唯一的主支撑仍然是 seed alert 本身，它没有得到更多恶意侧信号的放大。"
        return "当前缺少能独立支撑入侵结论的正向证据。"
    if execution_events:
        return f"目前最强的支撑来自 {asset_text} 围绕 {indicator_text} 的重复通信以及后续主机侧执行线索；但执行细节、载荷或影响范围仍不足以直接推进为确认事件。"
    if len(repeated_flows) >= 2:
        return f"目前最强的支撑来自 {asset_text} 围绕 {indicator_text} 的重复通信，但这条链还没有延伸到执行或扩散层。"
    return "当前只有有限的正向异常信号，证据链还不够长。"


def _build_counter_summary(
    *,
    status: str,
    counterevidence_events: List[Dict[str, Any]],
    entities: Dict[str, Any],
) -> str:
    if counterevidence_events:
        counter_assets = unique_preserve_order(item.get("asset_id") for item in counterevidence_events)
        tags = {
            str(tag or "").strip().lower()
            for item in counterevidence_events
            for tag in list(item.get("tags") or [])
        }
        if "maintenance" in tags or "patching" in tags:
            if len(counter_assets) > 1:
                return "反证主要来自维护窗口、签名更新以及兄弟资产同步访问，这些背景足以解释为什么不能只凭 seed alert 直接定性。"
            return "反证主要来自维护窗口和签名更新流量，这些背景足以解释为什么不能只凭 seed alert 直接定性。"
        return "当前也观察到能够解释该通信的正常背景，需要把种子命中放回整体上下文。"

    related_assets = list(entities.get("related_assets") or [])
    if status == "needs_review" and related_assets:
        return "其余关联资产目前更多体现为范围参考，而不是已经受影响的直接证据。"
    return ""


def _build_decision_basis(
    *,
    verdict: Dict[str, Any],
    events: List[Dict[str, Any]],
    evidence_clusters: List[Dict[str, Any]],
    entities: Dict[str, Any],
    scope: Dict[str, Any],
) -> Dict[str, Any]:
    positive_events = [
        item
        for item in events
        if str(item.get("role") or "") in {"seed", "supporting"} and str(item.get("classification") or "").strip().lower() != "benign"
    ]
    positive_events.sort(
        key=lambda item: (
            0 if str(item.get("role") or "") == "seed" else 1,
            -suspicion_score(item),
            str(item.get("ts") or ""),
        )
    )
    counterevidence_events = [item for item in events if str(item.get("role") or "") == "counterevidence"]
    counterevidence_events.sort(key=lambda item: (suspicion_score(item), str(item.get("ts") or "")))

    cluster_map = {str(item.get("title") or ""): item for item in evidence_clusters}
    status = str(verdict.get("status") or "").strip()
    seed_asset = str(entities.get("seed_asset") or "").strip()
    positives = [
        {
            "event_id": item.get("id"),
            "summary": item.get("summary"),
            "kind": item.get("kind"),
            "role": item.get("role"),
            "ts": item.get("ts"),
            "asset_id": item.get("asset_id"),
            "classification": item.get("classification"),
            "stages": list(item.get("stages") or []),
            "indicator_text": _event_indicator_text(item),
            "detail": _event_details(item),
            "why_it_matters": _event_evidence_note(item, status=status, seed_asset=seed_asset),
        }
        for item in positive_events[:6]
    ]
    counters = [
        {
            "event_id": item.get("id"),
            "summary": item.get("summary"),
            "kind": item.get("kind"),
            "role": item.get("role"),
            "ts": item.get("ts"),
            "asset_id": item.get("asset_id"),
            "classification": item.get("classification"),
            "stages": list(item.get("stages") or []),
            "indicator_text": _event_indicator_text(item),
            "detail": _event_details(item),
            "why_it_matters": _event_evidence_note(item, status=status, seed_asset=seed_asset),
        }
        for item in counterevidence_events[:4]
    ]

    if status == "confirmed_incident":
        narrative = "决策主要建立在种子告警后的重复外联、同基础设施复现以及后续执行线索之上。"
    elif status == "monitor_only":
        narrative = "决策主要建立在明确的维护窗口、重复的正常更新流量和可解释的背景证据之上。"
    else:
        narrative = "当前已有可疑关联，但支撑证据还不足以推进为确认事件。"

    supporting_cluster = cluster_map.get("C2 / Beacon 证据簇") or cluster_map.get("执行痕迹证据簇") or {}
    counter_cluster = cluster_map.get("反证 / 基线解释") or {}
    return {
        "narrative": narrative,
        "focus_statement": _build_focus_statement(status=status, entities=entities, scope=scope, events=events),
        "positive_summary": _build_positive_summary(
            status=status,
            positive_events=positive_events,
            scope=scope,
            entities=entities,
        ),
        "counter_summary": _build_counter_summary(
            status=status,
            counterevidence_events=counterevidence_events,
            entities=entities,
        ),
        "positive_signals": positives,
        "counterevidence": counters,
        "supporting_cluster": {
            "title": supporting_cluster.get("title"),
            "summary": supporting_cluster.get("summary"),
        }
        if supporting_cluster
        else None,
        "counter_cluster": {
            "title": counter_cluster.get("title"),
            "summary": counter_cluster.get("summary"),
        }
        if counter_cluster
        else None,
    }


def _build_incident_summary(
    *,
    verdict: Dict[str, Any],
    entities: Dict[str, Any],
    scope: Dict[str, Any],
    hypothesis: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "headline": str(hypothesis.get("title") or "").strip(),
        "verdict": str(verdict.get("status_label") or "").strip(),
        "confidence": int(verdict.get("confidence") or 0),
        "seed_asset": entities.get("seed_asset"),
        "suspected_asset_count": len(entities.get("suspected_assets") or []),
        "primary_indicator_count": len(scope.get("primary_external_indicators") or []),
        "time_window": scope.get("time_window") or {},
        "stage_labels": list(hypothesis.get("stages") or []),
    }


def _build_hypothesis(seed_event: Dict[str, Any], verdict: Dict[str, Any], events: List[Dict[str, Any]], entities: Dict[str, Any]) -> Dict[str, Any]:
    all_stages = unique_preserve_order(stage for event in events for stage in infer_stages(event))
    family_hint = _meaningful_family_hint(seed_event)
    status = verdict.get("status")
    suspected_assets = list(entities.get("suspected_assets") or [])
    asset_scope = "多资产" if len(suspected_assets) > 1 else "单资产"
    if status == "confirmed_incident":
        title = f"{asset_scope}疑似 {family_hint or '恶意外联'} 事件"
        if "command-and-control" in all_stages:
            narrative = "最小上下文和扩展事件簇都显示该资产与同一批外部基础设施发生重复通信，已经具备 C2 / beacon 事件特征。"
        else:
            narrative = "上下文事件已经从单条 alert 扩展到完整事件簇，说明这不是孤立命中。"
    elif status == "monitor_only":
        title = "弱信号已被背景流量部分解释"
        narrative = "当前看到的告警与补充背景更接近计划内活动或正常变更，建议继续观察而不是立即定性为入侵。"
    else:
        title = "上下文已形成，但仍需人工复核"
        if "execution" in all_stages and "exfiltration" in all_stages:
            narrative = "自动聚合已经找到可疑外联、执行线索和数据外传迹象，但关键细节或影响范围仍需人工复核。"
        elif "execution" in all_stages:
            narrative = "自动聚合已经找到可疑外联和执行线索，但执行细节、载荷或后续影响仍需人工复核。"
        elif "initial-access" in all_stages:
            narrative = "自动聚合已经找到初始访问和可疑外联上下文，但尚未看到足以确认执行成功的证据。"
        else:
            narrative = "自动聚合已经找到可关联的上下文，不过现阶段仍缺少足够强的执行或持续控制证据。"
    return {
        "title": title,
        "narrative": narrative,
        "stages": all_stages,
    }


def _build_uncertainties(verdict: Dict[str, Any], events: List[Dict[str, Any]], entities: Dict[str, Any]) -> List[str]:
    items: List[str] = []
    status = verdict.get("status")
    related_assets = list(entities.get("related_assets") or [])
    suspected_assets = list(entities.get("suspected_assets") or [])
    has_execution = any("execution" in infer_stages(event) for event in events)
    candidate_events = [event for event in events if str(event.get("role") or "").strip() == "candidate"]

    if status == "monitor_only":
        items.append("当前降级依赖于维护窗口和更新背景；如果后续在相同指示物上出现脱离基线的重复通信，需要重新升级研判。")
        if related_assets:
            items.append("关联资产出现的同类访问目前更像共享基线，而不是扩散迹象。")
        return unique_preserve_order(items)

    if status == "confirmed_incident":
        if related_assets:
            items.append("虽然已经看到关联资产，但尚未确认这些资产是否与主事件属于同一次扩散。")
        if candidate_events:
            items.append(f"仍有 {len(candidate_events)} 条扩展事件只是通过共享指示物被关联进来，尚未完成独立验证。")
        if not any("initial-access" in infer_stages(event) for event in events):
            items.append("当前事件链主要从外联和执行阶段收敛，初始入侵入口仍未识别。")
        return unique_preserve_order(items)

    if has_execution:
        items.append("虽然已经看到主机侧执行线索，但当前仍缺少更细的命令行、落地文件、持久化或完整影响范围证据。")
    else:
        items.append("当前仍缺少足够强的主机侧执行或扩散证据，自动结论需要结合人工复核。")
    if len(suspected_assets) <= 1:
        items.append("主支撑信号目前仍集中在单个重点资产上，尚未确认存在更大范围扩散。")
    if related_assets:
        items.append("其他关联资产目前更多体现为共享基础设施上的弱关联，仍需逐台确认是否真正受影响。")
    if candidate_events:
        items.append(f"当前仍有 {len(candidate_events)} 条扩展出来的关联线索缺少独立命中或情报支撑。")
    if not has_execution:
        items.append("事件簇中尚未观测到稳定的执行阶段证据。")
    return unique_preserve_order(items)


def _build_recommendations(verdict: Dict[str, Any], entities: Dict[str, Any], scope: Dict[str, Any], events: List[Dict[str, Any]]) -> List[str]:
    status = verdict.get("status")
    assets = entities.get("suspected_assets") or entities.get("observed_assets") or []
    related_assets = entities.get("related_assets") or []
    externals = scope.get("primary_external_indicators") or scope.get("external_indicators") or []
    candidate_events = [event for event in events if str(event.get("role") or "").strip() == "candidate"]
    if status == "confirmed_incident":
        recommendations = [
            f"优先隔离或重点监控资产：{'、'.join(assets) if assets else '相关主机'}。",
            f"在边界和代理设备上排查并封禁外部基础设施：{'、'.join(externals) if externals else 'seed 命中目标'}。",
        ]
        if candidate_events:
            recommendations.append("对扩线得到的关联事件逐条补做独立验证，确认它们是否也命中本地指纹、IOC 或外部情报。")
        recommendations.append("以 seed 指标和事件簇中的域名 / IP 为 pivot，继续检索同时间窗内的重复通信。")
        return recommendations
    if status == "monitor_only":
        return [
            "保留当前告警与上下文，作为后续相似行为的基线样本。",
            "结合变更窗口、补丁任务和资产画像确认是否需要做白名单或检测规则收敛。",
        ]
    recommendations = [
        "对重点资产补采主机侧日志，确认是否存在执行、持久化或横向移动证据。",
        "继续围绕同域名 / 同 dst_ip / 同 JA4 搜索更宽时间窗内的关联事件。",
    ]
    if candidate_events:
        recommendations.append("优先核验新扩出的关联事件是否存在独立命中，不要只因为共享基础设施就直接并入主证据链。")
    if related_assets:
        recommendations.append(f"把关联资产 {'、'.join(related_assets)} 纳入复核清单，确认它们是共享基础设施背景还是真实受影响对象。")
    return recommendations
