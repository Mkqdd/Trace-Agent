from typing import Any, Dict, List, Optional

from .renderers.artifacts import severity_from_confidence


def _first_non_empty(*values: Any) -> Optional[str]:
    for value in values:
        if isinstance(value, str):
            text = value.strip()
            if text:
                return text
    return None


def _first_label(labels: Any) -> Optional[str]:
    if not isinstance(labels, list):
        return None
    for value in labels:
        if isinstance(value, str):
            text = value.strip()
            if text:
                return text
    return None


def _coerce_int(*values: Any, default: int) -> int:
    for value in values:
        if value is None or value == "":
            continue
        try:
            return int(value)
        except Exception:
            continue
    return default


def _append_evidence(evidence: List[Dict[str, Any]], item: Dict[str, Any]) -> None:
    url = str(item.get("url") or "").strip()
    claim = str(item.get("claim") or "").strip()
    source = str(item.get("source") or "").strip()
    if url:
        for existing in evidence:
            if str(existing.get("url") or "").strip() == url:
                return
    elif claim and source:
        for existing in evidence:
            if (
                str(existing.get("source") or "").strip() == source
                and str(existing.get("claim") or "").strip() == claim
            ):
                return
    item["id"] = f"e{len(evidence) + 1:02d}"
    evidence.append(item)


def _estimate_confidence(
    *,
    event: Dict[str, Any],
    obs_fp: Optional[Dict[str, Any]],
    obs_family: Optional[Dict[str, Any]],
    family: str,
) -> int:
    explicit = _coerce_int((obs_fp or {}).get("confidence"), (event.get("enrichment") or {}).get("confidence"), default=-1)
    if explicit >= 0:
        return explicit

    score = 40
    if family != "Unknown":
        score += 10

    if isinstance(obs_fp, dict):
        if obs_fp.get("enabled") is True:
            score += 15
        if obs_fp.get("ok") is True and (obs_fp.get("results") or []):
            score += 10

    if isinstance(obs_family, dict) and obs_family.get("ok") is True and (obs_family.get("raw") or {}).get("results"):
        score += 10

    return max(20, min(95, score))


def _build_evidence(
    *,
    event: Dict[str, Any],
    obs_fp: Optional[Dict[str, Any]],
    obs_family: Optional[Dict[str, Any]],
    family: str,
    confidence: int,
) -> List[Dict[str, Any]]:
    evidence: List[Dict[str, Any]] = []
    fp = event.get("trigger_fingerprint") or {}
    enrichment = event.get("enrichment") or {}
    src = event.get("src") or {}
    dst = event.get("dst") or {}

    _append_evidence(
        evidence,
        {
            "kind": "event",
            "source": "alert",
            "type": "matched_alert",
            "query": None,
            "url": None,
            "title": "命中后告警事件",
            "claim": (
                f"在 {event.get('event_time')} 观察到 {src.get('ip')} -> {dst.get('ip')} 的 "
                f"{event.get('protocol')} 流量，命中 {fp.get('type')} 指纹 {fp.get('value')}。"
            ),
            "confidence": 95,
            "raw_ref": "event.raw_alert",
        },
    )

    family_hint = _first_non_empty(enrichment.get("info"), family)
    if family_hint:
        _append_evidence(
            evidence,
            {
                "kind": "hint",
                "source": enrichment.get("reference") or "alert_enrichment",
                "type": "family_hint",
                "query": None,
                "url": None,
                "title": "告警附带家族提示",
                "claim": f"原始告警将该事件关联到家族/标签 {family_hint}。",
                "confidence": 70,
                "raw_ref": "event.enrichment",
            },
        )

    if isinstance(obs_fp, dict):
        if obs_fp.get("enabled") is True:
            stats = obs_fp.get("last_analysis_stats") or {}
            stat_text = ""
            if isinstance(stats, dict) and stats:
                stat_text = f"VT 分析统计为 {stats}。"
            _append_evidence(
                evidence,
                {
                    "kind": "enrichment",
                    "source": "VirusTotal",
                    "type": "vt_ip",
                    "query": str(fp.get("value") or ""),
                    "url": None,
                    "title": "VirusTotal IP 富化",
                    "claim": (
                        f"VirusTotal 返回 IP {obs_fp.get('ip')} 的信誉/归属信息。"
                        f"{stat_text}".strip()
                    ),
                    "confidence": _coerce_int(obs_fp.get("confidence"), default=confidence),
                    "raw_ref": "observations.fingerprint_enrichment",
                },
            )
        elif obs_fp.get("ok") is True:
            for index, result in enumerate((obs_fp.get("results") or [])[:3]):
                title = str(result.get("title") or "").strip() or f"搜索证据 {index + 1}"
                snippet = str(result.get("snippet") or "").strip()
                _append_evidence(
                    evidence,
                    {
                        "kind": "search_result",
                        "source": result.get("source") or obs_fp.get("mode") or "web_search",
                        "type": "fingerprint_search",
                        "query": obs_fp.get("query"),
                        "url": result.get("url"),
                        "title": title,
                        "claim": snippet or title,
                        "confidence": 60,
                        "raw_ref": f"observations.fingerprint_enrichment.results[{index}]",
                    },
                )

    family_raw = (obs_family or {}).get("raw") if isinstance(obs_family, dict) else None
    family_results = (family_raw or {}).get("results") if isinstance(family_raw, dict) else []
    if isinstance(family_results, list):
        for index, result in enumerate(family_results[:3]):
            title = str(result.get("title") or "").strip() or f"{family} 家族情报 {index + 1}"
            snippet = str(result.get("snippet") or "").strip()
            _append_evidence(
                evidence,
                {
                    "kind": "family_intel",
                    "source": result.get("source") or (family_raw or {}).get("mode") or "family_intel",
                    "type": "family_search",
                    "query": (obs_family or {}).get("query"),
                    "url": result.get("url"),
                    "title": title,
                    "claim": snippet or title,
                    "confidence": 65,
                    "raw_ref": f"observations.family_intel.raw.results[{index}]",
                },
            )

    return evidence


def _build_findings(
    *,
    event: Dict[str, Any],
    family: str,
    confidence: int,
    severity: str,
    evidence: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    fp = event.get("trigger_fingerprint") or {}
    src = event.get("src") or {}
    dst = event.get("dst") or {}
    event_evidence_id = evidence[0]["id"] if evidence else None
    family_evidence_ids = [item["id"] for item in evidence if item.get("type") in {"family_hint", "family_search", "fingerprint_search"}]

    findings: List[Dict[str, Any]] = [
        {
            "id": "f01",
            "title": "命中后恶意流量告警",
            "statement": (
                f"源 {src.get('ip')} 与目的 {dst.get('ip')} 的 {event.get('protocol')} 流量命中 "
                f"{fp.get('type')} 指纹 {fp.get('value')}。"
            ),
            "confidence": 95,
            "severity": severity,
            "based_on": [event_evidence_id] if event_evidence_id else [],
        }
    ]

    if family != "Unknown":
        findings.append(
            {
                "id": "f02",
                "title": "疑似家族关联",
                "statement": f"该事件当前更可能与 {family} 相关。",
                "confidence": confidence,
                "severity": severity,
                "based_on": family_evidence_ids,
            }
        )

    if severity in {"中危", "高危"}:
        findings.append(
            {
                "id": "f03",
                "title": "建议优先处置",
                "statement": f"基于当前证据强度，事件处置优先级可评估为 {severity}。",
                "confidence": confidence,
                "severity": severity,
                "based_on": [item["id"] for item in evidence[:2]],
            }
        )

    return findings


def _build_uncertainties(
    *,
    obs_fp: Optional[Dict[str, Any]],
    obs_family: Optional[Dict[str, Any]],
    family: str,
) -> List[Dict[str, Any]]:
    uncertainties: List[Dict[str, Any]] = []

    if isinstance(obs_fp, dict) and obs_fp.get("enabled") is False:
        uncertainties.append(
            {
                "id": "u01",
                "statement": "未获取到 VirusTotal 的即时信誉结果。",
                "reason": obs_fp.get("note") or obs_fp.get("error") or "外部情报未启用",
            }
        )

    if family == "Unknown":
        uncertainties.append(
            {
                "id": "u02",
                "statement": "当前无法稳定归因到明确的恶意软件家族。",
                "reason": "缺少足够的家族命中线索或外部情报结果。",
            }
        )

    if isinstance(obs_family, dict) and not obs_family.get("ok"):
        uncertainties.append(
            {
                "id": "u03",
                "statement": "家族情报搜索没有成功返回结构化结果。",
                "reason": obs_family.get("error") or "搜索结果不足",
            }
        )

    return uncertainties


def _build_actions(
    *,
    event: Dict[str, Any],
    family: str,
) -> List[Dict[str, Any]]:
    fp = event.get("trigger_fingerprint") or {}
    src = event.get("src") or {}
    dst = event.get("dst") or {}
    actions: List[Dict[str, Any]] = [
        {
            "id": "a01",
            "priority": "high",
            "action": f"排查并视情况隔离源主机 {src.get('ip')}。",
            "rationale": "源主机产生了命中后恶意流量，需要确认是否存在持续外联或二次投递行为。",
        },
        {
            "id": "a02",
            "priority": "high",
            "action": f"在边界侧监控或阻断与 {dst.get('ip')} 相关的后续通信。",
            "rationale": "当前告警中的网络目的地址是最直接的外联对象，应优先纳入监测范围。",
        },
        {
            "id": "a03",
            "priority": "medium",
            "action": f"基于 {fp.get('type')} 指纹 {fp.get('value')} 在历史流量中做横向检索。",
            "rationale": "可以快速判断是否存在相同指纹的历史通信或更多受影响资产。",
        },
    ]

    if family != "Unknown":
        actions.append(
            {
                "id": "a04",
                "priority": "medium",
                "action": f"结合 {family} 相关 TTP 做主机侧排查与 IOC 扩线。",
                "rationale": "已有家族线索时，可以更有针对性地检查样本行为、持久化方式和额外外联特征。",
            }
        )

    return actions


def build_analysis(
    *,
    event: Dict[str, Any],
    mode: str,
    obs_fp: Optional[Dict[str, Any]] = None,
    obs_family: Optional[Dict[str, Any]] = None,
    report_markdown: Optional[str] = None,
    report_path: Optional[str] = None,
) -> Dict[str, Any]:
    enrichment = dict(event.get("enrichment") or {})
    family = _first_non_empty(
        (obs_family or {}).get("family"),
        enrichment.get("info"),
        _first_label(enrichment.get("labels")),
    ) or "Unknown"

    labels: List[str] = []
    existing_labels = enrichment.get("labels") or []
    if isinstance(existing_labels, list):
        for value in existing_labels:
            if isinstance(value, str):
                text = value.strip()
                if text and text not in labels:
                    labels.append(text)
    if family != "Unknown" and family not in labels:
        labels.append(family)

    confidence = _estimate_confidence(event=event, obs_fp=obs_fp, obs_family=obs_family, family=family)
    severity = severity_from_confidence(confidence)

    destination_enrichment: Dict[str, Any] = {}
    if isinstance(enrichment.get("dst_ip"), dict):
        destination_enrichment.update(enrichment.get("dst_ip") or {})

    fp_type = str((event.get("trigger_fingerprint") or {}).get("type") or "").upper()
    if fp_type == "IP" and isinstance(obs_fp, dict) and str((obs_fp or {}).get("ip") or "") == str((event.get("dst") or {}).get("ip") or ""):
        for key in ("enabled", "ip", "country", "asn", "as_owner", "reputation", "last_analysis_stats"):
            if key in obs_fp:
                destination_enrichment[key] = obs_fp[key]

    evidence = _build_evidence(event=event, obs_fp=obs_fp, obs_family=obs_family, family=family, confidence=confidence)
    findings = _build_findings(event=event, family=family, confidence=confidence, severity=severity, evidence=evidence)
    uncertainties = _build_uncertainties(obs_fp=obs_fp, obs_family=obs_family, family=family)
    recommended_actions = _build_actions(event=event, family=family)

    analysis: Dict[str, Any] = {
        "mode": mode,
        "event": event,
        "entities": {
            "src_ip": (event.get("src") or {}).get("ip"),
            "dst_ip": (event.get("dst") or {}).get("ip"),
            "protocol": event.get("protocol"),
            "fingerprint": {
                "type": (event.get("trigger_fingerprint") or {}).get("type"),
                "value": (event.get("trigger_fingerprint") or {}).get("value"),
                "matched": (event.get("trigger_fingerprint") or {}).get("matched"),
            },
            "family_hint": enrichment.get("info"),
            "reference": enrichment.get("reference"),
            "update_time": enrichment.get("update_time"),
        },
        "observations": {
            "fingerprint_enrichment": obs_fp,
            "family_intel": obs_family,
        },
        "evidence": evidence,
        "findings": findings,
        "uncertainties": uncertainties,
        "recommended_actions": recommended_actions,
        "derived": {
            "family": family,
            "labels": labels,
            "confidence": confidence,
            "severity": severity,
            "destination_enrichment": destination_enrichment,
        },
    }

    if report_markdown is not None or report_path is not None:
        analysis["report"] = {
            "path": report_path,
            "content": report_markdown or "",
        }

    return analysis
