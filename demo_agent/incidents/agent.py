from __future__ import annotations

import json
import os
import time
import ipaddress
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from ..tools import (
    extract_claim_candidates_from_page,
    extract_entities_from_page,
    fetch_page_content,
    malware_profile_lookup,
    pivot_related_indicators,
    technical_source_search,
    threatfox_ioc_lookup,
    urlhaus_ioc_lookup,
)
from ..types.event import normalize_alert
from .contracts import infer_stages, parse_timestamp, severity_from_confidence, suspicion_score, unique_preserve_order
from .pipeline import (
    _annotate_events,
    _build_decision_basis,
    _build_evidence_clusters,
    _build_hypothesis,
    _build_incident_summary,
    _build_recommendations,
    _build_timeline,
    _build_uncertainties,
    _extract_entities,
)
from .render import build_incident_report_outline, build_incident_topology, render_incident_report_with_llm
from .store import FixtureTraceStoreAdapter, TraceStore


DEFAULT_BUDGETS = {
    "max_steps": 8,
    "max_tool_calls": 12,
    "max_event_queries": 8,
    "max_intel_queries": 4,
    "max_runtime_s": 120,
}

EVENT_TOOL_NAMES = {"search_seed_context", "search_related_events", "expand_asset_scope"}
INTEL_TOOL_NAMES = {
    "technical_source_search",
    "malware_profile_lookup",
    "pivot_related_indicators",
    "threatfox_ioc_lookup",
    "urlhaus_ioc_lookup",
}
PAGE_TOOL_NAMES = {"fetch_page_content", "extract_claim_candidates_from_page", "extract_entities_from_page"}
ALL_TOOL_NAMES = EVENT_TOOL_NAMES | INTEL_TOOL_NAMES | PAGE_TOOL_NAMES


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


def _tool_json(tool: Any, payload: Dict[str, Any]) -> Dict[str, Any]:
    try:
        raw = tool.invoke(payload)
        if isinstance(raw, dict):
            return raw
        if isinstance(raw, str):
            return json.loads(raw)
    except Exception as exc:
        return {"ok": False, "error": str(exc), "payload": payload}
    return {"ok": False, "error": "empty tool response", "payload": payload}


def _extract_indicator_type(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if text.startswith(("http://", "https://")):
        return "URL"
    if "." in text and "/" not in text and " " not in text:
        return "DOMAIN"
    parts = text.split(".")
    if len(parts) == 4 and all(part.isdigit() for part in parts):
        return "IP"
    return ""


def _is_internal_ip(value: str) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    try:
        ip_obj = ipaddress.ip_address(text)
        internal_networks = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("127.0.0.0/8"),
            ipaddress.ip_network("169.254.0.0/16"),
        )
        return any(ip_obj in network for network in internal_networks)
    except ValueError:
        return False


def _seed_asset_hint(seed_event: Dict[str, Any]) -> str:
    raw_alert = seed_event.get("raw_alert") or {}
    return str(raw_alert.get("asset_id") or raw_alert.get("hostname") or raw_alert.get("host") or "").strip()


def _initial_open_questions(seed_event: Dict[str, Any]) -> List[Dict[str, Any]]:
    seed_dst = str(((seed_event.get("dst") or {}).get("ip")) or "").strip()
    fingerprint = str((((seed_event.get("trigger_fingerprint") or {}).get("value")) or "")).strip()
    questions = [
        {
            "id": "build_context",
            "priority": "high",
            "question": "围绕 seed alert 建立最小事件上下文，确认它是不是孤立命中。",
        },
        {
            "id": "expand_scope",
            "priority": "high",
            "question": "确认是否存在同资产重复通信、同基础设施复现或关联资产扩展。",
        },
        {
            "id": "ground_infra",
            "priority": "medium",
            "question": f"补充 {seed_dst or fingerprint or 'seed 指示物'} 的外部基础设施或家族背景。",
        },
        {
            "id": "check_counterevidence",
            "priority": "medium",
            "question": "确认是否存在维护窗口、补丁、备份或共享基线等反证。",
        },
    ]
    return questions


def _initial_working_hypotheses(seed_event: Dict[str, Any]) -> List[Dict[str, Any]]:
    family_hint = _meaningful_family_hint(seed_event)
    primary_title = f"疑似 {family_hint} 相关外联事件" if family_hint else "疑似恶意外联事件"
    return [
        {
            "id": "primary",
            "kind": "primary",
            "title": primary_title,
            "score": 0,
            "status": "open",
            "supporting_observation_ids": [],
            "counter_observation_ids": [],
        },
        {
            "id": "secondary",
            "kind": "secondary",
            "title": "共享基础设施上的弱关联或待复核扩展",
            "score": 0,
            "status": "open",
            "supporting_observation_ids": [],
            "counter_observation_ids": [],
        },
        {
            "id": "benign",
            "kind": "benign",
            "title": "计划内活动、正常更新或共享基线解释",
            "score": 0,
            "status": "open",
            "supporting_observation_ids": [],
            "counter_observation_ids": [],
        },
    ]


def _initial_session_state(seed_event: Dict[str, Any], budgets: Dict[str, int]) -> Dict[str, Any]:
    seed_src = str(((seed_event.get("src") or {}).get("ip")) or "").strip()
    seed_dst = str(((seed_event.get("dst") or {}).get("ip")) or "").strip()
    fingerprint = str((((seed_event.get("trigger_fingerprint") or {}).get("value")) or "")).strip()
    return {
        "goal": f"围绕 seed alert {seed_src or 'unknown'} -> {seed_dst or fingerprint or 'unknown'} 收敛为事件级研判结论。",
        "budgets": {
            "max_steps": int(budgets["max_steps"]),
            "remaining_steps": int(budgets["max_steps"]),
            "max_tool_calls": int(budgets["max_tool_calls"]),
            "remaining_tool_calls": int(budgets["max_tool_calls"]),
            "max_event_queries": int(budgets["max_event_queries"]),
            "remaining_event_queries": int(budgets["max_event_queries"]),
            "max_intel_queries": int(budgets["max_intel_queries"]),
            "remaining_intel_queries": int(budgets["max_intel_queries"]),
            "max_runtime_s": int(budgets["max_runtime_s"]),
        },
        "step_index": 0,
        "tool_history": [],
        "open_questions": _initial_open_questions(seed_event),
        "working_hypotheses": _initial_working_hypotheses(seed_event),
        "stop_reason": "",
        "consecutive_low_value_steps": 0,
        "policy_mode": "heuristic_fallback",
    }


def _initial_incident_state(seed_event: Dict[str, Any]) -> Dict[str, Any]:
    src_ip = str(((seed_event.get("src") or {}).get("ip")) or "").strip()
    dst_ip = str(((seed_event.get("dst") or {}).get("ip")) or "").strip()
    fingerprint = str((((seed_event.get("trigger_fingerprint") or {}).get("value")) or "")).strip()
    seed_asset = _seed_asset_hint(seed_event)
    return {
        "seed": seed_event,
        "pivots": {
            "seed_ts": str(seed_event.get("event_time") or ""),
            "asset_ids": unique_preserve_order([seed_asset]),
            "src_ips": unique_preserve_order([src_ip]),
            "dst_ips": unique_preserve_order([dst_ip]),
            "domains": [],
            "fingerprints": unique_preserve_order([fingerprint]),
        },
        "observations": [],
        "known_events": {},
        "page_candidates": [],
        "entities": {
            "seed_asset": seed_asset or None,
            "assets": unique_preserve_order([seed_asset]),
            "domains": [],
            "external_ips": unique_preserve_order([dst_ip]),
            "internal_ips": unique_preserve_order([src_ip]),
            "families": unique_preserve_order([_meaningful_family_hint(seed_event)]),
        },
        "timeline": [],
        "scope": {},
        "evidence_ledger": [],
        "counterevidence": [],
        "verdict": {"status": "needs_review", "status_label": "待人工复核"},
        "confidence": 45,
        "report_ready": False,
        "context_bundle": {"minimal_event_ids": [], "minimal_event_count": 0},
    }


def _compose_digest(seed_event: Dict[str, Any], incident_state: Dict[str, Any], session_state: Dict[str, Any]) -> str:
    lines: List[str] = []
    lines.append("Seed alert summary:")
    lines.append(
        f"- src={((seed_event.get('src') or {}).get('ip')) or 'unknown'} "
        f"dst={((seed_event.get('dst') or {}).get('ip')) or 'unknown'} "
        f"fp={(((seed_event.get('trigger_fingerprint') or {}).get('value')) or 'unknown')}"
    )
    family_hint = _meaningful_family_hint(seed_event)
    if family_hint:
        lines.append(f"- family_hint={family_hint}")
    hypotheses = list(session_state.get("working_hypotheses") or [])
    if hypotheses:
        lines.append("Current working hypotheses:")
        for item in hypotheses[:3]:
            lines.append(f"- {item.get('id')}: {item.get('title')} (score={item.get('score')})")
    events = list((incident_state.get("known_events") or {}).values())
    events.sort(key=lambda item: str(item.get("ts") or ""))
    if events:
        lines.append("Event summaries:")
        for item in events[:10]:
            lines.append(f"- {item.get('summary')}")
    ledger = list(incident_state.get("evidence_ledger") or [])
    if ledger:
        lines.append("Evidence ledger:")
        for item in ledger[:8]:
            refs = ",".join(item.get("event_ids") or [])
            lines.append(f"- {item.get('relation')}: {item.get('summary')} [{refs}]")
    return "\n".join(lines)


def _tool_called(session_state: Dict[str, Any], tool_name: str) -> bool:
    return any(str(item.get("tool_name") or "") == tool_name for item in list(session_state.get("tool_history") or []))


def _page_candidate_urls(incident_state: Dict[str, Any]) -> List[str]:
    return unique_preserve_order(item.get("url") for item in list(incident_state.get("page_candidates") or []))


def _action_candidates(seed_event: Dict[str, Any], session_state: Dict[str, Any], incident_state: Dict[str, Any]) -> List[Dict[str, Any]]:
    budgets = session_state.get("budgets") or {}
    remaining_event = int(budgets.get("remaining_event_queries") or 0)
    remaining_intel = int(budgets.get("remaining_intel_queries") or 0)
    candidates: List[Dict[str, Any]] = []
    pivots = incident_state.get("pivots") or {}
    entities = incident_state.get("entities") or {}
    family_hint = _meaningful_family_hint(seed_event)
    primary_indicator = (
        (list((incident_state.get("scope") or {}).get("primary_external_indicators") or []) or [None])[0]
        or (list((entities.get("external_ips") or [])) or [None])[0]
        or (list((entities.get("domains") or [])) or [None])[0]
    )
    digest = _compose_digest(seed_event, incident_state, session_state)
    page_urls = _page_candidate_urls(incident_state)

    if not _tool_called(session_state, "search_seed_context") and remaining_event > 0:
        candidates.append(
            {
                "tool_name": "search_seed_context",
                "category": "event",
                "question": "建立围绕 seed alert 的最小上下文。",
                "params": {},
                "trace_params": {
                    "src_ip": ((seed_event.get("src") or {}).get("ip")) or "",
                    "dst_ip": ((seed_event.get("dst") or {}).get("ip")) or "",
                },
                "expected_gain": "确认 seed 是否孤立、是否已有重复通信或相邻事件。",
            }
        )

    if not _tool_called(session_state, "search_related_events") and remaining_event > 0:
        candidates.append(
            {
                "tool_name": "search_related_events",
                "category": "event",
                "question": "基于当前 pivot 扩大事件簇。",
                "params": {
                    "pivots": pivots,
                    "window_minutes": 120,
                    "limit": 60,
                },
                "trace_params": {
                    "asset_ids": pivots.get("asset_ids") or [],
                    "dst_ips": pivots.get("dst_ips") or [],
                    "domains": pivots.get("domains") or [],
                },
                "expected_gain": "确认是否存在同资产重复通信、同域名/同 IP 复现或更多可疑事件。",
            }
        )

    related_assets = [asset for asset in list(entities.get("assets") or []) if asset and asset != entities.get("seed_asset")]
    if related_assets and not _tool_called(session_state, "expand_asset_scope") and remaining_event > 0:
        candidates.append(
            {
                "tool_name": "expand_asset_scope",
                "category": "event",
                "question": "围绕关联资产补采主机上下文。",
                "params": {"asset_ids": related_assets, "window_minutes": 180, "limit": 60},
                "trace_params": {"asset_ids": related_assets},
                "expected_gain": "确认关联资产是共享背景，还是已经进入同一事件范围。",
            }
        )

    allow_live_intel = str(os.getenv("INCIDENT_AGENT_LIVE_INTEL") or "").strip().lower() in {"1", "true", "yes"}
    if family_hint and allow_live_intel and not _tool_called(session_state, "technical_source_search") and remaining_intel > 0:
        candidates.append(
            {
                "tool_name": "technical_source_search",
                "category": "intel",
                "question": "补齐家族行为与基础设施背景。",
                "params": {"query": family_hint, "goal": "behavior_context", "max_results": 5},
                "trace_params": {"query": family_hint, "goal": "behavior_context"},
                "expected_gain": "确认家族背景能否支撑当前事件解释。",
            }
        )

    if primary_indicator and allow_live_intel and not _tool_called(session_state, "threatfox_ioc_lookup") and remaining_intel > 0:
        candidates.append(
            {
                "tool_name": "threatfox_ioc_lookup",
                "category": "intel",
                "question": "检查关键指示物是否有社区结构化情报。",
                "params": {"indicator_value": primary_indicator, "indicator_type": _extract_indicator_type(str(primary_indicator or ""))},
                "trace_params": {"indicator_value": primary_indicator},
                "expected_gain": "如果命中结构化情报，可快速增强对外部基础设施或家族的解释力。",
            }
        )

    if page_urls and not _tool_called(session_state, "fetch_page_content") and remaining_intel > 0:
        candidates.append(
            {
                "tool_name": "fetch_page_content",
                "category": "page",
                "question": "读取最相关技术页面正文。",
                "params": {"url": page_urls[0], "max_chars": 5000},
                "trace_params": {"url": page_urls[0]},
                "expected_gain": "把检索结果转化为可直接引用的正文证据。",
            }
        )

    if not _tool_called(session_state, "extract_claim_candidates_from_page") and remaining_intel > 0:
        candidates.append(
            {
                "tool_name": "extract_claim_candidates_from_page",
                "category": "page",
                "question": "从当前事件摘要中抽取可用于报告的关键 claim。",
                "params": {"content": digest, "focus": family_hint or str(primary_indicator or "")},
                "trace_params": {"content_preview": digest[:240], "focus": family_hint or str(primary_indicator or "")},
                "expected_gain": "把当前调查事实压缩成结构化证据与 TTP 线索。",
            }
        )

    if not _tool_called(session_state, "extract_entities_from_page") and remaining_intel > 0:
        candidates.append(
            {
                "tool_name": "extract_entities_from_page",
                "category": "page",
                "question": "从当前事件摘要中抽取域名、IP、家族等实体。",
                "params": {"content": digest},
                "trace_params": {"content_preview": digest[:240]},
                "expected_gain": "补齐 pivot 集合，让后续扩查更像真正的调查循环。",
            }
        )

    if primary_indicator and allow_live_intel and not _tool_called(session_state, "urlhaus_ioc_lookup") and remaining_intel > 0:
        candidates.append(
            {
                "tool_name": "urlhaus_ioc_lookup",
                "category": "intel",
                "question": "检查关键指示物是否落在恶意投递或 URL 基础设施视角中。",
                "params": {"indicator_value": primary_indicator, "indicator_type": _extract_indicator_type(str(primary_indicator or ""))},
                "trace_params": {"indicator_value": primary_indicator},
                "expected_gain": "补足围绕域名/IP 的恶意基础设施说明。",
            }
        )

    if family_hint and allow_live_intel and not _tool_called(session_state, "malware_profile_lookup") and remaining_intel > 0:
        candidates.append(
            {
                "tool_name": "malware_profile_lookup",
                "category": "intel",
                "question": "为已知家族补齐高质量 profile。",
                "params": {"query": family_hint, "max_results": 4},
                "trace_params": {"query": family_hint},
                "expected_gain": "补足家族背景和行为概要。",
            }
        )

    if primary_indicator and allow_live_intel and not _tool_called(session_state, "pivot_related_indicators") and remaining_intel > 0:
        candidates.append(
            {
                "tool_name": "pivot_related_indicators",
                "category": "intel",
                "question": "围绕关键指示物搜索二跳 IOC 或基础设施。",
                "params": {"query": str(primary_indicator), "max_results": 5},
                "trace_params": {"query": primary_indicator},
                "expected_gain": "补充与主事件相关的基础设施侧线索。",
            }
        )

    return candidates


def _format_llm_session_summary(session_state: Dict[str, Any], incident_state: Dict[str, Any]) -> Dict[str, Any]:
    ledger = list(incident_state.get("evidence_ledger") or [])
    latest_ledger = [
        {
            "observation_id": item.get("observation_id"),
            "relation": item.get("relation"),
            "summary": item.get("summary"),
        }
        for item in ledger[-5:]
    ]
    return {
        "open_questions": list(session_state.get("open_questions") or []),
        "working_hypotheses": list(session_state.get("working_hypotheses") or []),
        "budgets": session_state.get("budgets") or {},
        "latest_evidence": latest_ledger,
        "entities": incident_state.get("entities") or {},
        "verdict": incident_state.get("verdict") or {},
    }


def _choose_action(
    llm: Any,
    seed_event: Dict[str, Any],
    session_state: Dict[str, Any],
    incident_state: Dict[str, Any],
    candidates: List[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    if not candidates:
        return None
    if llm is None:
        return candidates[0]

    try:
        from langchain_core.prompts import ChatPromptTemplate

        prompt = ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    "你是 incident investigator 的动作选择器。"
                    "你只能在给定 candidates 中选一个最有价值的动作，不能编造新工具。"
                    "如果 candidates 里没有高价值动作，可返回 stop=true。"
                    "输出 JSON：{\"tool_name\":\"...\",\"stop\":false,\"reason\":\"...\"}。"
                    "如果 stop=true，则 tool_name 置为空字符串。",
                ),
                (
                    "user",
                    "seed:\n{seed_json}\n\nsession:\n{session_json}\n\ncandidates:\n{candidates_json}",
                ),
            ]
        )
        response = llm.invoke(
            prompt.format_messages(
                seed_json=json.dumps(seed_event, ensure_ascii=False),
                session_json=json.dumps(_format_llm_session_summary(session_state, incident_state), ensure_ascii=False),
                candidates_json=json.dumps(
                    [
                        {
                            "tool_name": item.get("tool_name"),
                            "question": item.get("question"),
                            "trace_params": item.get("trace_params"),
                            "expected_gain": item.get("expected_gain"),
                        }
                        for item in candidates
                    ],
                    ensure_ascii=False,
                ),
            )
        )
        content = str(getattr(response, "content", "") or "").strip()
        match = content
        if "```" in match:
            match = match.split("```", 2)[1]
        parsed = json.loads(match)
        if parsed.get("stop"):
            return None
        tool_name = str(parsed.get("tool_name") or "").strip()
        for item in candidates:
            if str(item.get("tool_name") or "") == tool_name:
                chosen = dict(item)
                chosen["llm_reason"] = str(parsed.get("reason") or "").strip()
                session_state["policy_mode"] = "llm_action_selector"
                return chosen
    except Exception:
        pass
    return candidates[0]


def _observation_base(tool_name: str, payload: Dict[str, Any], source_type: str, observation_id: str) -> Dict[str, Any]:
    return {
        "observation_id": observation_id,
        "tool_name": tool_name,
        "query": payload,
        "source_type": source_type,
        "events": [],
        "derived_entities": {"asset_ids": [], "src_ips": [], "dst_ips": [], "domains": [], "fingerprints": [], "families": []},
        "claims": [],
        "confidence": 20,
        "supports_hypothesis": [],
        "contradicts_hypothesis": [],
        "relation": "context",
        "summary": "",
        "note": "",
        "page_candidates": [],
        "status": "ok",
    }


def _normalize_event_batch(tool_name: str, payload: Dict[str, Any], batch_payload: Dict[str, Any], observation_id: str) -> Dict[str, Any]:
    events = list(batch_payload.get("events") or [])
    suspicious_events = [
        item
        for item in events
        if str(item.get("classification") or "").strip().lower() in {"malicious", "suspicious", "needs_review"}
        or infer_stages(item)
    ]
    benign_events = [item for item in events if str(item.get("classification") or "").strip().lower() == "benign"]
    unknown_events = [item for item in events if item not in suspicious_events and item not in benign_events]
    derived_entities = dict(batch_payload.get("derived_entities") or {})
    observation = _observation_base(tool_name, payload, str(batch_payload.get("source_type") or "trace_store"), observation_id)
    observation["events"] = events
    observation["derived_entities"] = {
        **observation["derived_entities"],
        **derived_entities,
    }
    observation["confidence"] = min(
        90,
        25 + len(suspicious_events) * 12 + len(benign_events) * 6 + len(unique_preserve_order(derived_entities.get("asset_ids") or [])) * 4,
    )
    if suspicious_events:
        domains = unique_preserve_order(item.get("domain") for item in suspicious_events)
        dst_ips = unique_preserve_order(item.get("dst_ip") for item in suspicious_events)
        summary = f"检索到 {len(suspicious_events)} 条偏可疑事件，围绕 {'、'.join((domains + dst_ips)[:3]) or 'seed 指示物'} 展开。"
        observation["relation"] = "supporting"
        observation["supports_hypothesis"] = ["primary"]
        observation["claims"] = [
            {
                "text": summary,
                "kind": "event_batch",
                "score": observation["confidence"],
            }
        ]
        if unknown_events and len(unique_preserve_order(item.get("asset_id") for item in unknown_events)) > 1:
            observation["supports_hypothesis"].append("secondary")
    elif benign_events:
        summary = f"检索到 {len(benign_events)} 条更接近维护、更新或正常基线的事件。"
        observation["relation"] = "counterevidence"
        observation["supports_hypothesis"] = ["benign"]
        observation["contradicts_hypothesis"] = ["primary"]
        observation["claims"] = [
            {
                "text": summary,
                "kind": "event_batch",
                "score": observation["confidence"],
            }
        ]
    else:
        assets = unique_preserve_order(item.get("asset_id") for item in unknown_events)
        summary = f"检索到 {len(events)} 条上下文事件，当前主要用于扩边界和补足范围。"
        observation["relation"] = "context"
        if len(assets) > 1:
            observation["supports_hypothesis"] = ["secondary"]
        observation["claims"] = [{"text": summary, "kind": "context", "score": observation["confidence"]}]
    observation["summary"] = summary
    observation["note"] = str(batch_payload.get("note") or "")
    return observation


def _normalize_intel_observation(tool_name: str, payload: Dict[str, Any], raw: Dict[str, Any], observation_id: str) -> Dict[str, Any]:
    observation = _observation_base(tool_name, payload, "intel_tool", observation_id)
    results = list(raw.get("results") or [])
    observation["page_candidates"] = [
        {"url": item.get("url"), "title": item.get("title"), "source": urlparse(str(item.get("url") or "")).netloc}
        for item in results[:3]
        if item.get("url")
    ]
    if tool_name in {"technical_source_search", "malware_profile_lookup", "pivot_related_indicators"}:
        observation["derived_entities"]["domains"] = unique_preserve_order(
            urlparse(str(item.get("url") or "")).netloc for item in results if item.get("url")
        )
        if results:
            top_titles = unique_preserve_order(item.get("title") for item in results)[:3]
            observation["relation"] = "context"
            observation["supports_hypothesis"] = ["primary"]
            observation["confidence"] = 48
            observation["summary"] = f"{tool_name} 返回了 {len(results)} 条候选技术来源，可用于后续正文证据提取。"
            observation["claims"] = [
                {
                    "text": f"候选技术来源包括：{'；'.join(title for title in top_titles if title)}",
                    "kind": "search_results",
                    "score": 48,
                }
            ]
        else:
            observation["status"] = "empty"
            observation["confidence"] = 18
            observation["summary"] = f"{tool_name} 没有返回可直接利用的技术结果。"
        return observation

    families = unique_preserve_order(
        item.get("family")
        for item in results
        if str(item.get("family") or "").strip()
    )
    observation["derived_entities"]["families"] = families
    observation["derived_entities"]["dst_ips"] = unique_preserve_order(item.get("ioc") for item in results if _extract_indicator_type(str(item.get("ioc") or "")) == "IP")
    observation["derived_entities"]["domains"] = unique_preserve_order(item.get("ioc") for item in results if _extract_indicator_type(str(item.get("ioc") or "")) == "DOMAIN")
    if results:
        top = results[0]
        label = str(top.get("malware") or top.get("family") or top.get("threat_type") or "").strip()
        claim = str(top.get("snippet") or top.get("title") or "").strip()
        observation["relation"] = "supporting"
        observation["supports_hypothesis"] = ["primary"]
        observation["confidence"] = 62
        observation["summary"] = f"{tool_name} 返回了结构化情报结果，可用于支撑外部基础设施解释。"
        observation["claims"] = [
            {
                "text": f"{label or '结构化情报'}：{claim}",
                "kind": "structured_intel",
                "score": 62,
            }
        ]
    else:
        observation["status"] = "empty"
        observation["confidence"] = 18
        observation["summary"] = f"{tool_name} 未命中结构化情报。"
    return observation


def _normalize_page_observation(tool_name: str, payload: Dict[str, Any], raw: Dict[str, Any], observation_id: str) -> Dict[str, Any]:
    observation = _observation_base(tool_name, payload, "page_tool", observation_id)
    if tool_name == "fetch_page_content":
        content = str(raw.get("content") or "")
        entities_hint = dict(raw.get("entities_hint") or {})
        observation["derived_entities"] = {
            **observation["derived_entities"],
            "domains": unique_preserve_order(entities_hint.get("domains") or []),
            "dst_ips": unique_preserve_order(entities_hint.get("ips") or []),
            "families": [],
        }
        if content:
            observation["confidence"] = 42
            observation["summary"] = "成功读取技术页面正文，可继续抽取 claim 和实体。"
            observation["note"] = content[:500]
            observation["relation"] = "context"
        else:
            observation["status"] = "empty"
            observation["summary"] = "未读取到可用页面正文。"
        return observation

    if tool_name == "extract_claim_candidates_from_page":
        claims = list(raw.get("claims") or [])
        entities = dict(raw.get("entities") or {})
        observation["derived_entities"] = {
            **observation["derived_entities"],
            "domains": unique_preserve_order(entities.get("domains") or []),
            "dst_ips": unique_preserve_order(entities.get("ips") or []),
            "families": unique_preserve_order([str(payload.get("focus") or "").strip()]) if str(payload.get("focus") or "").strip() else [],
        }
        observation["claims"] = claims[:5]
        if claims:
            primary_claims = [
                item
                for item in claims
                if str(item.get("kind") or "") in {"family_or_indicator", "ttp", "ioc"}
            ]
            observation["confidence"] = min(70, 35 + len(primary_claims) * 7 + len(claims) * 2)
            observation["summary"] = f"从当前事件摘要中抽取出 {len(claims)} 条可直接引用的 claim。"
            if primary_claims:
                observation["relation"] = "supporting"
                observation["supports_hypothesis"] = ["primary"]
            else:
                observation["relation"] = "context"
        else:
            observation["status"] = "empty"
            observation["summary"] = "当前摘要中没有抽取出高价值 claim。"
        return observation

    if tool_name == "extract_entities_from_page":
        entities = dict(raw.get("entities") or {})
        observation["derived_entities"] = {
            **observation["derived_entities"],
            "domains": unique_preserve_order(entities.get("domains") or []),
            "dst_ips": unique_preserve_order(entities.get("ips") or []),
            "families": [],
        }
        observation["confidence"] = 36 if any(observation["derived_entities"].values()) else 16
        observation["summary"] = "从当前事件摘要中抽取了可供扩查的实体集合。"
        observation["relation"] = "context"
        return observation

    observation["status"] = "empty"
    observation["summary"] = f"{tool_name} 返回了未识别的页面工具结果。"
    return observation


def _execute_action(
    seed_event: Dict[str, Any],
    action: Dict[str, Any],
    store: TraceStore,
    incident_state: Dict[str, Any],
    observation_id: str,
) -> Dict[str, Any]:
    tool_name = str(action.get("tool_name") or "")
    payload = dict(action.get("params") or {})
    if tool_name == "search_seed_context":
        batch = store.build_seed_context(seed_event)
        return _normalize_event_batch(tool_name, payload, batch.to_payload(), observation_id)
    if tool_name == "search_related_events":
        batch = store.query_related_events(
            payload.get("pivots") or {},
            window_minutes=int(payload.get("window_minutes") or 120),
            limit=int(payload.get("limit") or 60),
        )
        return _normalize_event_batch(tool_name, payload, batch.to_payload(), observation_id)
    if tool_name == "expand_asset_scope":
        batch = store.get_asset_context(
            list(payload.get("asset_ids") or []),
            window_minutes=int(payload.get("window_minutes") or 120),
            limit=int(payload.get("limit") or 60),
        )
        return _normalize_event_batch(tool_name, payload, batch.to_payload(), observation_id)

    if tool_name == "technical_source_search":
        return _normalize_intel_observation(tool_name, payload, _tool_json(technical_source_search, payload), observation_id)
    if tool_name == "malware_profile_lookup":
        return _normalize_intel_observation(tool_name, payload, _tool_json(malware_profile_lookup, payload), observation_id)
    if tool_name == "pivot_related_indicators":
        return _normalize_intel_observation(tool_name, payload, _tool_json(pivot_related_indicators, payload), observation_id)
    if tool_name == "threatfox_ioc_lookup":
        return _normalize_intel_observation(tool_name, payload, _tool_json(threatfox_ioc_lookup, payload), observation_id)
    if tool_name == "urlhaus_ioc_lookup":
        return _normalize_intel_observation(tool_name, payload, _tool_json(urlhaus_ioc_lookup, payload), observation_id)
    if tool_name == "fetch_page_content":
        return _normalize_page_observation(tool_name, payload, _tool_json(fetch_page_content, payload), observation_id)
    if tool_name == "extract_claim_candidates_from_page":
        return _normalize_page_observation(tool_name, payload, _tool_json(extract_claim_candidates_from_page, payload), observation_id)
    if tool_name == "extract_entities_from_page":
        return _normalize_page_observation(tool_name, payload, _tool_json(extract_entities_from_page, payload), observation_id)

    observation = _observation_base(tool_name, payload, "unknown", observation_id)
    observation["status"] = "error"
    observation["summary"] = f"未知工具：{tool_name}"
    return observation


def _update_budgets(session_state: Dict[str, Any], tool_name: str) -> None:
    budgets = session_state.get("budgets") or {}
    budgets["remaining_steps"] = max(0, int(budgets.get("remaining_steps") or 0) - 1)
    budgets["remaining_tool_calls"] = max(0, int(budgets.get("remaining_tool_calls") or 0) - 1)
    if tool_name in EVENT_TOOL_NAMES:
        budgets["remaining_event_queries"] = max(0, int(budgets.get("remaining_event_queries") or 0) - 1)
    elif tool_name in INTEL_TOOL_NAMES or tool_name in PAGE_TOOL_NAMES:
        budgets["remaining_intel_queries"] = max(0, int(budgets.get("remaining_intel_queries") or 0) - 1)


def _merge_entities_from_observation(base: Dict[str, Any], observation: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(base)
    derived = observation.get("derived_entities") or {}
    derived_ips = unique_preserve_order(derived.get("dst_ips") or [])
    internal_ips = [ip for ip in derived_ips if _is_internal_ip(ip)]
    external_ips = [ip for ip in derived_ips if ip and not _is_internal_ip(ip)]
    for key in ("assets", "domains", "external_ips", "internal_ips", "families"):
        merged.setdefault(key, [])
    merged["assets"] = unique_preserve_order(
        list(merged.get("assets") or [])
        + list(derived.get("asset_ids") or [])
    )
    merged["internal_ips"] = unique_preserve_order(
        list(merged.get("internal_ips") or [])
        + list(derived.get("src_ips") or [])
        + internal_ips
    )
    merged["external_ips"] = unique_preserve_order(
        list(merged.get("external_ips") or [])
        + external_ips
    )
    merged["domains"] = unique_preserve_order(
        list(merged.get("domains") or [])
        + list(derived.get("domains") or [])
    )
    merged["families"] = unique_preserve_order(
        list(merged.get("families") or [])
        + list(derived.get("families") or [])
    )
    return merged


def _update_pivots_from_events(pivots: Dict[str, Any], events: List[Dict[str, Any]], observation: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(pivots)
    merged["asset_ids"] = unique_preserve_order(list(merged.get("asset_ids") or []) + [item.get("asset_id") for item in events])
    merged["src_ips"] = unique_preserve_order(list(merged.get("src_ips") or []) + [item.get("src_ip") for item in events])
    merged["dst_ips"] = unique_preserve_order(list(merged.get("dst_ips") or []) + [item.get("dst_ip") for item in events] + list((observation.get("derived_entities") or {}).get("dst_ips") or []))
    merged["domains"] = unique_preserve_order(list(merged.get("domains") or []) + [item.get("domain") for item in events] + list((observation.get("derived_entities") or {}).get("domains") or []))
    merged["fingerprints"] = unique_preserve_order(
        list(merged.get("fingerprints") or [])
        + [item.get("ja4") for item in events]
        + [item.get("ja3") for item in events]
        + [item.get("ssl_sha1") for item in events]
        + [item.get("cert_sha1") for item in events]
        + list((observation.get("derived_entities") or {}).get("fingerprints") or [])
    )
    return merged


def _scores_from_events(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    suspicious_events = []
    benign_events = []
    unknown_events = []
    primary_score = 0
    benign_score = 0
    repeated_indicators = set()
    stage_labels = set()
    for event in events:
        score = suspicion_score(event)
        stages = infer_stages(event)
        stage_labels.update(stages)
        if score > 0 or stages:
            suspicious_events.append(event)
            primary_score += max(score, 1) + len(stages)
            if event.get("dst_ip"):
                repeated_indicators.add(str(event.get("dst_ip")))
            if event.get("domain"):
                repeated_indicators.add(str(event.get("domain")))
        elif score < 0:
            benign_events.append(event)
            benign_score += abs(score)
        else:
            unknown_events.append(event)
    return {
        "suspicious_events": suspicious_events,
        "benign_events": benign_events,
        "unknown_events": unknown_events,
        "primary_score": primary_score,
        "benign_score": benign_score,
        "stage_labels": unique_preserve_order(stage_labels),
        "execution_seen": "execution" in stage_labels,
        "lateral_seen": "lateral-movement" in stage_labels,
        "exfil_seen": "exfiltration" in stage_labels,
        "repeated_indicator_count": len(repeated_indicators),
    }


def _build_runtime_verdict(
    seed_event: Dict[str, Any],
    annotated_events: List[Dict[str, Any]],
    evidence_ledger: List[Dict[str, Any]],
    entities: Dict[str, Any],
) -> Dict[str, Any]:
    event_scores = _scores_from_events(annotated_events)
    primary_score = int(event_scores["primary_score"])
    benign_score = int(event_scores["benign_score"])
    execution_seen = bool(event_scores["execution_seen"])
    lateral_seen = bool(event_scores["lateral_seen"])
    exfil_seen = bool(event_scores["exfil_seen"])
    suspected_assets = list(entities.get("suspected_assets") or [])
    related_assets = list(entities.get("related_assets") or [])
    supporting_obs = [item for item in evidence_ledger if item.get("relation") == "supporting"]
    benign_obs = [item for item in evidence_ledger if item.get("relation") == "counterevidence"]
    alternative_obs = [item for item in evidence_ledger if item.get("relation") == "alternative"]
    family_hint = _meaningful_family_hint(seed_event)

    if benign_score >= primary_score + 4 and primary_score <= 4:
        status = "monitor_only"
        confidence = min(55, 28 + benign_score * 4 + len(benign_obs) * 2)
        reasons = ["当前证据更容易被维护窗口、补丁、备份或共享基线解释。"]
    elif primary_score >= 10 and (execution_seen or lateral_seen or exfil_seen or len(suspected_assets) > 1 or len(supporting_obs) >= 3):
        status = "confirmed_incident"
        confidence = min(94, 64 + primary_score * 2 + len(suspected_assets) * 5 + (8 if execution_seen else 0))
        reasons = ["事件簇已经出现连续恶意外联或主机侧异常，足以支撑事件成立。"]
    elif primary_score >= 6:
        status = "needs_review"
        confidence = min(76, 52 + primary_score * 2 + len(alternative_obs) * 2)
        reasons = ["当前已形成可疑事件簇，但关键阶段或影响范围仍需人工复核。"]
    elif benign_score >= max(3, primary_score + 2):
        status = "monitor_only"
        confidence = min(52, 30 + benign_score * 3)
        reasons = ["现有事件更偏向正常背景，自动化倾向降级观察。"]
    else:
        status = "needs_review"
        confidence = 48 + len(supporting_obs) * 3
        reasons = ["当前只有有限正向证据，仍需继续围绕关键资产和指示物复核。"]

    if family_hint and status != "monitor_only":
        reasons.append(f"seed alert 自带家族/工具提示：{family_hint}。")
    if related_assets and status != "monitor_only":
        reasons.append("已观察到关联资产或共享基础设施上的扩展信号，但尚需继续确认是否属于同一事件。")
    if benign_obs and status == "needs_review":
        reasons.append("同时也存在可解释为背景活动的信号，因此暂未自动推进为确认事件。")

    return {
        "status": status,
        "status_label": {
            "confirmed_incident": "确认事件",
            "needs_review": "待人工复核",
            "monitor_only": "降级观察",
        }.get(status, status),
        "confidence": int(confidence),
        "severity": severity_from_confidence(int(confidence), status),
        "rationale": unique_preserve_order(reasons),
    }


def _update_working_hypotheses(
    session_state: Dict[str, Any],
    incident_state: Dict[str, Any],
    verdict: Dict[str, Any],
    evidence_ledger: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    supporting_ids = [item["observation_id"] for item in evidence_ledger if item.get("relation") == "supporting"]
    counter_ids = [item["observation_id"] for item in evidence_ledger if item.get("relation") == "counterevidence"]
    secondary_ids = [item["observation_id"] for item in evidence_ledger if item.get("relation") in {"alternative", "context"}]
    family_hint = _meaningful_family_hint(incident_state.get("seed") or {})
    entities = incident_state.get("entities") or {}
    primary_assets = list(entities.get("suspected_assets") or [])
    primary_indicators = list((incident_state.get("scope") or {}).get("primary_external_indicators") or [])

    primary_title = (
        f"{'、'.join(primary_assets) or '种子资产'} 疑似 {family_hint} 相关事件"
        if family_hint
        else f"{'、'.join(primary_assets) or '种子资产'} 疑似恶意外联事件"
    )
    secondary_title = "共享基础设施上的待复核扩展"
    if list(entities.get("related_assets") or []):
        secondary_title = f"{'、'.join(list(entities.get('related_assets') or [])[:2])} 等资产的关联范围仍待确认"
    benign_title = "维护、补丁、备份或共享基线解释"
    if primary_indicators:
        benign_title = f"围绕 {'、'.join(primary_indicators[:2])} 的通信可能存在正常背景解释"

    hypotheses = [
        {
            "id": "primary",
            "kind": "primary",
            "title": primary_title,
            "score": len(supporting_ids) * 3 + (6 if verdict.get("status") == "confirmed_incident" else 0),
            "status": "leading" if verdict.get("status") == "confirmed_incident" else "supported",
            "supporting_observation_ids": unique_preserve_order(supporting_ids),
            "counter_observation_ids": unique_preserve_order(counter_ids),
        },
        {
            "id": "secondary",
            "kind": "secondary",
            "title": secondary_title,
            "score": len(secondary_ids) * 2 + (3 if verdict.get("status") == "needs_review" else 0),
            "status": "supported" if secondary_ids else "open",
            "supporting_observation_ids": unique_preserve_order(secondary_ids),
            "counter_observation_ids": [],
        },
        {
            "id": "benign",
            "kind": "benign",
            "title": benign_title,
            "score": len(counter_ids) * 3 + (5 if verdict.get("status") == "monitor_only" else 0),
            "status": "leading" if verdict.get("status") == "monitor_only" else ("supported" if counter_ids else "open"),
            "supporting_observation_ids": unique_preserve_order(counter_ids),
            "counter_observation_ids": unique_preserve_order(supporting_ids),
        },
    ]
    session_state["working_hypotheses"] = hypotheses
    return hypotheses


def _open_questions(seed_event: Dict[str, Any], incident_state: Dict[str, Any], verdict: Dict[str, Any]) -> List[Dict[str, Any]]:
    entities = incident_state.get("entities") or {}
    scope = incident_state.get("scope") or {}
    stage_labels = list((incident_state.get("summary") or {}).get("stage_labels") or [])
    observation_tools = {
        str(item.get("tool_name") or "").strip()
        for item in list(incident_state.get("observations") or [])
    }
    questions: List[Dict[str, Any]] = []
    if not incident_state.get("context_bundle", {}).get("minimal_event_count"):
        questions.append(
            {
                "id": "build_context",
                "priority": "high",
                "question": "仍需围绕 seed alert 补足最小上下文。",
            }
        )
    if verdict.get("status") != "monitor_only" and not list(entities.get("assets") or []):
        questions.append(
            {
                "id": "identify_assets",
                "priority": "high",
                "question": "仍需确认事件涉及的关键资产。",
            }
        )
    if verdict.get("status") != "monitor_only" and "execution" not in stage_labels:
        questions.append(
            {
                "id": "execution_gap",
                "priority": "medium",
                "question": "是否存在主机侧执行、持久化或横向移动证据？",
            }
        )
    if verdict.get("status") == "needs_review" and list(entities.get("related_assets") or []):
        questions.append(
            {
                "id": "related_assets_review",
                "priority": "medium",
                "question": f"关联资产 {'、'.join(list(entities.get('related_assets') or [])[:3])} 是否真正受影响？",
            }
        )
    if verdict.get("status") != "monitor_only" and not list(scope.get("primary_external_indicators") or []):
        questions.append(
            {
                "id": "ground_infra",
                "priority": "medium",
                "question": "仍需补足外部基础设施、域名或家族背景。",
            }
        )
    if not any(name in (INTEL_TOOL_NAMES | PAGE_TOOL_NAMES) for name in observation_tools):
        questions.append(
            {
                "id": "structure_evidence",
                "priority": "medium",
                "question": "仍需把当前事件事实沉淀为 claim 或可引用实体，避免报告只剩原始事件聚合。",
            }
        )
    family_hint = _meaningful_family_hint(seed_event)
    if family_hint and verdict.get("status") == "needs_review":
        questions.append(
            {
                "id": "validate_family_hint",
                "priority": "low",
                "question": f"seed 自带的家族提示 {family_hint} 是否有更多外部证据支撑？",
            }
        )
    return questions


def _observation_high_value(observation: Dict[str, Any]) -> bool:
    if list(observation.get("events") or []):
        return True
    if list(observation.get("claims") or []):
        return True
    if any(list(values or []) for values in (observation.get("derived_entities") or {}).values()):
        return True
    return False


def _attach_observation(incident_state: Dict[str, Any], observation: Dict[str, Any]) -> None:
    incident_state.setdefault("observations", []).append(observation)
    if observation.get("events"):
        for event in list(observation.get("events") or []):
            incident_state.setdefault("known_events", {})[str(event.get("id") or "")] = event
    for candidate in list(observation.get("page_candidates") or []):
        incident_state.setdefault("page_candidates", []).append(candidate)
    incident_state["entities"] = _merge_entities_from_observation(incident_state.get("entities") or {}, observation)
    incident_state["pivots"] = _update_pivots_from_events(
        incident_state.get("pivots") or {},
        list(observation.get("events") or []),
        observation,
    )


def _evidence_entry_from_observation(observation: Dict[str, Any]) -> Dict[str, Any]:
    event_ids = [str(item.get("id") or "") for item in list(observation.get("events") or []) if item.get("id")]
    claims = list(observation.get("claims") or [])
    summary = str(observation.get("summary") or "").strip()
    if not summary and claims:
        summary = str(claims[0].get("text") or "").strip()
    return {
        "observation_id": observation.get("observation_id"),
        "tool_name": observation.get("tool_name"),
        "relation": observation.get("relation") or "context",
        "source_type": observation.get("source_type"),
        "summary": summary,
        "event_ids": event_ids,
        "claim_texts": [str(item.get("text") or "").strip() for item in claims[:4] if str(item.get("text") or "").strip()],
        "confidence": int(observation.get("confidence") or 0),
        "supports_hypothesis": list(observation.get("supports_hypothesis") or []),
        "contradicts_hypothesis": list(observation.get("contradicts_hypothesis") or []),
    }


def _finalize_runtime_state(seed_event: Dict[str, Any], session_state: Dict[str, Any], incident_state: Dict[str, Any]) -> Dict[str, Any]:
    known_events = list((incident_state.get("known_events") or {}).values())
    known_events.sort(key=lambda item: str(item.get("ts") or ""))
    annotation = _annotate_events(seed_event, known_events)
    annotated_events = list(annotation.get("events") or [])
    entities = _extract_entities(seed_event, annotated_events, seed_event_id=str(annotation.get("seed_event_id") or ""))

    # Merge in intel/page-derived entities that may not exist in event rows.
    observation_entities = incident_state.get("entities") or {}
    entities["assets"] = unique_preserve_order(list(entities.get("assets") or []) + list(observation_entities.get("assets") or []))
    entities["observed_assets"] = unique_preserve_order(list(entities.get("observed_assets") or []) + list(observation_entities.get("assets") or []))
    entities["internal_ips"] = unique_preserve_order(list(entities.get("internal_ips") or []) + list(observation_entities.get("internal_ips") or []))
    entities["external_ips"] = unique_preserve_order(list(entities.get("external_ips") or []) + list(observation_entities.get("external_ips") or []))
    entities["domains"] = unique_preserve_order(list(entities.get("domains") or []) + list(observation_entities.get("domains") or []))
    entities["primary_external_ips"] = unique_preserve_order(list(entities.get("primary_external_ips") or []) + list(observation_entities.get("external_ips") or []))
    entities["primary_domains"] = unique_preserve_order(list(entities.get("primary_domains") or []) + list(observation_entities.get("domains") or []))

    timeline = _build_timeline(annotated_events)
    evidence_clusters = _build_evidence_clusters(annotated_events)
    suspicious_scope_events = [item for item in annotated_events if str(item.get("role") or "") in {"seed", "supporting"}]
    counterevidence_events = [item for item in annotated_events if str(item.get("role") or "") == "counterevidence"]
    scope = {
        "event_count": len(annotated_events),
        "primary_event_count": len(suspicious_scope_events),
        "context_event_count": len([item for item in annotated_events if str(item.get("role") or "") == "context"]),
        "counterevidence_count": len(counterevidence_events),
        "time_window": {
            "start": timeline[0]["ts"] if timeline else None,
            "end": timeline[-1]["ts"] if timeline else None,
        },
        "affected_assets": entities.get("suspected_assets") or [],
        "related_assets": entities.get("related_assets") or [],
        "primary_external_indicators": unique_preserve_order(
            [item.get("dst_ip") for item in suspicious_scope_events]
            + [item.get("domain") for item in suspicious_scope_events]
            + list(observation_entities.get("families") or [])
        ),
        "contextual_external_indicators": unique_preserve_order(
            [item.get("dst_ip") for item in counterevidence_events]
            + [item.get("domain") for item in counterevidence_events]
        ),
    }
    scope["external_indicators"] = unique_preserve_order(
        list(scope.get("primary_external_indicators") or []) + list(scope.get("contextual_external_indicators") or [])
    )

    evidence_ledger = list(incident_state.get("evidence_ledger") or [])
    verdict = _build_runtime_verdict(seed_event, annotated_events, evidence_ledger, entities)
    working_hypotheses = _update_working_hypotheses(session_state, incident_state, verdict, evidence_ledger)
    hypothesis = _build_hypothesis(seed_event, verdict, annotated_events, entities)
    incident_summary = _build_incident_summary(verdict=verdict, entities=entities, scope=scope, hypothesis=hypothesis)
    incident_state["summary"] = incident_summary
    session_state["open_questions"] = _open_questions(seed_event, {"entities": entities, "scope": scope, "summary": incident_summary, **incident_state}, verdict)
    uncertainties = _build_uncertainties(verdict, annotated_events, entities)
    if session_state["open_questions"]:
        uncertainties = unique_preserve_order(
            list(uncertainties)
            + [str(item.get("question") or "").strip() for item in session_state["open_questions"] if str(item.get("question") or "").strip()]
        )
    recommendations = _build_recommendations(verdict, entities, scope)
    decision_basis = _build_decision_basis(
        verdict=verdict,
        events=annotated_events,
        evidence_clusters=evidence_clusters,
        entities=entities,
        scope=scope,
    )

    event_to_observation_ids: Dict[str, List[str]] = {}
    for item in evidence_ledger:
        for event_id in list(item.get("event_ids") or []):
            event_to_observation_ids.setdefault(event_id, []).append(str(item.get("observation_id") or ""))

    for bucket in ("positive_signals", "counterevidence"):
        for signal in list(decision_basis.get(bucket) or []):
            obs_ids = unique_preserve_order(event_to_observation_ids.get(str(signal.get("event_id") or ""), []))
            if obs_ids:
                signal["observation_ids"] = obs_ids
    decision_basis["positive_observation_ids"] = unique_preserve_order(
        item.get("observation_id") for item in evidence_ledger if item.get("relation") == "supporting"
    )
    decision_basis["counter_observation_ids"] = unique_preserve_order(
        item.get("observation_id") for item in evidence_ledger if item.get("relation") == "counterevidence"
    )

    report_ready = bool(
        known_events
        and any(item.get("tool_name") in EVENT_TOOL_NAMES for item in list(session_state.get("tool_history") or []))
        and any(item.get("tool_name") in (INTEL_TOOL_NAMES | PAGE_TOOL_NAMES) for item in list(session_state.get("tool_history") or []))
        and verdict.get("status")
    )

    state = {
        "context_built": bool(incident_state.get("context_bundle", {}).get("minimal_event_count")),
        "entry_assessed": True,
        "cluster_built": len(annotated_events) >= max(2, int(incident_state.get("context_bundle", {}).get("minimal_event_count") or 0)),
        "entities_grounded": any(entities.values()),
        "timeline_built": bool(timeline),
        "scope_assessed": bool(scope.get("affected_assets") or scope.get("external_indicators")),
        "intrusion_hypothesis_grounded": verdict["status"] == "confirmed_incident",
        "external_infra_grounded": bool(scope.get("external_indicators")),
        "counterevidence_checked": bool(counterevidence_events or any(item.get("relation") == "counterevidence" for item in evidence_ledger)),
        "report_ready": report_ready,
    }

    session_state["working_hypotheses"] = working_hypotheses
    incident_state["entities"] = entities
    incident_state["timeline"] = timeline
    incident_state["scope"] = scope
    incident_state["verdict"] = verdict
    incident_state["confidence"] = verdict.get("confidence")
    incident_state["report_ready"] = report_ready

    return {
        "annotation": annotation,
        "annotated_events": annotated_events,
        "entities": entities,
        "timeline": timeline,
        "evidence_clusters": evidence_clusters,
        "scope": scope,
        "verdict": verdict,
        "hypothesis": hypothesis,
        "summary": incident_summary,
        "uncertainties": uncertainties,
        "recommendations": recommendations,
        "decision_basis": decision_basis,
        "report_ready": report_ready,
        "state": state,
    }


def _stop_decision(
    started_at: float,
    session_state: Dict[str, Any],
    incident_state: Dict[str, Any],
    finalized: Dict[str, Any],
) -> Dict[str, Any]:
    budgets = session_state.get("budgets") or {}
    elapsed_s = time.perf_counter() - started_at
    if finalized.get("report_ready") and int(session_state.get("step_index") or 0) >= 2:
        return {"stop": True, "reason": "report_ready"}
    if int(budgets.get("remaining_steps") or 0) <= 0:
        return {"stop": True, "reason": "step_budget_exhausted"}
    if int(budgets.get("remaining_tool_calls") or 0) <= 0:
        return {"stop": True, "reason": "tool_budget_exhausted"}
    if elapsed_s >= float(budgets.get("max_runtime_s") or DEFAULT_BUDGETS["max_runtime_s"]):
        return {"stop": True, "reason": "runtime_budget_exhausted"}
    if int(session_state.get("consecutive_low_value_steps") or 0) >= 2 and int(session_state.get("step_index") or 0) >= 2:
        return {"stop": True, "reason": "two_low_value_steps"}
    if (
        not list(session_state.get("open_questions") or [])
        and bool(finalized.get("report_ready"))
        and int(session_state.get("step_index") or 0) >= 2
    ):
        return {"stop": True, "reason": "no_open_questions"}
    return {"stop": False, "reason": "continue"}


def run_incident_agent_case(
    *,
    seed_alert: Dict[str, Any],
    fixture_dir: str,
    llm: Any = None,
    store: Optional[TraceStore] = None,
    budgets: Optional[Dict[str, int]] = None,
) -> Dict[str, Any]:
    resolved_budgets = dict(DEFAULT_BUDGETS)
    if budgets:
        resolved_budgets.update({key: int(value) for key, value in budgets.items()})

    seed_event = normalize_alert(seed_alert)
    resolved_store = store or FixtureTraceStoreAdapter.from_fixture_dir(Path(fixture_dir))  # type: ignore[name-defined]
    session_state = _initial_session_state(seed_event, resolved_budgets)
    incident_state = _initial_incident_state(seed_event)
    investigation_trace: List[Dict[str, Any]] = []
    started_at = time.perf_counter()

    while True:
        candidates = _action_candidates(seed_event, session_state, incident_state)
        finalized = _finalize_runtime_state(seed_event, session_state, incident_state)
        decision = _stop_decision(started_at, session_state, incident_state, finalized)
        if decision["stop"] and not candidates:
            session_state["stop_reason"] = decision["reason"]
            break

        chosen = _choose_action(llm, seed_event, session_state, incident_state, candidates)
        if chosen is None:
            session_state["stop_reason"] = decision["reason"] if decision["stop"] else "no_high_value_action"
            break

        session_state["step_index"] = int(session_state.get("step_index") or 0) + 1
        observation_id = f"obs-{int(session_state['step_index']):03d}"
        step_trace = {
            "step_index": session_state["step_index"],
            "open_questions": list(session_state.get("open_questions") or []),
            "working_hypotheses": list(session_state.get("working_hypotheses") or []),
            "selected_action": {
                "tool_name": chosen.get("tool_name"),
                "question": chosen.get("question"),
                "trace_params": chosen.get("trace_params"),
                "expected_gain": chosen.get("expected_gain"),
                "llm_reason": chosen.get("llm_reason") or "",
            },
        }

        observation = _execute_action(seed_event, chosen, resolved_store, incident_state, observation_id)
        _update_budgets(session_state, str(chosen.get("tool_name") or ""))
        _attach_observation(incident_state, observation)
        ledger_entry = _evidence_entry_from_observation(observation)
        incident_state.setdefault("evidence_ledger", []).append(ledger_entry)
        if observation.get("relation") == "counterevidence":
            incident_state.setdefault("counterevidence", []).append(ledger_entry)

        if observation.get("tool_name") == "search_seed_context":
            incident_state["context_bundle"] = {
                "minimal_event_ids": [str(item.get("id") or "") for item in list(observation.get("events") or [])],
                "minimal_event_count": len(list(observation.get("events") or [])),
            }

        if _observation_high_value(observation):
            session_state["consecutive_low_value_steps"] = 0
        else:
            session_state["consecutive_low_value_steps"] = int(session_state.get("consecutive_low_value_steps") or 0) + 1

        session_state.setdefault("tool_history", []).append(
            {
                "step_index": session_state["step_index"],
                "tool_name": observation.get("tool_name"),
                "observation_id": observation.get("observation_id"),
                "relation": observation.get("relation"),
                "status": observation.get("status"),
            }
        )

        finalized = _finalize_runtime_state(seed_event, session_state, incident_state)
        followup = _stop_decision(started_at, session_state, incident_state, finalized)
        step_trace["observation_ids"] = [observation.get("observation_id")]
        step_trace["state_updates"] = {
            "verdict": finalized["verdict"],
            "report_ready": finalized["report_ready"],
            "known_event_count": len(finalized["annotated_events"]),
            "supporting_observation_ids": finalized["decision_basis"].get("positive_observation_ids") or [],
            "counter_observation_ids": finalized["decision_basis"].get("counter_observation_ids") or [],
        }
        if followup["stop"]:
            step_trace["stop_reason"] = followup["reason"]
            session_state["stop_reason"] = followup["reason"]
        else:
            step_trace["continue_reason"] = followup["reason"]
        investigation_trace.append(step_trace)
        if followup["stop"]:
            break

    finalized = _finalize_runtime_state(seed_event, session_state, incident_state)
    report_outline = build_incident_report_outline(
        {
            "mode": "incident-agent",
            "seed": seed_event,
            "verdict": finalized["verdict"],
            "summary": finalized["summary"],
            "entities": finalized["entities"],
            "scope": finalized["scope"],
            "hypothesis": finalized["hypothesis"],
            "decision_basis": finalized["decision_basis"],
            "timeline": finalized["timeline"],
            "uncertainties": finalized["uncertainties"],
            "recommendations": finalized["recommendations"],
            "session_state": session_state,
            "incident_state": incident_state,
        }
    )

    incident = {
        "schema_version": "0.2",
        "mode": "incident-agent",
        "fixture_case": getattr(resolved_store, "fixture_dir", Path(fixture_dir)).name,  # type: ignore[name-defined]
        "seed": seed_event,
        "state": finalized["state"],
        "session_state": session_state,
        "incident_state": {
            "seed": seed_event,
            "pivots": incident_state.get("pivots") or {},
            "observations": list(incident_state.get("observations") or []),
            "entities": finalized["entities"],
            "timeline": finalized["timeline"],
            "scope": finalized["scope"],
            "evidence_ledger": list(incident_state.get("evidence_ledger") or []),
            "counterevidence": list(incident_state.get("counterevidence") or []),
            "verdict": finalized["verdict"],
            "confidence": finalized["verdict"].get("confidence"),
            "report_ready": finalized["report_ready"],
        },
        "open_questions": list(session_state.get("open_questions") or []),
        "working_hypotheses": list(session_state.get("working_hypotheses") or []),
        "verdict": finalized["verdict"],
        "summary": finalized["summary"],
        "decision_basis": finalized["decision_basis"],
        "context_bundle": incident_state.get("context_bundle") or {"minimal_event_ids": [], "minimal_event_count": 0},
        "cluster": {
            "seed_event_id": finalized["annotation"].get("seed_event_id"),
            "supporting_event_ids": finalized["annotation"].get("supporting_event_ids") or [],
            "counterevidence_event_ids": finalized["annotation"].get("counterevidence_event_ids") or [],
            "events": finalized["annotated_events"],
            "event_count": len(finalized["annotated_events"]),
        },
        "entities": finalized["entities"],
        "timeline": finalized["timeline"],
        "evidence_clusters": finalized["evidence_clusters"],
        "evidence_ledger": list(incident_state.get("evidence_ledger") or []),
        "hypothesis": finalized["hypothesis"],
        "scope": finalized["scope"],
        "uncertainties": finalized["uncertainties"],
        "recommendations": finalized["recommendations"],
        "report_outline": report_outline,
    }
    report_markdown = render_incident_report_with_llm(incident, llm=llm)
    topology = build_incident_topology(incident)
    return {
        "incident": incident,
        "investigation_trace": investigation_trace,
        "report_markdown": report_markdown,
        "report_outline": report_outline,
        "topology": topology,
    }
