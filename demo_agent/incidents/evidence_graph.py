from __future__ import annotations

import hashlib
import ipaddress
import re
from typing import Any, Dict, Iterable, List, Tuple


DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.IGNORECASE)
ARTIFACT_RE = re.compile(r".+\.(?:exe|dll|ps1|bat|cmd|vbs|js|aspx|jsp|php|dat|zip|7z|rar|bin)$", re.IGNORECASE)
SIMPLE_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")

BOUNDARY_MARKERS = {
    "candidate",
    "open",
    "gap",
    "boundary",
    "unverified",
    "needs validation",
    "needs independent validation",
    "待确认",
    "候选",
    "缺口",
    "边界",
    "反证",
    "替代",
}

COUNTEREVIDENCE_MARKERS = {
    "counterevidence",
    "background",
    "alternative",
    "shared",
    "benign",
    "maintenance",
    "反证",
    "背景",
    "替代",
    "共享",
    "正常",
    "维护",
}


def _text(value: Any) -> str:
    return str(value or "").strip()


def _as_dict(value: Any) -> Dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _as_list(value: Any) -> List[Any]:
    return list(value) if isinstance(value, list) else []


def _dedupe(values: Iterable[Any]) -> List[str]:
    seen: set[str] = set()
    result: List[str] = []
    for value in values:
        item = _text(value)
        if not item or item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


def _stable_id(prefix: str, *parts: Any) -> str:
    raw = "|".join(_text(part) for part in parts if _text(part)) or prefix
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]
    return f"{prefix}:{digest}"


def _blob(*values: Any) -> str:
    return " ".join(_text(value) for value in values if _text(value)).lower()


def _object_values(fact: Dict[str, Any]) -> List[str]:
    objects = fact.get("objects")
    if isinstance(objects, list):
        return _dedupe(_text(item).strip("` ") for item in objects)
    obj = _text(fact.get("object"))
    if not obj:
        return []
    return _dedupe(part.strip("` ") for part in re.split(r"[/,，、]+", obj) if part.strip("` "))


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _node_id_for_value(value: str) -> Tuple[str, str]:
    label = _text(value).strip("` ")
    lowered = label.lower()
    if _is_ip(label):
        return f"ip:{label}", "ip"
    if DOMAIN_RE.match(lowered):
        return f"domain:{lowered}", "domain"
    if ARTIFACT_RE.match(label):
        return f"artifact:{label}", "artifact"
    if SIMPLE_HOST_RE.match(label) and not any(char in label for char in "@:/\\"):
        return f"asset:{label}", "asset"
    return _stable_id("object", label), "object"


def _fact_id(fact: Dict[str, Any], index: int = 0) -> str:
    fact_id = _text(fact.get("fact_id"))
    source_id = _text(fact.get("source_id"))
    return fact_id or _stable_id("fact", source_id, index)


def _fact_node_id(fact: Dict[str, Any], index: int = 0) -> str:
    fact_id = _fact_id(fact, index)
    return fact_id if fact_id.startswith("fact:") else f"fact:{fact_id}"


def _fact_status(fact: Dict[str, Any]) -> str:
    status = _text(fact.get("status"))
    if status:
        return status
    return "candidate" if fact.get("candidate_or_boundary") else "unknown"


def _fact_roles(fact: Dict[str, Any]) -> List[str]:
    return _dedupe(
        [
            fact.get("fact_type"),
            fact.get("kind"),
            fact.get("classification"),
            *(_as_list(fact.get("stages"))),
            *(_as_list(fact.get("tags"))),
            fact.get("reporting_focus"),
        ]
    )


def _fact_is_boundary(fact: Dict[str, Any]) -> bool:
    if bool(fact.get("candidate_or_boundary")):
        return True
    status = _fact_status(fact).lower()
    if status in {"candidate", "open", "partially_closed", "reportable_unresolved", "unverified"}:
        return True
    haystack = _blob(
        fact.get("fact_type"),
        fact.get("status"),
        fact.get("classification"),
        fact.get("reporting_focus"),
        fact.get("boundary_note"),
        fact.get("summary_line"),
    )
    return any(marker in haystack for marker in BOUNDARY_MARKERS)


def _is_action_fact(fact: Dict[str, Any]) -> bool:
    return _text(fact.get("fact_type")).lower() == "action"


def _is_gap_fact(fact: Dict[str, Any]) -> bool:
    return _text(fact.get("fact_type")).lower() == "gap" or _text(fact.get("source_id")).startswith("gap:")


def _is_counterevidence_fact(fact: Dict[str, Any]) -> bool:
    haystack = _blob(
        fact.get("fact_type"),
        fact.get("status"),
        fact.get("classification"),
        fact.get("kind"),
        fact.get("reporting_focus"),
        fact.get("boundary_note"),
        fact.get("summary_line"),
    )
    return any(marker in haystack for marker in COUNTEREVIDENCE_MARKERS)


def _relation_for_fact(fact: Dict[str, Any]) -> str:
    if _is_action_fact(fact):
        return "recommends_check"
    if _is_gap_fact(fact):
        return "has_gap"
    if _is_counterevidence_fact(fact):
        return "provides_context"
    if _fact_is_boundary(fact):
        return "candidate_related_to"
    if _text(fact.get("fact_type")).lower() == "verdict":
        return "supports_verdict"
    return "observed_with"


def _merge_status(current: str, new_status: str, *, boundary: bool) -> str:
    if current == "confirmed" or new_status == "confirmed":
        return "confirmed"
    if boundary:
        return "candidate"
    return new_status or current or "unknown"


def build_evidence_graph(source_bundle: Dict[str, Any], fact_catalog: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Build a deterministic provenance-preserving graph from source facts.

    The graph is a navigational structure only. It groups existing facts by
    assets, indicators, artifacts, gaps, and actions without adding conclusions.
    """

    bundle = _as_dict(source_bundle)
    facts = [_as_dict(item) for item in _as_list(fact_catalog)]
    nodes: Dict[str, Dict[str, Any]] = {}
    edges: Dict[str, Dict[str, Any]] = {}

    def add_node(node_id: str, node_type: str, label: str, fact: Dict[str, Any], index: int) -> None:
        fact_id = _fact_id(fact, index)
        source_id = _text(fact.get("source_id"))
        boundary = _fact_is_boundary(fact)
        node = nodes.setdefault(
            node_id,
            {
                "node_id": node_id,
                "node_type": node_type,
                "label": label,
                "status": _fact_status(fact),
                "fact_ids": [],
                "source_ids": [],
                "roles": [],
                "boundary": False,
                "properties": {},
            },
        )
        node["fact_ids"] = _dedupe([*node["fact_ids"], fact_id])
        node["source_ids"] = _dedupe([*node["source_ids"], source_id])
        node["roles"] = _dedupe([*node["roles"], *_fact_roles(fact)])
        node["boundary"] = bool(node["boundary"] or boundary)
        node["status"] = _merge_status(_text(node.get("status")), _fact_status(fact), boundary=bool(node["boundary"]))
        if _text(fact.get("time")) and not node["properties"].get("first_time"):
            node["properties"]["first_time"] = _text(fact.get("time"))

    def add_edge(source: str, target: str, relation: str, fact: Dict[str, Any], index: int) -> None:
        fact_id = _fact_id(fact, index)
        source_id = _text(fact.get("source_id"))
        edge_id = _stable_id("edge", source, relation, target)
        edge = edges.setdefault(
            edge_id,
            {
                "edge_id": edge_id,
                "source": source,
                "target": target,
                "relation": relation,
                "status": _fact_status(fact),
                "fact_ids": [],
                "source_ids": [],
                "roles": [],
                "boundary": False,
                "boundary_note": "",
            },
        )
        edge["fact_ids"] = _dedupe([*edge["fact_ids"], fact_id])
        edge["source_ids"] = _dedupe([*edge["source_ids"], source_id])
        edge["roles"] = _dedupe([*edge["roles"], *_fact_roles(fact)])
        edge["boundary"] = bool(edge["boundary"] or _fact_is_boundary(fact))
        edge["status"] = _merge_status(_text(edge.get("status")), _fact_status(fact), boundary=bool(edge["boundary"]))
        if _text(fact.get("boundary_note")):
            edge["boundary_note"] = _text(fact.get("boundary_note"))

    for index, fact in enumerate(facts):
        fact_id = _fact_id(fact, index)
        source_id = _text(fact.get("source_id"))
        if not fact_id and not source_id:
            continue
        fact_node_id = _fact_node_id(fact, index)
        add_node(fact_node_id, "fact", fact_id or source_id, fact, index)

        subject_node_id = fact_node_id
        asset = _text(fact.get("asset")).strip("` ")
        if asset:
            subject_node_id = f"asset:{asset}"
            add_node(subject_node_id, "asset", asset, fact, index)
            add_edge(fact_node_id, subject_node_id, "mentions_asset", fact, index)

        for value in _object_values(fact):
            object_node_id, object_type = _node_id_for_value(value)
            add_node(object_node_id, object_type, value, fact, index)
            if object_node_id != subject_node_id:
                add_edge(subject_node_id, object_node_id, _relation_for_fact(fact), fact, index)

    node_list = sorted(nodes.values(), key=lambda item: _text(item.get("node_id")))
    edge_list = sorted(edges.values(), key=lambda item: _text(item.get("edge_id")))
    return {
        "schema_version": "report-evidence-graph-v1",
        "case_header": _as_dict(bundle.get("case_header")),
        "source_counts": _as_dict(bundle.get("source_counts")),
        "nodes": node_list,
        "edges": edge_list,
        "graph_stats": {
            "fact_count": len(facts),
            "node_count": len(node_list),
            "edge_count": len(edge_list),
        },
    }


def _ids_for_nodes(nodes: List[Dict[str, Any]], *, boundary: bool | None = None, node_types: set[str] | None = None) -> List[str]:
    result: List[str] = []
    for node in nodes:
        if boundary is not None and bool(node.get("boundary")) != boundary:
            continue
        if node_types is not None and _text(node.get("node_type")) not in node_types:
            continue
        result.append(_text(node.get("node_id")))
    return _dedupe(result)


def _fact_ids_for(
    nodes: List[Dict[str, Any]],
    edges: List[Dict[str, Any]],
    *,
    boundary: bool | None = None,
    role_markers: Iterable[str] = (),
    relation_markers: Iterable[str] = (),
) -> List[str]:
    result: List[str] = []
    markers = [marker.lower() for marker in role_markers]
    relation_checks = [marker.lower() for marker in relation_markers]
    for item in [*nodes, *edges]:
        if boundary is not None and bool(item.get("boundary")) != boundary:
            continue
        role_blob = _blob(*_as_list(item.get("roles")), item.get("boundary_note"))
        relation = _text(item.get("relation")).lower()
        if markers and not any(marker in role_blob for marker in markers):
            continue
        if relation_checks and not any(marker in relation for marker in relation_checks):
            continue
        result.extend(_as_list(item.get("fact_ids")))
    return _dedupe(result)


def _node_ids_for_fact_ids(nodes: List[Dict[str, Any]], fact_ids: Iterable[str]) -> List[str]:
    wanted = set(_dedupe(fact_ids))
    result = []
    for node in nodes:
        if wanted.intersection(_dedupe(_as_list(node.get("fact_ids")))):
            result.append(_text(node.get("node_id")))
    return _dedupe(result)


def build_evidence_graph_lenses(graph: Dict[str, Any]) -> Dict[str, Any]:
    nodes = [_as_dict(item) for item in _as_list(graph.get("nodes"))]
    edges = [_as_dict(item) for item in _as_list(graph.get("edges"))]

    external_nodes = [
        node
        for node in nodes
        if _text(node.get("node_type")) in {"domain", "ip"}
    ]
    external_fact_ids = _dedupe(fid for node in external_nodes for fid in _as_list(node.get("fact_ids")))
    counter_fact_ids = _fact_ids_for(nodes, edges, role_markers=COUNTEREVIDENCE_MARKERS)
    gap_fact_ids = _fact_ids_for(nodes, edges, role_markers={"gap", "缺口"}) + _fact_ids_for(
        nodes,
        edges,
        relation_markers={"has_gap"},
    )
    gap_fact_ids = _dedupe(gap_fact_ids)
    action_fact_ids = _fact_ids_for(nodes, edges, role_markers={"action", "处置", "建议"}) + _fact_ids_for(
        nodes,
        edges,
        relation_markers={"recommends_check"},
    )
    action_fact_ids = _dedupe(action_fact_ids)

    return {
        "schema_version": "report-evidence-graph-lenses-v1",
        "lenses": {
            "main_chain": {
                "purpose": "已确认主链与核心证据",
                "node_ids": _ids_for_nodes(nodes, boundary=False),
                "fact_ids": _fact_ids_for(nodes, edges, boundary=False),
                "boundary_policy": "confirmed_or_context_only",
            },
            "candidate_expansion": {
                "purpose": "候选扩线、待验证资产和边界事件",
                "node_ids": _ids_for_nodes(nodes, boundary=True),
                "fact_ids": _fact_ids_for(nodes, edges, boundary=True),
                "boundary_policy": "candidate_only",
            },
            "external_infrastructure": {
                "purpose": "外联域名、IP、共享基础设施和封禁对象",
                "node_ids": _dedupe(_text(node.get("node_id")) for node in external_nodes),
                "fact_ids": external_fact_ids,
                "boundary_policy": "external_not_affected_asset",
            },
            "counterevidence": {
                "purpose": "背景、替代解释和反证",
                "node_ids": _node_ids_for_fact_ids(nodes, counter_fact_ids),
                "fact_ids": counter_fact_ids,
                "boundary_policy": "limits_stronger_claims",
            },
            "open_gaps": {
                "purpose": "仍需补证的缺口",
                "node_ids": _node_ids_for_fact_ids(nodes, gap_fact_ids),
                "fact_ids": gap_fact_ids,
                "boundary_policy": "report_as_limits",
            },
            "actions": {
                "purpose": "面向运维的下一步核查和处置",
                "node_ids": _node_ids_for_fact_ids(nodes, action_fact_ids),
                "fact_ids": action_fact_ids,
                "boundary_policy": "recommendation_not_observation",
            },
        },
    }


def build_hypothesis_board(graph: Dict[str, Any], lenses: Dict[str, Any]) -> Dict[str, Any]:
    """Compile graph lenses into report hypotheses without inventing evidence."""

    lens_map = _as_dict(lenses.get("lenses"))

    def facts(name: str) -> List[str]:
        return _dedupe(_as_list(_as_dict(lens_map.get(name)).get("fact_ids")))

    hypotheses = [
        {
            "hypothesis_id": "confirmed_main_chain",
            "claim": "当前已确认主链足以支撑交付结论。",
            "supporting_fact_ids": facts("main_chain"),
            "refuting_fact_ids": facts("counterevidence"),
            "gap_fact_ids": facts("open_gaps"),
            "action_fact_ids": facts("actions"),
            "claim_policy": "can_support_current_verdict_only",
        },
        {
            "hypothesis_id": "candidate_expansion",
            "claim": "候选资产或候选事件可能扩大影响范围，但尚需独立验证。",
            "supporting_fact_ids": facts("candidate_expansion"),
            "refuting_fact_ids": facts("counterevidence"),
            "gap_fact_ids": facts("open_gaps"),
            "action_fact_ids": facts("actions"),
            "claim_policy": "candidate_not_confirmed",
        },
        {
            "hypothesis_id": "benign_or_shared_infra_alternative",
            "claim": "共享基础设施、维护窗口或正常业务背景可能解释部分边界信号。",
            "supporting_fact_ids": facts("counterevidence"),
            "refuting_fact_ids": facts("main_chain"),
            "gap_fact_ids": facts("open_gaps"),
            "action_fact_ids": facts("actions"),
            "claim_policy": "limits_stronger_claims",
        },
        {
            "hypothesis_id": "insufficient_evidence_limits",
            "claim": "未闭合缺口限制攻击者控制、持久化、横向闭环或外传闭环等更强结论。",
            "supporting_fact_ids": facts("open_gaps"),
            "refuting_fact_ids": [],
            "gap_fact_ids": facts("open_gaps"),
            "action_fact_ids": facts("actions"),
            "claim_policy": "must_be_reported_as_boundary",
        },
    ]
    return {
        "schema_version": "report-hypothesis-board-v1",
        "graph_schema_version": _text(graph.get("schema_version")),
        "hypotheses": hypotheses,
    }


def build_graph_writer_brief(source_bundle: Dict[str, Any], fact_catalog: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Build graph-grounded writer input from deterministic facts."""

    bundle = _as_dict(source_bundle)
    facts = [_as_dict(item) for item in _as_list(fact_catalog)]
    graph = build_evidence_graph(bundle, facts)
    lenses = build_evidence_graph_lenses(graph)
    hypothesis_board = build_hypothesis_board(graph, lenses)
    return {
        "schema_version": "report-graph-writer-brief-v1",
        "writer_mode": "evidence_graph",
        "case_header": _as_dict(bundle.get("case_header")),
        "source_counts": _as_dict(bundle.get("source_counts")),
        "source_fact_catalog": facts,
        "evidence_graph": graph,
        "graph_lenses": lenses,
        "hypothesis_board": hypothesis_board,
        "writing_contract": {
            "purpose": "测试证据图和假设板是否能在不依赖 LLM material agent 的情况下，帮助 writer 组织报告论证。",
            "required_shape": [
                "# 首页摘要",
                "## 1. 事件结论与当前判断",
                "## 2. 事件过程与关键时间线",
                "## 3. 关键证据判断",
                "## 4. 影响范围、候选对象与外部基础设施",
                "## 5. 反证、替代解释与未闭合缺口",
                "## 6. 处置建议与后续核查",
            ],
            "section_lenses": {
                "timeline_process": ["main_chain", "candidate_expansion"],
                "evidence_judgment": ["main_chain", "open_gaps"],
                "relationship_scope": ["main_chain", "candidate_expansion", "external_infrastructure"],
                "counterevidence_limits": ["counterevidence", "open_gaps", "candidate_expansion"],
                "actions": ["actions", "open_gaps", "candidate_expansion"],
            },
            "section_hypotheses": {
                "evidence_judgment": ["confirmed_main_chain", "insufficient_evidence_limits"],
                "relationship_scope": ["candidate_expansion"],
                "counterevidence_limits": ["benign_or_shared_infra_alternative", "insufficient_evidence_limits"],
                "actions": ["candidate_expansion", "insufficient_evidence_limits"],
            },
            "claim_policies": [
                "confirmed_main_chain: may support current verdict, but not stronger conclusions absent supporting facts",
                "candidate_not_confirmed: candidate facts remain candidate until independent evidence appears",
                "limits_stronger_claims: counterevidence limits overclaiming rather than deleting the incident",
                "recommendation_not_observation: action facts are future work, not observed events",
            ],
        },
    }
