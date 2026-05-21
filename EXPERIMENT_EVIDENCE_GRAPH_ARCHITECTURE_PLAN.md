# Evidence Graph Agent Architecture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an experimental report pipeline that replaces the default LLM material-agent layer with a deterministic evidence graph, lightweight hypothesis search, and graph-grounded writer brief.

**Architecture:** The experiment keeps the current investigation loop and direct-source writer path runnable, then adds a new `evidence-graph` writer mode. Deterministic code converts `report_source_bundle + source_fact_catalog` into an evidence graph and graph lenses; a lightweight hypothesis planner organizes competing explanations; the DS v4 writer receives graph-grounded report plans instead of free-form material-agent summaries.

**Tech Stack:** Python 3 in the existing `trail-agent` conda env, existing LangChain-compatible LLM wrapper, no new runtime dependency, JSON artifacts, existing fixture/smoke scripts.

---

## Branch And Experiment Context

- Current branch: `experiment-evidence-graph-architecture`.
- Baseline branch lineage: `direct-v4-no-material-agent`.
- Current strong baseline output: `outputs/plan13_v47_direct_source_current_branch_live/`.
- New experiment output target: `outputs/plan13_v48_evidence_graph_writer_live/`.
- Main comparison paths:
  - `material-agent`: current report material loop.
  - `direct-source`: current DS v4 writer over deterministic fact catalog.
  - `evidence-graph`: new deterministic evidence graph + hypothesis planner + graph writer brief.

## Current Execution Status

- Tasks 1-7 are implemented on `experiment-evidence-graph-architecture`.
- Task 8 report-side A/B experiment has been run at `outputs/plan13_v48_evidence_graph_writer_live/`.
- Task 8 machine checks passed for all 5 cases: run return code `0`, report polish validation `clean`, hard failures `0`, material trace `skipped_evidence_graph_writer`.
- Task 8 manual comparison is recorded in `outputs/plan13_v48_evidence_graph_writer_live/manual_comparison.md`.
- Validation checklist has been rerun successfully for evidence graph builder, hypothesis board, graph writer brief, report polish validator, LLM agent protocol, and Python compilation.
- Acceptance status: evidence-graph mode passes the report-side experiment criteria, but should not be promoted as the default full pipeline yet.
- Current blocker before full-pipeline promotion: live investigation/reviewer calls still depend on the default `tool` / `chat` provider and produced upstream connection failures in v48. Writer-side DS v4 calls completed successfully.
- Follow-up verification: after explicitly routing investigator/reviewer to DeepSeek v4 in local `.env`, one representative evidence-graph live case completed at `outputs/plan13_v50_evidence_graph_all_ds_v4_one/multi_host_confirmed_spread_plus/` with report validation `clean`, hard failures `0`, soft warnings `0`, material trace `skipped_evidence_graph_writer`, and LLM errors `0`.
- Full routing verification: `outputs/plan13_v51_evidence_graph_all_ds_v4_live/` completed all 5 cases with run return code `0`, material trace `skipped_evidence_graph_writer`, and LLM errors `0` across the suite. This fixed the v48 upstream provider-noise problem.
- Writer hard-fail follow-up: v51 exposed one real writer drift in `shared_infra_multi_asset_needs_review`, where an action recommendation invented exact lookback-window times. The writer normalizer now rewrites unsupported action lookback windows to `当前调查窗口内` instead of preserving invented timestamps.
- Targeted fix verification: `outputs/plan13_v52_evidence_graph_all_ds_v4_fix_lookback/shared_infra_multi_asset_needs_review/` reran the failing case with run return code `0`, report validation `clean`, hard failures `0`, soft warnings `0`, material trace `skipped_evidence_graph_writer`, and LLM errors `0`.
- Task 9 advisory investigation-layer hypothesis board is now implemented in `demo_agent/incidents/agent.py` with tests in `tools/test_investigation_hypothesis_board.py`.
- Fresh 5-case verification after Task 9 is recorded at `outputs/plan13_v53_task9_evidence_graph_all_ds_v4_live/`; all 5 cases now return `0`, report validation is `clean`, material trace is `skipped_evidence_graph_writer`, and LLM errors are `0`.
- Next recommended step: review the v53 all-green evidence-graph output root and decide whether to keep evidence-graph as the preferred report-side path before promoting any further investigation-layer experiments.
- Follow-up architecture direction: the next investigation-layer experiment is now documented in [EXPERIMENT_INVESTIGATION_HYPOTHESIS_GRAPH_PLAN.md](/home/estar0x/project/maltrail_test/Trace-Agent/EXPERIMENT_INVESTIGATION_HYPOTHESIS_GRAPH_PLAN.md), which moves hypothesis tracking and information-gain planning into the investigation loop itself.

## Research Basis And Translation

- ReAct argues for interleaving reasoning traces and actions so the model can gather external information and update plans. Trace-Agent should apply this to investigation-layer tool choice, not to final report writing. Source: https://arxiv.org/abs/2210.03629.
- LATS and Tree of Thoughts motivate exploring multiple reasoning paths rather than committing to a single chain too early. Trace-Agent should keep a lightweight hypothesis board instead of full MCTS. Sources: https://arxiv.org/abs/2310.04406 and https://arxiv.org/abs/2305.10601.
- GraphRAG motivates building explicit graph structure before global summarization. Trace-Agent cases are naturally graphs of assets, events, indicators, external infrastructure, gaps, and counterevidence. Source: https://arxiv.org/abs/2404.16130.
- STORM motivates a pre-writing stage that builds outlines from multiple perspectives before drafting long-form prose. Trace-Agent should generate graph-grounded section lenses before asking the writer for final prose. Source: https://arxiv.org/abs/2402.14207.
- Self-RAG and Reflexion motivate critique/feedback loops without hardcoding case-specific rules. Trace-Agent should record report failure classes as eval memory and rubric feedback, not as brittle entity or phrasing validators. Sources: https://arxiv.org/abs/2310.11511 and https://arxiv.org/abs/2303.11366.

## Design Principles

- Deterministic code may normalize facts, build graph nodes and edges, create lenses, validate ids, and persist artifacts.
- LLMs may choose ambiguous investigation focus, rank hypotheses, and write final prose from graph-grounded input.
- Do not let LLMs rewrite source facts into new semantic facts.
- Do not add case-specific rules for fixture names, event ids, timestamps, assets, domains, or expected wording.
- Do not add validators that judge natural-language semantics using keyword windows.
- Keep fallback explicit: if graph build or writer fails, trace must say `evidence_graph_failed` and fall back to direct-source only when configured.
- No new dependencies in the first experiment; implement graph as JSON dictionaries and helper functions.

## Target Artifacts

Each `evidence-graph` run should save these files:

- `report_source_bundle.json`: existing factual boundary.
- `report_fact_cards.json`: existing report validation source.
- `source_fact_catalog.json` or embedded `source_fact_catalog` in writer brief: deterministic fact catalog.
- `report_evidence_graph.json`: graph nodes, edges, provenance, and graph stats.
- `report_hypothesis_board.json`: competing hypotheses, support/refute/gap/action references.
- `report_graph_writer_brief.json`: graph-grounded writing input.
- `report_polished.md`: final report.
- `report_polish_validation.json`: hard factual drift check only.

## Success Criteria

- All five fixture live cases produce `report_polished.md` with `report_writer_mode=evidence-graph`.
- `report_material_loop_trace.json` clearly says material agent was bypassed by evidence graph mode.
- `report_evidence_graph.json` contains no invented facts; every node and edge has `fact_ids` or `source_ids`.
- Candidate assets and candidate events appear in graph lenses as candidate/boundary, not confirmed scope.
- Confirmed chain, candidate expansion, shared infrastructure, counterevidence, open gaps, and actions are visible as separate graph lenses.
- Final reports are at least as useful as direct-source v47 on: factual correctness, boundary correctness, concrete actions, insight depth, and readability.
- The only blocking validator failures are unknown exact time, unknown IP, unknown domain, or schema/id corruption.

## Non-Goals

- Do not implement full Monte Carlo Tree Search.
- Do not replace the whole investigation loop in the first experiment.
- Do not remove material-agent code until A/B evidence shows the new path is better.
- Do not add a second writer agent or reviewer loop.
- Do not introduce Neo4j, networkx, vector databases, or other graph dependencies.
- Do not tune against individual fixture ids or expected phrases.

## File Map

- Create `demo_agent/incidents/evidence_graph.py`: deterministic graph builder, graph lenses, hypothesis board, writer brief compiler.
- Modify `demo_agent/incidents/report_agent_writer.py`: add evidence-graph prompt and renderer that consumes `report_graph_writer_brief`.
- Modify `demo_agent/incidents/render.py`: add `evidence-graph` mode and artifact persistence.
- Modify `demo_agent/entrypoints/langchain_agent.py`: expose `--report-writer-mode evidence-graph`.
- Create `tools/test_evidence_graph_builder.py`: deterministic unit tests for graph schema, provenance, candidate boundaries, and lenses.
- Create `tools/test_evidence_graph_writer_brief.py`: contract tests for graph writer brief.
- Create `tools/evaluate_report_quality.py`: lightweight rubric helper for comparing output directories.
- Modify `demo_agent/docs/README.md`: document experimental mode, artifacts, and how to run A/B.

---

## Task 1: Add Evidence Graph Builder Tests

**Files:**
- Create: `tools/test_evidence_graph_builder.py`
- Implementation target: `demo_agent/incidents/evidence_graph.py`

- [ ] **Step 1: Write failing tests for graph schema and provenance**

Create `tools/test_evidence_graph_builder.py` with:

```python
from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from demo_agent.incidents.evidence_graph import build_evidence_graph, build_evidence_graph_lenses  # noqa: E402


def _sample_source_bundle() -> dict:
    return {
        "case_header": {
            "case_id": "sample-case",
            "verdict_status": "confirmed",
            "severity": "high",
        },
        "source_counts": {"events": 3, "actions": 1},
    }


def _sample_fact_catalog() -> list[dict]:
    return [
        {
            "fact_id": "fact:event:001",
            "source_id": "event:evt-001",
            "fact_type": "event",
            "status": "confirmed",
            "time": "2026-07-14 01:10:00 UTC",
            "asset": "ws-a",
            "objects": ["c2.example", "203.0.113.10"],
            "summary_line": "ws-a connected to c2.example / 203.0.113.10.",
            "exact_fact_text": "ws-a connected to c2.example / 203.0.113.10.",
            "reporting_focus": "主支撑事件",
            "boundary_note": "",
            "candidate_or_boundary": False,
        },
        {
            "fact_id": "fact:event:002",
            "source_id": "event:evt-002",
            "fact_type": "event",
            "status": "candidate",
            "time": "2026-07-14 01:39:20 UTC",
            "asset": "ws-b",
            "objects": ["ws-c"],
            "summary_line": "ws-b had a candidate WMI event toward ws-c.",
            "exact_fact_text": "ws-b had a candidate WMI event toward ws-c.",
            "reporting_focus": "候选扩线",
            "boundary_note": "needs independent validation",
            "candidate_or_boundary": True,
        },
        {
            "fact_id": "fact:gap:001",
            "source_id": "gap:host-command-line",
            "fact_type": "gap",
            "status": "open",
            "summary_line": "Full command line is missing.",
            "exact_fact_text": "Full command line is missing.",
            "reporting_focus": "未闭合缺口",
            "boundary_note": "limits execution conclusion",
            "candidate_or_boundary": True,
        },
        {
            "fact_id": "fact:action:001",
            "source_id": "action:collect-command-line",
            "fact_type": "action",
            "status": "recommended",
            "asset": "ws-a",
            "objects": ["rundll32.exe"],
            "summary_line": "Collect full rundll32.exe command line.",
            "exact_fact_text": "Collect full rundll32.exe command line.",
            "reporting_focus": "处置建议",
            "boundary_note": "",
            "candidate_or_boundary": False,
        },
    ]


def test_build_evidence_graph_preserves_fact_provenance() -> None:
    graph = build_evidence_graph(_sample_source_bundle(), _sample_fact_catalog())

    assert graph["schema_version"] == "report-evidence-graph-v1"
    assert graph["case_header"]["case_id"] == "sample-case"
    assert graph["graph_stats"]["fact_count"] == 4
    assert graph["graph_stats"]["node_count"] >= 6
    assert graph["graph_stats"]["edge_count"] >= 3

    node_ids = {node["node_id"] for node in graph["nodes"]}
    assert "asset:ws-a" in node_ids
    assert "asset:ws-c" in node_ids
    assert "domain:c2.example" in node_ids
    assert "ip:203.0.113.10" in node_ids

    for node in graph["nodes"]:
        assert node["node_id"]
        assert node["node_type"]
        assert node["label"]
        assert node["fact_ids"] or node["source_ids"]

    for edge in graph["edges"]:
        assert edge["edge_id"]
        assert edge["source"] in node_ids
        assert edge["target"] in node_ids
        assert edge["relation"]
        assert edge["fact_ids"] or edge["source_ids"]


def test_build_evidence_graph_lenses_separate_confirmed_candidate_gap_and_actions() -> None:
    graph = build_evidence_graph(_sample_source_bundle(), _sample_fact_catalog())
    lenses = build_evidence_graph_lenses(graph)

    assert lenses["schema_version"] == "report-evidence-graph-lenses-v1"
    assert "main_chain" in lenses["lenses"]
    assert "candidate_expansion" in lenses["lenses"]
    assert "open_gaps" in lenses["lenses"]
    assert "actions" in lenses["lenses"]

    candidate = lenses["lenses"]["candidate_expansion"]
    assert "asset:ws-c" in candidate["node_ids"]
    assert candidate["boundary_policy"] == "candidate_only"

    actions = lenses["lenses"]["actions"]
    assert "fact:action:001" in actions["fact_ids"]
```

- [ ] **Step 2: Run tests and verify they fail because the module does not exist**

Run:

```bash
conda run -n trail-agent python tools/test_evidence_graph_builder.py
```

Expected result:

```text
ModuleNotFoundError: No module named 'demo_agent.incidents.evidence_graph'
```

---

## Task 2: Implement Deterministic Evidence Graph

**Files:**
- Create: `demo_agent/incidents/evidence_graph.py`
- Test: `tools/test_evidence_graph_builder.py`

- [ ] **Step 1: Create graph builder module**

Create `demo_agent/incidents/evidence_graph.py` with these public functions:

```python
from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, Iterable, List, Tuple


IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.IGNORECASE)


def _text(value: Any) -> str:
    return str(value or "").strip()


def _as_dict(value: Any) -> Dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _as_list(value: Any) -> List[Any]:
    return list(value) if isinstance(value, list) else []


def _dedupe(values: Iterable[str]) -> List[str]:
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
    raw = "|".join(_text(part) for part in parts if _text(part))
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]
    return f"{prefix}:{digest}"


def _object_values(fact: Dict[str, Any]) -> List[str]:
    objects = fact.get("objects")
    if isinstance(objects, list):
        return _dedupe(_text(item).strip("` ") for item in objects)
    obj = _text(fact.get("object"))
    if not obj:
        return []
    return _dedupe(part.strip("` ") for part in obj.split("/") if part.strip("` "))


def _node_id_for_value(value: str) -> Tuple[str, str]:
    label = _text(value)
    lowered = label.lower()
    if IP_RE.match(label):
        return f"ip:{label}", "ip"
    if DOMAIN_RE.match(lowered):
        return f"domain:{lowered}", "domain"
    if re.match(r"^[a-zA-Z0-9_.-]+$", label) and ("ws-" in lowered or "web-" in lowered or "app-" in lowered):
        return f"asset:{label}", "asset"
    if lowered.endswith((".exe", ".dll", ".ps1", ".aspx", ".dat", ".zip", ".7z")):
        return f"artifact:{label}", "artifact"
    return _stable_id("object", label), "object"


def _fact_status(fact: Dict[str, Any]) -> str:
    return _text(fact.get("status")) or ("candidate" if fact.get("candidate_or_boundary") else "unknown")


def _fact_is_boundary(fact: Dict[str, Any]) -> bool:
    status = _fact_status(fact).lower()
    blob = " ".join(
        _text(fact.get(key)).lower()
        for key in ("fact_type", "status", "classification", "reporting_focus", "boundary_note", "summary_line")
    )
    return bool(fact.get("candidate_or_boundary")) or any(
        marker in blob
        for marker in ("candidate", "open", "gap", "boundary", "待确认", "缺口", "边界", "反证")
    )


def _relation_for_fact(fact: Dict[str, Any]) -> str:
    fact_type = _text(fact.get("fact_type"))
    blob = " ".join(
        _text(fact.get(key)).lower()
        for key in ("summary_line", "exact_fact_text", "reporting_focus", "classification")
    )
    if fact_type == "action":
        return "recommends_check"
    if fact_type == "gap":
        return "has_gap"
    if "解析" in blob or "dns" in blob:
        return "resolved"
    if "rundll32" in blob or "powershell" in blob or "执行" in blob:
        return "executed"
    if "wmi" in blob or "psexec" in blob or "横向" in blob or "远程" in blob:
        return "lateral_candidate" if _fact_is_boundary(fact) else "lateral_signal"
    if "共享" in blob or "background" in blob or "背景" in blob:
        return "background_context"
    return "connected_to"


def build_evidence_graph(source_bundle: Dict[str, Any], fact_catalog: List[Dict[str, Any]]) -> Dict[str, Any]:
    bundle = _as_dict(source_bundle)
    facts = [_as_dict(item) for item in _as_list(fact_catalog)]
    nodes: Dict[str, Dict[str, Any]] = {}
    edges: Dict[str, Dict[str, Any]] = {}

    def add_node(node_id: str, node_type: str, label: str, fact: Dict[str, Any]) -> None:
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
        node["fact_ids"] = _dedupe(node["fact_ids"] + [_text(fact.get("fact_id"))])
        node["source_ids"] = _dedupe(node["source_ids"] + [_text(fact.get("source_id"))])
        node["roles"] = _dedupe(node["roles"] + [_text(fact.get("fact_type")), _text(fact.get("reporting_focus"))])
        node["boundary"] = bool(node["boundary"] or _fact_is_boundary(fact))
        if _fact_status(fact) == "confirmed":
            node["status"] = "confirmed"

    def add_edge(source: str, target: str, relation: str, fact: Dict[str, Any]) -> None:
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
                "boundary": False,
                "boundary_note": "",
            },
        )
        edge["fact_ids"] = _dedupe(edge["fact_ids"] + [_text(fact.get("fact_id"))])
        edge["source_ids"] = _dedupe(edge["source_ids"] + [_text(fact.get("source_id"))])
        edge["boundary"] = bool(edge["boundary"] or _fact_is_boundary(fact))
        if _text(fact.get("boundary_note")):
            edge["boundary_note"] = _text(fact.get("boundary_note"))

    for fact in facts:
        fact_id = _text(fact.get("fact_id"))
        source_id = _text(fact.get("source_id"))
        if not fact_id and not source_id:
            continue
        fact_node_id = f"fact:{fact_id}" if fact_id and not fact_id.startswith("fact:") else fact_id
        add_node(fact_node_id, "fact", fact_id or source_id, fact)

        asset = _text(fact.get("asset"))
        subject_node_id = fact_node_id
        if asset:
            subject_node_id = f"asset:{asset}"
            add_node(subject_node_id, "asset", asset, fact)
            add_edge(fact_node_id, subject_node_id, "mentions_asset", fact)

        for value in _object_values(fact):
            object_node_id, object_type = _node_id_for_value(value)
            add_node(object_node_id, object_type, value, fact)
            add_edge(subject_node_id, object_node_id, _relation_for_fact(fact), fact)

    graph = {
        "schema_version": "report-evidence-graph-v1",
        "case_header": _as_dict(bundle.get("case_header")),
        "source_counts": _as_dict(bundle.get("source_counts")),
        "nodes": list(nodes.values()),
        "edges": list(edges.values()),
        "graph_stats": {
            "fact_count": len(facts),
            "node_count": len(nodes),
            "edge_count": len(edges),
        },
    }
    return graph
```

- [ ] **Step 2: Add graph lens helper**

Append this function to `demo_agent/incidents/evidence_graph.py`:

```python
def _ids_for_nodes(nodes: List[Dict[str, Any]], *, boundary: bool | None = None, node_types: set[str] | None = None) -> List[str]:
    result: List[str] = []
    for node in nodes:
        if boundary is not None and bool(node.get("boundary")) != boundary:
            continue
        if node_types is not None and _text(node.get("node_type")) not in node_types:
            continue
        result.append(_text(node.get("node_id")))
    return _dedupe(result)


def _fact_ids_for(nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]], *, boundary: bool | None = None, role_contains: str = "") -> List[str]:
    result: List[str] = []
    for item in nodes + edges:
        if boundary is not None and bool(item.get("boundary")) != boundary:
            continue
        if role_contains:
            roles_blob = " ".join(_text(role) for role in item.get("roles", []))
            if role_contains not in roles_blob and role_contains not in _text(item.get("relation")):
                continue
        result.extend(_text(value) for value in item.get("fact_ids", []))
    return _dedupe(result)


def _fact_ids_for_role_markers(nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]], markers: List[str]) -> List[str]:
    result: List[str] = []
    lowered_markers = [marker.lower() for marker in markers]
    for item in nodes + edges:
        blob = " ".join(
            [_text(item.get("relation")).lower()]
            + [_text(role).lower() for role in item.get("roles", [])]
            + [_text(item.get("boundary_note")).lower()]
        )
        if any(marker in blob for marker in lowered_markers):
            result.extend(_text(value) for value in item.get("fact_ids", []))
    return _dedupe(result)


def build_evidence_graph_lenses(graph: Dict[str, Any]) -> Dict[str, Any]:
    nodes = [_as_dict(item) for item in _as_list(graph.get("nodes"))]
    edges = [_as_dict(item) for item in _as_list(graph.get("edges"))]
    external_nodes = [
        node
        for node in nodes
        if _text(node.get("node_type")) in {"domain", "ip"}
        and any(role for role in node.get("roles", []) if "外部" in _text(role) or "基础设施" in _text(role))
    ]
    action_nodes = [node for node in nodes if any("处置" in _text(role) for role in node.get("roles", []))]
    gap_nodes = [node for node in nodes if any("缺口" in _text(role) or "gap" in _text(role).lower() for role in node.get("roles", []))]

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
                "fact_ids": _dedupe(fid for node in external_nodes for fid in node.get("fact_ids", [])),
                "boundary_policy": "external_not_affected_asset",
            },
            "counterevidence": {
                "purpose": "背景、替代解释和反证",
                "node_ids": _ids_for_nodes(nodes, node_types={"fact", "object", "domain", "ip", "asset"}),
                "fact_ids": _fact_ids_for_role_markers(nodes, edges, ["反证", "背景", "替代", "共享", "background", "alternative"]),
                "boundary_policy": "limits_stronger_claims",
            },
            "open_gaps": {
                "purpose": "仍需补证的缺口",
                "node_ids": _dedupe(_text(node.get("node_id")) for node in gap_nodes),
                "fact_ids": _dedupe(fid for node in gap_nodes for fid in node.get("fact_ids", [])),
                "boundary_policy": "report_as_limits",
            },
            "actions": {
                "purpose": "面向运维的下一步核查和处置",
                "node_ids": _dedupe(_text(node.get("node_id")) for node in action_nodes),
                "fact_ids": _dedupe(fid for node in action_nodes for fid in node.get("fact_ids", [])),
                "boundary_policy": "recommendation_not_observation",
            },
        },
    }
```

- [ ] **Step 3: Run graph builder tests**

Run:

```bash
conda run -n trail-agent python tools/test_evidence_graph_builder.py
```

Expected result:

```text
no traceback
```

---

## Task 3: Add Hypothesis Board Compiler

**Files:**
- Modify: `demo_agent/incidents/evidence_graph.py`
- Create: `tools/test_evidence_graph_hypotheses.py`

- [ ] **Step 1: Write failing tests for hypothesis board**

Create `tools/test_evidence_graph_hypotheses.py` with:

```python
from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from demo_agent.incidents.evidence_graph import build_hypothesis_board  # noqa: E402


def test_hypothesis_board_separates_confirmed_candidate_and_benign_explanations() -> None:
    graph = {
        "schema_version": "report-evidence-graph-v1",
        "nodes": [
            {"node_id": "fact:confirmed", "node_type": "fact", "label": "confirmed", "boundary": False, "fact_ids": ["fact:confirmed"], "source_ids": ["event:1"], "roles": ["主支撑事件"]},
            {"node_id": "fact:candidate", "node_type": "fact", "label": "candidate", "boundary": True, "fact_ids": ["fact:candidate"], "source_ids": ["event:2"], "roles": ["候选扩线"]},
            {"node_id": "fact:background", "node_type": "fact", "label": "background", "boundary": True, "fact_ids": ["fact:background"], "source_ids": ["event:3"], "roles": ["反证事实"]},
            {"node_id": "fact:gap", "node_type": "fact", "label": "gap", "boundary": True, "fact_ids": ["fact:gap"], "source_ids": ["gap:1"], "roles": ["未闭合缺口"]},
        ],
        "edges": [],
    }
    lenses = {
        "schema_version": "report-evidence-graph-lenses-v1",
        "lenses": {
            "main_chain": {"fact_ids": ["fact:confirmed"]},
            "candidate_expansion": {"fact_ids": ["fact:candidate"]},
            "counterevidence": {"fact_ids": ["fact:background"]},
            "open_gaps": {"fact_ids": ["fact:gap"]},
            "actions": {"fact_ids": []},
        },
    }

    board = build_hypothesis_board(graph, lenses)

    assert board["schema_version"] == "report-hypothesis-board-v1"
    names = [item["hypothesis_id"] for item in board["hypotheses"]]
    assert "confirmed_main_chain" in names
    assert "candidate_expansion" in names
    assert "benign_or_shared_infra_alternative" in names
    assert "insufficient_evidence_limits" in names

    confirmed = next(item for item in board["hypotheses"] if item["hypothesis_id"] == "confirmed_main_chain")
    assert confirmed["supporting_fact_ids"] == ["fact:confirmed"]
    assert confirmed["claim_policy"] == "can_support_current_verdict_only"

    candidate = next(item for item in board["hypotheses"] if item["hypothesis_id"] == "candidate_expansion")
    assert candidate["supporting_fact_ids"] == ["fact:candidate"]
    assert candidate["claim_policy"] == "candidate_not_confirmed"
```

- [ ] **Step 2: Implement hypothesis compiler**

Append to `demo_agent/incidents/evidence_graph.py`:

```python
def build_hypothesis_board(graph: Dict[str, Any], lenses: Dict[str, Any]) -> Dict[str, Any]:
    lens_map = _as_dict(lenses.get("lenses"))

    def facts(name: str) -> List[str]:
        return _dedupe(_text(item) for item in _as_list(_as_dict(lens_map.get(name)).get("fact_ids")))

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
```

- [ ] **Step 3: Run hypothesis tests**

Run:

```bash
conda run -n trail-agent python tools/test_evidence_graph_hypotheses.py
```

Expected result:

```text
no traceback
```

---

## Task 4: Build Graph Writer Brief Contract

**Files:**
- Modify: `demo_agent/incidents/evidence_graph.py`
- Create: `tools/test_evidence_graph_writer_brief.py`

- [ ] **Step 1: Write failing writer brief contract test**

Create `tools/test_evidence_graph_writer_brief.py` with:

```python
from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from demo_agent.incidents.evidence_graph import build_graph_writer_brief  # noqa: E402


def test_graph_writer_brief_contains_graph_lenses_hypotheses_and_constraints() -> None:
    source_bundle = {
        "case_header": {"case_id": "sample-case", "verdict_status": "confirmed"},
        "source_counts": {"events": 1},
    }
    fact_catalog = [
        {
            "fact_id": "fact:event:001",
            "source_id": "event:evt-001",
            "fact_type": "event",
            "status": "confirmed",
            "time": "2026-07-14 01:10:00 UTC",
            "asset": "ws-a",
            "objects": ["c2.example"],
            "summary_line": "ws-a connected to c2.example.",
            "exact_fact_text": "ws-a connected to c2.example.",
            "reporting_focus": "主支撑事件",
            "candidate_or_boundary": False,
        }
    ]

    brief = build_graph_writer_brief(source_bundle, fact_catalog)

    assert brief["schema_version"] == "report-graph-writer-brief-v1"
    assert brief["writer_mode"] == "evidence_graph"
    assert brief["evidence_graph"]["schema_version"] == "report-evidence-graph-v1"
    assert brief["graph_lenses"]["schema_version"] == "report-evidence-graph-lenses-v1"
    assert brief["hypothesis_board"]["schema_version"] == "report-hypothesis-board-v1"
    assert "required_shape" in brief["writing_contract"]
    assert "candidate_not_confirmed" in " ".join(brief["writing_contract"]["claim_policies"])
```

- [ ] **Step 2: Implement graph writer brief compiler**

Append to `demo_agent/incidents/evidence_graph.py`:

```python
def build_graph_writer_brief(source_bundle: Dict[str, Any], fact_catalog: List[Dict[str, Any]]) -> Dict[str, Any]:
    graph = build_evidence_graph(source_bundle, fact_catalog)
    lenses = build_evidence_graph_lenses(graph)
    hypothesis_board = build_hypothesis_board(graph, lenses)
    return {
        "schema_version": "report-graph-writer-brief-v1",
        "writer_mode": "evidence_graph",
        "case_header": _as_dict(source_bundle.get("case_header")),
        "source_counts": _as_dict(source_bundle.get("source_counts")),
        "source_fact_catalog": [_as_dict(item) for item in _as_list(fact_catalog)],
        "evidence_graph": graph,
        "graph_lenses": lenses,
        "hypothesis_board": hypothesis_board,
        "writing_contract": {
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
```

- [ ] **Step 3: Run writer brief tests**

Run:

```bash
conda run -n trail-agent python tools/test_evidence_graph_writer_brief.py
```

Expected result:

```text
no traceback
```

---

## Task 5: Add Evidence-Graph Writer Mode

**Files:**
- Modify: `demo_agent/incidents/report_agent_writer.py`
- Modify: `demo_agent/incidents/render.py`
- Modify: `demo_agent/entrypoints/langchain_agent.py`
- Test: `tools/test_evidence_graph_writer_brief.py`

- [ ] **Step 1: Add imports and writer prompt**

In `demo_agent/incidents/report_agent_writer.py`, import:

```python
from .evidence_graph import build_graph_writer_brief
```

Add a new prompt constant:

```python
EVIDENCE_GRAPH_WRITER_SYSTEM_PROMPT = """你是 Trace-Agent 的资深安全事件报告 writer。本次输入是 report_graph_writer_brief。

事实边界：
- source_fact_catalog 是唯一事实来源。
- evidence_graph 和 graph_lenses 只组织事实关系，不新增事实。
- hypothesis_board 是写作论证视角，不是额外证据。
- 任何候选、边界、反证、open gap、action fact 都不能被写成当前已确认事实。

写作策略：
- 第 2 节按 graph_lenses.main_chain 写主线推进，可补充 candidate_expansion 但必须标明待验证。
- 第 3 节结合 graph_lenses.main_chain 与 hypothesis_board.confirmed_main_chain，写当前结论为什么成立；同时用 insufficient_evidence_limits 说明哪些更强结论仍不成立。
- 第 4 节写确认资产、候选资产、核心外部基础设施、共享或背景基础设施，不能把外部 IP 写成受影响资产。
- 第 5 节结合 graph_lenses.counterevidence、graph_lenses.open_gaps 与 hypothesis_board.benign_or_shared_infra_alternative，写反证、替代解释和缺口如何限制结论上限。
- 第 6 节写行动建议，每条包含对象、日志源或字段、验证目标。

输出格式：
- 只输出中文 Markdown 正文。
- 严格使用 writing_contract.required_shape 的标题。
- 不输出 JSON、fact_id、source_id、工具名、内部状态或解释过程。
- 不发明事实卡之外的精确时间、IP、域名、资产、进程、文件或 IOC。
"""
```

- [ ] **Step 2: Add renderer functions**

In `demo_agent/incidents/report_agent_writer.py`, add:

```python
def render_polished_body_from_graph_writer_brief(llm: Any, writer_brief: Dict[str, Any]) -> str:
    from langchain_core.prompts import ChatPromptTemplate

    prompt = ChatPromptTemplate.from_messages(
        [
            ("system", EVIDENCE_GRAPH_WRITER_SYSTEM_PROMPT),
            (
                "user",
                "请仅基于以下 report_graph_writer_brief 生成完整 Markdown 正文：\n"
                "{writer_brief_json}",
            ),
        ]
    )
    writer = llm.bind(max_tokens=7000, temperature=0) if hasattr(llm, "bind") else llm
    response = invoke_llm_with_trace(
        writer,
        prompt.format_messages(writer_brief_json=_json(writer_brief)),
        role="report_agent_writer",
        extra={"writer_mode": "evidence_graph"},
    )
    return _normalize_writer_markdown(str(getattr(response, "content", "") or "").strip(), writer_brief)


def render_polished_body_from_evidence_graph(llm: Any, source_bundle: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    fact_catalog = [_as_dict(item) for item in build_source_fact_catalog(source_bundle)]
    writer_brief = build_graph_writer_brief(source_bundle, fact_catalog)
    return render_polished_body_from_graph_writer_brief(llm, writer_brief), writer_brief
```

- [ ] **Step 3: Wire render mode**

In `demo_agent/incidents/render.py`, extend imports:

```python
from .report_agent_writer import (
    build_report_writer_brief,
    build_direct_source_writer_brief,
    render_polished_body_from_direct_source_brief,
    render_polished_body_from_graph_writer_brief,
    render_polished_body_from_writer_brief,
)
from .evidence_graph import build_graph_writer_brief
from .report_agent_tools import build_source_fact_catalog
```

In `render_incident_report_with_llm()`, after `direct_source_writer`, add:

```python
evidence_graph_writer = report_writer_mode in {"evidence-graph", "evidence_graph", "graph"}
```

Update `_with_report_agent_artifacts()` so evidence-graph mode does not claim report-agent materials are enabled:

```python
"report_agent_materials_enabled": bool(use_report_agent_materials and not direct_source_writer and not evidence_graph_writer),
```

Before the direct-source block, add an `if evidence_graph_writer:` block:

```python
    if evidence_graph_writer:
        try:
            source_fact_catalog = build_source_fact_catalog(report_source_bundle)
            report_writer_brief = build_graph_writer_brief(report_source_bundle, source_fact_catalog)
            report_writer_materials = {
                "schema_version": "report-writer-materials-evidence-graph-experiment-v1",
                "material_agent_bypassed": True,
                "case_header": report_writer_brief.get("case_header") or {},
                "source_fact_catalog": report_writer_brief.get("source_fact_catalog") or [],
                "evidence_graph": report_writer_brief.get("evidence_graph") or {},
                "graph_lenses": report_writer_brief.get("graph_lenses") or {},
                "hypothesis_board": report_writer_brief.get("hypothesis_board") or {},
                "writing_contract": report_writer_brief.get("writing_contract") or {},
            }
            report_material_loop_trace = {
                "schema_version": "report-material-loop-trace-v1",
                "status": "skipped_evidence_graph_writer",
                "material_agent_bypassed": True,
                "validation": {"ok": True, "mode": "evidence_graph"},
            }
            body = render_polished_body_from_graph_writer_brief(llm, report_writer_brief)
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
            report_agent_error = "evidence_graph_writer_empty_response"
        except Exception as exc:
            report_agent_error = f"evidence_graph_writer:{type(exc).__name__}: {exc}"
        return _with_report_agent_artifacts({
            "report_markdown": deterministic,
            "report_polished_markdown": "",
            "report_appendix_markdown": appendix,
            "report_fact_cards": report_fact_cards,
            "report_polish_input": polish_input,
            "report_polish_brief": polish_brief,
            "report_polish_validation": skipped_validation,
            "report_polish_error": report_agent_error,
        })
```

- [ ] **Step 4: Extend CLI mode choices**

In `demo_agent/entrypoints/langchain_agent.py`, update the parser:

```python
choices=["", "material-agent", "direct-source", "evidence-graph"],
help="报告 writer 实验模式：默认 material-agent；direct-source 跳过 material agent；evidence-graph 使用证据图和假设板写作。",
```

- [ ] **Step 5: Run compile checks**

Run:

```bash
conda run -n trail-agent python -m py_compile \
  demo_agent/incidents/evidence_graph.py \
  demo_agent/incidents/report_agent_writer.py \
  demo_agent/incidents/render.py \
  demo_agent/entrypoints/langchain_agent.py
```

Expected result:

```text
no output
```

---

## Task 6: Persist Graph Artifacts As First-Class Outputs

**Files:**
- Modify: `demo_agent/entrypoints/langchain_agent.py`
- No change expected in `demo_agent/incidents/agent.py`; it already returns `report_writer_materials`, `report_writer_brief`, and `report_material_loop_trace`.

- [ ] **Step 1: Add explicit graph artifact writes**

In `demo_agent/entrypoints/langchain_agent.py`, after existing `report_writer_brief` and `report_writer_materials` variables are assigned, add:

```python
report_evidence_graph = (report_writer_brief or {}).get("evidence_graph") or (report_writer_materials or {}).get("evidence_graph") or {}
report_hypothesis_board = (report_writer_brief or {}).get("hypothesis_board") or (report_writer_materials or {}).get("hypothesis_board") or {}
```

After the existing `save_json(out_dir / "report_writer_brief.json", report_writer_brief)` block, add:

```python
if report_evidence_graph:
    save_json(out_dir / "report_evidence_graph.json", report_evidence_graph)
if report_hypothesis_board:
    save_json(out_dir / "report_hypothesis_board.json", report_hypothesis_board)
if report_writer_brief and report_writer_brief.get("schema_version") == "report-graph-writer-brief-v1":
    save_json(out_dir / "report_graph_writer_brief.json", report_writer_brief)
```

In the response path section, add:

```python
if report_evidence_graph:
    response["report_evidence_graph_path"] = str((out_dir / "report_evidence_graph.json").resolve())
if report_hypothesis_board:
    response["report_hypothesis_board_path"] = str((out_dir / "report_hypothesis_board.json").resolve())
if report_writer_brief and report_writer_brief.get("schema_version") == "report-graph-writer-brief-v1":
    response["report_graph_writer_brief_path"] = str((out_dir / "report_graph_writer_brief.json").resolve())
```

- [ ] **Step 2: Run one live fixture to confirm files exist**

Run with the same temporary DS v4 environment used for live report checks:

```bash
conda run -n trail-agent python -m demo_agent \
  --alert fixtures/incidents/shared_infra_multi_asset_needs_review \
  --out outputs/plan13_v48_graph_artifact_probe/shared_infra_multi_asset_needs_review \
  --mode incident-agent \
  --decision-mode llm_agent \
  --use-report-agent-materials \
  --report-writer-mode evidence-graph
```

Expected result:

```text
command exits 0
```

Then check:

```bash
test -f outputs/plan13_v48_graph_artifact_probe/shared_infra_multi_asset_needs_review/report_writer_brief.json
test -f outputs/plan13_v48_graph_artifact_probe/shared_infra_multi_asset_needs_review/report_writer_materials.json
test -f outputs/plan13_v48_graph_artifact_probe/shared_infra_multi_asset_needs_review/report_evidence_graph.json
test -f outputs/plan13_v48_graph_artifact_probe/shared_infra_multi_asset_needs_review/report_hypothesis_board.json
test -f outputs/plan13_v48_graph_artifact_probe/shared_infra_multi_asset_needs_review/report_graph_writer_brief.json
```

Expected result:

```text
all test commands exit 0
```

---

## Task 7: Add Report Quality Rubric Helper

**Files:**
- Create: `tools/evaluate_report_quality.py`
- Create: `docs/report_quality_rubric.md`

- [ ] **Step 1: Create rubric documentation**

Create `docs/report_quality_rubric.md`:

```markdown
# Report Quality Rubric

Score each dimension from 1 to 5.

## Dimensions

- Factual grounding: every concrete time, asset, IOC, process, file, and conclusion is traceable to artifacts.
- Boundary correctness: candidate assets, shared infrastructure, background events, and gaps are not promoted to confirmed scope.
- Actionability: recommendations name the object, data source or field, and validation target.
- Analytical depth: the report explains why evidence changes the incident judgment instead of only restating chronology.
- Non-repetition: sections have distinct jobs and do not repeat the same facts without a different analytical role.
- Operator readability: the report can be read by security operations and infrastructure teams without knowing Trace-Agent internals.

## Manual Review Notes

Record the strongest paragraph, weakest paragraph, one suspected overclaim, one missing action detail, and one comparison against the baseline report.
```

- [ ] **Step 2: Create lightweight evaluator**

Create `tools/evaluate_report_quality.py`:

```python
from __future__ import annotations

import argparse
import json
from pathlib import Path


DIMENSIONS = [
    "factual_grounding",
    "boundary_correctness",
    "actionability",
    "analytical_depth",
    "non_repetition",
    "operator_readability",
]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.exists() else ""


def _validation_status(case_dir: Path) -> dict:
    path = case_dir / "report_polish_validation.json"
    if not path.exists():
        return {"status": "missing", "issue_counts": {"hard_fail": 0, "soft_warn": 0}}
    return json.loads(path.read_text(encoding="utf-8"))


def _case_summary(case_dir: Path) -> dict:
    report = _read(case_dir / "report_polished.md")
    validation = _validation_status(case_dir)
    material_trace_path = case_dir / "report_material_loop_trace.json"
    trace = json.loads(material_trace_path.read_text(encoding="utf-8")) if material_trace_path.exists() else {}
    return {
        "case": case_dir.name,
        "report_chars": len(report),
        "report_lines": len(report.splitlines()),
        "validation_status": validation.get("status"),
        "validation_issues": validation.get("issue_counts"),
        "material_status": trace.get("status"),
        "material_agent_bypassed": trace.get("material_agent_bypassed"),
        "mentions_candidate": "候选" in report,
        "mentions_boundary": "边界" in report or "限制" in report,
        "mentions_action_fields": any(term in report for term in ["命令行", "日志", "字段", "哈希", "父进程", "DLL", "验证目标"]),
        "manual_scores": {dimension: None for dimension in DIMENSIONS},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Summarize Trace-Agent report quality signals for manual review.")
    parser.add_argument("--root", required=True, help="output root containing one directory per case")
    parser.add_argument("--out", default="", help="optional JSON summary output path")
    args = parser.parse_args()

    root = Path(args.root)
    cases = sorted(path for path in root.iterdir() if path.is_dir())
    summary = {"root": str(root), "cases": [_case_summary(case_dir) for case_dir in cases]}
    text = json.dumps(summary, ensure_ascii=False, indent=2)
    print(text)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
```

- [ ] **Step 3: Run evaluator on v47 baseline**

Run:

```bash
conda run -n trail-agent python tools/evaluate_report_quality.py \
  --root outputs/plan13_v47_direct_source_current_branch_live \
  --out outputs/plan13_v47_direct_source_current_branch_live/report_quality_summary.json
```

Expected result:

```text
JSON summary printed and report_quality_summary.json written
```

---

## Task 8: Run A/B Experiments

**Files:**
- Output only under `outputs/`.

- [ ] **Step 1: Run one graph-mode live case**

Run with temporary DS v4 key in environment, not committed to files:

```bash
OUT=outputs/plan13_v48_evidence_graph_writer_live_one
CASE=multi_host_confirmed_spread_plus
mkdir -p "$OUT/$CASE"
conda run -n trail-agent python -m demo_agent \
  --alert "fixtures/incidents/$CASE" \
  --out "$OUT/$CASE" \
  --mode incident-agent \
  --decision-mode llm_agent \
  --use-report-agent-materials \
  --report-writer-mode evidence-graph \
  > "$OUT/$CASE/run_stdout.json" \
  2> "$OUT/$CASE/run_stderr.log"
printf '%s\n' "$?" > "$OUT/$CASE/run_rc.txt"
```

Expected result:

```text
run_rc.txt contains 0
```

- [ ] **Step 2: Inspect artifacts before broad run**

Run:

```bash
python3 - <<'PY'
import json
from pathlib import Path
case = Path("outputs/plan13_v48_evidence_graph_writer_live_one/multi_host_confirmed_spread_plus")
for name in ["report_writer_brief.json", "report_writer_materials.json", "report_polish_validation.json", "report_polished.md"]:
    path = case / name
    print(name, path.exists(), path.stat().st_size if path.exists() else 0)
trace = json.loads((case / "report_material_loop_trace.json").read_text())
print(trace.get("status"), trace.get("material_agent_bypassed"))
PY
```

Expected result:

```text
report files exist
status is skipped_evidence_graph_writer
material_agent_bypassed is True
```

- [ ] **Step 3: Run five-case graph-mode live eval**

Run:

```bash
OUT=outputs/plan13_v48_evidence_graph_writer_live
mkdir -p "$OUT"
for CASE in \
  multi_host_confirmed_spread_plus \
  shared_infra_multi_asset_needs_review \
  suspected_exfil_after_execution \
  web_initial_access_to_beacon \
  web_initial_access_without_execution
do
  CASE_OUT="$OUT/$CASE"
  mkdir -p "$CASE_OUT"
  conda run -n trail-agent python -m demo_agent \
    --alert "fixtures/incidents/$CASE" \
    --out "$CASE_OUT" \
    --mode incident-agent \
    --decision-mode llm_agent \
    --use-report-agent-materials \
    --report-writer-mode evidence-graph \
    > "$CASE_OUT/run_stdout.json" \
    2> "$CASE_OUT/run_stderr.log"
  printf '%s\n' "$?" > "$CASE_OUT/run_rc.txt"
done
```

Expected result:

```text
each run_rc.txt contains 0
```

- [ ] **Step 4: Generate quality summaries**

Run:

```bash
conda run -n trail-agent python tools/evaluate_report_quality.py \
  --root outputs/plan13_v48_evidence_graph_writer_live \
  --out outputs/plan13_v48_evidence_graph_writer_live/report_quality_summary.json
```

Expected result:

```text
report_quality_summary.json written
```

- [ ] **Step 5: Manual comparison**

Open these pairs:

```text
outputs/plan13_v47_direct_source_current_branch_live/multi_host_confirmed_spread_plus/report_polished.md
outputs/plan13_v48_evidence_graph_writer_live/multi_host_confirmed_spread_plus/report_polished.md
outputs/plan13_v47_direct_source_current_branch_live/shared_infra_multi_asset_needs_review/report_polished.md
outputs/plan13_v48_evidence_graph_writer_live/shared_infra_multi_asset_needs_review/report_polished.md
```

Score using `docs/report_quality_rubric.md`.

Expected decision rule:

```text
Evidence-graph mode is promoted only if it improves actionability or analytical depth without reducing factual grounding or boundary correctness.
```

---

## Task 9: Optional Investigation-Layer Hypothesis Board

**Files:**
- Modify: `demo_agent/incidents/agent.py`
- Create: `tools/test_investigation_hypothesis_board.py`

This task should start only after the report-side graph experiment shows value. It is intentionally not required for v48.

- [ ] **Step 1: Add session-state hypothesis board**

Add to `_initial_incident_state()` or the session-state initializer:

```python
"hypothesis_board": {
    "schema_version": "investigation-hypothesis-board-v1",
    "active": [],
    "closed": [],
    "last_updated_round": 0,
}
```

- [ ] **Step 2: Update reviewer context**

Add to review context:

```python
"hypothesis_board": dict(session_state.get("hypothesis_board") or {}),
```

- [ ] **Step 3: Prompt investigator to choose tools by discriminating hypotheses**

Add to investigator prompt:

```text
当存在多个合理假设时，优先选择最能区分这些假设的工具调用。
例如：真实传播 vs 共享基础设施背景，优先查询候选资产主机侧证据和共享基础设施上下文。
```

- [ ] **Step 4: Keep this advisory, not a hard gate**

Do not block finish solely because the hypothesis board has open candidates. The reviewer may allow delivery when the main chain is reportable and open candidates can be written as boundaries.

---

## Task 10: Documentation And Cleanup

**Files:**
- Modify: `demo_agent/docs/README.md`
- Modify: `AGENTS.md` only if workflow rules change.

- [ ] **Step 1: Document evidence-graph mode**

Add to `demo_agent/docs/README.md`:

````markdown
### Evidence Graph Writer Experiment

Use this mode to bypass the LLM material agent and compile a deterministic evidence graph before writing:

```bash
conda run -n trail-agent python -m demo_agent \
  --alert fixtures/incidents/multi_host_confirmed_spread_plus \
  --out outputs/plan13_v48_evidence_graph_writer_live/multi_host_confirmed_spread_plus \
  --mode incident-agent \
  --decision-mode llm_agent \
  --use-report-agent-materials \
  --report-writer-mode evidence-graph
```

Expected artifacts include `report_writer_brief.json`, `report_writer_materials.json`, `report_material_loop_trace.json`, and `report_polish_validation.json`.
````

- [ ] **Step 2: Run documentation grep**

Run:

```bash
rg -n "evidence-graph|direct-source|material-agent" demo_agent/docs/README.md AGENTS.md
```

Expected result:

```text
evidence-graph command and artifact description are present
```

---

## Validation Checklist

Run after implementation:

```bash
conda run -n trail-agent python tools/test_evidence_graph_builder.py
conda run -n trail-agent python tools/test_evidence_graph_hypotheses.py
conda run -n trail-agent python tools/test_evidence_graph_writer_brief.py
conda run -n trail-agent python tools/test_report_polish_validator.py
conda run -n trail-agent python tools/test_llm_agent_protocol.py
conda run -n trail-agent python -m py_compile \
  demo_agent/incidents/evidence_graph.py \
  demo_agent/incidents/report_agent_writer.py \
  demo_agent/incidents/render.py \
  demo_agent/entrypoints/langchain_agent.py
```

Run after live evaluation:

```bash
conda run -n trail-agent python tools/evaluate_report_quality.py \
  --root outputs/plan13_v48_evidence_graph_writer_live \
  --out outputs/plan13_v48_evidence_graph_writer_live/report_quality_summary.json
```

## Acceptance Decision

Promote `evidence-graph` mode only if:

- It has no new hard factual drift failures compared with direct-source v47.
- It improves or ties direct-source v47 on boundary correctness.
- It improves at least two of: actionability, analytical depth, non-repetition, operator readability.
- It does not require case-specific validators or prompt rules.
- It produces artifacts that make failure analysis easier than v47.

Keep `direct-source` as default if:

- Evidence graph mode mostly rearranges facts without improving report judgment.
- The graph introduces noisy nodes that confuse the writer.
- The hypothesis board becomes a fake reasoning artifact that does not change output quality.
- The implementation makes the report path harder to debug.

## Self-Review Log

### Review Pass 1

- Spec coverage: This plan covers branch setup, evidence graph, hypothesis board, writer integration, artifacts, eval, and documentation.
- Marker scan: No unresolved implementation markers are present.
- Risk found: The first version could overreach by touching investigation-layer behavior before report-side graph value is proven.
- Fix applied in this plan: Investigation-layer hypothesis board is moved to optional Task 9 and gated on report-side evidence.

### Review Pass 2

- Spec coverage: The plan now maps the experiment to concrete CLI mode, writer mode, graph artifacts, and A/B outputs.
- Marker scan: No unresolved implementation markers are present.
- Risk found: The first version placed graph artifact persistence in the wrong layer and used a heuristic run that would not exercise the LLM writer path.
- Fix applied in this plan: Artifact writes are moved to `demo_agent/entrypoints/langchain_agent.py`, and the artifact probe is changed to a live `llm_agent` run.

### Review Pass 3

- Spec coverage: The plan now separates graph lenses from hypothesis ids so writer inputs are not semantically overloaded.
- Marker scan: No unresolved implementation markers are present.
- Risk found: The counterevidence lens was too narrow and could miss background or shared-infrastructure explanations that do not use the literal word "反证".
- Fix applied in this plan: The lens builder now uses generic role markers for background, alternative, shared infrastructure, and counterevidence.
