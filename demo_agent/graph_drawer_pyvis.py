from __future__ import annotations

from datetime import datetime
from pathlib import Path

from pyvis.network import Network


DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parent / "out_langchain"


def _validate_graph_data(graph_data: dict) -> tuple[list[dict], list[dict]]:
    if not isinstance(graph_data, dict):
        raise TypeError("graph_data must be a dict")

    nodes = graph_data.get("nodes")
    edges = graph_data.get("edges")

    if not isinstance(nodes, list):
        raise ValueError("graph_data['nodes'] must be a list")
    if not isinstance(edges, list):
        raise ValueError("graph_data['edges'] must be a list")

    node_ids: set[str] = set()
    for index, node in enumerate(nodes):
        if not isinstance(node, dict):
            raise ValueError(f"nodes[{index}] must be a dict")

        node_id = node.get("id")
        if not node_id:
            raise ValueError(f"nodes[{index}] is missing 'id'")
        if node_id in node_ids:
            raise ValueError(f"duplicate node id: {node_id}")
        node_ids.add(node_id)

    for index, edge in enumerate(edges):
        if not isinstance(edge, dict):
            raise ValueError(f"edges[{index}] must be a dict")

        src = edge.get("src") or edge.get("source")
        dst = edge.get("dst") or edge.get("target")
        if not src or not dst:
            raise ValueError(f"edges[{index}] must include 'src'/'source' and 'dst'/'target'")
        if src not in node_ids:
            raise ValueError(f"edges[{index}] references missing src node: {src}")
        if dst not in node_ids:
            raise ValueError(f"edges[{index}] references missing dst node: {dst}")

    return nodes, edges


def _build_output_path(output_path: str | None) -> Path:
    if output_path:
        path = Path(output_path)
        if not path.is_absolute():
            path = Path.cwd() / path
    else:
        DEFAULT_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = DEFAULT_OUTPUT_DIR / f"graph_{timestamp}.html"

    if path.suffix.lower() != ".html":
        path = path.with_suffix(".html")

    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _node_color(node_type: str) -> str:
    mapping = {
        "host": "lightblue",
        "internal_host": "lightblue",
        "ja3": "orange",
        "fingerprint_ja3": "orange",
        "ip": "lightgreen",
        "external_ip": "lightgreen",
        "malware_family": "lightcoral",
    }
    return mapping.get(node_type, "gray")


def _node_label(node: dict) -> str:
    node_type = str(node.get("type", "")).strip()
    value = str(node.get("label") or node["id"]).strip()
    title_map = {
        "host": "HOST",
        "internal_host": "HOST",
        "ja3": "JA3",
        "fingerprint_ja3": "JA3",
        "ip": "IP",
        "external_ip": "IP",
        "malware_family": "FAMILY",
    }
    prefix = title_map.get(node_type, node_type.upper() or "NODE")
    return f"{prefix}\n{value}"


def _node_title(node: dict) -> str:
    node_type = str(node.get("type", "")).strip()
    value = str(node.get("label") or node["id"]).strip()
    title_map = {
        "host": "Victim Host",
        "internal_host": "Victim Host",
        "ja3": "JA3 Fingerprint",
        "fingerprint_ja3": "JA3 Fingerprint",
        "ip": "External IP",
        "external_ip": "External IP",
        "malware_family": "Malware Family",
    }
    prefix = title_map.get(node_type, "Node")
    return f"{prefix}\n{value}"


def _node_levels(nodes: list[dict], edges: list[dict]) -> dict[str, int]:
    incoming_count = {node["id"]: 0 for node in nodes}
    outgoing: dict[str, list[str]] = {node["id"]: [] for node in nodes}

    for edge in edges:
        src = edge.get("src") or edge.get("source")
        dst = edge.get("dst") or edge.get("target")
        outgoing[src].append(dst)
        incoming_count[dst] += 1

    levels = {node_id: 0 for node_id, count in incoming_count.items() if count == 0}
    queue = list(levels)

    while queue:
        current = queue.pop(0)
        current_level = levels[current]
        for neighbor in outgoing[current]:
            next_level = current_level + 1
            if next_level > levels.get(neighbor, -1):
                levels[neighbor] = next_level
            incoming_count[neighbor] -= 1
            if incoming_count[neighbor] == 0:
                queue.append(neighbor)

    for node in nodes:
        levels.setdefault(node["id"], 0)

    return levels


def draw_graph_pyvis(graph_data: dict, output_path: str | None = None) -> str:
    nodes, edges = _validate_graph_data(graph_data)
    final_output_path = _build_output_path(output_path)
    node_levels = _node_levels(nodes, edges)

    net = Network(height="720px", width="100%", directed=True, bgcolor="white", font_color="black")
    net.set_options(
        """
        {
          "layout": {
            "hierarchical": {
              "enabled": true,
              "direction": "LR",
              "sortMethod": "directed",
              "nodeSpacing": 160,
              "levelSeparation": 180,
              "treeSpacing": 180
            }
          },
          "physics": {
            "enabled": true,
            "hierarchicalRepulsion": {
              "centralGravity": 0.0,
              "springLength": 120,
              "springConstant": 0.02,
              "nodeDistance": 140,
              "damping": 0.85
            },
            "solver": "hierarchicalRepulsion"
          },
          "edges": {
            "smooth": false,
            "color": {
              "color": "gray",
              "highlight": "gray"
            },
            "font": {
              "size": 10,
              "align": "middle"
            },
            "arrows": {
              "to": {
                "enabled": true
              }
            }
          },
          "interaction": {
            "hover": true,
            "dragNodes": true,
            "dragView": true,
            "zoomView": true
          }
        }
        """
    )

    for node in nodes:
        node_type = str(node.get("type", "")).strip()
        net.add_node(
            node["id"],
            label=_node_label(node),
            title=_node_title(node),
            color=_node_color(node_type),
            shape="dot",
            size=22,
            level=node_levels[node["id"]],
            font={"size": 16, "face": "Arial"},
            borderWidth=1,
        )

    for edge in edges:
        edge_type = str(edge.get("label") or edge.get("type", ""))
        src = edge.get("src") or edge.get("source")
        dst = edge.get("dst") or edge.get("target")
        net.add_edge(
            src,
            dst,
            label=edge_type,
            title=edge_type,
            color="gray",
            arrows="to",
            font={"size": 10, "align": "middle"},
        )

    net.write_html(str(final_output_path), notebook=False)
    return str(final_output_path.resolve())
