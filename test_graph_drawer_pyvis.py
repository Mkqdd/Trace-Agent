from tools.graph_drawer_pyvis import draw_graph_pyvis


def main() -> None:
    graph_data = {
        "nodes": [
            {"id": "host", "type": "host", "label": "10.1.20.55"},
            {
                "id": "ja3",
                "type": "ja3",
                "label": "fc54e0d16d9764783542f0146a98b300",
            },
            {"id": "c2", "type": "ip", "label": "92.63.192.30:443"},
        ],
        "edges": [
            {"src": "host", "dst": "ja3", "type": "tls_flow"},
            {"src": "ja3", "dst": "c2", "type": "known_c2"},
        ],
    }

    html_path = draw_graph_pyvis(graph_data)
    print("Generated HTML:", html_path)


if __name__ == "__main__":
    main()
