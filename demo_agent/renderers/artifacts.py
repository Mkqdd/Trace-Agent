from typing import Any, Dict

def severity_from_confidence(conf: int) -> str:
    if conf >= 85:
        return "高危"
    if conf >= 65:
        return "中危"
    return "低危"


def build_topology(event: Dict[str, Any]) -> Dict[str, Any]:
    fp_type = event["trigger_fingerprint"]["type"]
    fp_value = event["trigger_fingerprint"]["value"]
    conf = int(event.get("enrichment", {}).get("confidence", 50))
    sev = severity_from_confidence(conf)

    internal = event["src"]["ip"]
    external = event["dst"]["ip"]
    family = (event.get("enrichment", {}).get("labels") or ["Unknown"])[0]

    nodes = [
        {
            "id": f"host:{internal}",
            "type": "internal_host",
            "label": internal,
            "attrs": {"simulated": bool(event.get("simulated"))},
            "style": {"group": "internal", "severity": sev},
        },
        {
            "id": f"ip:{external}",
            "type": "external_ip",
            "label": external,
            "attrs": event.get("enrichment", {}).get("dst_ip", {}),
            "style": {"group": "external"},
        },
        {
            "id": f"{fp_type.lower()}:{fp_value}",
            "type": f"fingerprint_{fp_type.lower()}",
            "label": f"{fp_type} {fp_value}",
            "attrs": {"confidence": conf},
            "style": {"group": "fingerprint"},
        },
        {"id": f"family:{family}", "type": "malware_family", "label": family, "attrs": {}, "style": {"group": "actor_or_family"}},
    ]

    edges = [
        {
            "id": "e_flow",
            "source": f"host:{internal}",
            "target": f"ip:{external}",
            "type": "network_flow",
            "label": f"{event['protocol']} {event['src']['port']} → {event['dst']['port']}",
            "attrs": {"protocol": event["protocol"], "time": event["event_time"], "simulated": bool(event.get("simulated"))},
        },
        {
            "id": "e_fp",
            "source": f"host:{internal}",
            "target": f"{fp_type.lower()}:{fp_value}",
            "type": "observed_fingerprint",
            "label": f"命中 {fp_type}",
            "attrs": {"match": bool(event.get("local_hit"))},
        },
        {
            "id": "e_attr",
            "source": f"{fp_type.lower()}:{fp_value}",
            "target": f"family:{family}",
            "type": "attribution",
            "label": "关联家族/标签",
            "attrs": {"confidence": conf},
        },
    ]

    return {
        "version": "1.0",
        "title": "恶意指纹自动化溯源图谱",
        "meta": {"severity": sev},
        "nodes": nodes,
        "edges": edges,
    }
