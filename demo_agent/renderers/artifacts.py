from typing import Any, Dict

def severity_from_confidence(conf: int) -> str:
    if conf >= 85:
        return "高危"
    if conf >= 65:
        return "中危"
    return "低危"


def _family_from_enrichment(enrichment: Dict[str, Any]) -> str:
    labels = enrichment.get("labels") or []
    if isinstance(labels, list):
        for value in labels:
            if isinstance(value, str):
                text = value.strip()
                if text:
                    return text

    info = enrichment.get("info")
    if isinstance(info, str) and info.strip():
        return info.strip()

    return "Unknown"


def build_topology(event: Dict[str, Any]) -> Dict[str, Any]:
    fp_type = event["trigger_fingerprint"]["type"]
    fp_value = event["trigger_fingerprint"]["value"]
    enrichment = dict(event.get("enrichment") or {})
    conf = int(enrichment.get("confidence", 50))
    sev = severity_from_confidence(conf)

    internal = event["src"]["ip"]
    external = event["dst"]["ip"]
    family = _family_from_enrichment(enrichment)

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
            "attrs": enrichment.get("dst_ip", {}),
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
            "attrs": {"match": bool((event.get("trigger_fingerprint") or {}).get("matched"))},
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


def build_topology_from_analysis(analysis: Dict[str, Any]) -> Dict[str, Any]:
    event = dict(analysis.get("event") or {})
    enrichment = dict(event.get("enrichment") or {})
    derived = dict(analysis.get("derived") or {})

    labels = derived.get("labels")
    if isinstance(labels, list) and labels:
        enrichment["labels"] = labels

    if derived.get("family") and not enrichment.get("info"):
        enrichment["info"] = derived.get("family")

    if derived.get("confidence") is not None:
        enrichment["confidence"] = derived.get("confidence")

    destination_enrichment = derived.get("destination_enrichment")
    if isinstance(destination_enrichment, dict) and destination_enrichment:
        enrichment["dst_ip"] = destination_enrichment

    event["enrichment"] = enrichment
    trigger = dict(event.get("trigger_fingerprint") or {})
    trigger.setdefault("matched", True)
    event["trigger_fingerprint"] = trigger

    return build_topology(event)
