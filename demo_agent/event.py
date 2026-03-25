from typing import Any, Dict


def normalize_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Input is assumed to be an alert generated AFTER a fingerprint/rule match.
    We only normalize fields for downstream tools; we do not do local TI lookup.
    """
    trigger = alert.get("trigger_fingerprint") or {}

    # Carry hint fields (family/source/update) into enrichment for the LLM.
    enrichment = dict(alert.get("enrichment") or {})
    for k in ("info", "reference", "update_time"):
        if k in alert and k not in enrichment:
            enrichment[k] = alert.get(k)

    event: Dict[str, Any] = {
        "event_time": alert.get("event_time") or alert.get("timestamp") or alert.get("time") or "unknown",
        "simulated": bool(alert.get("simulated", False)),
        "src": {
            "ip": alert.get("src_ip") or (alert.get("src") or {}).get("ip") or "unknown",
            "port": alert.get("src_port") or (alert.get("src") or {}).get("port"),
        },
        "dst": {
            "ip": alert.get("dst_ip") or (alert.get("dst") or {}).get("ip") or "unknown",
            "port": alert.get("dst_port") or (alert.get("dst") or {}).get("port"),
        },
        "protocol": alert.get("protocol") or "unknown",
        "trigger_fingerprint": {
            "type": trigger.get("type") or "unknown",
            "value": trigger.get("value") or "unknown",
            "matched": True,
        },
        "enrichment": enrichment,
        "raw_alert": alert,
    }
    return event

