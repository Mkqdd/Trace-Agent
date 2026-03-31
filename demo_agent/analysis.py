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

    confidence = _coerce_int((obs_fp or {}).get("confidence"), enrichment.get("confidence"), default=50)
    severity = severity_from_confidence(confidence)

    destination_enrichment: Dict[str, Any] = {}
    if isinstance(enrichment.get("dst_ip"), dict):
        destination_enrichment.update(enrichment.get("dst_ip") or {})

    fp_type = str((event.get("trigger_fingerprint") or {}).get("type") or "").upper()
    if fp_type == "IP" and isinstance(obs_fp, dict) and str((obs_fp or {}).get("ip") or "") == str((event.get("dst") or {}).get("ip") or ""):
        for key in ("enabled", "ip", "country", "asn", "as_owner", "reputation", "last_analysis_stats"):
            if key in obs_fp:
                destination_enrichment[key] = obs_fp[key]

    analysis: Dict[str, Any] = {
        "mode": mode,
        "event": event,
        "observations": {
            "fingerprint_enrichment": obs_fp,
            "family_intel": obs_family,
        },
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
