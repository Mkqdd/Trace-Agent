from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List


_TIME_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S",
)


def parse_timestamp(value: Any) -> datetime:
    text = str(value or "").strip()
    if not text:
        return datetime(1970, 1, 1, tzinfo=timezone.utc)
    for fmt in _TIME_FORMATS:
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    try:
        normalized = text.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        return datetime(1970, 1, 1, tzinfo=timezone.utc)


def isoformat_z(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def unique_preserve_order(values: Iterable[Any]) -> List[str]:
    seen: set[str] = set()
    ordered: List[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        ordered.append(text)
    return ordered


def suspicion_score(record: Dict[str, Any]) -> int:
    classification = str(record.get("classification") or "unknown").strip().lower()
    score_map = {
        "malicious": 4,
        "suspicious": 2,
        "needs_review": 1,
        "unknown": 0,
        "benign": -2,
    }
    score = score_map.get(classification, 0)
    tags = {str(item or "").strip().lower() for item in list(record.get("tags") or [])}
    summary = str(record.get("summary") or "").strip().lower()
    if any(token in tags for token in {"command-and-control", "beacon", "lateral-movement", "exfiltration"}):
        score += 1
    if "beacon" in summary or "c2" in summary:
        score += 1
    if "patch window" in summary or "signed update" in summary:
        score -= 1
    return score


def infer_stages(record: Dict[str, Any]) -> List[str]:
    classification = str(record.get("classification") or "").strip().lower()
    tags = {str(item or "").strip().lower() for item in list(record.get("tags") or [])}
    haystack = " ".join(
        [
            str(record.get("kind") or ""),
            str(record.get("summary") or ""),
            " ".join(str(item or "") for item in list(record.get("tags") or [])),
        ]
    ).strip().lower()
    benign_transfer_context = (
        classification == "benign"
        and any(tag in tags for tag in {"maintenance", "patching", "backup"})
        and any(token in haystack for token in {"backup", "patch", "vendor", "maintenance", "approved"})
    )
    stage_map = {
        "initial-access": ("initial-access", "exploit", "phish", "webshell", "login"),
        "execution": ("execution", "powershell", "named pipe", "loader", "process"),
        "command-and-control": ("command-and-control", "beacon", "c2", "callback"),
        "lateral-movement": ("lateral-movement", "smb", "remote service", "remote process"),
        "exfiltration": ("exfiltration", "data transfer", "archive", "upload"),
    }
    stages: List[str] = []
    for stage, keywords in stage_map.items():
        if benign_transfer_context and stage == "exfiltration":
            continue
        if any(keyword in haystack for keyword in keywords):
            stages.append(stage)
    return stages


def summarize_record(record: Dict[str, Any]) -> str:
    summary = str(record.get("summary") or "").strip()
    if summary:
        return summary
    kind = str(record.get("kind") or "event").strip()
    domain = str(record.get("domain") or "").strip()
    dst_ip = str(record.get("dst_ip") or "").strip()
    asset_id = str(record.get("asset_id") or record.get("src_ip") or "unknown").strip()
    if kind == "dns" and domain:
        return f"{asset_id} 解析域名 {domain}"
    if kind in {"flow", "alert", "http"} and dst_ip:
        return f"{asset_id} 与 {dst_ip} 之间出现 {kind} 事件"
    return f"{asset_id} 产生了 {kind} 事件"


def severity_from_confidence(confidence: int, status: str) -> str:
    if status == "monitor_only":
        return "低危"
    if status == "confirmed_incident" and confidence >= 80:
        return "高危"
    if status == "needs_review" and confidence >= 55:
        return "中危"
    if confidence >= 60:
        return "中危"
    return "低危"
