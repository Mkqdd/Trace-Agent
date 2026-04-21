from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .contracts import isoformat_z, parse_timestamp, summarize_record, unique_preserve_order


def _normalize_trace_event(payload: Dict[str, Any], *, default_id: str) -> Dict[str, Any]:
    event = dict(payload)
    event["id"] = str(event.get("id") or default_id)
    event["kind"] = str(event.get("kind") or "event").strip().lower()
    event["classification"] = str(event.get("classification") or "unknown").strip().lower()
    event["tags"] = unique_preserve_order(event.get("tags") or [])
    event["summary"] = summarize_record(event)
    event["ts"] = isoformat_z(parse_timestamp(event.get("ts")))
    return event


def _derive_entities_from_events(events: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    return {
        "asset_ids": unique_preserve_order(item.get("asset_id") for item in events),
        "src_ips": unique_preserve_order(item.get("src_ip") for item in events),
        "dst_ips": unique_preserve_order(item.get("dst_ip") for item in events),
        "domains": unique_preserve_order(item.get("domain") for item in events),
        "fingerprints": unique_preserve_order(
            value
            for item in events
            for value in [item.get("ja4"), item.get("ja3"), item.get("ssl_sha1"), item.get("cert_sha1")]
        ),
    }


@dataclass
class EventBatch:
    source_type: str
    query: Dict[str, Any]
    events: List[Dict[str, Any]]
    reasons_by_event: Dict[str, List[str]] = field(default_factory=dict)
    note: str = ""

    @property
    def derived_entities(self) -> Dict[str, List[str]]:
        return _derive_entities_from_events(self.events)

    def to_payload(self) -> Dict[str, Any]:
        return {
            "source_type": self.source_type,
            "query": self.query,
            "events": list(self.events),
            "derived_entities": self.derived_entities,
            "reasons_by_event": dict(self.reasons_by_event),
            "note": self.note,
        }


class TraceStore(ABC):
    fixture_dir: Path

    @abstractmethod
    def build_seed_context(self, seed_event: Dict[str, Any]) -> EventBatch:
        raise NotImplementedError

    @abstractmethod
    def query_related_events(self, pivots: Dict[str, Any], *, window_minutes: int = 120, limit: int = 60) -> EventBatch:
        raise NotImplementedError

    @abstractmethod
    def get_asset_context(self, asset_ids: List[str], *, window_minutes: int = 120, limit: int = 60) -> EventBatch:
        raise NotImplementedError

    @abstractmethod
    def expand_entities(self, entity_set: Dict[str, List[str]], *, window_minutes: int = 120, limit: int = 60) -> EventBatch:
        raise NotImplementedError


class FixtureTraceStoreAdapter(TraceStore):
    def __init__(self, *, fixture_dir: Path, trace_events: List[Dict[str, Any]]) -> None:
        self.fixture_dir = fixture_dir
        self.trace_events = sorted(trace_events, key=lambda item: parse_timestamp(item.get("ts")))

    @classmethod
    def from_fixture_dir(cls, fixture_dir: Path) -> "FixtureTraceStoreAdapter":
        trace_path = fixture_dir / "trace_events.ndjson"
        if not trace_path.exists():
            raise FileNotFoundError(f"missing trace_events.ndjson under {fixture_dir}")

        events: List[Dict[str, Any]] = []
        for index, raw_line in enumerate(trace_path.read_text(encoding="utf-8").splitlines()):
            line = raw_line.strip()
            if not line:
                continue
            payload = json.loads(line)
            events.append(_normalize_trace_event(payload, default_id=f"trace-{index:03d}"))
        return cls(fixture_dir=fixture_dir, trace_events=events)

    def _windowed_seed_matches(self, seed_event: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], Dict[str, List[str]]]:
        seed_ts = parse_timestamp(seed_event.get("event_time"))
        seed_src = str(((seed_event.get("src") or {}).get("ip")) or "").strip()
        seed_dst = str(((seed_event.get("dst") or {}).get("ip")) or "").strip()
        seed_fp = str((((seed_event.get("trigger_fingerprint") or {}).get("value")) or "")).strip()

        matched: List[Dict[str, Any]] = []
        reasons_by_event: Dict[str, List[str]] = {}
        for event in self.trace_events:
            event_ts = parse_timestamp(event.get("ts"))
            delta_minutes = abs((event_ts - seed_ts).total_seconds()) / 60.0

            reasons: List[str] = []
            if seed_src and event.get("src_ip") == seed_src and delta_minutes <= 20:
                reasons.append("same_src_ip_in_20m")
            if seed_dst and event.get("dst_ip") == seed_dst and delta_minutes <= 30:
                reasons.append("same_dst_ip_in_30m")
            if seed_fp:
                fp_candidates = (
                    str(event.get("ja4") or "").strip(),
                    str(event.get("ja3") or "").strip(),
                    str(event.get("ssl_sha1") or "").strip(),
                    str(event.get("cert_sha1") or "").strip(),
                )
                if seed_fp in {value for value in fp_candidates if value} and delta_minutes <= 45:
                    reasons.append("same_fingerprint_in_45m")
            if reasons:
                matched.append(event)
                reasons_by_event[event["id"]] = reasons
        return matched, reasons_by_event

    def build_seed_context(self, seed_event: Dict[str, Any]) -> EventBatch:
        matched, reasons_by_event = self._windowed_seed_matches(seed_event)
        return EventBatch(
            source_type="trace_store.seed_context",
            query={
                "src_ip": ((seed_event.get("src") or {}).get("ip")) or "",
                "dst_ip": ((seed_event.get("dst") or {}).get("ip")) or "",
                "fingerprint": ((seed_event.get("trigger_fingerprint") or {}).get("value")) or "",
            },
            events=matched,
            reasons_by_event=reasons_by_event,
            note="seed-context query over fixture trace events",
        )

    def query_related_events(self, pivots: Dict[str, Any], *, window_minutes: int = 120, limit: int = 60) -> EventBatch:
        seed_ts = parse_timestamp(pivots.get("seed_ts"))
        pivot_assets = unique_preserve_order(pivots.get("asset_ids") or [])
        pivot_src_ips = unique_preserve_order(pivots.get("src_ips") or [])
        pivot_dst_ips = unique_preserve_order(pivots.get("dst_ips") or [])
        pivot_domains = unique_preserve_order(pivots.get("domains") or [])
        pivot_fingerprints = unique_preserve_order(pivots.get("fingerprints") or [])

        expanded: List[Dict[str, Any]] = []
        reasons_by_event: Dict[str, List[str]] = {}
        for event in self.trace_events:
            event_ts = parse_timestamp(event.get("ts"))
            delta_minutes = abs((event_ts - seed_ts).total_seconds()) / 60.0
            if delta_minutes > window_minutes:
                continue

            reasons: List[str] = []
            if pivot_assets and str(event.get("asset_id") or "").strip() in pivot_assets:
                reasons.append("same_asset")
            if pivot_src_ips and str(event.get("src_ip") or "").strip() in pivot_src_ips:
                reasons.append("same_src_ip")
            if pivot_dst_ips and str(event.get("dst_ip") or "").strip() in pivot_dst_ips:
                reasons.append("same_dst_ip")
            if pivot_domains and str(event.get("domain") or "").strip() in pivot_domains:
                reasons.append("same_domain")
            event_fingerprints = {
                str(event.get("ja4") or "").strip(),
                str(event.get("ja3") or "").strip(),
                str(event.get("ssl_sha1") or "").strip(),
                str(event.get("cert_sha1") or "").strip(),
            }
            if any(value and value in pivot_fingerprints for value in event_fingerprints):
                reasons.append("same_fingerprint")

            if reasons:
                expanded.append(event)
                reasons_by_event[event["id"]] = reasons
                if len(expanded) >= limit:
                    break

        return EventBatch(
            source_type="trace_store.related_events",
            query={
                "asset_ids": pivot_assets,
                "src_ips": pivot_src_ips,
                "dst_ips": pivot_dst_ips,
                "domains": pivot_domains,
                "fingerprints": pivot_fingerprints,
                "window_minutes": window_minutes,
                "limit": limit,
            },
            events=expanded,
            reasons_by_event=reasons_by_event,
            note="pivot expansion over fixture trace events",
        )

    def get_asset_context(self, asset_ids: List[str], *, window_minutes: int = 120, limit: int = 60) -> EventBatch:
        targets = unique_preserve_order(asset_ids)
        asset_events: List[Dict[str, Any]] = []
        reasons_by_event: Dict[str, List[str]] = {}
        for event in self.trace_events:
            asset_id = str(event.get("asset_id") or "").strip()
            if asset_id and asset_id in targets:
                asset_events.append(event)
                reasons_by_event[event["id"]] = ["asset_context"]
                if len(asset_events) >= limit:
                    break
        return EventBatch(
            source_type="trace_store.asset_context",
            query={"asset_ids": targets, "window_minutes": window_minutes, "limit": limit},
            events=asset_events,
            reasons_by_event=reasons_by_event,
            note="asset-context expansion over fixture trace events",
        )

    def expand_entities(self, entity_set: Dict[str, List[str]], *, window_minutes: int = 120, limit: int = 60) -> EventBatch:
        dst_ips = unique_preserve_order(entity_set.get("dst_ips") or [])
        domains = unique_preserve_order(entity_set.get("domains") or [])
        fingerprints = unique_preserve_order(entity_set.get("fingerprints") or [])
        expanded: List[Dict[str, Any]] = []
        reasons_by_event: Dict[str, List[str]] = {}

        for event in self.trace_events:
            reasons: List[str] = []
            if dst_ips and str(event.get("dst_ip") or "").strip() in dst_ips:
                reasons.append("matched_dst_ip")
            if domains and str(event.get("domain") or "").strip() in domains:
                reasons.append("matched_domain")
            event_fingerprints = {
                str(event.get("ja4") or "").strip(),
                str(event.get("ja3") or "").strip(),
                str(event.get("ssl_sha1") or "").strip(),
                str(event.get("cert_sha1") or "").strip(),
            }
            if any(value and value in fingerprints for value in event_fingerprints):
                reasons.append("matched_fingerprint")
            if reasons:
                expanded.append(event)
                reasons_by_event[event["id"]] = reasons
                if len(expanded) >= limit:
                    break

        return EventBatch(
            source_type="trace_store.entity_expand",
            query={
                "dst_ips": dst_ips,
                "domains": domains,
                "fingerprints": fingerprints,
                "window_minutes": window_minutes,
                "limit": limit,
            },
            events=expanded,
            reasons_by_event=reasons_by_event,
            note="entity-based expansion over fixture trace events",
        )

    # Compatibility helpers for the current deterministic incident pipeline.
    def build_minimal_context(self, seed_event: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        batch = self.build_seed_context(seed_event)
        trace = {
            "step": "context_assemble",
            "status": "ok",
            "matched_events": len(batch.events),
            "matched_event_ids": [item["id"] for item in batch.events],
            "reasons_by_event": batch.reasons_by_event,
        }
        return list(batch.events), trace

    def expand_incident(self, seed_event: Dict[str, Any], minimal_context: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        seed_ts = parse_timestamp(seed_event.get("event_time"))
        batch = self.query_related_events(
            {
                "seed_ts": isoformat_z(seed_ts),
                "asset_ids": unique_preserve_order(item.get("asset_id") for item in minimal_context),
                "src_ips": unique_preserve_order(
                    [((seed_event.get("src") or {}).get("ip"))] + [item.get("src_ip") for item in minimal_context]
                ),
                "dst_ips": unique_preserve_order(
                    [((seed_event.get("dst") or {}).get("ip"))] + [item.get("dst_ip") for item in minimal_context]
                ),
                "domains": unique_preserve_order(item.get("domain") for item in minimal_context),
                "fingerprints": unique_preserve_order(
                    [((seed_event.get("trigger_fingerprint") or {}).get("value"))]
                    + [item.get("ja4") for item in minimal_context]
                    + [item.get("ja3") for item in minimal_context]
                    + [item.get("ssl_sha1") for item in minimal_context]
                    + [item.get("cert_sha1") for item in minimal_context]
                ),
            },
            window_minutes=120,
            limit=max(60, len(self.trace_events)),
        )
        trace = {
            "step": "incident_expand",
            "status": "ok",
            "expanded_events": len(batch.events),
            "expanded_event_ids": [item["id"] for item in batch.events],
            "pivot_assets": batch.query.get("asset_ids") or [],
            "pivot_src_ips": batch.query.get("src_ips") or [],
            "pivot_dst_ips": batch.query.get("dst_ips") or [],
            "pivot_domains": batch.query.get("domains") or [],
            "pivot_fingerprints": batch.query.get("fingerprints") or [],
            "reasons_by_event": batch.reasons_by_event,
        }
        return list(batch.events), trace


class LocalTraceStoreAdapter(TraceStore):
    def __init__(self) -> None:
        self.fixture_dir = Path(".")

    def _empty_batch(self, source_type: str, query: Dict[str, Any], note: str) -> EventBatch:
        return EventBatch(source_type=source_type, query=query, events=[], reasons_by_event={}, note=note)

    def build_seed_context(self, seed_event: Dict[str, Any]) -> EventBatch:
        return self._empty_batch("trace_store.seed_context", {"seed_event": seed_event}, "local trace store adapter not implemented yet")

    def query_related_events(self, pivots: Dict[str, Any], *, window_minutes: int = 120, limit: int = 60) -> EventBatch:
        return self._empty_batch(
            "trace_store.related_events",
            {"pivots": pivots, "window_minutes": window_minutes, "limit": limit},
            "local trace store adapter not implemented yet",
        )

    def get_asset_context(self, asset_ids: List[str], *, window_minutes: int = 120, limit: int = 60) -> EventBatch:
        return self._empty_batch(
            "trace_store.asset_context",
            {"asset_ids": list(asset_ids), "window_minutes": window_minutes, "limit": limit},
            "local trace store adapter not implemented yet",
        )

    def expand_entities(self, entity_set: Dict[str, List[str]], *, window_minutes: int = 120, limit: int = 60) -> EventBatch:
        return self._empty_batch(
            "trace_store.entity_expand",
            {"entity_set": entity_set, "window_minutes": window_minutes, "limit": limit},
            "local trace store adapter not implemented yet",
        )


# Backward-compatible name for the deterministic incident pipeline.
FixtureTraceStore = FixtureTraceStoreAdapter


__all__ = [
    "EventBatch",
    "FixtureTraceStore",
    "FixtureTraceStoreAdapter",
    "LocalTraceStoreAdapter",
    "TraceStore",
]
