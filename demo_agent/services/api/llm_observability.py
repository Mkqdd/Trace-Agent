from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional


TRACE_ENV = "INCIDENT_AGENT_LLM_TRACE_PATH"


def _safe_json(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    except Exception:
        return json.dumps(str(value), ensure_ascii=False)


def _message_text(message: Any) -> str:
    content = getattr(message, "content", message)
    if isinstance(content, list):
        return _safe_json(content)
    return str(content or "")


def llm_messages_payload_summary(messages: Any) -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    total_bytes = 0
    normalized_messages = list(messages or []) if isinstance(messages, (list, tuple)) else [messages]
    for index, message in enumerate(normalized_messages):
        text = _message_text(message)
        encoded = text.encode("utf-8", errors="replace")
        total_bytes += len(encoded)
        rows.append(
            {
                "index": index,
                "type": type(message).__name__,
                "bytes": len(encoded),
                "sha1": hashlib.sha1(encoded).hexdigest()[:12],
            }
        )
    return {
        "message_count": len(normalized_messages),
        "total_bytes": total_bytes,
        "messages": rows,
    }


def record_llm_trace_event(event: Dict[str, Any], trace_path: Optional[str] = None) -> None:
    resolved = str(trace_path or os.getenv(TRACE_ENV) or "").strip()
    if not resolved:
        return
    try:
        path = Path(resolved)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=False, sort_keys=True, default=str) + "\n")
            handle.flush()
    except Exception:
        return


def invoke_llm_with_trace(
    llm: Any,
    messages: Any,
    *,
    role: str,
    step_index: Optional[int] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Any:
    call_id = uuid.uuid4().hex[:12]
    started_at = time.time()
    payload = llm_messages_payload_summary(messages)
    base_event = {
        "call_id": call_id,
        "role": str(role or "unknown"),
        "step_index": step_index,
        "payload": payload,
        "extra": dict(extra or {}),
    }
    record_llm_trace_event({**base_event, "event": "start", "ts": started_at})
    monotonic_start = time.perf_counter()
    try:
        response = llm.invoke(messages)
    except Exception as exc:
        elapsed_ms = int((time.perf_counter() - monotonic_start) * 1000)
        record_llm_trace_event(
            {
                **base_event,
                "event": "error",
                "ts": time.time(),
                "elapsed_ms": elapsed_ms,
                "error_type": type(exc).__name__,
                "error": str(exc),
            }
        )
        raise
    elapsed_ms = int((time.perf_counter() - monotonic_start) * 1000)
    content = str(getattr(response, "content", "") or "")
    encoded = content.encode("utf-8", errors="replace")
    record_llm_trace_event(
        {
            **base_event,
            "event": "end",
            "ts": time.time(),
            "elapsed_ms": elapsed_ms,
            "response_bytes": len(encoded),
            "response_sha1": hashlib.sha1(encoded).hexdigest()[:12],
        }
    )
    return response
