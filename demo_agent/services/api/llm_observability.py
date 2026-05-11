from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from ...config import load_config


TRACE_ENV = "INCIDENT_AGENT_LLM_TRACE_PATH"

ROLE_SPECIFIC_MODEL_ENVS = {
    "investigator": "INCIDENT_AGENT_INVESTIGATOR_MODEL",
    "llm_selector": "INCIDENT_AGENT_SELECTOR_MODEL",
    "report_material_loop": "INCIDENT_AGENT_REPORT_MATERIAL_MODEL",
    "report_agent_writer": "INCIDENT_AGENT_WRITER_MODEL",
    "report_polish_initial": "INCIDENT_AGENT_WRITER_MODEL",
    "report_polish_full_repair": "INCIDENT_AGENT_WRITER_MODEL",
    "report_polish_section_repair": "INCIDENT_AGENT_WRITER_MODEL",
    "finish_reviewer": "INCIDENT_AGENT_REVIEWER_MODEL",
    "post_action_reviewer": "INCIDENT_AGENT_REVIEWER_MODEL",
    "legacy_proposal_reviewer": "INCIDENT_AGENT_REVIEWER_MODEL",
}
TOOL_MODEL_ROLES = {"investigator", "llm_selector", "report_material_loop"}
REASONER_MODEL_ROLES = {
    "report_agent_writer",
    "report_polish_initial",
    "report_polish_full_repair",
    "report_polish_section_repair",
    "finish_reviewer",
    "post_action_reviewer",
    "legacy_proposal_reviewer",
}
DEFAULT_ROLE_MODELS = {
    # The investigation loop is mostly short tool-selection decisions. In live
    # evals the provider's `tool` model picked grounding/counterevidence actions
    # more reliably than the generic chat model, while material routing still
    # performed better on the default model.
    "investigator": "tool",
}


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


def _env_value(name: str) -> str:
    return str(os.getenv(name) or "").strip()


def resolve_llm_model_for_role(role: str) -> Dict[str, Any]:
    """Resolve an optional model override for an LLM role.

    This is intentionally a thin routing layer. It changes only the model name
    used for a role and does not alter tool protocols, prompts, budgets, or
    fallback behavior.
    """

    normalized_role = str(role or "unknown").strip() or "unknown"
    specific_env = ROLE_SPECIFIC_MODEL_ENVS.get(normalized_role)
    if specific_env and _env_value(specific_env):
        return {
            "role": normalized_role,
            "routing_group": "specific",
            "selected_model": _env_value(specific_env),
            "source_env": specific_env,
            "bind_applied": False,
        }
    if normalized_role in TOOL_MODEL_ROLES and _env_value("INCIDENT_AGENT_TOOL_MODEL"):
        return {
            "role": normalized_role,
            "routing_group": "tool",
            "selected_model": _env_value("INCIDENT_AGENT_TOOL_MODEL"),
            "source_env": "INCIDENT_AGENT_TOOL_MODEL",
            "bind_applied": False,
        }
    if normalized_role in REASONER_MODEL_ROLES and _env_value("INCIDENT_AGENT_REASONER_MODEL"):
        return {
            "role": normalized_role,
            "routing_group": "reasoner",
            "selected_model": _env_value("INCIDENT_AGENT_REASONER_MODEL"),
            "source_env": "INCIDENT_AGENT_REASONER_MODEL",
            "bind_applied": False,
        }
    if normalized_role in DEFAULT_ROLE_MODELS:
        return {
            "role": normalized_role,
            "routing_group": "role_default",
            "selected_model": DEFAULT_ROLE_MODELS[normalized_role],
            "source_env": "role_default",
            "bind_applied": False,
        }
    return {
        "role": normalized_role,
        "routing_group": "default",
        "selected_model": "",
        "source_env": "",
        "bind_applied": False,
    }


class _NativeChatResponse:
    def __init__(self, content: str) -> None:
        self.content = content


def _openai_role_from_message(message: Any) -> str:
    message_type = str(getattr(message, "type", "") or "").strip().lower()
    if message_type in {"system", "human", "ai", "assistant", "user"}:
        return {"human": "user", "ai": "assistant"}.get(message_type, message_type)
    class_name = type(message).__name__.lower()
    if "system" in class_name:
        return "system"
    if "ai" in class_name or "assistant" in class_name:
        return "assistant"
    return "user"


def _openai_messages(messages: Any) -> List[Dict[str, Any]]:
    normalized_messages = list(messages or []) if isinstance(messages, (list, tuple)) else [messages]
    rows: List[Dict[str, Any]] = []
    for message in normalized_messages:
        content = getattr(message, "content", message)
        if isinstance(content, list):
            content = _safe_json(content)
        rows.append({"role": _openai_role_from_message(message), "content": str(content or "")})
    return rows


def _invocation_kwargs(llm: Any) -> Dict[str, Any]:
    kwargs = dict(getattr(llm, "kwargs", {}) or {})
    return {
        key: value
        for key, value in kwargs.items()
        if key in {"max_tokens", "temperature", "response_format"} and value is not None
    }


def _invoke_openai_native_chat(
    llm: Any,
    messages: Any,
    *,
    role: str,
    model: str,
    invocation_kwargs: Dict[str, Any],
) -> _NativeChatResponse:
    """Invoke OpenAI-compatible chat directly for models unsupported by LangChain."""

    from openai import OpenAI

    cfg = load_config()
    client = OpenAI(base_url=cfg.llm_base_url, api_key=cfg.llm_api_key, timeout=180, max_retries=1)
    response = client.chat.completions.create(
        model=model,
        messages=_openai_messages(messages),
        **dict(invocation_kwargs or {}),
    )
    message = response.choices[0].message if response.choices else None
    return _NativeChatResponse(str(getattr(message, "content", "") or ""))


def _is_langchain_openai_chat(llm: Any) -> bool:
    class_name = type(llm).__name__
    module_name = type(llm).__module__
    return class_name == "ChatOpenAI" or module_name.startswith("langchain_openai")


def _llm_for_role(llm: Any, role: str) -> tuple[Any, Dict[str, Any]]:
    routing = resolve_llm_model_for_role(role)
    if routing.get("routing_group") == "role_default" and not _is_langchain_openai_chat(llm):
        routing = {
            "role": routing.get("role") or str(role or "unknown"),
            "routing_group": "default",
            "selected_model": "",
            "source_env": "",
            "bind_applied": False,
            "skipped_role_default": True,
        }
    selected_model = str(routing.get("selected_model") or "").strip()
    if not selected_model:
        return llm, routing
    routing["native_openai_adapter"] = True
    return llm, routing


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
    routed_llm, routing = _llm_for_role(llm, role)
    trace_extra = dict(extra or {})
    trace_extra["model_routing"] = routing
    base_event = {
        "call_id": call_id,
        "role": str(role or "unknown"),
        "step_index": step_index,
        "payload": payload,
        "extra": trace_extra,
    }
    record_llm_trace_event({**base_event, "event": "start", "ts": started_at})
    monotonic_start = time.perf_counter()
    try:
        selected_model = str(routing.get("selected_model") or "").strip()
        if routing.get("native_openai_adapter") and selected_model:
            response = _invoke_openai_native_chat(
                routed_llm,
                messages,
                role=str(role or "unknown"),
                model=selected_model,
                invocation_kwargs=_invocation_kwargs(routed_llm),
            )
        else:
            response = routed_llm.invoke(messages)
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
