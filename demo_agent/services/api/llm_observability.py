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
ROLE_ENV_PREFIXES = {
    "investigator": "INCIDENT_AGENT_INVESTIGATOR",
    "llm_selector": "INCIDENT_AGENT_SELECTOR",
    "report_material_loop": "INCIDENT_AGENT_REPORT_MATERIAL",
    "report_agent_writer": "INCIDENT_AGENT_WRITER",
    "report_polish_initial": "INCIDENT_AGENT_WRITER",
    "report_polish_full_repair": "INCIDENT_AGENT_WRITER",
    "report_polish_section_repair": "INCIDENT_AGENT_WRITER",
    "finish_reviewer": "INCIDENT_AGENT_REVIEWER",
    "post_action_reviewer": "INCIDENT_AGENT_REVIEWER",
    "legacy_proposal_reviewer": "INCIDENT_AGENT_REVIEWER",
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


def _role_env_prefix(role: str) -> str:
    return ROLE_ENV_PREFIXES.get(str(role or "").strip(), "")


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
    def __init__(
        self,
        content: str,
        *,
        finish_reason: str = "",
        usage: Optional[Dict[str, Any]] = None,
        model_name: str = "",
    ) -> None:
        self.content = content
        self.finish_reason = finish_reason
        self.usage = dict(usage or {})
        self.model_name = model_name


def _trace_jsonable(value: Any) -> Any:
    if value is None:
        return None
    if hasattr(value, "model_dump") and callable(getattr(value, "model_dump")):
        value = value.model_dump()
    elif hasattr(value, "dict") and callable(getattr(value, "dict")):
        value = value.dict()
    elif not isinstance(value, (dict, list, tuple, str, int, float, bool)):
        value = getattr(value, "__dict__", str(value))
    try:
        return json.loads(json.dumps(value, ensure_ascii=False, default=str))
    except Exception:
        return str(value)


def _generation_options_for_trace(invocation_kwargs: Dict[str, Any]) -> Dict[str, Any]:
    options: Dict[str, Any] = {}
    for key in ("max_tokens", "temperature", "reasoning_effort", "response_format"):
        if key in invocation_kwargs:
            options[key] = _trace_jsonable(invocation_kwargs.get(key))
    extra_body = invocation_kwargs.get("extra_body")
    if isinstance(extra_body, dict):
        thinking = extra_body.get("thinking")
        if isinstance(thinking, dict) and str(thinking.get("type") or "").lower() == "enabled":
            options["thinking_enabled"] = True
    return options


def _response_trace_fields(response: Any) -> Dict[str, Any]:
    fields: Dict[str, Any] = {}
    response_metadata = getattr(response, "response_metadata", {}) or {}
    if not isinstance(response_metadata, dict):
        response_metadata = {}

    finish_reason = (
        str(getattr(response, "finish_reason", "") or "")
        or str(response_metadata.get("finish_reason") or "")
        or str(response_metadata.get("stop_reason") or "")
    )
    if finish_reason:
        fields["finish_reason"] = finish_reason

    usage = (
        getattr(response, "usage", None)
        or getattr(response, "usage_metadata", None)
        or response_metadata.get("token_usage")
        or response_metadata.get("usage")
    )
    usage_json = _trace_jsonable(usage)
    if usage_json:
        fields["usage"] = usage_json

    model_name = (
        str(getattr(response, "model_name", "") or "")
        or str(response_metadata.get("model_name") or "")
        or str(response_metadata.get("model") or "")
    )
    if model_name:
        fields["model_name"] = model_name
    return fields


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


def _invocation_kwargs(llm: Any, role: str) -> Dict[str, Any]:
    kwargs = dict(getattr(llm, "kwargs", {}) or {})
    invocation = {
        key: value
        for key, value in kwargs.items()
        if key in {"max_tokens", "temperature", "response_format"} and value is not None
    }
    prefix = _role_env_prefix(role)
    max_tokens = _env_value(f"{prefix}_MAX_TOKENS") if prefix else ""
    if max_tokens:
        try:
            invocation["max_tokens"] = int(max_tokens)
        except ValueError:
            pass
    temperature = _env_value(f"{prefix}_TEMPERATURE") if prefix else ""
    if temperature:
        try:
            invocation["temperature"] = float(temperature)
        except ValueError:
            pass
    reasoning_effort = _env_value(f"{prefix}_REASONING_EFFORT") if prefix else ""
    if not reasoning_effort:
        reasoning_effort = _env_value("INCIDENT_AGENT_REASONING_EFFORT")
    if reasoning_effort:
        invocation["reasoning_effort"] = reasoning_effort
    thinking_enabled = _env_value(f"{prefix}_THINKING_ENABLED") if prefix else ""
    if not thinking_enabled:
        thinking_enabled = _env_value("INCIDENT_AGENT_THINKING_ENABLED")
    if thinking_enabled.lower() in {"1", "true", "yes", "enabled"}:
        invocation["extra_body"] = {"thinking": {"type": "enabled"}}
    return invocation


def _native_client_config(role: str) -> Dict[str, str]:
    cfg = load_config()
    prefix = _role_env_prefix(role)
    base_url = _env_value(f"{prefix}_BASE_URL") if prefix else ""
    api_key = _env_value(f"{prefix}_API_KEY") if prefix else ""
    return {
        "base_url": base_url or cfg.llm_base_url,
        "api_key": api_key or cfg.llm_api_key,
        "base_url_env": f"{prefix}_BASE_URL" if base_url and prefix else "",
        "api_key_env": f"{prefix}_API_KEY" if api_key and prefix else "",
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

    client_cfg = _native_client_config(role)
    client = OpenAI(base_url=client_cfg["base_url"], api_key=client_cfg["api_key"], timeout=180, max_retries=1)
    response = client.chat.completions.create(
        model=model,
        messages=_openai_messages(messages),
        **dict(invocation_kwargs or {}),
    )
    choice = response.choices[0] if response.choices else None
    message = getattr(choice, "message", None) if choice is not None else None
    return _NativeChatResponse(
        str(getattr(message, "content", "") or ""),
        finish_reason=str(getattr(choice, "finish_reason", "") or ""),
        usage=_trace_jsonable(getattr(response, "usage", None)) or {},
        model_name=str(getattr(response, "model", "") or model),
    )


def _is_langchain_openai_chat(llm: Any) -> bool:
    class_name = type(llm).__name__
    module_name = type(llm).__module__
    return class_name == "ChatOpenAI" or module_name.startswith("langchain_openai")


def _is_test_double_llm(llm: Any) -> bool:
    class_name = type(llm).__name__.lower()
    module_name = type(llm).__module__.lower()
    return "fake" in class_name or module_name.startswith("tools.")


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
    if _is_test_double_llm(llm):
        routing = dict(routing)
        routing["selected_model"] = ""
        routing["bind_applied"] = False
        routing["skipped_model_override_for_test_double"] = True
        return llm, routing
    routing["native_openai_adapter"] = True
    prefix = _role_env_prefix(str(role or "unknown"))
    if prefix and _env_value(f"{prefix}_BASE_URL"):
        routing["base_url_env"] = f"{prefix}_BASE_URL"
    if prefix and _env_value(f"{prefix}_API_KEY"):
        routing["api_key_env"] = f"{prefix}_API_KEY"
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
    selected_model = str(routing.get("selected_model") or "").strip()
    native_invocation_kwargs: Dict[str, Any] = {}
    if routing.get("native_openai_adapter") and selected_model:
        native_invocation_kwargs = _invocation_kwargs(routed_llm, str(role or "unknown"))
    trace_extra = dict(extra or {})
    trace_extra["model_routing"] = routing
    generation_options = _generation_options_for_trace(native_invocation_kwargs)
    if generation_options:
        trace_extra["generation_options"] = generation_options
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
        if routing.get("native_openai_adapter") and selected_model:
            response = _invoke_openai_native_chat(
                routed_llm,
                messages,
                role=str(role or "unknown"),
                model=selected_model,
                invocation_kwargs=native_invocation_kwargs,
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
            **_response_trace_fields(response),
        }
    )
    return response
