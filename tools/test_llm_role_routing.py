from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import demo_agent.services.api.llm_observability as llm_observability  # noqa: E402
from demo_agent.services.api.llm_observability import (  # noqa: E402
    TRACE_ENV,
    invoke_llm_with_trace,
    resolve_llm_model_for_role,
)


class _FakeResponse:
    content = "ok"


class _FakeLLM:
    def __init__(self, bound_kwargs: dict | None = None) -> None:
        self.bound_kwargs = dict(bound_kwargs or {})
        self.kwargs = dict(bound_kwargs or {})
        self.invocations = 0

    def bind(self, **kwargs):
        merged = dict(self.bound_kwargs)
        merged.update(kwargs)
        return _FakeLLM(merged)

    def invoke(self, messages):
        self.invocations += 1
        return _FakeResponse()


def _with_env(overrides: dict[str, str | None], fn) -> None:
    previous = {key: os.environ.get(key) for key in overrides}
    try:
        for key, value in overrides.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        fn()
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def test_investigator_defaults_to_tool_without_material_default() -> None:
    def run() -> None:
        investigator = resolve_llm_model_for_role("investigator")
        material = resolve_llm_model_for_role("report_material_loop")

        assert investigator["selected_model"] == "tool"
        assert investigator["routing_group"] == "role_default"
        assert material["selected_model"] == ""

    _with_env(
        {
            "INCIDENT_AGENT_INVESTIGATOR_MODEL": None,
            "INCIDENT_AGENT_TOOL_MODEL": None,
            "INCIDENT_AGENT_REPORT_MATERIAL_MODEL": None,
        },
        run,
    )


def test_investigator_role_default_does_not_bypass_fake_llm() -> None:
    def run() -> None:
        fake = _FakeLLM()
        response = invoke_llm_with_trace(fake, ["hello"], role="investigator")

        assert response.content == "ok"
        assert fake.invocations == 1

    _with_env(
        {
            "INCIDENT_AGENT_INVESTIGATOR_MODEL": None,
            "INCIDENT_AGENT_TOOL_MODEL": None,
        },
        run,
    )


def test_role_model_resolution_uses_tool_and_reasoner_groups() -> None:
    def run() -> None:
        investigator = resolve_llm_model_for_role("investigator")
        material = resolve_llm_model_for_role("report_material_loop")
        writer = resolve_llm_model_for_role("report_agent_writer")
        polish = resolve_llm_model_for_role("report_polish_initial")
        reviewer = resolve_llm_model_for_role("finish_reviewer")

        assert investigator["selected_model"] == "tool"
        assert investigator["source_env"] == "INCIDENT_AGENT_TOOL_MODEL"
        assert material["selected_model"] == "tool"
        assert writer["selected_model"] == "reasoner"
        assert polish["selected_model"] == "reasoner"
        assert reviewer["selected_model"] == "reasoner"

    _with_env(
        {
            "INCIDENT_AGENT_TOOL_MODEL": "tool",
            "INCIDENT_AGENT_REASONER_MODEL": "reasoner",
        },
        run,
    )


def test_specific_role_model_overrides_group_model() -> None:
    def run() -> None:
        writer = resolve_llm_model_for_role("report_agent_writer")
        material = resolve_llm_model_for_role("report_material_loop")

        assert writer["selected_model"] == "writer-special"
        assert writer["source_env"] == "INCIDENT_AGENT_WRITER_MODEL"
        assert material["selected_model"] == "material-special"
        assert material["source_env"] == "INCIDENT_AGENT_REPORT_MATERIAL_MODEL"

    _with_env(
        {
            "INCIDENT_AGENT_TOOL_MODEL": "tool",
            "INCIDENT_AGENT_REASONER_MODEL": "reasoner",
            "INCIDENT_AGENT_WRITER_MODEL": "writer-special",
            "INCIDENT_AGENT_REPORT_MATERIAL_MODEL": "material-special",
        },
        run,
    )


def test_invoke_trace_records_role_model_routing() -> None:
    def run() -> None:
        fake = _FakeLLM()
        previous = getattr(llm_observability, "_invoke_openai_native_chat", None)

        def fake_native(llm, messages, *, role, model, invocation_kwargs):
            return _FakeResponse()

        llm_observability._invoke_openai_native_chat = fake_native
        with tempfile.TemporaryDirectory() as tmp:
            trace_path = Path(tmp) / "llm_calls.jsonl"
            os.environ[TRACE_ENV] = str(trace_path)
            try:
                invoke_llm_with_trace(fake, ["hello"], role="report_agent_writer")
            finally:
                if previous is not None:
                    llm_observability._invoke_openai_native_chat = previous

            events = [json.loads(line) for line in trace_path.read_text().splitlines() if line.strip()]
            start = next(item for item in events if item["event"] == "start")
            end = next(item for item in events if item["event"] == "end")

        assert start["extra"]["model_routing"]["selected_model"] == "reasoner"
        assert start["extra"]["model_routing"]["source_env"] == "INCIDENT_AGENT_REASONER_MODEL"
        assert end["extra"]["model_routing"]["selected_model"] == "reasoner"

    _with_env(
        {
            "INCIDENT_AGENT_REASONER_MODEL": "reasoner",
            TRACE_ENV: "",
        },
        run,
    )


def test_trace_records_role_specific_endpoint_env_names() -> None:
    def run() -> None:
        fake = _FakeLLM()
        previous = getattr(llm_observability, "_invoke_openai_native_chat", None)

        def fake_native(llm, messages, *, role, model, invocation_kwargs):
            return _FakeResponse()

        llm_observability._invoke_openai_native_chat = fake_native
        with tempfile.TemporaryDirectory() as tmp:
            trace_path = Path(tmp) / "llm_calls.jsonl"
            os.environ[TRACE_ENV] = str(trace_path)
            try:
                invoke_llm_with_trace(fake, ["hello"], role="report_agent_writer")
            finally:
                if previous is not None:
                    llm_observability._invoke_openai_native_chat = previous

            events = [json.loads(line) for line in trace_path.read_text().splitlines() if line.strip()]
            start = next(item for item in events if item["event"] == "start")
            routing = start["extra"]["model_routing"]

        assert routing["base_url_env"] == "INCIDENT_AGENT_WRITER_BASE_URL"
        assert routing["api_key_env"] == "INCIDENT_AGENT_WRITER_API_KEY"
        assert "dummy-key" not in json.dumps(routing)

    _with_env(
        {
            "INCIDENT_AGENT_WRITER_MODEL": "deepseek-v4-pro",
            "INCIDENT_AGENT_WRITER_BASE_URL": "https://api.deepseek.com",
            "INCIDENT_AGENT_WRITER_API_KEY": "dummy-key",
            TRACE_ENV: "",
        },
        run,
    )


def test_role_override_uses_native_openai_adapter_instead_of_langchain_bind() -> None:
    calls: list[dict] = []
    previous = getattr(llm_observability, "_invoke_openai_native_chat", None)

    def fake_native(llm, messages, *, role, model, invocation_kwargs):
        calls.append(
            {
                "llm": llm,
                "messages": messages,
                "role": role,
                "model": model,
                "invocation_kwargs": dict(invocation_kwargs),
            }
        )
        return _FakeResponse()

    def run() -> None:
        fake = _FakeLLM(bound_kwargs={"max_tokens": 123, "temperature": 0})
        llm_observability._invoke_openai_native_chat = fake_native
        invoke_llm_with_trace(fake, ["hello"], role="report_agent_writer")

        assert calls
        assert calls[0]["llm"] is fake
        assert calls[0]["model"] == "reasoner"
        assert calls[0]["role"] == "report_agent_writer"
        assert calls[0]["invocation_kwargs"]["max_tokens"] == 123
        assert calls[0]["invocation_kwargs"]["temperature"] == 0
        assert fake.invocations == 0

    try:
        _with_env(
            {
                "INCIDENT_AGENT_REASONER_MODEL": "reasoner",
            },
            run,
        )
    finally:
        if previous is not None:
            llm_observability._invoke_openai_native_chat = previous


def test_native_adapter_can_pass_reasoning_and_thinking_options() -> None:
    calls: list[dict] = []
    previous = getattr(llm_observability, "_invoke_openai_native_chat", None)

    def fake_native(llm, messages, *, role, model, invocation_kwargs):
        calls.append(dict(invocation_kwargs))
        return _FakeResponse()

    def run() -> None:
        fake = _FakeLLM()
        llm_observability._invoke_openai_native_chat = fake_native
        invoke_llm_with_trace(fake, ["hello"], role="report_agent_writer")

        assert calls
        assert calls[0]["reasoning_effort"] == "high"
        assert calls[0]["extra_body"] == {"thinking": {"type": "enabled"}}

    try:
        _with_env(
            {
                "INCIDENT_AGENT_REASONER_MODEL": "deepseek-v4-pro",
                "INCIDENT_AGENT_REASONING_EFFORT": "high",
                "INCIDENT_AGENT_THINKING_ENABLED": "1",
            },
            run,
        )
    finally:
        if previous is not None:
            llm_observability._invoke_openai_native_chat = previous


def test_native_adapter_can_pass_role_generation_options() -> None:
    calls: list[dict] = []
    previous = getattr(llm_observability, "_invoke_openai_native_chat", None)

    def fake_native(llm, messages, *, role, model, invocation_kwargs):
        calls.append(dict(invocation_kwargs))
        return _FakeResponse()

    def run() -> None:
        fake = _FakeLLM()
        llm_observability._invoke_openai_native_chat = fake_native
        invoke_llm_with_trace(fake, ["hello"], role="report_agent_writer")

        assert calls
        assert calls[0]["max_tokens"] == 7000
        assert calls[0]["temperature"] == 0.2

    try:
        _with_env(
            {
                "INCIDENT_AGENT_WRITER_MODEL": "deepseek-v4-pro",
                "INCIDENT_AGENT_WRITER_MAX_TOKENS": "7000",
                "INCIDENT_AGENT_WRITER_TEMPERATURE": "0.2",
            },
            run,
        )
    finally:
        if previous is not None:
            llm_observability._invoke_openai_native_chat = previous


def test_trace_records_native_finish_reason_usage_and_generation_options() -> None:
    class FakeNativeResponse:
        content = "ok"
        finish_reason = "length"
        model_name = "deepseek-v4-pro"
        usage = {"prompt_tokens": 100, "completion_tokens": 16000, "total_tokens": 16100}

    previous = getattr(llm_observability, "_invoke_openai_native_chat", None)

    def fake_native(llm, messages, *, role, model, invocation_kwargs):
        return FakeNativeResponse()

    def run() -> None:
        fake = _FakeLLM()
        llm_observability._invoke_openai_native_chat = fake_native
        with tempfile.TemporaryDirectory() as tmp:
            trace_path = Path(tmp) / "llm_calls.jsonl"
            os.environ[TRACE_ENV] = str(trace_path)
            invoke_llm_with_trace(fake, ["hello"], role="report_agent_writer")

            events = [json.loads(line) for line in trace_path.read_text().splitlines() if line.strip()]
            start = next(item for item in events if item["event"] == "start")
            end = next(item for item in events if item["event"] == "end")

        assert start["extra"]["generation_options"]["max_tokens"] == 16000
        assert start["extra"]["generation_options"]["reasoning_effort"] == "high"
        assert start["extra"]["generation_options"]["thinking_enabled"] is True
        assert end["finish_reason"] == "length"
        assert end["model_name"] == "deepseek-v4-pro"
        assert end["usage"]["completion_tokens"] == 16000

    try:
        _with_env(
            {
                "INCIDENT_AGENT_WRITER_MODEL": "deepseek-v4-pro",
                "INCIDENT_AGENT_WRITER_MAX_TOKENS": "16000",
                "INCIDENT_AGENT_WRITER_REASONING_EFFORT": "high",
                "INCIDENT_AGENT_WRITER_THINKING_ENABLED": "1",
                TRACE_ENV: "",
            },
            run,
        )
    finally:
        if previous is not None:
            llm_observability._invoke_openai_native_chat = previous


if __name__ == "__main__":
    test_investigator_defaults_to_tool_without_material_default()
    test_investigator_role_default_does_not_bypass_fake_llm()
    test_role_model_resolution_uses_tool_and_reasoner_groups()
    test_specific_role_model_overrides_group_model()
    test_invoke_trace_records_role_model_routing()
    test_trace_records_role_specific_endpoint_env_names()
    test_role_override_uses_native_openai_adapter_instead_of_langchain_bind()
    test_native_adapter_can_pass_reasoning_and_thinking_options()
    test_native_adapter_can_pass_role_generation_options()
    test_trace_records_native_finish_reason_usage_and_generation_options()
    print("llm role routing checks passed")
