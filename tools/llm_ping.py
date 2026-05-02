from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from demo_agent.config import load_config
from demo_agent.services.api.llm import make_llm
from demo_agent.services.api.llm_observability import TRACE_ENV, invoke_llm_with_trace


def main() -> None:
    parser = argparse.ArgumentParser(description="Minimal Trace-Agent LLM connectivity ping.")
    parser.add_argument("--trace-path", default="", help="optional JSONL path for LLM call start/end/error trace")
    parser.add_argument("--prompt", default='只回复 JSON：{"ok":true}', help="short prompt used for the ping")
    args = parser.parse_args()

    if args.trace_path:
        os.environ[TRACE_ENV] = str(Path(args.trace_path).resolve())

    started = time.perf_counter()
    cfg = load_config()
    llm = make_llm(cfg)
    bound_llm = llm.bind(max_tokens=32) if hasattr(llm, "bind") else llm

    try:
        from langchain_core.prompts import ChatPromptTemplate

        prompt = ChatPromptTemplate.from_messages(
            [
                ("system", "你是一个连通性测试助手。只输出最小 JSON，不要解释。"),
                ("user", "{prompt}"),
            ]
        )
        messages = prompt.format_messages(prompt=args.prompt)
        response = invoke_llm_with_trace(bound_llm, messages, role="llm_ping")
        content = str(getattr(response, "content", "") or "").strip()
        result = {
            "ok": True,
            "elapsed_ms": int((time.perf_counter() - started) * 1000),
            "model": cfg.llm_model,
            "base_url": cfg.llm_base_url,
            "content_preview": content[:200],
            "trace_path": str(Path(args.trace_path).resolve()) if args.trace_path else "",
        }
        print(json.dumps(result, ensure_ascii=False, indent=2))
    except Exception as exc:
        result = {
            "ok": False,
            "elapsed_ms": int((time.perf_counter() - started) * 1000),
            "model": cfg.llm_model,
            "base_url": cfg.llm_base_url,
            "error_type": type(exc).__name__,
            "error": str(exc),
            "trace_path": str(Path(args.trace_path).resolve()) if args.trace_path else "",
        }
        print(json.dumps(result, ensure_ascii=False, indent=2))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
