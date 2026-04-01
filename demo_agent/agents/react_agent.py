import json
import re
from typing import Any, Dict, List

from langchain.agents import AgentExecutor, create_react_agent
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.tools import BaseTool


def build_react_executor(llm: Any, tools: List[BaseTool], *, verbose: bool = True) -> AgentExecutor:
    prompt = ChatPromptTemplate.from_messages(
        [
            (
                "system",
                "你是自动化溯源 Agent。输入是一条“命中后告警”的事件 JSON。"
                "你可以调用工具做外部情报富化与整理，并最终产出中文 Markdown 报告。"
                "要求：证据/情报必须用中文转述（URL 保持原样），不要编造 JSON/工具输出中不存在的 IOC。"
                "当你认为信息足够时，直接输出 Final: <报告Markdown全文>。"
                "注意：如果工具输出中出现 cache_hit=true 或 done=true，说明无需重复调用该工具，应继续下一步。"
                "\n可用工具名：{tool_names}\n\n{tools}\n\n{agent_scratchpad}",
            ),
            ("user", "这是告警事件 JSON：\n{event_json}\n\n输出目录 out_dir：{out_dir}"),
        ]
    )
    agent = create_react_agent(llm, tools, prompt)
    # If the agent hits iteration/time limits, "generate" asks the LLM
    # to produce a final answer instead of returning the generic stop message.
    return AgentExecutor(
        agent=agent,
        tools=tools,
        verbose=verbose,
        handle_parsing_errors=True,
        max_iterations=6,
        early_stopping_method="generate",
    )


def run_react(executor: AgentExecutor, *, event: Dict[str, Any], out_dir: str) -> Dict[str, Any]:
    result = executor.invoke({"event_json": json.dumps(event, ensure_ascii=False), "out_dir": out_dir})
    return {"ok": True, "result": result}


def build_gap_fill_executor(llm: Any, tools: List[BaseTool], *, verbose: bool = False) -> AgentExecutor:
    prompt = ChatPromptTemplate.from_messages(
        [
            (
                "system",
                "你是受限补查 Agent。你的任务不是重做完整研判，而是仅围绕 analysis JSON 中的 gaps 做一次定向补查。"
                "你可以调用有限工具补充证据，但只能围绕 gaps 指定的问题行动。"
                "最终必须输出 JSON，不能输出 Markdown。"
                "JSON 结构固定为："
                '{"supplemental_evidence":[{"kind":"","source":"","type":"","query":"","url":"","title":"","claim":"","confidence":50,"raw_ref":"react_gap_fill"}],'
                '"gap_updates":[{"gap_id":"","status":"resolved|partially_resolved|unresolved","note":""}],'
                '"candidate_family":"","supplemental_summary":""}'
                "如果没有查到有效新增证据，也要返回空 supplemental_evidence 和 gap_updates。"
                "\n可用工具名：{tool_names}\n\n{tools}\n\n{agent_scratchpad}",
            ),
            ("user", "analysis:\n{analysis_json}\n\nout_dir:\n{out_dir}"),
        ]
    )
    agent = create_react_agent(llm, tools, prompt)
    return AgentExecutor(
        agent=agent,
        tools=tools,
        verbose=verbose,
        handle_parsing_errors=True,
        max_iterations=4,
        early_stopping_method="generate",
    )


def _extract_json_object(text: str) -> Dict[str, Any]:
    cleaned = str(text or "").strip()
    if not cleaned:
        return {}
    fenced = re.search(r"```(?:json)?\s*(\{.*\})\s*```", cleaned, flags=re.DOTALL)
    if fenced:
        cleaned = fenced.group(1)
    if cleaned.startswith("Final:"):
        cleaned = cleaned.split("Final:", 1)[1].strip()
    if cleaned.startswith("{") and cleaned.endswith("}"):
        try:
            return json.loads(cleaned)
        except Exception:
            pass
    match = re.search(r"(\{.*\})", cleaned, flags=re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except Exception:
            return {}
    return {}


def run_gap_fill_react(executor: AgentExecutor, *, analysis: Dict[str, Any], out_dir: str) -> Dict[str, Any]:
    result = executor.invoke({"analysis_json": json.dumps(analysis, ensure_ascii=False), "out_dir": out_dir})
    output = str(result.get("output") or "").strip()
    parsed = _extract_json_object(output)
    return {
        "ok": True,
        "result": result,
        "parsed": {
            "supplemental_evidence": list(parsed.get("supplemental_evidence") or []),
            "gap_updates": list(parsed.get("gap_updates") or []),
            "candidate_family": parsed.get("candidate_family"),
            "supplemental_summary": parsed.get("supplemental_summary") or output,
        },
    }

