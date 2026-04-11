import json
import re
from typing import Any, Dict, List

from langchain.agents import AgentExecutor, create_react_agent
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.tools import BaseTool

from ..types.schemas import SupplementalResult, model_dump, validate_model


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
                "如果你要调用工具，必须严格使用以下格式："
                "Thought: <你的思考>"
                "Action: <工具名>"
                "Action Input: <JSON 或字符串参数>"
                "当信息足够时，必须使用：Final Answer: <报告Markdown全文>"
                "\n可用工具名：{tool_names}\n\n{tools}\n\n{agent_scratchpad}",
            ),
            ("user", "这是告警事件 JSON：\n{event_json}\n\n输出目录 out_dir：{out_dir}"),
        ]
    )
    agent = create_react_agent(llm, tools, prompt)
    return AgentExecutor(
        agent=agent,
        tools=tools,
        verbose=verbose,
        handle_parsing_errors=True,
        max_iterations=6,
        max_execution_time=45.0,
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
                "你可以调用有限工具补充证据，但只能围绕 gap_plan JSON 中指定的问题和动作行动。"
                "最终必须输出 JSON，不能输出 Markdown。"
                "JSON 结构固定为："
                '{{"supplemental_evidence":[{{"kind":"","source":"","type":"","query":"","url":"","title":"","claim":"","confidence":50,"raw_ref":"react_gap_fill"}}],'
                '"gap_updates":[{{"gap_id":"","status":"resolved|partially_resolved|unresolved","note":""}}],'
                '"candidate_family":"","supplemental_summary":""}}'
                "如果没有查到有效新增证据，也必须返回合法 JSON，并将 gap_updates 的状态写为 unresolved 或 partially_resolved。"
                "绝不编造家族、IOC、TTP 或攻击意图。"
                "补查时优先选择高价值技术来源，如 ThreatFox、URLhaus、any.run、Malpedia、Microsoft、Trend Micro、Proofpoint、Check Point、VirusTotal。"
                "你不必机械执行 gap_plan 中的全部 actions，而应优先选择最有可能补上关键缺口的一条动作链。"
                "如果多个 gap 指向同一目标（例如都是家族归因），优先用一次最强的技术来源搜索和页面阅读来同时回答它们。"
                "只要 gap_plan 里存在 actions，直接给 Final Answer 而不先调用至少一个工具是无效的。"
                "如果 ThreatFox 或 URLhaus 返回了结构化结果，优先把这些结构化结论整理为 supplemental_evidence，不要再重复搜索同一指标。"
                "如果你读取了页面正文，优先继续调用 extract_claim_candidates_from_page 和 extract_entities_from_page，"
                "从正文中提取可以直接写入证据的具体句子、TTP 线索和二跳 IOC。"
                "只有当页面或工具结果明确给出家族关联、行为描述或关联 IOC 时，才写入 supplemental_evidence。"
                "supplemental_evidence.claim 必须是基于页面正文或工具结果的中文转述；如果是正文证据，优先引用能支持结论的具体句子。"
                "candidate_family 只有在高价值来源或明确页面正文显式关联到某家族时才填写，否则留空。"
                "不要为了完成任务重复 baseline 已有的 VT / 本地库结论。"
                "如果你要调用工具，必须严格使用以下格式："
                "Thought: <你的思考>"
                "Action: <工具名>"
                "Action Input: <JSON 或字符串参数>"
                "当你完成时，必须使用：Final Answer: <JSON对象>"
                "\n可用工具名：{tool_names}\n\n{tools}\n\n{agent_scratchpad}",
            ),
            ("user", "analysis:\n{analysis_json}\n\ngap_plan:\n{gap_plan_json}\n\nout_dir:\n{out_dir}"),
        ]
    )
    agent = create_react_agent(llm, tools, prompt)
    return AgentExecutor(
        agent=agent,
        tools=tools,
        verbose=verbose,
        handle_parsing_errors=True,
        max_iterations=6,
        max_execution_time=30.0,
    )


def _extract_json_object(text: str) -> Dict[str, Any]:
    cleaned = str(text or "").strip()
    if not cleaned:
        return {}
    fenced = re.search(r"```(?:json)?\s*(\{.*\})\s*```", cleaned, flags=re.DOTALL)
    if fenced:
        cleaned = fenced.group(1)
    for prefix in ("Final Answer:", "Final:"):
        if cleaned.startswith(prefix):
            cleaned = cleaned.split(prefix, 1)[1].strip()
            break
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


def run_gap_fill_react(executor: AgentExecutor, *, analysis: Dict[str, Any], gap_plan: Dict[str, Any], out_dir: str) -> Dict[str, Any]:
    result = executor.invoke(
        {
            "analysis_json": json.dumps(analysis, ensure_ascii=False),
            "gap_plan_json": json.dumps(gap_plan, ensure_ascii=False),
            "out_dir": out_dir,
        }
    )
    output = str(result.get("output") or "").strip()
    parsed = _extract_json_object(output)
    validated = validate_model(
        SupplementalResult,
        parsed,
        default=SupplementalResult(supplemental_evidence=[], gap_updates=[], supplemental_summary=output),
    )
    return {
        "ok": True,
        "result": result,
        "parsed": model_dump(validated),
    }
