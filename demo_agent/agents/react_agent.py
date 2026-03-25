import json
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
                "\n\n{tools}\n\n{agent_scratchpad}",
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

