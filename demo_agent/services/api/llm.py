from langchain_openai import ChatOpenAI

from ...config import AgentConfig


def make_llm(cfg: AgentConfig) -> ChatOpenAI:
    return ChatOpenAI(
        model=cfg.llm_model,
        temperature=cfg.llm_temperature,
        openai_api_key=cfg.llm_api_key,
        openai_api_base=cfg.llm_base_url,
        request_timeout=180,
        max_retries=1,
    )
