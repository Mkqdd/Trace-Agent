import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

try:
    from dotenv import load_dotenv
except Exception:  # pragma: no cover - keep env loading optional at runtime
    def load_dotenv(*args, **kwargs):  # type: ignore[no-redef]
        return False


ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env", override=False)


@dataclass(frozen=True)
class AgentConfig:
    """
    Mirrors Hello-Agents style: load model config from env.
    DeepShield is OpenAI-compatible.
    """

    llm_api_key: str
    llm_base_url: str
    llm_model: str
    llm_temperature: float = 0.7
    vt_api_key: Optional[str] = None


def load_config() -> AgentConfig:
    api_key = os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY") or ""
    if not api_key:
        raise RuntimeError("Missing LLM_API_KEY (or OPENAI_API_KEY).")

    base_url = os.getenv("LLM_BASE_URL") or os.getenv("OPENAI_BASE_URL") or "https://api.deepshields.com/v1"
    model = os.getenv("LLM_MODEL") or "chat"  # DeepShield: chat|reasoner
    temperature = float(os.getenv("LLM_TEMPERATURE") or "0.7")
    vt_api_key = os.getenv("VT_API_KEY") or os.getenv("VIRUSTOTAL_API_KEY")

    return AgentConfig(
        llm_api_key=api_key,
        llm_base_url=base_url,
        llm_model=model,
        llm_temperature=temperature,
        vt_api_key=vt_api_key,
    )

