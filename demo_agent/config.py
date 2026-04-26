import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

try:
    from dotenv import load_dotenv
    DOTENV_AVAILABLE = True
    DOTENV_IMPORT_ERROR = ""
except Exception as exc:  # pragma: no cover - keep env loading optional at runtime
    DOTENV_AVAILABLE = False
    DOTENV_IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

    def load_dotenv(*args, **kwargs):  # type: ignore[no-redef]
        return False


ROOT = Path(__file__).resolve().parent
ENV_FILE = ROOT / ".env"
DOTENV_LOADED = bool(load_dotenv(ENV_FILE, override=False))


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
    abusech_auth_key: Optional[str] = None
    threatfox_auth_key: Optional[str] = None
    urlhaus_auth_key: Optional[str] = None
    db_host: str = "127.0.0.1"
    db_port: int = 3306
    db_name: str = "threat_intel"
    db_user: str = "root"
    db_password: str = ""
    db_charset: str = "utf8mb4"


@dataclass(frozen=True)
class DatabaseConfig:
    host: str = "127.0.0.1"
    port: int = 3306
    name: str = "threat_intel"
    user: str = "root"
    password: str = ""
    charset: str = "utf8mb4"


def load_database_config() -> DatabaseConfig:
    db_url = os.getenv("DB_URL") or ""
    parsed = urlparse(db_url) if db_url else None
    url_host = parsed.hostname if parsed else None
    url_port = parsed.port if parsed and parsed.port is not None else None
    url_user = parsed.username if parsed else None
    url_password = parsed.password if parsed else None
    url_name = parsed.path.lstrip("/") if parsed and parsed.path else None
    return DatabaseConfig(
        host=os.getenv("DB_HOST") or url_host or "127.0.0.1",
        port=int(os.getenv("DB_PORT") or url_port or 3306),
        name=os.getenv("DB_NAME") or url_name or "threat_intel",
        user=os.getenv("DB_USER") or url_user or "root",
        password=os.getenv("DB_PASSWORD") or url_password or "",
        charset=os.getenv("DB_CHARSET") or "utf8mb4",
    )


def load_config() -> AgentConfig:
    api_key = os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY") or ""
    if not api_key:
        raise RuntimeError("Missing LLM_API_KEY (or OPENAI_API_KEY).")

    base_url = os.getenv("LLM_BASE_URL") or os.getenv("OPENAI_BASE_URL") or "https://api.deepshields.com/v1"
    model = os.getenv("LLM_MODEL") or "chat"  # DeepShield: chat|reasoner
    temperature = float(os.getenv("LLM_TEMPERATURE") or "0.7")
    vt_api_key = os.getenv("VT_API_KEY") or os.getenv("VIRUSTOTAL_API_KEY")
    abusech_auth_key = os.getenv("ABUSECH_AUTH_KEY") or os.getenv("ABUSE_CH_AUTH_KEY")
    threatfox_auth_key = os.getenv("THREATFOX_AUTH_KEY") or abusech_auth_key
    urlhaus_auth_key = os.getenv("URLHAUS_AUTH_KEY") or abusech_auth_key
    db_cfg = load_database_config()

    return AgentConfig(
        llm_api_key=api_key,
        llm_base_url=base_url,
        llm_model=model,
        llm_temperature=temperature,
        vt_api_key=vt_api_key,
        abusech_auth_key=abusech_auth_key,
        threatfox_auth_key=threatfox_auth_key,
        urlhaus_auth_key=urlhaus_auth_key,
        db_host=db_cfg.host,
        db_port=db_cfg.port,
        db_name=db_cfg.name,
        db_user=db_cfg.user,
        db_password=db_cfg.password,
        db_charset=db_cfg.charset,
    )

