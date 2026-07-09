from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AGENT_",
        env_file=".env",
        case_sensitive=False,
        extra="ignore",
    )

    database_url: str = Field(default="sqlite:///./data/agent.db")
    log_level: str = Field(default="INFO")

    # LLM provider — auto-detected from whichever key is set if left blank
    llm_provider: str = Field(default="")   # "anthropic" | "gemini"
    llm_model: str = Field(default="")      # uses provider default when blank

    # Provider keys — set exactly one
    anthropic_api_key: str = Field(default="")
    gemini_api_key: str = Field(default="")

    # JAR security scanner: upload/scan-working-directory + upload size cap
    max_upload_mb: int = Field(default=150)
    scan_upload_dir: str = Field(default="data/uploads")
    scan_work_dir: str = Field(default="data/decompiled")

    # Local decompiler (CFR) invocation
    cfr_jar_path: str = Field(default="tools/cfr-0.152.jar")
    java_bin: str = Field(default="java")
    cfr_timeout_s: int = Field(default=180)

    # Triage / cost-control caps for what reaches the LLM per scan
    triage_max_classes: int = Field(default=60)
    triage_max_chars: int = Field(default=150_000)
    triage_per_category_max_chars: int = Field(default=30_000)

    # Hardcoded pricing table version tag (src/llm/pricing.py)
    pricing_table_version: str = Field(default="2026-07")

    # Max output tokens per LLM call. Category review nodes can return several
    # fully-populated 20-field Finding objects per response; this must have
    # real headroom below the model's real output ceiling (64000 for Claude
    # Sonnet 4.6) so a rich finding set never gets truncated mid-JSON.
    llm_max_tokens: int = Field(default=32000)


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
