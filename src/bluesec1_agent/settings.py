from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

_ENV_FILE = Path(__file__).resolve().parents[2] / ".env"


class Settings(BaseSettings):
    """Scenario-runtime and OpenAI-compatible provider settings."""

    model_config = SettingsConfigDict(
        env_file=_ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    scenario_runtime_endpoint: str = Field(
        default="127.0.0.1:50051",
        validation_alias="SCENARIO_RUNTIME_ENDPOINT",
        min_length=1,
    )
    scenario_runtime_token: SecretStr = Field(
        validation_alias="SCENARIO_RUNTIME_TOKEN",
        min_length=1,
    )
    scenario_runtime_verify_tls: bool = Field(
        default=True,
        validation_alias="SCENARIO_RUNTIME_VERIFY_TLS",
    )
    scenario_runtime_arena: str | None = Field(
        default=None,
        validation_alias="SCENARIO_RUNTIME_ARENA",
        min_length=1,
        max_length=64,
    )
    # Unset by default: the CLI derives `<experiment>@<commit>` so every platform run
    # maps to one EXPERIMENTS.md row. Set only to force a fixed label.
    remote_run_label: str | None = Field(
        default=None,
        validation_alias="REMOTE_RUN_LABEL",
        min_length=1,
        max_length=255,
    )
    agent_name: str = Field(
        default="bluesec1-agent",
        validation_alias="AGENT_NAME",
        min_length=1,
        max_length=255,
    )

    llm_base_url: str = Field(validation_alias="LLM_BASE_URL", min_length=1)
    llm_api_key: SecretStr = Field(validation_alias="LLM_API_KEY", min_length=1)
    llm_default_model: str = Field(validation_alias="LLM_DEFAULT_MODEL", min_length=1)
    agent_prompt: Literal["reference", "strategy"] = Field(
        default="strategy",
        validation_alias="AGENT_PROMPT",
    )
    agent_expand_entity: bool = Field(
        default=False,
        validation_alias="AGENT_EXPAND_ENTITY",
    )
    agent_finish_review: bool = Field(
        default=False,
        validation_alias="AGENT_FINISH_REVIEW",
    )
    # H-08: a stronger model takes the single finish-review turn. Empty = use the main model.
    llm_review_model: str | None = Field(default=None, validation_alias="LLM_REVIEW_MODEL")
    # Hard cap on provider spend for the review model per run (USD, from usage.cost).
    llm_review_budget_usd: float = Field(
        default=0.5, validation_alias="LLM_REVIEW_BUDGET_USD", ge=0
    )
    llm_response_format: Literal["json_schema", "json_object"] = Field(
        default="json_schema",
        validation_alias="LLM_RESPONSE_FORMAT",
    )
    llm_timeout_seconds: float = Field(
        default=120.0,
        validation_alias="LLM_TIMEOUT_SECONDS",
        gt=0,
    )
    llm_max_completion_tokens: int = Field(
        default=16_384,
        validation_alias="LLM_MAX_COMPLETION_TOKENS",
        gt=0,
    )
    llm_max_step_retries: int = Field(
        default=3,
        validation_alias="LLM_MAX_STEP_RETRIES",
        ge=1,
        le=5,
    )
    agent_max_steps: int = Field(
        default=100,
        validation_alias="BLUESEC_AGENT_MAX_STEPS",
        ge=1,
        le=100,
    )
