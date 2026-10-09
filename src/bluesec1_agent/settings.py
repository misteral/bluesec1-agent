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

    # The leaderboard shows run label, agent and model. When true, only opaque codes are sent;
    # the mapping to experiment/commit/model stays local in runs/<dir>/config.json.
    public_opaque_labels: bool = Field(default=True, validation_alias="PUBLIC_OPAQUE_LABELS")

    llm_base_url: str = Field(validation_alias="LLM_BASE_URL", min_length=1)
    llm_api_key: SecretStr = Field(validation_alias="LLM_API_KEY", min_length=1)
    llm_default_model: str = Field(validation_alias="LLM_DEFAULT_MODEL", min_length=1)
    # Which agent runs: `sgr` = SimpleSGRAgent (LLM loop); `jev_llm` = Jev navigates, LLM decides
    # (H-18); `jev_only` = Jev navigates and decides (H-19). Separate classes, never mixed.
    agent_kind: Literal["sgr", "jev_llm", "jev_only"] = Field(
        default="sgr", validation_alias="AGENT_KIND"
    )
    jev_model: str = Field(default="typesafe/jev-1.13", validation_alias="JEV_MODEL")
    jev_call_budget: int = Field(default=20, validation_alias="JEV_CALL_BUDGET", ge=1, le=95)
    jev_attack_threshold: float = Field(
        default=0.35, validation_alias="JEV_ATTACK_THRESHOLD", gt=0, lt=1
    )
    # Sufficiency stop for Jev navigation; unset = only an explicit `finish` choice stops.
    jev_stop_threshold: float | None = Field(
        default=None, validation_alias="JEV_STOP_THRESHOLD", gt=0, lt=1
    )
    jev_artifact_policy: Literal["jev", "dual_tier"] = Field(
        default="jev", validation_alias="JEV_ARTIFACT_POLICY"
    )
    jev_benign_max_entities: int = Field(
        default=4, validation_alias="JEV_BENIGN_MAX_ENTITIES", ge=1, le=20
    )
    # Contract tiers + benign cap on the final payload of the LLM agent (from exp-014).
    agent_payload_policy: bool = Field(default=False, validation_alias="AGENT_PAYLOAD_POLICY")
    # Stricter payload shaping from the 2026-10-07 brainstorm (see EXPERIMENTS exp-019).
    payload_v2: bool = Field(default=False, validation_alias="PAYLOAD_V2")
    agent_payload_tiers: bool = Field(default=True, validation_alias="AGENT_PAYLOAD_TIERS")
    agent_verdict_samples: int = Field(
        default=1, validation_alias="AGENT_VERDICT_SAMPLES", ge=1, le=7
    )
    # Control experiment only: submit benign verdicts without legitimacy evidence (Jev agent).
    jev_benign_empty: bool = Field(default=False, validation_alias="JEV_BENIGN_EMPTY")
    # H-34: Jev chooses benign root-cause citations for the LLM agent.
    agent_jev_benign_evidence: bool = Field(
        default=False, validation_alias="AGENT_JEV_BENIGN_EVIDENCE"
    )
    # H-37: drop telemetry records (cmdlet invocations, connections) from malicious artifacts.
    payload_no_telemetry: bool = Field(default=False, validation_alias="PAYLOAD_NO_TELEMETRY")
    agent_benign_empty: bool = Field(default=False, validation_alias="AGENT_BENIGN_EMPTY")
    agent_review_precision: bool = Field(default=False, validation_alias="AGENT_REVIEW_PRECISION")
    agent_benign_host_check: bool = Field(default=False, validation_alias="AGENT_BENIGN_HOST_CHECK")
    agent_verdict_bar: bool = Field(default=False, validation_alias="AGENT_VERDICT_BAR")
    # H-44: comma-separated conclude checks (host_window, inbound_sources, children,
    # actor_mechanism); empty = conclude step disabled.
    agent_conclude_flags: str = Field(default="", validation_alias="AGENT_CONCLUDE_FLAGS")
    payload_keep_c2: bool = Field(default=False, validation_alias="PAYLOAD_KEEP_C2")
    agent_rotate_identity: bool = Field(default=False, validation_alias="AGENT_ROTATE_IDENTITY")
    agent_hash_pivot: bool = Field(default=False, validation_alias="AGENT_HASH_PIVOT")
    agent_min_processes: bool = Field(default=False, validation_alias="AGENT_MIN_PROCESSES")
    agent_host_scope: bool = Field(default=False, validation_alias="AGENT_HOST_SCOPE")
    agent_benign_max_citations: int = Field(
        default=3, validation_alias="AGENT_BENIGN_MAX_CITATIONS", ge=1, le=6
    )
    agent_complete_payload: bool = Field(default=False, validation_alias="AGENT_COMPLETE_PAYLOAD")
    agent_claude_profile: bool = Field(default=False, validation_alias="AGENT_CLAUDE_PROFILE")
    agent_resolve_roots: bool = Field(default=False, validation_alias="AGENT_RESOLVE_ROOTS")
    agent_clean_rows: bool = Field(default=False, validation_alias="AGENT_CLEAN_ROWS")
    agent_max_rows: int = Field(default=0, validation_alias="AGENT_MAX_ROWS", ge=0, le=30)
    agent_local_relations: bool = Field(default=False, validation_alias="AGENT_LOCAL_RELATIONS")
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
    # Whole-run LLM spend cap (USD). The current task finishes; no new task is leased.
    llm_run_budget_usd: float | None = Field(
        default=None, validation_alias="LLM_RUN_BUDGET_USD", gt=0
    )
    llm_reasoning_effort: Literal["low", "medium", "high"] | None = Field(
        default=None, validation_alias="LLM_REASONING_EFFORT"
    )
    # Comma-separated OpenRouter providers to pin (no fallback), e.g. "anthropic" for BYOK.
    llm_provider_only: str = Field(default="", validation_alias="LLM_PROVIDER_ONLY")
    llm_plain_history: bool = Field(default=False, validation_alias="LLM_PLAIN_HISTORY")
    llm_response_format: Literal["json_schema", "json_object", "none"] = Field(
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
