from __future__ import annotations

import os
from dataclasses import dataclass

from threatprism.auth.production import (
    PRODUCTION_IDENTITY_AUTH_MODE,
    ProductionIdentityReadinessReport,
    evaluate_production_identity_readiness,
)

_DOTENV_LOADED = False


def load_local_dotenv() -> None:
    """Load a local .env once if python-dotenv is available, treating .env as
    **authoritative** (override=True) — so a stray/empty shell variable cannot
    shadow the configured value on an explicit live run. Called only from explicit
    live entry points (e.g. the demo runners' --live flag), never from
    `from_env()`, so tests, the validation wrapper, and the app factory never
    auto-pick-up a local .env."""
    global _DOTENV_LOADED
    if _DOTENV_LOADED:
        return
    _DOTENV_LOADED = True
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    load_dotenv(override=True)


@dataclass(frozen=True)
class Settings:
    env: str = "demo"
    database_url: str = "sqlite:///./data/threatprism.db"
    api_auth_mode: str = "none"
    api_token: str | None = None
    demo_api_keys: str = ""
    auth_required: bool = True
    local_dev_ack: bool = False
    demo_role_override_enabled: bool = False
    demo_seed_enabled: bool = False
    llm_provider: str = "deterministic_demo"
    allow_real_actions: bool = False
    # Real-LLM provider (spec 33) — gated; defaults keep the demo posture.
    anthropic_api_key: str = ""
    llm_model_id: str = "claude-sonnet-4-5"
    llm_model_revision: str = ""
    llm_temperature: float = 0.2
    llm_call_timeout_seconds: int = 60
    llm_max_retries: int = 2
    # Governance: usage/cost accounting + spend caps (gaps 1-2).
    llm_input_price_per_mtok: float = 0.0
    llm_output_price_per_mtok: float = 0.0
    llm_max_cost_usd_per_run: float = 5.0
    llm_max_total_tokens_per_run: int = 2_000_000
    summary_max_chars: int = 1200
    batch_max_events: int = 50
    batch_max_input_tokens: int = 150_000
    output_token_reserve: int = 4_096
    mock_analyst_provider: str = "openai"
    openai_api_key: str = ""
    mock_analyst_model_id: str = "gpt-4o-mini"
    # Independent-analyst pricing (a different model from the triage brain, so it
    # needs its own price). gpt-4o-mini standard: $0.15 / $0.60 per 1M tokens.
    mock_analyst_input_price_per_mtok: float = 0.0
    mock_analyst_output_price_per_mtok: float = 0.0
    # Semantic prompt-injection firewall (spec 32) — gated; default off keeps the
    # demo/CI pipeline byte-for-byte unchanged. Detector, never a gate.
    semantic_firewall_enabled: bool = False
    semantic_firewall_model_id: str = "meta-llama/Llama-Prompt-Guard-2-86M"
    semantic_firewall_model_revision: str = ""
    semantic_firewall_quarantine_threshold: float = 0.9
    semantic_firewall_review_threshold: float = 0.5
    max_request_body_bytes: int = 262_144
    case_post_rate_limit_per_minute: int = 60
    triage_concurrency_limit: int = 4
    production_identity_provider: str = ""
    production_identity_issuer: str = ""
    production_identity_audience: str = ""
    production_identity_jwks_uri: str = ""
    production_identity_subject_claim: str = "sub"
    production_identity_roles_claim: str = "roles"
    production_identity_tenant_claim: str = "tid"
    production_identity_required_roles: str = "analyst,engineer,manager_grc,legal_privacy,audit_debug,admin"
    production_identity_allowed_algorithms: str = "RS256"
    production_identity_live_verification_enabled: bool = False
    production_identity_allowed_tenants: str = ""
    production_identity_role_mapping: str = ""
    production_identity_jwks_json: str = ""
    production_identity_jwks_fetch_enabled: bool = False
    production_identity_clock_skew_seconds: int = 60
    production_identity_max_token_bytes: int = 8192
    production_identity_claim_mapping_version: str = "local-demo-v1"

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            env=os.getenv("THREATPRISM_ENV", "demo"),
            database_url=os.getenv("DATABASE_URL", "sqlite:///./data/threatprism.db"),
            api_auth_mode=os.getenv("API_AUTH_MODE", "none"),
            api_token=os.getenv("API_TOKEN") or None,
            demo_api_keys=os.getenv("DEMO_API_KEYS", ""),
            auth_required=_parse_bool(os.getenv("THREATPRISM_AUTH_REQUIRED"), default=True),
            local_dev_ack=_parse_bool(os.getenv("THREATPRISM_LOCAL_DEV_ACK"), default=False),
            demo_role_override_enabled=_parse_bool(os.getenv("DEMO_ROLE_OVERRIDE_ENABLED"), default=False),
            demo_seed_enabled=_parse_bool(os.getenv("THREATPRISM_DEMO_SEED"), default=False),
            llm_provider=os.getenv("LLM_PROVIDER", "deterministic_demo"),
            allow_real_actions=_parse_bool(os.getenv("ALLOW_REAL_ACTIONS"), default=False),
            anthropic_api_key=os.getenv("ANTHROPIC_API_KEY", ""),
            llm_model_id=os.getenv("LLM_MODEL_ID", "claude-sonnet-4-5"),
            llm_model_revision=os.getenv("LLM_MODEL_REVISION", ""),
            llm_temperature=float(os.getenv("LLM_TEMPERATURE", "0.2")),
            llm_call_timeout_seconds=_parse_int(os.getenv("LLM_CALL_TIMEOUT_SECONDS"), default=60),
            llm_max_retries=_parse_int(os.getenv("LLM_MAX_RETRIES"), default=2),
            llm_input_price_per_mtok=float(os.getenv("LLM_INPUT_PRICE_PER_MTOK", "0") or "0"),
            llm_output_price_per_mtok=float(os.getenv("LLM_OUTPUT_PRICE_PER_MTOK", "0") or "0"),
            llm_max_cost_usd_per_run=float(os.getenv("LLM_MAX_COST_USD_PER_RUN", "5") or "5"),
            llm_max_total_tokens_per_run=_parse_int(os.getenv("LLM_MAX_TOTAL_TOKENS_PER_RUN"), default=2_000_000),
            summary_max_chars=_parse_int(os.getenv("SUMMARY_MAX_CHARS"), default=1200),
            batch_max_events=_parse_int(os.getenv("BATCH_MAX_EVENTS"), default=50),
            batch_max_input_tokens=_parse_int(os.getenv("BATCH_MAX_INPUT_TOKENS"), default=150_000),
            output_token_reserve=_parse_int(os.getenv("OUTPUT_TOKEN_RESERVE"), default=4_096),
            mock_analyst_provider=os.getenv("MOCK_ANALYST_PROVIDER", "openai"),
            openai_api_key=os.getenv("OPENAI_API_KEY", ""),
            mock_analyst_model_id=os.getenv("MOCK_ANALYST_MODEL_ID", "gpt-4o-mini"),
            mock_analyst_input_price_per_mtok=float(
                os.getenv("MOCK_ANALYST_INPUT_PRICE_PER_MTOK", "0") or "0"
            ),
            mock_analyst_output_price_per_mtok=float(
                os.getenv("MOCK_ANALYST_OUTPUT_PRICE_PER_MTOK", "0") or "0"
            ),
            semantic_firewall_enabled=_parse_bool(
                os.getenv("SEMANTIC_FIREWALL_ENABLED"), default=False
            ),
            semantic_firewall_model_id=os.getenv(
                "SEMANTIC_FIREWALL_MODEL_ID", "meta-llama/Llama-Prompt-Guard-2-86M"
            ),
            semantic_firewall_model_revision=os.getenv("SEMANTIC_FIREWALL_MODEL_REVISION", ""),
            semantic_firewall_quarantine_threshold=float(
                os.getenv("SEMANTIC_FIREWALL_QUARANTINE_THRESHOLD", "0.9") or "0.9"
            ),
            semantic_firewall_review_threshold=float(
                os.getenv("SEMANTIC_FIREWALL_REVIEW_THRESHOLD", "0.5") or "0.5"
            ),
            max_request_body_bytes=_parse_int(os.getenv("MAX_REQUEST_BODY_BYTES"), default=262_144),
            case_post_rate_limit_per_minute=_parse_int(
                os.getenv("CASE_POST_RATE_LIMIT_PER_MINUTE"), default=60
            ),
            triage_concurrency_limit=_parse_int(os.getenv("TRIAGE_CONCURRENCY_LIMIT"), default=4),
            production_identity_provider=os.getenv("PRODUCTION_IDENTITY_PROVIDER", ""),
            production_identity_issuer=os.getenv("PRODUCTION_IDENTITY_ISSUER", ""),
            production_identity_audience=os.getenv("PRODUCTION_IDENTITY_AUDIENCE", ""),
            production_identity_jwks_uri=os.getenv("PRODUCTION_IDENTITY_JWKS_URI", ""),
            production_identity_subject_claim=os.getenv("PRODUCTION_IDENTITY_SUBJECT_CLAIM", "sub"),
            production_identity_roles_claim=os.getenv("PRODUCTION_IDENTITY_ROLES_CLAIM", "roles"),
            production_identity_tenant_claim=os.getenv("PRODUCTION_IDENTITY_TENANT_CLAIM", "tid"),
            production_identity_required_roles=os.getenv(
                "PRODUCTION_IDENTITY_REQUIRED_ROLES",
                "analyst,engineer,manager_grc,legal_privacy,audit_debug,admin",
            ),
            production_identity_allowed_algorithms=os.getenv(
                "PRODUCTION_IDENTITY_ALLOWED_ALGORITHMS", "RS256"
            ),
            production_identity_live_verification_enabled=_parse_bool(
                os.getenv("PRODUCTION_IDENTITY_LIVE_VERIFICATION_ENABLED"), default=False
            ),
            production_identity_allowed_tenants=os.getenv("PRODUCTION_IDENTITY_ALLOWED_TENANTS", ""),
            production_identity_role_mapping=os.getenv("PRODUCTION_IDENTITY_ROLE_MAPPING", ""),
            production_identity_jwks_json=os.getenv("PRODUCTION_IDENTITY_JWKS_JSON", ""),
            production_identity_jwks_fetch_enabled=_parse_bool(
                os.getenv("PRODUCTION_IDENTITY_JWKS_FETCH_ENABLED"), default=False
            ),
            production_identity_clock_skew_seconds=_parse_int(
                os.getenv("PRODUCTION_IDENTITY_CLOCK_SKEW_SECONDS"), default=60
            ),
            production_identity_max_token_bytes=_parse_int(
                os.getenv("PRODUCTION_IDENTITY_MAX_TOKEN_BYTES"), default=8192
            ),
            production_identity_claim_mapping_version=os.getenv(
                "PRODUCTION_IDENTITY_CLAIM_MAPPING_VERSION", "local-demo-v1"
            ),
        )

    def production_identity_readiness(self) -> ProductionIdentityReadinessReport:
        return evaluate_production_identity_readiness(
            auth_mode=self.api_auth_mode,
            provider=self.production_identity_provider,
            issuer=self.production_identity_issuer,
            audience=self.production_identity_audience,
            jwks_uri=self.production_identity_jwks_uri,
            subject_claim=self.production_identity_subject_claim,
            roles_claim=self.production_identity_roles_claim,
            tenant_claim=self.production_identity_tenant_claim,
            required_roles=self.production_identity_required_roles,
            allowed_algorithms=self.production_identity_allowed_algorithms,
            live_verification_enabled=self.production_identity_live_verification_enabled,
            allowed_tenants=self.production_identity_allowed_tenants,
            role_mapping=self.production_identity_role_mapping,
            jwks_json=self.production_identity_jwks_json,
            jwks_fetch_enabled=self.production_identity_jwks_fetch_enabled,
            clock_skew_seconds=self.production_identity_clock_skew_seconds,
            max_token_bytes=self.production_identity_max_token_bytes,
            claim_mapping_version=self.production_identity_claim_mapping_version,
        )

    def validate_runtime(self) -> None:
        auth_mode = self.api_auth_mode.strip().lower()
        if auth_mode not in {"none", "demo_key", PRODUCTION_IDENTITY_AUTH_MODE}:
            raise ValueError("Unsupported API_AUTH_MODE.")
        if self.demo_seed_enabled and self.env.strip().lower() in {"prod", "production"}:
            raise ValueError("Demo seeding (THREATPRISM_DEMO_SEED) cannot be enabled in production environments.")
        if self.env.strip().lower() in {"prod", "production"} and auth_mode in {"none", "demo_key"}:
            raise ValueError("Production environments cannot use disabled or demo API authentication.")
        if auth_mode == PRODUCTION_IDENTITY_AUTH_MODE:
            self.production_identity_readiness().require_static_ready()
        if auth_mode == "demo_key" and not self.demo_api_keys.strip():
            raise ValueError("DEMO_API_KEYS must be configured when API_AUTH_MODE=demo_key.")
        if auth_mode == "none" and self.auth_required and not self.local_dev_ack:
            raise ValueError(
                "API_AUTH_MODE=none requires THREATPRISM_LOCAL_DEV_ACK=true or THREATPRISM_AUTH_REQUIRED=false."
            )
        if self.max_request_body_bytes <= 0:
            raise ValueError("MAX_REQUEST_BODY_BYTES must be greater than zero.")
        if self.case_post_rate_limit_per_minute <= 0:
            raise ValueError("CASE_POST_RATE_LIMIT_PER_MINUTE must be greater than zero.")
        if self.triage_concurrency_limit <= 0:
            raise ValueError("TRIAGE_CONCURRENCY_LIMIT must be greater than zero.")
        if self.llm_provider == "anthropic_claude":
            if not self.anthropic_api_key.strip():
                raise ValueError("LLM_PROVIDER=anthropic_claude requires ANTHROPIC_API_KEY.")
            from threatprism.llm.governance import APPROVED_MODELS  # lazy: avoid import cycle

            if self.llm_model_id not in APPROVED_MODELS:
                raise ValueError(
                    f"LLM_MODEL_ID '{self.llm_model_id}' is not in the approved-model allowlist."
                )
            if self.llm_max_cost_usd_per_run <= 0 and self.llm_max_total_tokens_per_run <= 0:
                raise ValueError(
                    "A spend cap is required for a real LLM provider: set "
                    "LLM_MAX_COST_USD_PER_RUN or LLM_MAX_TOTAL_TOKENS_PER_RUN > 0."
                )
        if self.batch_max_events <= 0 or self.batch_max_input_tokens <= 0:
            raise ValueError("BATCH_MAX_EVENTS and BATCH_MAX_INPUT_TOKENS must be greater than zero.")
        if self.semantic_firewall_enabled:
            # Supply-chain determinism (spec 32 §6): a moving tag is not allowed —
            # the model must be pinned by revision so the score is reproducible.
            if not self.semantic_firewall_model_revision.strip():
                raise ValueError(
                    "SEMANTIC_FIREWALL_MODEL_REVISION (pinned SHA) is required when "
                    "SEMANTIC_FIREWALL_ENABLED=true."
                )
            review = self.semantic_firewall_review_threshold
            quarantine = self.semantic_firewall_quarantine_threshold
            if not (0.0 < review <= quarantine <= 1.0):
                raise ValueError(
                    "Semantic firewall thresholds must satisfy "
                    "0 < SEMANTIC_FIREWALL_REVIEW_THRESHOLD <= "
                    "SEMANTIC_FIREWALL_QUARANTINE_THRESHOLD <= 1."
                )


def _parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _parse_int(value: str | None, default: int) -> int:
    if value is None or not value.strip():
        return default
    return int(value.strip())
