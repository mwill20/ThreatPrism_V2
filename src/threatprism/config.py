from __future__ import annotations

import os
from dataclasses import dataclass


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
    llm_provider: str = "deterministic_demo"
    allow_real_actions: bool = False
    max_request_body_bytes: int = 262_144
    case_post_rate_limit_per_minute: int = 60
    triage_concurrency_limit: int = 4

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
            llm_provider=os.getenv("LLM_PROVIDER", "deterministic_demo"),
            allow_real_actions=_parse_bool(os.getenv("ALLOW_REAL_ACTIONS"), default=False),
            max_request_body_bytes=_parse_int(os.getenv("MAX_REQUEST_BODY_BYTES"), default=262_144),
            case_post_rate_limit_per_minute=_parse_int(
                os.getenv("CASE_POST_RATE_LIMIT_PER_MINUTE"), default=60
            ),
            triage_concurrency_limit=_parse_int(os.getenv("TRIAGE_CONCURRENCY_LIMIT"), default=4),
        )

    def validate_runtime(self) -> None:
        auth_mode = self.api_auth_mode.strip().lower()
        if self.env.strip().lower() in {"prod", "production"} and auth_mode in {"none", "demo_key"}:
            raise ValueError("Production environments cannot use disabled or demo API authentication.")
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


def _parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _parse_int(value: str | None, default: int) -> int:
    if value is None or not value.strip():
        return default
    return int(value.strip())
