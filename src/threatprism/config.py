from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    env: str = "demo"
    database_url: str = "sqlite:///./data/threatprism.db"
    api_auth_mode: str = "none"
    api_token: str | None = None
    llm_provider: str = "deterministic_demo"
    allow_real_actions: bool = False

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            env=os.getenv("THREATPRISM_ENV", "demo"),
            database_url=os.getenv("DATABASE_URL", "sqlite:///./data/threatprism.db"),
            api_auth_mode=os.getenv("API_AUTH_MODE", "none"),
            api_token=os.getenv("API_TOKEN") or None,
            llm_provider=os.getenv("LLM_PROVIDER", "deterministic_demo"),
            allow_real_actions=_parse_bool(os.getenv("ALLOW_REAL_ACTIONS"), default=False),
        )


def _parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}
