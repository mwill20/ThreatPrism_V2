from __future__ import annotations

import os
from dataclasses import dataclass

from threatprism.auth.production import (
    PRODUCTION_IDENTITY_AUTH_MODE,
    ProductionIdentityReadinessReport,
    evaluate_production_identity_readiness,
)


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


def _parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _parse_int(value: str | None, default: int) -> int:
    if value is None or not value.strip():
        return default
    return int(value.strip())
