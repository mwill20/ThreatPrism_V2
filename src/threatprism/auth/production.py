from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlparse


PRODUCTION_IDENTITY_AUTH_MODE = "external_oidc"

ALLOWED_PRODUCTION_IDENTITY_PROVIDERS = {"oidc", "entra_oidc"}
SAFE_TOKEN_ALGORITHMS = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}
REQUIRED_ROLE_VIEWS = (
    "analyst",
    "engineer",
    "manager_grc",
    "legal_privacy",
    "audit_debug",
    "admin",
)

_CLAIM_NAME_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:-]{0,63}$")


@dataclass(frozen=True)
class ProductionIdentityReadinessFinding:
    check: str
    severity: Literal["error", "warning"]
    message: str


@dataclass(frozen=True)
class ProductionIdentityReadinessReport:
    auth_mode: str
    provider: str
    ready_for_token_verifier: bool
    live_verification_enabled: bool
    required_roles: tuple[str, ...]
    allowed_algorithms: tuple[str, ...]
    findings: tuple[ProductionIdentityReadinessFinding, ...]

    @property
    def errors(self) -> tuple[ProductionIdentityReadinessFinding, ...]:
        return tuple(finding for finding in self.findings if finding.severity == "error")

    def require_static_ready(self) -> None:
        if self.errors:
            summary = "; ".join(finding.message for finding in self.errors)
            raise ValueError(f"Production identity readiness failed: {summary}")


def evaluate_production_identity_readiness(
    *,
    auth_mode: str,
    provider: str,
    issuer: str,
    audience: str,
    jwks_uri: str,
    subject_claim: str,
    roles_claim: str,
    tenant_claim: str,
    required_roles: str,
    allowed_algorithms: str,
    live_verification_enabled: bool,
) -> ProductionIdentityReadinessReport:
    normalized_auth_mode = auth_mode.strip().lower()
    normalized_provider = provider.strip().lower()
    parsed_roles = _parse_csv(required_roles)
    parsed_algorithms = _parse_algorithms(allowed_algorithms)
    findings: list[ProductionIdentityReadinessFinding] = []

    if normalized_auth_mode != PRODUCTION_IDENTITY_AUTH_MODE:
        findings.append(
            ProductionIdentityReadinessFinding(
                check="auth-mode",
                severity="error",
                message=f"API_AUTH_MODE must be {PRODUCTION_IDENTITY_AUTH_MODE} for production identity readiness.",
            )
        )

    if normalized_provider not in ALLOWED_PRODUCTION_IDENTITY_PROVIDERS:
        findings.append(
            ProductionIdentityReadinessFinding(
                check="provider",
                severity="error",
                message="PRODUCTION_IDENTITY_PROVIDER must be oidc or entra_oidc.",
            )
        )

    _require_https_url(findings, "issuer", "PRODUCTION_IDENTITY_ISSUER", issuer)
    _require_https_url(findings, "jwks-uri", "PRODUCTION_IDENTITY_JWKS_URI", jwks_uri)

    if not audience.strip():
        findings.append(
            ProductionIdentityReadinessFinding(
                check="audience",
                severity="error",
                message="PRODUCTION_IDENTITY_AUDIENCE must be configured.",
            )
        )

    for check, env_name, claim_name in (
        ("subject-claim", "PRODUCTION_IDENTITY_SUBJECT_CLAIM", subject_claim),
        ("roles-claim", "PRODUCTION_IDENTITY_ROLES_CLAIM", roles_claim),
        ("tenant-claim", "PRODUCTION_IDENTITY_TENANT_CLAIM", tenant_claim),
    ):
        if not _CLAIM_NAME_PATTERN.match(claim_name.strip()):
            findings.append(
                ProductionIdentityReadinessFinding(
                    check=check,
                    severity="error",
                    message=f"{env_name} must be a simple claim name.",
                )
            )

    missing_roles = tuple(role for role in REQUIRED_ROLE_VIEWS if role not in parsed_roles)
    if missing_roles:
        findings.append(
            ProductionIdentityReadinessFinding(
                check="required-roles",
                severity="error",
                message="PRODUCTION_IDENTITY_REQUIRED_ROLES must include every dashboard/API role view.",
            )
        )

    if not parsed_algorithms:
        findings.append(
            ProductionIdentityReadinessFinding(
                check="algorithms",
                severity="error",
                message="PRODUCTION_IDENTITY_ALLOWED_ALGORITHMS must include at least one asymmetric algorithm.",
            )
        )
    unsafe_algorithms = tuple(algorithm for algorithm in parsed_algorithms if algorithm not in SAFE_TOKEN_ALGORITHMS)
    if unsafe_algorithms:
        findings.append(
            ProductionIdentityReadinessFinding(
                check="algorithms",
                severity="error",
                message="PRODUCTION_IDENTITY_ALLOWED_ALGORITHMS must use approved asymmetric algorithms only.",
            )
        )

    if live_verification_enabled:
        findings.append(
            ProductionIdentityReadinessFinding(
                check="live-verifier",
                severity="error",
                message="Live production token verification is not implemented in this readiness slice.",
            )
        )
    else:
        findings.append(
            ProductionIdentityReadinessFinding(
                check="live-verifier",
                severity="warning",
                message="Production token verification remains a future explicit slice; protected requests fail closed.",
            )
        )

    errors = tuple(finding for finding in findings if finding.severity == "error")
    return ProductionIdentityReadinessReport(
        auth_mode=normalized_auth_mode,
        provider=normalized_provider,
        ready_for_token_verifier=not errors,
        live_verification_enabled=live_verification_enabled,
        required_roles=parsed_roles,
        allowed_algorithms=parsed_algorithms,
        findings=tuple(findings),
    )


def _parse_csv(value: str) -> tuple[str, ...]:
    return tuple(part.strip().lower() for part in value.split(",") if part.strip())


def _parse_algorithms(value: str) -> tuple[str, ...]:
    return tuple(part.strip().upper() for part in value.split(",") if part.strip())


def _require_https_url(
    findings: list[ProductionIdentityReadinessFinding],
    check: str,
    env_name: str,
    value: str,
) -> None:
    parsed = urlparse(value.strip())
    if parsed.scheme != "https" or not parsed.netloc:
        findings.append(
            ProductionIdentityReadinessFinding(
                check=check,
                severity="error",
                message=f"{env_name} must be an https URL.",
            )
        )
