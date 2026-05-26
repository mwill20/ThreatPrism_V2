from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal
from urllib.parse import urlparse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


PRODUCTION_IDENTITY_AUTH_MODE = "external_oidc"

ALLOWED_PRODUCTION_IDENTITY_PROVIDERS = {"oidc", "entra_oidc"}
SAFE_TOKEN_ALGORITHMS = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}
SUPPORTED_RUNTIME_TOKEN_ALGORITHMS = {"RS256", "RS384", "RS512"}
REQUIRED_ROLE_VIEWS = (
    "analyst",
    "engineer",
    "manager_grc",
    "legal_privacy",
    "audit_debug",
    "admin",
)

_CLAIM_NAME_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:-]{0,63}$")
_JWT_SEGMENT_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")
_HASH_ALGORITHMS = {
    "RS256": hashes.SHA256,
    "RS384": hashes.SHA384,
    "RS512": hashes.SHA512,
}


@dataclass(frozen=True)
class ProductionPrincipal:
    subject_hash: str
    issuer: str
    audience: str
    tenant_id_hash: str
    effective_role: str
    auth_mode: str
    provider: str
    algorithm: str
    kid_hash: str
    claim_mapping_version: str

    @property
    def audit_metadata(self) -> dict[str, object]:
        return {
            "auth_mode": self.auth_mode,
            "provider": self.provider,
            "verifier_decision": "allow",
            "verifier_reason": "production_token_verified",
            "issuer_match": True,
            "audience_match": True,
            "subject_hash": self.subject_hash,
            "tenant_id_hash": self.tenant_id_hash,
            "mapped_effective_role": self.effective_role,
            "algorithm": self.algorithm,
            "kid_hash": self.kid_hash,
            "claim_mapping_version": self.claim_mapping_version,
        }


class ProductionTokenVerificationError(Exception):
    def __init__(
        self,
        status_code: int,
        reason: str,
        audit_metadata: dict[str, object] | None = None,
    ) -> None:
        super().__init__(reason)
        self.status_code = status_code
        self.reason = reason
        self.audit_metadata = audit_metadata or {}


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
    allowed_tenants: tuple[str, ...]
    role_mappings: tuple[tuple[str, str], ...]
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
    allowed_tenants: str = "",
    role_mapping: str = "",
    jwks_json: str = "",
    jwks_fetch_enabled: bool = False,
    clock_skew_seconds: int = 60,
    max_token_bytes: int = 8192,
    claim_mapping_version: str = "local-demo-v1",
) -> ProductionIdentityReadinessReport:
    normalized_auth_mode = auth_mode.strip().lower()
    normalized_provider = provider.strip().lower()
    parsed_roles = _parse_csv(required_roles)
    parsed_algorithms = _parse_algorithms(allowed_algorithms)
    parsed_allowed_tenants = _parse_csv_case_sensitive(allowed_tenants)
    parsed_role_mapping = _parse_role_mapping(role_mapping)
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
        if jwks_fetch_enabled:
            findings.append(
                ProductionIdentityReadinessFinding(
                    check="jwks-fetch",
                    severity="error",
                    message="PRODUCTION_IDENTITY_JWKS_FETCH_ENABLED must stay false for safe local validation.",
                )
            )
        if not (set(parsed_algorithms) & SUPPORTED_RUNTIME_TOKEN_ALGORITHMS):
            findings.append(
                ProductionIdentityReadinessFinding(
                    check="algorithms",
                    severity="error",
                    message="The local verifier currently supports RS256, RS384, or RS512 only.",
                )
            )
        if not jwks_json.strip():
            findings.append(
                ProductionIdentityReadinessFinding(
                    check="local-jwks",
                    severity="error",
                    message="PRODUCTION_IDENTITY_JWKS_JSON must contain a local fake JWKS when verification is enabled.",
                )
            )
        else:
            try:
                _load_local_jwks(jwks_json)
            except ProductionTokenVerificationError:
                findings.append(
                    ProductionIdentityReadinessFinding(
                        check="local-jwks",
                        severity="error",
                        message="PRODUCTION_IDENTITY_JWKS_JSON must be a valid local JWKS document.",
                    )
                )
        if not parsed_allowed_tenants:
            findings.append(
                ProductionIdentityReadinessFinding(
                    check="allowed-tenants",
                    severity="error",
                    message="PRODUCTION_IDENTITY_ALLOWED_TENANTS must be configured when verification is enabled.",
                )
            )
        if not parsed_role_mapping:
            findings.append(
                ProductionIdentityReadinessFinding(
                    check="role-mapping",
                    severity="error",
                    message="PRODUCTION_IDENTITY_ROLE_MAPPING must map external roles or groups to ThreatPrism roles.",
                )
            )
        invalid_mappings = tuple(
            mapped_role
            for _, mapped_role in parsed_role_mapping
            if mapped_role not in REQUIRED_ROLE_VIEWS or mapped_role == "ai"
        )
        if invalid_mappings:
            findings.append(
                ProductionIdentityReadinessFinding(
                    check="role-mapping",
                    severity="error",
                    message="PRODUCTION_IDENTITY_ROLE_MAPPING must map only to external user roles.",
                )
            )
        if clock_skew_seconds < 0 or clock_skew_seconds > 300:
            findings.append(
                ProductionIdentityReadinessFinding(
                    check="clock-skew",
                    severity="error",
                    message="PRODUCTION_IDENTITY_CLOCK_SKEW_SECONDS must be between 0 and 300.",
                )
            )
        if max_token_bytes <= 0 or max_token_bytes > 32768:
            findings.append(
                ProductionIdentityReadinessFinding(
                    check="token-size",
                    severity="error",
                    message="PRODUCTION_IDENTITY_MAX_TOKEN_BYTES must be between 1 and 32768.",
                )
            )
        if not claim_mapping_version.strip():
            findings.append(
                ProductionIdentityReadinessFinding(
                    check="claim-mapping-version",
                    severity="error",
                    message="PRODUCTION_IDENTITY_CLAIM_MAPPING_VERSION must be configured.",
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
        allowed_tenants=parsed_allowed_tenants,
        role_mappings=parsed_role_mapping,
        findings=tuple(findings),
    )


def verify_production_bearer_token(
    token: str,
    *,
    settings: Any,
    now: datetime | None = None,
) -> ProductionPrincipal:
    if not settings.production_identity_live_verification_enabled:
        raise _verification_error(settings, 403, "verifier_not_enabled")

    token_bytes = token.encode("utf-8")
    if len(token_bytes) > settings.production_identity_max_token_bytes:
        raise _verification_error(settings, 401, "token_oversized")

    parts = token.split(".")
    if len(parts) != 3 or not all(parts):
        raise _verification_error(settings, 401, "malformed_token")
    if not all(_JWT_SEGMENT_PATTERN.match(part) for part in parts):
        raise _verification_error(settings, 401, "malformed_token")

    header = _decode_json_segment(parts[0], settings=settings, error_reason="malformed_header")
    algorithm = _string_claim(header, "alg")
    kid = _string_claim(header, "kid")
    if not algorithm or algorithm.lower() == "none":
        raise _verification_error(settings, 401, "unsupported_algorithm")
    if algorithm not in _parse_algorithms(settings.production_identity_allowed_algorithms):
        raise _verification_error(settings, 401, "unsupported_algorithm", algorithm=algorithm)
    if algorithm not in SUPPORTED_RUNTIME_TOKEN_ALGORITHMS:
        raise _verification_error(settings, 401, "unsupported_runtime_algorithm", algorithm=algorithm)
    if not kid:
        raise _verification_error(settings, 401, "missing_kid", algorithm=algorithm)
    token_type = _string_claim(header, "typ")
    if token_type and token_type != "JWT":
        raise _verification_error(settings, 401, "unexpected_token_type", algorithm=algorithm, kid=kid)

    jwks = _load_local_jwks(settings.production_identity_jwks_json)
    jwk = _find_jwk(jwks, kid=kid, algorithm=algorithm, settings=settings)
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    signature = _base64url_decode(parts[2], settings=settings, error_reason="malformed_signature")
    _verify_rsa_signature(
        jwk,
        algorithm=algorithm,
        signing_input=signing_input,
        signature=signature,
        settings=settings,
        kid=kid,
    )

    claims = _decode_json_segment(parts[1], settings=settings, error_reason="malformed_claims", kid=kid, algorithm=algorithm)
    current_time = now or datetime.now(UTC)
    _validate_standard_claims(claims, settings=settings, now=current_time, kid=kid, algorithm=algorithm)
    subject = _required_claim_string(
        claims,
        settings.production_identity_subject_claim,
        status_code=403,
        reason="missing_subject_claim",
        settings=settings,
        kid=kid,
        algorithm=algorithm,
    )
    tenant_id = _required_claim_string(
        claims,
        settings.production_identity_tenant_claim,
        status_code=403,
        reason="missing_tenant_claim",
        settings=settings,
        kid=kid,
        algorithm=algorithm,
    )
    allowed_tenants = set(_parse_csv_case_sensitive(settings.production_identity_allowed_tenants))
    if tenant_id not in allowed_tenants:
        raise _verification_error(settings, 403, "tenant_not_allowed", algorithm=algorithm, kid=kid)

    effective_role = _map_effective_role(
        claims,
        settings=settings,
        kid=kid,
        algorithm=algorithm,
    )
    return ProductionPrincipal(
        subject_hash=_hash_claim_value(subject, settings.production_identity_claim_mapping_version),
        issuer=settings.production_identity_issuer,
        audience=settings.production_identity_audience,
        tenant_id_hash=_hash_claim_value(tenant_id, settings.production_identity_claim_mapping_version),
        effective_role=effective_role,
        auth_mode=PRODUCTION_IDENTITY_AUTH_MODE,
        provider=settings.production_identity_provider,
        algorithm=algorithm,
        kid_hash=_hash_claim_value(kid, settings.production_identity_claim_mapping_version),
        claim_mapping_version=settings.production_identity_claim_mapping_version,
    )


def _parse_csv(value: str) -> tuple[str, ...]:
    return tuple(part.strip().lower() for part in value.split(",") if part.strip())


def _parse_csv_case_sensitive(value: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in value.split(",") if part.strip())


def _parse_algorithms(value: str) -> tuple[str, ...]:
    return tuple(part.strip().upper() for part in value.split(",") if part.strip())


def _parse_role_mapping(value: str) -> tuple[tuple[str, str], ...]:
    entries: list[tuple[str, str]] = []
    for raw_entry in value.split(","):
        entry = raw_entry.strip()
        if not entry:
            continue
        if ":" not in entry:
            continue
        external_role, mapped_role = [part.strip() for part in entry.split(":", 1)]
        if external_role and mapped_role:
            entries.append((external_role, mapped_role))
    return tuple(entries)


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


def _verification_error(
    settings: Any,
    status_code: int,
    reason: str,
    *,
    algorithm: str | None = None,
    kid: str | None = None,
    issuer_match: bool | None = None,
    audience_match: bool | None = None,
) -> ProductionTokenVerificationError:
    metadata: dict[str, object] = {
        "auth_mode": PRODUCTION_IDENTITY_AUTH_MODE,
        "provider": settings.production_identity_provider,
        "verifier_decision": "deny",
        "verifier_reason": reason,
        "claim_mapping_version": settings.production_identity_claim_mapping_version,
    }
    if algorithm:
        metadata["algorithm"] = algorithm
    if kid:
        metadata["kid_hash"] = _hash_claim_value(kid, settings.production_identity_claim_mapping_version)
    if issuer_match is not None:
        metadata["issuer_match"] = issuer_match
    if audience_match is not None:
        metadata["audience_match"] = audience_match
    return ProductionTokenVerificationError(status_code, reason, metadata)


def _decode_json_segment(
    segment: str,
    *,
    settings: Any,
    error_reason: str,
    kid: str | None = None,
    algorithm: str | None = None,
) -> dict[str, Any]:
    try:
        payload = _base64url_decode(segment, settings=settings, error_reason=error_reason)
        loaded = json.loads(payload.decode("utf-8"), object_pairs_hook=_reject_duplicate_json_fields)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise _verification_error(settings, 401, error_reason, algorithm=algorithm, kid=kid) from exc
    if not isinstance(loaded, dict):
        raise _verification_error(settings, 401, error_reason, algorithm=algorithm, kid=kid)
    return loaded


def _reject_duplicate_json_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError(f"Duplicate JSON field: {key}")
        output[key] = value
    return output


def _base64url_decode(
    value: str,
    *,
    settings: Any,
    error_reason: str,
) -> bytes:
    try:
        padded = value + "=" * (-len(value) % 4)
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, UnicodeEncodeError) as exc:
        raise _verification_error(settings, 401, error_reason) from exc


def _load_local_jwks(value: str) -> dict[str, Any]:
    try:
        jwks = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ProductionTokenVerificationError(403, "invalid_local_jwks") from exc
    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
        raise ProductionTokenVerificationError(403, "invalid_local_jwks")
    return jwks


def _find_jwk(jwks: dict[str, Any], *, kid: str, algorithm: str, settings: Any) -> dict[str, Any]:
    matches = [key for key in jwks["keys"] if isinstance(key, dict) and key.get("kid") == kid]
    if not matches:
        raise _verification_error(settings, 401, "unknown_kid", algorithm=algorithm, kid=kid)
    if len(matches) > 1:
        raise _verification_error(settings, 401, "duplicate_kid", algorithm=algorithm, kid=kid)
    jwk = matches[0]
    if jwk.get("kty") != "RSA":
        raise _verification_error(settings, 401, "unsupported_key_type", algorithm=algorithm, kid=kid)
    key_algorithm = jwk.get("alg")
    if key_algorithm and key_algorithm != algorithm:
        raise _verification_error(settings, 401, "key_algorithm_mismatch", algorithm=algorithm, kid=kid)
    return jwk


def _verify_rsa_signature(
    jwk: dict[str, Any],
    *,
    algorithm: str,
    signing_input: bytes,
    signature: bytes,
    settings: Any,
    kid: str,
) -> None:
    try:
        modulus = int.from_bytes(
            _base64url_decode(str(jwk["n"]), settings=settings, error_reason="invalid_jwk_modulus"),
            "big",
        )
        exponent = int.from_bytes(
            _base64url_decode(str(jwk["e"]), settings=settings, error_reason="invalid_jwk_exponent"),
            "big",
        )
        public_key = rsa.RSAPublicNumbers(exponent, modulus).public_key()
        public_key.verify(
            signature,
            signing_input,
            padding.PKCS1v15(),
            _HASH_ALGORITHMS[algorithm](),
        )
    except (InvalidSignature, KeyError, ValueError) as exc:
        raise _verification_error(settings, 401, "bad_signature", algorithm=algorithm, kid=kid) from exc


def _validate_standard_claims(
    claims: dict[str, Any],
    *,
    settings: Any,
    now: datetime,
    kid: str,
    algorithm: str,
) -> None:
    issuer = _required_claim_string(
        claims,
        "iss",
        status_code=401,
        reason="missing_issuer_claim",
        settings=settings,
        kid=kid,
        algorithm=algorithm,
    )
    if issuer != settings.production_identity_issuer:
        raise _verification_error(
            settings,
            401,
            "issuer_mismatch",
            algorithm=algorithm,
            kid=kid,
            issuer_match=False,
        )
    if not _audience_matches(claims.get("aud"), settings.production_identity_audience):
        raise _verification_error(
            settings,
            401,
            "audience_mismatch",
            algorithm=algorithm,
            kid=kid,
            issuer_match=True,
            audience_match=False,
        )
    current_timestamp = int(now.timestamp())
    skew = settings.production_identity_clock_skew_seconds
    exp = _required_numeric_date(
        claims,
        "exp",
        status_code=401,
        reason="missing_expiration_claim",
        settings=settings,
        kid=kid,
        algorithm=algorithm,
    )
    if current_timestamp > exp + skew:
        raise _verification_error(settings, 401, "token_expired", algorithm=algorithm, kid=kid)
    iat = _required_numeric_date(
        claims,
        "iat",
        status_code=401,
        reason="missing_issued_at_claim",
        settings=settings,
        kid=kid,
        algorithm=algorithm,
    )
    if iat > current_timestamp + skew:
        raise _verification_error(settings, 401, "issued_at_in_future", algorithm=algorithm, kid=kid)
    nbf = claims.get("nbf")
    if nbf is not None:
        nbf_value = _numeric_date_value(
            nbf,
            status_code=401,
            reason="invalid_not_before_claim",
            settings=settings,
            kid=kid,
            algorithm=algorithm,
        )
        if current_timestamp + skew < nbf_value:
            raise _verification_error(settings, 401, "token_not_yet_valid", algorithm=algorithm, kid=kid)


def _required_claim_string(
    claims: dict[str, Any],
    name: str,
    *,
    status_code: int,
    reason: str,
    settings: Any,
    kid: str,
    algorithm: str,
) -> str:
    value = claims.get(name)
    if not isinstance(value, str) or not value.strip():
        raise _verification_error(settings, status_code, reason, algorithm=algorithm, kid=kid)
    return value.strip()


def _required_numeric_date(
    claims: dict[str, Any],
    name: str,
    *,
    status_code: int,
    reason: str,
    settings: Any,
    kid: str,
    algorithm: str,
) -> int:
    value = claims.get(name)
    if value is None:
        raise _verification_error(settings, status_code, reason, algorithm=algorithm, kid=kid)
    return _numeric_date_value(
        value,
        status_code=status_code,
        reason=reason,
        settings=settings,
        kid=kid,
        algorithm=algorithm,
    )


def _numeric_date_value(
    value: Any,
    *,
    status_code: int,
    reason: str,
    settings: Any,
    kid: str,
    algorithm: str,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise _verification_error(settings, status_code, reason, algorithm=algorithm, kid=kid)
    return int(value)


def _audience_matches(value: Any, expected: str) -> bool:
    if isinstance(value, str):
        return value == expected
    if isinstance(value, list):
        return any(isinstance(item, str) and item == expected for item in value)
    return False


def _string_claim(values: dict[str, Any], name: str) -> str | None:
    value = values.get(name)
    if isinstance(value, str):
        return value.strip() or None
    return None


def _map_effective_role(
    claims: dict[str, Any],
    *,
    settings: Any,
    kid: str,
    algorithm: str,
) -> str:
    role_values = _claim_values(claims.get(settings.production_identity_roles_claim))
    if not role_values:
        raise _verification_error(settings, 403, "missing_role_claim", algorithm=algorithm, kid=kid)
    role_mapping = dict(_parse_role_mapping(settings.production_identity_role_mapping))
    mapped_roles = {role_mapping[value] for value in role_values if value in role_mapping}
    if not mapped_roles:
        raise _verification_error(settings, 403, "unmapped_role", algorithm=algorithm, kid=kid)
    if len(mapped_roles) > 1:
        raise _verification_error(settings, 403, "conflicting_roles", algorithm=algorithm, kid=kid)
    effective_role = next(iter(mapped_roles))
    if effective_role not in REQUIRED_ROLE_VIEWS or effective_role == "ai":
        raise _verification_error(settings, 403, "invalid_effective_role", algorithm=algorithm, kid=kid)
    return effective_role


def _claim_values(value: Any) -> tuple[str, ...]:
    if isinstance(value, str) and value.strip():
        return (value.strip(),)
    if isinstance(value, list):
        return tuple(item.strip() for item in value if isinstance(item, str) and item.strip())
    return ()


def _hash_claim_value(value: str, key: str) -> str:
    digest = hmac.new(key.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"hmac-sha256:{digest}"
