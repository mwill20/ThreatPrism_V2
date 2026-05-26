from __future__ import annotations

import base64
import json
import socket
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import FastAPI
from fastapi.testclient import TestClient

from threatprism.api.app import create_app
from threatprism.auth.production import (
    PRODUCTION_IDENTITY_AUTH_MODE,
    ProductionTokenVerificationError,
    verify_production_bearer_token,
)
from threatprism.config import Settings


FAKE_ISSUER = "https://idp.example.com/tenant/v2.0"
FAKE_AUDIENCE = "api://threatprism-demo"
FAKE_JWKS_URI = "https://idp.example.com/tenant/discovery/v2.0/keys"
FAKE_KID = "fake-local-rsa-key"
FAKE_SUBJECT = "fake-subject-analyst-001"
FAKE_TENANT = "tenant_demo_alpha"
FAKE_GROUP_ANALYST = "demo_analysts"
FAKE_GROUP_MANAGER = "demo_managers"
FIXED_NOW = datetime(2026, 5, 26, 12, 0, 0, tzinfo=UTC)
FUTURE_EXP = 4_102_444_800
STABLE_IAT = 1_700_000_000


def _fixture() -> tuple[rsa.RSAPrivateKey, Settings]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwks_json = json.dumps({"keys": [_jwk_from_public_key(private_key.public_key())]}, sort_keys=True)
    settings = Settings(
        env="production",
        database_url="sqlite:///:memory:",
        api_auth_mode=PRODUCTION_IDENTITY_AUTH_MODE,
        allow_real_actions=False,
        production_identity_provider="entra_oidc",
        production_identity_issuer=FAKE_ISSUER,
        production_identity_audience=FAKE_AUDIENCE,
        production_identity_jwks_uri=FAKE_JWKS_URI,
        production_identity_subject_claim="sub",
        production_identity_roles_claim="roles",
        production_identity_tenant_claim="tid",
        production_identity_required_roles="analyst,engineer,manager_grc,legal_privacy,audit_debug,admin",
        production_identity_allowed_algorithms="RS256",
        production_identity_live_verification_enabled=True,
        production_identity_allowed_tenants=FAKE_TENANT,
        production_identity_role_mapping=(
            f"{FAKE_GROUP_ANALYST}:analyst,{FAKE_GROUP_MANAGER}:manager_grc"
        ),
        production_identity_jwks_json=jwks_json,
        production_identity_jwks_fetch_enabled=False,
        production_identity_clock_skew_seconds=60,
        production_identity_max_token_bytes=8192,
        production_identity_claim_mapping_version="local-demo-v1",
    )
    return private_key, settings


def _claims(**overrides: Any) -> dict[str, Any]:
    claims: dict[str, Any] = {
        "iss": FAKE_ISSUER,
        "aud": FAKE_AUDIENCE,
        "sub": FAKE_SUBJECT,
        "tid": FAKE_TENANT,
        "roles": [FAKE_GROUP_ANALYST],
        "iat": STABLE_IAT,
        "nbf": STABLE_IAT,
        "exp": FUTURE_EXP,
    }
    claims.update(overrides)
    return claims


def _sign_token(
    private_key: rsa.RSAPrivateKey,
    claims: dict[str, Any],
    *,
    header_overrides: dict[str, Any] | None = None,
) -> str:
    header = {"alg": "RS256", "typ": "JWT", "kid": FAKE_KID}
    header.update(header_overrides or {})
    signing_input = b".".join([_b64_json(header), _b64_json(claims)])
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return ".".join(
        [
            signing_input.decode("ascii"),
            _b64_bytes(signature).decode("ascii"),
        ]
    )


def _jwk_from_public_key(public_key: rsa.RSAPublicKey) -> dict[str, str]:
    numbers = public_key.public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "kid": FAKE_KID,
        "alg": "RS256",
        "n": _b64_int(numbers.n),
        "e": _b64_int(numbers.e),
    }


def _b64_json(payload: dict[str, Any]) -> bytes:
    return _b64_bytes(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _b64_int(value: int) -> str:
    length = max(1, (value.bit_length() + 7) // 8)
    return _b64_bytes(value.to_bytes(length, "big")).decode("ascii")


def _b64_bytes(value: bytes) -> bytes:
    return base64.urlsafe_b64encode(value).rstrip(b"=")


def _create_case(client: TestClient) -> str:
    payload = json.loads(Path("examples/soar_payloads/generic_soar_case.json").read_text())
    response = client.post("/cases", json=payload)
    assert response.status_code == 202
    return str(response.json()["case_id"])


def _auth_events(app: FastAPI, case_id: str) -> list[Any]:
    case = app.state.case_service.get_case(case_id)
    assert case is not None
    return [event for event in case.audit_trail if event.event_type == "authorization_decision"]


def _assert_verifier_error(
    token: str,
    settings: Settings,
    *,
    status_code: int,
    reason: str,
    now: datetime = FIXED_NOW,
) -> None:
    with pytest.raises(ProductionTokenVerificationError) as exc:
        verify_production_bearer_token(token, settings=settings, now=now)
    assert exc.value.status_code == status_code
    assert exc.value.reason == reason
    serialized = json.dumps(exc.value.audit_metadata, sort_keys=True)
    assert FAKE_SUBJECT not in serialized
    assert FAKE_TENANT not in serialized
    assert FAKE_GROUP_ANALYST not in serialized


def test_valid_local_jwks_token_maps_verified_claims_to_production_principal() -> None:
    private_key, settings = _fixture()
    token = _sign_token(private_key, _claims())

    principal = verify_production_bearer_token(token, settings=settings, now=FIXED_NOW)

    assert principal.auth_mode == PRODUCTION_IDENTITY_AUTH_MODE
    assert principal.effective_role == "analyst"
    assert principal.subject_hash.startswith("hmac-sha256:")
    assert principal.tenant_id_hash.startswith("hmac-sha256:")
    assert principal.kid_hash.startswith("hmac-sha256:")
    assert principal.algorithm == "RS256"
    serialized = json.dumps(principal.audit_metadata, sort_keys=True)
    assert FAKE_SUBJECT not in serialized
    assert FAKE_TENANT not in serialized
    assert FAKE_GROUP_ANALYST not in serialized


def test_token_shape_algorithm_and_size_fail_closed() -> None:
    private_key, settings = _fixture()

    _assert_verifier_error("not-a-jwt", settings, status_code=401, reason="malformed_token")
    _assert_verifier_error(
        _sign_token(private_key, _claims(), header_overrides={"alg": "none"}),
        settings,
        status_code=401,
        reason="unsupported_algorithm",
    )
    _assert_verifier_error(
        _sign_token(private_key, _claims(), header_overrides={"alg": "HS256"}),
        settings,
        status_code=401,
        reason="unsupported_algorithm",
    )

    tiny_limit_settings = Settings(**{**settings.__dict__, "production_identity_max_token_bytes": 8})
    _assert_verifier_error(
        _sign_token(private_key, _claims()),
        tiny_limit_settings,
        status_code=401,
        reason="token_oversized",
    )


def test_kid_and_signature_failures_fail_closed() -> None:
    private_key, settings = _fixture()

    _assert_verifier_error(
        _sign_token(private_key, _claims(), header_overrides={"kid": ""}),
        settings,
        status_code=401,
        reason="missing_kid",
    )
    _assert_verifier_error(
        _sign_token(private_key, _claims(), header_overrides={"kid": "unknown-key"}),
        settings,
        status_code=401,
        reason="unknown_kid",
    )
    token_parts = _sign_token(private_key, _claims()).split(".")
    token_parts[2] = _b64_bytes(b"bad-signature").decode("ascii")
    _assert_verifier_error(
        ".".join(token_parts),
        settings,
        status_code=401,
        reason="bad_signature",
    )


def test_issuer_audience_and_time_claims_fail_closed() -> None:
    private_key, settings = _fixture()

    _assert_verifier_error(
        _sign_token(private_key, _claims(iss="https://idp.example.com/wrong/v2.0")),
        settings,
        status_code=401,
        reason="issuer_mismatch",
    )
    _assert_verifier_error(
        _sign_token(private_key, _claims(aud="api://wrong-audience")),
        settings,
        status_code=401,
        reason="audience_mismatch",
    )
    _assert_verifier_error(
        _sign_token(private_key, _claims(exp=1_700_000_000)),
        settings,
        status_code=401,
        reason="token_expired",
    )
    _assert_verifier_error(
        _sign_token(private_key, _claims(nbf=4_102_444_800)),
        settings,
        status_code=401,
        reason="token_not_yet_valid",
    )
    _assert_verifier_error(
        _sign_token(private_key, _claims(iat=4_102_444_800)),
        settings,
        status_code=401,
        reason="issued_at_in_future",
    )


def test_subject_tenant_and_role_claim_mapping_fail_closed() -> None:
    private_key, settings = _fixture()

    no_subject = _claims()
    del no_subject["sub"]
    _assert_verifier_error(
        _sign_token(private_key, no_subject),
        settings,
        status_code=403,
        reason="missing_subject_claim",
    )

    no_tenant = _claims()
    del no_tenant["tid"]
    _assert_verifier_error(
        _sign_token(private_key, no_tenant),
        settings,
        status_code=403,
        reason="missing_tenant_claim",
    )

    no_role = _claims()
    del no_role["roles"]
    _assert_verifier_error(
        _sign_token(private_key, no_role),
        settings,
        status_code=403,
        reason="missing_role_claim",
    )

    _assert_verifier_error(
        _sign_token(private_key, _claims(tid="tenant_demo_beta")),
        settings,
        status_code=403,
        reason="tenant_not_allowed",
    )
    _assert_verifier_error(
        _sign_token(private_key, _claims(roles=["unknown_group"])),
        settings,
        status_code=403,
        reason="unmapped_role",
    )
    _assert_verifier_error(
        _sign_token(private_key, _claims(roles=[FAKE_GROUP_ANALYST, FAKE_GROUP_MANAGER])),
        settings,
        status_code=403,
        reason="conflicting_roles",
    )


def test_external_oidc_route_accepts_verified_local_token() -> None:
    private_key, settings = _fixture()
    client = TestClient(create_app(settings))
    token = _sign_token(private_key, _claims())

    response = client.get("/metrics", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    assert response.json()["case_counts"]["total"] == 0


def test_external_oidc_role_view_escalation_fails_closed_and_audit_is_sanitized() -> None:
    private_key, settings = _fixture()
    app = create_app(settings)
    client = TestClient(app)
    case_id = _create_case(client)
    token = _sign_token(private_key, _claims(roles=[FAKE_GROUP_MANAGER]))

    response = client.get(
        f"/cases/{case_id}?role=analyst",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Requested role view is not allowed for this caller."
    event = _auth_events(app, case_id)[-1]
    assert event.metadata["decision"] == "deny"
    assert event.metadata["reason"] == "role_view_not_allowed"
    assert event.metadata["effective_role"] == "manager_grc"
    assert event.metadata["mapped_effective_role"] == "manager_grc"
    serialized = json.dumps(event.model_dump(mode="json"), sort_keys=True)
    assert token not in serialized
    assert "Bearer " not in serialized
    assert FAKE_SUBJECT not in serialized
    assert FAKE_TENANT not in serialized
    assert FAKE_GROUP_MANAGER not in serialized


def test_local_verifier_does_not_attempt_network(monkeypatch: pytest.MonkeyPatch) -> None:
    private_key, settings = _fixture()
    token = _sign_token(private_key, _claims())
    blocked_calls: list[tuple[object, ...]] = []

    def blocked_socket(*args: object, **kwargs: object) -> socket.socket:
        blocked_calls.append(args)
        raise AssertionError("network calls are not allowed")

    monkeypatch.setattr(socket, "socket", blocked_socket)

    principal = verify_production_bearer_token(token, settings=settings, now=FIXED_NOW)

    assert principal.effective_role == "analyst"
    assert blocked_calls == []
