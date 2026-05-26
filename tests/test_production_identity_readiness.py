from __future__ import annotations

import logging

import pytest
from fastapi.testclient import TestClient

from threatprism.api.app import create_app
from threatprism.auth.production import (
    PRODUCTION_IDENTITY_AUTH_MODE,
    evaluate_production_identity_readiness,
)
from threatprism.config import Settings


FAKE_LOCAL_JWKS = '{"keys":[{"kty":"RSA","kid":"fake-local-key","alg":"RS256","n":"AQAB","e":"AQAB"}]}'


def _production_identity_settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "env": "production",
        "database_url": "sqlite:///:memory:",
        "api_auth_mode": PRODUCTION_IDENTITY_AUTH_MODE,
        "production_identity_provider": "entra_oidc",
        "production_identity_issuer": "https://idp.example.com/tenant/v2.0",
        "production_identity_audience": "api://threatprism-demo",
        "production_identity_jwks_uri": "https://idp.example.com/tenant/discovery/v2.0/keys",
        "production_identity_subject_claim": "sub",
        "production_identity_roles_claim": "roles",
        "production_identity_tenant_claim": "tid",
        "production_identity_required_roles": (
            "analyst,engineer,manager_grc,legal_privacy,audit_debug,admin"
        ),
        "production_identity_allowed_algorithms": "RS256",
        "production_identity_live_verification_enabled": False,
        "production_identity_allowed_tenants": "",
        "production_identity_role_mapping": "",
        "production_identity_jwks_json": "",
        "production_identity_jwks_fetch_enabled": False,
        "production_identity_clock_skew_seconds": 60,
        "production_identity_max_token_bytes": 8192,
        "production_identity_claim_mapping_version": "local-demo-v1",
        "allow_real_actions": False,
    }
    values.update(overrides)
    return Settings(**values)


def test_production_identity_static_readiness_passes_for_fake_oidc_config() -> None:
    settings = _production_identity_settings()

    settings.validate_runtime()
    report = settings.production_identity_readiness()

    assert report.ready_for_token_verifier is True
    assert report.live_verification_enabled is False
    assert report.required_roles == (
        "analyst",
        "engineer",
        "manager_grc",
        "legal_privacy",
        "audit_debug",
        "admin",
    )
    assert any(finding.check == "live-verifier" and finding.severity == "warning" for finding in report.findings)


def test_production_identity_rejects_missing_static_config() -> None:
    settings = _production_identity_settings(
        production_identity_provider="",
        production_identity_issuer="",
        production_identity_jwks_uri="",
        production_identity_audience="",
    )

    with pytest.raises(ValueError, match="Production identity readiness failed"):
        settings.validate_runtime()


def test_production_identity_rejects_verifier_enablement_without_local_config() -> None:
    settings = _production_identity_settings(production_identity_live_verification_enabled=True)

    with pytest.raises(ValueError, match="PRODUCTION_IDENTITY_JWKS_JSON"):
        settings.validate_runtime()


def test_production_identity_allows_local_no_network_verifier_config() -> None:
    settings = _production_identity_settings(
        production_identity_live_verification_enabled=True,
        production_identity_allowed_tenants="tenant_demo_alpha",
        production_identity_role_mapping="demo_analysts:analyst,demo_engineers:engineer",
        production_identity_jwks_json=FAKE_LOCAL_JWKS,
    )

    settings.validate_runtime()
    report = settings.production_identity_readiness()

    assert report.ready_for_token_verifier is True
    assert report.live_verification_enabled is True
    assert report.allowed_tenants == ("tenant_demo_alpha",)
    assert report.role_mappings == (
        ("demo_analysts", "analyst"),
        ("demo_engineers", "engineer"),
    )
    assert not report.errors


def test_production_identity_rejects_jwks_fetch_enablement() -> None:
    settings = _production_identity_settings(
        production_identity_live_verification_enabled=True,
        production_identity_allowed_tenants="tenant_demo_alpha",
        production_identity_role_mapping="demo_analysts:analyst",
        production_identity_jwks_json=FAKE_LOCAL_JWKS,
        production_identity_jwks_fetch_enabled=True,
    )

    with pytest.raises(ValueError, match="JWKS_FETCH_ENABLED"):
        settings.validate_runtime()


def test_production_identity_rejects_unsafe_algorithms() -> None:
    settings = _production_identity_settings(production_identity_allowed_algorithms="HS256")

    with pytest.raises(ValueError, match="approved asymmetric algorithms"):
        settings.validate_runtime()


def test_unknown_api_auth_mode_fails_startup() -> None:
    with pytest.raises(ValueError, match="Unsupported API_AUTH_MODE"):
        Settings(env="test", api_auth_mode="mystery_auth").validate_runtime()


def test_external_oidc_mode_fails_closed_on_protected_routes(caplog) -> None:
    caplog.set_level(logging.WARNING)
    app = create_app(_production_identity_settings())
    client = TestClient(app)

    response = client.get("/metrics", headers={"Authorization": "Bearer fake-demo-token"})

    assert response.status_code == 403
    assert response.json()["detail"] == "Production token is not authorized for this request."
    assert "protected requests fail closed" in caplog.text


def test_readiness_evaluator_does_not_expose_secret_or_network_fields() -> None:
    report = evaluate_production_identity_readiness(
        auth_mode=PRODUCTION_IDENTITY_AUTH_MODE,
        provider="oidc",
        issuer="https://idp.example.com/oauth2/default",
        audience="api://threatprism-demo",
        jwks_uri="https://idp.example.com/oauth2/default/keys",
        subject_claim="sub",
        roles_claim="roles",
        tenant_claim="tenant_id",
        required_roles="analyst,engineer,manager_grc,legal_privacy,audit_debug,admin",
        allowed_algorithms="RS256",
        live_verification_enabled=False,
    )

    serialized = repr(report)

    assert report.ready_for_token_verifier is True
    assert "client_secret" not in serialized.lower()
    assert "password" not in serialized.lower()
    assert "private_key" not in serialized.lower()
