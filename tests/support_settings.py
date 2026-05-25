from __future__ import annotations

from threatprism.config import Settings


DEMO_API_KEYS = (
    "demo-analyst-key:demo_analyst:analyst,"
    "demo-engineer-key:demo_engineer:engineer,"
    "demo-manager-key:demo_manager:manager_grc,"
    "demo-legal-key:demo_legal:legal_privacy,"
    "demo-audit-key:demo_audit:audit_debug,"
    "demo-admin-key:demo_admin:admin"
)


def local_auth_disabled_settings(**overrides: object) -> Settings:
    values = {
        "env": "test",
        "database_url": "sqlite:///:memory:",
        "api_auth_mode": "none",
        "auth_required": False,
        "local_dev_ack": True,
        "llm_provider": "deterministic_demo",
        "allow_real_actions": False,
    }
    values.update(overrides)
    return Settings(**values)


def demo_key_settings(**overrides: object) -> Settings:
    values = {
        "env": "test",
        "database_url": "sqlite:///:memory:",
        "api_auth_mode": "demo_key",
        "demo_api_keys": DEMO_API_KEYS,
        "llm_provider": "deterministic_demo",
        "allow_real_actions": False,
    }
    values.update(overrides)
    return Settings(**values)
