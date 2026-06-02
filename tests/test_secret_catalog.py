"""Spec 34 §3: product runtime secret detectors and the standalone dev-workflow
hook must derive from a single shared secret-pattern catalog so they stay in sync
under one quarterly refresh.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

from threatprism.guardrails import secret_catalog
from threatprism.guardrails.healthcare import SECRET_RULES
from threatprism.guardrails.tokenization import TOKEN_PATTERNS

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_hook_common():
    """Load the standalone hook helper by file path (no `threatprism` import),
    the same way Claude Code runs the hooks."""
    path = REPO_ROOT / "tools" / "hooks" / "_common.py"
    spec = importlib.util.spec_from_file_location("_tp_hook_common_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _name_regex_map(patterns) -> dict[str, str]:
    return {name: pattern.pattern for name, pattern in patterns}


def test_dev_hook_and_product_share_one_catalog() -> None:
    hook = _load_hook_common()
    assert _name_regex_map(hook.SECRET_PATTERNS) == _name_regex_map(secret_catalog.SECRET_PATTERNS)


def test_tokenization_secret_like_sources_from_catalog() -> None:
    token_map = dict(TOKEN_PATTERNS)
    assert token_map["secret_like"].pattern == secret_catalog.pattern_for("provider_token_prefix").pattern


def test_healthcare_secret_rules_source_from_catalog() -> None:
    catalog_regexes = {pattern.pattern for _name, pattern in secret_catalog.SECRET_PATTERNS}
    assert SECRET_RULES, "expected at least one secret rule"
    for rule in SECRET_RULES:
        assert rule.sensitive_class == "secret"
        assert rule.pattern.pattern in catalog_regexes


def test_catalog_detects_known_secret_shapes() -> None:
    # Fake secret-shaped values assembled by concatenation so no literal secret
    # token appears in source (mirrors tests/test_dev_workflow_hooks.py).
    aws = "AKIA" + "QWERTYUIOPASDFGH"
    gh = "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"
    provider = "sk-" + "proj-" + "abcdefghijklmnopqrstuvwxyz123456"
    assert "aws_access_key_id" in secret_catalog.scan(f"key = {aws}")
    assert "github_token" in secret_catalog.scan(f"token = {gh}")
    assert "anthropic_openai_key" in secret_catalog.scan(f"OPENAI_API_KEY={provider}")
    assert secret_catalog.scan("name = John Doe") == []
