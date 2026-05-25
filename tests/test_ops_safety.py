from __future__ import annotations

import importlib.util
import logging
import sys
from pathlib import Path

import pytest

from threatprism.api.app import create_app
from threatprism.config import Settings


REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_safety_module():
    module_path = REPO_ROOT / "tools" / "check_demo_safety.py"
    spec = importlib.util.spec_from_file_location("check_demo_safety", module_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_current_repo_passes_demo_safety_checks(monkeypatch) -> None:
    safety = _load_safety_module()
    monkeypatch.setenv("ALLOW_REAL_ACTIONS", "false")
    for env_var in safety.LIVE_CREDENTIAL_ENV_VARS:
        monkeypatch.delenv(env_var, raising=False)

    findings = safety.run_checks(REPO_ROOT)

    assert findings == []


def test_secret_scanner_rejects_live_key_patterns(tmp_path) -> None:
    safety = _load_safety_module()
    unsafe_file = tmp_path / "unsafe.txt"
    unsafe_file.write_text("OPENAI_API_KEY=" + "sk-" + "livevalue12345678901234567890", encoding="utf-8")

    findings = safety._check_secret_patterns(tmp_path, [Path("unsafe.txt")])

    assert findings
    assert findings[0].check == "secret-scan"


def test_runtime_environment_rejects_real_actions(monkeypatch) -> None:
    safety = _load_safety_module()
    monkeypatch.setenv("ALLOW_REAL_ACTIONS", "true")

    findings = safety._check_runtime_environment()

    assert any(finding.check == "runtime-env" for finding in findings)


def test_runtime_rejects_demo_key_without_configured_keys() -> None:
    with pytest.raises(ValueError, match="DEMO_API_KEYS must be configured"):
        Settings(env="test", api_auth_mode="demo_key", demo_api_keys="", allow_real_actions=False).validate_runtime()


def test_runtime_rejects_auth_disabled_without_local_ack() -> None:
    with pytest.raises(ValueError, match="THREATPRISM_LOCAL_DEV_ACK=true"):
        Settings(
            env="test",
            api_auth_mode="none",
            auth_required=True,
            local_dev_ack=False,
            allow_real_actions=False,
        ).validate_runtime()


def test_runtime_allows_auth_disabled_with_local_ack_and_logs_warning(caplog) -> None:
    caplog.set_level(logging.WARNING)

    create_app(
        Settings(
            env="test",
            database_url="sqlite:///:memory:",
            api_auth_mode="none",
            auth_required=True,
            local_dev_ack=True,
            allow_real_actions=False,
        )
    )

    assert "API authentication is disabled for explicit local-development use only." in caplog.text


def test_eval_artifact_scan_rejects_raw_sensitive_values(tmp_path) -> None:
    safety = _load_safety_module()
    eval_dir = tmp_path / ".eval_runs" / "eval_test"
    eval_dir.mkdir(parents=True)
    (eval_dir / "results.json").write_text('{"preview":"PAT-44321"}', encoding="utf-8")

    findings = safety._check_eval_artifacts(tmp_path)

    assert findings
    assert findings[0].check == "eval-artifact-sanitize"
