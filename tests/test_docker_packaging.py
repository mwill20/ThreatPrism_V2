from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
LIVE_PROVIDER_ENV_VARS = {
    "OPENAI_API_KEY",
    "LOCAL_LLM_BASE_URL",
    "VIRUSTOTAL_API_KEY",
    "URLSCAN_API_KEY",
    "ABUSEIPDB_API_KEY",
}


def test_dockerfile_uses_demo_safe_runtime_defaults() -> None:
    dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "FROM python:3.12-slim" in dockerfile
    assert "PYTHONPATH=/app/src" in dockerfile
    assert "DATABASE_URL=sqlite:////app/data/threatprism.db" in dockerfile
    assert "API_AUTH_MODE=demo_key" in dockerfile
    assert "DEMO_API_KEYS=demo-analyst-key" in dockerfile
    assert "LLM_PROVIDER=deterministic_demo" in dockerfile
    assert "ALLOW_REAL_ACTIONS=false" in dockerfile
    assert "requirements-lock.txt" in dockerfile
    assert "USER threatprism" in dockerfile
    assert "uvicorn" in dockerfile
    assert "--host\", \"0.0.0.0\"" in dockerfile


def test_compose_file_preserves_fake_data_only_defaults() -> None:
    compose = (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    lower_compose = compose.lower()

    assert "threatprism-api:" in compose
    assert "API_AUTH_MODE: demo_key" in compose
    assert "DEMO_API_KEYS: demo-analyst-key" in compose
    assert 'ALLOW_REAL_ACTIONS: "false"' in compose
    assert "LLM_PROVIDER: deterministic_demo" in compose
    assert "DATABASE_URL: sqlite:////app/data/threatprism.db" in compose
    assert "threatprism-data:/app/data" in compose
    assert "postgres" not in lower_compose
    assert "redis" not in lower_compose
    for env_var in LIVE_PROVIDER_ENV_VARS:
        assert f'{env_var}: ""' in compose


def test_dockerignore_excludes_sensitive_and_generated_artifacts() -> None:
    dockerignore = (REPO_ROOT / ".dockerignore").read_text(encoding="utf-8")

    for required_entry in [
        ".git/",
        ".env",
        ".env.*",
        ".eval_runs/",
        ".pytest_tmp*/",
        "pytest-cache-files-*/",
        "data/",
        "*.db",
        "external_datasets/",
        "fixtures/generated/",
    ]:
        assert required_entry in dockerignore
