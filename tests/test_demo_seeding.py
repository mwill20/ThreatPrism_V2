from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from threatprism.api.app import create_app
from threatprism.cases.schemas import CaseCreate, TriageStatus
from threatprism.cases.service import CaseService
from threatprism.demo.seeding import (
    CuratedFixtureLoadError,
    CuratedFixtureSource,
    DemoSeeder,
)
from support_settings import local_auth_disabled_settings


def _service() -> CaseService:
    return CaseService(local_auth_disabled_settings())


def _write_temp_curated(tmp_path: Path, manifest: dict, files: dict[str, str]) -> Path:
    curated = tmp_path / "fixtures" / "curated"
    curated.mkdir(parents=True)
    (curated / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    for name, content in files.items():
        (curated / name).write_text(content, encoding="utf-8")
    return tmp_path


def test_curated_source_lists_demo_review_fixtures() -> None:
    seeds = CuratedFixtureSource().list_demo_fixtures()

    assert len(seeds) == 4
    assert seeds == sorted(seeds, key=lambda s: (s.fixture_id, s.source_case_id))
    for seed in seeds:
        # Each payload must validate against the live intake schema.
        CaseCreate.model_validate(seed.payload)
        assert seed.source_case_id


def test_seed_runs_real_intake_and_triage() -> None:
    service = _service()
    seeder = DemoSeeder(service)

    result = seeder.seed([CuratedFixtureSource()])

    assert result.seeded_count == 4
    assert result.skipped_count == 0
    # Cases are persisted and discoverable through the normal list path.
    listed = {summary.source_case_id for summary in service.list_cases()}
    assert {outcome.source_case_id for outcome in result.seeded} == listed


def test_seeded_cases_run_full_pipeline_to_terminal_status() -> None:
    # Curated fixtures are post-sanitization snapshots, so the prompt firewall has
    # nothing left to quarantine on replay -- all four reach a terminal state, and
    # live Stage-2 telemetry tokenization still runs (proving the pipeline executes).
    service = _service()
    result = DemoSeeder(service).seed([CuratedFixtureSource()])

    terminal = {TriageStatus.completed, TriageStatus.blocked_by_guardrail}
    total_sanitization_records = 0
    for outcome in result.seeded:
        case = service.get_case(outcome.case_id)
        assert case is not None
        assert case.triage_status in terminal
        total_sanitization_records += len(case.sanitization_records)

    assert total_sanitization_records > 0


def test_seed_is_idempotent_with_skip_existing() -> None:
    service = _service()
    seeder = DemoSeeder(service)

    first = seeder.seed([CuratedFixtureSource()])
    second = seeder.seed([CuratedFixtureSource()])

    assert first.seeded_count == 4
    assert second.seeded_count == 0
    assert second.skipped_count == 4
    # No duplicate cases were created on the second run.
    assert len(service.list_cases()) == 4


def test_safety_filter_excludes_non_demo_review_fixtures(tmp_path: Path) -> None:
    payload = json.loads(
        Path("examples/soar_payloads/generic_soar_case.json").read_text(encoding="utf-8")
    )
    line = json.dumps({"fixture_id": "temp_fixture_0001", "payload": payload})
    manifest = {
        "manifest_version": "curated-fixtures/0.1",
        "fixtures": [
            {
                "fixture_id": "temp_fixture_0001",
                "path": "fixtures/curated/temp_fixture_0001.jsonl",
                "safety_review_status": "approved_demo_safe",
                "content_review_status": "approved_for_tests",
                "allowed_uses": ["api_schema_validation"],
            }
        ],
    }
    root = _write_temp_curated(tmp_path, manifest, {"temp_fixture_0001.jsonl": line})

    seeds = CuratedFixtureSource(repo_root=root).list_demo_fixtures()

    assert seeds == []


@pytest.mark.parametrize(
    "bad_path",
    [
        "fixtures/curated/../../secrets.jsonl",
        "/etc/passwd.jsonl",
        "fixtures/curated/note.txt",
    ],
)
def test_path_sandbox_rejects_unsafe_paths(tmp_path: Path, bad_path: str) -> None:
    manifest = {
        "manifest_version": "curated-fixtures/0.1",
        "fixtures": [
            {
                "fixture_id": "temp_fixture_0001",
                "path": bad_path,
                "safety_review_status": "approved_demo_safe",
                "content_review_status": "approved_for_tests",
                "allowed_uses": ["demo_review"],
            }
        ],
    }
    root = _write_temp_curated(tmp_path, manifest, {})

    with pytest.raises(CuratedFixtureLoadError):
        CuratedFixtureSource(repo_root=root).list_demo_fixtures()


def test_startup_hook_seeds_when_enabled() -> None:
    app = create_app(local_auth_disabled_settings(demo_seed_enabled=True))
    client = TestClient(app)

    response = client.get("/cases")

    assert response.status_code == 200
    # Startup seeds both wired sources: 4 hand-authored curated fixtures plus the
    # dataset derivatives -- 12 promoted Synthea + 12 promoted deepset
    # prompt-injection fixtures (see api/app.py seed hook).
    assert len(response.json()) == 28


def test_startup_hook_disabled_by_default() -> None:
    app = create_app(local_auth_disabled_settings())
    client = TestClient(app)

    response = client.get("/cases")

    assert response.status_code == 200
    assert response.json() == []


def test_demo_seed_blocked_in_production() -> None:
    settings = local_auth_disabled_settings(env="production", demo_seed_enabled=True)
    with pytest.raises(ValueError, match="Demo seeding"):
        settings.validate_runtime()
