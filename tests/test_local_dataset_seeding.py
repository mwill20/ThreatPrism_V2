from __future__ import annotations

import json
from pathlib import Path

import pytest

from threatprism.cases.schemas import CaseCreate
from threatprism.cases.service import CaseService
from threatprism.demo.seed_cli import _build_sources, _ensure_source_allowed
from threatprism.demo.seeding import (
    CuratedDatasetSource,
    CuratedFixtureLoadError,
    CuratedFixtureSource,
    DemoSeeder,
    LocalDatasetSource,
)
from support_settings import local_auth_disabled_settings


_VALID_PAYLOAD = json.loads(
    Path("examples/soar_payloads/generic_soar_case.json").read_text(encoding="utf-8")
)


def _service() -> CaseService:
    return CaseService(local_auth_disabled_settings())


def _staged_line(source_case_id: str) -> str:
    payload = dict(_VALID_PAYLOAD)
    payload["source_case_id"] = source_case_id
    return json.dumps({"payload": payload})


def _stage_local(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "external_datasets" / "local_seed"
    root.mkdir(parents=True)
    for name, content in files.items():
        (root / name).write_text(content, encoding="utf-8")
    return tmp_path


def test_local_source_reads_external_jsonl_on_the_fly(tmp_path: Path) -> None:
    repo_root = _stage_local(
        tmp_path,
        {"batch.jsonl": _staged_line("local-001") + "\n" + _staged_line("local-002")},
    )

    seeds = LocalDatasetSource(repo_root=repo_root).list_demo_fixtures()

    assert {seed.source_case_id for seed in seeds} == {"local-001", "local-002"}
    for seed in seeds:
        CaseCreate.model_validate(seed.payload)


def test_local_source_empty_when_no_staging_dir(tmp_path: Path) -> None:
    # No external_datasets/ at all -> nothing to seed, no error.
    assert LocalDatasetSource(repo_root=tmp_path).list_demo_fixtures() == []


def test_local_source_ignores_non_jsonl_files(tmp_path: Path) -> None:
    repo_root = _stage_local(
        tmp_path,
        {
            "ok.jsonl": _staged_line("local-001"),
            "raw.json": _staged_line("should-not-load"),
            "notes.txt": "not data",
        },
    )

    seeds = LocalDatasetSource(repo_root=repo_root).list_demo_fixtures()

    assert {seed.source_case_id for seed in seeds} == {"local-001"}


def test_local_source_limit_caps_returned_fixtures(tmp_path: Path) -> None:
    repo_root = _stage_local(
        tmp_path,
        {
            "batch.jsonl": "\n".join(
                _staged_line(f"local-{n:03d}") for n in range(1, 6)
            )
        },
    )

    seeds = LocalDatasetSource(repo_root=repo_root, limit=2).list_demo_fixtures()

    assert len(seeds) == 2
    # Deterministic: the first two by (fixture_id, source_case_id) ordering.
    assert [seed.source_case_id for seed in seeds] == ["local-001", "local-002"]


def test_local_source_rejects_non_positive_limit(tmp_path: Path) -> None:
    with pytest.raises(CuratedFixtureLoadError):
        LocalDatasetSource(repo_root=tmp_path, limit=0)


def test_local_source_seeds_through_real_intake(tmp_path: Path) -> None:
    repo_root = _stage_local(tmp_path, {"batch.jsonl": _staged_line("local-001")})
    service = _service()

    result = DemoSeeder(service).seed([LocalDatasetSource(repo_root=repo_root)])

    assert result.seeded_count == 1
    listed = {summary.source_case_id for summary in service.list_cases()}
    assert "local-001" in listed


def test_local_source_off_by_default_in_cli() -> None:
    # Default and "all" must never silently pull uncommitted local data.
    default_sources = _build_sources("curated")
    all_sources = _build_sources("all")

    assert not any(isinstance(s, LocalDatasetSource) for s in default_sources)
    assert not any(isinstance(s, LocalDatasetSource) for s in all_sources)
    assert {s.name for s in all_sources} == {"curated", "curated_datasets"}


def test_local_source_selected_explicitly() -> None:
    sources = _build_sources("local", limit=3)

    assert len(sources) == 1
    assert isinstance(sources[0], LocalDatasetSource)
    assert sources[0].name == "local"


def test_local_source_refused_in_production() -> None:
    with pytest.raises(SystemExit):
        _ensure_source_allowed("local", "production")
    with pytest.raises(SystemExit):
        _ensure_source_allowed("local", "prod")


def test_non_local_sources_allowed_in_any_env() -> None:
    # No exception expected for committed/reviewed sources or local in demo.
    _ensure_source_allowed("curated", "production")
    _ensure_source_allowed("local", "demo")
