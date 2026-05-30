from __future__ import annotations

import json
from pathlib import Path

import pytest

from threatprism.cases.schemas import CaseCreate
from threatprism.cases.service import CaseService
from threatprism.demo.seed_cli import _build_sources
from threatprism.demo.seeding import (
    CuratedDatasetSource,
    CuratedFixtureLoadError,
    CuratedFixtureSource,
    DemoSeeder,
)
from support_settings import local_auth_disabled_settings


_VALID_PAYLOAD = json.loads(
    Path("examples/soar_payloads/generic_soar_case.json").read_text(encoding="utf-8")
)


def _service() -> CaseService:
    return CaseService(local_auth_disabled_settings())


def _entry(**overrides: object) -> dict:
    entry = {
        "fixture_id": "synthea_healthcare_0001",
        "path": "fixtures/curated_datasets/synthea_healthcare_0001.jsonl",
        "source_family": "synthea",
        "license_review_status": "approved_third_party_apache2_synthetic",
        "safety_review_status": "approved_demo_safe",
        "content_review_status": "approved_for_tests",
        "raw_source_committed": False,
        "auto_downloaded": False,
        "allowed_uses": ["demo_review"],
    }
    entry.update(overrides)
    return entry


def _write_temp_dataset(tmp_path: Path, manifest: dict, files: dict[str, str]) -> Path:
    root = tmp_path / "fixtures" / "curated_datasets"
    root.mkdir(parents=True)
    (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    for name, content in files.items():
        (root / name).write_text(content, encoding="utf-8")
    return tmp_path


def _manifest(fixtures: list[dict], *, version: str = "curated-datasets/0.1") -> dict:
    return {"manifest_version": version, "generated_fixture_auto_scan": False, "fixtures": fixtures}


def _fixture_line(fixture_id: str = "synthea_healthcare_0001") -> str:
    return json.dumps({"fixture_id": fixture_id, "payload": _VALID_PAYLOAD})


def test_committed_dataset_manifest_loads_promoted_synthea_fixtures() -> None:
    # Slice 4 promoted 12 column-projected Synthea derivatives. The committed
    # manifest must load them all through the real license/safety gate, each a
    # schema-valid CaseCreate payload with a distinct source_case_id.
    seeds = [
        seed
        for seed in CuratedDatasetSource().list_demo_fixtures()
        if seed.fixture_id == "synthea_healthcare"
    ]

    assert len(seeds) == 12
    assert len({seed.source_case_id for seed in seeds}) == 12
    for seed in seeds:
        CaseCreate.model_validate(seed.payload)


def test_dataset_source_lists_approved_third_party_fixtures(tmp_path: Path) -> None:
    root = _write_temp_dataset(
        tmp_path,
        _manifest([_entry()]),
        {"synthea_healthcare_0001.jsonl": _fixture_line()},
    )

    seeds = CuratedDatasetSource(repo_root=root).list_demo_fixtures()

    assert len(seeds) == 1
    CaseCreate.model_validate(seeds[0].payload)
    assert seeds[0].source_case_id


def test_dataset_source_rejects_non_third_party_license(tmp_path: Path) -> None:
    # The hand-authored curated license must not be accepted by the dataset
    # contract -- the runtime allowlist, not the manifest, is the authority.
    root = _write_temp_dataset(
        tmp_path,
        _manifest([_entry(license_review_status="not_third_party_local_fake")]),
        {"synthea_healthcare_0001.jsonl": _fixture_line()},
    )

    assert CuratedDatasetSource(repo_root=root).list_demo_fixtures() == []


def test_dataset_source_excludes_unreviewed_entries(tmp_path: Path) -> None:
    root = _write_temp_dataset(
        tmp_path,
        _manifest(
            [
                _entry(safety_review_status="pending"),
                _entry(
                    fixture_id="synthea_healthcare_0002",
                    path="fixtures/curated_datasets/synthea_healthcare_0002.jsonl",
                    allowed_uses=["api_schema_validation"],
                ),
            ]
        ),
        {
            "synthea_healthcare_0001.jsonl": _fixture_line(),
            "synthea_healthcare_0002.jsonl": _fixture_line("synthea_healthcare_0002"),
        },
    )

    assert CuratedDatasetSource(repo_root=root).list_demo_fixtures() == []


def test_dataset_source_rejects_wrong_manifest_version(tmp_path: Path) -> None:
    root = _write_temp_dataset(
        tmp_path,
        _manifest([_entry()], version="curated-fixtures/0.1"),
        {"synthea_healthcare_0001.jsonl": _fixture_line()},
    )

    with pytest.raises(CuratedFixtureLoadError):
        CuratedDatasetSource(repo_root=root).list_demo_fixtures()


@pytest.mark.parametrize(
    "bad_path",
    [
        "fixtures/curated_datasets/../../secrets.jsonl",
        "/etc/passwd.jsonl",
        "fixtures/curated_datasets/note.txt",
        "fixtures/curated/leak.jsonl",
    ],
)
def test_dataset_path_sandbox_rejects_unsafe_paths(tmp_path: Path, bad_path: str) -> None:
    root = _write_temp_dataset(tmp_path, _manifest([_entry(path=bad_path)]), {})

    with pytest.raises(CuratedFixtureLoadError):
        CuratedDatasetSource(repo_root=root).list_demo_fixtures()


def test_dataset_source_seeds_through_real_intake(tmp_path: Path) -> None:
    root = _write_temp_dataset(
        tmp_path,
        _manifest([_entry()]),
        {"synthea_healthcare_0001.jsonl": _fixture_line()},
    )
    service = _service()

    result = DemoSeeder(service).seed([CuratedDatasetSource(repo_root=root)])

    assert result.seeded_count == 1
    listed = {summary.source_case_id for summary in service.list_cases()}
    assert {outcome.source_case_id for outcome in result.seeded} == listed


def test_cli_all_source_builds_both_curated_and_dataset() -> None:
    sources = _build_sources("all")

    names = {source.name for source in sources}
    assert names == {"curated", "curated_datasets"}
    assert any(isinstance(s, CuratedFixtureSource) for s in sources)
    assert any(isinstance(s, CuratedDatasetSource) for s in sources)
