from __future__ import annotations

import json
from pathlib import Path

import pytest

from threatprism.cases.schemas import CaseCreate
from tools.fixture_factory.promotions import (
    load_curated_fixtures,
    load_curated_manifest,
    resolve_curated_fixture_path,
    validate_curated_manifest,
)
from tools.fixture_factory.validators import fixture_to_sorted_json


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_curated_fixture_manifest_records_manual_review_and_no_auto_scan() -> None:
    manifest = load_curated_manifest(repo_root=REPO_ROOT)

    assert manifest["generated_fixture_auto_scan"] is False
    assert manifest["promotion_policy"] == {
        "raw_external_datasets_committed": False,
        "auto_downloads_allowed": False,
        "live_provider_output_allowed": False,
        "real_data_allowed": False,
        "standard_validation_auto_scans_generated_folder": False,
    }
    assert [entry["fixture_id"] for entry in manifest["fixtures"]] == ["curated_soc_case_0001"]
    entry = manifest["fixtures"][0]
    assert entry["source_sample_status"] == "handwritten_fake_source_shape"
    assert entry["license_review_status"] == "not_third_party_local_fake"
    assert entry["safety_review_status"] == "approved_demo_safe"
    assert entry["content_review_status"] == "approved_for_tests"
    assert entry["raw_source_committed"] is False
    assert entry["auto_downloaded"] is False


def test_curated_fixture_is_schema_valid_sanitized_and_deterministic() -> None:
    fixtures = load_curated_fixtures(repo_root=REPO_ROOT)

    assert [fixture.fixture_id for fixture in fixtures] == ["curated_soc_case_0001"]
    fixture = fixtures[0]
    CaseCreate.model_validate(fixture.payload)
    assert fixture.synthetic_only is True
    assert fixture.raw_source_retained is False
    assert fixture.source_metadata.license_review_required is True
    assert fixture.source_metadata.raw_source_committed is False
    assert fixture.expected_evidence_ids == [
        "ev_curated_soc_case_0001_001",
        "ev_curated_soc_case_0001_002",
    ]

    rendered = fixture_to_sorted_json(fixture)
    parsed = json.loads(rendered)
    assert list(parsed) == sorted(parsed)
    assert "raw_payload" not in rendered
    assert "vault_mappings" not in rendered
    assert "token_vault" not in rendered
    assert "sk-" not in rendered
    assert "PAT-" not in rendered


def test_curated_fixture_paths_are_explicit_and_do_not_use_generated_folder() -> None:
    fixture_path = resolve_curated_fixture_path(
        "fixtures/curated/curated_soc_case_0001.jsonl",
        repo_root=REPO_ROOT,
    )

    assert fixture_path.exists()
    with pytest.raises(ValueError):
        resolve_curated_fixture_path("fixtures/generated/curated_soc_case_0001.jsonl", repo_root=REPO_ROOT)
    with pytest.raises(ValueError):
        resolve_curated_fixture_path("fixtures/curated/../generated/escape.jsonl", repo_root=REPO_ROOT)
    with pytest.raises(ValueError):
        resolve_curated_fixture_path(str(fixture_path.resolve()), repo_root=REPO_ROOT)


def test_curated_manifest_rejects_unreviewed_entries() -> None:
    manifest = load_curated_manifest(repo_root=REPO_ROOT)
    manifest["fixtures"][0]["safety_review_status"] = "pending"

    with pytest.raises(ValueError, match="approved safety review"):
        validate_curated_manifest(manifest, repo_root=REPO_ROOT)
