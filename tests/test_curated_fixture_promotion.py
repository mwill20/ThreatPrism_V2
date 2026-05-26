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
EXPECTED_CURATED_FIXTURE_IDS = [
    "curated_evidence_conflict_grc_0001",
    "curated_healthcare_exposure_0001",
    "curated_prompt_injection_0001",
    "curated_soc_case_0001",
]
APPROVED_ALLOWED_USES = [
    "fixture_factory_regression",
    "api_schema_validation",
    "demo_review",
]


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
    manifest_ids = sorted(entry["fixture_id"] for entry in manifest["fixtures"])
    assert manifest_ids == EXPECTED_CURATED_FIXTURE_IDS
    for entry in manifest["fixtures"]:
        assert entry["source_sample_status"] == "handwritten_fake_source_shape"
        assert entry["license_review_status"] == "not_third_party_local_fake"
        assert entry["safety_review_status"] == "approved_demo_safe"
        assert entry["content_review_status"] == "approved_for_tests"
        assert entry["raw_source_committed"] is False
        assert entry["auto_downloaded"] is False
        assert entry["allowed_uses"] == APPROVED_ALLOWED_USES


def test_curated_fixtures_are_schema_valid_sanitized_and_deterministic() -> None:
    fixtures = load_curated_fixtures(repo_root=REPO_ROOT)

    assert [fixture.fixture_id for fixture in fixtures] == EXPECTED_CURATED_FIXTURE_IDS
    for fixture in fixtures:
        CaseCreate.model_validate(fixture.payload)
        assert fixture.synthetic_only is True
        assert fixture.raw_source_retained is False
        assert fixture.source_metadata.license_review_required is True
        assert fixture.source_metadata.raw_source_committed is False
        assert fixture.source_metadata.adapter == "manual_curated_promotion"
        assert fixture.payload["source_metadata"]["curated_promotion"] is True
        assert fixture.payload["source_metadata"]["fixture_factory"] is True
        assert fixture.expected_evidence_ids

        rendered = fixture_to_sorted_json(fixture)
        parsed = json.loads(rendered)
        assert list(parsed) == sorted(parsed)
        assert "raw_payload" not in rendered
        assert "vault_mappings" not in rendered
        assert "token_vault" not in rendered
        assert "sk-" not in rendered
        assert "PAT-" not in rendered
        assert "patient id" not in rendered.lower()
        assert "control satisfied" not in rendered.lower()
        assert "audit-ready" not in rendered.lower()


def test_curated_fixture_scenario_coverage_is_explicit() -> None:
    fixtures = {fixture.fixture_id: fixture for fixture in load_curated_fixtures(repo_root=REPO_ROOT)}
    scenario_types = {fixture.scenario_type for fixture in fixtures.values()}

    assert scenario_types == {"evidence_conflict", "healthcare_exposure", "prompt_injection", "soc_case"}
    healthcare = fixtures["curated_healthcare_exposure_0001"]
    assert healthcare.expected_result["healthcare_review_required"] is True
    assert any(outcome.guardrail == "healthcare_safeguard" for outcome in healthcare.expected_guardrails)
    assert "[POTENTIAL_PHI:MRN:phi_0001]" in json.dumps(healthcare.payload, sort_keys=True)

    prompt = fixtures["curated_prompt_injection_0001"]
    assert prompt.expected_result["prompt_quarantined"] is True
    assert any(
        outcome.guardrail == "prompt_firewall" and outcome.expected == "quarantine"
        for outcome in prompt.expected_guardrails
    )
    assert "[REDACTED_PROMPT_INJECTION]" in json.dumps(prompt.payload, sort_keys=True)

    conflict = fixtures["curated_evidence_conflict_grc_0001"]
    assert conflict.expected_result["expected_conflict"] is True
    assert conflict.expected_result["grc_review_required"] is True
    assert any(outcome.guardrail == "grc_language" for outcome in conflict.expected_guardrails)


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


def test_curated_manifest_rejects_duplicate_fixture_ids() -> None:
    manifest = load_curated_manifest(repo_root=REPO_ROOT)
    duplicate = dict(manifest["fixtures"][0])
    manifest["fixtures"].append(duplicate)

    with pytest.raises(ValueError, match="Duplicate curated fixture id"):
        validate_curated_manifest(manifest, repo_root=REPO_ROOT)
