from __future__ import annotations

from pathlib import Path
from typing import Any

from tools.fixture_factory.adapters.shared import (
    case_payload,
    default_role_visibility,
    guardrail,
    load_source_rows,
    source_metadata,
    stable_fixture_id,
)
from tools.fixture_factory.models import HealthcareExposureFixture
from tools.fixture_factory.sanitizers import sanitize_fixture_source
from tools.fixture_factory.validators import validate_fixture_safety


SOURCE_ID = "synthea_sample_data"
SOURCE_FAMILY = "synthea"
ADAPTER_NAME = "synthea_adapter"


def convert(input_path: Path, limit: int) -> list[HealthcareExposureFixture]:
    rows = load_source_rows(input_path, limit)
    fixtures: list[HealthcareExposureFixture] = []
    input_root = input_path if input_path.is_dir() else input_path.parent
    for idx, (source_file, record_index, row) in enumerate(rows):
        fixture_id = stable_fixture_id("synthea_healthcare", idx)
        sanitized = sanitize_fixture_source(row, case_id=fixture_id)
        payload = _build_payload(fixture_id, sanitized.value, sanitized.healthcare_summary)
        fixture = HealthcareExposureFixture(
            fixture_id=fixture_id,
            source_family=SOURCE_FAMILY,
            source_reference=SOURCE_ID,
            source_metadata=source_metadata(
                input_root=input_root,
                source_file=source_file,
                record_index=record_index,
                source_id=SOURCE_ID,
                adapter=ADAPTER_NAME,
                sanitized_row=sanitized.value,
            ),
            payload=payload,
            expected_result={
                "review_required": True,
                "healthcare_review_required": True,
                "manager_review_required": True,
            },
            expected_guardrails=[
                guardrail(
                    "healthcare_safeguard",
                    "tokenize",
                    "Healthcare-context source-shape content is tokenized before fixture use.",
                    sanitized.healthcare_summary.get("field_paths", []),
                ),
                guardrail(
                    "role_visibility",
                    "review_required",
                    "Manager, GRC, legal, and audit views must not receive raw sensitive values.",
                ),
            ],
            expected_role_visibility=default_role_visibility(),
            expected_evidence_ids=[f"ev_{fixture_id}_001"],
            notes="Synthetic healthcare-context fixture generated from a manually reviewed local source-shape sample.",
        )
        validate_fixture_safety(fixture)
        fixtures.append(fixture)
    return fixtures


def _build_payload(fixture_id: str, row: dict[str, Any], healthcare_summary: dict[str, Any]) -> dict[str, Any]:
    title = "Synthetic healthcare-context contamination review"
    description = (
        "Synthetic security alert contains healthcare-context markers after sanitization; "
        "privacy and analyst review are required."
    )
    evidence_summary = "Reviewed synthetic source-shape row produced healthcare safeguard tokens."
    evidence_excerpt = str(row)[:300]
    normalized = {
        "source_row": row,
        "healthcare_summary": healthcare_summary,
        "fixture_type": "healthcare_exposure",
    }
    return case_payload(
        fixture_id=fixture_id,
        title=title,
        description=description,
        evidence_summary=evidence_summary,
        evidence_excerpt=evidence_excerpt,
        normalized=normalized,
        source_family=SOURCE_FAMILY,
        manager_review_required=True,
        healthcare_review_required=True,
    )
