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
from tools.fixture_factory.models import PromptInjectionEvalFixture
from tools.fixture_factory.sanitizers import sanitize_fixture_source
from tools.fixture_factory.validators import validate_fixture_safety


SOURCE_ID = "lakera_pint"
SOURCE_FAMILY = "pint"
ADAPTER_NAME = "pint_adapter"


def convert(input_path: Path, limit: int) -> list[PromptInjectionEvalFixture]:
    rows = load_source_rows(input_path, limit)
    fixtures: list[PromptInjectionEvalFixture] = []
    input_root = input_path if input_path.is_dir() else input_path.parent
    for idx, (source_file, record_index, row) in enumerate(rows):
        fixture_id = stable_fixture_id("pint_prompt_injection", idx)
        sanitized = sanitize_fixture_source(row, case_id=fixture_id)
        payload = _build_payload(fixture_id, sanitized.value)
        fixture = PromptInjectionEvalFixture(
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
                "prompt_injection_expected": True,
                "quarantine_expected": sanitized.prompt_quarantined,
            },
            expected_guardrails=[
                guardrail(
                    "prompt_firewall",
                    "quarantine" if sanitized.prompt_quarantined else "redact",
                    "Unsafe prompt source-shape content is sanitized before fixture use.",
                    sanitized.removed_fields,
                )
            ],
            expected_role_visibility=default_role_visibility(),
            expected_evidence_ids=[f"ev_{fixture_id}_001"],
            notes="Synthetic prompt-injection fixture generated from a manually reviewed local source-shape sample.",
        )
        validate_fixture_safety(fixture)
        fixtures.append(fixture)
    return fixtures


def _build_payload(fixture_id: str, row: dict[str, Any]) -> dict[str, Any]:
    prompt_preview = _first_value(row, ["prompt", "attack", "input", "text"]) or str(row)
    return case_payload(
        fixture_id=fixture_id,
        title="Synthetic prompt-injection defense review",
        description="Synthetic source-shape prompt content was sanitized for local eval and demo use.",
        evidence_summary="Sanitized prompt-injection source-shape row requires guardrail review.",
        evidence_excerpt=str(prompt_preview)[:300],
        normalized={"source_row": row, "fixture_type": "prompt_injection"},
        source_family=SOURCE_FAMILY,
        manager_review_required=True,
    )


def _first_value(row: dict[str, Any], keys: list[str]) -> str | None:
    for key in keys:
        value = row.get(key)
        if value not in (None, ""):
            return str(value)
    return None
