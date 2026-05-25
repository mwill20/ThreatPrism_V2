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
from tools.fixture_factory.models import SyntheticSOARCaseFixture
from tools.fixture_factory.sanitizers import sanitize_fixture_source
from tools.fixture_factory.validators import validate_fixture_safety


SOURCE_ID = "otrf_security_datasets"
SOURCE_FAMILY = "otrf"
ADAPTER_NAME = "otrf_adapter"


def convert(input_path: Path, limit: int) -> list[SyntheticSOARCaseFixture]:
    rows = load_source_rows(input_path, limit)
    fixtures: list[SyntheticSOARCaseFixture] = []
    input_root = input_path if input_path.is_dir() else input_path.parent
    for idx, (source_file, record_index, row) in enumerate(rows):
        fixture_id = stable_fixture_id("otrf_soc_case", idx)
        sanitized = sanitize_fixture_source(row, case_id=fixture_id)
        technique = _first_value(sanitized.value, ["technique_id", "attack_technique", "mitre_technique"])
        payload = _build_payload(fixture_id, sanitized.value, technique)
        fixture = SyntheticSOARCaseFixture(
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
                "manager_review_required": False,
                "technique": technique,
            },
            expected_guardrails=[
                guardrail(
                    "infrastructure_sanitizer",
                    "redact",
                    "Real-looking infrastructure is replaced with reserved documentation examples.",
                )
            ],
            expected_role_visibility=default_role_visibility(),
            expected_evidence_ids=[f"ev_{fixture_id}_001"],
            notes="Synthetic SOC telemetry fixture generated from a manually reviewed local source-shape sample.",
        )
        validate_fixture_safety(fixture)
        fixtures.append(fixture)
    return fixtures


def _build_payload(fixture_id: str, row: dict[str, Any], technique: str | None) -> dict[str, Any]:
    title = "Synthetic SOC telemetry review"
    description = "Synthetic security telemetry converted into a ThreatPrism-native case fixture."
    evidence_summary = _first_value(row, ["message", "event_description", "description", "event_type"]) or (
        "Synthetic telemetry event requires analyst review."
    )
    evidence_excerpt = str(row)[:300]
    iocs = []
    source_ip = _first_value(row, ["src_ip", "source_ip", "SourceIp", "client_ip"])
    if source_ip:
        iocs.append(
            {
                "ioc_id": f"ioc_{fixture_id}_001",
                "ioc_type": "ip",
                "value": source_ip,
                "source": "fixture",
                "confidence": 0.55,
                "evidence_ids": [f"ev_{fixture_id}_001"],
            }
        )
    return case_payload(
        fixture_id=fixture_id,
        title=title,
        description=description,
        evidence_summary=str(evidence_summary),
        evidence_excerpt=evidence_excerpt,
        normalized={"source_row": row, "fixture_type": "soc_case"},
        source_family=SOURCE_FAMILY,
        mitre_technique=technique,
        iocs=iocs,
    )


def _first_value(row: dict[str, Any], keys: list[str]) -> str | None:
    for key in keys:
        value = row.get(key)
        if value not in (None, ""):
            return str(value)
    return None
