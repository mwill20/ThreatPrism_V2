from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
from typing import Any

from tools.fixture_factory.models import ExpectedGuardrailOutcome, ExpectedRoleVisibility, FixtureSourceMetadata


def load_source_rows(input_path: Path, limit: int) -> list[tuple[Path, int, dict[str, Any]]]:
    if limit <= 0:
        raise ValueError("--limit must be greater than zero")
    files = _iter_source_files(input_path)
    rows: list[tuple[Path, int, dict[str, Any]]] = []
    for source_file in files:
        for record_index, row in _read_file_rows(source_file):
            rows.append((source_file, record_index, row))
            if len(rows) >= limit:
                return rows
    return rows


def source_metadata(
    *,
    input_root: Path,
    source_file: Path,
    record_index: int,
    source_id: str,
    adapter: str,
    sanitized_row: dict[str, Any],
) -> FixtureSourceMetadata:
    relative_source = source_file.relative_to(input_root).as_posix() if source_file != input_root else source_file.name
    source_hash = hashlib.sha256(
        json.dumps(sanitized_row, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()
    return FixtureSourceMetadata(
        source_id=source_id,
        source_file=relative_source,
        record_index=record_index,
        source_payload_hash=f"sha256:{source_hash}",
        adapter=adapter,
    )


def stable_fixture_id(prefix: str, index: int) -> str:
    return f"{prefix}_{index + 1:04d}"


def default_role_visibility() -> dict[str, ExpectedRoleVisibility]:
    return {
        "ai": ExpectedRoleVisibility(
            role="ai",
            tokenized_values_visible=True,
            summary="Model-visible views receive sanitized and tokenized content only.",
        ),
        "analyst": ExpectedRoleVisibility(
            role="analyst",
            tokenized_values_visible=True,
            summary="Analyst views may inspect sanitized security context but not raw sensitive values.",
        ),
        "engineer": ExpectedRoleVisibility(
            role="engineer",
            tokenized_values_visible=True,
            summary="Engineer views may inspect sanitized technical context but not raw sensitive values.",
        ),
        "manager_grc": ExpectedRoleVisibility(
            role="manager_grc",
            tokenized_values_visible=True,
            summary="Manager and GRC views receive safe summaries and evidence alignment only.",
        ),
        "legal_privacy": ExpectedRoleVisibility(
            role="legal_privacy",
            tokenized_values_visible=True,
            summary="Legal and privacy views receive exposure metadata without raw sensitive values.",
        ),
        "audit_debug": ExpectedRoleVisibility(
            role="audit_debug",
            tokenized_values_visible=True,
            summary="Audit/debug views receive tokens, detector categories, hashes, and decisions only.",
        ),
    }


def guardrail(guardrail_name: str, expected: str, reason: str, fields: list[str] | None = None) -> ExpectedGuardrailOutcome:
    return ExpectedGuardrailOutcome(
        guardrail=guardrail_name,
        expected=expected,  # type: ignore[arg-type]
        reason=reason,
        fields=fields or [],
    )


def case_payload(
    *,
    fixture_id: str,
    title: str,
    description: str,
    evidence_summary: str,
    evidence_excerpt: str,
    normalized: dict[str, Any],
    source_family: str,
    manager_review_required: bool = False,
    healthcare_review_required: bool = False,
    mitre_technique: str | None = None,
    iocs: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    evidence_id = f"ev_{fixture_id}_001"
    event_id = f"evt_{fixture_id}_001"
    source_metadata = {
        "fixture_factory": True,
        "source_family": source_family,
        "manager_review_required": manager_review_required,
        "healthcare_review_required": healthcare_review_required,
    }
    if mitre_technique:
        source_metadata["mitre_technique"] = mitre_technique
    return {
        "source": "generic_soar",
        "source_case_id": f"fixture-{fixture_id}",
        "source_payload_hash": f"sha256:{hashlib.sha256(fixture_id.encode('utf-8')).hexdigest()}",
        "source_metadata": source_metadata,
        "organization_context": {
            "environment": "demo",
            "business_unit": "internal_soc",
            "sensitivity": "demo",
            "operating_model": "mssp_to_internal_soc_transition",
        },
        "title": title,
        "description": description,
        "alerts": [
            {
                "alert_id": f"alert_{fixture_id}_001",
                "name": title,
                "severity": "medium",
                "source": source_family,
                "description": description,
            }
        ],
        "events": [
            {
                "event_id": event_id,
                "event_type": "synthetic_fixture_event",
                "source": source_family,
                "description": evidence_summary,
                "normalized": normalized,
                "provenance": {
                    "source_file": f"{source_family}_reviewed_sample",
                    "record_index": 0,
                    "source_event_id": fixture_id,
                },
                "raw_reference": "external source sample removed after sanitization",
            }
        ],
        "entities": [
            {
                "entity_type": "host",
                "value": "demo-workstation-01",
                "role": "affected_asset",
            }
        ],
        "iocs": iocs or [],
        "evidence": [
            {
                "evidence_id": evidence_id,
                "evidence_type": "log",
                "summary": evidence_summary,
                "source_uri": f"fixture://{fixture_id}",
                "event_ids": [event_id],
                "excerpt": evidence_excerpt,
                "sensitivity": "demo",
                "provenance": {
                    "source_file": f"{source_family}_reviewed_sample",
                    "record_index": 0,
                    "source_event_id": fixture_id,
                },
            }
        ],
    }


def _iter_source_files(input_path: Path) -> list[Path]:
    if input_path.is_file():
        return [input_path]
    suffixes = {".csv", ".json", ".jsonl"}
    return sorted(path for path in input_path.rglob("*") if path.is_file() and path.suffix.lower() in suffixes)


def _read_file_rows(source_file: Path) -> list[tuple[int, dict[str, Any]]]:
    suffix = source_file.suffix.lower()
    if suffix == ".jsonl":
        rows = []
        for idx, line in enumerate(source_file.read_text(encoding="utf-8").splitlines()):
            stripped = line.strip()
            if not stripped:
                continue
            parsed = json.loads(stripped)
            rows.append((idx, _coerce_mapping(parsed)))
        return rows
    if suffix == ".json":
        parsed = json.loads(source_file.read_text(encoding="utf-8"))
        if isinstance(parsed, list):
            return [(idx, _coerce_mapping(row)) for idx, row in enumerate(parsed)]
        if isinstance(parsed, dict):
            candidates = parsed.get("records") or parsed.get("rows") or parsed.get("items")
            if isinstance(candidates, list):
                return [(idx, _coerce_mapping(row)) for idx, row in enumerate(candidates)]
            return [(0, parsed)]
    if suffix == ".csv":
        with source_file.open("r", encoding="utf-8", newline="") as handle:
            return [(idx, dict(row)) for idx, row in enumerate(csv.DictReader(handle))]
    raise ValueError(f"Unsupported source file extension: {source_file.suffix}")


def _coerce_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return {str(key): entry for key, entry in value.items()}
    return {"value": value}
