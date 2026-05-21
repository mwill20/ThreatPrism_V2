from __future__ import annotations

import json
from pathlib import Path

import pytest

from threatprism.cases.schemas import Source
from threatprism.soar.generic import normalize_soar_payload


@pytest.mark.parametrize(
    ("payload_path", "expected_source"),
    [
        ("examples/soar_payloads/generic_soar_case.json", Source.generic_soar),
        ("examples/soar_payloads/sentinel_incident.json", Source.sentinel),
        ("examples/soar_payloads/defender_xdr_alert.json", Source.defender_xdr),
        ("examples/soar_payloads/logic_apps_webhook_payload.json", Source.logic_apps),
        ("examples/soar_payloads/swimlane_case_mock.json", Source.swimlane_mock),
    ],
)
def test_demo_soar_payloads_normalize_to_expected_sources(
    payload_path: str,
    expected_source: Source,
) -> None:
    payload = json.loads(Path(payload_path).read_text())

    normalized = normalize_soar_payload(payload)

    assert normalized.source == expected_source
    assert normalized.source_case_id
    assert normalized.evidence
