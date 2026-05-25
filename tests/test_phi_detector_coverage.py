from __future__ import annotations

import json

from threatprism.guardrails.healthcare import (
    CONTEXT_IDENTIFIER_RULES,
    PHI_RULES,
    PII_RULES,
    SECRET_RULES,
    SensitiveRule,
    safeguard_value,
)


DETECTOR_FIXTURES = {
    "api_key": "sk-testsecretvalue12345",
    "password": "password: TempPass123",
    "mrn": "MRN: ABCD1234",
    "patient_id": "patient id PAT-44321",
    "encounter_id": "encounter id ENC-44321",
    "member_id": "member id MEM-44321",
    "claim_id": "claim id CLM-44321",
    "appointment_id": "appointment id APT-44321",
    "dob": "DOB: 01/02/1980",
    "clinical_file_path": r"C:\demo\patient_mrn_12345\lab_result.pdf",
    "context_email": "jane.patient@example.invalid",
    "context_ip": "203.0.113.42",
    "context_url": "https://example.invalid/login",
    "ssn": "123-45-6789",
    "phone": "555-010-2222",
    "street_address": "123 Main Street",
}


def _all_rules() -> list[SensitiveRule]:
    return [*SECRET_RULES, *PHI_RULES, *CONTEXT_IDENTIFIER_RULES, *PII_RULES]


def test_detector_fixture_catalog_covers_every_current_rule() -> None:
    detectors = {rule.detector for rule in _all_rules()}

    assert set(DETECTOR_FIXTURES) == detectors


def test_every_healthcare_detector_has_a_tokenizing_fixture() -> None:
    for rule in _all_rules():
        fixture = DETECTOR_FIXTURES[rule.detector]
        context = "Patient portal billing investigation. " if rule.requires_context else ""

        result = safeguard_value({"description": f"{context}{fixture}"}, case_id="case_detector_test")
        rendered = json.dumps(result.value, default=str)

        assert rule.detector in result.summary["detectors"]
        assert fixture not in rendered
