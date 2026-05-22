from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

from threatprism.cases.schemas import (
    Determination,
    Disposition,
    Finding,
    GrcControl,
    Severity,
    SimulatedAction,
    TriageReport,
)
from threatprism.cases.service import CaseService
from threatprism.config import Settings
from threatprism.guardrails.evidence import validate_report_evidence
from threatprism.guardrails.healthcare import safeguard_text
from threatprism.guardrails.policy import scan_output_policy
from threatprism.guardrails.views import render_role_view


RAW_PATIENT_ID = "PAT-44321"
RAW_CONTEXT_EMAIL = "jane.patient@example.invalid"
RAW_CONTEXT_IP = "203.0.113.42"
RAW_SECRET = "sk-testsecretvalue12345"
RAW_CLINICAL_PATH = r"C:\demo\patient_mrn_12345\lab_result.pdf"


def _service() -> CaseService:
    return CaseService(
        Settings(
            env="test",
            database_url="sqlite:///:memory:",
            llm_provider="deterministic_demo",
            allow_real_actions=False,
        )
    )


def _payload() -> dict:
    return json.loads(Path("examples/soar_payloads/generic_soar_case.json").read_text())


def _healthcare_contaminated_payload() -> dict:
    payload = deepcopy(_payload())
    payload["source_case_id"] = "SOAR-HEALTHCARE-SAFE-001"
    payload["title"] = "Patient portal security alert"
    payload["description"] = (
        f"Patient portal alert for patient id {RAW_PATIENT_ID} from {RAW_CONTEXT_IP} "
        f"using {RAW_CONTEXT_EMAIL}. Automation note included API key {RAW_SECRET}."
    )
    payload["events"][0]["description"] = (
        f"Patient portal login investigation referenced {RAW_CLINICAL_PATH} "
        f"and source address {RAW_CONTEXT_IP}."
    )
    payload["events"][0]["normalized"]["actor"] = RAW_CONTEXT_EMAIL
    payload["events"][0]["normalized"]["source_ip"] = RAW_CONTEXT_IP
    payload["entities"][0]["value"] = RAW_CONTEXT_EMAIL
    payload["iocs"][0]["value"] = RAW_CONTEXT_IP
    payload["evidence"][0]["summary"] = (
        f"Patient portal evidence mentions patient id {RAW_PATIENT_ID}, "
        f"contact {RAW_CONTEXT_EMAIL}, source IP {RAW_CONTEXT_IP}, and {RAW_CLINICAL_PATH}."
    )
    payload["evidence"][0]["excerpt"] = f"Secret-like value {RAW_SECRET} was present in a fake note."
    return payload


class CapturingProvider:
    provider_name = "capturing"

    def __init__(self) -> None:
        self.model_visible_payload = ""

    def generate_report(self, case) -> TriageReport:  # noqa: ANN001
        self.model_visible_payload = case.model_dump_json()
        evidence_ids = [item.evidence_id for item in case.evidence]
        return TriageReport(
            case_id=case.case_id,
            summary="ThreatPrism reviewed the sanitized case and requires analyst review.",
            determination=Determination.suspicious,
            severity=Severity.high,
            disposition=Disposition.escalate,
            confidence=0.78,
            findings=[
                Finding(
                    title="Sanitized evidence review",
                    summary="The finding cites sanitized fake evidence only.",
                    severity=Severity.high,
                    evidence_ids=evidence_ids,
                )
            ],
            evidence=[
                {
                    "evidence_id": case.evidence[0].evidence_id,
                    "claim": case.evidence[0].summary,
                    "supports": ["severity", "disposition"],
                }
            ],
            simulated_actions=[
                SimulatedAction(
                    action="simulate_escalation_to_analyst_queue",
                    would_target=case.source_case_id,
                )
            ],
            grc_controls=[
                GrcControl(
                    category="HITRUST-aligned access-control evidence mapping",
                    rationale="Evidence mapping is advisory and requires review.",
                    evidence_ids=evidence_ids,
                )
            ],
            analyst_review_required=True,
        )


def test_identifier_only_security_telemetry_is_not_phi() -> None:
    text = (
        "Endpoint telemetry shows analyst@example.invalid connected from "
        "203.0.113.42 to https://example.invalid/security-tool."
    )

    result = safeguard_text(text, "evidence[0].summary")

    assert result.value == text
    assert result.summary["token_count"] == 0


def test_patient_context_identifiers_are_tokenized_as_potential_phi() -> None:
    text = (
        f"Patient portal alert for patient id {RAW_PATIENT_ID} from {RAW_CONTEXT_IP} "
        f"using {RAW_CONTEXT_EMAIL}."
    )

    result = safeguard_text(text, "evidence[0].summary")

    assert RAW_PATIENT_ID not in result.value
    assert RAW_CONTEXT_IP not in result.value
    assert RAW_CONTEXT_EMAIL not in result.value
    assert "[POTENTIAL_PHI:PATIENT_ID:phi_0001]" in result.value
    assert any(record.token_type == "potential_phi:context_ip" for record in result.records)
    assert any(record.token_type == "potential_phi:context_email" for record in result.records)
    assert result.summary["potential_sensitive_data_exposure"] is True
    assert result.summary["privacy_legal_review_required"] is True


def test_clinical_file_path_and_secret_are_tokenized() -> None:
    result = safeguard_text(
        f"Alert referenced {RAW_CLINICAL_PATH} and secret {RAW_SECRET}.",
        "events[0].description",
    )

    assert RAW_CLINICAL_PATH not in result.value
    assert RAW_SECRET not in result.value
    assert "[POTENTIAL_PHI:CLINICAL_FILE_PATH:phi_0001]" in result.value
    assert "[SECRET:API_KEY:secret_0001]" in result.value
    assert all(record.rehydration_allowed is False for record in result.records)
    assert result.summary["secret_exposure_detected"] is True


def test_case_creation_and_triage_never_expose_raw_healthcare_values() -> None:
    service = _service()
    accepted = service.create_case(_healthcare_contaminated_payload())
    case = service.get_case(accepted.case_id)
    assert case is not None

    stored_case = case.model_dump_json()
    for raw_value in [RAW_PATIENT_ID, RAW_CONTEXT_EMAIL, RAW_CONTEXT_IP, RAW_SECRET, RAW_CLINICAL_PATH]:
        assert raw_value not in stored_case

    assert case.source_metadata["healthcare_safeguard"]["potential_sensitive_data_exposure"] is True
    assert case.source_metadata["healthcare_safeguard"]["secret_exposure_detected"] is True
    assert any(event.event_type == "healthcare_safeguard_applied" for event in case.audit_trail)
    assert any(event.event_type == "sensitive_data_tokenized" for event in case.audit_trail)
    assert any(event.event_type == "secret_exposure_detected" for event in case.audit_trail)
    assert any(record.token and record.token.startswith("[POTENTIAL_PHI:") for record in case.sanitization_records)
    assert any(record.token and record.token.startswith("[SECRET:") for record in case.sanitization_records)

    provider = CapturingProvider()
    service.provider = provider
    service.run_triage(accepted.case_id)

    report = service.get_report(accepted.case_id)
    assert report is not None
    report_payload = report.model_dump_json()
    for raw_value in [RAW_PATIENT_ID, RAW_CONTEXT_EMAIL, RAW_CONTEXT_IP, RAW_SECRET, RAW_CLINICAL_PATH]:
        assert raw_value not in provider.model_visible_payload
        assert raw_value not in report_payload
        assert raw_value not in report.rendered_report


def test_role_views_preserve_analyst_security_telemetry_and_mask_manager_view() -> None:
    payload = {
        "summary": f"Security telemetry contains {RAW_CONTEXT_IP} and [POTENTIAL_PHI:MRN:phi_0001]."
    }

    analyst_view = render_role_view(payload, "analyst", case_id="case-demo")
    assert RAW_CONTEXT_IP in analyst_view.payload["summary"]
    assert "[POTENTIAL_PHI:MRN:phi_0001]" in analyst_view.payload["summary"]
    assert any(event.event_type == "rehydration_denied" for event in analyst_view.audit_events)

    manager_view = render_role_view(payload, "manager_grc", case_id="case-demo")
    assert RAW_CONTEXT_IP not in manager_view.payload["summary"]
    assert "[SECURITY_TELEMETRY:IP:masked]" in manager_view.payload["summary"]
    assert "[POTENTIAL_PHI:MRN:phi_0001]" in manager_view.payload["summary"]
    assert manager_view.metadata["masked_security_telemetry"] == 1
    assert any(event.event_type == "role_view_policy_applied" for event in manager_view.audit_events)
    assert any(event.event_type == "rehydration_denied" for event in manager_view.audit_events)


def test_api_role_view_records_view_audit_event() -> None:
    service = _service()
    accepted = service.create_case(_healthcare_contaminated_payload())

    view = service.get_case_view(accepted.case_id, "manager_grc")

    assert view is not None
    view_json = json.dumps(view)
    assert RAW_CONTEXT_IP not in view_json
    assert view["role_view"]["role"] == "manager_grc"
    assert view["role_view"]["sensitive_tokens_present"] > 0

    case = service.get_case(accepted.case_id)
    assert case is not None
    assert case.audit_trail[-1].event_type == "rehydration_denied"
    assert any(event.event_type == "role_view_policy_applied" for event in case.audit_trail)


def test_validated_report_rehydration_records_security_telemetry_approval() -> None:
    service = _service()
    accepted = service.create_case(_payload())

    service.run_triage(accepted.case_id)

    case = service.get_case(accepted.case_id)
    assert case is not None
    approval_events = [event for event in case.audit_trail if event.event_type == "rehydration_approved"]
    assert approval_events
    assert approval_events[-1].metadata["token_types"]["ip"] >= 1
    assert approval_events[-1].metadata["token_types"]["email"] >= 1


def test_compliance_certification_claims_are_blocked_but_alignment_language_is_allowed() -> None:
    prohibited_claims = [
        "This case is HIPAA compliant.",
        "The evidence shows HITRUST certification readiness.",
        "The control is satisfied by this evidence.",
        "This packet is audit-ready.",
        "The evidence proves compliance.",
    ]

    for claim in prohibited_claims:
        assert scan_output_policy({"summary": claim})

    allowed = {
        "summary": (
            "HITRUST-aligned category mapping only; evidence mapping is advisory "
            "and requires human review."
        )
    }
    assert scan_output_policy(allowed) == []


def test_grc_mappings_must_cite_evidence_ids() -> None:
    report = TriageReport(
        case_id="case-demo",
        summary="Evidence-linked demo triage requires analyst review.",
        determination=Determination.suspicious,
        severity=Severity.high,
        disposition=Disposition.escalate,
        confidence=0.8,
        findings=[
            Finding(
                title="Evidence-linked finding",
                summary="The finding is supported by fake evidence.",
                severity=Severity.high,
                evidence_ids=["ev-001"],
            )
        ],
        grc_controls=[
            GrcControl(
                category="HITRUST-aligned access-control evidence mapping",
                rationale="Evidence mapping is advisory and requires review.",
                evidence_ids=[],
            )
        ],
    )

    issues = validate_report_evidence(report, {"ev-001"})

    assert "must cite at least one evidence_id" in str(issues)
