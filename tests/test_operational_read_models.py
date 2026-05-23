from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from threatprism.api.app import create_app
from threatprism.config import Settings


RAW_PATIENT_ID = "PAT-44321"
RAW_CONTEXT_EMAIL = "jane.patient@example.invalid"
RAW_CONTEXT_IP = "203.0.113.42"
RAW_SECRET = "sk-testsecretvalue12345"
RAW_CLINICAL_PATH = r"C:\demo\patient_mrn_12345\lab_result.pdf"


def _app_and_client(api_auth_mode: str = "none") -> tuple[FastAPI, TestClient]:
    app = create_app(
        Settings(
            env="test",
            database_url="sqlite:///:memory:",
            api_auth_mode=api_auth_mode,
            llm_provider="deterministic_demo",
            allow_real_actions=False,
        )
    )
    return app, TestClient(app)


def _payload(source_case_id: str = "SOAR-READMODEL-001") -> dict:
    payload = json.loads(Path("examples/soar_payloads/generic_soar_case.json").read_text())
    payload["source_case_id"] = source_case_id
    return payload


def _healthcare_contaminated_payload() -> dict:
    payload = deepcopy(_payload("SOAR-READMODEL-HEALTHCARE-001"))
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


def _create_case(client: TestClient, payload: dict) -> str:
    response = client.post("/cases", json=payload)
    assert response.status_code == 202
    return str(response.json()["case_id"])


def _submit_disagreeing_feedback(client: TestClient, case_id: str) -> None:
    response = client.post(
        f"/cases/{case_id}/analyst-feedback",
        json={
            "analyst_id": "analyst_demo_001",
            "analyst_determination": "benign",
            "analyst_severity": "low",
            "analyst_confidence": 0.76,
            "analyst_final_disposition": "close",
            "time_to_acknowledge_seconds": 120,
            "time_to_close_seconds": 900,
            "analyst_notes": "Synthetic review for read-model tests.",
            "manager_review_required": False,
            "false_positive": True,
            "false_negative": False,
            "missed_ioc": False,
            "missed_mitre_mapping": False,
            "missed_escalation": True,
        },
    )
    assert response.status_code == 200


def test_metrics_aggregate_cases_feedback_guardrails_and_grc() -> None:
    _, client = _app_and_client()
    manager_case_id = _create_case(client, _payload("SOAR-READMODEL-MANAGER-001"))
    healthcare_case_id = _create_case(client, _healthcare_contaminated_payload())
    _submit_disagreeing_feedback(client, manager_case_id)

    response = client.get("/metrics")

    assert response.status_code == 200
    metrics = response.json()
    assert metrics["case_counts"]["total"] == 2
    assert metrics["case_counts"]["by_source"]["generic_soar"] == 2
    assert metrics["triage"]["completed"] == 2
    assert sum(metrics["report_decisions"]["severity"].values()) == 2
    assert metrics["report_decisions"]["severity"]["high"] >= 1
    assert metrics["guardrails"]["healthcare_review_required"] == 1
    assert metrics["guardrails"]["secret_exposure_detected"] == 1
    assert metrics["disagreement"]["feedback_count"] == 1
    assert metrics["disagreement"]["manager_review_required_count"] == 1
    assert metrics["timing"]["average_time_to_acknowledge_seconds"] == 120
    assert metrics["timing"]["average_time_to_close_seconds"] == 900
    assert metrics["grc"]["mapping_count"] >= 2
    assert metrics["grc"]["mappings_with_evidence_count"] == metrics["grc"]["mapping_count"]
    assert healthcare_case_id


def test_case_read_model_filters_manager_and_healthcare_review_queues() -> None:
    _, client = _app_and_client()
    manager_case_id = _create_case(client, _payload("SOAR-READMODEL-MANAGER-002"))
    healthcare_case_id = _create_case(client, _healthcare_contaminated_payload())
    _submit_disagreeing_feedback(client, manager_case_id)

    manager_response = client.get("/cases/read-model?manager_review_required=true")
    healthcare_response = client.get("/cases/read-model?healthcare_review_required=true")

    assert manager_response.status_code == 200
    manager_items = manager_response.json()["items"]
    assert [item["case_id"] for item in manager_items] == [manager_case_id]
    assert manager_items[0]["manager_review_required"] is True

    assert healthcare_response.status_code == 200
    healthcare_items = healthcare_response.json()["items"]
    assert [item["case_id"] for item in healthcare_items] == [healthcare_case_id]
    assert healthcare_items[0]["healthcare_review_required"] is True


def test_detail_routes_apply_role_safe_rendering_and_preserve_grc_evidence_links() -> None:
    _, client = _app_and_client(api_auth_mode="demo_key")
    case_id = _create_case(client, _healthcare_contaminated_payload())
    mitre_case_id = _create_case(client, _payload("SOAR-READMODEL-MITRE-001"))

    evidence_response = client.get(
        f"/cases/{case_id}/evidence",
        headers={"X-ThreatPrism-Demo-Key": "demo-manager-key"},
    )
    grc_response = client.get(
        f"/cases/{case_id}/grc-controls",
        headers={"X-ThreatPrism-Demo-Key": "demo-manager-key"},
    )
    mitre_response = client.get(
        f"/cases/{mitre_case_id}/mitre",
        headers={"X-ThreatPrism-Demo-Key": "demo-manager-key"},
    )
    timeline_response = client.get(
        f"/cases/{case_id}/timeline",
        headers={"X-ThreatPrism-Demo-Key": "demo-manager-key"},
    )

    assert evidence_response.status_code == 200
    evidence_payload = evidence_response.json()
    evidence_json = json.dumps(evidence_payload)
    assert evidence_payload["role_view"]["role"] == "manager_grc"
    for raw_value in [RAW_PATIENT_ID, RAW_CONTEXT_EMAIL, RAW_CONTEXT_IP, RAW_SECRET, RAW_CLINICAL_PATH]:
        assert raw_value not in evidence_json
    assert "[POTENTIAL_PHI:" in evidence_json
    assert "[SECRET:" in evidence_json

    assert grc_response.status_code == 200
    controls = grc_response.json()["items"]
    assert controls
    assert all(control["evidence_ids"] for control in controls)
    assert all(control["language_note"].startswith("HITRUST-aligned") for control in controls)
    assert "certified" not in json.dumps(controls).lower()

    assert mitre_response.status_code == 200
    assert mitre_response.json()["items"][0]["evidence_ids"]
    assert timeline_response.status_code == 200
    assert timeline_response.json()["items"][0]["evidence_id"]


def test_read_model_auth_denial_and_safe_audit_event_details() -> None:
    _, client = _app_and_client(api_auth_mode="demo_key")
    case_id = _create_case(client, _payload("SOAR-READMODEL-AUTH-001"))

    unauth_metrics = client.get("/metrics")
    unauth_case_list = client.get("/cases/read-model")
    denied_case = client.get(f"/cases/{case_id}?role=analyst")
    audit_events = client.get(
        f"/cases/{case_id}/audit-events",
        headers={"X-ThreatPrism-Demo-Key": "demo-audit-key"},
    )
    authorization_filtered = client.get(
        "/cases/read-model?authorization_denied=true",
        headers={"X-ThreatPrism-Demo-Key": "demo-manager-key"},
    )

    assert unauth_metrics.status_code == 401
    assert unauth_case_list.status_code == 401
    assert denied_case.status_code == 401
    assert audit_events.status_code == 200
    audit_payload = audit_events.json()
    audit_json = json.dumps(audit_payload)
    assert audit_payload["role_view"]["role"] == "audit_debug"
    assert "authorization_decision" in audit_json
    assert "demo-audit-key" not in audit_json
    assert "demo-manager-key" not in audit_json
    assert "raw_payload" not in audit_json

    assert authorization_filtered.status_code == 200
    filtered_items = authorization_filtered.json()["items"]
    assert [item["case_id"] for item in filtered_items] == [case_id]
    assert filtered_items[0]["authorization_denied"] is True


def test_manager_cannot_force_analyst_detail_view() -> None:
    _, client = _app_and_client(api_auth_mode="demo_key")
    case_id = _create_case(client, _payload("SOAR-READMODEL-ESCALATION-001"))

    response = client.get(
        f"/cases/{case_id}/evidence?role=analyst",
        headers={"X-ThreatPrism-Demo-Key": "demo-manager-key"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Requested role view is not allowed for this caller."
