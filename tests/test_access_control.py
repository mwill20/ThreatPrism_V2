from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from threatprism.api.app import create_app
from threatprism.config import Settings
from support_settings import DEMO_API_KEYS


RAW_PATIENT_ID = "PAT-44321"
RAW_CONTEXT_EMAIL = "jane.patient@example.invalid"
RAW_CONTEXT_IP = "203.0.113.42"
RAW_SECRET = "sk-testsecretvalue12345"
RAW_CLINICAL_PATH = r"C:\demo\patient_mrn_12345\lab_result.pdf"


def _app_and_client() -> tuple[FastAPI, TestClient]:
    app = create_app(
        Settings(
            env="test",
            database_url="sqlite:///:memory:",
            api_auth_mode="demo_key",
            demo_api_keys=DEMO_API_KEYS,
            llm_provider="deterministic_demo",
            allow_real_actions=False,
        )
    )
    return app, TestClient(app)


def _payload() -> dict:
    return json.loads(Path("examples/soar_payloads/generic_soar_case.json").read_text())


def _healthcare_contaminated_payload() -> dict:
    payload = deepcopy(_payload())
    payload["source_case_id"] = "SOAR-AUTH-SAFE-001"
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


def _create_case(client: TestClient, payload: dict | None = None) -> str:
    response = client.post("/cases", json=payload or _payload())
    assert response.status_code == 202
    return str(response.json()["case_id"])


def _auth_events(app: FastAPI, case_id: str) -> list:
    case = app.state.case_service.get_case(case_id)
    assert case is not None
    return [event for event in case.audit_trail if event.event_type == "authorization_decision"]


def test_unauthenticated_role_view_is_denied_and_audited() -> None:
    app, client = _app_and_client()
    case_id = _create_case(client)

    response = client.get(f"/cases/{case_id}?role=analyst")

    assert response.status_code == 401
    assert response.json()["detail"] == "Missing demo API key."
    event = _auth_events(app, case_id)[-1]
    assert event.actor == "anonymous"
    assert event.metadata["decision"] == "deny"
    assert event.metadata["reason"] == "missing_demo_credential"
    assert event.metadata["requested_role"] == "analyst"
    assert event.metadata["request_metadata_hash"].startswith("sha256:")


def test_unknown_demo_key_is_denied_without_auditing_full_credential() -> None:
    app, client = _app_and_client()
    case_id = _create_case(client)

    response = client.get(
        f"/cases/{case_id}?role=analyst",
        headers={"X-ThreatPrism-Demo-Key": "not-a-real-demo-key"},
    )

    assert response.status_code == 401
    event = _auth_events(app, case_id)[-1]
    assert event.metadata["decision"] == "deny"
    assert event.metadata["reason"] == "unknown_demo_credential"
    assert "not-a-real-demo-key" not in json.dumps(event.model_dump(mode="json"))


def test_manager_grc_cannot_force_analyst_view() -> None:
    app, client = _app_and_client()
    case_id = _create_case(client)

    response = client.get(
        f"/cases/{case_id}?role=analyst",
        headers={"X-ThreatPrism-Demo-Key": "demo-manager-key"},
    )

    assert response.status_code == 403
    event = _auth_events(app, case_id)[-1]
    assert event.metadata["decision"] == "deny"
    assert event.metadata["effective_role"] == "manager_grc"
    assert event.metadata["view_role"] == "analyst"
    assert event.metadata["reason"] == "role_view_not_allowed"


def test_manager_grc_default_view_is_masked_and_allow_audited() -> None:
    app, client = _app_and_client()
    case_id = _create_case(client)

    response = client.get(
        f"/cases/{case_id}",
        headers={"X-ThreatPrism-Demo-Key": "demo-manager-key"},
    )

    assert response.status_code == 200
    payload = response.json()
    payload_json = json.dumps(payload)
    assert payload["role_view"]["role"] == "manager_grc"
    assert "203.0.113.42" not in payload_json
    assert "[SECURITY_TELEMETRY:IP:masked]" in payload_json
    event = _auth_events(app, case_id)[-1]
    assert event.metadata["decision"] == "allow"
    assert event.metadata["effective_role"] == "manager_grc"
    assert event.metadata["view_role"] == "manager_grc"


def test_analyst_can_request_analyst_view_and_allow_is_audited() -> None:
    app, client = _app_and_client()
    case_id = _create_case(client)

    response = client.get(
        f"/cases/{case_id}?role=analyst",
        headers={"X-ThreatPrism-Demo-Key": "demo-analyst-key"},
    )

    assert response.status_code == 200
    payload_json = json.dumps(response.json())
    assert "203.0.113.42" in payload_json
    event = _auth_events(app, case_id)[-1]
    assert event.metadata["decision"] == "allow"
    assert event.metadata["caller_identity"] == "demo_analyst"
    assert event.metadata["view_role"] == "analyst"


def test_audit_debug_view_does_not_expose_raw_healthcare_values() -> None:
    app, client = _app_and_client()
    case_id = _create_case(client, _healthcare_contaminated_payload())

    response = client.get(
        f"/cases/{case_id}",
        headers={"X-ThreatPrism-Demo-Key": "demo-audit-key"},
    )

    assert response.status_code == 200
    payload_json = json.dumps(response.json())
    assert response.json()["role_view"]["role"] == "audit_debug"
    for raw_value in [RAW_PATIENT_ID, RAW_CONTEXT_EMAIL, RAW_CONTEXT_IP, RAW_SECRET, RAW_CLINICAL_PATH]:
        assert raw_value not in payload_json
    assert "[POTENTIAL_PHI:" in payload_json
    assert "[SECRET:" in payload_json


def test_manager_grc_cannot_force_engineer_report_view() -> None:
    app, client = _app_and_client()
    case_id = _create_case(client)

    response = client.get(
        f"/cases/{case_id}/triage-report?role=engineer",
        headers={"X-ThreatPrism-Demo-Key": "demo-manager-key"},
    )

    assert response.status_code == 403
    event = _auth_events(app, case_id)[-1]
    assert event.metadata["decision"] == "deny"
    assert event.metadata["endpoint"] == "get_triage_report"
    assert event.metadata["view_role"] == "engineer"


def test_production_environment_rejects_disabled_or_demo_auth() -> None:
    for auth_mode in ["none", "demo_key"]:
        try:
            create_app(
                Settings(
                    env="production",
                    database_url="sqlite:///:memory:",
                    api_auth_mode=auth_mode,
                    demo_api_keys=DEMO_API_KEYS if auth_mode == "demo_key" else "",
                    llm_provider="deterministic_demo",
                    allow_real_actions=False,
                )
            )
        except ValueError as exc:
            assert "Production environments cannot use disabled or demo API authentication." in str(exc)
        else:
            raise AssertionError(f"Expected production auth mode {auth_mode} to be rejected.")
