from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from threatprism.api.app import create_app
from support_settings import local_auth_disabled_settings


def _client(tmp_path: Path) -> TestClient:
    app = create_app(
        local_auth_disabled_settings()
    )
    return TestClient(app)


def test_health_reports_real_actions_disabled(tmp_path: Path) -> None:
    client = _client(tmp_path)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["allow_real_actions"] is False


def test_generic_soar_case_flow_and_feedback(tmp_path: Path) -> None:
    client = _client(tmp_path)
    payload = json.loads(Path("examples/soar_payloads/generic_soar_case.json").read_text())

    create_response = client.post("/cases", json=payload)
    assert create_response.status_code == 202
    created = create_response.json()
    assert created["triage_status"] == "queued"

    case_id = created["case_id"]
    report_response = client.get(f"/cases/{case_id}/triage-report")
    assert report_response.status_code == 200
    report = report_response.json()
    assert report["status"] == "completed"
    assert report["severity"] == "high"
    assert report["simulated_actions"][0]["real_action_executed"] is False
    assert report["grc_controls"][0]["language_note"].startswith("HITRUST-aligned")
    assert "203.0.113.42" in json.dumps(report)

    feedback_response = client.post(
        f"/cases/{case_id}/analyst-feedback",
        json={
            "analyst_id": "analyst_demo_001",
            "analyst_determination": "benign",
            "analyst_severity": "low",
            "analyst_confidence": 0.76,
            "analyst_final_disposition": "close",
            "time_to_acknowledge_seconds": 120,
            "time_to_close_seconds": 900,
            "analyst_notes": "Synthetic review for test flow.",
            "manager_review_required": False,
            "false_positive": True,
            "false_negative": False,
            "missed_ioc": False,
            "missed_mitre_mapping": False,
            "missed_escalation": True,
        },
    )
    assert feedback_response.status_code == 200
    disagreement = feedback_response.json()["disagreement"]
    assert disagreement["determination_mismatch"] is True
    assert disagreement["severity_mismatch"] is True
    assert disagreement["manager_review_required"] is True
