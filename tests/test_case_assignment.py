"""Evolution 3 sub-slice 1 — case ownership/assignment tests."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from threatprism.api.app import create_app
from threatprism.cases.service import CaseService
from support_settings import demo_key_settings, local_auth_disabled_settings

ANALYST = {"X-ThreatPrism-Demo-Key": "demo-analyst-key"}
ENGINEER = {"X-ThreatPrism-Demo-Key": "demo-engineer-key"}
MANAGER = {"X-ThreatPrism-Demo-Key": "demo-manager-key"}
ADMIN = {"X-ThreatPrism-Demo-Key": "demo-admin-key"}

_PAYLOAD = {
    "source": "generic_soar",
    "source_case_id": "SOAR-ASSIGN-001",
    "title": "Assignment test case",
    "description": "routine monitor event for assignment testing",
    "evidence": [{"evidence_id": "ev-assign-1", "evidence_type": "log", "summary": "routine"}],
}


def _client() -> TestClient:
    return TestClient(create_app(demo_key_settings()))


def _create_case(client: TestClient) -> str:
    resp = client.post("/cases", json=_PAYLOAD, headers=ADMIN)
    assert resp.status_code == 202
    return resp.json()["case_id"]


# --- API authorization ------------------------------------------------------

def test_analyst_can_self_assign() -> None:
    client = _client()
    case_id = _create_case(client)
    resp = client.post(f"/cases/{case_id}/assign", headers=ANALYST)
    assert resp.status_code == 200
    body = resp.json()
    assert body["assigned_to"] == "demo_analyst"
    assert body["assigned_at"] is not None


def test_manager_cannot_self_assign() -> None:
    client = _client()
    case_id = _create_case(client)
    resp = client.post(f"/cases/{case_id}/assign", headers=MANAGER)
    assert resp.status_code == 403


def test_unauthenticated_assign_is_denied() -> None:
    client = _client()
    case_id = _create_case(client)
    resp = client.post(f"/cases/{case_id}/assign")  # no key
    assert resp.status_code == 401


def test_assign_unknown_case_is_404() -> None:
    client = _client()
    resp = client.post("/cases/case_nonexistent/assign", headers=ANALYST)
    assert resp.status_code == 404


def test_owner_can_release_non_owner_cannot_admin_can() -> None:
    client = _client()
    case_id = _create_case(client)
    client.post(f"/cases/{case_id}/assign", headers=ANALYST)  # owned by demo_analyst

    # A different working role (engineer) is NOT the owner -> 403.
    assert client.post(f"/cases/{case_id}/release", headers=ENGINEER).status_code == 403

    # Admin can release any case.
    admin_release = client.post(f"/cases/{case_id}/release", headers=ADMIN)
    assert admin_release.status_code == 200
    assert admin_release.json()["assigned_to"] is None

    # Re-assign, then the owner releases their own case.
    client.post(f"/cases/{case_id}/assign", headers=ANALYST)
    owner_release = client.post(f"/cases/{case_id}/release", headers=ANALYST)
    assert owner_release.status_code == 200
    assert owner_release.json()["assigned_to"] is None


def test_assignment_records_audit_events() -> None:
    client = _client()
    case_id = _create_case(client)
    client.post(f"/cases/{case_id}/assign", headers=ANALYST)
    view = client.get(f"/cases/{case_id}/audit-events", headers=ADMIN).json()
    types = [e.get("event_type") for e in view["items"]]
    assert "case_assigned" in types


def test_local_dev_mode_assign_works() -> None:
    # In API_AUTH_MODE=none the caller is admin -> assignment is allowed.
    client = TestClient(create_app(local_auth_disabled_settings()))
    resp = client.post("/cases", json=_PAYLOAD)
    case_id = resp.json()["case_id"]
    assert client.post(f"/cases/{case_id}/assign").status_code == 200


# --- service-level ownership rules ------------------------------------------

def _service_case() -> tuple[CaseService, str]:
    service = CaseService(local_auth_disabled_settings())
    accepted = service.create_case(_PAYLOAD)
    return service, accepted.case_id


def test_service_assign_sets_owner_and_audit() -> None:
    service, case_id = _service_case()
    result = service.assign_case(case_id, actor_identity="analyst_1", actor_role="analyst")
    assert result.assigned_to == "analyst_1"
    case = service.get_case(case_id)
    assert case.assigned_to == "analyst_1" and case.assigned_at is not None
    assert any(e.event_type == "case_assigned" and e.actor == "analyst_1" for e in case.audit_trail)


def test_service_release_blocks_non_owner_non_admin() -> None:
    service, case_id = _service_case()
    service.assign_case(case_id, actor_identity="analyst_1", actor_role="analyst")
    with pytest.raises(PermissionError):
        service.release_case(case_id, actor_identity="analyst_2", actor_role="engineer")
    # Admin override succeeds.
    service.release_case(case_id, actor_identity="admin_1", actor_role="admin")
    assert service.get_case(case_id).assigned_to is None


def test_service_assign_unknown_case_raises_keyerror() -> None:
    service, _ = _service_case()
    with pytest.raises(KeyError):
        service.assign_case("nope", actor_identity="analyst_1", actor_role="analyst")


# --- "my queue" assignment filter -------------------------------------------

def _create_case_id(client: TestClient, scid: str) -> str:
    payload = {**_PAYLOAD, "source_case_id": scid}
    return client.post("/cases", json=payload, headers=ADMIN).json()["case_id"]


def test_my_cases_lists_only_callers_owned_cases() -> None:
    client = _client()
    c_analyst = _create_case_id(client, "SOAR-MQ-A")
    c_engineer = _create_case_id(client, "SOAR-MQ-E")
    c_unassigned = _create_case_id(client, "SOAR-MQ-U")
    client.post(f"/cases/{c_analyst}/assign", headers=ANALYST)
    client.post(f"/cases/{c_engineer}/assign", headers=ENGINEER)

    body = client.get("/queues/my-cases", headers=ANALYST).json()
    assert body["queue"] == "my-cases"
    ids = {it["case_id"] for it in body["items"]}
    assert c_analyst in ids
    assert c_engineer not in ids and c_unassigned not in ids  # isolation
    item = next(it for it in body["items"] if it["case_id"] == c_analyst)
    assert item["assigned_to"] == "demo_analyst"


def test_my_cases_manager_is_denied() -> None:
    client = _client()
    assert client.get("/queues/my-cases", headers=MANAGER).status_code == 403


def test_my_cases_unauthenticated_is_denied() -> None:
    client = _client()
    assert client.get("/queues/my-cases").status_code == 401


def test_read_model_assigned_to_filter() -> None:
    client = _client()
    c1 = _create_case_id(client, "SOAR-RM-1")
    _create_case_id(client, "SOAR-RM-2")  # unassigned
    client.post(f"/cases/{c1}/assign", headers=ANALYST)
    body = client.get("/cases/read-model?assigned_to=demo_analyst", headers=ADMIN).json()
    ids = {it["case_id"] for it in body["items"]}
    assert ids == {c1}


# --- analyst-feedback authorization + server-authoritative attribution -------

_FEEDBACK = {
    "analyst_id": "SPOOFED_OTHER",
    "analyst_determination": "benign",
    "analyst_severity": "low",
    "analyst_confidence": 0.5,
    "analyst_final_disposition": "monitor",
}


def test_feedback_requires_auth_and_attributes_to_authenticated_identity() -> None:
    app = create_app(demo_key_settings())
    client = TestClient(app)
    case_id = client.post(
        "/cases", json={**_PAYLOAD, "source_case_id": "SOAR-FB-1"}, headers=ADMIN
    ).json()["case_id"]
    url = f"/cases/{case_id}/analyst-feedback"

    # A non-working role (manager_grc) cannot submit feedback.
    assert client.post(url, json=_FEEDBACK, headers=MANAGER).status_code == 403
    # Unauthenticated is denied.
    assert client.post(url, json=_FEEDBACK).status_code == 401

    # Analyst may submit; the spoofed body analyst_id is overridden with the
    # AUTHENTICATED identity (can't file feedback in another analyst's name).
    assert client.post(url, json=_FEEDBACK, headers=ANALYST).status_code == 200
    stored = app.state.case_service.get_case(case_id).analyst_feedback[-1]
    assert stored.analyst_id == "demo_analyst"  # not "SPOOFED_OTHER"
