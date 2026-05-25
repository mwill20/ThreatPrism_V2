from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from threatprism.api.app import create_app
from threatprism.config import Settings
from threatprism.demo.scenarios import (
    ApiContractRoute,
    DemoScenario,
    DemoScenarioPack,
    DemoScenarioStep,
    load_demo_scenario_pack,
)
from support_settings import DEMO_API_KEYS


REPO_ROOT = Path(__file__).resolve().parents[1]
REQUIRED_PERSONAS = {"analyst", "manager_grc", "legal_privacy", "audit_debug", "engineer"}
EXPECTED_ROUTE_METHODS = {
    "/health": {"get"},
    "/cases": {"get", "post"},
    "/metrics": {"get"},
    "/cases/read-model": {"get"},
    "/queues/manager-review": {"get"},
    "/queues/healthcare-review": {"get"},
    "/cases/{case_id}": {"get"},
    "/cases/{case_id}/triage-report": {"get"},
    "/cases/{case_id}/evidence": {"get"},
    "/cases/{case_id}/timeline": {"get"},
    "/cases/{case_id}/mitre": {"get"},
    "/cases/{case_id}/grc-controls": {"get"},
    "/cases/{case_id}/audit-events": {"get"},
    "/cases/{case_id}/analyst-feedback": {"post"},
}
READ_MODEL_FILTERS = {
    "source",
    "status",
    "triage_status",
    "severity",
    "determination",
    "manager_review_required",
    "healthcare_review_required",
    "guardrail_blocked",
    "authorization_denied",
    "created_after",
    "created_before",
    "limit",
    "cursor",
    "role",
}


def _client() -> TestClient:
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
    return TestClient(app)


def _pack() -> DemoScenarioPack:
    return load_demo_scenario_pack()


def test_demo_scenario_pack_is_fake_local_and_role_complete() -> None:
    pack = _pack()

    assert pack.schema_version == "demo-scenario-pack/0.1"
    assert pack.safety_rules["data_boundary"] == "fake_data_only"
    assert pack.safety_rules["external_calls"] == "not_allowed"
    assert pack.safety_rules["allow_real_actions"] is False
    assert {scenario.persona for scenario in pack.scenarios} == REQUIRED_PERSONAS

    for scenario in pack.scenarios:
        assert scenario.auth_key.startswith("demo-")
        payload_path = Path(scenario.payload_path)
        assert payload_path.parts[0] == "examples"
        assert (REPO_ROOT / payload_path).is_file()
        for step in scenario.steps:
            assert step.path.startswith("/")
            assert "http://" not in step.path
            assert "https://" not in step.path


def test_demo_scenario_loader_is_cwd_independent(monkeypatch, tmp_path) -> None:  # noqa: ANN001
    monkeypatch.chdir(tmp_path)

    pack = load_demo_scenario_pack()

    assert pack.schema_version == "demo-scenario-pack/0.1"
    assert {scenario.persona for scenario in pack.scenarios} == REQUIRED_PERSONAS


def test_current_openapi_contract_freeze_matches_documented_routes() -> None:
    client = _client()
    openapi = client.get("/openapi.json").json()
    paths = openapi["paths"]

    for route in _pack().api_contract:
        assert route.path in paths
        assert route.method.lower() in paths[route.path]
        operation = paths[route.path][route.method.lower()]
        _assert_route_contract(operation, route)

    for path, methods in EXPECTED_ROUTE_METHODS.items():
        assert path in paths
        assert methods <= set(paths[path])

    read_model_params = _parameter_names(paths["/cases/read-model"]["get"])
    assert READ_MODEL_FILTERS <= read_model_params
    for path in [
        "/cases/{case_id}",
        "/cases/{case_id}/triage-report",
        "/cases/{case_id}/evidence",
        "/cases/{case_id}/timeline",
        "/cases/{case_id}/mitre",
        "/cases/{case_id}/grc-controls",
        "/cases/{case_id}/audit-events",
    ]:
        params = _parameter_names(paths[path]["get"])
        assert {"case_id", "role"} <= params


def test_demo_scenarios_smoke_current_role_workflows() -> None:
    pack = _pack()

    for scenario in pack.scenarios:
        _run_scenario(_client(), scenario)


def _run_scenario(client: TestClient, scenario: DemoScenario) -> None:
    payload = json.loads((REPO_ROOT / scenario.payload_path).read_text(encoding="utf-8"))
    case_id: str | None = None

    for step in scenario.steps:
        path = step.path.format(case_id=case_id or "")
        body = _request_body(step, payload, scenario)
        headers = _headers(step, scenario)

        if step.method == "POST":
            response = client.post(path, json=body, headers=headers)
        else:
            response = client.get(path, headers=headers)

        assert response.status_code == step.expected_status, (
            scenario.scenario_id,
            step.step_id,
            response.status_code,
            response.text,
        )
        response_payload = response.json()
        if step.step_id == "create_case":
            case_id = str(response_payload["case_id"])
        _assert_step_expectations(response_payload, step)


def _request_body(step: DemoScenarioStep, payload: dict[str, Any], scenario: DemoScenario) -> dict[str, Any] | None:
    if step.body == "payload":
        return payload
    if step.body == "feedback":
        assert scenario.feedback is not None
        return scenario.feedback
    return None


def _headers(step: DemoScenarioStep, scenario: DemoScenario) -> dict[str, str]:
    if step.auth == "none":
        return {}
    if step.auth == "scenario":
        return {"X-ThreatPrism-Demo-Key": scenario.auth_key}
    return {"X-ThreatPrism-Demo-Key": step.auth}


def _assert_step_expectations(payload: Any, step: DemoScenarioStep) -> None:
    payload_json = json.dumps(payload, sort_keys=True)
    for path in step.expected_json_paths:
        assert _json_path(payload, path) is not None, (step.step_id, path, payload)
    for expected in step.expected_substrings:
        assert expected in payload_json, (step.step_id, expected, payload_json)
    for forbidden in step.forbidden_substrings:
        assert forbidden not in payload_json, (step.step_id, forbidden, payload_json)


def _json_path(payload: Any, path: str) -> Any:
    current = payload
    for part in path.split("."):
        if isinstance(current, list):
            current = current[int(part)]
        elif isinstance(current, dict):
            current = current[part]
        else:
            raise AssertionError(f"Cannot descend through {path!r}.")
    return current


def _assert_route_contract(operation: dict[str, Any], route: ApiContractRoute) -> None:
    response_codes = set(operation["responses"])
    for status_code in route.status_codes:
        assert str(status_code) in response_codes, (route.path, route.method, status_code, response_codes)

    if route.response_model is None:
        return

    schema = _first_success_response_schema(operation, route.status_codes)
    if route.response_model == "list[CaseSummary]":
        assert schema["type"] == "array"
        assert schema["items"]["$ref"].endswith("/CaseSummary")
    else:
        assert schema["$ref"].endswith(f"/{route.response_model}")


def _response_schema(operation: dict[str, Any], *, status_code: str = "200") -> dict[str, Any]:
    return operation["responses"][status_code]["content"]["application/json"]["schema"]


def _first_success_response_schema(operation: dict[str, Any], status_codes: list[int]) -> dict[str, Any]:
    for status_code in status_codes:
        if 200 <= status_code < 300:
            return _response_schema(operation, status_code=str(status_code))
    raise AssertionError("Contract route with a response model must declare a success status code.")


def _parameter_names(operation: dict[str, Any]) -> set[str]:
    return {param["name"] for param in operation.get("parameters", [])}
