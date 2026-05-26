from __future__ import annotations

import json

from fastapi.testclient import TestClient

from support_settings import demo_key_settings, local_auth_disabled_settings
from threatprism.api.app import create_app
from threatprism.csi.schemas import RetrievalContext, RetrievalPurpose
from threatprism.csi.service import CognitiveRetrievalService


def _context(
    *,
    tenant_id: str = "tenant_demo_alpha",
    view_role: str = "analyst",
    purpose: RetrievalPurpose = RetrievalPurpose.analyst_investigation,
) -> RetrievalContext:
    return RetrievalContext(
        tenant_id=tenant_id,
        principal_id=f"demo_{view_role}",
        effective_role=view_role,
        view_role=view_role,  # type: ignore[arg-type]
        purpose=purpose,
    )


def _demo_key_client() -> TestClient:
    return TestClient(create_app(demo_key_settings()))


def test_csi_retrieval_is_tenant_scoped_read_only_and_evidence_aligned() -> None:
    service = CognitiveRetrievalService.demo()

    response = service.search(context=_context(), query="identity", limit=20)

    assert response.total > 0
    assert response.explanation.cross_tenant_objects_suppressed >= 1
    assert "read_only_cognition" in response.explanation.enforced_controls
    assert {item.object.tenant_id for item in response.items} == {"tenant_demo_alpha"}
    assert "tenant_demo_beta" not in json.dumps(response.model_dump(mode="json"))
    assert all(item.evidence_alignment.valid for item in response.items)
    assert all(item.object.retrieval_zone != "quarantine" for item in response.items)


def test_csi_preserves_competing_interpretations_and_ai_non_authority() -> None:
    service = CognitiveRetrievalService.demo()

    response = service.search(context=_context(), object_type="reasoning", query="interpretation")
    objects = {item.object.id: item for item in response.items}

    assert "cog_reason_alpha_ai_001" in objects
    assert "cog_reason_alpha_human_001" in objects
    assert objects["cog_reason_alpha_ai_001"].authority_state == "ai_non_authoritative"
    assert objects["cog_reason_alpha_human_001"].authority_state == "human_approved"
    assert objects["cog_reason_alpha_ai_001"].object.competes_with == ["cog_reason_alpha_human_001"]
    assert "AI-generated cognition is non-authoritative until approved" in objects[
        "cog_reason_alpha_ai_001"
    ].trust.reasons


def test_csi_manager_role_cannot_retrieve_soc_operational_zone() -> None:
    service = CognitiveRetrievalService.demo()
    context = _context(view_role="manager_grc", purpose=RetrievalPurpose.manager_review)

    response = service.search(context=context, retrieval_zone="soc_operational", limit=20)

    assert response.total == 0
    assert response.explanation.denied_same_tenant_objects
    denied_reasons = {
        reason
        for decision in response.explanation.denied_same_tenant_objects
        for reason in decision.reasons
    }
    assert "retrieval_zone_not_allowed_for_role" in denied_reasons


def test_csi_stale_cognition_is_hidden_by_default_and_visible_to_audit_when_requested() -> None:
    service = CognitiveRetrievalService.demo()
    context = _context(view_role="audit_debug", purpose=RetrievalPurpose.audit_reconstruction)

    default_response = service.search(context=context, object_type="drift")
    stale_response = service.search(context=context, object_type="drift", include_stale=True)

    assert default_response.total == 0
    assert stale_response.total == 1
    assert stale_response.items[0].object.id == "cog_drift_alpha_001"
    assert stale_response.items[0].stale is True


def test_csi_quarantined_adversarial_memory_is_not_retrievable() -> None:
    service = CognitiveRetrievalService.demo()

    response = service.search(context=_context(), query="poisoned", limit=20)

    assert response.total == 0
    denied_reasons = {
        reason
        for decision in response.explanation.denied_same_tenant_objects
        for reason in decision.reasons
    }
    assert "quarantined_object_excluded" in denied_reasons
    assert "evidence_alignment_failed" in denied_reasons


def test_csi_api_requires_demo_auth_and_suppresses_cross_tenant_objects() -> None:
    client = _demo_key_client()

    unauthenticated = client.get("/csi/objects?tenant_id=tenant_demo_alpha&query=identity")
    assert unauthenticated.status_code == 401

    response = client.get(
        "/csi/objects?tenant_id=tenant_demo_alpha&query=identity",
        headers={"X-ThreatPrism-Demo-Key": "demo-analyst-key"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] > 0
    assert payload["explanation"]["cross_tenant_objects_suppressed"] >= 1
    assert "tenant_demo_beta" not in json.dumps(payload)


def test_csi_api_denies_role_escalation_before_retrieval() -> None:
    client = _demo_key_client()

    response = client.get(
        "/csi/objects?tenant_id=tenant_demo_alpha&role=analyst",
        headers={"X-ThreatPrism-Demo-Key": "demo-manager-key"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Requested role view is not allowed for this caller."


def test_csi_api_lineage_replay_observability_and_divergence_are_explainable() -> None:
    client = TestClient(create_app(local_auth_disabled_settings()))

    lineage = client.get("/csi/lineage/cog_reason_alpha_human_001?tenant_id=tenant_demo_alpha")
    assert lineage.status_code == 200
    lineage_payload = lineage.json()
    assert lineage_payload["object_id"] == "cog_reason_alpha_human_001"
    assert {node["object_id"] for node in lineage_payload["nodes"]} >= {
        "cog_intel_alpha_001",
        "cog_reason_alpha_ai_001",
        "cog_reason_alpha_human_001",
    }

    replay = client.get("/csi/replay/cog_reason_alpha_human_001?tenant_id=tenant_demo_alpha")
    assert replay.status_code == 200
    assert replay.json()["deterministic_inputs_hash"].startswith("sha256:")
    assert replay.json()["limitations"]

    observability = client.get("/csi/observability?tenant_id=tenant_demo_alpha")
    assert observability.status_code == 200
    observability_payload = observability.json()
    assert "read_only_cognition" in observability_payload["controls_active"]
    assert observability_payload["ai_non_authoritative_count"] >= 1

    divergence = client.get("/csi/divergence?tenant_id=tenant_demo_alpha")
    assert divergence.status_code == 200
    divergence_payload = divergence.json()
    assert divergence_payload["total"] == 1
    assert divergence_payload["records"][0]["status"] == "human_decision_controls_truth"


def test_csi_routes_are_in_openapi_contract() -> None:
    client = TestClient(create_app(local_auth_disabled_settings()))

    openapi = client.get("/openapi.json").json()
    paths = set(openapi["paths"])

    assert "/csi/objects" in paths
    assert "/csi/objects/{object_id}" in paths
    assert "/csi/lineage/{object_id}" in paths
    assert "/csi/replay/{object_id}" in paths
    assert "/csi/observability" in paths
    assert "/csi/divergence" in paths
