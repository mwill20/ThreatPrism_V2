from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from support_settings import demo_key_settings, local_auth_disabled_settings
from threatprism.api.app import create_app


REPO_ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_DIR = REPO_ROOT / "src" / "threatprism" / "dashboard" / "static"
CONTRACT_ROUTES = {
    "/health",
    "/metrics",
    "/cases/read-model",
    "/queues/manager-review",
    "/queues/healthcare-review",
    "/cases/{case_id}",
    "/cases/{case_id}/triage-report",
    "/cases/{case_id}/evidence",
    "/cases/{case_id}/timeline",
    "/cases/{case_id}/mitre",
    "/cases/{case_id}/grc-controls",
    "/cases/{case_id}/audit-events",
    "/csi/objects",
    "/csi/objects/{object_id}",
    "/csi/lineage/{object_id}",
    "/csi/replay/{object_id}",
    "/csi/observability",
    "/csi/divergence",
}
DEMO_CREDENTIALS = {
    "demo-analyst-key",
    "demo-manager-key",
    "demo-legal-key",
    "demo-audit-key",
    "demo-engineer-key",
}


def test_dashboard_route_serves_static_shell_and_assets() -> None:
    client = TestClient(create_app(local_auth_disabled_settings()))

    page = client.get("/dashboard")
    script = client.get("/dashboard/assets/app.js")
    styles = client.get("/dashboard/assets/styles.css")

    assert page.status_code == 200
    assert script.status_code == 200
    assert styles.status_code == 200
    assert "ThreatPrism Dashboard" in page.text
    assert "data-persona=\"analyst\"" in page.text
    assert "data-persona=\"csi_rgoi\"" in page.text
    assert "ALLOW_REAL_ACTIONS=false" in page.text


def test_dashboard_responses_have_hardening_headers() -> None:
    client = TestClient(create_app(local_auth_disabled_settings()))

    page = client.get("/dashboard")
    script = client.get("/dashboard/assets/app.js")
    styles = client.get("/dashboard/assets/styles.css")

    for response in (page, script, styles):
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY"
        assert response.headers["referrer-policy"] == "no-referrer"
        assert response.headers["cross-origin-opener-policy"] == "same-origin"
        assert response.headers["cross-origin-resource-policy"] == "same-origin"
        assert response.headers["x-permitted-cross-domain-policies"] == "none"
        assert "camera=()" in response.headers["permissions-policy"]
        csp = response.headers["content-security-policy"]
        assert "default-src 'self'" in csp
        assert "connect-src 'self'" in csp
        assert "frame-ancestors 'none'" in csp
        assert "object-src 'none'" in csp
        assert "script-src 'self'" in csp
        assert "style-src 'self'" in csp


def test_dashboard_assets_are_same_origin_and_fake_credential_only() -> None:
    html = (DASHBOARD_DIR / "index.html").read_text(encoding="utf-8")
    script = (DASHBOARD_DIR / "app.js").read_text(encoding="utf-8")
    styles = (DASHBOARD_DIR / "styles.css").read_text(encoding="utf-8")
    combined = "\n".join([html, script, styles])

    for route in CONTRACT_ROUTES:
        assert route in script
    for credential in DEMO_CREDENTIALS:
        assert credential in script or credential in html

    assert "https://" not in combined
    assert "http://" not in combined
    assert "sk-" not in combined
    assert '"allow_real_actions": true' not in combined
    assert "vault_mappings" not in combined
    assert "raw_payload" not in combined


def test_dashboard_fetches_are_same_origin_timeout_bounded_and_keyboard_accessible() -> None:
    html = (DASHBOARD_DIR / "index.html").read_text(encoding="utf-8")
    script = (DASHBOARD_DIR / "app.js").read_text(encoding="utf-8")
    styles = (DASHBOARD_DIR / "styles.css").read_text(encoding="utf-8")

    assert "role=\"tablist\"" in html
    assert "role=\"tab\"" in html
    assert "aria-selected=\"true\"" in html
    assert "aria-controls=\"main\"" in html
    assert "Blocked non-same-origin dashboard request." in script
    assert "new URL(path, window.location.origin)" in script
    assert "REQUEST_TIMEOUT_MS = 8000" in script
    assert "AbortController" in script
    assert "signal: controller.signal" in script
    assert "keydown" in script
    assert "ArrowRight" in script
    assert "Home" in script
    assert "focus-visible" in styles


def test_dashboard_demo_key_mode_keeps_api_protected_while_serving_ui() -> None:
    client = TestClient(create_app(demo_key_settings()))

    dashboard = client.get("/dashboard")
    protected_api = client.get("/metrics")
    protected_api_with_demo_key = client.get(
        "/metrics",
        headers={"X-ThreatPrism-Demo-Key": "demo-manager-key"},
    )

    assert dashboard.status_code == 200
    assert protected_api.status_code == 401
    assert protected_api_with_demo_key.status_code == 200


def test_dashboard_static_content_has_responsive_operational_layout() -> None:
    html = (DASHBOARD_DIR / "index.html").read_text(encoding="utf-8")
    styles = (DASHBOARD_DIR / "styles.css").read_text(encoding="utf-8")

    assert "role-nav" in html
    assert "summary-band" in html
    assert "workbench" in html
    assert "@media (max-width: 1180px)" in styles
    assert "@media (max-width: 760px)" in styles
    assert "grid-template-columns" in styles


def test_dashboard_copilot_controls_present_and_assignable_gated() -> None:
    html = (DASHBOARD_DIR / "index.html").read_text(encoding="utf-8")
    script = (DASHBOARD_DIR / "app.js").read_text(encoding="utf-8")

    # "My cases" toggle in the shell.
    assert "my-cases-toggle" in html

    # Evolution 3 routes wired into the dashboard.
    for route in (
        "/queues/my-cases",
        "/cases/{case_id}/assign",
        "/cases/{case_id}/release",
        "/cases/{case_id}/analyst-feedback",
    ):
        assert route in script

    # Co-pilot panel + CSP-safe delegated actions (no inline handlers).
    assert "renderCopilot" in script
    assert "runCaseAction" in script
    for action in ('data-action="assign"', 'data-action="release"', 'data-action="submit-feedback"'):
        assert action in script
    assert "onclick" not in html and "onclick" not in script  # CSP: no inline handlers

    # Controls are gated to assignable personas (analyst/engineer) only.
    assert "ASSIGNABLE_PERSONAS" in script
    assert "isAssignable" in script

    # Feedback form fields exist.
    for field in ("fb-determination", "fb-severity", "fb-disposition", "fb-confidence"):
        assert field in script


def test_dashboard_detail_uses_validated_triage_report_for_decision_fields() -> None:
    script = (DASHBOARD_DIR / "app.js").read_text(encoding="utf-8")

    assert 'triageReport: "/cases/{case_id}/triage-report"' in script
    assert "apiGetOptional(casePath(API_ROUTES.triageReport))" in script
    assert "state.report" in script
    assert "currentReportSummary" in script
    assert "selectedCaseReadModel" in script
