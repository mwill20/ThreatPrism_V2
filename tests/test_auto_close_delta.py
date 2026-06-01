"""Evolution 1 auto-close delta tests (deterministic demo provider, no network)."""

from __future__ import annotations

import json

from threatprism.cases.service import CaseService
from threatprism.demo.auto_close_delta import (
    AutoCloseDeltaReport,
    run_auto_close_delta,
)
from threatprism.demo.seeding import CuratedDatasetSource, DemoSeeder
from support_settings import local_auth_disabled_settings

_FORBIDDEN = ("theshire", "cloudapp", "WORKSTATION5", "S-1-5-21")


def _service() -> CaseService:
    return CaseService(local_auth_disabled_settings())


def _seeded_service() -> CaseService:
    service = _service()
    DemoSeeder(service).seed([CuratedDatasetSource()])
    return service


def _seed_case(service: CaseService, *, case_id: str, description: str, inbound_severity: str) -> str:
    accepted = service.create_case({
        "source": "generic_soar",
        "source_case_id": case_id,
        "title": "Auto-close delta test case",
        "description": description,
        "alerts": [{"name": "src alert", "severity": inbound_severity}],
        "evidence": [{"evidence_id": f"ev-{case_id}", "evidence_type": "log", "summary": description}],
    })
    service.run_triage(accepted.case_id)
    return accepted.case_id


def _result_for(report: AutoCloseDeltaReport, source_case_id: str):
    return next(r for r in report.results if r.source_case_id == source_case_id)


# --- crafted cases: deterministic catch / safe / escalate -------------------

def test_low_inbound_but_dangerous_content_is_a_catch() -> None:
    service = _service()
    # Inbound "low" -> SOAR would auto-close; demo provider scores ransomware/exfil
    # as critical -> ThreatPrism flags it. That gap is the catch.
    _seed_case(service, case_id="ACD-CATCH-001",
               description="ransomware exfiltration detected on the finance host",
               inbound_severity="low")
    report = run_auto_close_delta(service)
    row = _result_for(report, "ACD-CATCH-001")
    assert row.soar_would_auto_close is True
    assert row.threatprism_flagged is True
    assert row.is_catch is True
    assert report.catches >= 1


def test_low_inbound_benign_content_is_safe_auto_close() -> None:
    service = _service()
    _seed_case(service, case_id="ACD-SAFE-001",
               description="routine scheduled backup completed and was closed by automation",
               inbound_severity="low")
    report = run_auto_close_delta(service)
    row = _result_for(report, "ACD-SAFE-001")
    assert row.soar_would_auto_close is True
    assert row.threatprism_flagged is False
    assert row.is_catch is False


def test_high_inbound_severity_is_not_auto_closed() -> None:
    service = _service()
    _seed_case(service, case_id="ACD-ESC-001",
               description="routine event", inbound_severity="critical")
    report = run_auto_close_delta(service)
    row = _result_for(report, "ACD-ESC-001")
    assert row.soar_would_auto_close is False  # SOAR escalates high/critical inbound
    assert row.is_catch is False


# --- seeded-corpus structural invariants ------------------------------------

def test_delta_over_curated_corpus_is_consistent() -> None:
    report = run_auto_close_delta(_seeded_service())
    assert report.total == 31  # 32 seeded, 1 blocked injection has no report
    assert report.auto_close_count + report.residual_review_count == report.total
    assert report.catches == len(report.catch_cases)
    # Every catch genuinely satisfies both conditions.
    for r in report.catch_cases:
        assert r.soar_would_auto_close and r.threatprism_flagged
    # Auto-close set splits cleanly into cleared + caught.
    assert report.safe_auto_close_count + report.catches == report.auto_close_count


def test_report_is_serializable_and_leaks_nothing() -> None:
    report = run_auto_close_delta(_seeded_service())
    blob = report.model_dump_json()
    json.loads(blob)
    assert isinstance(report, AutoCloseDeltaReport)
    for token in _FORBIDDEN:
        assert token not in blob
