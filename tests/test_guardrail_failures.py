from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from threatprism.cases.schemas import (
    CaseRecord,
    Determination,
    Disposition,
    Finding,
    Severity,
    SimulatedAction,
    TriageReport,
    TriageStatus,
)
from threatprism.cases.service import CaseService
from threatprism.config import Settings


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


def _base_report(case: CaseRecord, **overrides: object) -> TriageReport:
    evidence_ids = [item.evidence_id for item in case.evidence]
    report_payload = {
        "case_id": case.case_id,
        "summary": "Evidence-linked demo triage requires analyst review.",
        "determination": Determination.suspicious,
        "severity": Severity.high,
        "disposition": Disposition.escalate,
        "confidence": 0.8,
        "findings": [
            Finding(
                title="Evidence-linked finding",
                summary="The finding is supported by the submitted fake evidence.",
                severity=Severity.high,
                evidence_ids=evidence_ids,
            )
        ],
        "simulated_actions": [
            SimulatedAction(
                action="simulate_escalation_to_analyst_queue",
                would_target=case.source_case_id,
            )
        ],
        "analyst_review_required": True,
    }
    report_payload.update(overrides)
    return TriageReport.model_validate(report_payload)


class StubProvider:
    provider_name = "stub"

    def __init__(self, report_factory: Callable[[CaseRecord], TriageReport]) -> None:
        self._report_factory = report_factory

    def generate_report(self, case: CaseRecord) -> TriageReport:
        return self._report_factory(case)


def test_policy_violation_blocks_triage_report() -> None:
    service = _service()
    accepted = service.create_case(_payload())
    service.provider = StubProvider(
        lambda case: _base_report(case, summary="I disabled the account during triage.")
    )

    service.run_triage(accepted.case_id)

    case = service.get_case(accepted.case_id)
    assert case is not None
    assert case.triage_status == TriageStatus.blocked_by_guardrail
    assert service.get_report(accepted.case_id) is None
    assert case.audit_trail[-1].event_type == "triage_blocked_by_guardrail"


def test_unknown_evidence_reference_blocks_triage_report() -> None:
    service = _service()
    accepted = service.create_case(_payload())
    service.provider = StubProvider(
        lambda case: _base_report(
            case,
            findings=[
                Finding(
                    title="Unsupported finding",
                    summary="This finding cites evidence that does not exist.",
                    severity=Severity.high,
                    evidence_ids=["ev-missing"],
                )
            ],
        )
    )

    service.run_triage(accepted.case_id)

    case = service.get_case(accepted.case_id)
    assert case is not None
    assert case.triage_status == TriageStatus.blocked_by_guardrail
    assert service.get_report(accepted.case_id) is None
    assert "unknown evidence_id=ev-missing" in str(case.audit_trail[-1].metadata["issues"])


def test_real_action_claim_blocks_triage_report() -> None:
    service = _service()
    accepted = service.create_case(_payload())
    service.provider = StubProvider(
        lambda case: _base_report(
            case,
            simulated_actions=[
                SimulatedAction(
                    action="simulate_account_disable",
                    would_target=case.source_case_id,
                    real_action_executed=True,
                    blocked_reason="Invalid provider output for test.",
                )
            ],
        )
    )

    service.run_triage(accepted.case_id)

    case = service.get_case(accepted.case_id)
    assert case is not None
    assert case.triage_status == TriageStatus.blocked_by_guardrail
    assert service.get_report(accepted.case_id) is None
    assert "Real action execution is not allowed in V2" in str(case.audit_trail[-1].metadata["issues"])
