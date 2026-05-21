from __future__ import annotations

from typing import Protocol

from threatprism.actions.safety import simulated_action
from threatprism.cases.schemas import (
    CaseRecord,
    Determination,
    Disposition,
    Finding,
    Hypothesis,
    RecommendedAction,
    Severity,
    TriageReport,
)
from threatprism.grc.mapping import map_grc_controls
from threatprism.mitre.mapping import map_mitre


class TriageProvider(Protocol):
    provider_name: str

    def generate_report(self, case: CaseRecord) -> TriageReport:
        ...


class DeterministicDemoProvider:
    provider_name = "deterministic_demo"

    def generate_report(self, case: CaseRecord) -> TriageReport:
        evidence = case.evidence
        combined = " ".join(
            [case.title, case.description]
            + [item.summary for item in evidence]
            + [(item.excerpt or "") for item in evidence]
        ).lower()

        severity = _severity_from_text(combined)
        determination = _determination_from_severity(severity)
        disposition = Disposition.escalate if severity in {Severity.high, Severity.critical} else Disposition.monitor
        evidence_ids = [item.evidence_id for item in evidence]

        finding = Finding(
            title="Evidence-linked SOAR case review",
            summary="Submitted evidence requires analyst review before relying on automation closure.",
            severity=severity,
            evidence_ids=evidence_ids or ["missing-evidence"],
        )

        report = TriageReport(
            case_id=case.case_id,
            summary="ThreatPrism reviewed the submitted SOAR case with deterministic guardrails and evidence grounding.",
            determination=determination,
            severity=severity,
            disposition=disposition,
            confidence=0.82 if severity in {Severity.high, Severity.critical} else 0.64,
            findings=[finding],
            evidence=[
                {
                    "evidence_id": item.evidence_id,
                    "claim": item.summary,
                    "supports": ["severity", "disposition"],
                }
                for item in evidence
            ],
            timeline=[
                {
                    "timestamp": event.timestamp,
                    "event_type": event.event_type,
                    "summary": event.description,
                    "evidence_id": evidence_ids[0] if evidence_ids else "",
                }
                for event in case.events
            ],
            iocs=case.iocs,
            mitre_mappings=map_mitre(evidence),
            hypotheses=[
                Hypothesis(
                    hypothesis="The case may represent risk missed by an automated closure path.",
                    confidence=0.7,
                    evidence_ids=evidence_ids,
                )
            ],
            recommended_actions=[
                RecommendedAction(
                    action="Review the evidence and source automation decision before final closure.",
                    priority="high" if severity in {Severity.high, Severity.critical} else "medium",
                    evidence_ids=evidence_ids,
                )
            ],
            simulated_actions=[
                simulated_action(
                    "simulate_escalation_to_analyst_queue",
                    would_target=case.source_case_id,
                )
            ],
            grc_controls=map_grc_controls(evidence),
            limitations=[
                "ThreatPrism did not access live SOAR, SIEM, identity, endpoint, or enrichment systems.",
                "Threat intelligence providers are not configured in demo mode.",
                "Analyst review is required before final disposition.",
            ],
            analyst_review_required=True,
        )
        return report


def get_provider(name: str) -> TriageProvider:
    if name != "deterministic_demo":
        return DeterministicDemoProvider()
    return DeterministicDemoProvider()


def _severity_from_text(text: str) -> Severity:
    if any(term in text for term in ["critical", "exfil", "malware", "ransomware", "token revocation"]):
        return Severity.critical
    if any(term in text for term in ["impossible travel", "mailbox rule", "credential", "suspicious", "powershell"]):
        return Severity.high
    if any(term in text for term in ["alert", "automation", "closed", "monitor"]):
        return Severity.medium
    return Severity.low


def _determination_from_severity(severity: Severity) -> Determination:
    if severity == Severity.critical:
        return Determination.critical
    if severity == Severity.high:
        return Determination.suspicious
    return Determination.benign
