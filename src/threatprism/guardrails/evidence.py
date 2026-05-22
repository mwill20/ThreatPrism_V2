from __future__ import annotations

from threatprism.cases.schemas import TriageReport


def validate_report_evidence(report: TriageReport, valid_evidence_ids: set[str]) -> list[str]:
    issues: list[str] = []
    for finding in report.findings:
        for evidence_id in finding.evidence_ids:
            if evidence_id not in valid_evidence_ids:
                issues.append(f"Finding {finding.finding_id} references unknown evidence_id={evidence_id}")
    for mapping in report.mitre_mappings:
        for evidence_id in mapping.evidence_ids:
            if evidence_id not in valid_evidence_ids:
                issues.append(f"MITRE mapping {mapping.technique_id} references unknown evidence_id={evidence_id}")
    for control in report.grc_controls:
        if not control.evidence_ids:
            issues.append(f"GRC mapping {control.category} must cite at least one evidence_id")
        for evidence_id in control.evidence_ids:
            if evidence_id not in valid_evidence_ids:
                issues.append(f"GRC mapping {control.category} references unknown evidence_id={evidence_id}")
    for hypothesis in report.hypotheses:
        for evidence_id in hypothesis.evidence_ids:
            if evidence_id not in valid_evidence_ids:
                issues.append(f"Hypothesis references unknown evidence_id={evidence_id}")
    return issues
