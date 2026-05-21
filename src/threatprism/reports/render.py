from __future__ import annotations

from threatprism.cases.schemas import TriageReport


def render_report(report: TriageReport) -> str:
    lines = [
        "ThreatPrism Triage Report",
        f"Report ID: {report.report_id}",
        f"Case ID: {report.case_id}",
        "",
        "Summary",
        report.summary,
        "",
        f"Determination: {report.determination}",
        f"Severity: {report.severity}",
        f"Disposition: {report.disposition}",
        f"Confidence: {report.confidence:.2f}",
        "",
        "Findings",
    ]
    if report.findings:
        for finding in report.findings:
            lines.append(f"- [{finding.severity}] {finding.title}: {finding.summary}")
    else:
        lines.append("- None")

    lines.extend(["", "Recommended Analyst Actions"])
    if report.recommended_actions:
        for action in report.recommended_actions:
            lines.append(f"- [{action.priority}] {action.action}")
    else:
        lines.append("- None")

    lines.extend(["", "Limitations"])
    for limitation in report.limitations:
        lines.append(f"- {limitation}")
    lines.append("- Analyst review is required before final disposition.")
    return "\n".join(lines)
